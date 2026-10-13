"""
ips.py - Independent Subsystem IPS & Mitigation Engine.

Handles automated threat response across three decoupled layers.

RECENT FIXES:
- FIXED (FATAL THREAD DEADLOCK): Upgraded `self._lock` from a standard `threading.Lock()` to a 
  `threading.RLock()` (Reentrant Lock). This resolves a catastrophic pipeline freeze where `mitigate()` 
  acquired the lock to trigger `_unisolate_device_router()`, which then attempted to acquire the exact 
  same lock upon receiving an HTTP 202 success response, permanently deadlocking the main execution thread.
- ADDED (DUAL-STACK IPv6 TARPIT): Upgraded the mitigation engine to sniff for IPv6 Neighbor Discovery 
  Protocol (NDP) requests. Dynamically intercepts ICMPv6ND_NS (Neighbor Solicitation) packets and injects 
  spoofed ICMPv6ND_NA (Neighbor Advertisement) packets to blackhole IPv6 routing.
- FIXED (HARDWARE MITIGATION BYPASS): Added dynamic MAC address reconstruction from `device_id`. 
- ADDED (SECURE AUTHENTICATION): Implemented Pi-hole v6 session ID ('sid') header authentication, dynamically 
  pulling from the configuration engine (which supports environment variable overrides).
"""

import json
import logging
import collections
import threading
import time
import requests
from pathlib import Path
from typing import Dict, Any, List, Optional

from metrics import (
    ips_pihole_blocks_metric,
    ips_isolations_metric,
    ips_errors_metric,
    ips_active_blocks_gauge,
    ips_pihole_status,
    ips_router_status,
    ips_tarpit_status,
    ips_tarpit_active,
    ips_router_isolated_active,
    ips_queue_status_gauge,
    ips_dead_letter_gauge,
    ips_pihole_unblocks_metric,
    ips_router_releases_metric,
    ips_tarpit_activations_total,
)

from core.onboarding import is_onboarding_active

LOGGER = logging.getLogger("home_ids.ips")


def _remove_gauge_labels(gauge, *labels) -> None:
    """Drops one label set from a Prometheus gauge. A label set that was never set raises KeyError: that is the
    expected "nothing to remove" case and stays silent. Anything else is logged (W-14: these used to be bare
    `except: pass`, which also swallowed KeyboardInterrupt/SystemExit)."""
    try:
        gauge.remove(*labels)
    except KeyError:
        pass
    except Exception as exc:
        LOGGER.warning("Could not remove gauge labels %r: %s", labels, exc)

# SECURITY FIX (P0-2, third-party architecture review, 2026-09-28): mitigate() had no
# device-criticality check at all before autonomously firing full-host containment
# (Layer-2 tarpit / router isolation) -- a heuristic false positive on one of these
# device_type classifications (utils.py's infer_device_type()) would isolate a
# household's router, NAS, or TV with zero human gate, purely because risk_score
# crossed the same threshold used for any other device. These device_type values are
# reused as-is (utils.py already classifies "router"/"gateway"/"nas"/"smart_tv" from
# hostname/vendor -- this doesn't invent a new taxonomy or hand-encode any household-
# specific host, keeping with this project's network-agnostic-design standard) purely
# to decide when to require the SAME interactive/Telegram-approval path
# `interactive_blocking_enabled` already provides for every device, not to grant any
# immunity -- lateral_threat (actual observed internal port-scan/lateral movement, the
# one signal this file already treats as strong enough to override the operator-
# release cooldown) still bypasses this exactly as it bypasses interactive_mode below.
# Not underscore-prefixed: pipeline.py imports this too, so its own "queue an approval
# button" decision (the containment_status rewrite in its main loop) can never drift
# out of sync with what this file actually held back -- see that call site's comment.
CRITICAL_DEVICE_TYPES = frozenset({"router", "gateway", "nas", "smart_tv"})


def _discover_gateway_ipv4():
    """This network's IPv4 default gateway, from the kernel's routing table (argus/identity/discovery.py) -- read only;
    a module-level name so tests can replace it."""
    from argus.identity.discovery import default_gateway_ip
    return default_gateway_ip()


def _is_v4(ip) -> bool:
    """True when `ip` is an IPv4 address (used to tell the ARP half's work from the NDP half's)."""
    try:
        return ipaddress.ip_address(str(ip).split("%", 1)[0]).version == 4
    except (ValueError, TypeError):
        return False

# Layer-2 tarpit primitives are our own stdlib raw-socket code (mitigation/l2_raw.py), replacing scapy (GPL-2.0).
# Linux-only, like the tarpit always was: AF_PACKET must exist. (Still needs root/CAP_NET_RAW at runtime.)
import ipaddress
import socket as _socket_mod
from mitigation import l2_raw
from mitigation import containment as _ct
from mitigation import pihole_auth
from mitigation import peer_table as _peer_mod       # T2: same-segment peer observation (socket-free core)
from mitigation import l2_enforcer as _l2e           # T2: which forged frames to send (socket-free decisions)
from mitigation import nftables_fw as _nft           # T2/T3: the containment firewall (box-drop / in-path)
L2_AVAILABLE = hasattr(_socket_mod, "AF_PACKET")
# Key in the shared IPS state: {"armed": bool, "updated_at": epoch} as the engine's own IPSMitigator found it at start.
ENGINE_TARPIT_STATE_KEY = "engine_tarpit"


def check_pihole_health(config: Dict[str, Any], timeout: float = 3.0,
                         session: Optional[Any] = None) -> "tuple[bool, str]":
    """BUGFIX (live audit): real, on-demand Pi-hole reachability+auth check for the
    boot-time Telegram status message -- previously that message either hardcoded
    "Online" or never checked Pi-hole at all. Reuses the exact same endpoint/auth
    _block_domain()'s desync check already exercises successfully in production, so a
    green result here means blocking will actually work, not just that config values
    are non-empty.

    Module-level (not a method) so it can be called WITHOUT constructing a full
    IPSMitigator -- that constructor starts the ARP-tarpit listener and the retry-worker
    thread as side effects (see __init__ below), which is exactly wrong for a read-only
    health check called from a process that isn't doing mitigation at all (the WebUI's
    health panel, PRODUCTIZATION_ROADMAP.md Phase 4). IPSMitigator.check_pihole_health()
    below is now a thin wrapper over this for existing callers."""
    if not bool(config.get("ips_pihole_enabled", True)):
        return False, "disabled in config (ips_pihole_enabled=false)"
    api_url = config.get("pihole_api_url", "")
    if not api_url:
        return False, "pihole_api_url not configured"
    api_path = config.get("pihole_api_path", "/api/domains")
    api_password = config.get("pihole_api_password", "")
    url = f"{api_url}{api_path}/deny/exact"
    client = session or requests
    try:
        resp = client.get(url, headers=pihole_auth.auth_headers(api_url, api_password, session, timeout), timeout=timeout)
        if resp.status_code == 401 and api_password:
            # the cached session may have expired or the Pi-hole restarted: log in again once
            pihole_auth.invalidate(api_url, api_password)
            resp = client.get(url, headers=pihole_auth.auth_headers(api_url, api_password, session, timeout), timeout=timeout)
    except Exception as exc:
        return False, f"connection failed: {exc}"
    if resp.status_code == 401:
        return False, "authentication rejected (wrong pihole_api_password)"
    if resp.status_code != 200:
        return False, f"HTTP {resp.status_code}"
    try:
        resp.json()
    except Exception:
        return False, "response was not valid JSON (wrong pihole_api_path?)"
    return True, "reachable, authenticated, real response"


class IPSMitigator:
    def __init__(self, config: Dict[str, Any], state_manager: Optional[Any] = None, stream_writer: Optional[Any] = None,
                  graph_store: Optional[Any] = None, start_workers: bool = True):
        """start_workers=False builds a state-only instance: no retry/reconcile threads, no tarpit threads, no
        boot reconcile. Request handlers (W-01) construct one per call to apply an operator action to the shared
        state, and must never leave background threads or raw sockets behind. The engine's own instance keeps the
        default."""
        self.config = config
        self.stream_writer = stream_writer
        # IPS containment unification: OPTIONAL
        # write-only audit mirror into GraphStore's containment_actions table --
        # never the real containment state (self.state_manager's ips_state dict
        # below stays that, unchanged, hot-path). None (the default, and every
        # pre-existing caller) means this class behaves EXACTLY as before this
        # param existed -- every mirror call site below no-ops on None rather than
        # erroring. See _mirror_containment()'s own docstring for the fail-safe
        # contract every call site follows.
        self._graph_store = graph_store
        
        if state_manager is None:
            LOGGER.warning("IPSMitigator initialized without StateManager. Booting fallback instance.")
            from core.state_guard import StateManager
            state_path = config.get("state_path", "state/ids_state.json")
            max_devices = int(config.get("max_device_states", 5000))
            self.state_manager = StateManager(state_path=state_path, max_devices=max_devices)
            self.state_manager.load_from_disk()
        else:
            self.state_manager = state_manager

        self.session = requests.Session()
        
        # ARCHITECTURAL FIX: Reentrant Lock to prevent same-thread nesting deadlocks
        self._lock = threading.RLock()
        
        LOGGER.debug("Loading persistent IPS queues, active tarpit targets, and router isolations...")
        ips_state = self.state_manager.get_ips_state()
        self._retry_queue = ips_state.get("retry_queue", {})
        self._dead_letter = ips_state.get("dead_letter", {})
        # T1 (2026-10-12): tarpit entries are keyed by DEVICE ("dev:<id>") and carry every MAC the device is known by;
        # entries persisted under an address are re-keyed here (mitigation/containment.py).
        raw_targets = ips_state.get("tarpit_targets", {}) or {}
        self._tarpit_active_targets = _ct.normalize_tarpit_targets(raw_targets)
        self._router_isolated_devices = ips_state.get("router_isolated_devices", {})
        self._operator_released_devices = ips_state.get("operator_released_devices", {})
        # Per-MAC observations of contained devices' frames (observer thread) and the events the engine alerts on.
        self._observed: Dict[str, Dict[str, float]] = {}
        self._observed_lock = threading.Lock()
        self._containment_events = collections.deque(maxlen=100)
        self._targets_refreshed_at = 0.0
        # T2 same-segment containment (CONTAINMENT_MODEL.md section 5). Peers observed on the wire, the IPv6 routers
        # learned from Router Advertisements, and the box firewall (owner decision 1: a Tarpit also cuts the box
        # itself). All socket-free cores; the sockets live in the loops below. nft absent -> every box_* call no-ops,
        # so same-segment still works on its own.
        self._peer_table = _peer_mod.PeerTable()
        self._ipv6_routers: Dict[str, str] = {}      # router link-local -> real MAC, from RAs (Block-internet v6)
        self._fw = _nft.NftContainment(uplink=None)  # uplink discovered lazily in _fw_uplink()
        self._fw_avail: Optional[bool] = None         # cached nft availability (checked once)
        self._fw_box_macs: set = set()                # MACs currently box-dropped (Tarpit mode), reconciled each round
        
        self._state_only = not start_workers
        if not start_workers:
            # State-only instance (W-01): no tarpit threads, no sockets, no background workers. A tarpit target it
            # registers is applied by the ENGINE's tarpit (pipeline.py reloads tarpit_targets on .ipc_sync_signal),
            # so "armed" here means the engine's tarpit is armed, as the engine last published it. Before
            # 2026-10-07 this was a hard False, so the console's Tarpit always answered 502.
            self.tarpit_armed = bool((ips_state.get(ENGINE_TARPIT_STATE_KEY) or {}).get("armed"))
            self._tarpit_thread = None
            self._ndp_tarpit_thread = None
            return

        self._init_arp_tarpit()
        self._publish_engine_tarpit_state()
        if self._tarpit_active_targets != raw_targets:
            with self._lock:
                self._save_queues()
            LOGGER.info("Tarpit entries re-keyed by device (%d entr%s).", len(self._tarpit_active_targets),
                        "y" if len(self._tarpit_active_targets) == 1 else "ies")
        self._sync_metrics_from_state()

        interactive_mode = bool(self.config.get("interactive_blocking_enabled", False))
        LOGGER.info(
            "🛡️  IPS Mitigator Active │ Interactive HITL Mode: %s │ Pi-hole: %s │ Router: %s │ Tarpit: %s",
            "ENABLED (Telegram Approval Required)" if interactive_mode else "DISABLED (Autonomous Auto-Block)",
            bool(self.config.get("ips_pihole_enabled", True)),
            bool(self.config.get("ips_router_enabled", False)),
            bool(self.config.get("ips_tarpit_enabled", True))
        )

        LOGGER.info("Starting IPS Retry Worker Thread...")
        threading.Thread(target=self._retry_worker, daemon=True, name="ips_retry_worker").start()

        # BUGFIX (live audit): _router_reconcile_worker() sleeps for
        # router_reconcile_interval_seconds (default 300s) BEFORE its first check, so a
        # device released directly in the Fritz!Box admin UI while this process was
        # down stayed shown as isolated (ips_router_isolated_active=1, stale
        # router_isolated_devices loaded straight from disk above) for up to 5 minutes
        # after every restart, with nothing to correct it in that window -- the
        # per-cycle garbage_collect_ips_metrics() pass (pipeline.py) only reconciles
        # the gauge against this process's OWN on-disk belief, not against what
        # Fritz!Box actually has isolated right now, so it can't catch this case
        # either. Run one reconcile pass immediately at boot, before the periodic
        # worker's first sleep, so a restart converges to Fritz!Box's real state
        # right away regardless of how the device was released while this IDS wasn't
        # running to observe it.
        if bool(self.config.get("ips_router_enabled", False)) and self._router_isolated_devices:
            try:
                cleared = self.reconcile_router_isolation_state()
                if cleared:
                    LOGGER.warning("🔄 [BOOT RECONCILE] Cleared %d stale router-isolation record(s) no longer isolated by Fritz!Box.", cleared)
            except Exception as exc:
                # BUGFIX (live audit): was LOGGER.debug() -- reconcile_router_isolation_state()
                # now logs each per-target failure itself, so reaching THIS except means
                # something broke in the reconcile pass as a whole (not just one device's
                # query), worth a WARNING same as everything else in this fix.
                LOGGER.warning("🔄 [BOOT RECONCILE] Router isolation reconcile failed: %s", exc)

        LOGGER.info("Starting Router Isolation Reconcile Worker Thread...")
        threading.Thread(target=self._router_reconcile_worker, daemon=True, name="ips_router_reconcile_worker").start()

    @staticmethod
    def _is_arp_ipv4(a) -> bool:
        try:
            return not ipaddress.IPv4Address(a).is_link_local
        except (ValueError, TypeError):
            return False

    @classmethod
    def _arp_target_ip(cls, ip: str, mac: str, ipv4_candidates=()) -> str:
        """The IPv4 address the ARP half of the tarpit forges its reply to. A dual-stack device's client_ip can be
        its fe80::/ULA address; the target stays registered under that key (every lookup by client_ip -- release,
        the safe-device auto-release, merge carry-over, status -- keeps working), and the ARP loop resolves the IPv4
        here on every round: the one the kernel's neighbour table holds for the MAC now, else the most recent IPv4
        the caller knew (known_ips, newest last; link-local skipped). Found 2026-10-07 on .94: the console would have
        tarpitted a wired test host by its fe80:: address -- the ARP half skipped it and only the IPv6 (NDP) half
        acted. Without any IPv4 the address is returned as is and the ARP half skips it: the NDP loop still covers
        the device by MAC."""
        if cls._is_arp_ipv4(ip):
            return ip
        found = l2_raw.ipv4_for_mac(mac)
        if cls._is_arp_ipv4(found):
            return found
        try:
            candidates = list(ipv4_candidates or ())   # a live BoundedSet can change while copied
        except RuntimeError:
            candidates = []
        for cand in reversed(candidates):
            if cls._is_arp_ipv4(cand):
                return cand
        return ip

    @classmethod
    def _arp_ip_hint(cls, ip: str, mac: str, ipv4_candidates=()) -> Optional[str]:
        """IPv4 fallback stored with a target registered under a non-IPv4 address (meta "arp_ip"), for the rounds in
        which the neighbour table has no entry for its MAC. None when the key is already IPv4 or nothing resolves."""
        if cls._is_arp_ipv4(ip):
            return None
        found = cls._arp_target_ip(ip, mac, ipv4_candidates)
        return found if cls._is_arp_ipv4(found) else None

    # ------------------------------------------------------------------------------------------ per-device registry
    def _device_macs(self, dev_id: str, fallback_mac: Optional[str] = None) -> List[str]:
        """Every MAC the device is known by now (StateManager.macs_of: its MAC and every MAC the MAC index binds to
        it), lower case; the caller's MAC only when the state knows none (a device not in this process's state yet)."""
        macs: List[str] = []
        macs_of = getattr(self.state_manager, "macs_of", None)
        if macs_of is not None and _ct._usable(dev_id):
            try:
                macs = sorted({_ct.norm_mac(m) for m in macs_of(dev_id) if _ct._usable(m)})
            except Exception as exc:
                LOGGER.debug("macs_of(%s) failed: %s", dev_id, exc)
        fallback = _ct.norm_mac(fallback_mac)
        if not macs and _ct._usable(fallback):
            macs = [fallback]
        return macs

    def _ipv4_hint(self, ip: Optional[str], mac: str, ipv4_candidates=()) -> Optional[str]:
        """The IPv4 the ARP half uses for `mac` when the kernel's neighbour table has none: `ip` when it is IPv4, else
        the newest IPv4 among the device's known addresses (see _arp_target_ip)."""
        if self._is_arp_ipv4(ip):
            return ip
        return self._arp_ip_hint(ip or "", mac, ipv4_candidates)

    def _register_tarpit(self, dev_id: str, mac: Optional[str], hostname: str, reason: str,
                         ip: Optional[str] = None, ipv4_candidates=(),
                         alert_ref: Optional[dict] = None,
                         mode: str = _ct.TARPIT_MODE) -> "tuple[bool, Optional[str]]":
        """Creates or refreshes the device's tarpit entry ("dev:<id>"). Returns (created, key); (False, None) when the
        device has no id or no known MAC (the tarpit acts on MACs). Refreshing sets the MACs to what the device is
        known by now -- never another device's: an address that changed hands never moves containment.

        `mode` (T2) is the containment scope: TARPIT_MODE cuts all traffic (peers + gateways + the box itself);
        BLOCK_INTERNET_MODE cuts only the internet path (gateways / IPv6 routers), leaving LAN and this box reachable.
        A refresh keeps the mode the entry was created with -- it never silently widens or narrows containment."""
        macs = self._device_macs(dev_id, mac)
        if not _ct._usable(dev_id) or not macs:
            return False, None
        key = _ct.tarpit_key(dev_id)
        hint = self._ipv4_hint(ip, _ct.norm_mac(mac) or macs[0], ipv4_candidates)
        hint_mac = _ct.norm_mac(mac) if _ct.norm_mac(mac) in macs else macs[0]
        with self._lock:
            # an entry of this device still under an older key (another process wrote it) is the same entry
            self._tarpit_active_targets = _ct.normalize_tarpit_targets(self._tarpit_active_targets)
            cur = self._tarpit_active_targets.get(key)
            if cur is not None:
                cur["macs"], cur["mac"] = macs, macs[0]
                cur["hostname"] = hostname if _ct._usable(hostname) else cur.get("hostname", "unknown")
                if hint:
                    cur.setdefault("arp_ips", {})[hint_mac] = hint
                self._save_queues()
                return False, key
            graph_action_id = self._mirror_containment(dev_id, action_type="tarpit", status="active",
                                                       target=",".join(macs), reason=reason)
            entry = {"dev_id": dev_id, "hostname": hostname, "macs": macs, "mac": macs[0], "since": time.time(),
                     "status": _ct.REQUESTED, "mode": mode, "_graph_action_id": graph_action_id}
            if _ct._usable(ip):
                entry["registered_ip"] = ip
            if hint:
                entry["arp_ips"] = {hint_mac: hint}
            if alert_ref:
                entry["alert"] = dict(alert_ref)          # what caused it (None for an operator's own action)
            self._tarpit_active_targets[key] = entry
            self._save_queues()
        try:
            ips_tarpit_active.labels(device=dev_id, hostname=hostname, mac=macs[0]).set(1.0)
            ips_tarpit_activations_total.labels(device=dev_id, hostname=hostname, mac=macs[0]).inc()
        except Exception:
            pass
        return True, key

    def _pop_tarpit_entries(self, keys) -> List[dict]:
        """Caller holds self._lock. Removes the entries and their gauges; returns their metas."""
        out = []
        for key in keys:
            meta = self._tarpit_active_targets.pop(key, None)
            if meta is None:
                continue
            out.append(meta)
            try:
                ips_tarpit_active.labels(meta.get("dev_id", ""), meta.get("hostname", ""), meta.get("mac", "")).set(0.0)
                ips_tarpit_active.remove(meta.get("dev_id", ""), meta.get("hostname", ""), meta.get("mac", ""))
            except Exception:
                pass
        if out:
            self._save_queues()
        return out

    def _tarpit_keys_for(self, dev_ids=(), macs=()) -> List[str]:
        """Caller holds self._lock. Keys of the tarpit entries of these devices (by id) or holding one of these MACs."""
        dev_ids = {d for d in dev_ids if _ct._usable(d)}
        macs = {_ct.norm_mac(m) for m in macs if _ct._usable(m)}
        return [k for k, m in self._tarpit_active_targets.items()
                if isinstance(m, dict) and (m.get("dev_id") in dev_ids or macs & set(_ct.entry_macs(m)))]

    def reload_ips_state(self, ips_state: Dict[str, Any]) -> None:
        """The engine re-reads containment written by another process (web UI / console / Telegram), re-keyed by
        device. Replaces pipeline.py's direct assignment of the raw dicts."""
        with self._lock:
            self._tarpit_active_targets = _ct.normalize_tarpit_targets(ips_state.get("tarpit_targets", {}) or {})
            self._router_isolated_devices = ips_state.get("router_isolated_devices", {})
            self._operator_released_devices = ips_state.get("operator_released_devices", {})
            if self._tarpit_active_targets != (ips_state.get("tarpit_targets", {}) or {}):
                self._save_queues()

    def pop_containment_events(self) -> List[dict]:
        """Containment events for the engine to alert on (a contained device the tarpit does not reach)."""
        out = []
        while self._containment_events:
            out.append(self._containment_events.popleft())
        return out

    def _publish_engine_tarpit_state(self) -> None:
        """The engine's instance records whether its tarpit is armed in the shared IPS state, for state-only instances
        in the API process (see __init__). Written at every engine start, so a restart without raw-socket access
        turns it off again."""
        try:
            self.state_manager.update_ips_state_atomic(
                {ENGINE_TARPIT_STATE_KEY: {"armed": bool(self.tarpit_armed), "updated_at": time.time()}})
        except Exception as exc:
            LOGGER.warning("Could not publish the tarpit's armed state: %s", exc)

    def _init_arp_tarpit(self) -> None:
        # BUGFIX (live audit): tarpit_armed is what the boot-time Telegram status
        # message reads -- must reflect whether this subsystem can ACTUALLY function,
        # not just "the constructor didn't raise." Real (functional) check.
        self.tarpit_armed = False
        tarpit_enabled = bool(self.config.get("ips_tarpit_enabled", True))
        ips_tarpit_status.set(1.0 if tarpit_enabled else 0.0)

        if not tarpit_enabled:
            LOGGER.info("🛡️ Layer-2 ARP/NDP Tarpit subsystem disabled via configuration.")
            return

        if not L2_AVAILABLE:
            LOGGER.warning("⚠️ Layer-2 Tarpit disabled: this platform has no AF_PACKET raw sockets (Linux only)")
            ips_tarpit_status.set(0.0)
            return

        # BUGFIX (live audit): the old code claimed "RAW socket access verified" right
        # after `conf.verb = 0` -- which doesn't touch a socket at all, so this always
        # logged "ARMED" regardless of whether the process actually had CAP_NET_RAW.
        # A permission failure would only surface later, deep inside sniff()/send()
        # calls on the background threads, with no correction to this claim. Actually
        # attempt a raw socket open/close here so a real permission problem (e.g. not
        # running as root, no CAP_NET_RAW) is caught and reported honestly right now.
        try:
            import socket as _socket
            probe = _socket.socket(_socket.AF_PACKET if hasattr(_socket, "AF_PACKET") else _socket.AF_INET,
                                    _socket.SOCK_RAW, 0x0003 if hasattr(_socket, "AF_PACKET") else 0)
            probe.close()
        except PermissionError:
            LOGGER.error("⚠️ Layer-2 Tarpit disabled: no permission to open a raw socket "
                         "(needs root or CAP_NET_RAW).")
            ips_tarpit_status.set(0.0)
            return
        except Exception as exc:
            LOGGER.error("⚠️ Layer-2 Tarpit disabled: raw socket probe failed: %s", exc)
            ips_tarpit_status.set(0.0)
            return

        try:
            LOGGER.info("🛡️ RAW socket access verified. Layer-2 Dual-Stack (ARP & NDP) Tarpit module ARMED.")
            self.tarpit_armed = True

            self._tarpit_thread = threading.Thread(target=self._arp_tarpit_loop, daemon=True, name="arp_tarpit_worker")
            self._tarpit_thread.start()
            
            self._ndp_tarpit_thread = threading.Thread(target=self._ndp_tarpit_loop, daemon=True, name="ndp_tarpit_worker")
            self._ndp_tarpit_thread.start()

            # T1: what the contained devices' frames show (holding / not reaching / ...), see _observer_loop
            self._observer_thread = threading.Thread(target=self._observer_loop, daemon=True,
                                                     name="containment_observer")
            self._observer_thread.start()

            # T2: observe the segment (peers + IPv6 routers), answer reactively, counter-fake re-announcements.
            self._segment_thread = threading.Thread(target=self._segment_loop, daemon=True,
                                                    name="containment_segment")
            self._segment_thread.start()

        except Exception as exc:
            LOGGER.error("⚠️ Dual-Stack Tarpit bypassing. Lacks raw socket privileges: %s", exc)
            ips_tarpit_status.set(0.0)
            self.tarpit_armed = False

    def _ndp_tarpit_loop(self) -> None:
        """Answers a contained device's IPv6 Neighbor Solicitations with a forged advertisement.
        Kernel-side BPF drops everything but NS frames, so Python only ever sees candidates."""
        bogus_mac = "00:11:22:33:44:55"
        try:
            sock = l2_raw.open_raw()
            l2_raw.attach_ns_filter(sock)
        except Exception as exc:
            LOGGER.debug("NDP Tarpit socket exception: %s", exc)
            return
        while True:
            try:
                frame, ifname = l2_raw.recv_frame(sock)
                ns = l2_raw.parse_neighbor_solicitation(frame)
                if not ns:
                    continue
                # T2: answer only when the asking device is contained AND the solicited address is in its scope --
                # l2_enforcer.reactive_spec decides (a Tarpit answers for any address; Block internet only for a
                # router, leaving LAN IPv6 open). Before modes this answered every NS from a contained MAC.
                with self._lock:
                    metas = [m for m in self._tarpit_active_targets.values()
                             if isinstance(m, dict) and ns["eth_src"].lower() in _ct.entry_macs(m)]
                if not metas:
                    continue
                peers, gws = self._peer_table.active(), self._gateways_now()
                if not any(_l2e.reactive_spec("ns", ns["eth_src"], ns["target"], meta, peers, gws) for meta in metas):
                    continue
                dst_ip = ns["ip_src"] if ns["ip_src"] != "::" else "ff02::1"
                na = l2_raw.build_neighbor_advertisement(
                    eth_src=bogus_mac, eth_dst=ns["eth_src"], ip_src=ns["target"], ip_dst=dst_ip,
                    target=ns["target"], lladdr=bogus_mac)
                l2_raw.send_frame(sock, ifname, na)
            except Exception as exc:
                LOGGER.debug("NDP Tarpit iteration exception: %s", exc)
                time.sleep(0.5)

    def sync_state_from_manager(self) -> None:
        """Synchronizes in-memory IPS targets with disk state modified by external processes."""
        with self._lock:
            ips_state = self.state_manager.get_ips_state()
            disk_tarpits = _ct.normalize_tarpit_targets(ips_state.get("tarpit_targets", {}) or {})
            disk_router = ips_state.get("router_isolated_devices", {})
            disk_released = ips_state.get("operator_released_devices", {})
            
            # Sync operator released devices so release cooldown is preserved across state syncs
            self._operator_released_devices.update(disk_released)

            # Remove stale tarpit targets not in disk state
            for ip in list(self._tarpit_active_targets.keys()):
                if ip not in disk_tarpits:
                    meta = self._tarpit_active_targets.pop(ip, {})
                    try:
                        ips_tarpit_active.labels(meta.get("dev_id", ""), meta.get("hostname", ""), meta.get("mac", "")).set(0.0)
                        ips_tarpit_active.remove(meta.get("dev_id", ""), meta.get("hostname", ""), meta.get("mac", ""))
                    except Exception:
                        pass

            # Remove stale router isolated targets not in disk state
            for mac in list(self._router_isolated_devices.keys()):
                if mac not in disk_router:
                    meta = self._router_isolated_devices.pop(mac, {})
                    try:
                        ips_router_isolated_active.labels(meta.get("dev_id", ""), meta.get("hostname", ""), mac).set(0.0)
                        ips_router_isolated_active.remove(meta.get("dev_id", ""), meta.get("hostname", ""), mac)
                    except Exception:
                        pass

    def _sync_metrics_from_state(self) -> None:
        try:
            self.sync_state_from_manager()
            LOGGER.debug("Synchronizing Prometheus gauges with current IPS state store.")
            ips_state = self.state_manager.get_ips_state()
            
            for domain, meta in ips_state.get("blocked_domains", {}).items():
                ips_active_blocks_gauge.labels(device=meta.get("device_id", ""), hostname=meta.get("hostname", ""), domain=domain).set(1.0)
            
            for domain, meta in self._retry_queue.items():
                ips_queue_status_gauge.labels(device=meta.get("device_id", ""), hostname=meta.get("hostname", ""), domain=domain).set(meta.get("attempts", 1))
                
            for domain, meta in self._dead_letter.items():
                ips_dead_letter_gauge.labels(device=meta.get("device_id", ""), hostname=meta.get("hostname", ""), domain=domain).set(1.0)

            for ip, meta in self._tarpit_active_targets.items():
                ips_tarpit_active.labels(device=meta.get("dev_id", ""), hostname=meta.get("hostname", ""), mac=meta.get("mac", "")).set(1.0)

            for mac, meta in self._router_isolated_devices.items():
                ips_router_isolated_active.labels(device=meta.get("dev_id", ""), hostname=meta.get("hostname", ""), mac=mac).set(1.0)
                
            ips_pihole_status.set(1.0 if self.config.get("ips_pihole_enabled", True) else 0.0)
            ips_router_status.set(1.0 if self.config.get("ips_router_enabled", False) else 0.0)
        except Exception as exc:
            LOGGER.error("Failed to synchronize IPS metrics: %s", exc)

    def _mirror_containment(self, device_id: str, action_type: str, status: str,
                              target: Optional[str] = None, reason: Optional[str] = None) -> Optional[str]:
        """IPS containment unification: best-effort
        write-only mirror of a containment action THIS CLASS HAS ALREADY TAKEN
        into GraphStore.containment_actions -- never gates or affects the real
        action, which has already happened by the time every call site below
        calls this. No-ops (returns None) when self._graph_store is None (every
        pre-existing caller). The real containment state (self.state_manager's
        ips_state dict) is unaffected by a graph failure here, but the failure is
        logged at WARNING: a mirror that fails silently at DEBUG went unnoticed for
        weeks in the identity-merge mirror (graph and engine then disagreed on 33 of
        113 merges on .94, 2026-10-05), and the console reads containment history
        from the graph. Returns the new action_id, or None if not mirrored (no
        graph_store, or a failure)."""
        if self._graph_store is None:
            return None
        try:
            return self._graph_store.insert_containment_action(
                device_id=device_id, action_type=action_type, status=status,
                target=target, reason=reason,
            )
        except Exception as exc:
            LOGGER.warning("Containment graph mirror failed (device=%s, action_type=%s): %s",
                           device_id, action_type, exc)
            return None

    def _mirror_containment_released(self, action_id: Optional[str]) -> None:
        """Companion to _mirror_containment() -- marks a previously-mirrored
        action_id 'released'. No-ops silently if action_id is None (no
        graph_store, or the original mirror call itself failed/was never made --
        there's nothing to update in either case)."""
        if self._graph_store is None or not action_id:
            return
        try:
            self._graph_store.update_containment_status(action_id, "released")
        except Exception as exc:
            LOGGER.warning("Containment graph release-mirror failed (action_id=%s): %s", action_id, exc)

    def _save_queues(self):
        with self.state_manager._global_lock:
            LOGGER.debug("Flushing active queues and router isolation states into StateManager.")
            ips_state = self.state_manager.get_ips_state()
            ips_state["retry_queue"] = self._retry_queue
            ips_state["dead_letter"] = self._dead_letter
            ips_state["tarpit_targets"] = self._tarpit_active_targets
            ips_state["router_isolated_devices"] = self._router_isolated_devices
            ips_state["operator_released_devices"] = self._operator_released_devices
            self.state_manager.save_ips_state(ips_state)

    def _router_reconcile_worker(self) -> None:
        """BUGFIX (live audit): `_router_isolated_devices` is a LATCHED state (see
        release_device()'s own docstring) -- it only clears via this IDS's OWN
        _unisolate_device_router() call, never by observing what Fritz!Box's WAN
        access filter actually says right now. Confirmed live: an operator toggling
        a device's block off directly in the Fritz!Box admin UI (bypassing this IDS
        entirely) left the device permanently shown as "still isolated" in Grafana's
        containment panel, since nothing ever told this dict to forget it. Polls
        Fritz!Box's real state periodically and drops any entry Fritz!Box no longer
        actually has isolated, instead of assuming this IDS is the only actor that
        can ever change it."""
        interval = float(self.config.get("router_reconcile_interval_seconds", 300.0))
        if interval <= 0:
            interval = 300.0
        while True:
            time.sleep(interval)
            if not self.config.get("ips_router_enabled", False):
                continue
            try:
                self.reconcile_router_isolation_state()
            except Exception as e:
                LOGGER.debug("Router isolation reconcile pass failed: %s", e)

    def reconcile_router_isolation_state(self) -> int:
        """Queries Fritz!Box's actual current WAN-access-filter state for every
        device this IDS still THINKS is router-isolated, and clears any that
        Fritz!Box no longer has blocked. Returns how many stale entries were
        cleared. Public (not just the worker's private call) so it can also be
        triggered on-demand, e.g. from a future Telegram /sync command."""
        with self._lock:
            targets = [(mac, dict(meta)) for mac, meta in self._router_isolated_devices.items()]

        fastapi_port = int(self.config.get("fastapi_port", 8010))
        api_token = self.config.get("fritz_api_token", "")
        headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
        # BUGFIX (live audit, 2026-09-04): this used to reuse router_webhook_timeout_seconds
        # (5.0s, tuned for the isolate/unisolate SET webhook) for this read-only status
        # QUERY too -- confirmed live this Fritzbox's TR-064 GetWANAccessByIP genuinely
        # takes ~10s round-trip, so every single reconcile attempt silently timed out and
        # was swallowed by the bare `except Exception` below (logged at DEBUG, invisible
        # at the service's normal INFO level) -- example_pc's stale "still isolated" record
        # never actually cleared despite this worker running on schedule and Fritz!Box
        # correctly reporting it unblocked. Own, more generous timeout for this query
        # specifically; the SET actions' own timeout is untouched.
        timeout_seconds = float(self.config.get("router_status_query_timeout_seconds", 20.0))
        if timeout_seconds <= 0:
            timeout_seconds = 20.0

        cleared = 0
        for mac, meta in targets:
            ip = meta.get("ip")
            hostname = meta.get("hostname", "unknown")
            dev_id = meta.get("dev_id", "unknown")
            if not ip or ip == "unknown":
                continue
            try:
                status_url = f"http://127.0.0.1:{fastapi_port}/api/ipc/router_isolation_status"
                resp = self.session.get(status_url, params={"ip": ip}, headers=headers, timeout=timeout_seconds)
                if resp.status_code != 200:
                    # Query itself failed (Fritz!Box unreachable, etc.) -- leave the
                    # existing state alone rather than guess; a real un-isolation
                    # will still clear it via _unisolate_device_router() as normal.
                    # BUGFIX (live audit): this used to be a silent `continue` -- the
                    # exact same silence that let the timeout above go unnoticed for
                    # as long as it did. A non-200 here is still worth an operator's
                    # attention (bad token, Fritz!Box auth failure, etc.), just not
                    # worth treating the record as cleared.
                    LOGGER.warning(
                        "🔄 [RECONCILE] Status query for %s (%s) returned HTTP %d -- "
                        "leaving existing router-isolation record as-is this pass.",
                        hostname, ip, resp.status_code,
                    )
                    continue
                if not bool(resp.json().get("isolated", True)):
                    with self._lock:
                        if mac in self._router_isolated_devices:
                            del self._router_isolated_devices[mac]
                            self._save_queues()
                    try:
                        ips_router_isolated_active.labels(dev_id, hostname, mac).set(0.0)
                        ips_router_isolated_active.remove(dev_id, hostname, mac)
                    except Exception:
                        pass
                    cleared += 1
                    LOGGER.warning(
                        "🔄 [RECONCILE] %s (%s) reported no longer isolated by Fritz!Box directly -- "
                        "clearing stale IDS-side router-isolation record.", hostname, ip
                    )
            except Exception as e:
                # BUGFIX (live audit): was LOGGER.debug() -- invisible at this service's
                # normal INFO level, which is exactly how a real, currently-active
                # failure mode (the timeout this fix addresses) went unnoticed through
                # every scheduled reconcile pass since this worker was built. A query
                # failure here means a stale record will keep showing wrong in Grafana
                # for at least one more interval -- worth a WARNING every time, not a
                # DEBUG line nobody's log level will ever surface.
                LOGGER.warning(
                    "🔄 [RECONCILE] Status query failed for %s (%s): %s: %s",
                    hostname, ip, type(e).__name__, e,
                )
        return cleared

    def _ensure_tarpit_target(self, client_ip: str, mac_addr: str, hostname: str, dev_id: str) -> None:
        """Refresh the device's tarpit entry (its current MACs and IPv4 hint)."""
        self._register_tarpit(dev_id, mac_addr, hostname, reason="refresh", ip=client_ip)

    def _arm_tarpit_for_dual_stack_coverage(self, client_ip: str, mac_addr: str, hostname: str,
                                              dev_id: str, reason: str, alert_ref: Optional[dict] = None) -> bool:
        """Registers `client_ip` as a Layer-2 ARP/NDP tarpit target as a side effect of a
        SEPARATE containment decision (router isolation) that already decided this device
        is severe enough to cut off -- not gated on the tarpit mechanism's own,
        independently-tuned risk_score threshold.

        2026-09-16 (router-agnostic IPv6 device-identity plan,
        Documentation/IPV6_DEVICE_IDENTITY_PLAN.md): router isolation is a real
        requests.post() to Fritz!Box's TR-064 `DisallowWANAccessByIP` action -- IPv4-only
        by construction (the parameter is literally NewIPv4Address; see
        middleware/routers/fritzbox_api.py's execute_fritzbox_isolation()). Once a device
        is dual-stack, that call blocks its IPv4 WAN path but leaves its IPv6 path
        completely open -- a real bypass for the exact device a containment decision just
        judged severe enough to isolate. Confirmed live in mitigate() before this fix:
        router isolation fires at risk_score>=8.5, but the tarpit block below has its OWN,
        stricter, separate risk_score>=9.0 gate -- so a device isolated at 8.5-8.99 got
        ZERO IPv6 coverage at all, not partial.

        Rather than chasing an AVM-specific IPv6 TR-064 action (undocumented, vendor-
        specific, exactly what feedback_network_agnostic_design warns against), the fix is
        router-agnostic: this box's own Layer-2 ARP/NDP tarpit (_ndp_tarpit_loop, raw
        sockets directly on this box's own NIC, no router cooperation needed at all)
        already covers IPv6 neighbor-discovery disruption for ANY router vendor -- it just
        needs to be armed here too, as a direct consequence of "we decided to isolate this
        device," not left to its own separate score bar. Both callers (mitigate()'s
        autonomous path and operator_isolate_router()'s console-button path) get identical
        coverage this way. Idempotent against mitigate()'s own later, independent tarpit
        block (whichever runs first wins; both check `client_ip not in
        _tarpit_active_targets` the same way) and against calling this twice for the same
        device (e.g. an operator re-clicking Isolate on an already-isolated one).

        Silently no-ops (not an error) when tarpit itself is disabled/unavailable, or when
        the operator has explicitly opted out of this specific coupling via
        ips_tarpit_follows_router_isolation=false -- router isolation's OWN success is
        never affected either way, this only ever adds coverage on top of it. Returns
        True only when it genuinely armed a NEW tarpit target just now (so a caller like
        operator_isolate_router() can tell the operator honestly whether dual-stack
        coverage was actually applied, not just attempted) -- False for every no-op
        reason (disabled, unavailable, already tarpitted, missing identifiers)."""
        if not bool(self.config.get("ips_tarpit_follows_router_isolation", True)):
            return False
        if not bool(self.config.get("ips_tarpit_enabled", True)):
            return False
        if not (L2_AVAILABLE or bool(self.config.get("simulation_mode", False))):
            return False
        # BLOCK_INTERNET_MODE (T2): this coverage rides on router isolation, which cuts the WAN/internet path only --
        # the matching same-segment scope fakes just the gateways / IPv6 routers, never the device's LAN peers or the
        # box. (Before modes existed this path shared the tarpit's gateway-only ARP loop, so behaviour is unchanged
        # until peers are observed; it never widens to a full tarpit.)
        created, _key = self._register_tarpit(dev_id, mac_addr, hostname, reason=reason, ip=client_ip,
                                              alert_ref=alert_ref, mode=_ct.BLOCK_INTERNET_MODE)
        if not created:
            return False
        LOGGER.critical(
            "⚠️ [DUAL-STACK COVERAGE] Layer-2 block-internet coverage also armed for %s (%s) alongside router "
            "isolation -- covers this device's IPv6 internet path, which the router-level block alone cannot.",
            hostname, client_ip)
        return True

    def get_containment_status(self, client_ip: str, mac_addr: str = "unknown", domain: str = "", dev_id: str = "",
                               incident_id: Optional[str] = None) -> str:
        """Returns readable Telegram containment badge (TARPITTED, ROUTER ISOLATED, both
        together, DOMAIN BLOCKED, or UNBLOCKED).

        Dashboard/alert-buttons fix: added a dev_id fallback. The primary lookups are
        keyed by raw client_ip (tarpit) / mac_addr (router isolation), which can miss a
        genuinely-contained device on an identifier mismatch -- e.g. this alert's own
        client_ip/mac_addr differ slightly from whatever the device was isolated under
        in an earlier incident (a DHCP lease change, or the MAC not yet re-resolved this
        cycle). Both _tarpit_active_targets/_router_isolated_devices entries already
        store a "dev_id" field (see mitigate()), so when the direct key misses, scan by
        dev_id instead before concluding the device is genuinely unblocked.

        BUGFIX (2026-09-16, router-agnostic IPv6 device-identity plan): this used to
        return ONLY "TARPITTED" whenever tarpit was active, even if router isolation was
        ALSO active for the same device -- true and harmless back when the two mechanisms
        fired independently on different, disjoint conditions, but actively misleading now
        that _arm_tarpit_for_dual_stack_coverage() makes "tarpitted alongside router
        isolation" the routine case, not a rare coincidence. An operator reading only
        "TARPITTED" would have no way to know the device's IPv4 WAN path was ALSO cut off
        at the router -- an understatement of what containment is actually in place, the
        same class of accuracy bug this session's earlier WHY-block fix closed for
        evidence text. Checks both independently now and joins whichever are true, instead
        of returning on the first match."""
        macs = self._device_macs(dev_id, mac_addr)
        with self._lock:
            view = {"tarpit_targets": self._tarpit_active_targets,
                    "router_isolated_devices": self._router_isolated_devices}
            # by device id or one of its MACs -- never by address (the next holder of an address is another device)
            is_tarpitted = _ct.tarpitted(view, dev_id, macs) is not None
            is_router_isolated = _ct.router_isolated(view, dev_id, macs) is not None
            if is_tarpitted and is_router_isolated:
                return "🔒 ROUTER ISOLATED (router internet block) + TARPITTED (Layer-2 ARP/NDP, IPv6 coverage)"
            if is_tarpitted:
                return "🔒 TARPITTED (Layer-2 ARP/NDP)"
            if is_router_isolated:
                return "🔒 ROUTER ISOLATED (router internet block)"
        # C5 FIX: _blocked_domains was never an attribute on IPSMitigator;
        # blocked domains live in state_manager IPS state.
        if domain and domain not in ("unknown", ""):
            ips_state = self.state_manager.get_ips_state()
            meta = ips_state.get("blocked_domains", {}).get(domain)
            if meta is not None:
                # "Blocked" only when THIS alert's incident caused the block (2026-10-12): the domain being on the
                # list since an earlier, unrelated alert is not this alert's action.
                caused_by = ((meta.get("alert") or {}).get("incident_id")) if isinstance(meta, dict) else None
                if incident_id is None or (caused_by and caused_by == incident_id):
                    return "🔒 DOMAIN BLOCKED (Pi-hole DNS)"
                return "🔒 DOMAIN ALREADY ON BLOCKLIST (earlier alert, Pi-hole DNS)"
        return "🔓 ACTIVE / UNBLOCKED (Monitoring Only)"

    def mitigate(
        self,
        st: Any,
        target_domain: str,
        risk_score: float,
        lateral_threat: bool,
        is_safe: bool,
        ti_engine: Optional[Any] = None,
        reason: str = "High Risk Identified",
        fp_verdict: Optional[dict] = None,
        decision_state: str = "SUSPICIOUS",
        alert_ref: Optional[dict] = None,
    ) -> Dict[str, Any]:
        """Autonomous containment for one alert. `alert_ref` names the alert ({"incident_id", "signature",
        "target_source", "evidence_types"}) and is recorded with every block / isolation / tarpit this call creates.
        Returns {"actions": graph containment action ids this call created, "domain_blocked": the domain this call
        blocked or None, "pending_domain_block": the domain waiting for a person (interactive mode) or None}."""
        result: Dict[str, Any] = {"actions": [], "domain_blocked": None, "pending_domain_block": None}
        LOGGER.debug("Mitigate evaluation triggered | Device: %s, Domain: %s, Risk: %.2f, Safe: %s", 
                     getattr(st, "hostname", "unknown"), target_domain, risk_score, is_safe)

        # FP ENGINE TIGHT GATING: Abort mitigation immediately if FP engine suppressed alert
        if fp_verdict and fp_verdict.get("suppress", False):
            LOGGER.info("🛡️ [IPS] Mitigation suppressed by FP Engine verdict for device %s.", getattr(st, "hostname", "unknown"))
            return result

        client_ip = getattr(st, "client_ip", "unknown")
        hostname = getattr(st, "hostname", "unknown")
        dev_id = getattr(st, "device_id", "unknown")
        mac_addr = getattr(st, "mac_address", "unknown")
        device_type = str(getattr(st, "device_type", "unknown") or "unknown").lower()
        is_critical_device = device_type in CRITICAL_DEVICE_TYPES

        # The device's MACs come from the state (T1, 2026-10-12). This used to FABRICATE a MAC from the device id when
        # the MAC was unknown (any 12-hex-character id -- every hashed id), so containment could act on a MAC no
        # device has.
        device_macs = self._device_macs(dev_id, mac_addr)
        if (not mac_addr or mac_addr == "unknown") and device_macs:
            mac_addr = device_macs[0]

        # LATCHED CONTAINMENT PROTECTION:
        # Containment (Layer-2 tarpit, router internet block) cuts the device's internet traffic (CONTAINMENT_MODEL.md
        # section 1: today the IPv4 tarpit fakes only the gateway, so local IPv4 traffic continues).
        # As a result, feature query rates naturally decay to 0 over the 5-minute rolling window.
        # Automatically releasing hardware/tarpit isolation purely on zero-traffic decay creates an infinite flapping loop:
        # (ISOLATE -> 0 TRAFFIC -> DECAY TO 0 -> AUTO UNISOLATE -> C2 BEACON AGAIN -> RE-ISOLATE).
        # Therefore, hardware router isolation and Layer-2 tarpits are LATCHED containment states:
        # They are ONLY auto-released if the device is explicitly marked safe (is_safe=True via safe_ips/patterns)
        # or via an explicit operator un-isolation command.
        if is_safe:
            should_unisolate_router = False
            tarpit_meta = None
            with self._lock:
                # this device's entries (by id or MAC; _pop_tarpit_entries also clears the gauges)
                popped = self._pop_tarpit_entries(self._tarpit_keys_for([dev_id], device_macs))
                if popped:
                    LOGGER.info("Device %s marked safe. Releasing from ARP/NDP Tarpit.", hostname)
                    tarpit_meta = popped[0]
                if mac_addr in self._router_isolated_devices:
                    should_unisolate_router = True

            # AUDIT FIX #8's own precedent (see release_device()): I/O (here, the
            # graph write) happens OUTSIDE self._lock.
            if tarpit_meta is not None:
                self._mirror_containment_released(tarpit_meta.get("_graph_action_id"))

            if should_unisolate_router:
                LOGGER.info("Device %s marked safe. Initiating router un-isolation restore.", hostname)
                self._unisolate_device_router(mac=mac_addr, ip=client_ip, hostname=hostname, dev_id=dev_id, reason="device_marked_safe")
            return result

        # Check operator release cooldown status quietly
        now = time.time()
        cooldown_sec = float(self.config.get("operator_release_cooldown_seconds", 3600.0))
        with self._lock:
            released_snapshot = dict(self._operator_released_devices)
        # by device id or one of its MACs -- an address is reused and a name shared ("android-..."), so keying by
        # them gave another device an hour without autonomous containment (T1, 2026-10-12)
        is_operator_released = _ct.released_recently(released_snapshot, dev_id, device_macs, cooldown_sec, now)

        # ONBOARDING GRACE PERIOD (PRODUCTIZATION_ROADMAP.md Phase 4): a brand-new
        # network hasn't had time to build a real baseline yet, so every autonomous
        # containment mechanism -- Pi-hole, router isolation, AND the Layer-2 tarpit --
        # stays off regardless of decision_state while onboarding is active. Broader than
        # PRODUCT_ARCHITECTURE.md's original two-mechanism sketch (ips_pihole_enabled/
        # ips_router_enabled only) -- the tarpit is the single most disruptive mechanism
        # here (it can genuinely break a real device's connectivity), so it would defeat
        # the whole point of a "don't act on an unfamiliar network yet" grace period to
        # leave it exempt. Detection/alerting/Telegram are completely unaffected -- this
        # gates action only, same as every other per-mechanism toggle below.
        onboarding_state_dir = str(Path(self.config.get("state_path", "state/ids_state.json")).parent)
        onboarding_active = is_onboarding_active(self.config, onboarding_state_dir)
        if onboarding_active:
            LOGGER.debug(
                "🕒 [ONBOARDING] Autonomous mitigation withheld for %s -- grace period "
                "still active (alert-only).", hostname
            )

        interactive_mode = bool(self.config.get("interactive_blocking_enabled", False))
        pihole_enabled = (
            bool(self.config.get("ips_pihole_enabled", True))
            and bool(self.config.get("ips_enabled", True))
            and not onboarding_active
        )

        # SEVERITY-GATED BLOCKING: a complete safe-domain list can never exist, so blocking
        # cannot rely on "not on the allowlist" as its bar — that blocks anything merely
        # unrecognized, which risks breaking a device's normal function on nothing more than
        # CL-AFPE failing to suppress it. Pi-hole blocking now requires the decision engine's
        # own corroborated verdict (HIGH/CRITICAL — reached only via a hard-stop, a confirmed
        # reputation tier, or >=2 independent evidence sources scoring >=3.0; see
        # argus/decision/engine.py) before it will act at all. A SUSPICIOUS/monitor verdict — a
        # single uncorroborated signal — is alerted on but never blocks: it stays under
        # observation until either it escalates on its own evidence or CL-AFPE/Ollama clears it.
        if pihole_enabled and target_domain and target_domain not in ("unknown", "-"):
            if decision_state not in ("HIGH", "CRITICAL"):
                LOGGER.debug(
                    "🛡️ [IPS] Pi-hole block withheld for %s: decision state '%s' has not reached "
                    "HIGH/CRITICAL corroboration — monitoring only, no containment action taken.",
                    target_domain, decision_state
                )
            else:
                safe_domains = set(self.config.get("safe_domains", []))
                is_domain_safe = (target_domain in safe_domains) or (ti_engine and ti_engine.is_allowlisted(target_domain))

                if not is_domain_safe and interactive_mode:
                    # Interactive mode: a person approves every block (router isolation and the tarpit already waited;
                    # the domain block did not -- 2026-10-12). The engine offers it with an approval button.
                    result["pending_domain_block"] = target_domain
                    LOGGER.info("🛡️ [INTERACTIVE MODE] Pi-hole block of %s for %s queued for approval.",
                                target_domain, hostname)
                elif not is_domain_safe:
                    LOGGER.debug("Executing immediate Pi-hole block protocol for %s.", target_domain)
                    if self._block_domain(domain=target_domain, hostname=hostname, device_ip=client_ip, dev_id=dev_id,
                                          reason=reason, alert_ref=alert_ref):
                        meta = self.state_manager.get_ips_state().get("blocked_domains", {}).get(target_domain) or {}
                        if alert_ref and (meta.get("alert") or {}).get("incident_id") == alert_ref.get("incident_id"):
                            result["domain_blocked"] = target_domain
                            if meta.get("_graph_action_id"):
                                result["actions"].append(meta["_graph_action_id"])
                else:
                    LOGGER.debug("Mitigation suppressed: %s is on the Global Trust/Safe list.", target_domain)

        ips_on = bool(self.config.get("ips_enabled", True))
        router_enabled = ips_on and bool(self.config.get("ips_router_enabled", False)) and not onboarding_active
        if router_enabled and (risk_score >= 8.5 or lateral_threat):
            if is_operator_released and not lateral_threat:
                LOGGER.debug("🛡️ Router isolation suppressed for %s: Operator release cooldown active.", hostname)
            elif (interactive_mode or is_critical_device) and not lateral_threat:
                LOGGER.info(
                    "🛡️ [%s] Router isolation for %s (device_type=%s) queued for Telegram approval.",
                    "CRITICAL DEVICE" if is_critical_device and not interactive_mode else "INTERACTIVE MODE",
                    hostname, device_type,
                )
            elif mac_addr and mac_addr != "unknown":
                # BUGFIX (2026-09-10, AUDIT_V14_REVIEW_RESPONSE.md §2.6): _isolate_device_router()
                # is a real requests.post() to Fritz!Box (router_webhook_timeout_seconds,
                # default 5s) -- this used to run INSIDE self._lock, a single engine-wide
                # RLock every OTHER mitigation operation (Pi-hole blocking, tarpit
                # registration, release_device(), status queries) also acquires, so a
                # slow/unresponsive Fritz!Box stalled the entire IPS engine for up to that
                # timeout on every high-risk decision, not just router isolation.
                # Restructured to match operator_isolate_router()'s already-correct shape
                # (line ~676 below): check/reserve under the lock, release it, make the
                # network call unlocked, then re-acquire only to record the result.
                with self._lock:
                    already_isolated = mac_addr in self._router_isolated_devices
                if not already_isolated:
                    if is_operator_released and lateral_threat:
                        LOGGER.critical("🚨 [LATERAL THREAT OVERRIDE] Device %s attempted internal port scan during release cooldown! Router isolation re-enforced.", hostname)
                    LOGGER.critical("Extreme risk detected. Executing hardware router isolation for MAC %s.", mac_addr)
                    success = self._isolate_device_router(mac=mac_addr, ip=client_ip, hostname=hostname, dev_id=dev_id, reason=f"Risk Score {risk_score:.1f}: {reason}")
                    if success:
                        graph_action_id = self._mirror_containment(
                            dev_id, action_type="router_isolate", status="active",
                            target=mac_addr, reason=f"Risk Score {risk_score:.1f}: {reason}")
                        with self._lock:
                            self._router_isolated_devices[mac_addr] = {
                                "ip": client_ip, "hostname": hostname, "dev_id": dev_id,
                                "_graph_action_id": graph_action_id,
                                **({"alert": dict(alert_ref)} if alert_ref else {}),
                            }
                            self._save_queues()
                        if graph_action_id:
                            result["actions"].append(graph_action_id)
                        if self._arm_tarpit_for_dual_stack_coverage(
                                client_ip=client_ip, mac_addr=mac_addr, hostname=hostname, dev_id=dev_id,
                                reason=f"IPv6 coverage for router isolation: {reason}", alert_ref=alert_ref):
                            gid = (self._tarpit_active_targets.get(_ct.tarpit_key(dev_id)) or {}).get("_graph_action_id")
                            if gid:
                                result["actions"].append(gid)

        tarpit_enabled = ips_on and bool(self.config.get("ips_tarpit_enabled", True)) and not onboarding_active
        is_sim = bool(self.config.get("simulation_mode", False))
        if tarpit_enabled and (L2_AVAILABLE or is_sim) and (risk_score >= 9.0 or lateral_threat):
            if is_operator_released and not lateral_threat:
                LOGGER.debug("🛡️ Layer-2 Tarpit suppressed for %s: Operator release cooldown active.", client_ip)
            elif (interactive_mode or is_critical_device) and not lateral_threat:
                LOGGER.info(
                    "🛡️ [%s] Layer-2 Tarpit for %s (device_type=%s) queued for Telegram approval.",
                    "CRITICAL DEVICE" if is_critical_device and not interactive_mode else "INTERACTIVE MODE",
                    client_ip, device_type,
                )
            else:
                if not mac_addr or mac_addr == "unknown":
                    ips_errors_metric.labels(target_type="mac_unknown_tarpit").inc()
                    LOGGER.warning("⚠️ MAC address unknown for %s; tarpit activation deferred until a later Zeek/ARP identification update.", client_ip)
                else:
                    created, _key = self._register_tarpit(
                        dev_id, mac_addr, hostname, reason=reason, ip=client_ip,
                        ipv4_candidates=getattr(st, "known_ips", None) or (), alert_ref=alert_ref)
                    if created:
                        gid = (self._tarpit_active_targets.get(_key) or {}).get("_graph_action_id")
                        if gid:
                            result["actions"].append(gid)
                        if is_operator_released and lateral_threat:
                            LOGGER.critical("🚨 [LATERAL THREAT OVERRIDE] Device %s attempted internal port scan during release cooldown! Layer-2 Tarpit re-enforced.", hostname)
                        LOGGER.critical("⚠️ [DUAL-STACK TARPIT] Trapped compromised device %s (%s) in Layer-2 isolation.", hostname, dev_id)
        return result

    def operator_isolate_router(self, dev_id: str, ip: str, mac: str, hostname: str,
                                  reason: str = "Operator-requested router isolation") -> "tuple[bool, str]":
        """Console 'Isolate via Fritz!Box' button: explicit operator action, independent
        of mitigate()'s own risk-score/interactive-mode/cooldown gating -- those gates
        exist to keep the AUTONOMOUS decision path cautious, not a human who just clicked
        a button. Mirrors the bookkeeping mitigate() already does for its own
        router-isolation path (state dict entry, graph mirror, Prometheus gauge) so this
        device shows up identically to an autonomously-isolated one everywhere else
        (Grafana, get_containment_status(), the reconcile worker). Network I/O kept
        outside self._lock, same rationale as release_device()'s own AUDIT FIX #8.
        Returns (success, reason) -- reason is always populated on failure, for the API
        layer to surface directly rather than a bare 'failed'."""
        if not bool(self.config.get("ips_router_enabled", False)):
            return False, "Router isolation is disabled in config (ips_router_enabled=false)."
        if not mac or mac == "unknown":
            return False, "No known MAC address for this device -- router isolation needs one."
        with self._lock:
            if mac in self._router_isolated_devices:
                return True, "Already isolated."
        success = self._isolate_device_router(mac=mac, ip=ip, hostname=hostname, dev_id=dev_id, reason=reason)
        if not success:
            return False, "The router refused or was unreachable for this action -- see server logs for detail."
        graph_action_id = self._mirror_containment(dev_id, action_type="router_isolate", status="active", target=mac, reason=reason)
        with self._lock:
            self._router_isolated_devices[mac] = {"ip": ip, "hostname": hostname, "dev_id": dev_id, "_graph_action_id": graph_action_id}
            self._save_queues()
        try:
            ips_router_isolated_active.labels(dev_id, hostname, mac).set(1.0)
        except Exception:
            pass
        # 2026-09-16 (router-agnostic IPv6 device-identity plan): same dual-stack
        # coverage mitigate()'s own autonomous router-isolation path now gets -- a human
        # operator clicking this button gets identical IPv6 coverage without needing to
        # separately click "Tarpit (Layer-2)" too. See _arm_tarpit_for_dual_stack_coverage()'s
        # own docstring for why Fritz!Box's TR-064 action alone can't cover this.
        tarpit_armed = self._arm_tarpit_for_dual_stack_coverage(
            client_ip=ip, mac_addr=mac, hostname=hostname, dev_id=dev_id,
            reason=f"IPv6 coverage for router isolation: {reason}")
        if tarpit_armed:
            return True, "Isolated via the router (IPv4) + Layer-2 tarpit armed (covers IPv6)."
        return True, "Isolated via the router."

    def carry_containment_after_merge(self, orphan_mac: str, orphan_ip: str, canonical_id: str,
                                        canonical_mac: str, canonical_ip: str, hostname: str) -> List[str]:
        """An identity merge folded a CONTAINED orphan into `canonical_id` (the same physical device): its
        containment entries stay (StateManager.merge_into_canonical() relabels them) and are extended to the
        canonical's own current MAC/IP, so the device cannot leave containment by appearing under its other
        identity. Uses the same calls as the console buttons (each respects its config switch and is a no-op for an
        address already contained). Returns what was added ("router", "tarpit")."""
        def usable(v):
            return bool(v) and v != "unknown"
        with self._lock:
            router_contained = usable(orphan_mac) and orphan_mac in self._router_isolated_devices
            # StateManager.merge_into_canonical() relabelled the orphan's entry to the canonical id; re-key it
            self._tarpit_active_targets = _ct.normalize_tarpit_targets(self._tarpit_active_targets)
            tarpit_contained = bool(self._tarpit_keys_for([canonical_id], [orphan_mac]))
        if not (router_contained or tarpit_contained):
            return []
        reason = f"Containment carried over: a contained identity was merged into device {canonical_id}"
        added: List[str] = []
        if router_contained and usable(canonical_mac) and canonical_mac != orphan_mac:
            ok, msg = self.operator_isolate_router(canonical_id, canonical_ip, canonical_mac, hostname, reason=reason)
            if ok and msg != "Already isolated.":
                added.append("router")
            elif not ok:
                LOGGER.warning("Could not extend router isolation to merged device %s (%s): %s",
                               canonical_id, canonical_mac, msg)
        if tarpit_contained:
            # one entry for the device, acting on every MAC it is known by now (the merged-in ones included)
            with self._lock:
                before = set(_ct.entry_macs(self._tarpit_active_targets.get(_ct.tarpit_key(canonical_id), {})))
            self._register_tarpit(canonical_id, canonical_mac, hostname, reason=reason, ip=canonical_ip)
            with self._lock:
                after = set(_ct.entry_macs(self._tarpit_active_targets.get(_ct.tarpit_key(canonical_id), {})))
            if after - before:
                added.append("tarpit")
        LOGGER.critical("🔗 [CONTAINMENT CARRIED OVER] %s (%s): orphan containment kept (mac=%s ip=%s)%s.",
                        hostname, canonical_id, orphan_mac, orphan_ip,
                        f", extended to {', '.join(added)}" if added else "")
        return added

    def operator_tarpit(self, dev_id: str, ip: str, mac: str, hostname: str,
                          reason: str = "Operator-requested Layer-2 tarpit",
                          ipv4_candidates=()) -> "tuple[bool, str]":
        """Console 'Tarpit (Layer-2)' button -- see operator_isolate_router()'s docstring
        for why this bypasses mitigate()'s own autonomous-path gating. Purely local (no
        network I/O of its own beyond the tarpit's background threads, already running),
        so the whole registration stays under self._lock, same as mitigate()'s own tarpit
        path."""
        if not bool(self.config.get("ips_tarpit_enabled", True)):
            return False, "Tarpit is disabled in config (ips_tarpit_enabled=false)."
        if not self.tarpit_armed:
            if getattr(self, "_state_only", False):
                return False, ("The engine's Layer-2 tarpit isn't armed (no AF_PACKET support or no raw-socket "
                               "permission where the engine runs, or the engine has not started yet) -- see the engine log.")
            return False, "Tarpit subsystem isn't armed on this server (no AF_PACKET support, or no raw-socket permission) -- see server logs."
        if not self._device_macs(dev_id, mac):
            return False, "No known MAC address for this device -- the tarpit needs one."
        created, _key = self._register_tarpit(dev_id, mac, hostname, reason=reason, ip=ip,
                                              ipv4_candidates=ipv4_candidates)
        if not created:
            return True, "Already tarpitted."
        LOGGER.critical("⚠️ [OPERATOR TARPIT] Console-requested Layer-2 isolation for %s (%s).", hostname, dev_id)
        if getattr(self, "_state_only", False):
            return True, "Tarpit requested (Layer-2 ARP/NDP) -- the engine applies it within one cycle."
        return True, "Tarpitted (Layer-2 ARP/NDP)."

    # The ARP half's gateway is DISCOVERED (the kernel's default route), never configured: config `fritz_ip` is the
    # address of a router integration, not this network's gateway, and its default made the tarpit fake the wrong
    # address on every network that is not 192.168.1.0/24 (CONTAINMENT_MODEL.md section 1, T0). Re-read every minute
    # so a changed gateway is followed; its real MAC (for Release) from the kernel's neighbour table.
    _GATEWAY_REFRESH_SECONDS = 60.0
    # After Release the device still holds the fake gateway MAC until its own cache entry expires (~1 min, live test
    # 2026-10-12). The loop sends it the real one for this many rounds (2 s apart), so access returns at once.
    _RESTORE_ROUNDS = 3

    def _tarpit_gateway(self):
        """(gateway IPv4, its real MAC or None) -- (None, None) when no IPv4 default route exists."""
        now = time.monotonic()
        cache = getattr(self, "_gateway_cache", None)
        if cache is not None and now - cache[0] < self._GATEWAY_REFRESH_SECONDS:
            return cache[1], cache[2]
        gw, gw_mac = None, None
        try:
            gw = _discover_gateway_ipv4()
        except Exception as exc:
            LOGGER.debug("ARP Tarpit: gateway discovery failed: %s", exc)
        if not self._is_arp_ipv4(gw):
            gw = None
        if gw:
            try:
                gw_mac = l2_raw.neighbor_mac(gw)
            except Exception as exc:
                LOGGER.debug("ARP Tarpit: no neighbour entry for the gateway %s: %s", gw, exc)
        self._gateway_cache = (now, gw, gw_mac)
        return gw, gw_mac

    def _gateways_now(self) -> Dict[str, str]:
        """{gateway/router IP: its real MAC or ""} the scope fakes: the discovered IPv4 default gateway plus every
        IPv6 router learned from a Router Advertisement (segment receiver). Network-agnostic -- all discovered."""
        g: Dict[str, str] = {}
        gw_ip, gw_mac = self._tarpit_gateway()
        if gw_ip:
            g[gw_ip] = _ct.norm_mac(gw_mac) or ""
        with self._lock:
            g.update({ip: _ct.norm_mac(mac) for ip, mac in self._ipv6_routers.items()})
        return g

    def _fw_usable(self) -> bool:
        """nft present and writable (checked once). A state-only instance (W-01, per request) never touches the
        firewall -- it leaves no side effects -- so it reports unusable regardless."""
        if getattr(self, "_state_only", False):
            return False
        if self._fw_avail is None:
            try:
                if self._fw.uplink is None:
                    self._fw.uplink = self._fw_uplink()
                self._fw_avail = self._fw.available()
            except Exception as exc:
                LOGGER.debug("nft availability probe failed: %s", exc)
                self._fw_avail = False
        return bool(self._fw_avail)

    def _fw_uplink(self) -> Optional[str]:
        """The interface the IPv4 default gateway is reached on -- the in-path Block-internet rule drops forwarding out
        of it. None when no gateway is known (the in-path rule is then simply not added)."""
        gw_ip, _ = self._tarpit_gateway()
        try:
            return l2_raw.interface_for(gw_ip) if gw_ip else None
        except Exception:
            return None

    def _reconcile_box_firewall(self, current: Dict[str, dict]) -> None:
        """Owner decision 1: a Tarpit cuts the device from the box itself (Pi-hole DNS, web UI). Keep the nft
        `box_blocked` set equal to the MACs of the TARPIT-mode entries -- adding newly contained MACs, removing
        released/re-keyed ones. Block-internet entries are never box-dropped (the box stays reachable for them).
        Idempotent and a no-op when nft is absent, so same-segment containment never depends on it."""
        if not self._fw_usable():
            return
        want = {m for meta in current.values()
                if isinstance(meta, dict) and meta.get("mode", _ct.TARPIT_MODE) == _ct.TARPIT_MODE
                for m in _ct.entry_macs(meta)}
        new, gone = want - self._fw_box_macs, self._fw_box_macs - want
        if new:
            self._fw.box_drop(new)
        if gone:
            self._fw.box_undrop(gone)
        self._fw_box_macs = want

    def _send_v4_specs(self, sock, specs, meta_by_mac, no_ipv4_logged) -> int:
        """Send each IPv4 SendSpec as an ARP reply ('spec.ip is at spec.sender_mac') to the contained device's MAC,
        reusing _arp_reply_for to resolve the device's own IPv4 / interface. Returns how many frames went out."""
        sent = 0
        for s in specs:
            if s.family != 4:
                continue
            meta = meta_by_mac.get(s.dst_mac) or {}
            try:
                out = self._arp_reply_for(s.dst_mac, meta, s.ip, s.sender_mac, no_ipv4_logged)
                if out:
                    l2_raw.send_frame(sock, out[0], out[1])
                    sent += 1
            except Exception as exc:
                LOGGER.debug("ARP send failed for %s -> %s: %s", s.dst_mac, s.ip, exc)
        return sent

    def _reactive_answer(self, kind: str, src_mac: str, wanted_ip: str, sock, ifname) -> None:
        """A contained device's own ARP request (or NS) for an in-scope address is answered at once (l2_enforcer
        decides per entry/mode). Only the entry whose MAC sent it yields a spec."""
        with self._lock:
            metas = [m for m in self._tarpit_active_targets.values() if isinstance(m, dict)]
        peers, gws = self._peer_table.active(), self._gateways_now()
        for meta in metas:
            spec = _l2e.reactive_spec(kind, src_mac, wanted_ip, meta, peers, gws)
            if spec and spec.family == 4:
                try:
                    out = self._arp_reply_for(spec.dst_mac, meta, spec.ip, spec.sender_mac, set())
                    if out:
                        l2_raw.send_frame(sock, out[0] or ifname, out[1])
                except Exception as exc:
                    LOGGER.debug("Reactive ARP answer failed: %s", exc)

    def _counter_fake(self, announced_ip: str, sock, ifname) -> None:
        """A peer/router announced itself (ARP reply / gratuitous ARP / NA / RA): re-send the fake for that address to
        every contained device whose scope covers it, so a device that just saw the real host is re-poisoned at once."""
        with self._lock:
            metas = [m for m in self._tarpit_active_targets.values() if isinstance(m, dict)]
        if not metas:
            return
        peers, gws = self._peer_table.active(), self._gateways_now()
        meta_by_mac = {m: meta for meta in metas for m in _ct.entry_macs(meta)}
        self._send_v4_specs(sock, _l2e.counter_fake_specs(announced_ip, metas, peers, gws), meta_by_mac, set())

    def _segment_loop(self) -> None:
        """T2 segment receiver (CONTAINMENT_MODEL.md section 5): one socket, kernel-filtered to ARP + ICMPv6, feeding
        three things -- the peer table (who is on the segment), the reactive answer (a contained device's own request),
        and the counter-fake (a peer re-announcing itself). IPv6 routers are learned here from RAs. NS -> NA is left to
        _ndp_tarpit_loop. Frames the switch does not mirror to this box are simply not seen (no guessing)."""
        try:
            sock = l2_raw.open_raw()
            l2_raw.attach_filter(sock, l2_raw.arp_and_icmp6_filter_program())
            sock.settimeout(1.0)
        except Exception as exc:
            LOGGER.warning("Segment receiver not started (same-segment peer coverage limited to the gateway): %s", exc)
            return
        while True:
            try:
                try:
                    frame, ifname = l2_raw.recv_frame(sock)
                except (TimeoutError, OSError) as exc:
                    if isinstance(exc, TimeoutError) or "timed out" in str(exc):
                        continue
                    raise
                arp = l2_raw.parse_arp(frame)
                if arp:
                    if _ct._usable(arp["sender_ip"]) and arp["sender_ip"] != "0.0.0.0":
                        self._peer_table.observe(arp["sender_ip"], arp["sender_mac"])
                    if arp["op"] == "request":
                        self._reactive_answer("arp_request", arp["eth_src"], arp["target_ip"], sock, ifname)
                    self._counter_fake(arp["sender_ip"], sock, ifname)
                    continue
                na = l2_raw.parse_neighbor_advertisement(frame)
                if na:
                    self._peer_table.observe(na["target"], na["lladdr"])
                    self._counter_fake(na["target"], sock, ifname)
                    continue
                ra = l2_raw.parse_router_advertisement(frame)
                if ra:
                    with self._lock:
                        self._ipv6_routers[ra["ip_src"]] = _ct.norm_mac(ra["eth_src"])
                    self._counter_fake(ra["ip_src"], sock, ifname)
            except Exception as exc:
                LOGGER.debug("Segment receiver iteration exception: %s", exc)
                time.sleep(0.5)

    def _arp_reply_for(self, mac: str, meta: dict, gateway_ip: str, sender_mac: str, no_ipv4_logged: set):
        """(ifname, frame) telling the device's `mac` that `gateway_ip` is at `sender_mac`; None when that MAC has no
        usable IPv4 (the kernel's neighbour table for the MAC, else the hint stored for it) or no interface reaches it."""
        hint = (meta.get("arp_ips") or {}).get(mac)
        arp_ip = self._arp_target_ip("", mac, [hint] if hint else ())   # neighbour table first, then the hint
        if not self._is_arp_ipv4(arp_ip):
            if mac not in no_ipv4_logged:
                no_ipv4_logged.add(mac)
                LOGGER.info("ARP Tarpit: no IPv4 address known for %s (%s); only the NDP half covers it.",
                            meta.get("dev_id", "?"), mac)
            return None
        no_ipv4_logged.discard(mac)
        ifname = l2_raw.interface_for(arp_ip)
        src_mac = l2_raw.interface_mac(ifname) if ifname else None
        if not (ifname and src_mac):
            LOGGER.debug("ARP Tarpit: no interface/MAC found for %s", arp_ip)
            return None
        return ifname, l2_raw.build_arp_reply(eth_src=src_mac, eth_dst=mac, sender_mac=sender_mac,
                                              sender_ip=gateway_ip, target_mac=mac, target_ip=arp_ip)

    # T1: the entries follow the device -- its MACs and IPv4 hint are re-read from the state this often.
    _TARGET_REFRESH_SECONDS = 10.0

    def _refresh_targets_from_state(self) -> None:
        """Re-keys the entries by device (an identity merge relabels an entry's id) and sets each one's MACs to what
        the device is known by now, with the IPv4 hint of its current MAC. A device no longer in the state keeps its
        last MACs (containment holds until released)."""
        sm = self.state_manager
        with self._lock:
            normalized = _ct.normalize_tarpit_targets(self._tarpit_active_targets)
            changed = normalized != self._tarpit_active_targets
            self._tarpit_active_targets = normalized
            items = list(self._tarpit_active_targets.items())
        for key, meta in items:
            dev_id = meta.get("dev_id")
            macs = self._device_macs(dev_id)
            hint_mac, hint_ip = None, None
            try:
                if _ct._usable(dev_id) and sm.has_device(dev_id):
                    with sm.lock_device(dev_id) as st:
                        hint_mac = _ct.norm_mac(getattr(st, "mac_address", None))
                        hint_ip = self._ipv4_hint(getattr(st, "client_ip", None), hint_mac,
                                                  list(getattr(st, "known_ips", None) or ()))
            except Exception as exc:
                LOGGER.debug("Tarpit refresh: device %s not readable: %s", dev_id, exc)
            with self._lock:
                live = self._tarpit_active_targets.get(key)
                if live is None:
                    continue
                if macs and macs != _ct.entry_macs(live):
                    LOGGER.info("Tarpit for %s now acts on %s (was %s).", dev_id, macs, _ct.entry_macs(live))
                    live["macs"], live["mac"] = macs, macs[0]
                    changed = True
                if hint_ip and hint_mac in _ct.entry_macs(live) and (live.get("arp_ips") or {}).get(hint_mac) != hint_ip:
                    live.setdefault("arp_ips", {})[hint_mac] = hint_ip
                    changed = True
        if changed:
            with self._lock:
                self._save_queues()

    # T1 status: the first seconds are "requested"; observations older than the window no longer count.
    _STATUS_GRACE_SECONDS = 10.0
    _STATUS_WINDOW_SECONDS = 120.0

    def _status_for(self, meta: dict, now: float) -> str:
        """The device's containment status from what the observer saw of its frames since containment started (see
        mitigation/containment.py for the states). Never inferred: no frames, no claim."""
        since = float(meta.get("since") or 0.0)
        if now - since < self._STATUS_GRACE_SECONDS:
            return _ct.REQUESTED
        start = since + self._STATUS_GRACE_SECONDS
        recent = now - self._STATUS_WINDOW_SECONDS
        with self._observed_lock:
            obs = [self._observed.get(m, {}) for m in _ct.entry_macs(meta)]
        last_tarpit = max([o.get("to_tarpit", 0.0) for o in obs] or [0.0])
        last_gateway = max([o.get("to_gateway", 0.0) for o in obs] or [0.0])
        last_frame = max([o.get("frame", 0.0) for o in obs] or [0.0])
        if last_gateway >= max(start, recent) and last_gateway >= last_tarpit:
            return _ct.NOT_REACHING
        if last_tarpit >= recent:
            return _ct.HOLDING
        if last_frame >= recent:
            return _ct.UNCONFIRMED
        return _ct.OFFLINE

    def _update_statuses(self, now: float) -> None:
        """Records each entry's status; a change to "not reaching" is queued for the engine to alert on (once per
        change)."""
        changed = False
        with self._lock:
            for key, meta in self._tarpit_active_targets.items():
                if not isinstance(meta, dict):
                    continue
                status = self._status_for(meta, now)
                if status == meta.get("status"):
                    continue
                old = meta.get("status")
                meta["status"], meta["status_at"] = status, now
                changed = True
                LOGGER.info("Tarpit status for %s (%s): %s -> %s", meta.get("hostname", "?"), meta.get("dev_id", "?"),
                            old, status)
                if status == _ct.NOT_REACHING:
                    self._containment_events.append({
                        "type": "tarpit_not_reaching", "dev_id": meta.get("dev_id"), "hostname": meta.get("hostname"),
                        "macs": _ct.entry_macs(meta), "at": now})
            if changed:
                self._save_queues()

    def _observer_loop(self) -> None:
        """Watches the frames the contained devices send that reach this box: a frame to the tarpit's fake address
        proves the device obeys (holding); after the grace period a frame to the gateway's real MAC proves it is not
        reached; any frame shows it is active. A kernel filter passes only the contained MACs' frames. Frames the
        switch does not bring to this box are not seen -- the status then stays "unconfirmed", never guessed."""
        bogus_mac = "00:11:22:33:44:55"
        try:
            sock = l2_raw.open_raw()
            sock.settimeout(1.0)
        except Exception as exc:
            LOGGER.warning("Containment observer not started: %s", exc)
            return
        filtered_for = None
        while True:
            try:
                with self._lock:
                    macs = sorted({m for meta in self._tarpit_active_targets.values() for m in _ct.entry_macs(meta)})
                if macs != filtered_for:
                    l2_raw.attach_filter(sock, l2_raw.src_mac_filter_program(macs))
                    filtered_for = macs
                    with self._observed_lock:
                        for m in list(self._observed):
                            if m not in macs:
                                self._observed.pop(m, None)
                wanted = set(macs)
                try:
                    frame, _ifname = l2_raw.recv_frame(sock)
                except (TimeoutError, OSError) as exc:
                    if isinstance(exc, TimeoutError) or "timed out" in str(exc):
                        continue
                    raise
                self._observe_frame(frame, wanted, bogus_mac)
            except Exception as exc:
                LOGGER.debug("Containment observer iteration exception: %s", exc)
                time.sleep(0.5)

    def _observe_frame(self, frame: bytes, wanted: set, bogus_mac: str) -> None:
        if len(frame) < 14:
            return
        dst, src = l2_raw.mac_str(frame[0:6]), l2_raw.mac_str(frame[6:12])
        if src not in wanted:
            return
        now = time.time()
        gateway_mac = _ct.norm_mac((getattr(self, "_gateway_cache", None) or (0, None, None))[2])
        with self._observed_lock:
            o = self._observed.setdefault(src, {})
            o["frame"] = now
            if dst == bogus_mac:
                o["to_tarpit"] = now
            elif gateway_mac and dst == gateway_mac:
                o["to_gateway"] = now

    def _arp_tarpit_loop(self) -> None:
        bogus_mac = "00:11:22:33:44:55"
        try:
            sock = l2_raw.open_raw(l2_raw.ETH_P_ARP)
        except Exception as exc:
            LOGGER.debug("ARP Tarpit socket exception: %s", exc)
            return
        no_ipv4_logged = set()
        no_gateway_logged = False
        previous: Dict[str, dict] = {}       # device key -> meta of the entries held last round
        restoring: Dict[str, list] = {}      # device key -> [meta, rounds left] of entries released since
        while True:
            now = time.time()
            if now - self._targets_refreshed_at >= self._TARGET_REFRESH_SECONDS:
                self._targets_refreshed_at = now
                try:
                    self._refresh_targets_from_state()
                except Exception as exc:
                    LOGGER.debug("Tarpit refresh failed: %s", exc)
            gateways = self._gateways_now()                 # IPv4 gateway + IPv6 routers (the scope's gateways)
            gateway_ip = next((ip for ip in gateways if _is_v4(ip)), None)   # the one IPv4 gateway (if any)
            peers = self._peer_table.active()               # {ip: mac} seen on the segment within the TTL
            with self._lock:
                targets = dict(self._tarpit_active_targets)
            # Keyed by DEVICE now (not MAC): a released device, whatever its MACs, restores its whole scope -- peers
            # and gateway for a Tarpit, gateways only for Block internet. Every release path (Release, release-all,
            # safe-device auto-release, another process's change synced in) lands here.
            current = {key: meta for key, meta in targets.items() if isinstance(meta, dict)}
            for key, meta in previous.items():
                if key not in current:
                    restoring[key] = [meta, self._RESTORE_ROUNDS]
            for key in current:
                restoring.pop(key, None)
            previous = current
            self._reconcile_box_firewall(current)           # owner decision 1: a Tarpit also cuts the box itself
            # The ARP half fakes the scope's IPv4 addresses. With no peers observed this is exactly the gateway, per
            # device MAC -- unchanged from before T2. "Idle" (and the one-time warning) means no IPv4 gateway AND no
            # IPv4 peers: nothing on this segment to fake over v4 (the NDP half still acts; peers may appear later).
            v4_peers = {ip: mac for ip, mac in peers.items() if _is_v4(ip)}
            if not gateway_ip and not v4_peers:
                if not no_gateway_logged:
                    no_gateway_logged = True
                    LOGGER.warning("ARP Tarpit: no IPv4 default gateway discovered -- the ARP half is idle until one "
                                   "is (the NDP half still acts).")
                restoring.clear()
            else:
                no_gateway_logged = False
                for key, meta in current.items():
                    specs = _l2e.refresh_specs(meta, peers, gateways, bogus=bogus_mac)
                    self._send_v4_specs(sock, specs, {m: meta for m in _ct.entry_macs(meta)}, no_ipv4_logged)
                for key, entry in list(restoring.items()):
                    meta, left = entry
                    specs = _l2e.restore_specs(meta, peers, gateways)
                    sent = self._send_v4_specs(sock, specs, {m: meta for m in _ct.entry_macs(meta)}, no_ipv4_logged)
                    if not sent and left == self._RESTORE_ROUNDS and gateway_ip:
                        LOGGER.info("ARP Tarpit: released %s, but its scope's real MAC is unknown -- the device's "
                                    "cache recovers on its own (about a minute).", meta.get("dev_id", "?"))
                    entry[1] -= 1
                    if entry[1] <= 0:
                        restoring.pop(key, None)
            try:
                self._update_statuses(time.time())
            except Exception as exc:
                LOGGER.debug("Tarpit status update failed: %s", exc)
            time.sleep(2.0)

    def _pihole_domain_url(self, api_url: str, api_path: str, domain: str = "") -> str:
        """Builds a Pi-hole v6 domain-list REST URL.

        PHASE 17 FIX: the v6 REST API keys its domain-list endpoints by list type and
        match kind IN THE URL PATH -- /api/domains/{type}/{kind}[/{domain}] -- not via a
        JSON body field, confirmed against a live Pi-hole v6 instance (GET returned 200
        with the real blocklist at this exact shape; the old {api_path} alone 404'd with
        FTL's own "route not found" error). Every domain this codebase manages is an
        exact-match denylist entry -- no regex, no allowlist -- so 'deny/exact' is fixed,
        matching existing behavior exactly; nothing upstream ever set kind/type differently.
        """
        base = f"{api_url}{api_path}/deny/exact"
        return f"{base}/{domain}" if domain else base

    def check_pihole_health(self, timeout: float = 3.0) -> "tuple[bool, str]":
        return check_pihole_health(self.config, timeout=timeout, session=self.session)

    def _block_domain(self, domain: str, hostname: str, device_ip: str, dev_id: str, reason: str = "",
                      alert_ref: Optional[dict] = None) -> bool:
        ips_state = self.state_manager.get_ips_state()
        
        # Self-healing desync check: Clear queues if block is already confirmed active
        if domain in ips_state.get("blocked_domains", {}):
            api_url = self.config.get("pihole_api_url", "")
            api_path = self.config.get("pihole_api_path", "/api/domains")
            api_password = self.config.get("pihole_api_password", "")
            headers = pihole_auth.auth_headers(api_url, api_password, self.session)
            
            is_actually_blocked = True
            if api_url:
                try:
                    resp = self.session.get(self._pihole_domain_url(api_url, api_path), headers=headers, timeout=2.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        # PHASE 17 FIX: v6's actual response shape is {"domains": [...], "took": ...},
                        # not {"data": [...]} -- the old key never matched, so actual_domains was
                        # always empty and this desync check would have wrongly concluded every
                        # already-blocked domain had been "unblocked externally" on every single
                        # call, the moment the API path fix above made this branch actually reachable.
                        items = data.get("domains", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                        actual_domains = {item.get("domain") for item in items if isinstance(item, dict)}
                        if domain not in actual_domains:
                            is_actually_blocked = False
                            LOGGER.warning("Pi-hole desync: %s was unblocked externally. Resyncing internal state.", domain)
                            with self.state_manager._global_lock:
                                ips_state = self.state_manager.get_ips_state()
                                ips_state.get("blocked_domains", {}).pop(domain, None)
                                self.state_manager.save_ips_state(ips_state)
                            # self.state_manager.flush_to_disk()  # Removed to prevent lock contention
                            _remove_gauge_labels(ips_active_blocks_gauge, dev_id, hostname, domain)
                except Exception as e:
                    LOGGER.debug("Pi-hole sync check failed: %s", e)
            
            if is_actually_blocked:
                with self._lock:
                    modified = False
                    if domain in self._retry_queue:
                        self._retry_queue.pop(domain)
                        _remove_gauge_labels(ips_queue_status_gauge, dev_id, hostname, domain)
                        modified = True
                    if domain in self._dead_letter:
                        self._dead_letter.pop(domain)
                        _remove_gauge_labels(ips_dead_letter_gauge, dev_id, hostname, domain)
                        modified = True
                    if modified:
                        self._save_queues()
                return True
            
        comment = f"Home-IDS Auto-Block | Device: {hostname} | Trigger: {reason}"
        api_url = self.config.get("pihole_api_url", "")
        # AUDIT FIX #9: Pi-hole API path is now configurable, not hardcoded to /api/domains
        api_path = self.config.get("pihole_api_path", "/api/domains")

        if not api_url:
            LOGGER.warning("⚠️ Pi-hole API URL is not configured. Cannot enforce network block for domain %s.", domain)
            return False

        timeout_seconds = float(self.config.get("pihole_api_timeout_seconds", 5.0))
        if timeout_seconds <= 0:
            timeout_seconds = 5.0

        # Inject the authentication token from config (populated automatically from ENV by config.py)
        api_password = self.config.get("pihole_api_password", "")
        headers = pihole_auth.auth_headers(self.config.get("pihole_api_url", ""), api_password, self.session, timeout_seconds)

        import subprocess
        try:
            # PHASE 17 FIX: v6's addDomain endpoint takes "domain" as an ARRAY (its bulk-add
            # convention) with type/kind conveyed by the URL path, not a "type" body field --
            # the old body shape was rejected by FTL's own request validation before it ever
            # got to check auth or do anything else, which is why every real block on this
            # deployment has been silently falling through to the CLI fallback below.
            resp = self.session.post(
                self._pihole_domain_url(api_url, api_path),
                json={"domain": [domain], "comment": comment},
                headers=headers,
                timeout=timeout_seconds
            )
            
            # Fallback to Pi-hole v5 API or local CLI if v6 endpoint returns 404 or auth fails
            if resp.status_code == 404 or resp.status_code == 401 or "password incorrect" in resp.text.lower():
                LOGGER.warning(f"Pi-hole API failed (status {resp.status_code}). Attempting local CLI fallback (pihole deny).")
                try:
                    res = subprocess.run(["pihole", "deny", domain], capture_output=True, text=True, timeout=5.0)
                    if res.returncode == 0:
                        LOGGER.info(f"Successfully blocked {domain} using local pihole CLI.")
                        self._finalize_block(domain, hostname, device_ip, dev_id, comment=comment, alert_ref=alert_ref)
                        return True
                    else:
                        LOGGER.error(f"Local CLI fallback failed: {res.stderr}")
                except Exception as e:
                    LOGGER.error(f"Local CLI fallback exception: {e}")
                
                # If CLI fails, try the old v5 API as a last resort
                LOGGER.info("Falling back to Pi-hole v5 API.")
                v5_url = f"{api_url}/admin/api.php?list=black&add={domain}&auth={api_password}"
                resp = self.session.get(v5_url, timeout=timeout_seconds)
                LOGGER.info("Pi-hole v5 fallback response: %s %s", resp.status_code, resp.text)
                if "Not authorized" in resp.text:
                    # Pi-hole rejected auth on every rung and nothing was blocked. Report failure
                    # so the alert and self-heal state match reality (W-02). Never record success here.
                    LOGGER.warning("Pi-hole block of %s failed: all auth paths rejected (v5 needs a SHA256-hashed password).", domain)
                    return False

            if resp.status_code in (200, 201, 204):
                if "Not authorized" in resp.text:
                    return False
                self._finalize_block(domain, hostname, device_ip, dev_id, comment=comment, alert_ref=alert_ref)
                return True
            elif 400 <= resp.status_code < 500 and resp.status_code != 429:
                self._add_to_dead_letter(domain, hostname, dev_id, f"HTTP {resp.status_code}: {resp.text}")
                return False
            else:
                self._add_to_retry(domain, hostname, device_ip, dev_id, reason)
                return False
        except Exception as e:
            LOGGER.error("Pi-hole API connection error for %s: %s", domain, e)
            self._add_to_retry(domain, hostname, device_ip, dev_id, reason)
            return False

    def _add_to_retry(self, domain, hostname, device_ip, dev_id, reason):
        with self._lock:
            meta = self._retry_queue.get(domain, {"hostname": hostname, "device_ip": device_ip, "device_id": dev_id, "reason": reason, "attempts": 0})
            meta["attempts"] += 1
            if meta["attempts"] > 5:
                del self._retry_queue[domain]
                self._add_to_dead_letter(domain, hostname, dev_id, "Max retries exceeded (5/5)")
                _remove_gauge_labels(ips_queue_status_gauge, dev_id, hostname, domain)
            else:
                self._retry_queue[domain] = meta
                ips_queue_status_gauge.labels(device=dev_id, hostname=hostname, domain=domain).set(meta["attempts"])
            self._save_queues()

    def _prune_dead_letter_entries(self, now=None, max_items=500, max_age_seconds=30 * 24 * 3600):
        if now is None:
            now = time.time()

        with self._lock:
            if max_age_seconds is not None:
                stale_dead = [
                    dom for dom, meta in list(self._dead_letter.items())
                    if now - float(meta.get("ts", 0.0)) > max_age_seconds
                ]
                for dom in stale_dead:
                    meta = self._dead_letter.pop(dom, {})
                    try:
                        ips_dead_letter_gauge.remove(meta.get("device_id", ""), meta.get("hostname", ""), dom)
                    except Exception:
                        pass

            while len(self._dead_letter) > max_items:
                oldest = min(self._dead_letter.items(), key=lambda item: item[1].get("ts", 0.0))
                meta = self._dead_letter.pop(oldest[0], {})
                try:
                    ips_dead_letter_gauge.remove(meta.get("device_id", ""), meta.get("hostname", ""), oldest[0])
                except Exception:
                    pass

    def _add_to_dead_letter(self, domain, hostname, dev_id, error_msg):
        with self._lock:
            self._dead_letter[domain] = {"hostname": hostname, "device_id": dev_id, "error": error_msg, "ts": time.time()}
            self._prune_dead_letter_entries(now=time.time())
            ips_dead_letter_gauge.labels(device=dev_id, hostname=hostname, domain=domain).set(1.0)
            self._save_queues()
        self._mirror_containment(dev_id, action_type="dead_letter", status="failed",
                                   target=domain, reason=error_msg)

    def _finalize_block(self, domain, hostname, device_ip, dev_id, comment: str = "", alert_ref: Optional[dict] = None):
        timestamp = time.time()
        # PHASE 14: the "Home-IDS Auto-Block | Device: ... | Trigger: ..." comment is only
        # guaranteed to reach Pi-hole itself on the primary v6 API path (it's passed in the
        # JSON body there). The CLI (`pihole deny`) and legacy v5 API fallback paths don't
        # have a verified way to carry a comment through without risking the block call
        # itself failing on unfamiliar CLI flags -- so the comment is stored here, in LOCAL
        # state, on every successful block regardless of which path executed it. This is
        # the durable, always-present answer to "was this blocked by the script, and why".
        # Snapshot and update IPS state while holding the state-manager lock, then flush outside the lock.
        graph_action_id = self._mirror_containment(dev_id, action_type="dns_block", status="active",
                                                      target=domain, reason=comment or "Home-IDS Auto-Block")
        with self.state_manager._global_lock:
            ips_state = self.state_manager.get_ips_state()
            ips_state["blocked_domains"][domain] = {
                "device_id": dev_id,
                "hostname": hostname,
                "device_ip": device_ip,
                "timestamp": timestamp,
                "status": "active",
                "persisted": True,
                "comment": comment or "Home-IDS Auto-Block",
                "_graph_action_id": graph_action_id,
                # the alert that caused this block (incident, signature, the evidence that fired); None for a block an
                # operator made by hand -- 2026-10-12, no record linked a block to its cause before
                "alert": dict(alert_ref) if alert_ref else None,
            }
            self.state_manager.save_ips_state(ips_state)
        self.state_manager.flush_to_disk()

        with self._lock:
            modified = False
            if domain in self._retry_queue:
                self._retry_queue.pop(domain)
                _remove_gauge_labels(ips_queue_status_gauge, dev_id, hostname, domain)
                modified = True
            if domain in self._dead_letter:
                self._dead_letter.pop(domain)
                _remove_gauge_labels(ips_dead_letter_gauge, dev_id, hostname, domain)
                modified = True
            if modified:
                self._save_queues()

        try:
            ips_active_blocks_gauge.labels(device=dev_id, hostname=hostname, domain=domain).set(1.0)
            ips_pihole_blocks_metric.labels(device=dev_id, hostname=hostname).inc()
        except Exception:
            pass

        LOGGER.warning("🛑 [PI-HOLE IPS] Blocked malicious domain %s (Device: %s)", domain, hostname)
        return True

    def _retry_worker(self):
        """H4 FIX: Background retry worker with exponential backoff per-domain attempt count.

        W-23: an exception used to end this thread for good, silently (no liveness check watched it). Each pass now
        beats the health heartbeat and is guarded, so a bad entry is logged and the worker keeps running."""
        from core.heartbeat import HEARTBEATS
        while True:
            time.sleep(30)
            HEARTBEATS.beat("ips_retry_worker", health_state="healthy")
            try:
                self._retry_pass()
            except Exception:
                LOGGER.exception("IPS retry pass failed; retrying on the next cycle")

    def _retry_pass(self) -> None:
        if not self.config.get("ips_pihole_enabled", True):
            return
        with self._lock:
            items_to_retry = list(self._retry_queue.items())
            self._prune_dead_letter_entries(now=time.time())
        for domain, meta in items_to_retry:
            # Exponential backoff: wait 30s × 2^attempts before each retry
            # attempt 1 → 60s, attempt 2 → 120s, attempt 3 → 240s, attempt 4 → 480s
            min_wait = 30 * (2 ** meta.get("attempts", 1))
            last_attempt = meta.get("last_attempt_ts", 0.0)
            if time.time() - last_attempt < min_wait:
                continue
            with self._lock:
                if domain in self._retry_queue:
                    self._retry_queue[domain]["last_attempt_ts"] = time.time()
            try:
                self._block_domain(domain, meta["hostname"], meta.get("device_ip", ""), meta["device_id"], meta["reason"])
            except Exception:
                LOGGER.exception("IPS retry of %s failed; left in the retry queue", domain)

    def unblock_domain(self, domain: str, reason: str = "manual") -> bool:
        if not domain: return False
        api_url = self.config.get("pihole_api_url", "")
        api_path = self.config.get("pihole_api_path", "/api/domains")
        
        if api_url and self.config.get("ips_pihole_enabled", True):
            api_password = self.config.get("pihole_api_password", "")
            headers = pihole_auth.auth_headers(api_url, api_password, self.session)
            
            import subprocess
            try:
                timeout_seconds = float(self.config.get("pihole_api_timeout_seconds", 5.0))
                if timeout_seconds <= 0:
                    timeout_seconds = 5.0
                # PHASE 17 FIX: v6's DELETE targets a specific /{domain} in the URL path --
                # the old bare {api_path} with a JSON body 404'd (FTL's own "route not
                # found"), meaning unblock_domain() has never actually reached Pi-hole's v6
                # API on this deployment; every release has been silently going through the
                # CLI fallback below instead.
                resp = self.session.delete(
                    self._pihole_domain_url(api_url, api_path, domain),
                    headers=headers,
                    timeout=timeout_seconds
                )
                
                # Fallback to Pi-hole local CLI or v5 API if v6 endpoint returns 404 or auth fails
                if resp.status_code == 404 or resp.status_code == 401 or "password incorrect" in resp.text.lower():
                    LOGGER.warning(f"Pi-hole API failed (status {resp.status_code}). Attempting local CLI fallback (pihole -b -d).")
                    try:
                        # Try v5 legacy command first, then v6 command
                        res = subprocess.run(["pihole", "-b", "-d", domain], capture_output=True, text=True, timeout=5.0)
                        if res.returncode != 0 and "unrecognized" in res.stderr.lower():
                            res = subprocess.run(["pihole", "deny", "-d", domain], capture_output=True, text=True, timeout=5.0)
                        
                        if res.returncode == 0:
                            LOGGER.info(f"Successfully released {domain} using local pihole CLI.")
                        else:
                            LOGGER.error(f"Local CLI fallback failed: {res.stderr}")
                    except Exception as e:
                        LOGGER.error(f"Local CLI fallback exception: {e}")
                        
                    LOGGER.info("Falling back to Pi-hole v5 API for release.")
                    v5_url = f"{api_url}/admin/api.php?list=black&sub={domain}&auth={api_password}"
                    resp2 = self.session.get(v5_url, timeout=timeout_seconds)
                    LOGGER.info("Pi-hole v5 unblock fallback response: %s %s", resp2.status_code, resp2.text)
                    if "Not authorized" in resp2.text:
                        LOGGER.warning("Pi-hole v5 requires SHA256 hashed password. Skipping.")
            except Exception as e:
                ips_errors_metric.labels(target_type="pihole_unblock_api").inc()

        hostname, dev_id, graph_action_id = "unknown", "unknown", None
        with self.state_manager._global_lock:
            ips_state = self.state_manager.get_ips_state()
            meta = ips_state.get("blocked_domains", {}).pop(domain, None)
            if meta:
                hostname, dev_id = meta.get("hostname", "unknown"), meta.get("device_id", "unknown")
                graph_action_id = meta.get("_graph_action_id")
            self.state_manager.save_ips_state(ips_state)
            # self.state_manager.flush_to_disk()  # Removed to prevent lock contention

        self._mirror_containment_released(graph_action_id)

        try: 
            ips_active_blocks_gauge.remove(dev_id, hostname, domain)
            ips_pihole_unblocks_metric.labels(device=dev_id, hostname=hostname, reason=reason).inc()
        except Exception: 
            pass
        return True

    def unblock_by_base_domain(self, base_domain: str) -> list:
        """Releases every currently-blocked domain whose registrable (eTLD+1) domain is
        base_domain -- not just a blocked_domains entry that equals base_domain literally.

        Immunization always operates on a base domain (e.g. 'zee5.com'), but Pi-hole
        blocks are keyed by the specific queried FQDN (e.g. 'stcf-prod.zee5.com',
        'stcf1.zee5.com'). All three self-healing callers (autonomous CL-AFPE suppress in
        pipeline.py, the LLM-validated path in ollama_soc.py, and the operator "Mark False
        Positive" IPC handler) used to call unblock_domain(base_domain) directly or check
        `base_domain in blocked_domains` -- an exact-string match that almost never fires,
        since the base domain itself is rarely what got blocked. The practical effect,
        confirmed against live production state: a base domain could sit in the trust
        cache for over a day while every one of its actually-blocked subdomains stayed
        blocked indefinitely, silently breaking the device that depended on them. This
        sweeps every blocked entry sharing the newly-trusted base domain, not just one.
        """
        if not base_domain:
            return []
        blocked = dict(self.state_manager.get_ips_state().get("blocked_domains", {}))
        matches = [d for d in blocked if d == base_domain or d.endswith("." + base_domain)]
        released = []
        for domain in matches:
            if self.unblock_domain(domain=domain, reason="immunized"):
                released.append(domain)
        return released

    def _isolate_device_router(self, mac: str, ip: str, hostname: str, dev_id: str, reason: str) -> bool:
        webhook_url = self.config.get("router_webhook_url") or "http://127.0.0.1:8010/isolate"
        api_token = self.config.get("fritz_api_token", "")
        try:
            headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
            timeout_seconds = float(self.config.get("router_webhook_timeout_seconds", 5.0))
            if timeout_seconds <= 0:
                timeout_seconds = 5.0
            resp = self.session.post(webhook_url, json={"action": "isolate", "ip": ip, "mac": mac, "reason": reason}, headers=headers, timeout=timeout_seconds)
            if resp.status_code == 202:
                ips_isolations_metric.labels(device=dev_id, hostname=hostname, mac=mac).inc()
                LOGGER.critical("✅ [ROUTER IPS] Hardware isolation request accepted for %s (%s)", hostname, mac)
                return True
            ips_errors_metric.labels(target_type="router_webhook").inc()
        except Exception as e:
            ips_errors_metric.labels(target_type="router_webhook_connection").inc()
        return False

    def _unisolate_device_router(self, mac: str, ip: str, hostname: str, dev_id: str, reason: str = "manual") -> bool:
        webhook_url = self.config.get("router_webhook_url") or "http://127.0.0.1:8010/isolate"
        api_token = self.config.get("fritz_api_token", "")
        try:
            headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
            timeout_seconds = float(self.config.get("router_webhook_timeout_seconds", 5.0))
            if timeout_seconds <= 0:
                timeout_seconds = 5.0
            resp = self.session.post(webhook_url, json={"action": "unisolate", "ip": ip, "mac": mac, "reason": "Risk subsided"}, headers=headers, timeout=timeout_seconds)
            if resp.status_code == 202:
                graph_action_id = None
                with self._lock:
                    if mac in self._router_isolated_devices:
                        graph_action_id = self._router_isolated_devices[mac].get("_graph_action_id")
                        del self._router_isolated_devices[mac]
                        self._save_queues()
                self._mirror_containment_released(graph_action_id)
                try:
                    ips_router_isolated_active.labels(dev_id, hostname, mac).set(0.0)
                    ips_router_isolated_active.remove(dev_id, hostname, mac)
                except Exception:
                    # release_device() sometimes already removed this gauge label itself
                    # before calling here -- a resulting KeyError must not skip the
                    # counter increment below, so it's in its own try, not this one.
                    pass
                try:
                    ips_router_releases_metric.labels(device=dev_id, hostname=hostname, reason=reason).inc()
                except Exception:
                    pass
                LOGGER.critical("✅ [ROUTER IPS] Hardware un-isolation request accepted for %s (%s)", hostname, mac)
                return True
            ips_errors_metric.labels(target_type="router_unisolate_webhook").inc()
        except Exception as e:
            ips_errors_metric.labels(target_type="router_unisolate_connection").inc()
        return False

    def _resolve_release_targets(self, identifier: str) -> "tuple[set, set]":
        """(device ids, MACs) an operator's release names. A device id, a tarpit key or a MAC names that device; an
        address names the device that holds it NOW (StateManager), never whatever was once registered under it; a
        name is not an identifier (names are shared). Caller holds self._lock."""
        ident = str(identifier or "").strip()
        dev_ids, macs = set(), set()
        if not _ct._usable(ident):
            return dev_ids, macs
        low = ident.lower()
        for key, meta in self._tarpit_active_targets.items():
            if not isinstance(meta, dict):
                continue
            if ident in (key, meta.get("dev_id")) or low in _ct.entry_macs(meta):
                dev_ids.add(meta.get("dev_id"))
                macs.update(_ct.entry_macs(meta))
        for mac, meta in self._router_isolated_devices.items():
            if ident == meta.get("dev_id") or low == _ct.norm_mac(mac):
                dev_ids.add(meta.get("dev_id"))
                macs.add(_ct.norm_mac(mac))
        if not dev_ids and not macs:
            try:
                ipaddress.ip_address(ident.split("%", 1)[0])
                holder = self.state_manager.get_device_id_for_ip(ident)
                if holder:
                    dev_ids.add(holder)
            except ValueError:
                if self.state_manager.has_device(ident):
                    dev_ids.add(ident)
        for d in list(dev_ids):
            macs.update(self._device_macs(d))
        dev_ids.discard(None)
        return {d for d in dev_ids if _ct._usable(d)}, {m for m in macs if _ct._usable(m)}

    def release_device(self, identifier: str) -> bool:
        """
        Explicit operator release: lifts the tarpit and router isolation of the device `identifier` names (device id,
        MAC, or the address it holds now -- _resolve_release_targets), and the Pi-hole blocks made because of that
        device, WITHOUT adding it to safe_ips (monitoring continues). `identifier` may also be a blocked domain itself.
        T1 (2026-10-12): by device. Matching by address or name released, or kept, another device's containment and
        domain blocks once an address changed hands or two devices shared a name.
        AUDIT FIX #8: Collect targets under lock then execute HTTP I/O outside the lock
        to avoid blocking all lock-protected operations during a network round-trip.
        """
        released = False
        router_targets = []
        with self._lock:
            dev_ids, macs = self._resolve_release_targets(identifier)
            popped = self._pop_tarpit_entries(self._tarpit_keys_for(dev_ids, macs))
            for meta in popped:
                released = True
                LOGGER.info("✅ [RELEASE] Operator released device %s (%s) from the Layer-2 tarpit.",
                            meta.get("hostname", "unknown"), meta.get("dev_id", "unknown"))
            for mac, meta in list(self._router_isolated_devices.items()):
                if meta.get("dev_id") in dev_ids or _ct.norm_mac(mac) in macs:
                    del self._router_isolated_devices[mac]
                    router_targets.append((mac, meta))
                    try:
                        ips_router_isolated_active.labels(meta.get("dev_id", ""), meta.get("hostname", ""), mac).set(0.0)
                        ips_router_isolated_active.remove(meta.get("dev_id", ""), meta.get("hostname", ""), mac)
                    except Exception:
                        pass
            if router_targets:
                self._save_queues()

        # Phase 2: router HTTP calls + graph mirror releases OUTSIDE the lock. Mirrored here (not via
        # _unisolate_device_router()'s own release-mirror): the dict entries are already gone.
        for meta in popped:
            self._mirror_containment_released(meta.get("_graph_action_id"))
        for mac, meta in router_targets:
            self._mirror_containment_released(meta.get("_graph_action_id"))
            self._unisolate_device_router(mac=mac, ip=meta.get("ip") or "0.0.0.0", hostname=meta.get("hostname", "unknown"),
                                          dev_id=meta.get("dev_id", "unknown"), reason="manual")
            released = True
            LOGGER.info("✅ [RELEASE] Operator released device %s (%s) from router isolation.",
                        meta.get("hostname", "unknown"), mac)

        # The Pi-hole blocks made because of this device (by its id), or the domain itself when one was named.
        ident = str(identifier or "").strip()
        ips_state = self.state_manager.get_ips_state()
        blocked_dict = ips_state.get("blocked_domains", {})
        domains_to_unblock = [dom for dom, meta in blocked_dict.items()
                              if dom == ident or (isinstance(meta, dict) and meta.get("device_id") in dev_ids)]
        for dom in domains_to_unblock:
            self.unblock_domain(dom, reason="manual")
            released = True

        # Clear retry & dead-letter queue items of this device / domain
        with self._lock:
            stale_retries = [dom for dom, meta in self._retry_queue.items()
                             if dom == ident or meta.get("device_id") in dev_ids]
            for dom in stale_retries:
                meta = self._retry_queue.pop(dom, {})
                try: ips_queue_status_gauge.remove(meta.get("device_id", ""), meta.get("hostname", ""), dom)
                except Exception: pass
                released = True

            stale_dead = [dom for dom, meta in self._dead_letter.items()
                          if dom == ident or meta.get("device_id") in dev_ids]
            for dom in stale_dead:
                meta = self._dead_letter.pop(dom, {})
                try: ips_dead_letter_gauge.remove(meta.get("device_id", ""), meta.get("hostname", ""), dom)
                except Exception: pass
                released = True

        if dev_ids or macs:
            # the post-release cooldown, by device id and MAC (read by mitigate() via containment.released_recently)
            now = time.time()
            with self._lock:
                for k in list(dev_ids) + sorted(macs):
                    self._operator_released_devices[k] = now
                self._save_queues()

        return released

    def release_all_devices(self) -> int:
        """Explicit operator release of ALL contained devices (tarpit and router isolation), one device at a time."""
        with self._lock:
            idents = {m.get("dev_id") for m in self._tarpit_active_targets.values()
                      if isinstance(m, dict) and _ct._usable(m.get("dev_id"))}
            idents |= {(m.get("dev_id") if _ct._usable(m.get("dev_id")) else mac)
                       for mac, m in self._router_isolated_devices.items() if isinstance(m, dict)}
            idents |= {k for k, m in self._tarpit_active_targets.items()
                       if isinstance(m, dict) and not _ct._usable(m.get("dev_id"))}
        return sum(1 for ident in idents if self.release_device(ident))

    def unisolate_all(self, mac_addr: str, ip_addr: str):
        """Completely un-isolates a device (Router + Tarpit) across MAC and IP changes[cite: 28].

        BUGFIX (log-spam/wasted-webhook audit, found live: dozens of CRITICAL
        "un-isolation request accepted for unknown (unknown)" / "unknown (<random
        MAC>)" log lines, most 1-2 per identity re-resolution -- i.e. essentially
        once per MAC-rotation event from any privacy-randomizing device on the
        network). This method's own docstring elsewhere (identity.py's
        _release_stale_isolation_if_merged()) claims "unisolate_all() itself is a
        safe no-op if the old identifiers weren't actually isolated (it checks
        membership before doing anything)" -- true for the LOCAL bookkeeping below,
        but the real outbound HTTP call to the router used to fire unconditionally
        whenever ips_router_enabled was set, regardless of whether mac_addr was
        ever actually in _router_isolated_devices. Every device-identity merge/
        re-identify (any MAC rotation, not just ones that were ever isolated) was
        sending a real webhook POST to Fritz!Box for nothing, plus a misleading
        CRITICAL log implying a real containment action happened. Now gated on
        router_was_isolated, mirroring the single-target release path's own
        existing pattern a few hundred lines up (which already checks
        `mac_addr in self._router_isolated_devices` before calling this)."""
        target_hostname = "unknown"
        target_dev = "unknown"
        tarpit_graph_action_id = None
        router_graph_action_id = None
        router_was_isolated = False

        with self._lock:
            self._tarpit_active_targets = _ct.normalize_tarpit_targets(self._tarpit_active_targets)
            # Unchanged behaviour with device keys: the entry registered under `ip_addr` is removed, as when entries
            # were keyed by it. (That a linked MAC rotation releases containment at all is the caller's decision in
            # identity code -- parked for T5 / identity P4, MASTER_TODO Section 0b, T1 finding (a).)
            keys = [k for k, m in self._tarpit_active_targets.items()
                    if isinstance(m, dict) and _ct._usable(ip_addr) and m.get("registered_ip") == ip_addr]
            for meta in self._pop_tarpit_entries(keys):
                target_hostname = meta.get("hostname", "unknown")
                target_dev = meta.get("dev_id", "unknown")
                tarpit_graph_action_id = meta.get("_graph_action_id")
                LOGGER.info("🧹 Cleared Tarpit entry registered under reassigned IP %s", ip_addr)
                
            if mac_addr in self._router_isolated_devices:
                meta = self._router_isolated_devices[mac_addr]
                target_hostname = meta.get("hostname", target_hostname)
                target_dev = meta.get("dev_id", target_dev)
                router_graph_action_id = meta.get("_graph_action_id")
                del self._router_isolated_devices[mac_addr]
                router_was_isolated = True
                LOGGER.info("🧹 Cleared Router Isolation entry for new MAC %s[cite: 28]", mac_addr)

        # Mirrored HERE (not via _unisolate_device_router()'s own release-mirror
        # below), same reasoning as release_device() -- the dict entries are
        # already gone by the time _unisolate_device_router() would look for them.
        self._mirror_containment_released(tarpit_graph_action_id)
        self._mirror_containment_released(router_graph_action_id)

        if router_was_isolated and bool(self.config.get("ips_router_enabled", False)):
            self._unisolate_device_router(
                mac=mac_addr, 
                ip=ip_addr, 
                hostname=target_hostname, 
                dev_id=target_dev
            )
