"""
identity.py - Device Identity, Hostname Sanitization & MAC Migration Manager.

RECENT FIXES:
- FIXED (SPLIT-BRAIN IDENTITY CORRELATION): Updated `resolve_device_id()` to anchor trackable 
  local private IPs directly. Eliminates race conditions where Pi-hole (with a hostname) and 
  Zeek (with hostname 'unknown') generated conflicting device IDs for the same physical machine.
- ADDED (GENERIC HOSTNAME COLLISION FIX): Banned generic hostnames ('iphone', 'android').
- ADDED (ROUTER MASTER TRUTH): Integrated background polling for FritzBox webhook (/hosts).
"""

import hashlib
import logging
import ipaddress
import re
import threading
import time
import requests
from collections import OrderedDict
from typing import Optional, List, Dict, Set, Any, Tuple

from utils import sanitize_hostname, infer_device_type, get_mac_vendor

# Pi-hole query statuses that mean "blocked" (same set as extractors/dns_features.py's BLOCKED).
_PIHOLE_BLOCKED_STATUSES = frozenset({1, 4, 5, 6, 7, 8, 10})
from core.state_guard import StateManager
from core.device_matching import AUTO_MERGE_CONFIDENCE
from core.device_labels import get_label as get_confirmed_device_label
from metrics import device_type_reclassifications_total

LOGGER = logging.getLogger("home_ids.identity")

_GENERIC_HOSTNAMES = frozenset({
    "android", "iphone", "ipad", "ipod", "macbook", "macbook-pro", "macbook-air",
    "imac", "apple-tv", "desktop", "laptop", "pc", "workstation", "unknown",
    "localhost", "galaxy", "samsung", "pixel", "amazon-device", "chromecast",
    "windows", "linux", "debian", "ubuntu", "raspberrypi", "router", "gateway",
    "switch", "ap", "access-point", "wlan", "wifi", "host", "device", "none"
})


def stable_device_id(raw_client: str) -> str:
    if not raw_client:
        return "000000000000"
    cleaned = str(raw_client).strip().lower()
    return hashlib.sha256(cleaned.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _is_trackable_local_ip(ip: str) -> bool:
    """PHASE 5 FIX (IPv6 visibility): previously hard-excluded every IPv6 address, so any
    device using IPv6 (even link-local/ULA on the same LAN) was invisible to identity
    resolution entirely — the audit's #5 finding. IPv6 is disabled on this network's
    router today, so this has no live effect right now, but it stops silently blinding
    the IDS the moment IPv6 gets turned on rather than requiring a code change then too.
    `is_private` already correctly covers IPv6 ULA (fc00::/7) and link-local (fe80::/10)
    the same way it covers RFC1918 for IPv4, so no separate IPv6 branch is needed."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_unspecified or ip_obj.is_loopback:
            return False
        if not ip_obj.is_private:
            return False
        return True
    except ValueError:
        return False


def _is_generic_hostname(hostname: str) -> bool:
    if not hostname or hostname == "unknown":
        return True
    clean_host = hostname.lower().strip()
    if clean_host in _GENERIC_HOSTNAMES:
        return True
    if re.match(r'^\d+$', clean_host):
        return True
    return False


class DeviceIdentityManager:
    def __init__(self, state_manager: StateManager, config: Any):
        self.state_manager = state_manager
        self.config = config
        # H5 FIX: _ip_cache must be protected by self._lock (was read/written without lock).
        # M6 FIX: Use OrderedDict so we can do proper LRU eviction via move_to_end().
        self._ip_cache: OrderedDict = OrderedDict()
        self._fritz_cache: Dict[str, Dict[str, str]] = {}
        # BUGFIX (live audit, continuation session): Fritz!Box's /hosts webhook
        # (fritzbox_api.py's get_dhcp_hosts(), TR-064's Hosts:1/LanDeviceHost
        # service) is genuinely IPv4-only -- a DHCPv4 lease table, with no
        # concept of IPv6 SLAAC/link-local addresses at all. _fritz_cache above
        # is keyed by whatever IP string a given resolve event happens to pass
        # as `ip`, which for a dual-stack device is frequently an IPv6 address
        # (link-local/ULA/GUA) that Fritz!Box's own table could never contain a
        # matching key for -- even though the SAME device's real IPv4 address
        # (which WOULD hit the cache) is sitting right there in its own
        # known_ips. Confirmed live: 9 currently-active devices with real,
        # already-resolved MAC addresses and a real IPv4 address in known_ips
        # were still showing hostname=unknown, because whichever cycle's event
        # happened to resolve via their IPv6 address never got a chance to
        # match. This second, MAC-keyed cache is the fallback _enrich_from_cache()
        # tries when the IP-keyed lookup misses -- same data, same poll, just
        # indexed a second way (Fritz!Box's own host records already carry MAC).
        self._fritz_cache_by_mac: Dict[str, Dict[str, str]] = {}
        self._lock = threading.Lock()
        # GENERAL FIX (2026-08-27): the gateway special-case below only ever matched the
        # single configured gateway_ip literal (IPv4), so the same physical router's IPv6
        # link-local/ULA traffic still fragmented into a separate identity -- confirmed
        # live via two independent router honeypot-hit incidents, one keyed by
        # 192.168.1.1 and one by an fe80:: address. Deliberately MAC-based rather than a
        # second hardcoded IP literal (which would need updating on every deployment, and
        # even on this one if the router's IPv6 address ever rotates) -- learned once from
        # whichever cycle sees gateway_ip with a real MAC attached, then reused for any
        # OTHER address presenting the same MAC. Generic: works for any router on any
        # deployment, not tied to a specific address family or literal value.
        self._gateway_mac: Optional[str] = None
        
        threading.Thread(target=self._poll_fritzbox_hosts, daemon=True, name="fritz-hosts-poller").start()

    def _poll_fritzbox_hosts(self) -> None:
        session = requests.Session()
        first_failure_logged = False
        while True:
            try:
                webhook_url = self.config.get("router_hosts_url", "http://127.0.0.1:8010/hosts")
                api_token = self.config.get("fritz_api_token", "")
                headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}

                # BUGFIX (live audit, continuation session): this was hardcoded to
                # 5.0s -- confirmed live via direct measurement that a real,
                # successful Fritz!Box TR-064 round-trip (fritzbox_api.py's
                # get_dhcp_hosts()) genuinely takes ~8s on a cold connection
                # (4.5s device-description/service-discovery handshake + 3.5s
                # get_hosts_info() itself), meaning this poller was timing out on
                # the CLIENT side before the SERVER's own request ever finished --
                # every single one of its 60s-interval polls silently failed,
                # starving _fritz_cache/_fritz_cache_by_mac of ever having real
                # data. fritzbox_api.py's own connection-caching fix (this same
                # session) should make most polls fast after the first, but this
                # timeout stays generous as the real safety margin for a cold
                # start or a genuine reconnect after Fritz!Box drops the session.
                poll_timeout = float(self.config.get("router_hosts_poll_timeout_seconds", 20.0))
                if poll_timeout <= 0:
                    poll_timeout = 20.0
                resp = session.get(webhook_url, headers=headers, timeout=poll_timeout)
                if resp.status_code == 200:
                    hosts_data = resp.json()  
                    new_cache = {}
                    new_cache_by_mac = {}
                    for host in hosts_data:
                        ip = host.get("ip")
                        mac = host.get("mac", "unknown").lower()
                        name = host.get("name", "unknown")
                        if ip:
                            new_cache[ip] = {"mac": mac, "name": name}
                        if mac and mac != "unknown":
                            new_cache_by_mac[mac] = {"ip": ip or "unknown", "name": name}
                    with self._lock:
                        self._fritz_cache = new_cache
                        self._fritz_cache_by_mac = new_cache_by_mac
                    if first_failure_logged:
                        LOGGER.info("✅ FritzBox hosts webhook poll recovered (%d hosts).", len(new_cache))
                        first_failure_logged = False
                else:
                    LOGGER.warning("FritzBox hosts webhook returned HTTP %d. Retrying in 60s.", resp.status_code)
            except Exception as e:
                # BUGFIX (live audit, continuation session): was LOGGER.debug() --
                # invisible at this service's normal INFO level, the exact same
                # silence pattern this project has already found and fixed once
                # before for a different Fritz!Box timeout (ips.py's own
                # router-reconcile worker, 2026-09-04) -- a persistent poll
                # failure here silently starves real hostname/MAC enrichment data
                # with nothing surfacing it. Logged once per failure streak (not
                # every single 60s tick) to avoid spamming the log if Fritz!Box is
                # genuinely down for an extended period.
                if not first_failure_logged:
                    LOGGER.warning("FritzBox hosts webhook poll failed: %s: %s. Retrying every 60s "
                                    "(further failures logged at DEBUG until it recovers).", type(e).__name__, e)
                    first_failure_logged = True
                else:
                    LOGGER.debug("FritzBox hosts webhook poll still failing: %s", e)
            time.sleep(60)

    def _enrich_from_cache(self, ip: str, current_mac: str, current_hostname: str) -> Tuple[str, str]:
        if ip and ip != "unknown":
            with self._lock:
                fritz_data = self._fritz_cache.get(ip)
            if fritz_data:
                f_mac = fritz_data.get("mac", "unknown")
                f_name = fritz_data.get("name", "unknown")
                best_mac = f_mac if f_mac != "unknown" else current_mac
                best_host = f_name if f_name != "unknown" else current_hostname
                return best_mac, best_host

        # BUGFIX (live audit, continuation session): the IP-keyed lookup above can
        # never match for a dual-stack device's IPv6 addresses at all -- Fritz!Box's
        # own DHCP-lease host list is IPv4-only (see _fritz_cache_by_mac's own
        # __init__ comment for the full live-data confirmation). Try the SAME
        # underlying Fritz!Box data a second way, by MAC, whenever a real MAC is
        # already known -- this is the actual fix for the confirmed live gap, not
        # a hypothetical: 9 currently-active devices with a resolved MAC and a real
        # IPv4 address in known_ips stayed hostname=unknown purely because the
        # specific event enriching them happened to pass an IPv6 address as `ip`.
        if current_mac and current_mac != "unknown":
            with self._lock:
                fritz_data_by_mac = self._fritz_cache_by_mac.get(current_mac.lower())
            if fritz_data_by_mac:
                f_name = fritz_data_by_mac.get("name", "unknown")
                if f_name != "unknown":
                    return current_mac, f_name

        if not ip or ip == "unknown":
            return current_mac, current_hostname

        # H5 FIX: All _ip_cache operations now happen under self._lock
        with self._lock:
            entry = self._ip_cache.get(ip)
            if entry is None:
                entry = {"mac": "unknown", "hostname": "unknown"}
                # M6 FIX: LRU eviction via OrderedDict
                if len(self._ip_cache) >= 5000:
                    self._ip_cache.popitem(last=False)  # evict least recently used
                self._ip_cache[ip] = entry
            else:
                self._ip_cache.move_to_end(ip)  # promote to MRU

            if current_hostname and current_hostname != "unknown":
                entry["hostname"] = current_hostname
            if current_mac and current_mac != "unknown":
                entry["mac"] = current_mac

            best_mac = entry["mac"] if (not current_mac or current_mac == "unknown") else current_mac
            best_host = entry["hostname"] if (not current_hostname or current_hostname == "unknown") else current_hostname

        return best_mac, best_host

    def _clean_fake_hostname(self, hostname: str) -> str:
        if hostname == "unknown":
            return hostname
        if re.match(r'^[\d_]+(?:_fritz_box|_lan)?$', hostname):
            return "unknown"
        return hostname

    def resolve_device_id(self, client_ip: str, mac_addr: Optional[str] = None, hostname: Optional[str] = None) -> str:
        # DEVICE-IDENTITY FRAGMENTATION FIX (router special-case): a router genuinely has
        # multiple distinct physical MACs (one per LAN/WLAN/WAN interface), so the
        # MAC-first branch below can never fully unify it into one device_id -- its
        # different interfaces would keep minting separate identities even with the
        # retroactive-merge fix (_merge_orphan_if_fragmented(), see process_dns_identities()
        # below) in place. Pin the configured gateway IP to one fixed canonical device_id
        # instead, checked BEFORE the MAC-first branch so it always wins for this one
        # address regardless of which MAC happens to be resolved for it. Uses the exact
        # same hash formula the ordinary trackable-local-IP branch below would already
        # produce for this literal IP, so a deployment upgrading into this fix sees zero
        # device_id churn for the router's existing gateway-IP identity. Inert (returns
        # nothing here, falls through to the normal branches) when gateway_ip is unset —
        # safe default for any other deployment of this codebase.
        gateway_ip = self.config.get("gateway_ip", "")
        if gateway_ip and client_ip == gateway_ip:
            if mac_addr and mac_addr != "unknown":
                with self._lock:
                    self._gateway_mac = mac_addr
            return self.state_manager.resolve_merge_redirect(stable_device_id(gateway_ip))

        # GENERAL FIX (2026-08-27): the router's OTHER addresses (most commonly its IPv6
        # link-local/ULA, which never equals gateway_ip literally) still deserve the same
        # canonical identity once we've learned its MAC from the branch just above --
        # checked before the generic MAC-first branch below so it can't be shadowed by a
        # coincidental existing device_id/MAC binding.
        if mac_addr and mac_addr != "unknown":
            with self._lock:
                learned_gateway_mac = self._gateway_mac
            if learned_gateway_mac and mac_addr == learned_gateway_mac:
                return self.state_manager.resolve_merge_redirect(stable_device_id(gateway_ip))

        # PHASE 6 FIX (cross-address-family correlation): if this MAC address is already
        # bound to a known device_id — most commonly because we've already seen this same
        # physical device's IPv4 side (via DHCPv4, or now via Zeek's mac-logging.zeek
        # conn.log field on either address family) — anchor to that SAME device_id instead
        # of minting a fresh one from this address. This MUST run before the IP-anchor
        # branch below: since Phase 5, every IPv6 address (link-local/ULA included)
        # independently satisfies _is_trackable_local_ip(), so without this MAC check a
        # dual-stack device's IPv6 traffic would keep cold-starting its own separate
        # DeviceState forever, splitting evidence/threat-detection signal across two
        # profiles for one physical device.
        if mac_addr and mac_addr != "unknown":
            existing_dev_id = self.state_manager.get_device_id_for_mac(mac_addr)
            if existing_dev_id:
                # Already MAC-anchored to a live device_id -- nothing to redirect, this
                # IS the canonical id (resolve_merge_redirect() would be a no-op here by
                # construction, since a dead id is never left bound in _mac_to_device_id).
                return existing_dev_id

        # ARCHITECTURAL FIX: Anchor local private IPs to guarantee unified correlation
        # between Pi-hole DNS logs and Zeek flow logs for the exact same physical device.
        if _is_trackable_local_ip(client_ip):
            result = stable_device_id(client_ip)
        elif hostname and not _is_generic_hostname(hostname):
            result = stable_device_id(f"host:{hostname.lower()}")
        elif mac_addr and mac_addr != "unknown":
            result = stable_device_id(mac_addr)
        else:
            result = stable_device_id(client_ip)

        # BUGFIX (identity-merge race, handover 2026-09-20): every branch above is a pure,
        # state-unaware hash -- stable_device_id() has no memory of what it's hashed
        # before. If this same ip/hostname/mac was already used to mint a device_id that
        # has since been discarded via merge_into_canonical() (e.g. a per-flow
        # MAC-resolution miss on a device that's otherwise already MAC-anchored
        # elsewhere), this would otherwise resurrect a zombie DeviceState under the dead
        # id and silently steal this address's future traffic from its real canonical
        # identity -- confirmed live via merge_into_canonical()'s own abort-warning
        # firing because the resurrected id is, by definition, "not a currently tracked
        # device". Resolving through the redirect map transparently upgrades any dead id
        # straight to its live successor, so the resurrection never happens.
        return self.state_manager.resolve_merge_redirect(result)

    def process_dns_identities(self, dns_rows: List[Dict[str, Any]], zeek_fx: Any, ml_registry: Any = None,
                                ips_mitigator: Any = None, familiarity: Any = None,
                                evidence_store: Any = None, metrics_exporter: Any = None) -> List[str]:
        if not dns_rows:
            return []

        active_device_ids: Set[str] = set()
        type_overrides = self.config.get("device_type_overrides", {})
        alpha = float(self.config.get("baseline_alpha", 0.05))

        for row in dns_rows:
            client_ip = str(row.get("client_ip", "")).strip()
            if not client_ip or not _is_trackable_local_ip(client_ip):
                continue

            raw_hostname = str(row.get("hostname", "unknown")).strip()
            hostname = sanitize_hostname(raw_hostname) or "unknown"
            
            if hostname == "unknown" and zeek_fx:
                zeek_host = zeek_fx.get_hostname(client_ip)
                if zeek_host and zeek_host != "unknown":
                    hostname = sanitize_hostname(zeek_host) or "unknown"

            hostname = self._clean_fake_hostname(hostname)
            mac_addr = zeek_fx.get_mac(client_ip) if zeek_fx else "unknown"
            mac_addr, hostname = self._enrich_from_cache(client_ip, mac_addr, hostname)

            dev_id = self.resolve_device_id(client_ip, mac_addr, hostname)
            # DEVICE-IDENTITY FRAGMENTATION FIX: dev_id may differ from a device_id this
            # exact client_ip was ALREADY tracked under (e.g. its MAC just became known
            # for the first time and resolves to a different, richer canonical identity)
            # -- fold that now-orphaned identity in before creating/reusing dev_id below.
            self._merge_orphan_if_fragmented(client_ip, dev_id, ml_registry, familiarity,
                                              ips_mitigator, evidence_store, metrics_exporter)
            # PHASE 6: publish/refresh the MAC->device_id binding as soon as we know it, so
            # the NEXT address family (or the next batch's IPv6 row for this same device)
            # can find it via resolve_device_id()'s MAC-first check above.
            if mac_addr and mac_addr != "unknown":
                self.state_manager.bind_mac(mac_addr, dev_id)

            state = self.state_manager.get_or_create(
                device_id=dev_id, client_ip=client_ip, hostname=hostname, alpha=alpha,
                ml_registry=ml_registry, **self._reidentify_kwargs(client_ip, zeek_fx)
            )
            self._release_stale_isolation_if_merged(ips_mitigator)

            with self.state_manager.lock_device(dev_id) as locked_state:
                self._refresh_identity_signals(locked_state, mac_addr, client_ip, hostname, zeek_fx)
                self.apply_device_type(locked_state, type_overrides)

            active_device_ids.add(dev_id)

            # Domain popularity learned on this network (replaces Tranco). Blocked queries are not learned:
            # ad/tracker lists must never become "popular, therefore trusted".
            popularity = getattr(self, "popularity", None)
            if popularity is not None and row.get("status") not in _PIHOLE_BLOCKED_STATUSES:
                popularity.observe(dev_id, row.get("domain", ""), row.get("timestamp"))

        return list(active_device_ids)

    def _reidentify_kwargs(self, client_ip: str, zeek_fx: Any) -> Dict[str, Any]:
        """PHASE 4: bundles the fingerprint data + tunable thresholds passed into
        StateManager.get_or_create() so it can attempt MAC-rotation re-identification on a
        cold start. All three thresholds are operator-tunable via config.yaml without a
        code change, once real-world confidence scores from the log lines have been
        observed (`identity_reidentify_*` keys)."""
        if not zeek_fx:
            return {"dhcp_fingerprint": None, "ja4_set": None, "reidentify": False}
        return {
            "dhcp_fingerprint": zeek_fx.get_dhcp_fingerprint(client_ip),
            "ja4_set": zeek_fx.get_ja4_set(client_ip),
            "reidentify": bool(self.config.get("identity_reidentify_enabled", True)),
            "min_confidence": float(self.config.get("identity_reidentify_min_confidence", AUTO_MERGE_CONFIDENCE)),
            "candidate_window": float(self.config.get("identity_reidentify_window_seconds", 1800.0)),
        }

    def _release_stale_isolation_if_merged(self, ips_mitigator: Any) -> None:
        """BUGFIX (dead-code audit): IPSMitigator.unisolate_all() existed with zero
        callers -- a device isolated under an old MAC/IP that then rotated identity (a
        get_or_create() re-identify merge) had no code path ever releasing the stale
        isolation bookkeeping tied to its old identifiers. Called right after
        get_or_create() and OUTSIDE state_manager's lock (unisolate_all() can make a real
        outbound HTTP call to the router) -- pop_last_migrated_isolation_target() is a
        consume-once side channel, so this is a no-op on every call that wasn't a merge.
        unisolate_all() itself is a safe no-op if the old identifiers weren't actually
        isolated (it checks membership before doing anything)."""
        if ips_mitigator is None:
            return
        target = self.state_manager.pop_last_migrated_isolation_target()
        if not target:
            return
        ips_mitigator.unisolate_all(mac_addr=target["mac_addr"], ip_addr=target["ip_addr"])

    def _merge_orphan_if_fragmented(self, client_ip: str, dev_id: str, ml_registry: Any, familiarity: Any,
                                     ips_mitigator: Any, evidence_store: Any, metrics_exporter: Any) -> Optional[str]:
        """DEVICE-IDENTITY FRAGMENTATION FIX: resolve_device_id() can return a DIFFERENT
        device_id for client_ip than whatever it was already tracked under -- most
        commonly because this IP's MAC just became known and resolves (via the MAC-first
        branch) to a richer, already-established canonical identity, while this exact IP
        was previously cold-started under its own IP-anchored device_id before that MAC
        was known. Without this, that earlier device_id is permanently orphaned: nothing
        ever points traffic, evidence, or containment at it again, but it also never gets
        folded into the canonical identity it actually belongs to (confirmed live: 24
        such fragmented groups across 60 of 88 tracked devices in one real deployment).

        Only fires for the actual fragmentation scenario: get_device_id_for_ip(client_ip)
        returns None (this IP has never been tracked) or the SAME id resolve_device_id()
        just returned (the ordinary, non-fragmented case) in every other situation --
        identical to today's behavior when nothing is actually orphaned.

        Called BEFORE bind_mac()/get_or_create() run for this row, so dev_id is already
        the final canonical id by the time either of those touch it.

        Returns the orphan_id that was actually merged, or None if nothing
        merged (continuation session: 
        LiveIdentityManager overrides this method to ALSO fold the same merge
        into the argus graph via GraphStore.merge_device(orphan_id, dev_id) --
        it needs the SPECIFIC orphan_id captured here, not just a bool,
        because get_device_id_for_ip(client_ip) would return the UPDATED
        (post-merge) value if re-queried after merge_into_canonical() runs, not
        the orphan's original id. merge_into_canonical() itself can still
        no-op (e.g. dev_id isn't tracked yet -- this runs BEFORE
        get_or_create() creates it, on a genuinely first sighting), which is
        exactly why the real return value is needed rather than inferring
        success from the trigger condition alone. Every pre-existing caller
        ignores the return value, so this is purely additive, not a behavior
        change for them."""
        orphan_id = self.state_manager.get_device_id_for_ip(client_ip)
        if not orphan_id or orphan_id == dev_id:
            return None
        merged = self.state_manager.merge_into_canonical(orphan_id, dev_id, ml_registry=ml_registry, familiarity=familiarity)
        if not merged:
            return None
        LOGGER.warning(
            "🔗 RETROACTIVE IDENTITY MERGE: orphan %s folded into canonical %s (ip=%s) -- "
            "its own accumulated state was discarded per merge policy, not blended.",
            orphan_id, dev_id, client_ip
        )
        self._release_stale_isolation_if_merged(ips_mitigator)
        self._cleanup_merged_orphan(evidence_store, metrics_exporter)
        return orphan_id

    def _cleanup_merged_orphan(self, evidence_store: Any, metrics_exporter: Any) -> None:
        """Consumes the orphan-merge cleanup side channel set by merge_into_canonical()
        (via _merge_orphan_if_fragmented() above) and purges the discarded orphan's
        now-stale evidence/metric rows. Mirrors _release_stale_isolation_if_merged()'s
        own consume-once, no-op-if-nothing-pending, no-op-if-collaborator-not-supplied
        style exactly."""
        info = self.state_manager.pop_last_orphan_merge_cleanup()
        if not info:
            return
        if evidence_store is not None:
            evidence_store.clear_device(info["orphan_id"])
        if metrics_exporter is not None:
            metrics_exporter.remove_device_metric_labels(
                info["orphan_id"], info["orphan_hostname"], info["orphan_device_type"]
            )

    def _refresh_identity_signals(self, locked_state: Any, mac_addr: str, client_ip: str,
                                    hostname: str, zeek_fx: Any, overwrite_hostname: bool = True) -> None:
        """Updates the mutable per-cycle identity fields on an already-locked DeviceState:
        MAC/IP/hostname (existing behavior, unchanged per-caller semantics via
        `overwrite_hostname`) plus the new PHASE 4 fingerprint/heartbeat fields."""
        locked_state.mac_address = mac_addr or "unknown"
        locked_state.client_ip = client_ip
        locked_state.last_seen = time.time()
        # PHASE 6 (cross-address-family correlation): record every address this device has
        # been seen at, so feature/evidence aggregation (zeek_features.get_features et al.,
        # via pipeline.py passing state.known_ips) can sum activity across BOTH its IPv4 and
        # IPv6 addresses instead of only the single "most recently active" client_ip.
        if client_ip and client_ip != "unknown":
            locked_state.known_ips.add(client_ip)
        if hostname != "unknown":
            if overwrite_hostname or locked_state.hostname == "unknown":
                locked_state.hostname = hostname
        if zeek_fx:
            dhcp_fp = zeek_fx.get_dhcp_fingerprint(client_ip)
            if dhcp_fp:
                locked_state.dhcp_fingerprint = dhcp_fp
            for ja4_hash in zeek_fx.get_ja4_set(client_ip):
                locked_state.ja4_seen.add(ja4_hash)

    def process_zeek_identities(self, zeek_events: List[Dict[str, Any]], zeek_fx: Any, ml_registry: Any = None,
                                 ips_mitigator: Any = None, familiarity: Any = None,
                                 evidence_store: Any = None, metrics_exporter: Any = None) -> List[str]:
        if not zeek_events:
            return []

        active_device_ids: Set[str] = set()
        type_overrides = self.config.get("device_type_overrides", {})
        alpha = float(self.config.get("baseline_alpha", 0.05))

        for event in zeek_events:
            # handle both conn/dns "id.orig_h" and dhcp "client_addr"
            src_ip = event.get("id.orig_h", event.get("orig_h", event.get("client_addr", "")))
            if not src_ip or not _is_trackable_local_ip(src_ip):
                continue

            hostname = "unknown"
            if zeek_fx:
                resolved_host = zeek_fx.get_hostname(src_ip)
                if resolved_host and resolved_host != "unknown":
                    hostname = sanitize_hostname(resolved_host) or "unknown"

            hostname = self._clean_fake_hostname(hostname)
            mac_addr = zeek_fx.get_mac(src_ip) if zeek_fx else "unknown"
            mac_addr, hostname = self._enrich_from_cache(src_ip, mac_addr, hostname)

            dev_id = self.resolve_device_id(src_ip, mac_addr, hostname)
            # DEVICE-IDENTITY FRAGMENTATION FIX: see matching comment in
            # process_dns_identities() above.
            self._merge_orphan_if_fragmented(src_ip, dev_id, ml_registry, familiarity,
                                              ips_mitigator, evidence_store, metrics_exporter)
            # PHASE 6: see matching comment in process_dns_identities() above.
            if mac_addr and mac_addr != "unknown":
                self.state_manager.bind_mac(mac_addr, dev_id)

            state = self.state_manager.get_or_create(
                device_id=dev_id, client_ip=src_ip, hostname=hostname, alpha=alpha,
                ml_registry=ml_registry, **self._reidentify_kwargs(src_ip, zeek_fx)
            )
            self._release_stale_isolation_if_merged(ips_mitigator)

            with self.state_manager.lock_device(dev_id) as locked_state:
                self._refresh_identity_signals(locked_state, mac_addr, src_ip, hostname, zeek_fx,
                                                 overwrite_hostname=False)
                self.apply_device_type(locked_state, type_overrides)

            active_device_ids.add(dev_id)

        return list(active_device_ids)

    def apply_device_type(self, state: Any, overrides: Dict[str, str]) -> None:
        """PHASE 1 FIX (device-sensitivity source): tags whether device_type came from an
        operator-set override (device_type_is_override=True) or from hostname-substring
        inference (False). pipeline.py's infra-sensitivity evidence filter only trusts the
        override path — a device can't self-report its way into being treated as verified
        network infrastructure just by choosing a hostname like "my-router"."""
        client_ip = getattr(state, "client_ip", "")
        device_id = getattr(state, "device_id", "")
        hostname = getattr(state, "hostname", "").lower()

        # WebUI device-labeling (PRODUCTIZATION_ROADMAP.md Phase 4): an explicit user
        # confirmation through the dashboard outranks config.yaml's bulk
        # device_type_overrides list below -- a human looked at THIS specific device and
        # said what it is, which is a higher-trust signal than a hostname-substring rule
        # written for the whole network. mtime-cached read (device_labels.py), cheap to
        # call every cycle.
        confirmed_label = get_confirmed_device_label(device_id) if device_id else None
        if confirmed_label:
            state.device_type = confirmed_label
            state.device_type_is_override = True
            return

        if client_ip in overrides:
            state.device_type = overrides[client_ip]
            state.device_type_is_override = True
            return
        if device_id in overrides:
            state.device_type = overrides[device_id]
            state.device_type_is_override = True
            return
        if hostname and hostname != "unknown":
            for pattern, dtype in overrides.items():
                if pattern.lower() in hostname:
                    state.device_type = dtype
                    state.device_type_is_override = True
                    return
        # BUGFIX (found via the device-identity-merge cleanup script's real output): this
        # used to only re-infer when device_type was still the literal string "unknown" --
        # but at the time, infer_device_type() (utils.py) never actually returned
        # "unknown" itself; its final fallback was "laptop". So this branch could only
        # ever fire ONCE, on a device's very first apply_device_type() call (before
        # device_type has been set at all). A device whose real hostname resolves on a
        # LATER cycle than its first sighting (the common case -- e.g. a router first
        # seen via an address with no hostname yet) was PERMANENTLY stuck with whatever
        # infer_device_type("unknown") produced at cold-start ("laptop"), even after its
        # real hostname became known. Confirmed live: a router's canonical identity
        # (post device-identity-fragmentation-merge) still showed device_type="laptop"
        # despite the router's real hostname having been known for hours. Re-infer whenever
        # the CURRENT value isn't an explicit operator override (device_type_is_override
        # reused exactly for this distinction) instead of only when it's literally
        # unset -- a stable hostname always re-infers to the same classification, so
        # this is idempotent/self-correcting, not flapping. (infer_device_type()'s
        # fallback is "unknown" again as of 2026-08-29 -- this re-infer-every-cycle
        # behavior stays correct either way, since it's driven by device_type_is_override,
        # not by comparing against any specific string.)
        if not getattr(state, "device_type_is_override", False):
            # BUGFIX (2026-08-29, live audit): infer_device_type() has always accepted a
            # mac_vendor parameter for exactly this purpose, but no caller ever passed
            # one -- confirmed on production state, 12 of 13 "laptop"-classified devices
            # actually had hostname="unknown" (no real signal at all). MAC OUI lookup
            # (utils.get_mac_vendor(), offline via the manuf package) resolves some of
            # these even with no hostname -- e.g. an Espressif-vendor MAC correctly
            # types as "iot" instead of falling all the way through to the fallback.
            # Devices with a randomized/locally-administered MAC (increasingly common
            # iOS/Android privacy behavior) get "" back and fall through exactly as
            # before -- this is additive, not a behavior change for hostname-resolved
            # devices.
            mac_vendor = get_mac_vendor(getattr(state, "mac_address", ""))
            new_type = infer_device_type(hostname, mac_vendor=mac_vendor)
            old_type = getattr(state, "device_type", None)
            # Dashboard-redesign metric: only counts an ACTUAL change of the stored
            # value (e.g. the DeviceState constructor's cold-start guess or an earlier
            # inference giving way to a hostname-informed one) -- a stable hostname
            # always re-infers to the same type per the fix above, so this doesn't flap.
            if old_type and old_type != new_type:
                device_type_reclassifications_total.labels(
                    device=device_id, hostname=hostname or "unknown", to_type=new_type
                ).inc()
            state.device_type = new_type
            state.device_type_is_override = False