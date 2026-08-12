"""
ips.py - Independent Subsystem IPS & Mitigation Engine.

Handles automated threat response across three decoupled layers.

RECENT FIXES:
- FIXED (FATAL THREAD DEADLOCK): Upgraded `self._lock` from a standard `threading.Lock()` to a 
  `threading.RLock()` (Reentrant Lock). This resolves a catastrophic pipeline freeze where `mitigate()` 
  acquired the lock to trigger `_unisolate_device_router()`, which then attempted to acquire the exact 
  same lock upon receiving an HTTP 202 success response, permanently deadlocking the main execution thread.
- ADDED (DUAL-STACK IPv6 TARPIT): Upgraded the Scapy mitigation engine to sniff for IPv6 Neighbor Discovery 
  Protocol (NDP) requests. Dynamically intercepts ICMPv6ND_NS (Neighbor Solicitation) packets and injects 
  spoofed ICMPv6ND_NA (Neighbor Advertisement) packets to blackhole IPv6 routing.
- FIXED (HARDWARE MITIGATION BYPASS): Added dynamic MAC address reconstruction from `device_id`. 
- ADDED (SECURE AUTHENTICATION): Implemented Pi-hole v6 session ID ('sid') header authentication, dynamically 
  pulling from the configuration engine (which supports environment variable overrides).
"""

import json
import logging
import threading
import time
import requests
from pathlib import Path
from typing import Dict, Any, Optional

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
    ips_dead_letter_gauge
)

LOGGER = logging.getLogger("home_ids.ips")

SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, send, conf, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sniff
    conf.verb = 0
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy").setLevel(logging.ERROR)
    SCAPY_AVAILABLE = True
except (ImportError, Exception):
    pass


class IPSMitigator:
    def __init__(self, config: Dict[str, Any], state_manager: Optional[Any] = None, stream_writer: Optional[Any] = None):
        self.config = config
        self.stream_writer = stream_writer
        
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
        self._tarpit_active_targets = ips_state.get("tarpit_targets", {})
        self._router_isolated_devices = ips_state.get("router_isolated_devices", {})
        self._operator_released_devices = ips_state.get("operator_released_devices", {})
        
        self._init_arp_tarpit()
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

    def _init_arp_tarpit(self) -> None:
        tarpit_enabled = bool(self.config.get("ips_tarpit_enabled", True))
        ips_tarpit_status.set(1.0 if tarpit_enabled else 0.0)

        if not tarpit_enabled:
            LOGGER.info("🛡️ Scapy ARP Tarpit subsystem disabled via configuration.")
            return

        if not SCAPY_AVAILABLE:
            LOGGER.warning("⚠️ Scapy ARP Tarpit disabled: No module named 'scapy'")
            ips_tarpit_status.set(0.0)
            return

        try:
            conf.verb = 0
            LOGGER.info("🛡️ Scapy RAW socket access verified. Layer-2 Dual-Stack (ARP & NDP) Tarpit module ARMED.")
            
            self._tarpit_thread = threading.Thread(target=self._arp_tarpit_loop, daemon=True, name="arp_tarpit_worker")
            self._tarpit_thread.start()
            
            self._ndp_tarpit_thread = threading.Thread(target=self._ndp_tarpit_loop, daemon=True, name="ndp_tarpit_worker")
            self._ndp_tarpit_thread.start()
            
        except Exception as exc:
            LOGGER.error("⚠️ Scapy Dual-Stack Tarpit bypassing. Lacks raw socket privileges: %s", exc)
            ips_tarpit_status.set(0.0)

    def _ndp_tarpit_loop(self) -> None:
        def handle_ndp(pkt):
            if pkt.haslayer(ICMPv6ND_NS) and pkt.haslayer(IPv6) and pkt.haslayer(Ether):
                mac_src = pkt[Ether].src
                
                is_trapped = False
                with self._lock:
                    for meta in self._tarpit_active_targets.values():
                        if meta.get("mac", "").lower() == mac_src.lower():
                            is_trapped = True
                            break
                            
                if is_trapped:
                    target_ip = pkt[IPv6].src
                    requested_ip = pkt[ICMPv6ND_NS].tgt
                    bogus_mac = "00:11:22:33:44:55"
                    
                    dst_ip = target_ip if target_ip != "::" else "ff02::1"
                    
                    spoofed_pkt = (
                        Ether(dst=mac_src, src=bogus_mac) /
                        IPv6(dst=dst_ip, src=requested_ip) /
                        ICMPv6ND_NA(tgt=requested_ip, R=1, S=1, O=1) /
                        ICMPv6NDOptDstLLAddr(lladdr=bogus_mac)
                    )
                    send(spoofed_pkt, verbose=False)

        try:
            sniff(filter="icmp6", prn=handle_ndp, store=0)
        except Exception as exc:
            LOGGER.debug("NDP Tarpit sniffing exception: %s", exc)

    def sync_state_from_manager(self) -> None:
        """Synchronizes in-memory IPS targets with disk state modified by external processes."""
        with self._lock:
            ips_state = self.state_manager.get_ips_state()
            disk_tarpits = ips_state.get("tarpit_targets", {})
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

    def _ensure_tarpit_target(self, client_ip: str, mac_addr: str, hostname: str, dev_id: str) -> None:
        """Create or refresh a tarpit target using the latest MAC if it becomes known later."""
        if not client_ip or client_ip == "unknown":
            return

        with self._lock:
            target = self._tarpit_active_targets.get(client_ip)
            if target is None:
                self._tarpit_active_targets[client_ip] = {"mac": mac_addr or "unknown", "hostname": hostname, "dev_id": dev_id}
                ips_tarpit_active.labels(device=dev_id, hostname=hostname, mac=mac_addr or "unknown").set(1.0)
                LOGGER.info("🛡️ Registered tarpit target for %s using MAC %s", client_ip, mac_addr or "unknown")
            else:
                if mac_addr and mac_addr != "unknown" and target.get("mac") != mac_addr:
                    target["mac"] = mac_addr
                    target["hostname"] = hostname
                    target["dev_id"] = dev_id
                    ips_tarpit_active.labels(device=dev_id, hostname=hostname, mac=mac_addr).set(1.0)
                    LOGGER.info("🛡️ Updated tarpit target %s with latest MAC %s", client_ip, mac_addr)
                else:
                    target["hostname"] = hostname or target.get("hostname", "unknown")
                    target["dev_id"] = dev_id or target.get("dev_id", dev_id)
            self._save_queues()

    def get_containment_status(self, client_ip: str, mac_addr: str = "unknown", domain: str = "") -> str:
        """Returns readable Telegram containment badge (TARPITTED, ROUTER ISOLATED, DOMAIN BLOCKED, or UNBLOCKED)."""
        with self._lock:
            if client_ip in self._tarpit_active_targets:
                return "🔒 TARPITTED (Layer-2 ARP/NDP)"
            if mac_addr and mac_addr != "unknown" and mac_addr in self._router_isolated_devices:
                return "🔒 ROUTER ISOLATED (Fritz!Box WAN)"
        # C5 FIX: _blocked_domains was never an attribute on IPSMitigator;
        # blocked domains live in state_manager IPS state.
        if domain and domain not in ("unknown", ""):
            ips_state = self.state_manager.get_ips_state()
            if domain in ips_state.get("blocked_domains", {}):
                return "🔒 DOMAIN BLOCKED (Pi-hole DNS)"
        return "🔓 ACTIVE / UNBLOCKED (Monitoring Only)"

    def mitigate(
        self,
        st: Any,
        target_domain: str,
        risk_score: float,
        c2_hits: int,
        dga_burst: bool,
        lateral_threat: bool,
        is_safe: bool,
        ti_engine: Optional[Any] = None,
        reason: str = "High Risk Identified",
        fp_verdict: Optional[dict] = None
    ) -> None:
        LOGGER.debug("Mitigate evaluation triggered | Device: %s, Domain: %s, Risk: %.2f, Safe: %s", 
                     getattr(st, "hostname", "unknown"), target_domain, risk_score, is_safe)

        # FP ENGINE TIGHT GATING: Abort mitigation immediately if FP engine suppressed alert
        if fp_verdict and fp_verdict.get("suppress", False):
            LOGGER.info("🛡️ [IPS] Mitigation suppressed by FP Engine verdict for device %s.", getattr(st, "hostname", "unknown"))
            return

        client_ip = getattr(st, "client_ip", "unknown")
        hostname = getattr(st, "hostname", "unknown")
        dev_id = getattr(st, "device_id", "unknown")
        mac_addr = getattr(st, "mac_address", "unknown")

        # Fix bogus SHA256 MAC derivation bug: only format dev_id as MAC if it's not a SHA256 hash prefix
        if (not mac_addr or mac_addr == "unknown") and dev_id != "unknown":
            if len(dev_id) == 12 and all(c in "0123456789abcdefABCDEF" for c in dev_id) and not dev_id.isdigit():
                mac_addr = ":".join(dev_id[i:i+2] for i in range(0, 12, 2))

        # LATCHED CONTAINMENT PROTECTION:
        # Full host containment (Scapy Layer-2 tarpit & Fritz!Box WAN isolation) cuts off 100% of network traffic.
        # As a result, feature query rates naturally decay to 0 over the 5-minute rolling window.
        # Automatically releasing hardware/tarpit isolation purely on zero-traffic decay creates an infinite flapping loop:
        # (ISOLATE -> 0 TRAFFIC -> DECAY TO 0 -> AUTO UNISOLATE -> C2 BEACON AGAIN -> RE-ISOLATE).
        # Therefore, hardware router isolation and Scapy tarpits are LATCHED containment states:
        # They are ONLY auto-released if the device is explicitly marked safe (is_safe=True via safe_ips/patterns)
        # or via an explicit operator un-isolation command.
        if is_safe:
            should_unisolate_router = False
            with self._lock:
                if client_ip in self._tarpit_active_targets:
                    LOGGER.info("Device %s marked safe. Releasing from ARP/NDP Tarpit.", client_ip)
                    del self._tarpit_active_targets[client_ip]
                    self._save_queues()
                if mac_addr in self._router_isolated_devices:
                    should_unisolate_router = True

            if should_unisolate_router:
                LOGGER.info("Device %s marked safe. Initiating router un-isolation restore.", hostname)
                self._unisolate_device_router(mac=mac_addr, ip=client_ip, hostname=hostname, dev_id=dev_id)
            return

        # Check operator release cooldown status quietly
        now = time.time()
        cooldown_sec = float(self.config.get("operator_release_cooldown_seconds", 3600.0))
        is_operator_released = False
        with self._lock:
            released_snapshot = dict(self._operator_released_devices)
        for ident in (mac_addr, client_ip, hostname, dev_id):
            if ident and ident != "unknown" and ident in released_snapshot:
                rel_time = released_snapshot[ident]
                if (now - rel_time) < cooldown_sec:
                    is_operator_released = True
                    break

        interactive_mode = bool(self.config.get("interactive_blocking_enabled", False))
        pihole_enabled = bool(self.config.get("ips_pihole_enabled", True)) and bool(self.config.get("ips_enabled", True))
        alert_threshold = float(self.config.get("alert_threshold", 6.0))

        if pihole_enabled and target_domain and target_domain not in ("unknown", "-"):
            safe_domains = set(self.config.get("safe_domains", []))
            is_domain_safe = (target_domain in safe_domains) or (ti_engine and ti_engine.is_allowlisted(target_domain))

            if not is_domain_safe:
                if risk_score >= alert_threshold or dga_burst or c2_hits > 0:
                    LOGGER.debug("Risk threshold breached. Executing immediate Pi-hole block protocol for %s.", target_domain)
                    self._block_domain(domain=target_domain, hostname=hostname, device_ip=client_ip, dev_id=dev_id, reason=reason)
            else:
                LOGGER.debug("Mitigation suppressed: %s is on the Global Trust/Safe list.", target_domain)

        router_enabled = bool(self.config.get("ips_router_enabled", False))
        if router_enabled and (risk_score >= 8.5 or lateral_threat):
            if is_operator_released and not lateral_threat:
                LOGGER.debug("🛡️ Router isolation suppressed for %s: Operator release cooldown active.", hostname)
            elif interactive_mode and not lateral_threat:
                LOGGER.info("🛡️ [INTERACTIVE MODE] Router isolation for %s queued for Telegram approval.", hostname)
            elif mac_addr and mac_addr != "unknown":
                with self._lock:
                    if mac_addr not in self._router_isolated_devices:
                        if is_operator_released and lateral_threat:
                            LOGGER.critical("🚨 [LATERAL THREAT OVERRIDE] Device %s attempted internal port scan during release cooldown! Router isolation re-enforced.", hostname)
                        LOGGER.critical("Extreme risk detected. Executing hardware router isolation for MAC %s.", mac_addr)
                        success = self._isolate_device_router(mac=mac_addr, ip=client_ip, hostname=hostname, dev_id=dev_id, reason=f"Risk Score {risk_score:.1f}: {reason}")
                        if success:
                            self._router_isolated_devices[mac_addr] = {"ip": client_ip, "hostname": hostname, "dev_id": dev_id}
                            self._save_queues()

        tarpit_enabled = bool(self.config.get("ips_tarpit_enabled", True))
        is_sim = bool(self.config.get("simulation_mode", False))
        if tarpit_enabled and (SCAPY_AVAILABLE or is_sim) and (risk_score >= 9.0 or lateral_threat):
            if is_operator_released and not lateral_threat:
                LOGGER.debug("🛡️ Layer-2 Tarpit suppressed for %s: Operator release cooldown active.", client_ip)
            elif interactive_mode and not lateral_threat:
                LOGGER.info("🛡️ [INTERACTIVE MODE] Layer-2 Tarpit for %s queued for Telegram approval.", client_ip)
            else:
                if not mac_addr or mac_addr == "unknown":
                    ips_errors_metric.labels(target_type="mac_unknown_tarpit").inc()
                    LOGGER.warning("⚠️ MAC address unknown for %s; tarpit activation deferred until a later Zeek/ARP identification update.", client_ip)
                else:
                    with self._lock:
                        if client_ip not in self._tarpit_active_targets:
                            if is_operator_released and lateral_threat:
                                LOGGER.critical("🚨 [LATERAL THREAT OVERRIDE] Device %s attempted internal port scan during release cooldown! Layer-2 Tarpit re-enforced.", hostname)
                            LOGGER.warning("High risk detected. Activating Scapy Layer-2 ARP/NDP Tarpit for IP %s (%s).", client_ip, mac_addr)
                            self._tarpit_active_targets[client_ip] = {"mac": mac_addr, "hostname": hostname, "dev_id": dev_id}
                            self._save_queues()
                            ips_tarpit_active.labels(device=dev_id, hostname=hostname, mac=mac_addr).set(1.0)
                            LOGGER.critical("⚠️ [DUAL-STACK TARPIT] Trapped compromised device %s (%s) in Layer-2 isolation.", hostname, client_ip)
                        else:
                            self._ensure_tarpit_target(client_ip=client_ip, mac_addr=mac_addr, hostname=hostname, dev_id=dev_id)

    def _arp_tarpit_loop(self) -> None:
        while True:
            try:
                gateway_ip = self.config.get("fritz_ip", "192.168.1.1")
                with self._lock:
                    targets = dict(self._tarpit_active_targets)
                for ip, meta in targets.items():
                    mac = meta["mac"]
                    pkt = Ether(dst=mac) / ARP(op=2, psrc=gateway_ip, pdst=ip, hwsrc="00:11:22:33:44:55")
                    send(pkt, verbose=False)
            except Exception as exc:
                LOGGER.debug("ARP Tarpit iteration exception: %s", exc)
            time.sleep(2.0)

    def _block_domain(self, domain: str, hostname: str, device_ip: str, dev_id: str, reason: str = "") -> bool:
        ips_state = self.state_manager.get_ips_state()
        
        # Self-healing desync check: Clear queues if block is already confirmed active
        if domain in ips_state.get("blocked_domains", {}):
            with self._lock:
                modified = False
                if domain in self._retry_queue:
                    self._retry_queue.pop(domain)
                    try: ips_queue_status_gauge.remove(dev_id, hostname, domain)
                    except: pass
                    modified = True
                if domain in self._dead_letter:
                    self._dead_letter.pop(domain)
                    try: ips_dead_letter_gauge.remove(dev_id, hostname, domain)
                    except: pass
                    modified = True
                if modified:
                    self._save_queues()
            return True
            
        comment = f"Home-IDS Auto-Block | Device: {hostname} | Trigger: {reason}"
        api_url = self.config.get("pihole_api_url", "")
        # AUDIT FIX #9: Pi-hole API path is now configurable, not hardcoded to /api/v2/domains
        api_path = self.config.get("pihole_api_path", "/api/v2/domains")

        if not api_url:
            LOGGER.warning("⚠️ Pi-hole API URL is not configured. Cannot enforce network block for domain %s.", domain)
            return False

        timeout_seconds = float(self.config.get("pihole_api_timeout_seconds", 5.0))
        if timeout_seconds <= 0:
            timeout_seconds = 5.0

        # Inject the authentication token from config (populated automatically from ENV by config.py)
        api_password = self.config.get("pihole_api_password", "")
        headers = {"sid": api_password} if api_password else {}

        try:
            resp = self.session.post(
                f"{api_url}{api_path}",
                json={"domain": domain, "type": "black", "comment": comment},
                headers=headers,
                timeout=timeout_seconds
            )
            if resp.status_code in (200, 201, 204):
                self._finalize_block(domain, hostname, device_ip, dev_id)
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
                try: ips_queue_status_gauge.remove(dev_id, hostname, domain)
                except: pass
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

    def _finalize_block(self, domain, hostname, device_ip, dev_id):
        timestamp = time.time()
        # Snapshot and update IPS state while holding the state-manager lock, then flush outside the lock.
        with self.state_manager._global_lock:
            ips_state = self.state_manager.get_ips_state()
            ips_state["blocked_domains"][domain] = {
                "device_id": dev_id,
                "hostname": hostname,
                "device_ip": device_ip,
                "timestamp": timestamp,
                "status": "active",
                "persisted": True,
            }
            self.state_manager.save_ips_state(ips_state)
        self.state_manager.flush_to_disk()

        with self._lock:
            modified = False
            if domain in self._retry_queue:
                self._retry_queue.pop(domain)
                try: ips_queue_status_gauge.remove(dev_id, hostname, domain)
                except: pass
                modified = True
            if domain in self._dead_letter:
                self._dead_letter.pop(domain)
                try: ips_dead_letter_gauge.remove(dev_id, hostname, domain)
                except: pass
                modified = True
            if modified:
                self._save_queues()

        try:
            ips_active_blocks_gauge.labels(device=dev_id, hostname=hostname, domain=domain).set(1.0)
            ips_pihole_blocks_metric.labels(device=dev_id, hostname=hostname, domain=domain).inc()
        except Exception:
            pass
            
        LOGGER.warning("🛑 [PI-HOLE IPS] Blocked malicious domain %s (Device: %s)", domain, hostname)
        return True

    def _retry_worker(self):
        """H4 FIX: Background retry worker with exponential backoff per-domain attempt count."""
        while True:
            time.sleep(30)
            if not self.config.get("ips_pihole_enabled", True):
                continue
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
                self._block_domain(domain, meta["hostname"], meta.get("device_ip", ""), meta["device_id"], meta["reason"])

    def unblock_domain(self, domain: str) -> bool:
        if not domain: return False
        api_url = self.config.get("pihole_api_url", "")
        api_path = self.config.get("pihole_api_path", "/api/v2/domains")
        
        if api_url and self.config.get("ips_pihole_enabled", True):
            api_password = self.config.get("pihole_api_password", "")
            headers = {"sid": api_password} if api_password else {}
            
            try:
                timeout_seconds = float(self.config.get("pihole_api_timeout_seconds", 5.0))
                if timeout_seconds <= 0:
                    timeout_seconds = 5.0
                self.session.delete(
                    f"{api_url}{api_path}",
                    json={"domain": domain, "type": "black"},
                    headers=headers,
                    timeout=timeout_seconds
                )
            except Exception as e:
                ips_errors_metric.labels(target_type="pihole_unblock_api").inc()

        hostname, dev_id = "unknown", "unknown"
        with self.state_manager._global_lock:
            ips_state = self.state_manager.get_ips_state()
            meta = ips_state.get("blocked_domains", {}).pop(domain, None)
            if meta:
                hostname, dev_id = meta.get("hostname", "unknown"), meta.get("device_id", "unknown")
            self.state_manager.save_ips_state(ips_state)
            self.state_manager.flush_to_disk()

        try: 
            ips_active_blocks_gauge.remove(dev_id, hostname, domain)
        except Exception: 
            pass
        return True

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

    def _unisolate_device_router(self, mac: str, ip: str, hostname: str, dev_id: str) -> bool:
        webhook_url = self.config.get("router_webhook_url") or "http://127.0.0.1:8010/isolate"
        api_token = self.config.get("fritz_api_token", "")
        try:
            headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
            timeout_seconds = float(self.config.get("router_webhook_timeout_seconds", 5.0))
            if timeout_seconds <= 0:
                timeout_seconds = 5.0
            resp = self.session.post(webhook_url, json={"action": "unisolate", "ip": ip, "mac": mac, "reason": "Risk subsided"}, headers=headers, timeout=timeout_seconds)
            if resp.status_code == 202:
                with self._lock:
                    if mac in self._router_isolated_devices:
                        del self._router_isolated_devices[mac]
                        self._save_queues()
                try:
                    ips_router_isolated_active.labels(dev_id, hostname, mac).set(0.0)
                    ips_router_isolated_active.remove(dev_id, hostname, mac)
                except Exception:
                    pass
                LOGGER.critical("✅ [ROUTER IPS] Hardware un-isolation request accepted for %s (%s)", hostname, mac)
                return True
            ips_errors_metric.labels(target_type="router_unisolate_webhook").inc()
        except Exception as e:
            ips_errors_metric.labels(target_type="router_unisolate_connection").inc()
        return False

    def release_device(self, identifier: str) -> bool:
        """
        Explicit operator release method for isolated devices.
        Restores Layer-2 ARP tarpit and Fritz!Box hardware WAN access WITHOUT 
        adding the device to safe_ips (preserving continuous threat monitoring).
        AUDIT FIX #8: Collect targets under lock then execute HTTP I/O outside the lock
        to avoid blocking all lock-protected operations during a network round-trip.
        """
        released = False
        target_ip = None
        target_mac = None
        target_host = "unknown"
        target_dev = "unknown"

        # Phase 1: Collect targets & update in-memory state under lock
        with self._lock:
            for ip, meta in list(self._tarpit_active_targets.items()):
                if identifier in (ip, meta.get("mac"), meta.get("hostname"), meta.get("dev_id")):
                    target_ip = ip
                    target_mac = meta.get("mac")
                    target_host = meta.get("hostname", "unknown")
                    target_dev = meta.get("dev_id", "unknown")
                    del self._tarpit_active_targets[ip]
                    self._save_queues()
                    released = True
                    try:
                        ips_tarpit_active.labels(target_dev, target_host, target_mac).set(0.0)
                        ips_tarpit_active.remove(target_dev, target_host, target_mac)
                    except Exception:
                        pass
                    LOGGER.info("✅ [RELEASE] Operator released device %s (%s) from Scapy Layer-2 Tarpit.", target_host, target_ip)

            for mac, meta in list(self._router_isolated_devices.items()):
                if identifier in (mac, meta.get("ip"), meta.get("hostname"), meta.get("dev_id")):
                    target_mac = mac
                    target_ip = meta.get("ip", target_ip)
                    target_host = meta.get("hostname", target_host)
                    target_dev = meta.get("dev_id", target_dev)
                    del self._router_isolated_devices[mac]
                    self._save_queues()
                    try:
                        ips_router_isolated_active.labels(target_dev, target_host, target_mac).set(0.0)
                        ips_router_isolated_active.remove(target_dev, target_host, target_mac)
                    except Exception:
                        pass

        # Phase 2: Execute router HTTP call OUTSIDE the lock to avoid blocking other operations
        if target_mac and target_mac != "unknown":
            self._unisolate_device_router(mac=target_mac, ip=target_ip or "0.0.0.0", hostname=target_host, dev_id=target_dev)
            released = True
            LOGGER.info("✅ [RELEASE] Operator released device %s (%s) from Hardware Router Isolation.", target_host, target_mac)

        # ALSO RELEASE ASSOCIATED PI-HOLE BLOCKED DOMAINS FOR THIS DEVICE
        ips_state = self.state_manager.get_ips_state()
        blocked_dict = ips_state.get("blocked_domains", {})
        domains_to_unblock = [dom for dom, meta in blocked_dict.items() if identifier in (dom, meta.get("device_id"), meta.get("hostname"), meta.get("device_ip"))]
        for dom in domains_to_unblock:
            self.unblock_domain(dom)
            released = True

        # Clear retry & dead-letter queue items matching identifier
        with self._lock:
            stale_retries = [dom for dom, meta in self._retry_queue.items() if identifier in (dom, meta.get("device_id"), meta.get("hostname"), meta.get("device_ip"))]
            for dom in stale_retries:
                meta = self._retry_queue.pop(dom, {})
                try: ips_queue_status_gauge.remove(meta.get("device_id", ""), meta.get("hostname", ""), dom)
                except Exception: pass
                released = True

            stale_dead = [dom for dom, meta in self._dead_letter.items() if identifier in (dom, meta.get("device_id"), meta.get("hostname"))]
            for dom in stale_dead:
                meta = self._dead_letter.pop(dom, {})
                try: ips_dead_letter_gauge.remove(meta.get("device_id", ""), meta.get("hostname", ""), dom)
                except Exception: pass
                released = True

        if released or identifier:
            now = time.time()
            with self._lock:
                for k in (target_mac, target_ip, target_host, target_dev, identifier):
                    if k and k != "unknown":
                        self._operator_released_devices[k] = now
                self._save_queues()

        return released

    def release_all_devices(self) -> int:
        """
        Explicit operator release method for ALL isolated devices.
        Un-isolates all tarpitted and router-isolated targets.

        IDENTITY NOTE: The identity system in identity.py anchors device identity to
        client IP address (not MAC) for local private IPs. _tarpit_active_targets is
        keyed by IP, and mobile devices change MAC frequently (MAC randomization), so
        IP is the canonical and stable identifier for release operations.
        Priority: IP → dev_id → hostname. MAC is NEVER used as a primary key.
        """
        released_count = 0
        # Use a set of (identifier, type) pairs to ensure uniqueness per real device
        targets_to_release: set = set()

        with self._lock:
            for ip, meta in list(self._tarpit_active_targets.items()):
                # IP is the stable canonical key (identity is IP-anchored for local devices)
                # dev_id is the second most reliable; hostname is last resort (collision risk)
                identifier = ip or meta.get("dev_id") or meta.get("hostname")
                if identifier:
                    targets_to_release.add(identifier)
            for mac, meta in list(self._router_isolated_devices.items()):
                # For router-isolated devices (keyed by MAC), use IP if available,
                # otherwise fall back to dev_id. Only use MAC as absolute last resort
                # since mobile devices randomize MAC addresses per connection.
                identifier = meta.get("ip") or meta.get("dev_id") or mac
                if identifier and identifier != "unknown":
                    targets_to_release.add(identifier)

        for target in targets_to_release:
            if self.release_device(target):
                released_count += 1

        return released_count