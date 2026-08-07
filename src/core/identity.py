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

from utils import sanitize_hostname, infer_device_type
from core.state_guard import StateManager

LOGGER = logging.getLogger("home_ids.identity")

_GENERIC_HOSTNAMES = frozenset({
    "android", "iphone", "ipad", "ipod", "macbook", "macbook-pro", "macbook-air",
    "imac", "apple-tv", "desktop", "laptop", "pc", "workstation", "unknown",
    "localhost", "galaxy", "samsung", "pixel", "amazon-device", "chromecast",
    "windows", "linux", "debian", "ubuntu", "raspberrypi", "router", "gateway",
    "switch", "ap", "access-point", "wlan", "wifi", "host", "device"
})


def stable_device_id(raw_client: str) -> str:
    if not raw_client:
        return "000000000000"
    cleaned = str(raw_client).strip().lower()
    return hashlib.sha256(cleaned.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _is_trackable_local_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_unspecified or ip_obj.is_loopback:
            return False
        if ip_obj.version == 6:
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
        self._lock = threading.Lock()
        
        threading.Thread(target=self._poll_fritzbox_hosts, daemon=True, name="fritz-hosts-poller").start()

    def _poll_fritzbox_hosts(self) -> None:
        session = requests.Session()
        while True:
            try:
                webhook_url = self.config.get("router_hosts_url", "http://127.0.0.1:8010/hosts")
                api_token = self.config.get("fritz_api_token", "")
                headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
                
                resp = session.get(webhook_url, headers=headers, timeout=5.0)
                if resp.status_code == 200:
                    hosts_data = resp.json()  
                    new_cache = {}
                    for host in hosts_data:
                        ip = host.get("ip")
                        mac = host.get("mac", "unknown").lower()
                        name = host.get("name", "unknown")
                        if ip:
                            new_cache[ip] = {"mac": mac, "name": name}
                    with self._lock:
                        self._fritz_cache = new_cache
            except Exception as e:
                LOGGER.debug("FritzBox hosts webhook poll unavailable. Retrying in 60s. %s", e)
            time.sleep(60)

    def _enrich_from_cache(self, ip: str, current_mac: str, current_hostname: str) -> Tuple[str, str]:
        if not ip or ip == "unknown":
            return current_mac, current_hostname

        with self._lock:
            fritz_data = self._fritz_cache.get(ip)
        
        if fritz_data:
            f_mac = fritz_data.get("mac", "unknown")
            f_name = fritz_data.get("name", "unknown")
            best_mac = f_mac if f_mac != "unknown" else current_mac
            best_host = f_name if f_name != "unknown" else current_hostname
            return best_mac, best_host

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
        # ARCHITECTURAL FIX: Anchor local private IPs to guarantee unified correlation 
        # between Pi-hole DNS logs and Zeek flow logs for the exact same physical device.
        if _is_trackable_local_ip(client_ip):
            return stable_device_id(client_ip)
            
        if hostname and not _is_generic_hostname(hostname):
            return stable_device_id(f"host:{hostname.lower()}")
            
        if mac_addr and mac_addr != "unknown":
            return stable_device_id(mac_addr)
            
        return stable_device_id(client_ip)

    def process_dns_identities(self, dns_rows: List[Dict[str, Any]], zeek_fx: Any, ml_registry: Any = None) -> List[str]:
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

            state = self.state_manager.get_or_create(
                device_id=dev_id, client_ip=client_ip, hostname=hostname, alpha=alpha
            )

            with self.state_manager.lock_device(dev_id) as locked_state:
                locked_state.mac_address = mac_addr or "unknown"
                locked_state.client_ip = client_ip
                if hostname != "unknown":
                    locked_state.hostname = hostname
                self.apply_device_type(locked_state, type_overrides)

            active_device_ids.add(dev_id)

        return list(active_device_ids)

    def process_zeek_identities(self, zeek_events: List[Dict[str, Any]], zeek_fx: Any, ml_registry: Any = None) -> List[str]:
        if not zeek_events:
            return []

        active_device_ids: Set[str] = set()
        type_overrides = self.config.get("device_type_overrides", {})
        alpha = float(self.config.get("baseline_alpha", 0.05))

        for event in zeek_events:
            src_ip = event.get("id.orig_h", event.get("orig_h", ""))
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

            state = self.state_manager.get_or_create(
                device_id=dev_id, client_ip=src_ip, hostname=hostname, alpha=alpha
            )

            with self.state_manager.lock_device(dev_id) as locked_state:
                locked_state.mac_address = mac_addr or "unknown"
                locked_state.client_ip = src_ip
                if hostname != "unknown" and locked_state.hostname == "unknown":
                    locked_state.hostname = hostname
                self.apply_device_type(locked_state, type_overrides)

            active_device_ids.add(dev_id)

        return list(active_device_ids)

    def apply_device_type(self, state: Any, overrides: Dict[str, str]) -> None:
        client_ip = getattr(state, "client_ip", "")
        device_id = getattr(state, "device_id", "")
        hostname = getattr(state, "hostname", "").lower()

        if client_ip in overrides:
            state.device_type = overrides[client_ip]
            return
        if device_id in overrides:
            state.device_type = overrides[device_id]
            return
        if hostname and hostname != "unknown":
            for pattern, dtype in overrides.items():
                if pattern.lower() in hostname:
                    state.device_type = dtype
                    return
        if getattr(state, "device_type", "unknown") == "unknown":
            state.device_type = infer_device_type(hostname)