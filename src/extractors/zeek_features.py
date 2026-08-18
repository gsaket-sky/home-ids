"""
zeek_features.py – Zeek network security monitor integration.

RECENT FIXES:
- FIXED (TAILER CORRUPTION / BLACKOUT): Replaced unbuffered `for line in f` iterations with strict 
  `f.readline()` byte-alignment checks. Prevents partial Zeek JSON flushes from permanently misaligning 
  the `_pos` cursor and causing infinite `JSONDecodeError` blackouts.
- FIXED (JSON NESTING COMPATIBILITY): Added a dynamic normalization hook inside `_on_event` to flatten 
  nested Zeek `{"id": {"orig_h": ...}}` structures into the expected `id.orig_h` format, ensuring 
  cross-compatibility with different Zeek JSON policy formats.
- FIXED (MEMORY BLOAT): `_enrich_ptr` now utilizes a proper TTL dictionary for `_reverse_dns_cache` 
  evicting 24-hour-old records instead of blind-clearing. 
- FIXED (THREAD EXHAUSTION): Applied strict size limits (`_work_queue.qsize()`) to the 
  `_ptr_pool` thread executor to silently drop backlogged PTR requests rather than crashing memory.
- ADDED (LOGGING): Detailed operational event logging for ingestion and cache trimming.
"""
import ipaddress
import json
import logging
import threading
import time
import concurrent.futures
from collections import defaultdict, deque
from pathlib import Path
from typing import Callable, Optional

LOGGER = logging.getLogger("home_ids.zeek")
ZEEK_LOG_DIR = Path("/opt/zeek/logs/current")

_LOG_FILES = {
    "conn.log": "conn", "dns.log": "dns", "http.log": "http", 
    "ssl.log": "ssl", "notice.log": "notice", "weird.log": "weird", "dhcp.log": "dhcp"
}

DOH_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
DOH_SNIS = {"cloudflare-dns.com", "dns.google", "dns.quad9.net"}
LATERAL_PORTS = frozenset([22, 445, 3389, 5900, 23])


class ZeekLogTailer:
    def __init__(self, path: Path, event_type: str, callback: Callable[[str, dict], None], state_dir: Path):
        self.path = path
        self.event_type = event_type
        self.callback = callback
        self._pos = 0
        self._inode = None
        self._json_err_count = 0
        
        self.cursor_path = state_dir / f"zeek_cursor_{self.event_type}.json"
        self._load_cursor()
        
        if self._inode is None:
            self._seek_to_end()

    def _load_cursor(self) -> None:
        if self.cursor_path.exists():
            try:
                data = json.loads(self.cursor_path.read_text())
                if self.path.exists() and self.path.stat().st_ino == data.get("inode"):
                    self._inode = data["inode"]
                    self._pos = data["pos"]
                    LOGGER.debug("Resumed Zeek %s tailer from cursor offset %d.", self.event_type, self._pos)
            except Exception:
                pass

    def _save_cursor(self) -> None:
        if self._inode:
            try:
                self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
                self.cursor_path.write_text(json.dumps({"inode": self._inode, "pos": self._pos}))
            except Exception:
                pass

    def _seek_to_end(self) -> None:
        if self.path.exists():
            try:
                stat = self.path.stat()
                self._inode = stat.st_ino
                self._pos = stat.st_size
                LOGGER.debug("Zeek %s tailer initialized at EOF (offset %d).", self.event_type, self._pos)
            except OSError:
                pass

    def poll(self) -> int:
        count = 0
        if not self.path.exists(): return 0
        try:
            stat = self.path.stat()
            if stat.st_ino != self._inode or stat.st_size < self._pos:
                self._pos = 0
                self._inode = stat.st_ino
            if stat.st_size <= self._pos: return 0
            
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._pos)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    
                    # ARCHITECTURAL FIX: Prevent JSONDecodeError cascades from partial lines.
                    # If the line doesn't end with a newline, Zeek hasn't finished flushing it to disk.
                    if not line.endswith("\n"):
                        break
                        
                    clean_line = line.strip()
                    if not clean_line or clean_line.startswith("#"):
                        self._pos = f.tell()
                        continue
                        
                    try:
                        self.callback(self.event_type, json.loads(clean_line))
                        count += 1
                        self._json_err_count = 0
                    except json.JSONDecodeError:
                        self._json_err_count += 1
                        
                    self._pos = f.tell()
                    
                self._save_cursor()
        except OSError: pass
        return count


class ZeekCollector:
    def __init__(self, log_dir: str = str(ZEEK_LOG_DIR), poll_interval: float = 2.0, state_dir: Path = Path("state")):
        self.log_dir = Path(log_dir)
        self.poll_interval = poll_interval
        self.state_dir = state_dir
        self._tailers = {}
        self._tailers_lock = threading.Lock()
        self._events = deque(maxlen=100000)
        self._lock = threading.Lock()
        self._tailers_lock = threading.Lock()
        self._available = False
        self._last_init_attempt = 0.0
        self._init_tailers()

    def update_log_dir(self, new_dir: str) -> None:
        with self._tailers_lock:
            self.log_dir = Path(new_dir)
            self._available = False
            self._tailers.clear()
            LOGGER.info("Log directory dynamically updated to: %s", new_dir)
        self._init_tailers()

    def _init_tailers(self) -> None:
        self._last_init_attempt = time.time()
        try:
            if not self.log_dir.exists():
                LOGGER.warning("Zeek log directory inaccessible or missing: %s", self.log_dir)
                self._available = False
                return

            with self._tailers_lock:
                if not self._tailers:
                    self._tailers = {
                        "conn": ZeekLogTailer(self.log_dir / "conn.log", "conn", self._on_event, self.state_dir),
                        "dns": ZeekLogTailer(self.log_dir / "dns.log", "dns", self._on_event, self.state_dir),
                        "http": ZeekLogTailer(self.log_dir / "http.log", "http", self._on_event, self.state_dir),
                        "ssl": ZeekLogTailer(self.log_dir / "ssl.log", "ssl", self._on_event, self.state_dir),
                        "notice": ZeekLogTailer(self.log_dir / "notice.log", "notice", self._on_event, self.state_dir),
                        "dhcp": ZeekLogTailer(self.log_dir / "dhcp.log", "dhcp", self._on_event, self.state_dir),
                        "test_conn": ZeekLogTailer(self.log_dir / "test_conn.log", "conn", self._on_event, self.state_dir),
                        "test_dhcp": ZeekLogTailer(self.log_dir / "test_dhcp.log", "dhcp", self._on_event, self.state_dir),
                    }
                self._available = True
                LOGGER.info("✅ Zeek Collector initialized successfully on directory: %s", self.log_dir)
        except Exception as exc:
            LOGGER.error("Failed to initialize Zeek tailers on %s: %s", self.log_dir, exc)
            self._available = False

    def _on_event(self, event_type: str, event: dict) -> None:
        event["_zeek_type"] = event_type
        
        # ARCHITECTURAL FIX: Normalize nested Zeek JSON structures.
        # Older Zeek JSON policies output nested {"id": {"orig_h": ...}} instead of flattened strings.
        if "id" in event and isinstance(event["id"], dict):
            for k, v in event["id"].items():
                event[f"id.{k}"] = v
                
        with self._lock:
            if len(self._events) < 100000:
                self._events.append(event)
            else:
                LOGGER.warning("Zeek event buffer overflow; dropping event from %s", event.get("id.orig_h", "unknown"))

    def poll(self) -> list[dict]:
        if not self._available:
            if time.time() - self._last_init_attempt > 10.0:
                self._init_tailers()
            if not self._available:
                return []

        with self._tailers_lock:
            tailers = list(self._tailers.values())
        for t in tailers:
            t.poll()

        with self._lock:
            e = self._events
            self._events = deque(maxlen=100000)
        return e

    @property
    def available(self) -> bool: 
        return self._available


class ZeekFeatureExtractor:
    _MALICIOUS_JA3 = frozenset(["e7d705a3286e19ea42f587b6207263db", "6734f37431670b3ab4292b8f60f29984", "36f7277af969b30647d1de5e8c4e6b08", "a0e9f5d64349fb13191bc781f81f42e1", "72a589da586844d7f0818ce684948eea", "c12f54a3f91dc7bafd92cb59fe009a35", "a2fb5534f0b5a8de1c21d8fc4efb3f95", "3b5074b1b5d032e5620f69f9159a2983", "b386946a5a3b9a6e0f78f7c6b9d1c9a0"])
    _MALICIOUS_JA4 = frozenset(["t13d1516h2_8daaf6152771_a0b271d46eb3", "t13d1715h2_8daaf6152771_b1218ebf4b00", "t12d190800_b9f67a21658b_000000000000"])
    _SUSPICIOUS_PORTS = frozenset([4444, 4445, 8888, 9999, 1337, 31337, 6667, 6697, 1080, 3128, 5353])
    _EXCLUDED_HONEYPOT_PORTS = frozenset([137, 138, 139, 1900, 5353])
    
    def __init__(self, home_subnets: list = None, ti_engine=None, geoip_engine=None, safe_ips: set = None, honeypot_ips: set = None, safe_patterns: set = None):
        self._conn_ts = defaultdict(lambda: deque(maxlen=5000))
        self._new_ips = defaultdict(dict)
        self._ja3_hits = defaultdict(lambda: deque(maxlen=100))
        self._ja4_hits = defaultdict(lambda: deque(maxlen=100))
        self._http_uas = defaultdict(dict)
        self._notices = defaultdict(lambda: deque(maxlen=100))
        self._susp_ports = defaultdict(lambda: deque(maxlen=500))
        self._http_reqs = defaultdict(dict)
        self._outbound_bytes = defaultdict(lambda: deque(maxlen=5000))
        self._doh_bypass_uids = defaultdict(dict)
        self._lateral_moves = defaultdict(lambda: deque(maxlen=500))
        self._conn_states = defaultdict(lambda: deque(maxlen=5000))
        self._conn_durations = defaultdict(lambda: deque(maxlen=5000))
        self._new_lateral_events = defaultdict(list)
        self._honeypot_hits = defaultdict(lambda: deque(maxlen=500))
        self._rejected_ips = defaultdict(lambda: deque(maxlen=5000))
        self._last_connection_meta = {}
        
        self.honeypot_ips = honeypot_ips if honeypot_ips is not None else set()
        self._wire_dns_resolutions = {}
        self._mac_bindings = {}
        # PHASE 4 (MAC-rotation resilience): DHCP Option 55/60/77 fingerprint of the most
        # recent DHCP transaction per IP/MAC, and a rolling per-device set of *all* JA3
        # hashes seen (not just malicious ones) used as a benign behavioral fingerprint.
        self._dhcp_fingerprints = {}          # ip -> {"vendor_class","param_list","user_class","ts"}
        self._dhcp_fingerprints_by_mac = {}   # mac -> same dict, survives across an IP change
        self._ja3_seen = defaultdict(set)     # ip -> set of ja3 hashes (capped per-device below)
        self.ti_engine = ti_engine
        self.geoip_engine = geoip_engine
        self._reverse_dns_cache = {}
        self._ptr_pool = concurrent.futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="zeek_ptr")
        self.safe_ips = safe_ips if safe_ips is not None else set()
        self.safe_patterns = {str(p).lower().strip() for p in (safe_patterns or []) if str(p).strip()}

        self._home_nets = []
        self.set_home_subnets(home_subnets or ["192.168.1.0/24"])
        LOGGER.debug("ZeekFeatureExtractor initialized.")

    def set_home_subnets(self, subnets: list) -> None:
        nets = []
        for net in subnets:
            if net:
                try: nets.append(ipaddress.ip_network(net, strict=False))
                except ValueError: pass
        self._home_nets = nets

    def _is_home_ip(self, ip: str) -> bool:
        if not ip: return False
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._home_nets)
        except ValueError: return False
        
    def _is_local_or_multicast(self, ip_str: str) -> bool:
        if not ip_str or ip_str == "unknown": return True
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_multicast or ip.is_link_local or ip.is_private or ip.is_loopback or ip.is_reserved:
                return True
            if ip.version == 4 and str(ip).endswith('.255'):
                return True
            if self._is_home_ip(ip_str):
                return True
            return False
        except ValueError:
            return True

    def _is_safe_device(self, src: str) -> bool:
        if src in self.safe_ips:
            return True
        hostname = self.get_hostname(src)
        if hostname and any(pat in hostname.lower() for pat in self.safe_patterns):
            return True
        return False

    def _enrich_ptr(self, ip: str) -> None:
        if not ip or not self._is_home_ip(ip) or ip in self._reverse_dns_cache: 
            return
        
        # FIX: Protect against Thread/Memory Exhaustion. Drop lookups if queue is heavily backlogged
        if self._ptr_pool._work_queue.qsize() > 100:
            LOGGER.debug("PTR resolution queue full. Dropping lookup for %s", ip)
            return

        self._reverse_dns_cache[ip] = {"host": "pending", "ts": time.time()}
        
        def _bg_lookup():
            if not self.geoip_engine:
                self._reverse_dns_cache[ip] = {"host": "unknown", "ts": time.time()}
                return
            try:
                host = self.geoip_engine.reverse_dns(ip)
                self._reverse_dns_cache[ip] = {"host": host if host else "unknown", "ts": time.time()}
                if host: LOGGER.debug("PTR resolved %s -> %s", ip, host)
            except Exception as e:
                self._reverse_dns_cache[ip] = {"host": "unknown", "ts": time.time()}
                LOGGER.debug("PTR exception for %s: %s", ip, e)
                
        self._ptr_pool.submit(_bg_lookup)

    def get_hostname(self, ip: str) -> Optional[str]:
        entry = self._reverse_dns_cache.get(ip)
        if isinstance(entry, dict):
            host = entry.get("host")
            return host if host not in (None, "pending", "unknown") else None
        return None

    def get_last_connection_meta(self, device_ip: str) -> dict:
        return self._last_connection_meta.get(device_ip, {
            "last_dest_ip": "unknown", "last_dest_port": 0, "dominant_protocol": "unknown", "zeek_outbound_bytes": 0
        })

    def pop_new_lateral_events(self, device_ip: str) -> list[tuple[str, int]]:
        events = self._new_lateral_events.get(device_ip, [])
        if events: self._new_lateral_events[device_ip] = []
        return events

    def prune(self, now_ts: float, window: int) -> None:
        cutoff = now_ts - window
        
        def prune_deque_dict(d):
            for k in list(d.keys()):
                while d[k] and d[k][0] < cutoff: d[k].popleft()
                if not d[k]: del d[k]

        def prune_tuple_deque_dict(d):
            for k in list(d.keys()):
                while d[k] and d[k][0][0] < cutoff: d[k].popleft()
                if not d[k]: del d[k]
                
        def prune_ts_dict(d):
            for src in list(d.keys()):
                for sub_k in list(d[src].keys()):
                    if d[src][sub_k] < cutoff: del d[src][sub_k]
                if not d[src]: del d[src]

        prune_deque_dict(self._conn_ts)
        prune_tuple_deque_dict(self._lateral_moves)
        prune_deque_dict(self._susp_ports)
        prune_tuple_deque_dict(self._outbound_bytes)
        prune_tuple_deque_dict(self._conn_states)
        prune_tuple_deque_dict(self._conn_durations)
        prune_tuple_deque_dict(self._rejected_ips)
        prune_deque_dict(self._honeypot_hits)
        
        prune_ts_dict(self._new_ips)
        prune_ts_dict(self._doh_bypass_uids)
        prune_ts_dict(self._http_uas)
        prune_ts_dict(self._http_reqs)

        for src in list(self._new_lateral_events.keys()):
            if not self._lateral_moves.get(src):
                del self._new_lateral_events[src]

        def prune_hit_dict(d):
            for src in list(d.keys()):
                while d[src] and d[src][0].get("ts", 0) < cutoff: d[src].popleft()
                if not d[src]: del d[src]

        prune_hit_dict(self._ja3_hits)
        prune_hit_dict(self._ja4_hits)
        prune_hit_dict(self._notices)
        
        if len(self._mac_bindings) > 50000:
            self._mac_bindings.clear()
            LOGGER.debug("Pruned zeek _mac_bindings capacity.")
            
        # FIX: Evict reverse DNS cache by 24h TTL to prevent infinite RAM bloat
        ttl_cutoff = now_ts - 86400
        for ip in list(self._reverse_dns_cache.keys()):
            entry = self._reverse_dns_cache[ip]
            if isinstance(entry, dict) and entry.get("ts", 0) < ttl_cutoff:
                del self._reverse_dns_cache[ip]
                
        if len(self._wire_dns_resolutions) > 20000:
            self._wire_dns_resolutions.clear()
            LOGGER.debug("Pruned zeek _wire_dns_resolutions capacity.")
            
        if len(self._last_connection_meta) > 10000:
            self._last_connection_meta.clear()

    def _bind_mac(self, ip: str, mac: str, ts: Optional[float] = None) -> None:
        """Shared MAC<->IP binding + Layer-2 spoofing detection, used by BOTH the DHCPv4
        ingestion path (ingest()'s "dhcp" branch, IPv4-only) and the PHASE 6 conn.log
        orig_l2_addr path (_process_conn(), protocol-family-agnostic — this is what makes
        IPv6 addresses correlatable at all). Factored out so both paths get identical
        spoof-detection behavior instead of two copies drifting apart."""
        if not ip or not mac:
            return
        ts = ts if ts is not None else time.time()
        existing_mac = self._mac_bindings.get(ip)

        # Feature 4: Layer-2 Spoofing Detection (ARP/NDP Telemetry)
        if existing_mac and existing_mac != mac:
            last_seen = getattr(self, "_mac_last_seen", {}).get(ip, 0)
            # If MAC flipped within 10 minutes, it's highly suspicious (not a normal DHCP
            # renewal or IPv6 privacy-address rotation, which don't change the underlying MAC).
            if (ts - last_seen) < 600:
                LOGGER.critical(f"🚨 LAYER-2 ARP/NDP SPOOFING DETECTED: IP {ip} flipped from {existing_mac} to {mac} in {int(ts - last_seen)}s")
                if not hasattr(self, "layer2_spoofs"): self.layer2_spoofs = {}
                self.layer2_spoofs[ip] = {"old": existing_mac, "new": mac, "ts": ts}

        self._mac_bindings[ip] = mac
        if not hasattr(self, "_mac_last_seen"): self._mac_last_seen = {}
        self._mac_last_seen[ip] = ts
        self._enrich_ptr(ip)

    def ingest(self, event: dict) -> None:
        etype = event.get("_zeek_type", "")
        if etype == "dhcp":
            mac, ip = event.get("mac"), event.get("client_addr")
            if mac and ip:
                mac = mac.lower()
                self._bind_mac(ip, mac, event.get("ts", time.time()))

                # PHASE 4: capture the DHCP fingerprint fields added by the
                # local-dhcp-fingerprint.zeek policy script (vendor_class / param_list /
                # user_class from DHCP Options 60 / 55 / 77). Only stored when at least one
                # is actually present, so devices/Zeek builds without the policy script
                # simply never populate this (safe no-op degrade).
                vendor_class = event.get("vendor_class")
                param_list = event.get("param_list")
                user_class = event.get("user_class")
                if vendor_class or param_list or user_class:
                    fp = {
                        "vendor_class": vendor_class or "",
                        "param_list": list(param_list) if param_list else [],
                        "user_class": user_class or "",
                        "ts": event.get("ts", time.time()),
                    }
                    self._dhcp_fingerprints[ip] = fp
                    self._dhcp_fingerprints_by_mac[mac] = fp
                    if len(self._dhcp_fingerprints) > 5000: self._dhcp_fingerprints.clear()
                    if len(self._dhcp_fingerprints_by_mac) > 5000: self._dhcp_fingerprints_by_mac.clear()
            return
            
        src = event.get("id.orig_h", event.get("orig_h", ""))
        if not src: return
        self._enrich_ptr(src)
            
        if etype == "conn": self._process_conn(src, event)
        elif etype == "dns": self._process_dns(event)
        elif etype == "ssl": self._process_ssl(src, event)
        elif etype == "http": self._process_http(src, event)
        elif etype == "notice": self._process_notice(src, event)
        elif etype == "weird": self._process_weird(src, event)

    def _process_conn(self, src: str, ev: dict) -> None:
        dst_port = int(ev.get("id.resp_p", ev.get("resp_p", 0)) or 0)
        dst_ip = ev.get("id.resp_h", ev.get("resp_h", ""))
        proto = ev.get("proto", "tcp")
        orig_bytes = int(ev.get("orig_bytes", 0) or 0)
        uid, ts = ev.get("uid", ""), ev.get("ts", time.time())

        self._conn_ts[src].append(ts)

        # PHASE 6 (cross-address-family identity correlation): conn.log's orig_l2_addr is
        # populated for EVERY connection, IPv4 or IPv6, when Zeek's built-in
        # `policy/protocols/conn/mac-logging.zeek` is loaded — unlike the DHCP-derived MAC
        # binding above (ingest()'s "dhcp" branch), which only ever fires for DHCPv4
        # transactions and is therefore permanently blind to IPv6-only traffic (SLAAC/
        # link-local addresses never get a DHCPv4 lease). Binding MAC from conn.log gives
        # every address family the SAME correlation key, so core/identity.py can resolve
        # an IPv6 flow to the SAME device_id as that device's IPv4 identity instead of
        # cold-starting a second, permanently-separate tracking profile. Requires adding
        # `@load policy/protocols/conn/mac-logging.zeek` to your Zeek config -- see
        # Documentation/INSTALL.md §3.3.1 and Documentation/ENGINEERING_MANUAL.md §1.3 for
        # the deployment step and verification command. Safe no-op if that script isn't
        # loaded (the field is simply absent from the event) -- this was true of this
        # project's own production deployment for some time before being traced back to
        # this exact gap: the mechanism was built and tested, but the deployment step was
        # only ever mentioned in this comment, never actually written into the install
        # guide, so it was live in code and inert in practice.
        orig_mac = ev.get("orig_l2_addr")
        if orig_mac and isinstance(orig_mac, str):
            self._bind_mac(src, orig_mac.lower())
        
        conn_state = ev.get("conn_state")
        if conn_state: 
            self._conn_states[src].append((ts, conn_state))
            if conn_state in ("S0", "REJ") and dst_ip:
                self._rejected_ips[src].append((ts, dst_ip))
                
        if ev.get("duration") is not None and not self._is_local_or_multicast(dst_ip):
            try: self._conn_durations[src].append((ts, float(ev.get("duration"))))
            except (ValueError, TypeError): pass
        
        self._last_connection_meta[src] = {
            "last_dest_ip": dst_ip, "last_dest_port": dst_port,
            "dominant_protocol": proto.upper(), "zeek_outbound_bytes": orig_bytes
        }

        if dst_ip:
            self._enrich_ptr(dst_ip)
            if dst_ip in self.honeypot_ips and dst_port not in self._EXCLUDED_HONEYPOT_PORTS:
                LOGGER.warning("Honeypot hit! Src: %s, Dst: %s:%d", src, dst_ip, dst_port)
                self._honeypot_hits[src].append(ts)
                
            if self._is_home_ip(src) and self._is_home_ip(dst_ip):
                if dst_port in LATERAL_PORTS and not self._is_safe_device(dst_ip) and not self._is_safe_device(src):
                    self._lateral_moves[src].append((ts, dst_ip, dst_port))
                    self._new_lateral_events[src].append((dst_ip, dst_port))

            if self._is_home_ip(src) and not self._is_local_or_multicast(dst_ip):
                if len(self._new_ips[src]) < 1000: self._new_ips[src][dst_ip] = ts
                if not self._is_safe_device(src):
                    if (dst_ip in DOH_IPS and dst_port == 443) or dst_port == 853:
                        if len(self._doh_bypass_uids[src]) < 100: self._doh_bypass_uids[src][uid] = ts
                    
        if dst_port in self._SUSPICIOUS_PORTS and not self._is_local_or_multicast(dst_ip):
            self._susp_ports[src].append(ts)
        
        if not self._is_local_or_multicast(dst_ip):
            self._outbound_bytes[src].append((ts, orig_bytes))

    def _process_dns(self, ev: dict) -> None:
        query, answers = ev.get("query"), ev.get("answers", [])
        if query and answers:
            q = str(query).lower().strip(".")
            for a in answers:
                try:
                    ipaddress.ip_address(a)
                    if len(self._wire_dns_resolutions) < 20000: self._wire_dns_resolutions[q] = a
                    break
                except ValueError: pass

    def get_wire_ip(self, domain: str) -> Optional[str]: return self._wire_dns_resolutions.get(str(domain).lower().strip("."))
    def get_mac(self, ip: str) -> Optional[str]: return self._mac_bindings.get(ip)
    def get_dhcp_fingerprint(self, ip: str) -> Optional[dict]: return self._dhcp_fingerprints.get(ip)
    def get_ja3_set(self, ip: str) -> set: return set(self._ja3_seen.get(ip, set()))
    def get_http_reqs(self, device_ip: str) -> set: return set(self._http_reqs.get(device_ip, {}).keys())
    def get_dest_ips(self, device_ip) -> set:
        out = set()
        for ip in self._as_ip_list(device_ip):
            out.update(self._new_ips.get(ip, {}).keys())
        return out

    def _process_ssl(self, src: str, ev: dict) -> None:
        ja3, ja4, ts = ev.get("ja3", ""), ev.get("ja4", ""), ev.get("ts", time.time())
        is_malicious_ja3, is_malicious_ja4 = False, False
        
        if ja3 and (ja3 in self._MALICIOUS_JA3 or (self.ti_engine and hasattr(self.ti_engine, "dynamic_ja3") and ja3 in self.ti_engine.dynamic_ja3)):
            is_malicious_ja3 = True
            LOGGER.debug("Malicious JA3 fingerprint identified: %s", ja3)
        if ja4 and ja4 in self._MALICIOUS_JA4: 
            is_malicious_ja4 = True
            LOGGER.debug("Malicious JA4+ fingerprint identified: %s", ja4)
                
        if is_malicious_ja3: self._ja3_hits[src].append({"ja3": ja3, "server": ev.get("server_name", ""), "ts": ts, "dest_port": ev.get("id.resp_p", 0)})
        if is_malicious_ja4: self._ja4_hits[src].append({"ja4": ja4, "server": ev.get("server_name", ""), "ts": ts, "dest_port": ev.get("id.resp_p", 0)})

        # PHASE 4: track *every* JA3 seen (not just malicious ones) as a benign per-device
        # behavioral fingerprint, used for MAC-rotation re-identification. Capped at 50
        # distinct hashes per device — this is meant to capture "the small stable set of
        # TLS stacks this device's apps use," not a full unbounded history.
        if ja3 and len(self._ja3_seen[src]) < 50:
            self._ja3_seen[src].add(ja3)

        if not self._is_safe_device(src):
            sni = str(ev.get("server_name", "")).lower().strip(".")
            if sni and any(sni == doh or sni.endswith(f".{doh}") for doh in DOH_SNIS):
                if len(self._doh_bypass_uids[src]) < 100:
                    self._doh_bypass_uids[src][ev.get("uid", "")] = ts

    def _process_http(self, src: str, ev: dict) -> None:
        ua, host, uri, ts = ev.get("user_agent", ""), ev.get("host", ""), ev.get("uri", ""), ev.get("ts", time.time())
        if ua and len(self._http_uas[src]) < 500: self._http_uas[src][ua] = ts
        if host and uri and len(self._http_reqs[src]) < 1000: self._http_reqs[src][f"{host}{uri}"] = ts

    def _process_notice(self, src: str, ev: dict) -> None: self._notices[src].append({"note": ev.get("note", ""), "msg": ev.get("msg", ""), "ts": ev.get("ts"), "dest_port": ev.get("id.resp_p", 0)})
    def _process_weird(self, src: str, ev: dict) -> None: self._notices[src].append({"note": f"weird:{ev.get('name', '')}", "msg": ev.get("addl", ""), "ts": ev.get("ts"), "dest_port": ev.get("id.resp_p", 0)})

    def get_scanned_ports(self, device_ip: str) -> list[str]:
        """Returns readable string list of distinct destination ports scanned by device (e.g. ['22 (SSH)', '445 (SMB)'])."""
        port_names = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
        }
        ports = set()
        for t, ip, p in self._lateral_moves.get(device_ip, []):
            if p: ports.add(p)
        for t, ip in self._rejected_ips.get(device_ip, []):
            pass
        
        result = []
        for p in sorted(list(ports))[:5]:
            name = port_names.get(p, f"Port {p}")
            result.append(f"{p} ({name})")
        return result

    def get_app_context(self, device_ip: str) -> str:
        """Returns the primary application or process/User-Agent signature for Telegram alerts."""
        uas = list(self._http_uas.get(device_ip, {}).keys())
        if uas:
            top_ua = uas[-1]
            if "Go-http-client" in top_ua: return "Go-http-client"
            if "curl" in top_ua: return "cURL"
            if "python" in top_ua.lower(): return "Python Script"
            if "powershell" in top_ua.lower(): return "PowerShell"
            if "nmap" in top_ua.lower(): return "Nmap Scanner"
            return top_ua[:40]
        meta = self._last_connection_meta.get(device_ip, {})
        proto = meta.get("dominant_protocol", "")
        port = meta.get("last_dest_port", 0)
        if port == 443: return "HTTPS / TLS 1.3"
        if port == 80: return "HTTP Web Traffic"
        if port in (22, 2222): return "SSH / SFTP Session"
        if port == 445: return "SMB File Sharing"
        return f"{proto} Port {port}" if port else "Network Socket"

    @staticmethod
    def _as_ip_list(device_ip) -> list:
        """PHASE 6: normalizes the historical single-IP call convention (a plain string)
        alongside the new multi-address convention (any iterable of IPs — pass
        `state.known_ips` for a device tracked across both IPv4 and IPv6). Every internal
        `self._xxx[ip]` structure below is still keyed per-IP exactly as before; this just
        lets callers aggregate across ALL of a device's known addresses instead of only
        whichever single address happens to be `state.client_ip` at evaluation time — the
        fix for a burst that's split across a device's IPv4 and IPv6 traffic silently
        staying under threshold on each address individually."""
        if isinstance(device_ip, str):
            return [device_ip] if device_ip else []
        try:
            seen, out = set(), []
            for ip in device_ip:
                if ip and ip not in seen:
                    seen.add(ip)
                    out.append(ip)
            return out
        except TypeError:
            return [device_ip] if device_ip else []

    def get_features(self, device_ip) -> dict:
        ips = self._as_ip_list(device_ip)
        states, durations, rejected_ips = [], [], set()
        for ip in ips:
            states.extend(s for t, s in self._conn_states.get(ip, []))
            durations.extend(d for t, d in self._conn_durations.get(ip, []))
            rejected_ips.update(ip2 for t, ip2 in self._rejected_ips.get(ip, []))

        # "Last" connection metadata: most recent write wins across all known addresses.
        # _last_connection_meta doesn't carry its own timestamp, so — same simplification
        # as before this change — whichever known IP was processed most recently in the
        # ingest stream provides it; we just now also check the device's other addresses
        # instead of only the single one the caller happened to pass.
        meta = {}
        for ip in ips:
            m = self._last_connection_meta.get(ip)
            if m:
                meta = m
        port = meta.get("last_dest_port", 0)
        app_weight = 0.2 if port in (80, 443) else (0.6 if port in (22, 445, 3389) else 0.4)

        return {
            "zeek_conn_count": sum(len(self._conn_ts.get(ip, [])) for ip in ips),
            "zeek_new_ips": sum(len(self._new_ips.get(ip, {})) for ip in ips),
            "zeek_ja3_malicious": sum(len(self._ja3_hits.get(ip, [])) for ip in ips),
            "zeek_ja4_malicious": sum(len(self._ja4_hits.get(ip, [])) for ip in ips),
            "zeek_notices": sum(len(self._notices.get(ip, [])) for ip in ips),
            "zeek_susp_ports": sum(len(self._susp_ports.get(ip, [])) for ip in ips),
            "zeek_http_ua_count": sum(len(self._http_uas.get(ip, {})) for ip in ips),
            "zeek_outbound_bytes": sum(b for ip in ips for t, b in self._outbound_bytes.get(ip, [])),
            "zeek_doh_bypass": sum(len(self._doh_bypass_uids.get(ip, {})) for ip in ips),
            "zeek_lateral_moves": sum(len(self._lateral_moves.get(ip, [])) for ip in ips),
            "zeek_s0_rej_count": sum(1 for s in states if s in ("S0", "REJ")),
            "zeek_s0_rej_unique_ips": len(rejected_ips),
            "zeek_max_duration": max(durations) if durations else 0.0,
            "zeek_honeypot_hits": sum(len(self._honeypot_hits.get(ip, [])) for ip in ips),
            "zeek_app_protocol_weight": app_weight,
            "last_dest_ip": meta.get("last_dest_ip", "unknown"),
            "last_dest_port": port,
            "dominant_protocol": meta.get("dominant_protocol", "TCP")
        }

    def get_alerts(self, device_ip) -> list[dict]:
        alerts = []
        for ip in self._as_ip_list(device_ip):
            for h in self._ja3_hits.get(ip, []): alerts.append({"type": "malicious_ja3", "ja3": h["ja3"], "dest_port": h.get("dest_port", 0), "confidence": 0.95})
            for h in self._ja4_hits.get(ip, []): alerts.append({"type": "malicious_ja4", "ja4": h["ja4"], "dest_port": h.get("dest_port", 0), "confidence": 0.95})
            for n in self._notices.get(ip, []): alerts.append({"type": "zeek_notice", "note": n["note"], "msg": n["msg"], "dest_port": n.get("dest_port", 0), "confidence": 0.75})
        return alerts

    def reset_all(self) -> None:
        for d in (self._conn_ts, self._new_ips, self._ja3_hits, self._ja4_hits, self._notices, self._susp_ports, self._http_uas, self._http_reqs, self._outbound_bytes, self._doh_bypass_uids, self._lateral_moves, self._conn_states, self._conn_durations, self._new_lateral_events, self._honeypot_hits, self._rejected_ips, self._last_connection_meta): d.clear()
        if len(self._wire_dns_resolutions) > 10000: self._wire_dns_resolutions.clear()

    def reset_client(self, client_ip) -> None:
        """PHASE 6: accepts a single IP (unchanged) or an iterable of IPs (pass
        `state.known_ips`) so post-alert resets clear a device's counters across ALL of
        its known addresses — without this, whichever address wasn't `state.client_ip` at
        alert time would keep its stale pre-alert counters and could immediately
        re-trigger the same alert next cycle purely from leftover, already-alerted-on data."""
        for ip in self._as_ip_list(client_ip):
            for d in (self._conn_ts, self._new_ips, self._ja3_hits, self._ja4_hits, self._notices, self._susp_ports, self._http_uas, self._http_reqs, self._outbound_bytes, self._doh_bypass_uids, self._lateral_moves, self._conn_states, self._conn_durations, self._new_lateral_events, self._honeypot_hits, self._rejected_ips, self._last_connection_meta, self._dhcp_fingerprints, self._ja3_seen):
                if ip in d:
                    del d[ip]