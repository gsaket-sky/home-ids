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
import math
import threading
import time
import concurrent.futures
import functools
from collections import defaultdict, deque
from intelligence import ja3_provenance
from utils import note_network_dns_domain
from pathlib import Path
from typing import Callable, Optional, Dict

LOGGER = logging.getLogger("home_ids.zeek")
ZEEK_LOG_DIR = Path("/opt/zeek/logs/current")

_LOG_FILES = {
    "conn.log": "conn", "dns.log": "dns", "http.log": "http", 
    "ssl.log": "ssl", "notice.log": "notice", "weird.log": "weird", "dhcp.log": "dhcp"
}

DOH_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
DOH_SNIS = {"cloudflare-dns.com", "dns.google", "dns.quad9.net"}
LATERAL_PORTS = frozenset([22, 445, 3389, 5900, 23])

# W-04 beacon tracker. Protocol-level periodic services that are periodic by design on every network: DNS/DoT,
# NTP, mDNS/LLMNR/NetBIOS, SSDP, DHCP, STUN (WebRTC/VoIP keepalives). Never beacon candidates.
_BEACON_EXCLUDED_PORTS = frozenset({53, 67, 68, 123, 137, 138, 853, 1900, 3478, 5353, 5355, 19302})
# Connections that never carried an exchange (no handshake / rejected) are retries to a dead endpoint, not check-ins.
_BEACON_EXCLUDED_STATES = frozenset({"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"})
_BEACON_MAX_PAIRS_PER_DEVICE = 64
_BEACON_SAME_CHECKIN_SECONDS = 2.0   # connections this close together are one check-in, not two intervals
_BEACON_MIN_MEAN_INTERVAL = 10.0     # faster periodicity is keepalive/streaming/polling-loop territory
_BEACON_MAX_GAP = 1800.0             # a longer silence ends the series; a new one starts from scratch
_BEACON_MISSED_FACTOR = 1.8          # an interval this many times the mean is a skipped check-in, not jitter
_BEACON_MAX_MISSED_SHARE = 0.2
_BEACON_MIN_OBSERVATIONS = 15        # same bar as the detector's beacon_total >= 15
# tdr = min(interval regularity, size regularity). tdr > 0.75 (the detector's bar) <=> interval CV < 0.15 AND
# payload-size CV < 0.30: check-ins within +-15 % of the period, each carrying a similar payload.
_BEACON_INTERVAL_CV_SCALE = 0.6
_BEACON_SIZE_CV_SCALE = 1.2
_BEACON_REPORT_TDR = 0.75


# Substring markers of a DNS line sent to the mDNS multicast groups (matches flat and nested Zeek JSON).
_MDNS_MARKERS = ('resp_h":"224.0.0.251"', 'resp_h":"ff02::fb"')
_MDNS_KEEP_EVERY = 50
_YIELD_EVERY_LINES = 500
_YIELD_SECONDS = 0.003


class ZeekLogTailer:
    def __init__(self, path: Path, event_type: str, callback: Callable[[str, dict], None], state_dir: Path):
        self.path = path
        self.event_type = event_type
        self.callback = callback
        self._pos = 0
        self._inode = None
        self._json_err_count = 0
        self._mdns_seen = 0
        
        from core.runtime_paths import runtime_dir   # rewritten every few seconds: RAM in Docker (flash wear)
        self.cursor_path = runtime_dir(state_dir) / f"zeek_cursor_{self.event_type}.json"
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
        lines_read = 0
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
                    # Yield the GIL regularly: catching up on a backlog (after a restart) is pure Python work that
                    # otherwise starves the main detection loop, whose many short sqlite calls each wait for the GIL.
                    lines_read += 1
                    if lines_read % _YIELD_EVERY_LINES == 0:
                        time.sleep(_YIELD_SECONDS)
                    
                    # ARCHITECTURAL FIX: Prevent JSONDecodeError cascades from partial lines.
                    # If the line doesn't end with a newline, Zeek hasn't finished flushing it to disk.
                    if not line.endswith("\n"):
                        break
                        
                    clean_line = line.strip()
                    if not clean_line or clean_line.startswith("#"):
                        self._pos = f.tell()
                        continue
                        
                    # mDNS multicast (a single chatty client can emit thousands of lines/s) is noise to every
                    # downstream consumer; skip the JSON parse for it and let 1 in N through as a presence signal.
                    if self.event_type == "dns" and any(m in clean_line for m in _MDNS_MARKERS):
                        self._mdns_seen += 1
                        if self._mdns_seen % _MDNS_KEEP_EVERY:
                            self._pos = f.tell()
                            continue

                    try:
                        self.callback(self.event_type, json.loads(clean_line))
                        count += 1
                        self._json_err_count = 0
                    except json.JSONDecodeError:
                        self._json_err_count += 1
                        
                    self._pos = f.tell()
                    # Persist progress periodically, not only at the end: a read
                    # interrupted mid-backlog (restart/kill) must resume near where it
                    # got to, not re-read the whole backlog from the last saved offset.
                    if count and count % 5000 == 0:
                        self._save_cursor()
                    
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
        self._dropped_event_count = 0
        self._reader_thread: Optional[threading.Thread] = None
        self._reader_stop = threading.Event()
        self._init_tailers()

    def start(self) -> None:
        """Start the background reader. File reading + JSON parsing then happens on
        this thread, continuously (events land within ~READER_INTERVAL_SECONDS of Zeek
        writing them), and poll() only swaps the already-filled buffer -- so a
        conn.log burst or backlog can never stall the main detection loop's heartbeat,
        and no event is delayed or dropped by a budget. Without start(), poll() keeps
        its original inline-read behavior."""
        if self._reader_thread is not None and self._reader_thread.is_alive():
            return
        self._reader_stop.clear()
        self._reader_thread = threading.Thread(target=self._reader_loop, name="zeek-reader", daemon=True)
        self._reader_thread.start()

    def stop(self) -> None:
        self._reader_stop.set()

    def _reader_running(self) -> bool:
        return self._reader_thread is not None and self._reader_thread.is_alive()

    def _poll_tailers(self) -> None:
        with self._tailers_lock:
            tailers = list(self._tailers.values())
        for t in tailers:
            t.poll()

    def _reader_loop(self) -> None:
        while not self._reader_stop.is_set():
            try:
                if not self._available:
                    if time.time() - self._last_init_attempt > 10.0:
                        self._init_tailers()
                else:
                    self._poll_tailers()
            except Exception:
                LOGGER.exception("Zeek reader thread iteration failed (continuing)")
            self._reader_stop.wait(self.READER_INTERVAL_SECONDS)

    READER_INTERVAL_SECONDS = 0.25

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
                        # PHASE 21B: ARP requests are broadcast, so they reach this tailer
                        # for every device regardless of WiFi/wired -- the same mechanism
                        # that already makes MAC correlation work for WiFi devices via
                        # conn.log's orig_l2_addr (confirmed live this session).
                        # REQUIRES a deployment step: confirmed live against a real Zeek
                        # 8.0.8 install (with zeek/foxio/ja4 + zeek/salesforce/ja3) that
                        # stock Zeek does NOT ship a base/protocols/arp module -- only the
                        # low-level arp_request/arp_reply events exist
                        # (base/bif/plugins/Zeek_ARP.events.bif.zeek), with no script
                        # subscribing to them to actually write arp.log. This tailer stays
                        # silent forever without zeek_scripts/local-arp-log.zeek (added
                        # this session, verified live end-to-end against a real captured
                        # burst -- see INSTALL.md's ARP-log deployment step) copied into
                        # the site dir and @load'd from local.zeek.
                        "arp": ZeekLogTailer(self.log_dir / "arp.log", "arp", self._on_event, self.state_dir),
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
                # Logging every dropped event individually (one synchronous
                # emit() per event, on whatever thread called poll() -- the
                # main detection loop's own thread) turned a buffer overflow
                # into a self-reinforcing freeze: tens of thousands of log
                # lines in under two minutes blew past the heartbeat
                # deadline and triggered a forced restart, which then let
                # the next burst overflow the buffer again. Count instead;
                # poll() logs one summary line per cycle.
                self._dropped_event_count += 1

    def poll(self) -> list[dict]:
        if not self._reader_running():
            if not self._available:
                if time.time() - self._last_init_attempt > 10.0:
                    self._init_tailers()
                if not self._available:
                    return []
            self._poll_tailers()

        with self._lock:
            e = self._events
            self._events = deque(maxlen=100000)
            dropped = self._dropped_event_count
            self._dropped_event_count = 0
        if dropped:
            LOGGER.warning("Zeek event buffer overflow; dropped %d events since last poll", dropped)
        return e

    @property
    def available(self) -> bool: 
        return self._available


def _synchronized(method):
    """Runs a ZeekFeatureExtractor method under the instance's state lock.

    The main loop and the reactive-capture thread both use the same extractor: the capture thread
    ingests a burst's Zeek logs and then reads destinations for the DNS-evasion audit
    (fritzbox_capture.ingest_zeek_logs / run_dns_evasion_audit) while the main loop ingests, prunes
    and iterates the same per-IP deques and dicts. Unlocked, get_features() raised "deque mutated
    during iteration" on .94 and aborted a whole engine cycle (runtime trace run 2, finding 4.3;
    _bind_mac() is the same class of race, audit A-05). Every public method holds the lock; it is
    re-entrant because public methods call each other."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._state_lock:
            return method(self, *args, **kwargs)
    return wrapper


class ZeekFeatureExtractor:
    # B3 (2026-10-01): the 8 hashes that used to be hard-coded here had no recorded origin and none of them is listed by
    # abuse.ch SSLBL or ET Open (checked against the live feeds on .94), and one earlier entry was a stock Windows hash.
    # Left empty: fingerprints now come only from the live, attributable feeds (SSLBL, ET Open) via ti_engine.dynamic_ja3.
    _MALICIOUS_JA3 = frozenset()
    # B3: emptied too. Two of the three entries carried 8daaf6152771, the cipher-suite hash of ordinary Chrome-family
    # clients (the same hash as a normal browser in tests/test_identity_reconcile_dhcp_ja4_signal.py), and none had a source.
    _MALICIOUS_JA4 = frozenset()
    # A5: services every LAN client uses on the wired devices (the IDS host runs Pi-hole) -- not a probe.
    # DNS, DHCP server/client, NTP, NetBIOS name service, mDNS, and ICMP (ping).
    DEFAULT_WIRED_PROBE_IGNORE_SERVICES = (53, 67, 68, 123, 137, 5353, "icmp")
    # 3b5074b1b5d032e5620f69f9159a2983 was removed from _MALICIOUS_JA3 (2026-10-01): it is the stock Windows
    # 10 / Server 2019 / 2022 TLS stack (ET sid 2058285-2058288 use it only together with a specific SNI).
    #
    # A JA3 identifies a TLS client LIBRARY. One that reaches this many different servers from the same device is
    # the device's ordinary TLS stack (browser/OS), whatever a blocklist says about the hash -- a dedicated implant
    # talks to a handful of its own servers. Past this many distinct server names the hash stops counting as evidence.
    _JA3_COMMON_STACK_MIN_SERVERS = 5
    _SUSPICIOUS_PORTS = frozenset([4444, 4445, 8888, 9999, 1337, 31337, 6667, 6697, 1080, 3128, 5353])
    _EXCLUDED_HONEYPOT_PORTS = frozenset([137, 138, 139, 1900, 5353])
    
    def __init__(self, home_subnets: list = None, ti_engine=None, geoip_engine=None, safe_ips: set = None, honeypot_ips: set = None, safe_patterns: set = None, wired_probe_ips: set = None, lateral_ports: set = None, wired_probe_ignore_sources: set = None,
                 wired_probe_ignore_services=None, wired_probe_warmup_seconds: float = 0.0):
        # See _synchronized(): guards all per-IP state against the reactive-capture thread.
        self._state_lock = threading.RLock()
        # BUGFIX (live audit): was a fixed 5-port module-level constant (LATERAL_PORTS)
        # -- a real attacker isn't limited to SSH/SMB/RDP/VNC/Telnet, and extending
        # coverage to a new port used to require a code change/deploy. Config-driven,
        # same pattern as arp_sweep_unique_targets_threshold and every other detection
        # knob in this class; falls back to the same 5 ports as before if unset.
        self.lateral_ports = frozenset(lateral_ports) if lateral_ports else LATERAL_PORTS
        self._conn_ts = defaultdict(lambda: deque(maxlen=5000))
        self._new_ips = defaultdict(dict)
        # VERSION 11 (P1, review #3/#4 follow-up): parallel to _new_ips -- last-seen
        # destination PORT per dest_ip, so dns_evasion.py's blind-spot audit can tell
        # a direct UDP/53-to-a-non-Pi-hole-resolver connection (DNS_POLICY_BYPASS)
        # apart from an ordinary unexplained connection on some other port
        # (DNS_ATTRIBUTION_GAP). Same 1000-entry cap and update site as _new_ips.
        self._dest_ports = defaultdict(dict)
        self._ja3_hits = defaultdict(lambda: deque(maxlen=100))
        # (device ip, ja3) -> distinct server names seen with it. Kept across reset_all(): "this hash reaches many
        # servers" is a lasting fact about the device's stack, not a per-window one. Bounded.
        self._ja3_servers: dict = {}
        self._ja3_common_stack: set = set()
        ja3_provenance.set_source("builtin", {h: "built-in list (origin not recorded)" for h in self._MALICIOUS_JA3})
        self._ja4_hits = defaultdict(lambda: deque(maxlen=100))
        self._http_uas = defaultdict(dict)
        self._notices = defaultdict(lambda: deque(maxlen=100))
        self._susp_ports = defaultdict(lambda: deque(maxlen=500))
        self._http_reqs = defaultdict(dict)
        self._outbound_bytes = defaultdict(lambda: deque(maxlen=5000))
        # P0 (architecture review 2026-10-02): (ts, dst_ip, bytes) so exfiltration evidence can name the
        # destination that actually received the bytes, not the device's most recent connection.
        self._outbound_by_dst = defaultdict(lambda: deque(maxlen=5000))
        # W-04: per-minute outbound byte totals, [minute, bytes], kept one hour (the history above is pruned to the
        # 5-min detection window, so it cannot answer "last hour"). 61 buckets per device at most.
        self._outbound_minutes = defaultdict(lambda: deque(maxlen=61))
        # W-04: per (device ip -> destination ip) connection-periodicity stats for beacon_tdr/beacon_total -- O(1)
        # memory per pair (running mean/variance, Welford), at most _BEACON_MAX_PAIRS_PER_DEVICE pairs per device,
        # stalest evicted. Lives across the 5-min window on purpose: a 1-minute beacon needs 15 minutes to show.
        self._beacon_pairs: Dict[str, Dict[str, list]] = defaultdict(dict)
        self._beacon_pruned_at = 0.0
        # intelligence.local_popularity.LocalPopularity, set by the pipeline; None keeps beacon features silent.
        self.popularity = None
        self._doh_bypass_uids = defaultdict(dict)
        # SNI-verified DoH hits only (real DOH_SNIS hostname match, e.g. "dns.google"),
        # separate from _doh_bypass_uids above which also counts the port+IP heuristic
        # in _process_conn (dst_ip in DOH_IPS and dst_port == 443) -- that heuristic
        # can't distinguish genuine DoH from ordinary HTTPS to the same provider IP
        # (see dns_evasion.py's own REVERTED note), so it's fine for the observability
        # metric it already feeds but not trustworthy enough to become Evidence. This
        # dict is {device_ip: {dest_ip: ts}}, exposed via get_doh_bypass_ips().
        self._doh_sni_hits = defaultdict(dict)
        self._lateral_moves = defaultdict(lambda: deque(maxlen=500))
        self._conn_states = defaultdict(lambda: deque(maxlen=5000))
        self._conn_durations = defaultdict(lambda: deque(maxlen=5000))
        self._new_lateral_events = defaultdict(list)
        self._honeypot_hits = defaultdict(lambda: deque(maxlen=500))
        self._rejected_ips = defaultdict(lambda: deque(maxlen=5000))
        self._last_connection_meta = {}
        # BUGFIX (live audit): timestamps of GENUINE (never-seen-before-for-this-IP)
        # MAC flips per IP -- see _bind_mac()'s corroboration-gated hard-stop below.
        self._genuine_flip_ts = defaultdict(lambda: deque(maxlen=5))
        self.pending_spoof_evidence: Dict[str, dict] = {}
        # Written by _bind_mac(), consumed with pop_layer2_spoof() / pop_pending_spoof().
        self.layer2_spoofs: Dict[str, dict] = {}
        self._mac_last_seen: Dict[str, float] = {}
        
        self.honeypot_ips = honeypot_ips if honeypot_ips is not None else set()
        # PHASE 21D: "wired-device-visible probe" reactive-capture trigger. The two
        # wired devices (NAS/server, configured via reactive_capture_wired_probe_ips)
        # already have full Zeek flow visibility today (unlike WiFi devices, per this
        # session's live testing) -- a new/unusual source IP connecting to one of them
        # for the first time is worth a capture using data that's already flowing, no
        # new detector needed beyond this membership check. Consume-once queue, same
        # pattern as StateManager.pop_last_reidentify_ambiguous().
        self.wired_probe_ips = wired_probe_ips if wired_probe_ips is not None else set()
        # A5: sources that routinely talk to the wired devices (the sensor host's own Prometheus/backup jobs, known
        # infrastructure) -- they must not count as a "new source" worth a capture burst.
        self.wired_probe_ignore_sources = wired_probe_ignore_sources if wired_probe_ignore_sources is not None else set()
        # A5 (second pass, 2026-10-01): the IDS host is itself a wired-probe device AND the LAN's DNS server, so every
        # client doing DNS -- and every phone that rotates its IPv6 privacy address -- was a "new source" (21 sources
        # on udp/53 in one conn.log on .94). Infrastructure services on the wired devices don't count, and sources
        # seen during a warm-up after start are learned silently (the known-source set is in memory, so every
        # restart used to fire a burst). Entries: ints (tcp/udp destination port) and/or "icmp".
        services = self.DEFAULT_WIRED_PROBE_IGNORE_SERVICES if wired_probe_ignore_services is None else wired_probe_ignore_services
        self._wired_probe_ignore_ports = {int(x) for x in services if str(x).isdigit()}
        self._wired_probe_ignore_icmp = any(str(x).lower() == "icmp" for x in services)
        self._wired_probe_warmup_until = time.time() + float(wired_probe_warmup_seconds or 0.0)
        self._known_sources_per_wired_ip = defaultdict(set)
        self._new_wired_probe_sources = []
        # PHASE 21-LGBM-EXTEND: the most recent dns_evasion.py blind-spot-audit
        # unexplained-connection ratio per IP (0.0-1.0), so LightGBM's feature vector
        # (train_fp_classifier.py) has something to actually learn from -- previously
        # dns_evasion_anomaly evidence reached the evidence store/decision engine but
        # never touched the `features` dict the FP classifier is trained on at all. A
        # plain dict, not a rolling window: a burst-audit result is a discrete "as of
        # the last capture" fact, not a continuous per-packet stream, so it's simply
        # overwritten by the next burst (or cleared on reset_client()) rather than
        # aged out on a timer the way _arp_targets/_conn_ts are.
        self._dns_evasion_ratio = {}   # ip -> most recent unexplained-connection ratio [0.0, 1.0]
        self._wire_dns_resolutions = {}
        self._mac_bindings = {}
        # BUGFIX (production false-positive): ip -> {mac: last_seen_ts}. A rolling record
        # of every MAC actually seen for an IP, not just the single most recent one --
        # see _bind_mac()'s spoof-detection comment for why this exists.
        self._mac_history: Dict[str, Dict[str, float]] = {}
        # PHASE 4 (MAC-rotation resilience): DHCP Option 55/60/77 fingerprint of the most
        # recent DHCP transaction per IP/MAC, and a rolling per-device set of *all* JA4
        # hashes seen (not just malicious ones) used as a benign behavioral fingerprint.
        self._dhcp_fingerprints = {}          # ip -> {"vendor_class","param_list","user_class","ts"}
        self._dhcp_fingerprints_by_mac = {}   # mac -> same dict, survives across an IP change
        self._ja4_seen = defaultdict(set)     # ip -> set of ja4 hashes (capped per-device below)
        # PHASE 21B: rolling (ts, target_ip) pairs per ARP-requesting source, for
        # host-discovery-sweep detection -- broadcast, so this reaches WiFi devices the
        # same way MAC correlation already does. REQUEST operations only (a REPLY is a
        # device announcing itself, not probing); pruned by prune() via the same shared
        # window_seconds as every other rolling structure (see prune()'s
        # prune_tuple_deque_dict call) -- there is no separate per-signal window.
        self._arp_targets = defaultdict(lambda: deque(maxlen=2000))
        self.ti_engine = ti_engine
        self.geoip_engine = geoip_engine
        self._reverse_dns_cache = {}
        self._ptr_pool = concurrent.futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="zeek_ptr")
        self.safe_ips = safe_ips if safe_ips is not None else set()
        self.safe_patterns = {str(p).lower().strip() for p in (safe_patterns or []) if str(p).strip()}

        self._home_nets = []
        self.set_home_subnets(home_subnets or ["192.168.1.0/24"])
        LOGGER.debug("ZeekFeatureExtractor initialized.")

    @_synchronized
    def set_home_subnets(self, subnets: list) -> None:
        nets = []
        for net in subnets:
            if net:
                try: nets.append(ipaddress.ip_network(net, strict=False))
                except ValueError: pass
        self._home_nets = nets
        self._home_ip_memo = {}

    # A2 (2026-10-01): called for both ends of every Zeek event (and again from _enrich_ptr); building an
    # ipaddress object each time was ~9% of the engine's GIL time on .94. A home network has a few hundred distinct
    # addresses, so the answer is memoised per string (bounded; reset when the subnets change).
    _HOME_IP_MEMO_MAX = 20000

    def _is_home_ip(self, ip: str) -> bool:
        if not ip: return False
        memo = self._home_ip_memo
        hit = memo.get(ip)
        if hit is not None:
            return hit
        try:
            addr = ipaddress.ip_address(ip)
            result = any(addr in net for net in self._home_nets)
        except ValueError:
            result = False
        if len(memo) >= self._HOME_IP_MEMO_MAX:
            memo.clear()
        memo[ip] = result
        return result

    def is_home_ip(self, ip: str) -> bool:
        """Public wrapper for _is_home_ip() -- lets callers outside this module (e.g.
        pipeline.py's local-device-discovery evidence gathering) reuse the same
        home-subnet check without re-parsing home_subnets a second time."""
        return self._is_home_ip(ip)
        
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

    @staticmethod
    def _is_discovery_target(ip_str: str) -> bool:
        """Multicast, link-local or broadcast destinations (mDNS/SSDP/NDP/etc.). Nothing
        answers these like a unicast host, so S0/REJ toward them is normal discovery
        chatter, never a port-scan signal. Unlike _is_local_or_multicast(), private
        unicast is NOT included -- a scan of a real LAN host must still count."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return (ip.is_multicast or ip.is_link_local
                or (ip.version == 4 and (ip == ipaddress.ip_address("255.255.255.255")
                                         or str(ip).endswith(".255"))))

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
            # The lookup itself runs unlocked (it can take seconds); only the cache write takes the
            # state lock, because prune() iterates this cache and may have evicted the "pending" entry.
            if not self.geoip_engine:
                with self._state_lock:
                    self._reverse_dns_cache[ip] = {"host": "unknown", "ts": time.time()}
                return
            try:
                host = self.geoip_engine.reverse_dns(ip)
                with self._state_lock:
                    self._reverse_dns_cache[ip] = {"host": host if host else "unknown", "ts": time.time()}
                if host: LOGGER.debug("PTR resolved %s -> %s", ip, host)
            except Exception as e:
                with self._state_lock:
                    self._reverse_dns_cache[ip] = {"host": "unknown", "ts": time.time()}
                LOGGER.debug("PTR exception for %s: %s", ip, e)
                
        self._ptr_pool.submit(_bg_lookup)

    @_synchronized
    def get_hostname(self, ip: str) -> Optional[str]:
        entry = self._reverse_dns_cache.get(ip)
        if isinstance(entry, dict):
            host = entry.get("host")
            return host if host not in (None, "pending", "unknown") else None
        return None

    def _outbound_top_destination(self, ips) -> dict:
        """The destination that received most of this device's outbound bytes in the window, and its share.
        P0 (architecture review 2026-10-02): exfiltration evidence used to be attributed to `last_dest_ip` -- the
        device's most RECENT connection, often unrelated to the transfer -- so one IP collected evidence from
        traffic it never received, corrupting the decision engine's per-destination corroboration. A destination
        is only named when it clearly dominates (>= 50 % of the bytes); a transfer spread over many destinations
        gets none rather than a wrong one."""
        per_dst: Dict[str, int] = {}
        for ip in ips:
            for _ts, dst, b in self._outbound_by_dst.get(ip, []):
                per_dst[dst] = per_dst.get(dst, 0) + b
        total = sum(per_dst.values())
        if not total:
            return {"zeek_outbound_top_dest": "unknown", "zeek_outbound_top_dest_share": 0.0}
        dst, b = max(per_dst.items(), key=lambda kv: kv[1])
        share = b / total
        return {"zeek_outbound_top_dest": dst if share >= 0.5 else "unknown",
                "zeek_outbound_top_dest_share": round(share, 3)}

    @_synchronized
    def get_last_connection_meta(self, device_ip: str) -> dict:
        return self._last_connection_meta.get(device_ip, {
            "last_dest_ip": "unknown", "last_dest_port": 0, "dominant_protocol": "unknown", "zeek_outbound_bytes": 0
        })

    @_synchronized
    def pop_new_lateral_events(self, device_ip: str) -> list[tuple[str, int]]:
        events = self._new_lateral_events.get(device_ip, [])
        if events: self._new_lateral_events[device_ip] = []
        return events

    @_synchronized
    def pop_layer2_spoof(self, ip: str) -> Optional[dict]:
        """Consume the confirmed (2nd genuine flip) spoof record for `ip`, if any."""
        return self.layer2_spoofs.pop(ip, None)

    @_synchronized
    def pop_pending_spoof(self, ip: str) -> Optional[dict]:
        """Consume the first-flip (uncorroborated) spoof record for `ip`, if any."""
        return self.pending_spoof_evidence.pop(ip, None)

    @_synchronized
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
        prune_tuple_deque_dict(self._outbound_by_dst)
        prune_tuple_deque_dict(self._conn_states)
        prune_tuple_deque_dict(self._conn_durations)
        prune_tuple_deque_dict(self._rejected_ips)
        prune_tuple_deque_dict(self._honeypot_hits)
        prune_tuple_deque_dict(self._arp_targets)
        
        prune_ts_dict(self._new_ips)
        prune_ts_dict(self._doh_bypass_uids)
        prune_ts_dict(self._doh_sni_hits)
        prune_ts_dict(self._http_uas)
        prune_ts_dict(self._http_reqs)

        # W-04 state lives longer than `window`; trim it on its own clock, once a minute.
        if now_ts - self._beacon_pruned_at >= 60.0:
            self._beacon_pruned_at = now_ts
            beacon_cutoff = now_ts - _BEACON_MAX_GAP
            for src in list(self._beacon_pairs.keys()):
                pairs = self._beacon_pairs.get(src)
                if pairs is None:
                    continue
                for dst in [d for d, st in list(pairs.items()) if st[1] < beacon_cutoff]:
                    pairs.pop(dst, None)
                if not pairs:
                    self._beacon_pairs.pop(src, None)
            minute_cutoff = int((now_ts - 3600.0) // 60)
            for src in list(self._outbound_minutes.keys()):
                buckets = self._outbound_minutes.get(src)
                if not buckets or buckets[-1][0] <= minute_cutoff:
                    self._outbound_minutes.pop(src, None)

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

        # BUGFIX: same 24h TTL for _mac_history (the known-oscillation dedup memory --
        # see _bind_mac()) -- a MAC not seen for a given IP in 24h is dropped from that
        # IP's "known" set, so a real re-hijack long after a mesh device's last known
        # rotation still gets treated as genuinely new.
        for ip in list(self._mac_history.keys()):
            macs = self._mac_history[ip]
            for mac in list(macs.keys()):
                if macs[mac] < ttl_cutoff:
                    del macs[mac]
            if not macs:
                del self._mac_history[ip]
                
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
            last_seen = self._mac_last_seen.get(ip, 0)
            # BUGFIX (production false-positive, feeds a Stage-0 HARD-STOP that bypasses
            # CL-AFPE entirely -- argus/decision/engine.py's has_arp_spoof branch, single evidence
            # item, zero corroboration required): a genuine ARP-spoofing attacker hijacks an
            # IP and HOLDS it -- it would be self-defeating for them to keep handing control
            # back to the real device and re-attacking every ~15-20s, since that's exactly
            # when their own MITM window would close. What was actually observed in
            # production is IP addresses oscillating between the SAME small set of MACs
            # repeatedly over minutes to hours (mesh-WiFi repeater relay/rewrite behavior is
            # the leading suspect -- conn.log's orig_l2_addr can differ from the DHCP-sourced
            # MAC depending on which mesh hop last touched a given packet) -- a pattern a
            # real attack fundamentally does not produce. Only treat this as a genuine spoof
            # when the NEW mac has never been seen for this IP before; a MAC re-appearing
            # that we've already recorded for this IP is a known oscillation, not a new
            # hijacker, and does not reach the hard-stop evidence pipeline.
            mac_is_known_for_ip = mac in self._mac_history.get(ip, {})
            if (ts - last_seen) < 600 and not mac_is_known_for_ip:
                # BUGFIX (live audit): a single genuinely-new MAC on an IP is ALSO the
                # normal signature of MAC-randomization ("private Wi-Fi address," on by
                # default since iOS 14/Android 10) reconnecting/roaming -- not just a
                # real hijack. The mesh-repeater fix above already handles a mac
                # RE-appearing; this handles the DIFFERENT case of a mac that's
                # genuinely never been seen before. A real MITM takeover holds control
                # and, per the comment above, doesn't hand it back and re-attack every
                # 15-20s -- but it VERY plausibly re-establishes a session (a second
                # genuine flip) within a short window if the attacker is actively
                # working the target, which a one-off privacy-driven reconnect does
                # not. Require a SECOND genuine flip within the same 600s window before
                # the hard-stop; a lone first flip is real but weaker SUSPICIOUS-tier
                # evidence, corroboration-required like every other behavioral signal,
                # not an instant zero-corroboration CRITICAL block.
                self._genuine_flip_ts[ip].append(ts)
                recent_genuine_flips = [t for t in self._genuine_flip_ts[ip] if (ts - t) < 600]
                if len(recent_genuine_flips) >= 2:
                    LOGGER.critical(f"🚨 LAYER-2 ARP/NDP SPOOFING DETECTED: IP {ip} flipped from {existing_mac} to {mac} in {int(ts - last_seen)}s (2nd genuine flip within window)")
                    self.layer2_spoofs[ip] = {"old": existing_mac, "new": mac, "ts": ts}
                    self.pending_spoof_evidence.pop(ip, None)
                else:
                    LOGGER.warning(f"⚠️ IP {ip} MAC flip {existing_mac} -> {mac} to a genuinely new MAC -- "
                                    f"weak/uncorroborated evidence only (needs a 2nd flip within 600s to hard-stop; "
                                    f"consistent with normal MAC-randomization reconnect otherwise).")
                    self.pending_spoof_evidence[ip] = {"old": existing_mac, "new": mac, "ts": ts}
            elif (ts - last_seen) < 600:
                LOGGER.debug(f"IP {ip} MAC flip {existing_mac} -> {mac} is a known-oscillation "
                             f"(mac previously seen for this ip) -- not treated as a new spoof.")

        self._mac_bindings[ip] = mac
        self._mac_last_seen[ip] = ts
        self._mac_history.setdefault(ip, {})[mac] = ts
        self._enrich_ptr(ip)

    @_synchronized
    def ingest(self, event: dict) -> None:
        etype = event.get("_zeek_type", "")
        if etype == "dhcp":
            # The network's own DNS domain, from its DHCP server's answer (option 15) -- how a router-agnostic
            # sensor learns "fritz.box", "lan", "home", ... (see utils.note_network_dns_domain for where it is used).
            if event.get("domain") and self._is_home_ip(event.get("server_addr", "")):
                note_network_dns_domain(event.get("domain"))
            mac, ip = event.get("mac"), event.get("client_addr")
            if mac and ip:
                mac = mac.lower()
                self._bind_mac(ip, mac, event.get("ts", time.time()))

                # PHASE 4: capture the DHCP fingerprint fields added by
                # zeek_scripts/local-dhcp-fingerprint.zeek (vendor_class / param_list from
                # DHCP Options 60 / 55 -- see that file for why Option 77/user_class was
                # left out). Only stored when at least one is actually present, so
                # devices/Zeek builds without the script simply never populate this (safe
                # no-op degrade). Deployment step: Documentation/INSTALL.md §3.3.2.
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

        if etype == "arp":
            # PHASE 21B: arp.log uses spa/tpa (sender/target protocol address), not
            # id.orig_h/orig_h like every other log type -- has to be handled before the
            # generic `src` extraction below, same reason "dhcp" is a special early-return
            # case. Field names (spa/tpa/operation) match zeek_scripts/local-arp-log.zeek's
            # ARP::Info record exactly -- confirmed live end-to-end against a real captured
            # burst (see _init_tailers()'s comment on this same phase: stock Zeek has no
            # arp.log writer at all, this repo's own script provides one).
            operation = str(event.get("operation", "")).upper()
            spa, tpa = event.get("spa"), event.get("tpa")
            if operation == "REQUEST" and spa and tpa:
                self._arp_targets[spa].append((event.get("ts", time.time()), tpa))
            return

        src = event.get("id.orig_h", event.get("orig_h", ""))
        if not src: return
        self._enrich_ptr(src)
            
        if etype == "conn":
            if self.wired_probe_ips:
                dst = event.get("id.resp_h", "")
                if dst in self.wired_probe_ips and src not in self.wired_probe_ignore_sources                         and not self._is_wired_probe_infra_service(event):
                    known = self._known_sources_per_wired_ip[dst]
                    if src not in known:
                        known.add(src)
                        if time.time() >= self._wired_probe_warmup_until:
                            self._new_wired_probe_sources.append((dst, src))
                        if len(self._new_wired_probe_sources) > 200:  # safety valve, not expected in practice
                            self._new_wired_probe_sources = self._new_wired_probe_sources[-200:]
            self._process_conn(src, event)
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
            # S0/REJ toward multicast/link-local/broadcast is discovery chatter (real
            # alert: a phone's mDNS + LAN pings saturated the LGBM port-scan feature and
            # drove its false-positive score to 0.5%) -- don't count it as a scan.
            if not (conn_state in ("S0", "REJ") and self._is_discovery_target(dst_ip)):
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
                self._honeypot_hits[src].append((ts, dst_ip))
                
            if self._is_home_ip(src) and self._is_home_ip(dst_ip):
                if dst_port in self.lateral_ports and not self._is_safe_device(dst_ip) and not self._is_safe_device(src):
                    self._lateral_moves[src].append((ts, dst_ip, dst_port))
                    self._new_lateral_events[src].append((dst_ip, dst_port))

            if self._is_home_ip(src) and not self._is_local_or_multicast(dst_ip):
                if len(self._new_ips[src]) < 1000: self._new_ips[src][dst_ip] = ts
                if len(self._dest_ports[src]) < 1000: self._dest_ports[src][dst_ip] = dst_port
                if not self._is_safe_device(src):
                    if (dst_ip in DOH_IPS and dst_port == 443) or dst_port == 853:
                        if len(self._doh_bypass_uids[src]) < 100: self._doh_bypass_uids[src][uid] = ts
                    
        if dst_port in self._SUSPICIOUS_PORTS and not self._is_local_or_multicast(dst_ip):
            self._susp_ports[src].append(ts)
        
        if not self._is_local_or_multicast(dst_ip):
            self._outbound_bytes[src].append((ts, orig_bytes))
            if orig_bytes and dst_ip:
                self._outbound_by_dst[src].append((ts, dst_ip, orig_bytes))
            try:
                minute = int(float(ts) // 60)
            except (TypeError, ValueError):
                minute = None
            if minute is not None:
                buckets = self._outbound_minutes[src]
                if buckets and minute <= buckets[-1][0]:
                    buckets[-1][1] += orig_bytes      # same (or an out-of-order earlier) minute
                else:
                    buckets.append([minute, orig_bytes])
            if (dst_ip and orig_bytes > 0 and dst_port not in _BEACON_EXCLUDED_PORTS
                    and conn_state not in _BEACON_EXCLUDED_STATES and self._is_home_ip(src)):
                try:
                    self._observe_beacon(src, dst_ip, float(ts), orig_bytes)
                except (TypeError, ValueError):
                    pass

    def _observe_beacon(self, src: str, dst_ip: str, ts: float, orig_bytes: int) -> None:
        """One connection into the (src -> dst_ip) periodicity series. Pair layout:
        [first_ts, last_checkin_ts, n_intervals, mean_interval, m2_interval, n_sizes, mean_size, m2_size, missed]."""
        pairs = self._beacon_pairs[src]
        st = pairs.get(dst_ip)
        if st is None or ts - st[1] > _BEACON_MAX_GAP:
            if st is None and len(pairs) >= _BEACON_MAX_PAIRS_PER_DEVICE:
                pairs.pop(min(pairs, key=lambda k: pairs[k][1]), None)
            pairs[dst_ip] = [ts, ts, 0, 0.0, 0.0, 1, float(orig_bytes), 0.0, 0]
            return
        gap = ts - st[1]
        if gap < 0:
            return  # out-of-order line (conn.log is written when a connection closes, ts is when it opened)
        st[5] += 1
        delta = orig_bytes - st[6]
        st[6] += delta / st[5]
        st[7] += delta * (orig_bytes - st[6])
        if gap < _BEACON_SAME_CHECKIN_SECONDS:
            return  # another connection of the same check-in
        if st[2] >= 5 and gap > _BEACON_MISSED_FACTOR * st[3]:
            st[8] += 1  # a skipped check-in; counted, kept out of the interval statistics
            st[1] = ts
            return
        st[2] += 1
        delta = gap - st[3]
        st[3] += delta / st[2]
        st[4] += delta * (gap - st[3])
        st[1] = ts

    def _beacon_features(self, ips, device_id=None) -> dict:
        """beacon_tdr / beacon_total for the most regular destination of this device that is NEW on this network.

        Regularity alone is not enough -- vendor-cloud polling from IoT devices is perfectly regular by design. A series
        is reported only when its destination resolves (as seen on the wire) to names that are all new on this network
        (intelligence/local_popularity.is_preexisting() is False) and none of them is CDN/telemetry infrastructure.
        A destination with no observed name (direct-IP) is not reported: novelty cannot be measured for it. Without a
        popularity source, or before its history warm-up, nothing is reported."""
        if self.popularity is None:
            return {}
        candidates = []
        for ip in ips:
            for dst, st in list(self._beacon_pairs.get(ip, {}).items()):
                n_int, mean_i, mean_b = st[2], st[3], st[6]
                if n_int + 1 < _BEACON_MIN_OBSERVATIONS or mean_i < _BEACON_MIN_MEAN_INTERVAL or mean_b <= 0:
                    continue
                if st[8] > _BEACON_MAX_MISSED_SHARE * n_int:
                    continue
                cv_i = math.sqrt(st[4] / n_int) / mean_i
                cv_b = math.sqrt(st[7] / st[5]) / mean_b if st[5] > 1 else 0.0
                tdr = max(0.0, min(1.0 - cv_i / _BEACON_INTERVAL_CV_SCALE, 1.0 - cv_b / _BEACON_SIZE_CV_SCALE))
                if tdr > _BEACON_REPORT_TDR:
                    candidates.append((tdr, n_int + 1, dst))
        if not candidates:
            return {}
        from utils import is_telemetry_domain, _is_cdn_or_cloud_domain
        for tdr, total, dst in sorted(candidates, reverse=True)[:3]:
            names = sorted({q for q, a in list(self._wire_dns_resolutions.items()) if a == dst})[:8]
            if not names or any(is_telemetry_domain(n) or _is_cdn_or_cloud_domain(n) for n in names):
                continue
            try:
                if all(self.popularity.is_preexisting(n, device_id=device_id) is False for n in names):
                    return {"beacon_tdr": tdr, "beacon_total": float(total),
                            "beacon_domain": names[0], "beacon_dest_ip": dst}
            except Exception:
                continue
        return {}

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

    @_synchronized
    def get_wire_ip(self, domain: str) -> Optional[str]: return self._wire_dns_resolutions.get(str(domain).lower().strip("."))
    @_synchronized
    def get_mac(self, ip: str) -> Optional[str]: return self._mac_bindings.get(ip)
    @_synchronized
    def get_dhcp_fingerprint(self, ip: str) -> Optional[dict]: return self._dhcp_fingerprints.get(ip)
    @_synchronized
    def get_ja4_set(self, ip: str) -> set: return set(self._ja4_seen.get(ip, set()))
    @_synchronized
    def get_http_reqs(self, device_ip: str) -> set: return set(self._http_reqs.get(device_ip, {}).keys())
    @_synchronized
    def get_dest_ips(self, device_ip) -> set:
        out = set()
        for ip in self._as_ip_list(device_ip):
            out.update(self._new_ips.get(ip, {}).keys())
        return out

    @_synchronized
    def get_dest_ports(self, device_ip) -> dict:
        """VERSION 11 (P1): {dest_ip: last-seen destination port} for a device --
        the port-tracking twin of get_dest_ips() above, same _as_ip_list() multi-
        address aggregation. A dest_ip absent here (e.g. from a burst predating this
        field) simply isn't in the returned dict -- callers must not assume every
        dest_ip from get_dest_ips() has a matching entry."""
        out = {}
        for ip in self._as_ip_list(device_ip):
            out.update(self._dest_ports.get(ip, {}))
        return out

    @_synchronized
    def get_doh_bypass_ips(self, device_ip) -> set:
        """Destination IPs this device made a TLS connection to with an SNI matching a
        known DoH provider hostname (DOH_SNIS) -- real, SNI-verified DoH, not the
        broader/noisier port+IP heuristic _doh_bypass_uids also counts. See
        _doh_sni_hits's own comment for why the two are kept separate."""
        out = set()
        for ip in self._as_ip_list(device_ip):
            out.update(self._doh_sni_hits.get(ip, {}).keys())
        return out

    def _is_wired_probe_infra_service(self, event: dict) -> bool:
        proto = str(event.get("proto", "")).lower()
        if proto == "icmp":
            return self._wired_probe_ignore_icmp
        try:
            return int(event.get("id.resp_p", -1)) in self._wired_probe_ignore_ports
        except (TypeError, ValueError):
            return False

    @_synchronized
    def pop_new_wired_probe_sources(self) -> list:
        """Consume-once accessor for PHASE 21D's wired-device-probe trigger. Returns
        [(wired_ip, new_source_ip), ...] for any first-time-seen source since the last
        call, and clears the queue -- a caller that doesn't check every cycle can't
        end up re-triggering on stale findings from several cycles ago."""
        out = self._new_wired_probe_sources
        self._new_wired_probe_sources = []
        return out

    @_synchronized
    def set_dns_evasion_ratio(self, ip: str, ratio: float) -> None:
        """Records the most recent dns_evasion.py blind-spot-audit result for one IP --
        see _dns_evasion_ratio's __init__ comment for why this is a plain overwrite,
        not a rolling structure. Called by fritzbox_capture.py's
        run_dns_evasion_audit() right after a burst produces (or clears) a finding."""
        if not ip or ip == "unknown":
            return
        self._dns_evasion_ratio[ip] = max(0.0, min(1.0, float(ratio)))

    def _is_common_ja3_stack(self, src: str, ja3: str, server_name: str) -> bool:
        """True once `ja3` has been seen from `src` with _JA3_COMMON_STACK_MIN_SERVERS different server names: it is
        then the device's own TLS library, not an implant. Earlier hits of that hash in the current window are
        withdrawn so they stop counting as zeek_ja3_malicious."""
        key = (src, ja3)
        if key in self._ja3_common_stack:
            return True
        if len(self._ja3_servers) > 5000:   # bounded: devices x hashes is small, but never unbounded
            self._ja3_servers.clear()
        servers = self._ja3_servers.setdefault(key, set())
        name = (server_name or "").strip().lower()
        if name and len(servers) < 64:
            servers.add(name)
        if len(servers) < self._JA3_COMMON_STACK_MIN_SERVERS:
            return False
        self._ja3_common_stack.add(key)
        if src in self._ja3_hits:
            self._ja3_hits[src] = deque((h for h in self._ja3_hits[src] if h.get("ja3") != ja3), maxlen=100)
        LOGGER.info("JA3 %s seen from %s with %d different servers -- treated as that device's ordinary TLS stack, "
                    "not malware evidence", ja3, src, len(servers))
        return True

    def _process_ssl(self, src: str, ev: dict) -> None:
        ja3, ja4, ts = ev.get("ja3", ""), ev.get("ja4", ""), ev.get("ts", time.time())
        is_malicious_ja3, is_malicious_ja4 = False, False
        
        if ja3 and (ja3 in self._MALICIOUS_JA3 or (self.ti_engine and hasattr(self.ti_engine, "dynamic_ja3") and ja3 in self.ti_engine.dynamic_ja3)):
            is_malicious_ja3 = True
            LOGGER.debug("Malicious JA3 fingerprint identified: %s", ja3)
        if ja4 and ja4 in self._MALICIOUS_JA4: 
            is_malicious_ja4 = True
            LOGGER.debug("Malicious JA4+ fingerprint identified: %s", ja4)
                
        # BUGFIX (live audit): dest_ip added so NetworkIntrusionHypothesis's evidence
        # (malicious_ja3/malicious_ja4, zeek_network.py) can carry a real attribution
        # target -- previously only dest_port was captured, so a NETWORK_INTRUSION
        # alert built from this evidence had nothing evidence-linked to attach and fell
        # back to pipeline.py's generic "last connection" fallback.
        if is_malicious_ja3 and self._is_common_ja3_stack(src, ja3, ev.get("server_name", "")):
            is_malicious_ja3 = False
        if is_malicious_ja3: self._ja3_hits[src].append({"ja3": ja3, "server": ev.get("server_name", ""), "ts": ts, "dest_port": ev.get("id.resp_p", 0), "dest_ip": ev.get("id.resp_h", "")})
        if is_malicious_ja4: self._ja4_hits[src].append({"ja4": ja4, "server": ev.get("server_name", ""), "ts": ts, "dest_port": ev.get("id.resp_p", 0), "dest_ip": ev.get("id.resp_h", "")})

        # PHASE 4: track *every* JA4 seen (not just malicious ones) as a benign per-device
        # behavioral fingerprint, used for MAC-rotation re-identification. Capped at 50
        # distinct hashes per device — this is meant to capture "the small stable set of
        # TLS stacks this device's apps use," not a full unbounded history. JA4 (not JA3):
        # confirmed live that the old salesforce/ja3 zkg package's client-hello handler
        # never fires on Zeek 8.x (unmaintained since 2020) -- FoxIO's JA4 package is the
        # maintained replacement, see Documentation/INSTALL.md 3.3.2.
        if ja4 and len(self._ja4_seen[src]) < 50:
            self._ja4_seen[src].add(ja4)

        if not self._is_safe_device(src):
            sni = str(ev.get("server_name", "")).lower().strip(".")
            if sni and any(sni == doh or sni.endswith(f".{doh}") for doh in DOH_SNIS):
                if len(self._doh_bypass_uids[src]) < 100:
                    self._doh_bypass_uids[src][ev.get("uid", "")] = ts
                dest_ip = ev.get("id.resp_h", "")
                if dest_ip and len(self._doh_sni_hits[src]) < 100:
                    self._doh_sni_hits[src][dest_ip] = ts

    def _process_http(self, src: str, ev: dict) -> None:
        ua, host, uri, ts = ev.get("user_agent", ""), ev.get("host", ""), ev.get("uri", ""), ev.get("ts", time.time())
        if ua and len(self._http_uas[src]) < 500: self._http_uas[src][ua] = ts
        if host and uri and len(self._http_reqs[src]) < 1000: self._http_reqs[src][f"{host}{uri}"] = ts

    def _process_notice(self, src: str, ev: dict) -> None: self._notices[src].append({"note": ev.get("note", ""), "msg": ev.get("msg", ""), "ts": ev.get("ts"), "dest_port": ev.get("id.resp_p", 0), "dest_ip": ev.get("id.resp_h", "")})
    def _process_weird(self, src: str, ev: dict) -> None: self._notices[src].append({"note": f"weird:{ev.get('name', '')}", "msg": ev.get("addl", ""), "ts": ev.get("ts"), "dest_port": ev.get("id.resp_p", 0), "dest_ip": ev.get("id.resp_h", "")})

    @_synchronized
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

    @_synchronized
    def get_last_honeypot_ip(self, ips) -> Optional[str]:
        """Returns the honeypot IP most recently hit by any of this device's known
        addresses, or None. honeypot_access evidence (pipeline.py) previously had no
        way to attach a real .domain -- _honeypot_hits only ever stored bare
        timestamps, not which honeypot_ips entry was actually touched -- so a CRITICAL
        "Internal Honeypot Accessed" alert fell back to pipeline.py's generic "last
        connection" (often unrelated multicast/DNS traffic), same attribution gap
        already fixed for CONNECTION_ABUSE/DGA_BOTNET_C2/etc via their own evidence
        .domain fields.
        """
        ip_list = ips if isinstance(ips, (list, set, tuple)) else [ips]
        best_ts, best_ip = None, None
        for ip in ip_list:
            for ts, dst_ip in self._honeypot_hits.get(ip, []):
                if best_ts is None or ts > best_ts:
                    best_ts, best_ip = ts, dst_ip
        return best_ip

    @_synchronized
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
            # BUGFIX (2026-08-27, third-party review): a bare [:40] slice with no
            # truncation indicator produced alerts like "Netflix/2026.1.5
            # MDX/undefined(DEVTYPE=1" and "Spotify/129600518 Win32_x86_64/0 (PC lap" --
            # cut off mid-token, reading as a garbled but seemingly-complete string
            # rather than an obviously-truncated one. Longer cap, and an explicit "..."
            # when truncation actually happens so it's honest about being partial.
            return top_ua if len(top_ua) <= 80 else top_ua[:80] + "..."
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

    @_synchronized
    def get_features(self, device_ip, device_id=None) -> dict:
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

        # BUGFIX: found via a live alert audit (a third-party review of a real
        # example_pc_fritz_box tarpit alert, verified against this exact code) --
        # zeek_lateral_moves is a raw COUNT of connections to LATERAL_PORTS, with no
        # distinction between "one legitimate SMB/SSH/RDP connection" and "a genuine
        # multi-target scan." the CL-AFPE's Stage-1 hard-stop and pipeline.py's
        # lateral_threat (which authorizes Layer-2 tarpit, bypassing the normal
        # risk>=9.0 floor) both gate on a bare `> 0` check against this same count --
        # confirmed live: a single connection (zeek_lateral_moves=1) was sufficient to
        # reach CONFIRMED_THREAT and trigger tarpit containment. zeek_s0_rej_unique_ips
        # already exists alongside zeek_s0_rej_count for exactly this reason; the same
        # distinct-target tracking was simply never added for lateral movement.
        lateral_targets = set()
        for ip in ips:
            lateral_targets.update(dst_ip for _, dst_ip, _ in self._lateral_moves.get(ip, []))

        outbound_1h_cutoff_minute = int((time.time() - 3600.0) // 60)
        return {
            "zeek_conn_count": sum(len(self._conn_ts.get(ip, [])) for ip in ips),
            "zeek_new_ips": sum(len(self._new_ips.get(ip, {})) for ip in ips),
            "zeek_ja3_malicious": sum(len(self._ja3_hits.get(ip, [])) for ip in ips),
            "zeek_ja4_malicious": sum(len(self._ja4_hits.get(ip, [])) for ip in ips),
            "zeek_notices": sum(len(self._notices.get(ip, [])) for ip in ips),
            "zeek_susp_ports": sum(len(self._susp_ports.get(ip, [])) for ip in ips),
            "zeek_http_ua_count": sum(len(self._http_uas.get(ip, {})) for ip in ips),
            "zeek_outbound_bytes": sum(b for ip in ips for t, b in self._outbound_bytes.get(ip, [])),
            # W-04: read by metrics_sync (home_ids_outbound_bytes_1h), but never produced, so the gauge was a constant 0.
            # From the per-minute buckets: the per-connection history is pruned to the 5-min window.
            "zeek_outbound_bytes_1h": sum(
                b for ip in ips for m, b in list(self._outbound_minutes.get(ip, ())) if m > outbound_1h_cutoff_minute
            ),
            # W-04: beacon_tdr / beacon_total / beacon_domain, only for a regular series to a destination new on
            # this network (see _beacon_features). Absent otherwise, so the detector's branch stays quiet.
            **self._beacon_features(ips, device_id),
            **self._outbound_top_destination(ips),
            "zeek_doh_bypass": sum(len(self._doh_bypass_uids.get(ip, {})) for ip in ips),
            "zeek_lateral_moves": sum(len(self._lateral_moves.get(ip, [])) for ip in ips),
            "zeek_lateral_unique_targets": len(lateral_targets),
            # BUGFIX (live audit): same attribution gap as zeek_s0_rej_ip_examples above --
            # zeek_lateral_scan evidence (pipeline.py) had a count but no actual targets.
            "zeek_lateral_target_examples": sorted(lateral_targets)[:5],
            "zeek_s0_rej_count": sum(1 for s in states if s in ("S0", "REJ")),
            "zeek_s0_rej_unique_ips": len(rejected_ips),
            # BUGFIX (live audit): zeek_s0_rej_unique_ips only ever exposed the COUNT,
            # never which IPs -- so a CONNECTION_ABUSE alert built from this evidence had
            # no real destination to attribute to and fell back to pipeline.py's generic
            # "last connection" fallback (often a totally unrelated DNS query). Exposes a
            # short, deterministic (sorted) sample so threat_signals.py can attach a real
            # one to Evidence.domain, same pattern dns_tunnel_v2/dns_dga_burst already use.
            "zeek_s0_rej_ip_examples": sorted(rejected_ips)[:5],
            "zeek_max_duration": max(durations) if durations else 0.0,
            "zeek_honeypot_hits": sum(len(self._honeypot_hits.get(ip, [])) for ip in ips),
            # PHASE 21B: distinct ARP-requested targets across this device's known
            # addresses, within the same shared rolling window as everything else above
            # (pruned by prune()) -- host-discovery-sweep signal, broadcast so it reaches
            # WiFi devices already.
            "zeek_arp_sweep_count": len({tpa for ip in ips for _ts, tpa in self._arp_targets.get(ip, [])}),
            # BUGFIX (live audit): zeek_arp_sweep_count only ever exposed the COUNT,
            # never which IPs -- so an arp_sweep-driven CONNECTION_ABUSE alert had no
            # real destination to attribute to, and pipeline.py's alert display fell
            # back to a coincidental, unrelated domain/port from the device's own last
            # connection. Same pattern as zeek_s0_rej_ip_examples/
            # zeek_lateral_target_examples above.
            "zeek_arp_swept_ip_examples": sorted({tpa for ip in ips for _ts, tpa in self._arp_targets.get(ip, [])})[:5],
            # PHASE 21-LGBM-EXTEND: most recent dns_evasion.py finding across this
            # device's known addresses (max, not sum -- it's a ratio per burst, not an
            # accumulating count). 0.0 for a device with no reactive-capture burst yet,
            # same "no data yet" semantics every other zero-default here already has.
            "zeek_dns_evasion_ratio": max((self._dns_evasion_ratio.get(ip, 0.0) for ip in ips), default=0.0),
            "zeek_app_protocol_weight": app_weight,
            "last_dest_ip": meta.get("last_dest_ip", "unknown"),
            "last_dest_port": port,
            "dominant_protocol": meta.get("dominant_protocol", "TCP")
        }

    @_synchronized
    def get_alerts(self, device_ip) -> list[dict]:
        alerts = []
        for ip in self._as_ip_list(device_ip):
            # BUGFIX (live audit): dest_ip/server now included so zeek_network.py can
            # attach a real attribution target to this evidence.
            for h in self._ja3_hits.get(ip, []): alerts.append({"type": "malicious_ja3", "ja3": h["ja3"], "dest_port": h.get("dest_port", 0), "dest_ip": h.get("dest_ip", ""), "server": h.get("server", ""), "confidence": 0.95})
            for h in self._ja4_hits.get(ip, []): alerts.append({"type": "malicious_ja4", "ja4": h["ja4"], "dest_port": h.get("dest_port", 0), "dest_ip": h.get("dest_ip", ""), "server": h.get("server", ""), "confidence": 0.95})
            for n in self._notices.get(ip, []): alerts.append({"type": "zeek_notice", "note": n["note"], "msg": n["msg"], "dest_port": n.get("dest_port", 0), "dest_ip": n.get("dest_ip", ""), "confidence": 0.75})
        return alerts

    @_synchronized
    def reset_all(self) -> None:
        for d in (self._conn_ts, self._new_ips, self._dest_ports, self._ja3_hits, self._ja4_hits, self._notices, self._susp_ports, self._http_uas, self._http_reqs, self._outbound_bytes, self._outbound_by_dst, self._doh_bypass_uids, self._doh_sni_hits, self._lateral_moves, self._conn_states, self._conn_durations, self._new_lateral_events, self._honeypot_hits, self._rejected_ips, self._last_connection_meta, self._beacon_pairs, self._outbound_minutes): d.clear()
        if len(self._wire_dns_resolutions) > 10000: self._wire_dns_resolutions.clear()

    @_synchronized
    def reset_client(self, client_ip) -> None:
        """PHASE 6: accepts a single IP (unchanged) or an iterable of IPs (pass
        `state.known_ips`) so post-alert resets clear a device's counters across ALL of
        its known addresses — without this, whichever address wasn't `state.client_ip` at
        alert time would keep its stale pre-alert counters and could immediately
        re-trigger the same alert next cycle purely from leftover, already-alerted-on data."""
        for ip in self._as_ip_list(client_ip):
            for d in (self._conn_ts, self._new_ips, self._ja3_hits, self._ja4_hits, self._notices, self._susp_ports, self._http_uas, self._http_reqs, self._outbound_bytes, self._outbound_by_dst, self._doh_bypass_uids, self._doh_sni_hits, self._lateral_moves, self._conn_states, self._conn_durations, self._new_lateral_events, self._honeypot_hits, self._rejected_ips, self._last_connection_meta, self._dhcp_fingerprints, self._ja4_seen, self._arp_targets, self._dns_evasion_ratio, self._beacon_pairs):
                if ip in d:
                    del d[ip]