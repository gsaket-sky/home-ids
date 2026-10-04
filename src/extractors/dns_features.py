"""
dns_features.py – Per-device DNS feature extraction and Pi-hole data collection.

RECENT FIXES:
- FIXED (STARTUP HANG / FULL TABLE SCAN): Replaced the time-based startup lookback query 
  (`WHERE timestamp >= ?`) with an instant O(1) `MAX(id)` index seek. Because Pi-hole does not 
  index the `timestamp` column, the previous query forced a multi-minute sequential scan on bloated 
  databases, permanently blocking the main Python thread at boot.
- FIXED (SQLITE I/O LAG): Completely rewrote `PiHoleCollector.poll()` to use a strict Primary Key 
  index seek (`WHERE id > ?`). Client IP exclusions and host pattern filtering are now handled natively 
  in Python memory (O(1) set lookups) rather than forcing SQLite to dynamically replan the query.
- FIXED (EXCEPTION TRAP): Replaced the `reply_type` try/except block with a `PRAGMA table_info` schema 
  validation during `_connect()`. Prevents the 2-second polling loop from continuously triggering and 
  swallowing `sqlite3.OperationalError` exceptions on older FTL databases.
- FIXED (2026-10-05, NXDOMAIN CLASSIFICATION): a row is NXDOMAIN when its `reply_type` is 2, never by status --
  FTL status 3 is "answered from cache" and 12/13 are retries, which used to count as NXDOMAIN. Blocked statuses
  follow Pi-hole's documented set. One classification for every consumer: extractors/pihole_codes.py.
"""
import logging
import sqlite3
import time
import math
from collections import Counter, defaultdict
from pathlib import Path

from utils import entropy, suspicious_dga, is_telemetry_domain, _is_cdn_or_cloud_domain, etld1
from config import CONFIG
from core.heartbeat import write_component_heartbeat
from extractors.pihole_codes import BLOCKED_STATUSES, NXDOMAIN_STATUSES, classify_status

LOGGER = logging.getLogger("home_ids.dns_features")

BLOCKED  = BLOCKED_STATUSES
NXDOMAIN = NXDOMAIN_STATUSES

_DEFAULT_DECAY_FACTOR = 0.995

# -------------------------------------------------------------------------
# MARKOV KILL-CHAIN MATRICES
# -------------------------------------------------------------------------
# VERSION 11 (P3, review #22): "RECON"/"C2"/"LATERAL"/"EXFIL" read as confirmed
# kill-chain stages to anyone seeing them on a dashboard, but they're purely
# heuristic feature-threshold guesses (see _determine_killchain_phase below) --
# nothing in argus/decision/engine.py or argus/hypotheses/engine.py ever reads this value, it's
# display/Grafana-telemetry only, but a human staring at "EXFIL" on a panel has no
# way to know that from the label alone. Prefixed SUSPECTED_ (except NORMAL, which
# needs no hedging) so the uncertainty is visible in the label itself, matching the
# review's explicit suggestion ("suspected_phase" instead of "killchain_phase=EXFIL").
# Detection thresholds themselves are UNCHANGED -- this is a labeling fix only.
_MARKOV_TRANSITIONS = {
    "NORMAL": {"NORMAL": 0.90, "SUSPECTED_RECON": 0.08, "SUSPECTED_C2": 0.01, "SUSPECTED_LATERAL": 0.01, "SUSPECTED_EXFIL": 0.00},
    "SUSPECTED_RECON": {"NORMAL": 0.70, "SUSPECTED_RECON": 0.20, "SUSPECTED_C2": 0.05, "SUSPECTED_LATERAL": 0.05, "SUSPECTED_EXFIL": 0.00},
    "SUSPECTED_C2": {"NORMAL": 0.20, "SUSPECTED_RECON": 0.10, "SUSPECTED_C2": 0.60, "SUSPECTED_LATERAL": 0.05, "SUSPECTED_EXFIL": 0.05},
    "SUSPECTED_LATERAL": {"NORMAL": 0.40, "SUSPECTED_RECON": 0.10, "SUSPECTED_C2": 0.10, "SUSPECTED_LATERAL": 0.30, "SUSPECTED_EXFIL": 0.10},
    "SUSPECTED_EXFIL": {"NORMAL": 0.30, "SUSPECTED_RECON": 0.05, "SUSPECTED_C2": 0.15, "SUSPECTED_LATERAL": 0.05, "SUSPECTED_EXFIL": 0.45},
}


def _decay_rate_per_second() -> float:
    decay_factor = CONFIG.get("decay_factor", _DEFAULT_DECAY_FACTOR)
    poll_interval = CONFIG.get("poll_interval", 2.0)
    try:
        decay_factor = float(decay_factor)
        poll_interval = float(poll_interval)
    except (TypeError, ValueError):
        return 1.0
    if not (0.0 < decay_factor < 1.0) or poll_interval <= 0:
        return 1.0  
    return decay_factor ** (1.0 / poll_interval)


class PiHoleCollector:
    """Reads newly written DNS records natively from Pi-hole's backend DB with live config bindings."""
    def __init__(self, db_path: str = "", lookback_seconds: int = 0, excluded_ips=None, excluded_patterns=None):
        self._explicit_db_path = db_path
        self._explicit_lookback = lookback_seconds
        self._explicit_excluded_ips = excluded_ips
        self._explicit_excluded_patterns = excluded_patterns
        
        self._conn = None
        self.last_id = 0
        self._hostnames = {}
        self._has_reply_type = False
        
        self._last_hostname_refresh = 0.0
        self._hostname_refresh_interval = 60.0

        # Rate-limits the new health heartbeat write below -- poll() itself runs
        # roughly once per poll_interval (config.yaml default 2s), but
        # write_component_heartbeat() is a full read-modify-write against a file
        # shared with several other writers (docstring: "low-frequency writes,
        # once per ~10s at most"); writing on literally every poll would be both
        # wasteful and out of line with that contract.
        self._last_heartbeat_write = 0.0
        self._heartbeat_write_interval = 30.0

        self._connect()

    @property
    def db_path(self) -> str:
        return self._explicit_db_path or CONFIG.get("pihole_db", "/etc/pihole/pihole-FTL.db")

    @property
    def lookback_seconds(self) -> int:
        if self._explicit_lookback > 0:
            return self._explicit_lookback
        return int(CONFIG.get("startup_lookback_seconds", 300))

    @property
    def excluded_ips(self) -> set:
        if self._explicit_excluded_ips is not None:
            return set(self._explicit_excluded_ips)
        return set(CONFIG.get("safe_ips", ["127.0.0.1"]))

    @excluded_ips.setter
    def excluded_ips(self, values) -> None:
        self._explicit_excluded_ips = set(values) if values is not None else None

    @property
    def excluded_patterns(self) -> set:
        if self._explicit_excluded_patterns is not None:
            return {str(p).lower().strip() for p in self._explicit_excluded_patterns if str(p).strip()}
        patterns = CONFIG.get("safe_host_patterns", [])
        return {str(p).lower().strip() for p in patterns if str(p).strip()}

    @excluded_patterns.setter
    def excluded_patterns(self, values) -> None:
        self._explicit_excluded_patterns = {str(p).lower().strip() for p in values if str(p).strip()} if values is not None else None

    def _refresh_hostnames(self) -> None:
        if not self._conn:
            return
        try:
            new_hostnames = {}
            for row in self._conn.execute("SELECT ip, name FROM network_addresses WHERE name IS NOT NULL").fetchall():
                new_hostnames[row[0]] = row[1]
            self._hostnames = new_hostnames
            self._last_hostname_refresh = time.time()
        except Exception as exc:
            LOGGER.debug("Failed to refresh Pi-hole hostnames: %s", exc)

    def _connect(self) -> None:
        try:
            uri = f"file:{self.db_path}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=10.0)
            self._conn.text_factory = lambda b: b.decode("utf-8", "ignore")
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA cache_size=-8000;")
            
            # Check schema dynamically to avoid OperationalError exceptions during the poll loop
            cols = [info[1] for info in self._conn.execute("PRAGMA table_info(queries)").fetchall()]
            self._has_reply_type = "reply_type" in cols
            
            self._refresh_hostnames()
                
            # HIGH PERFORMANCE BOOT:
            # Pi-hole does NOT index the 'timestamp' column. Using WHERE timestamp >= ? forces a multi-minute 
            # full table scan on millions of rows, permanently hanging the script at boot.
            # Instead, we fetch MAX(id) (which is an instant O(1) B-Tree seek) and subtract a 5000 row buffer.
            cur_max = self._conn.execute("SELECT MAX(id) FROM queries")
            max_id = cur_max.fetchone()[0] or 0
            self.last_id = max(0, max_id - 5000)

        except Exception as exc:
            LOGGER.error("Pi-hole DB connect failed: %s", exc)
            self._conn = None

    def _reconnect(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except:
                pass
        self._conn = None
        time.sleep(1.0)
        self._connect()

    def poll(self, limit: int = 5000) -> list[dict]:
        if self._conn is None:
            self._reconnect()
            if self._conn is None:
                return []
                
        if time.time() - self._last_hostname_refresh > self._hostname_refresh_interval:
            self._refresh_hostnames()
        
        try:
            # High-performance strict Primary Key seek. Query planner caches this efficiently.
            if self._has_reply_type:
                query = "SELECT id, timestamp, domain, client, status, reply_type FROM queries WHERE id > ? ORDER BY id ASC LIMIT ?"
            else:
                query = "SELECT id, timestamp, domain, client, status FROM queries WHERE id > ? ORDER BY id ASC LIMIT ?"
                
            rows = self._conn.execute(query, (self.last_id, limit)).fetchall()
        except sqlite3.OperationalError:
            self._reconnect()
            return []
        except Exception:
            return []

        # BUGFIX (2026-09-15, console/health audit -- user report: "the same logic
        # should apply for all other subsystems", re: Suricata's own last-scan
        # recency fix). Written here, right after a genuinely successful query,
        # regardless of whether it found any NEW rows -- zero new rows is still a
        # successful poll, not a failure, so it must still count. Never written on
        # either exception path above, matching suricata_scan's own "only a real
        # success refreshes the recency clock" design (write_component_heartbeat()
        # always stamps `now` unconditionally, so writing it on a failure would
        # wrongly mask a real outage). Rate-limited via _heartbeat_write_interval
        # (see __init__'s own comment) -- the console's health check only needs
        # ~2-minute-scale freshness, not every single 2-second poll cycle.
        now_ts = time.time()
        if now_ts - self._last_heartbeat_write > self._heartbeat_write_interval:
            self._last_heartbeat_write = now_ts
            try:
                write_component_heartbeat(
                    Path(CONFIG.get("state_path", "state/ids_state.json")).parent,
                    "pihole_poll", extra={"new_rows": len(rows)},
                )
            except Exception:
                pass

        if not rows:
            return []
        
        results = []
        excl_ips = self.excluded_ips
        excl_pats = self.excluded_patterns
        
        for r in rows:
            client_ip = r[3]
            
            # O(1) Python memory filtration is exponentially faster than SQLite `NOT IN` planner recalculations
            if client_ip in excl_ips:
                continue
                
            hostname = self._hostnames.get(client_ip, client_ip)
            if any(pat in hostname.lower() for pat in excl_pats):
                continue
                
            reply_type = r[5] if self._has_reply_type else 0

            results.append({
                "timestamp": r[1],
                "domain": r[2],
                "client_ip": client_ip,
                "hostname": hostname,
                "status": classify_status(r[4], reply_type),
                "ftl_status": r[4],
                "reply_type": reply_type
            })
            
        self.last_id = rows[-1][0]
        return results


# W-04 producers (unique_subdomain_ratio, dga_score). Both are novelty-gated: a value is produced only for names that
# are new on this network (intelligence/local_popularity.is_preexisting() is False). With no popularity source, or
# history younger than its warm-up, they produce nothing -- thin data never becomes evidence. No subnet, hostname or
# vendor of any one network is involved; every gate is measured from this network's own traffic.
UNIQUE_RATIO_MIN_CHILDREN = 20        # distinct subdomains under one parent, in the 5-min window
UNIQUE_RATIO_MIN_LABEL_ENTROPY = 3.5  # mean first-label entropy: encoded chunks, not customer1/customer2 names
DGA_MIN_NX_CANDIDATES = 10            # distinct NXDOMAIN names in the last hour before a score is computed
DGA_MIN_NOVEL_ALGORITHMIC = 8         # of which at least this many look algorithmic AND are new here

# A device's own learning period: everything it does is "new on this network" (a camera added today polling its
# vendor cloud), so novelty says nothing about it yet. Measured as activity actually observed
# (DeviceFamiliarity.learned_activity), never calendar time: a device that was on for an hour a week ago is still at
# the start of its learning period. Both bars must hold -- short sessions on many days are not enough either.
# Seven active days so a weekly rhythm (weekend-only use) is part of what was learned, not "new" next weekend.
# The pipeline applies this gate to every novelty-gated feature, from both extractors.
NOVELTY_MIN_ACTIVE_DAYS = 7
NOVELTY_MIN_ACTIVE_HOURS = 24
_NOVELTY_GATED_DEFAULTS = {"unique_subdomain_ratio": 0.0, "unique_subdomain_ratio_domain": "",
                           "dga_score": 0.0, "dga_score_examples": []}
_NOVELTY_GATED_OPTIONAL = ("beacon_tdr", "beacon_total", "beacon_domain", "beacon_dest_ip")


def in_learning_period(active_days: int, active_hours: int) -> bool:
    """True until a device has NOVELTY_MIN_ACTIVE_DAYS active days AND NOVELTY_MIN_ACTIVE_HOURS active hours of
    learned behaviour (DeviceFamiliarity.learned_activity). One definition for every consumer."""
    return not (active_days >= NOVELTY_MIN_ACTIVE_DAYS and active_hours >= NOVELTY_MIN_ACTIVE_HOURS)


def apply_device_age_gate(features: dict, active_days: int, active_hours: int) -> bool:
    """Clears the novelty-gated W-04 features while the device is in its learning period (in_learning_period).
    Returns True when it cleared them."""
    if not in_learning_period(active_days, active_hours):
        return False
    features.update({k: (list(v) if isinstance(v, list) else v) for k, v in _NOVELTY_GATED_DEFAULTS.items()})
    for key in _NOVELTY_GATED_OPTIONAL:
        features.pop(key, None)
    return True


class FeatureExtractor:
    # intelligence.local_popularity.LocalPopularity, set by the pipeline. None (tests, tools): the novelty-gated
    # producers stay silent.
    popularity = None

    def _novel(self, domain: str, device_id=None) -> bool:
        """True only when the popularity source positively says `domain` is new on this network (or, for an
        out-of-learning `device_id`, a name only learning-period devices had used -- see is_preexisting())."""
        pop = self.popularity
        if pop is None or not domain:
            return False
        try:
            return pop.is_preexisting(domain, device_id=device_id) is False
        except Exception:
            return False

    def _unique_subdomain_ratio(self, rw, fanout_by_base, parent: str, label_entropy: float, device_id=None):
        """Share of queries under the busiest non-CDN parent that went to a never-repeated subdomain. ~1.0 is the
        tunneling shape (every encoded chunk asked once). Produced only for a large, high-entropy fanout under a
        parent that is new on this network; otherwise (0.0, "")."""
        if not parent or label_entropy < UNIQUE_RATIO_MIN_LABEL_ENTROPY:
            return 0.0, ""
        children = fanout_by_base.get(parent) or ()
        if len(children) < UNIQUE_RATIO_MIN_CHILDREN or not self._novel(parent, device_id):
            return 0.0, ""
        total = sum(rw.domains.get(c, 0) for c in children)
        if total <= 0:
            return 0.0, ""
        return min(1.0, len(children) / total), parent

    def _dga_score(self, nx_names, device_id=None):
        """Share of the last hour's NXDOMAIN names that look algorithmic and are new on this network. Real DGA malware
        mostly hits unregistered names, hence NXDOMAIN. Single-label names (browser intranet probes), local and
        CDN/telemetry names, and anything already used here (a local search suffix, a typo of a known site) are left
        out before counting. Produced only with enough distinct names behind it; otherwise (0.0, [])."""
        if self.popularity is None:
            return 0.0, []
        candidates = [n for n in nx_names
                      if "." in n and etld1(n) and not is_telemetry_domain(n) and not _is_cdn_or_cloud_domain(n)]
        if len(candidates) < DGA_MIN_NX_CANDIDATES:
            return 0.0, []
        algorithmic = [n for n in candidates if suspicious_dga(n)]
        if len(algorithmic) < DGA_MIN_NOVEL_ALGORITHMIC:
            return 0.0, []
        # Novelty last and bounded: it is the only gate that reads the database.
        novel = [n for n in sorted(algorithmic)[:64] if self._novel(n, device_id)]
        if len(novel) < DGA_MIN_NOVEL_ALGORITHMIC:
            return 0.0, []
        return min(1.0, len(novel) / len(candidates)), novel[:3]
    
    def _determine_killchain_phase(self, state, features: dict) -> str:
        """Determines the current active kill-chain phase based on aggregated features."""
        outbound_bytes = features.get("zeek_outbound_bytes", 0)
        outbound_z = features.get("outbound_bytes_z", 0.0)
        if outbound_bytes > 50000000 or outbound_z > 3.0 or features.get("dns_tunneling_domains", 0) > 0 or features.get("dns_txt_null_ratio", 0.0) > 0.25:
            return "SUSPECTED_EXFIL"
        
        if features.get("beaconing_c2_count", 0) > 0 or features.get("beaconing_c2_1h", 0) > 0 or features.get("suspicious_domains", 0) > 5 or features.get("suspicious_tld_ratio", 0.0) > 0.20:
            return "SUSPECTED_C2"
            
        # B7 (2026-10-01): one connection to one host (a NAS share, a single SSH login) is not lateral
        # movement; same distinct-target bar the hard-stop uses (the CL-AFPE, lateral_movement_unique_targets).
        if (features.get("zeek_lateral_moves", 0) > 0 and features.get("zeek_lateral_unique_targets", 0) >= 2) \
                or features.get("zeek_s0_rej_count", 0) > 20:
            return "SUSPECTED_LATERAL"

        # B8: an NXDOMAIN ratio is only meaningful with enough queries behind it (a laptop that asked
        # five questions and got two NXDOMAINs is not scanning).
        if (features.get("nxdomain_ratio", 0.0) > 0.4 and features.get("total", 0) >= 20) \
                or features.get("zeek_susp_ports", 0) > 0:
            return "SUSPECTED_RECON"
            
        return "NORMAL"

    def _compute_markov_anomaly(self, state, current_phase: str) -> float:
        history = list(getattr(state, "killchain_history", []))
        if not history:
            return 0.0
            
        last_phase = history[-1]
        transition_prob = _MARKOV_TRANSITIONS.get(last_phase, {}).get(current_phase, 0.01)
        return 1.0 - transition_prob

    def compute(self, state, now: float, window_seconds: int) -> dict:
        rw = state.rolling

        # Prune 5-minute short-term events
        while rw.events and rw.events[0][0] < now - window_seconds:
            ts, domain, status = rw.events.popleft()
            if status in BLOCKED:
                rw.blocked = max(rw.blocked - 1, 0)
            if status in NXDOMAIN:
                rw.nxdomain = max(rw.nxdomain - 1, 0)
            if domain in rw.domains:
                rw.domains[domain] -= 1
                if rw.domains[domain] <= 0:
                    del rw.domains[domain]
            if domain in rw.domain_timestamps:
                while rw.domain_timestamps[domain] and rw.domain_timestamps[domain][0] < now - window_seconds:
                    rw.domain_timestamps[domain].popleft()
                if not rw.domain_timestamps[domain]:
                    del rw.domain_timestamps[domain]

        # Prune 1-hour (3600s) long-term events for low-and-slow telemetry
        while rw.long_events and rw.long_events[0][0] < now - 3600:
            rw.long_events.popleft()

        _MAX_EVENTS_CAP = 10000
        while len(rw.events) > _MAX_EVENTS_CAP:
            ts, domain, status = rw.events.popleft()
            if status in BLOCKED:
                rw.blocked = max(rw.blocked - 1, 0)
            if status in NXDOMAIN:
                rw.nxdomain = max(rw.nxdomain - 1, 0)
            if domain in rw.domains:
                rw.domains[domain] -= 1
                if rw.domains[domain] <= 0:
                    del rw.domains[domain]
            if domain in rw.domain_timestamps:
                if rw.domain_timestamps[domain]:
                    rw.domain_timestamps[domain].popleft()
                if not rw.domain_timestamps[domain]:
                    del rw.domain_timestamps[domain]

        n_events = len(rw.events)
        n_long_events = len(rw.long_events)
        if n_events == 0 and n_long_events == 0:
            return self._zero_features()

        entropy_sum  = 0.0
        suspicious   = 0
        suspicious_domain_examples = []
        deep_domains = 0
        beaconing_c2_count = 0
        beaconing_c2_1h = 0
        # P0 (architecture review 2026-10-02): the domains whose query timing was periodic -- beaconing evidence is
        # attributed to them instead of the device's last TCP connection.
        beaconing_c2_domains: list = []
        beaconing_c2_1h_domains: list = []
        min_jitter_cv = 999.0

        max_label_len = 0
        max_label_domain = ""
        # SECURITY FIX (P0-1, third-party architecture review, 2026-09-28): entropy_avg
        # below is a pure device-wide average across every domain in the window -- until
        # now, the single domain that actually drove that average up was never tracked
        # anywhere, unlike max_label_domain/tunneling_domain_examples/
        # suspicious_domain_examples just above and below, which already keep the real
        # example domain for their own evidence types. Without it, dns_behavior.py's
        # dns_entropy Evidence had no .domain to attach at all, so a DNS_TUNNELING alert
        # could only ever fall back to "unknown" (pipeline.py's own DNS_TUNNELING branch)
        # even when one specific domain's high-entropy label was what actually tripped
        # the threshold -- the same "real evidence-linked domain instead of an unrelated
        # fallback" gap already fixed for dns_tunnel_v2/dns_dga_burst below.
        top_entropy_value = 0.0
        top_entropy_domain = ""
        tunneling_domains = 0
        tunneling_domain_examples = []
        suspicious_tld_count = 0
        txt_null_count = 0
        # Sliding-window subdomain fanout: for real DNS tunneling, the tell isn't one
        # domain's own label length, it's MANY distinct labels sharing the same
        # registrable parent within the window (e.g. 1000s of encoded chunks under one
        # attacker-controlled domain). CDN/telemetry parents legitimately do this too
        # (many edge-node subdomains under one cloudfront.net/etc.), so those are excluded
        # the same way the existing tunneling_domains/beaconing checks already are.
        fanout_by_base = defaultdict(set)

        _SUSPICIOUS_TLDS = frozenset({"top", "xyz", "biz", "cc", "cfd", "buzz", "gq", "tk", "work", "rest", "country", "stream", "icu", "click", "live"})
        _TXT_NULL_QTYPES = frozenset({"TXT", "NULL", "ANY", "MX", "CNAME", 16, 10, 255, 15, 5})

        decay_rate = _decay_rate_per_second()
        decayed_weights = {}
        decayed_total = 0.0

        # High-impact feature evaluation across 5-min short-term window
        for domain in rw.domains:
            parts = domain.split(".")
            sublabel = parts[0]
            sublabel_len = len(sublabel)
            if sublabel_len > max_label_len:
                max_label_len = sublabel_len
                max_label_domain = domain

            # Calibrated DNS tunneling check (excludes Apple Push, CloudFront, Akamai, Amazon, Google, Microsoft hashes)
            if sublabel_len > 28 and entropy(sublabel) > 3.6 and not _is_cdn_or_cloud_domain(domain) and not is_telemetry_domain(domain):
                tunneling_domains += 1
                if len(tunneling_domain_examples) < 3:
                    tunneling_domain_examples.append(domain)

            # Subdomain fanout: group by registrable parent, only when this domain is a
            # genuine subdomain of that parent (not the base domain itself queried bare),
            # and the parent isn't legitimate CDN/telemetry infrastructure.
            base = etld1(domain)
            if base and base != domain and not _is_cdn_or_cloud_domain(domain) and not is_telemetry_domain(domain):
                fanout_by_base[base].add(domain)

            sublabel_entropy = entropy(sublabel)
            entropy_sum += sublabel_entropy
            if sublabel_entropy > top_entropy_value:
                top_entropy_value = sublabel_entropy
                top_entropy_domain = domain
            # BUGFIX: suspicious_dga() itself only excludes CDN/cloud domains (see its own
            # docstring), not telemetry -- unlike tunneling_domains/fanout_by_base just
            # above, which already exclude both at this exact source. Without this, the
            # only telemetry protection for suspicious_domains was threat_signals.py's
            # device-wide `is_telemetry` gate keyed on an unrelated "most notable domain in
            # the window" -- which both false-positived (a non-telemetry domain suppressed
            # because some OTHER domain in the window was telemetry) and, worse,
            # false-negatived (a genuinely suspicious domain silently never counted at all
            # whenever the device's top_domain happened to be telemetry-recognized).
            if suspicious_dga(domain) and not is_telemetry_domain(domain):
                suspicious += 1
                # BUGFIX (found via a production alerts.json audit): this loop already
                # checks each domain individually, but only ever counted the total -- the
                # SAME class of gap as tunneling_domains/tunneling_domain_examples just
                # above, for DGA_BOTNET_C2's underlying dns_dga_burst evidence instead of
                # dns_tunnel_v2's. Without this, DGA_BOTNET_C2 alerts had NO real domain to
                # attach to Evidence.domain at all -- the displayed "target" was always the
                # generic "most frequent domain in window" fallback, no causal connection
                # to which domain(s) actually looked DGA-like. Confirmed in production:
                # the same displayed domain string showing wildly different
                # max_label_length across consecutive alerts, and the same domain family
                # spread across 6+ unrelated devices with zero threat-intel corroboration
                # -- both symptoms of this exact attribution gap, not necessarily evidence
                # of a real coordinated threat.
                if len(suspicious_domain_examples) < 3:
                    suspicious_domain_examples.append(domain)
            if len(parts) > 5:
                deep_domains += 1

            # High-abuse TLD detection
            if len(parts) >= 2 and parts[-1] in _SUSPICIOUS_TLDS:
                suspicious_tld_count += rw.domains[domain]

            t_list = list(rw.domain_timestamps.get(domain, []))
            weight = sum(decay_rate ** max(0.0, now - t) for t in t_list)
            decayed_weights[domain] = weight
            decayed_total += weight

            # Calibrated C2 Beaconing check (allow CV < 0.35 for unfamiliar non-telemetry domains)
            if len(t_list) >= 5 and domain not in state.seen_domains and not is_telemetry_domain(domain):
                deltas = [t_list[i] - t_list[i-1] for i in range(1, len(t_list))]
                mean_delta = sum(deltas) / len(deltas)
                if mean_delta > 0:
                    var_delta = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                    cv = math.sqrt(var_delta) / mean_delta
                    min_jitter_cv = min(min_jitter_cv, cv)
                    if cv < 0.35:
                        beaconing_c2_count += 1
                        if len(beaconing_c2_domains) < 3:
                            beaconing_c2_domains.append(domain)

        # 1-Hour Long-Term Periodicity Evaluation (Catches low-and-slow 5-30 min C2 beacons)
        long_domain_timestamps = defaultdict(list)
        nx_names_1h = set()
        for ev in rw.long_events:
            if len(ev) >= 4 and ev[3] in _TXT_NULL_QTYPES:
                txt_null_count += 1
            if ev[2] in NXDOMAIN:   # blocked queries are never NXDOMAIN, even when the block replied NXDOMAIN
                nx_names_1h.add(ev[1])
            long_domain_timestamps[ev[1]].append(ev[0])
        # A2 (2026-10-01): the TLD check used to split every event of the last hour, per device, per cycle (the
        # single hottest line in the engine's profile on .94). Same count, one rpartition per UNIQUE domain:
        # "has a dot and its last label is a suspicious TLD", once for each of its events.
        for ev_dom, ts_list in long_domain_timestamps.items():
            if "." in ev_dom and ev_dom.rpartition(".")[2] in _SUSPICIOUS_TLDS:
                suspicious_tld_count += len(ts_list)

        for domain, t_list in long_domain_timestamps.items():
            if len(t_list) >= 4 and domain not in state.seen_domains and not is_telemetry_domain(domain) and not _is_cdn_or_cloud_domain(domain):
                deltas = [t_list[i] - t_list[i-1] for i in range(1, len(t_list))]
                mean_delta = sum(deltas) / len(deltas)
                if mean_delta > 120.0:  # Beacons spaced 2 minutes or longer
                    var_delta = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                    cv = math.sqrt(var_delta) / mean_delta
                    if cv < 0.35:
                        beaconing_c2_1h += 1
                        if len(beaconing_c2_1h_domains) < 3:
                            beaconing_c2_1h_domains.append(domain)

        n_domains   = len(rw.domains)
        avg_entropy = entropy_sum / max(n_domains, 1)
        query_rate = n_events * 60.0 / window_seconds

        vals   = list(rw.domains.values())
        mean_v = sum(vals) / max(n_domains, 1)
        query_variance = sum((v - mean_v) ** 2 for v in vals) / max(n_domains, 1)

        top_domain_ratio = max(decayed_weights.values(), default=0.0) / max(decayed_total, 1e-9)
        # P2 FIX (third-party review, 2026-09-28): the domain actually DRIVING
        # top_domain_ratio (and therefore the device-wide query_rate burst
        # dns_behavior.py's dns_rate Evidence reports) was never tracked, only the
        # ratio itself -- dns_rate Evidence had no .domain to attach, so
        # AdvertisingBurstHypothesis's rep_vector.tier gate (see that class's own
        # BUGFIX comment) was structurally a no-op: rep_vector always describes
        # SOME destination, but dns_rate evidence never named one to compare it
        # against, so _effective_rep_tier() could never actually verify the
        # rep_vector was about the right destination. Same "real evidence-linked
        # domain instead of an unrelated fallback" fix already shipped for
        # top_entropy_domain/tunneling_domain_examples/suspicious_domain_examples
        # above, applied to the one remaining case that never got it.
        top_rate_domain = max(decayed_weights, key=decayed_weights.get, default="")
        new_domains = sum(1 for d in rw.domains if d not in state.seen_domains)

        subdomain_fanout_count = 0
        subdomain_fanout_domain = ""
        for base, children in fanout_by_base.items():
            if len(children) > subdomain_fanout_count:
                subdomain_fanout_count = len(children)
                subdomain_fanout_domain = base

        # VERSION 11 (P2, review #17 "parent-domain model"): average Shannon entropy
        # of the FIRST label across every child domain sharing the winning fanout
        # parent -- fanout COUNT alone can't distinguish "many meaningfully-named
        # subdomains" (a legitimate multi-tenant SaaS: customer1.app.com,
        # customer2.app.com, ...) from "many randomized/encoded chunks" (the actual
        # DNS-tunneling shape). CDN/telemetry parents are already excluded from
        # fanout_by_base entirely (see the loop above), so this strengthens
        # confidence for an already-non-CDN fanout case rather than replacing that
        # exclusion. threat_signals.py's dns_tunnel_v2 subdomain_fanout check reads
        # this to scale confidence, not just the raw count.
        fanout_label_entropy = 0.0
        if subdomain_fanout_domain:
            fanout_children = fanout_by_base[subdomain_fanout_domain]
            fanout_label_entropy = sum(entropy(c.split(".")[0]) for c in fanout_children) / max(len(fanout_children), 1)

        # W-04: read by detectors/dns_behavior.py (dns_unique_ratio) and threat_signals.py (dns_dga_burst classifier
        # branch) but never produced before. Novelty-gated, see the producer docstrings.
        unique_subdomain_ratio, unique_subdomain_ratio_domain = self._unique_subdomain_ratio(
            rw, fanout_by_base, subdomain_fanout_domain, fanout_label_entropy, getattr(state, "device_id", None))
        dga_score, dga_score_examples = self._dga_score(nx_names_1h, getattr(state, "device_id", None))

        nxdomain_tld_conc = 0.0
        nx_events = [ev[1] for ev in rw.events if ev[2] in NXDOMAIN]
        if len(nx_events) >= 5:
            tld_counts = Counter()
            for domain in nx_events:
                parts = domain.rsplit(".", 1)
                if len(parts) == 2:
                    tld_counts[parts[-1]] += 1
            if tld_counts:
                nxdomain_tld_conc = tld_counts.most_common(1)[0][1] / len(nx_events)

        extracted_features = {
            "query_rate": query_rate,
            "unique_domains": n_domains,
            "blocked_ratio": min(rw.blocked / max(n_events, 1), 1.0),
            "nxdomain_ratio": min(rw.nxdomain / max(n_events, 1), 1.0),
            "entropy_avg": avg_entropy,
            "suspicious_domains": suspicious,
            "suspicious_domain_examples": suspicious_domain_examples,
            "total": n_events,
            "query_variance": query_variance,
            "events_per_second": n_events / max(window_seconds, 1),
            "top_domain_ratio": top_domain_ratio,
            "top_rate_domain": top_rate_domain,
            "new_domains": new_domains,
            "deep_domains": deep_domains,
            "max_label_length": max_label_len,
            "max_label_domain": max_label_domain,
            "top_entropy_domain": top_entropy_domain,
            "dns_tunneling_domains": tunneling_domains,
            "dns_tunneling_domain_examples": tunneling_domain_examples,
            "dns_txt_null_ratio": min(txt_null_count / max(len(rw.long_events), 1), 1.0),
            "suspicious_tld_ratio": min(suspicious_tld_count / max(n_events, n_long_events, 1), 1.0),
            "nxdomain_tld_conc": nxdomain_tld_conc,
            "beaconing_c2_count": beaconing_c2_count,
            "beaconing_c2_1h": beaconing_c2_1h,
            "beaconing_c2_domains": beaconing_c2_domains,
            "beaconing_c2_1h_domains": beaconing_c2_1h_domains,
            "min_jitter_cv": min_jitter_cv if min_jitter_cv != 999.0 else 0.0,
            "subdomain_fanout_count": subdomain_fanout_count,
            "subdomain_fanout_domain": subdomain_fanout_domain,
            "fanout_label_entropy": fanout_label_entropy,
            "unique_subdomain_ratio": unique_subdomain_ratio,
            "unique_subdomain_ratio_domain": unique_subdomain_ratio_domain,
            "dga_score": dga_score,
            "dga_score_examples": dga_score_examples,
        }
        
        current_phase = self._determine_killchain_phase(state, extracted_features)
        # markov_anomaly compares current_phase against the LAST recorded phase, so it
        # must be computed BEFORE this cycle's phase is appended to history below.
        markov_anomaly = self._compute_markov_anomaly(state, current_phase)
        
        extracted_features["killchain_phase"] = current_phase
        extracted_features["markov_anomaly"] = markov_anomaly

        # BUGFIX (dead-code audit): state.killchain_history (a deque(maxlen=5)) was
        # initialized, persisted, and read every cycle by _compute_markov_anomaly() above,
        # but nothing anywhere ever appended to it -- so `history` there was always empty
        # and markov_anomaly was permanently 0.0 for every device since this feature was
        # introduced. Appending here, after the comparison above, so next cycle's
        # _compute_markov_anomaly() has real transition history to score against.
        state.killchain_history.append(current_phase)

        return extracted_features

    def _zero_features(self) -> dict:
        return {
            "query_rate": 0.0, "unique_domains": 0, "blocked_ratio": 0.0,
            "nxdomain_ratio": 0.0, "entropy_avg": 0.0, "suspicious_domains": 0,
            "suspicious_domain_examples": [],
            "total": 0, "query_variance": 0.0, "events_per_second": 0.0,
            "top_domain_ratio": 0.0, "top_rate_domain": "", "new_domains": 0, "deep_domains": 0,
            "max_label_length": 0, "max_label_domain": "", "top_entropy_domain": "", "dns_tunneling_domains": 0,
            "dns_tunneling_domain_examples": [], "nxdomain_tld_conc": 0.0,
            "dns_txt_null_ratio": 0.0, "suspicious_tld_ratio": 0.0,
            "beaconing_c2_count": 0, "beaconing_c2_1h": 0, "min_jitter_cv": 0.0,
            "beaconing_c2_domains": [], "beaconing_c2_1h_domains": [],
            "subdomain_fanout_count": 0, "subdomain_fanout_domain": "", "fanout_label_entropy": 0.0,
            "unique_subdomain_ratio": 0.0, "unique_subdomain_ratio_domain": "",
            "dga_score": 0.0, "dga_score_examples": [],
            "killchain_phase": "NORMAL", "markov_anomaly": 0.0
        }