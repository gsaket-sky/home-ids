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
- FIXED (UNBOUND NXDOMAIN BLINDSPOT): Intelligently overrides `status=2` to `3` (NXDOMAIN) if an 
  external recursive resolver returned an NXDOMAIN (`reply_type=2`).
"""
import logging
import sqlite3
import time
import math
from collections import Counter, defaultdict

from utils import entropy, suspicious_dga, is_telemetry_domain, _is_cdn_or_cloud_domain, etld1
from config import CONFIG

LOGGER = logging.getLogger("home_ids.dns_features")

BLOCKED  = frozenset({1, 4, 5, 6, 7, 8, 10})
NXDOMAIN = frozenset({3, 12, 13})

_DEFAULT_DECAY_FACTOR = 0.995

# -------------------------------------------------------------------------
# MARKOV KILL-CHAIN MATRICES
# -------------------------------------------------------------------------
# VERSION 11 (P3, review #22): "RECON"/"C2"/"LATERAL"/"EXFIL" read as confirmed
# kill-chain stages to anyone seeing them on a dashboard, but they're purely
# heuristic feature-threshold guesses (see _determine_killchain_phase below) --
# nothing in decision_engine.py or hypotheses/engine.py ever reads this value, it's
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
                
            status = r[4]
            reply_type = r[5] if self._has_reply_type else 0
            
            if reply_type == 2:
                status = 3
                
            results.append({
                "timestamp": r[1],
                "domain": r[2],
                "client_ip": client_ip,
                "hostname": hostname,
                "status": status,
                "reply_type": reply_type
            })
            
        self.last_id = rows[-1][0]
        return results


class FeatureExtractor:
    
    def _determine_killchain_phase(self, state, features: dict) -> str:
        """Determines the current active kill-chain phase based on aggregated features."""
        outbound_bytes = features.get("zeek_outbound_bytes", 0)
        outbound_z = features.get("outbound_bytes_z", 0.0)
        if outbound_bytes > 50000000 or outbound_z > 3.0 or features.get("dns_tunneling_domains", 0) > 0 or features.get("dns_txt_null_ratio", 0.0) > 0.25:
            return "SUSPECTED_EXFIL"
        
        if features.get("beaconing_c2_count", 0) > 0 or features.get("beaconing_c2_1h", 0) > 0 or features.get("suspicious_domains", 0) > 5 or features.get("suspicious_tld_ratio", 0.0) > 0.20:
            return "SUSPECTED_C2"
            
        if features.get("zeek_lateral_moves", 0) > 0 or features.get("zeek_s0_rej_count", 0) > 20:
            return "SUSPECTED_LATERAL"
            
        if features.get("nxdomain_ratio", 0.0) > 0.4 or features.get("zeek_susp_ports", 0) > 0:
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
        min_jitter_cv = 999.0

        max_label_len = 0
        max_label_domain = ""
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

            entropy_sum += entropy(sublabel)
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

        # 1-Hour Long-Term Periodicity Evaluation (Catches low-and-slow 5-30 min C2 beacons)
        long_domain_timestamps = defaultdict(list)
        for ev in rw.long_events:
            ev_ts, ev_dom = ev[0], ev[1]
            parts = ev_dom.split(".")
            if len(parts) >= 2 and parts[-1] in _SUSPICIOUS_TLDS:
                suspicious_tld_count += 1
            if len(ev) >= 4 and ev[3] in _TXT_NULL_QTYPES:
                txt_null_count += 1
            long_domain_timestamps[ev_dom].append(ev_ts)

        for domain, t_list in long_domain_timestamps.items():
            if len(t_list) >= 4 and domain not in state.seen_domains and not is_telemetry_domain(domain) and not _is_cdn_or_cloud_domain(domain):
                deltas = [t_list[i] - t_list[i-1] for i in range(1, len(t_list))]
                mean_delta = sum(deltas) / len(deltas)
                if mean_delta > 120.0:  # Beacons spaced 2 minutes or longer
                    var_delta = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                    cv = math.sqrt(var_delta) / mean_delta
                    if cv < 0.35:
                        beaconing_c2_1h += 1

        n_domains   = len(rw.domains)
        avg_entropy = entropy_sum / max(n_domains, 1)
        query_rate = n_events * 60.0 / window_seconds

        vals   = list(rw.domains.values())
        mean_v = sum(vals) / max(n_domains, 1)
        query_variance = sum((v - mean_v) ** 2 for v in vals) / max(n_domains, 1)

        top_domain_ratio = max(decayed_weights.values(), default=0.0) / max(decayed_total, 1e-9)
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
            "new_domains": new_domains,
            "deep_domains": deep_domains,
            "max_label_length": max_label_len,
            "max_label_domain": max_label_domain,
            "dns_tunneling_domains": tunneling_domains,
            "dns_tunneling_domain_examples": tunneling_domain_examples,
            "dns_txt_null_ratio": min(txt_null_count / max(len(rw.long_events), 1), 1.0),
            "suspicious_tld_ratio": min(suspicious_tld_count / max(n_events, n_long_events, 1), 1.0),
            "nxdomain_tld_conc": nxdomain_tld_conc,
            "beaconing_c2_count": beaconing_c2_count,
            "beaconing_c2_1h": beaconing_c2_1h,
            "min_jitter_cv": min_jitter_cv if min_jitter_cv != 999.0 else 0.0,
            "subdomain_fanout_count": subdomain_fanout_count,
            "subdomain_fanout_domain": subdomain_fanout_domain,
            "fanout_label_entropy": fanout_label_entropy,
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
            "top_domain_ratio": 0.0, "new_domains": 0, "deep_domains": 0,
            "max_label_length": 0, "max_label_domain": "", "dns_tunneling_domains": 0,
            "dns_tunneling_domain_examples": [], "nxdomain_tld_conc": 0.0,
            "dns_txt_null_ratio": 0.0, "suspicious_tld_ratio": 0.0,
            "beaconing_c2_count": 0, "beaconing_c2_1h": 0, "min_jitter_cv": 0.0,
            "subdomain_fanout_count": 0, "subdomain_fanout_domain": "", "fanout_label_entropy": 0.0,
            "killchain_phase": "NORMAL", "markov_anomaly": 0.0
        }