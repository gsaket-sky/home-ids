"""
threat_intel.py – Threat intelligence enrichment engine.

Consolidates IP/Domain reputation tracking, parses static and streaming feeds, 
and (only when the hidden `advanced_keyed_feeds` switch is on) the personal-use keyed feeds.

RECENT FIXES:
- FIXED (TRANCO BYPASS VECTOR): Separated `_static_allowlist` (parent-domain wildcard allowed) 
  from `_tranco_top10k` (EXACT match only). Malicious subdomains on shared platforms 
  (e.g., *.github.io, *.herokuapp.com) are no longer auto-exempted from blocking.
- FIXED (FEED ISOLATION): Added per-feed tracking in `_refresh_all()`. Single feed errors 
  no longer erase active memory IOCs from other feeds.
- REMOVED (2026-09-29): VirusTotalClient -- VirusTotal's free terms forbid use in a commercial product.
"""
import csv
import gzip
import ipaddress
import json
import logging
import re
import threading
import time
import heapq
import zipfile
import io
import requests
from pathlib import Path
from typing import Optional, Dict, Set
from urllib.request import urlopen, Request
from urllib.error import URLError

from metrics import (pihole_gravity_queries_total, pihole_gravity_last_success_timestamp,
                     threat_intel_index_age_seconds, threat_intel_index_weight)
from intelligence import ti_staleness
from intelligence import ja3_provenance

from utils import etld1, etld1_strict
from intelligence import feed_health
from intelligence.intel_strength import is_strong_match
from intelligence.et_open_fetch import ETOpenUpdater
from core.heartbeat import HEARTBEATS

LOGGER = logging.getLogger("home_ids.ti")

_FEEDS = {
    "feodo_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv", 
        "type": "csv_ips", "comment": "#", "ip_col": 1, "tags": ["c2", "botnet", "feodo"], 
        "confidence": 0.95, "ttl": 3600
    },
    "urlhaus_hosts": {
        "keyed": True,
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/", 
        "type": "hostfile", "comment": "#", "tags": ["malware", "urlhaus_host"], 
        "confidence": 0.90, "ttl": 3600
    },
    "urlhaus_urls": {
        "keyed": True,
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/", 
        "type": "csv_urls", "comment": "#", "url_col": 2, "tags": ["malware", "urlhaus_url"], 
        "confidence": 0.95, "ttl": 3600
    },
    "threatfox_iocs": {
        "keyed": True,
        "url": "https://threatfox.abuse.ch/export/csv/recent/", 
        "type": "threatfox_csv", "comment": "#", "tags": ["threatfox"], 
        "confidence": 0.88, "ttl": 3600
    }
}

_OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}"
_TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
_SSLBL_JA3_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
_JA3_RE = re.compile(r"^[0-9a-f]{32}$")

_SSLBL_MAX_AGE_DAYS = 365


def _sslbl_listing_is_stale(last_seen: str, now: Optional[float] = None) -> bool:
    """True when an SSLBL row's last-seen date (YYYY-MM-DD) is older than _SSLBL_MAX_AGE_DAYS.
    An unparseable date is kept (fail towards detection, as before)."""
    try:
        seen = time.mktime(time.strptime(last_seen[:10], "%Y-%m-%d"))
    except (ValueError, TypeError):
        return False
    return ((now if now is not None else time.time()) - seen) > _SSLBL_MAX_AGE_DAYS * 86400


class ThreatIntel:
    def __init__(self, cache_dir: str = "state/ti_cache", otx_api_key: str = "", refresh_interval: int = 3600,
                 pihole_api_url: str = "", pihole_api_password: str = "", pihole_search_api_path: str = "/api/search",
                 et_open_enabled: bool = True, advanced_feeds: bool = False, tranco_enabled: bool = False,
                 abusech_auth_key: str = ""):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # Hidden advanced switch: OTX / URLhaus / ThreatFox need per-user keys and are free for
        # PERSONAL use only, so a shipped unit leaves them off (Feodo + the local ET index remain).
        self.advanced_feeds = bool(advanced_feeds)
        self.otx_api_key = otx_api_key if self.advanced_feeds else ""
        if self.advanced_feeds:
            LOGGER.warning("advanced_keyed_feeds is ON: OTX/URLhaus/ThreatFox/AbuseIPDB free tiers are for "
                           "personal, non-commercial use only. You are responsible for their terms.")
        self.refresh_interval = refresh_interval
        # BUGFIX (health manager, resource-pressure degradation): otx_api_key is a
        # _STATIC_KEYS entry (config.py) -- immune to the live config-override
        # channel -- so an in-process flag directly on this already-constructed
        # object is the only lever HealthManager has to pause TI enrichment under
        # memory pressure. Checked in _refresh_loop() below; never touches the
        # cache itself, so un-pausing just resumes normal refreshes.
        self.paused = False

        # PHASE (live audit): Pi-hole gravity/blocklist lookup -- your OWN Pi-hole
        # already maintains a regularly-updated ad/tracker classification (its gravity
        # list), reachable via the same v6 REST API (pihole_api_url/pihole_api_password)
        # ips.py already uses for block/unblock. Distinct endpoint (search, not
        # domains) since Pi-hole's search API is a different path from its
        # domain-management API. Pi-hole is a hard dependency of this project (both
        # this deployment and IDS_Product), not an optional/deployment-specific
        # integration -- unlike a raw gravity.db file mount, which would require
        # filesystem access to a separate host.
        self.pihole_api_url = pihole_api_url
        self.pihole_api_password = pihole_api_password
        self.pihole_search_api_path = pihole_search_api_path
        self._pihole_gravity_cache: Dict[str, tuple] = {}  # domain -> (is_gravity_match, cached_at_ts)
        self._pihole_gravity_cache_ttl = 21600.0  # 6h -- gravity itself refreshes ~daily on Pi-hole's own schedule
        self.session = requests.Session() if pihole_api_url else None

        # Per-feed storage to prevent a single feed error from wiping total memory
        self._feed_ips: Dict[str, Dict[str, dict]] = {}
        self._feed_domains: Dict[str, Dict[str, dict]] = {}
        self._feed_urls: Dict[str, Dict[str, dict]] = {}
        self._feed_cidrs: Dict[str, list] = {}

        self._bad_ips:     dict[str, dict] = {}   
        self._bad_domains: dict[str, dict] = {}   
        self._bad_urls:    dict[str, dict] = {}   
        self._bad_cidrs:   list[tuple]     = []   
        self.dynamic_ja3 = frozenset()
        # JA3 hashes per source; dynamic_ja3 is always their union.
        self._sslbl_ja3: frozenset = frozenset()
        self._et_ja3: frozenset = frozenset()
        # Local ET Open index (device-side fetch, no key/licence): see intelligence/et_open_fetch.py
        self.et_open_enabled = bool(et_open_enabled)
        self._et_updater: Optional[ETOpenUpdater] = ETOpenUpdater(self.cache_dir) if self.et_open_enabled else None
        self._et_factor_cache = (0.0, 1.0)   # (computed_at, factor)
        self._et_expired = False

        self._lock = threading.RLock()
        self._stats = {"ips": 0, "domains": 0, "urls": 0, "cidrs": 0, "last_refresh": "never"}
        
        # Curated single-tenant apex domains where parent wildcard matching is safe
        self._static_allowlist = frozenset({
            "raw.githubusercontent.com", "githubusercontent.com", "github.com", 
            "google.com", "googleapis.com", "apple.com", "icloud.com", 
            "microsoft.com", "windows.com"
        })
        self._tranco_top10k: Set[str] = set()
        self._tranco_ranks: Dict[str, int] = {}
        # Tranco is OFF by default (2026-10-01): one of its inputs is CC BY-NC, so it cannot ship. Its two jobs are
        # done by intelligence/local_popularity.py (bound by the pipeline as self.local_popularity).
        self.tranco_enabled = bool(tranco_enabled)
        # abuse.ch (URLhaus / ThreatFox) requires an Auth-Key on every download since 2025; it was never sent, so the
        # keyed feeds could not work even with advanced_keyed_feeds on (found 2026-10-02). Sent only to those feeds.
        self.abusech_auth_key = (abusech_auth_key or "").strip()
        self.local_popularity = None
        self.trust_cache_provider = None  # the CL-AFPE engine, bound by the pipeline at boot (get_dynamic_trust_cache())
        self._trust_cache_error_logged_at = 0.0  # rate-limits the is_allowlisted() cache-read error log
        self._refresh_listeners = []  # called after each feed refresh cycle (add_refresh_listener)
        
        LOGGER.debug("ThreatIntel instantiated. Loading cache from %s", self.cache_dir)
        self._load_cache()
        self._load_et_local()

    def is_ready(self) -> bool:
        """PHASE 5 FIX (fail-open visibility): True once at least one feed refresh cycle
        has completed successfully. Lookups return "no match" identically whether that
        means "checked, genuinely clean" or "no feed data loaded yet" — this lets callers
        (pipeline.py) distinguish the two for operator visibility without changing any
        detection behavior."""
        with self._lock:
            return self._stats.get("last_refresh", "never") != "never"

    def is_allowlisted(self, domain: str, trust_cache: Optional[set] = None) -> bool:
        """
        Returns True if:
        1. The domain strictly exists in the static allowlist OR Tranco Top 10k list.
        2. The parent registered domain exists in the curated _static_allowlist.
        
        Tranco Top 10k entries NEVER grant wildcard parent-domain immunity,
        preventing malicious subdomains on shared platforms (*.github.io, *.herokuapp.com)
        from bypassing IPS blocking.

        `trust_cache`: a snapshot of the dynamic trust cache to use instead of reading it from the provider. A bulk
        caller (the learning-period intel sweep) takes one snapshot per run rather than one database read per name.
        """
        try:
            if not domain:
                return False
            domain = domain.lower().strip(".")
            parts = domain.split(".")
            
            # 1. Exact match check against static allowlist OR Tranco top 10k
            if domain in self._static_allowlist or domain in self._tranco_top10k:
                LOGGER.debug("Allowlist match (Exact): %s", domain)
                return True

            # 1b. Learned on this network (replaces Tranco): established names, exact match only -- and never when the
            # name itself carries a direct, strong threat-list hit. A learned list can be poisoned (malware several
            # devices contact daily), so it may only shield a popular name from suffix matches and weak indicators.
            lp = self.local_popularity
            if lp is not None and lp.is_established(domain) and not self._strong_direct_ioc(domain):
                LOGGER.debug("Allowlist match (learned popularity): %s", domain)
                return True
                
            # 2. Parent domain match check against curated _static_allowlist OR dynamic trust cache
            if len(parts) >= 2:
                parent = ".".join(parts[-2:])
                if parent in self._static_allowlist:
                    LOGGER.debug("Allowlist match (Parent): %s", parent)
                    return True
                    
            # 3. Autonomous Dynamic Trust Cache (CL-AFPE 14-day immunized domains). Like 1b, a correction can be wrong
            # (an autonomous one, or a person's) and may only shield a name from suffix matches and weak indicators:
            # an activated feed's strong hit on the name, or on any name up to the trusted entry, takes priority.
            if self.trust_cache_provider or trust_cache is not None:
                try:
                    if trust_cache is None:
                        trust_cache = self.trust_cache_provider.get_dynamic_trust_cache()
                    # The same fail-closed base CL-AFPE immunizes (etld1_strict): a.example.co.uk -> example.co.uk.
                    # Without a public-suffix list it is "", and only the exact name can match.
                    base_dom = etld1_strict(domain)
                    trusted = domain if domain in trust_cache else (base_dom if base_dom and base_dom in trust_cache else "")
                    if trusted and not self._strong_ioc_up_to(domain, trusted):
                        LOGGER.debug("Allowlist match (CL-AFPE Dynamic Trust Cache): %s", trusted)
                        return True
                except Exception as e:
                    # Every static check above has already run and not matched, so this read failing cannot
                    # turn a static-list domain into a non-match. Log once a minute, not once per domain.
                    now = time.monotonic()
                    if now - self._trust_cache_error_logged_at >= 60.0:
                        self._trust_cache_error_logged_at = now
                        LOGGER.error("Error reading dynamic trust cache (last domain %s): %s", domain, e)
                    
            return False
        except Exception as exc:
            LOGGER.warning("Allowlist evaluation failed for %s: %s", domain, exc)
            return False

    def is_static_allowlisted(self, domain: str) -> bool:
        """Only the curated, shipped allowlist (and Tranco when switched on): the name or its last-two-label parent.
        Unlike is_allowlisted() it ignores learned popularity and the CL-AFPE trust cache, both of which can be wrong."""
        domain = (domain or "").lower().strip(".")
        if not domain:
            return False
        if domain in self._static_allowlist or domain in self._tranco_top10k:
            return True
        parts = domain.split(".")
        return len(parts) >= 2 and ".".join(parts[-2:]) in self._static_allowlist

    def is_pihole_gravity_domain(self, domain: str) -> Optional[bool]:
        """Queries YOUR OWN Pi-hole's REST API (v6 /api/search) for whether `domain`
        matches its gravity list (the downloaded ad/tracker blocklists Pi-hole already
        maintains and refreshes on its own schedule) or an explicit blocklist entry.

        This is the "regularly updated online source" for ad/telemetry domain
        classification -- not a new external dependency, since Pi-hole is already a
        hard requirement of this project (both this deployment and IDS_Product), and
        it's already actively curating exactly this classification for its own
        blocking purpose. Reuses the same pihole_api_url/pihole_api_password (v6 `sid`
        header) config keys ips.py's block/unblock calls already use.

        Returns True/False on a successful query, None if Pi-hole is unreachable/
        unconfigured/the query failed for any reason -- callers must treat None as
        "couldn't check," never as a negative result (same "don't let inconclusive
        collapse into unexplained/suspicious" principle as geoip.py's
        reverse_dns_status()).

        NEEDS LIVE VALIDATION: written against Pi-hole v6's documented REST API shape
        (GET /api/search/{domain}?partial=false, sid header auth) -- not exercised
        against a live Pi-hole instance in this session. Fails closed to None (safe:
        treated as "unknown," never as a false negative that would suppress real
        evidence) if the response shape doesn't match what's expected here.
        """
        if not self.pihole_api_url or not self.session:
            return None
        domain = (domain or "").lower().strip(".")
        if not domain:
            return None

        with self._lock:
            cached = self._pihole_gravity_cache.get(domain)
        if cached and (time.time() - cached[1]) < self._pihole_gravity_cache_ttl:
            pihole_gravity_queries_total.labels(outcome="cache_hit").inc()
            return cached[0]

        try:
            url = f"{self.pihole_api_url.rstrip('/')}{self.pihole_search_api_path}/{domain}"
            from mitigation import pihole_auth   # Pi-hole v6 needs a login, not a raw password header
            headers = pihole_auth.auth_headers(self.pihole_api_url, self.pihole_api_password, self.session)
            resp = self.session.get(url, params={"partial": "false"}, headers=headers, timeout=3.0)
            if resp.status_code != 200:
                LOGGER.debug("Pi-hole gravity search for %s returned HTTP %s", domain, resp.status_code)
                pihole_gravity_queries_total.labels(outcome="error").inc()
                return None
            data = resp.json()
            # v6 response shape: {"search": {"domains": [...], "gravity": [...]}, ...} --
            # a non-empty match in either list means Pi-hole itself already recognizes
            # this domain as ad/tracker/gravity-listed.
            search = data.get("search", {}) if isinstance(data, dict) else {}
            matched = bool(search.get("domains")) or bool(search.get("gravity"))
            with self._lock:
                self._pihole_gravity_cache[domain] = (matched, time.time())
            pihole_gravity_queries_total.labels(outcome="success").inc()
            pihole_gravity_last_success_timestamp.set(time.time())
            return matched
        except Exception as exc:
            LOGGER.debug("Pi-hole gravity search failed for %s: %s", domain, exc)
            pihole_gravity_queries_total.labels(outcome="error").inc()
            return None

    def lookup_ip(self, ip: str) -> Optional[dict]:
        if not ip or ip == "unknown": 
            return None
        with self._lock:
            if ip in self._bad_ips: 
                LOGGER.debug("IP IOC Match (Direct): %s", ip)
                return self._decayed(self._bad_ips[ip])
            try:
                addr = ipaddress.ip_address(ip)
                for network, meta in self._bad_cidrs:
                    if addr in network: 
                        LOGGER.debug("IP IOC Match (CIDR %s): %s", network, ip)
                        return self._decayed(meta)
            except ValueError: 
                pass
        return None

    def _strong_direct_ioc(self, domain: str) -> bool:
        """A threat-list entry for exactly this name that could confirm a threat on its own (confidence >= 0.5,
        i.e. risk >= 2.0 -- the false-positive engine's hard-stop bar)."""
        with self._lock:
            meta = self._bad_domains.get(domain)
        if not meta:
            return False
        hit = self._decayed(meta)
        return bool(hit) and is_strong_match(hit)

    def _strong_ioc_up_to(self, domain: str, trusted: str) -> bool:
        """_strong_direct_ioc() for `domain` and every parent name of it down to `trusted` (the trust-cache entry
        that matched, `domain` itself or its base domain). With no domain feed activated this is always False."""
        parts = domain.split(".")
        for i in range(0, max(1, len(parts) - len(trusted.split(".")) + 1)):
            if self._strong_direct_ioc(".".join(parts[i:])):
                return True
        return False

    def lookup_domain(self, domain: str, trust_cache: Optional[set] = None) -> Optional[dict]:
        if not domain: 
            return None
        domain = domain.lower().strip(".")
        if self.is_allowlisted(domain, trust_cache=trust_cache):
            return None
        with self._lock:
            if domain in self._bad_domains: 
                LOGGER.debug("Domain IOC Match (Direct): %s", domain)
                return self._decayed(self._bad_domains[domain])
            parts = domain.split(".")
            # Every label-suffix with >= 2 labels, most specific first (ET has 3+-label indicators).
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self._bad_domains:
                    LOGGER.debug("Domain IOC Match (Parent %s): %s", parent, domain)
                    hit = self._decayed(self._bad_domains[parent])
                    return None if hit is None else {**hit, "matched_parent": True}
        return None

    def lookup_url(self, url: str) -> Optional[dict]:
        if not url: 
            return None
        with self._lock: 
            match = self._bad_urls.get(url)
            if match:
                LOGGER.debug("URL IOC Match: %s", url)
            return match

    def check_domain(self, domain: str) -> bool: 
        return self.lookup_domain(domain) is not None

    def ioc_risk_score(self, domain: str = "", ip: str = "") -> float:
        score = 0.0
        domain_match = self.lookup_domain(domain) if domain else None
        ip_match = self.lookup_ip(ip) if ip else None
        if domain_match:
            score += domain_match.get("confidence", 0.8) * 4.0
        if ip_match:
            score += ip_match.get("confidence", 0.8) * 4.0
        final_score = min(score, 4.0)
        LOGGER.debug("IOC risk score evaluated for Domain: %s, IP: %s = %.2f", domain, ip, final_score)
        return final_score

    def start_refresh_thread(self) -> None:
        LOGGER.info("Starting ThreatIntel background refresh threads.")
        threading.Thread(target=self._refresh_loop, daemon=True, name="ti-refresh").start()
        threading.Thread(target=self._start_ja3_feed, daemon=True, name="ja3-refresh").start()

    def add_refresh_listener(self, fn) -> None:
        """`fn()` runs on the refresh thread after every feed refresh cycle that ran (not while paused). It must return
        quickly (hand real work to its own thread); an exception in it is logged and never stops the refresh loop."""
        self._refresh_listeners.append(fn)

    def _notify_refresh_listeners(self) -> None:
        for fn in list(self._refresh_listeners):
            try:
                fn()
            except Exception as e:
                LOGGER.warning("ThreatIntel refresh listener failed: %s", e)

    def _refresh_loop(self) -> None:
        time.sleep(10)
        LOGGER.debug("TI Refresh loop active.")
        while True:
            # BUGFIX (health manager, resource-pressure degradation): skip the actual
            # fetch when paused, but still beat the heartbeat below -- a paused-but-
            # alive thread is healthy, not stuck, and HealthManager needs to be able
            # to tell those two apart.
            if not self.paused:
                try:
                    self._refresh_all()
                    if self.tranco_enabled:
                        self._refresh_tranco_trust_list()
                except Exception as e:
                    LOGGER.error("TI Refresh cycle encountered an exception: %s", e)
                self._notify_refresh_listeners()
            HEARTBEATS.beat("ti_refresh", health_state="healthy")
            LOGGER.debug("TI Refresh loop sleeping for %d seconds.", self.refresh_interval)
            time.sleep(self.refresh_interval)

    def _start_ja3_feed(self) -> None:
        time.sleep(15)
        LOGGER.debug("JA3 Feed refresh loop active.")
        while True:
            try:
                # Default context: certificate + hostname verification ON.
                req = Request(_SSLBL_JA3_URL)
                LOGGER.debug("Fetching SSLBL JA3 fingerprints...")
                with urlopen(req, timeout=10) as resp:
                    lines = resp.read().decode('utf-8').splitlines()
                new_ja3 = set()
                labels = {}
                for line in lines:
                    if not line or line.startswith('#'):
                        continue
                    cols = [c.strip() for c in line.split(',')]
                    h = cols[0].lower()
                    if _JA3_RE.match(h):
                        # columns: ja3_md5, Firstseen, Lastseen, Listingreason
                        reason = cols[3] if len(cols) > 3 and cols[3] else "unspecified"
                        seen = cols[2][:10] if len(cols) > 2 and cols[2] else "?"
                        # B4: listings are never removed upstream; a hash last seen years ago is a retired
                        # tool (or a library everyone now shares), not current evidence.
                        if _sslbl_listing_is_stale(seen):
                            continue
                        new_ja3.add(h)
                        labels[h] = f"abuse.ch SSLBL listing '{reason}', last seen {seen}"
                if new_ja3:
                    ja3_provenance.set_source("sslbl", labels)
                    self._sslbl_ja3 = frozenset(new_ja3)
                    self._rebuild_ja3()
                    LOGGER.info("Successfully loaded %d SSLBL JA3 fingerprints.", len(new_ja3))
            except Exception as e: 
                LOGGER.error("JA3 Feed Refresh failed: %s", e)
            time.sleep(86400) 

    def _rebuild_ja3(self) -> None:
        self.dynamic_ja3 = self._sslbl_ja3 | (frozenset() if self._et_expired else self._et_ja3)

    def _et_factor(self) -> float:
        """Age-decay multiplier for ET Open hits (1.0 <=14 d, linear to 0.0 at 60 d); cached for 60 s."""
        now = time.time()
        at, f = self._et_factor_cache
        if now - at < 60.0:
            return f
        age = ti_staleness.read_age_seconds(self.cache_dir, now)
        f = ti_staleness.decay_factor(age)
        self._et_factor_cache = (now, f)
        if age is not None:
            threat_intel_index_age_seconds.labels(source="et_open").set(age)
        threat_intel_index_weight.labels(source="et_open").set(f)
        expired = f <= 0.0
        if expired != self._et_expired:
            self._et_expired = expired
            self._rebuild_ja3()
        return f

    def _decayed(self, meta: Optional[dict]) -> Optional[dict]:
        """Apply staleness decay to ET Open hits; other feeds are untouched."""
        if not meta or meta.get("source") != "et_open":
            return meta
        f = self._et_factor()
        if f >= 1.0:
            return meta
        if f <= 0.0:
            return None
        return {**meta, "confidence": meta.get("confidence", 0.8) * f, "decayed": True}

    def _apply_et_index(self, parsed) -> None:
        """Convert a ParsedIOCs into the per-feed dicts (meta shape matches the other feeds)."""
        ips = {ip: {**m, "malicious": True, "ip": ip} for ip, m in parsed.ips.items()}
        domains = {d: {**m, "malicious": True, "domain": d} for d, m in parsed.domains.items()}
        cidrs = []
        for net_str, m in parsed.cidrs:
            try:
                cidrs.append((ipaddress.ip_network(net_str, strict=False), {**m, "malicious": True, "cidr": net_str}))
            except ValueError:
                continue
        self._feed_ips["et_open"] = ips
        self._feed_domains["et_open"] = domains
        self._feed_urls["et_open"] = {}
        self._feed_cidrs["et_open"] = cidrs
        self._et_ja3 = frozenset(h.lower() for h in parsed.ja3)
        ja3_provenance.set_source("et_open", {
            h: (f"ET Open rule sid {m.get('sid')}" if isinstance(m, dict) and m.get("sid") else "ET Open rule")
            for h, m in parsed.ja3.items()})
        self._rebuild_ja3()

    def _load_et_local(self) -> None:
        """Boot: load the last good ET index (independent of the 24 h combined-cache expiry)."""
        if not self._et_updater:
            return
        try:
            cur = self._et_updater.load_current()
            if not cur:
                return
            self._apply_et_index(cur[0])
            self._combine_feeds()
            LOGGER.info("Loaded local ET Open index: %s", cur[0].counts())
        except Exception as exc:
            LOGGER.error("Failed to load local ET Open index: %s", exc)

    def _refresh_et_open(self) -> None:
        """Hourly hook; the updater gates itself to ~once a day (+jitter, back-off on errors)."""
        if not self._et_updater:
            return
        self._et_factor_cache = (0.0, 1.0)   # force a fresh age reading after this cycle
        try:
            res = self._et_updater.update()
            if res.status == "updated" and res.parsed is not None:
                self._apply_et_index(res.parsed)
                LOGGER.info("ET Open index updated: %s", res.parsed.counts())
            if res.status in ("updated", "unchanged"):
                feed_health.record_success("et_open")
            elif res.status in ("error", "rejected", "rate_limited"):
                feed_health.record_failure("et_open", res.detail or res.status, res.status)
        except Exception as exc:
            LOGGER.warning("ET Open refresh failed: %s", exc)
            feed_health.record_failure("et_open", str(exc), feed_health.classify_url_error(exc))
        self._et_factor()   # refresh age/weight gauges and JA3 expiry state

    def _combine_feeds(self) -> None:
        """Merge per-feed dicts into the lookup tables; on a clash the higher-confidence entry wins."""
        def merge(dst: dict, src: dict) -> None:
            for k, m in src.items():
                old = dst.get(k)
                if old is None or m.get("confidence", 0) >= old.get("confidence", 0):
                    dst[k] = m
        ips, domains, urls, cidrs = {}, {}, {}, []
        for f_name in self._feed_ips:
            merge(ips, self._feed_ips[f_name])
            merge(domains, self._feed_domains.get(f_name, {}))
            merge(urls, self._feed_urls.get(f_name, {}))
            cidrs.extend(self._feed_cidrs.get(f_name, []))
        with self._lock:
            self._bad_ips, self._bad_domains, self._bad_urls, self._bad_cidrs = ips, domains, urls, cidrs

    def _refresh_tranco_trust_list(self) -> None:
        cache_file = self.cache_dir / "tranco_top10k.cache"
        # BUGFIX: the CL-AFPE's Stage-2 LightGBM feature vector and
        # train_fp_classifier.py's training-time feature extraction both read
        # features["tranco_rank"] (Feature 0 of 11, f0_tranco_rank_norm) -- but nothing
        # anywhere ever WROTE that key, so it was permanently 0 for every alert, ever,
        # contributing zero information to the model. The full ranked 1M-row Tranco
        # list was already being downloaded here in full -- only the domain (parts[1])
        # was ever kept; the rank itself (parts[0]) was read and discarded on every
        # single line. Now also builds a rank cache file, same 24h refresh cadence as
        # the existing top-10k set, from the SAME download (no extra network cost).
        rank_cache_file = self.cache_dir / "tranco_ranks.cache"
        domains = set()
        ranks: Dict[str, int] = {}

        try:
            cache_fresh = (
                cache_file.exists() and rank_cache_file.exists()
                and (time.time() - cache_file.stat().st_mtime) < 86400
            )
            if cache_fresh:
                LOGGER.debug("Loading Tranco Top 10k + rank cache from local cache.")
                domains = set(cache_file.read_text(encoding="utf-8").splitlines())
                for line in rank_cache_file.read_text(encoding="utf-8").splitlines():
                    dom, _, rank_str = line.partition(",")
                    if dom and rank_str.isdigit():
                        ranks[dom] = int(rank_str)
            else:
                LOGGER.info("Downloading Tranco Top 1M list to build Top 10k Harmless Cache + full rank index...")
                req = Request(_TRANCO_URL, headers={"User-Agent": "home-ids/1.0"})
                with urlopen(req, timeout=30) as r:
                    with zipfile.ZipFile(io.BytesIO(r.read())) as z:
                        csv_filename = z.namelist()[0]
                        with z.open(csv_filename) as f:
                            for i, line in enumerate(f):
                                parts = line.decode('utf-8', errors='ignore').strip().split(',')
                                if len(parts) < 2:
                                    continue
                                dom = parts[1].lower().strip()
                                if not dom:
                                    continue
                                if i < 10000:
                                    domains.add(dom)
                                try:
                                    ranks[dom] = int(parts[0])
                                except ValueError:
                                    pass
                if domains:
                    cache_file.write_text("\n".join(domains), encoding="utf-8")
                if ranks:
                    rank_cache_file.write_text(
                        "\n".join(f"{dom},{rank}" for dom, rank in ranks.items()), encoding="utf-8"
                    )

            if domains:
                with self._lock:
                    self._tranco_top10k = domains
                LOGGER.info("✅ Loaded %d exact domains into Tranco Top 10k Trust List.", len(domains))
            if ranks:
                with self._lock:
                    self._tranco_ranks = ranks
                LOGGER.info("✅ Loaded %d domain ranks into the Tranco rank index.", len(ranks))
        except Exception as e:
            LOGGER.error("Failed to refresh Tranco Trust List: %s", e)

    def get_tranco_rank(self, domain: str) -> int:
        """Returns this domain's Tranco Top-1M rank (1 = most popular), or 0 if the
        domain isn't ranked at all -- matches the CL-AFPE's/train_fp_classifier.py's
        existing `tranco_rank > 0` convention for "unranked."

        BUGFIX: Tranco's list ranks registrable (eTLD+1) domains only -- e.g. "netflix.com",
        never "customerevents.netflix.com". A real DNS query is almost always for a specific
        subdomain, not the bare registrable domain, so an exact-match-only lookup here made
        this feature evaluate to 0 for effectively all real traffic -- confirmed live: 92/92
        alerts in the first production window after this feature shipped, including
        subdomains of Netflix/Amazon/Microsoft, all scored tranco_rank=0. Falls back to the
        eTLD+1 base domain (utils.etld1(), the same shared helper the CL-AFPE/local_intel.py
        already use) when the exact FQDN isn't ranked -- deliberately NOT applied to
        is_allowlisted()'s Tranco check above, which is a security-relevant trust decision
        where subdomain-of-a-trusted-base-domain is a real bypass risk; this is a continuous
        ML feature, where being generous about the match costs nothing."""
        if not domain:
            return 0
        domain = domain.lower().strip(".")
        if not self.tranco_enabled:
            lp = self.local_popularity
            return lp.get_rank(domain) if lp is not None else 0
        with self._lock:
            rank = self._tranco_ranks.get(domain, 0)
            if rank:
                return rank
            base = etld1(domain)
            if base and base != domain:
                return self._tranco_ranks.get(base, 0)
            return 0

    def _refresh_all(self) -> None:
        LOGGER.info("Initiating intelligence feed update cycle...")
        for feed_name, feed in _FEEDS.items():
            if feed.get("keyed") and not self.advanced_feeds:
                continue
            feed_ips, feed_domains, feed_urls, feed_cidrs = {}, {}, {}, []
            try:
                LOGGER.debug("Fetching feed: %s", feed_name)
                cache_file = self.cache_dir / f"{feed_name}.cache"
                data = self._fetch_with_cache(feed["url"], cache_file, feed["ttl"], feed_name=feed_name,
                                              auth_key=self.abusech_auth_key if feed.get("keyed") else "")
                if not data: 
                    LOGGER.debug("No data returned for feed %s", feed_name)
                    continue
                meta = {
                    "source": feed_name, 
                    "tags": feed["tags"], 
                    "confidence": feed["confidence"], 
                    "malicious": True
                }
                ftype = feed["type"]
                if ftype == "csv_ips":        
                    self._parse_ip_csv(data, feed, meta, feed_ips, feed_cidrs)
                elif ftype == "hostfile":     
                    self._parse_hostfile(data, feed, meta, feed_domains)
                elif ftype == "csv_urls":     
                    self._parse_csv_urls(data, feed, meta, feed_urls)
                elif ftype == "threatfox_csv": 
                    self._parse_threatfox(data, meta, feed_ips, feed_domains, feed_urls)

                if feed_ips or feed_domains or feed_urls or feed_cidrs:
                    self._feed_ips[feed_name] = feed_ips
                    self._feed_domains[feed_name] = feed_domains
                    self._feed_urls[feed_name] = feed_urls
                    self._feed_cidrs[feed_name] = feed_cidrs
                    LOGGER.debug("Successfully parsed feed '%s' (IPs: %d, Domains: %d, URLs: %d)", 
                                 feed_name, len(feed_ips), len(feed_domains), len(feed_urls))
                else:
                    LOGGER.warning("Feed '%s' parsed 0 IOCs; preserving prior cached state.", feed_name)
            except Exception as exc:
                LOGGER.error("Feed '%s' parsing failed; preserving prior cached state. Error: %s", feed_name, exc)

        if self.otx_api_key:
            try: 
                LOGGER.debug("Fetching AlienVault OTX pulses...")
                otx_ips, otx_domains = {}, {}
                self._fetch_otx(otx_ips, otx_domains)
                self._feed_ips["otx"] = otx_ips
                self._feed_domains["otx"] = otx_domains
                feed_health.record_success("otx")
            except Exception as exc: 
                LOGGER.warning("OTX Feed refresh failed: %s", exc)
                feed_health.record_failure("otx", str(exc), feed_health.classify_url_error(exc))

        self._refresh_et_open()
        self._combine_feeds()
        with self._lock:
            combined_ips, combined_domains = self._bad_ips, self._bad_domains
            combined_urls, combined_cidrs = self._bad_urls, self._bad_cidrs
        with self._lock:
            self._stats.update({
                "ips": len(combined_ips), 
                "domains": len(combined_domains), 
                "urls": len(combined_urls), 
                "cidrs": len(combined_cidrs), 
                "last_refresh": time.strftime("%Y-%m-%d %H:%M:%S")
            })
        self._save_cache(combined_ips, combined_domains, combined_urls, combined_cidrs)
        LOGGER.info("ThreatIntel update complete. Loaded %d IPs, %d Domains, %d URLs.", 
                    len(combined_ips), len(combined_domains), len(combined_urls))

    def _parse_ip_csv(self, data, feed, meta, ips, cidrs):
        for row in csv.reader(data.splitlines()):
            if not row or row[0].startswith(feed.get("comment", "#")): 
                continue
            try:
                raw = row[feed.get("ip_col", 0)].strip()
                if not raw: 
                    continue
                if "/" in raw: 
                    cidrs.append((ipaddress.ip_network(raw, strict=False), {**meta, "cidr": raw}))
                else:          
                    ipaddress.ip_address(raw)
                    ips[raw] = {**meta, "ip": raw}
            except (ValueError, IndexError): 
                pass

    def _parse_hostfile(self, data, feed, meta, domains):
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith(feed.get("comment", "#")): 
                continue
            dom = line.split()[-1].lower().strip(".")
            if dom and "." in dom and dom != "localhost": 
                domains[dom] = {**meta, "domain": dom}

    def _parse_csv_urls(self, data, feed, meta, urls):
        from urllib.parse import urlparse
        col = feed.get("url_col", 2)
        for row in csv.reader(data.splitlines()):
            if not row or row[0].startswith(feed.get("comment", "#")): 
                continue
            try:
                raw = row[col].strip().strip('"')
                if raw.startswith("http"):
                    p = urlparse(raw)
                    u = f"{p.hostname}{p.path}" + (f"?{p.query}" if p.query else "")
                    urls[u] = {**meta, "url": raw}
            except (ValueError, IndexError): 
                pass

    def _parse_threatfox(self, data, meta, ips, domains, urls):
        from urllib.parse import urlparse
        for row in csv.reader(data.splitlines(), skipinitialspace=True):
            if not row or row[0].startswith("#") or len(row) < 3: 
                continue
            try:
                ioc_type, ioc_value = row[3].strip().lower(), row[2].strip()
                try:
                    conf = float(row[9]) / 100 if len(row) > 9 and row[9].strip() else 0.8
                except ValueError:
                    conf = 0.8
                tags = [t.strip() for t in row[12].split(",")] if len(row) > 12 and row[12].strip() else []
                entry = {**meta, "confidence": conf, "tags": meta["tags"] + tags}
                
                if ioc_type in ("ip:port", "ip"):
                    ip = ioc_value.split(":")[0]
                    ipaddress.ip_address(ip)
                    ips[ip] = {**entry, "ip": ip}
                elif ioc_type in ("domain", "url"):
                    if ioc_type == "url" and ioc_value.startswith("http"):
                        p = urlparse(ioc_value)
                        u = f"{p.hostname}{p.path}" + (f"?{p.query}" if p.query else "")
                        urls[u] = {**entry, "url": ioc_value}
                    else:
                        d = (urlparse(ioc_value).hostname or ioc_value if ioc_value.startswith("http") else ioc_value).lower().strip(".")
                        if d and "." in d: 
                            domains[d] = {**entry, "domain": d}
            except Exception: 
                pass

    def _fetch_otx(self, ips, domains):
        from urllib.parse import urlparse
        since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - self.refresh_interval * 2))
        req = Request(_OTX_URL.format(since=since), headers={"X-OTX-API-KEY": self.otx_api_key, "User-Agent": "home-ids/1.0"})
        with urlopen(req, timeout=15) as r:
            for p in json.loads(r.read()).get("results", []):
                for ioc in p.get("indicators", []):
                    itype, val = ioc.get("type", ""), ioc.get("indicator", "").strip()
                    e = {"malicious": True, "source": "otx", "tags": p.get("tags", []), "confidence": 0.80, "pulse": p.get("name", "")}
                    if itype == "IPv4" and val:
                        try: 
                            ipaddress.ip_address(val)
                            ips[val] = {**e, "ip": val}
                        except ValueError: 
                            pass
                    elif itype in ("domain", "hostname", "URL") and val:
                        d = (urlparse(val).hostname or val if val.startswith("http") else val).lower().strip(".")
                        if d and "." in d: 
                            domains[d] = {**e, "domain": d}

    def _save_cache(self, ips, domains, urls, cidrs) -> None:
        try:
            payload = {
                "ips": ips, 
                "domains": domains, 
                "urls": urls, 
                "cidrs": [[str(n), m] for n, m in cidrs], 
                "saved": time.time()
            }
            with gzip.open(self.cache_dir / "combined.json.gz", "wt", encoding="utf-8") as f: 
                json.dump(payload, f)
            LOGGER.debug("Successfully saved ThreatIntel memory snapshot to disk.")
        except Exception as exc: 
            LOGGER.error("Failed to save ThreatIntel cache: %s", exc)

    def _load_cache(self) -> None:
        if not (self.cache_dir / "combined.json.gz").exists(): 
            LOGGER.debug("No existing ThreatIntel cache found.")
            return
        try:
            with gzip.open(self.cache_dir / "combined.json.gz", "rt", encoding="utf-8") as f: 
                payload = json.load(f)
            if time.time() - payload.get("saved", 0) > 86400: 
                LOGGER.info("ThreatIntel cache expired. Discarding old records.")
                return
            
            cidrs = []
            for net_str, m in payload.get("cidrs", []):
                try: 
                    cidrs.append((ipaddress.ip_network(net_str, strict=False), m))
                except ValueError: 
                    pass
            with self._lock:
                self._bad_ips = payload.get("ips", {})
                self._bad_domains = payload.get("domains", {})
                self._bad_urls = payload.get("urls", {})
                self._bad_cidrs = cidrs
            LOGGER.info("Successfully restored ThreatIntel cache from disk.")
        except Exception as exc: 
            LOGGER.error("Failed to load ThreatIntel cache: %s", exc)

    def _fetch_with_cache(self, url: str, cache_file: Path, ttl: int, feed_name: str = "",
                          auth_key: str = "") -> Optional[str]:
        if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < ttl: 
            LOGGER.debug("Using cached feed response for %s", url)
            return cache_file.read_text(encoding="utf-8", errors="ignore")
        try:
            LOGGER.debug("Executing external HTTP fetch for %s", url)
            headers = {"User-Agent": "home-ids/1.0"}
            if auth_key:
                headers["Auth-Key"] = auth_key
            req = Request(url, headers=headers)
            with urlopen(req, timeout=20) as r: 
                data = r.read().decode("utf-8", errors="ignore")
            if data and len(data.strip()) > 0:
                tmp_file = cache_file.with_suffix(cache_file.suffix + ".tmp")
                tmp_file.write_text(data, encoding="utf-8")
                tmp_file.replace(cache_file)
            if feed_name:
                feed_health.record_success(feed_name)
            return data
        except URLError as exc:
            if hasattr(exc, "close"):
                try: exc.close()
                except Exception: pass
            LOGGER.warning("HTTP fetch failed for %s. Error: %s", url, exc)
            if feed_name:
                feed_health.record_failure(feed_name, str(exc), feed_health.classify_url_error(exc))
            return cache_file.read_text(encoding="utf-8", errors="ignore") if cache_file.exists() else None

class AbuseIPDB:
    _BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=75&limit=10000&plaintext"
    _CHECK_URL = "https://api.abuseipdb.com/api/v2/check?ipAddress={}"
    _RATE_DELAY = 16.0
    _DAILY_CAP = 480
    
    def __init__(self, api_key: str, cache_dir: Path, refresh_interval: int = 3600, enabled_fn=None):
        self.api_key = api_key
        # 2026-10-01 (owner decision): AbuseIPDB stays implemented for a later paid/opt-in tier but is OFF by
        # default -- its free plan forbids commercial use. `enabled_fn` is read on every use (the web UI's
        # advanced-settings toggle is a live config override), so switching it needs no restart; the API key
        # itself still does (static secret).
        self._enabled_fn = enabled_fn or (lambda: True)
        self.cache_file = cache_dir / "abuseipdb_blacklist.txt"
        self.live_cache_file = cache_dir / "abuseipdb_live.json.gz"
        self.refresh_interval = refresh_interval
        self._bad_ips = set()
        self._live_cache = {}
        self._queue = []
        self._queued_items = set()
        self._last_req = 0.0
        self._today_count = 0
        self._today_date = ""
        self._quota_exhausted_until = 0.0
        self._lock = threading.RLock()
        # BUGFIX (health manager, resource-pressure degradation): see ThreatIntel's
        # own self.paused comment above -- abuseipdb_api_key is also _STATIC_KEYS.
        self.paused = False

        LOGGER.debug("AbuseIPDB wrapper initialized.")
        self._load_cache()
        self._load_live_cache()

    def start_refresh_thread(self) -> None: 
        LOGGER.info("Starting AbuseIPDB background refresh thread.")
        threading.Thread(target=self._refresh_loop, daemon=True, name="abuseipdb-refresh").start()
        if self.api_key:
            LOGGER.info("Starting AbuseIPDB async live worker thread.")
            threading.Thread(target=self._live_worker_loop, daemon=True, name="abuseipdb-live").start()

    @property
    def active(self) -> bool:
        try:
            return bool(self.api_key) and not self.paused and bool(self._enabled_fn())
        except Exception:
            return False

    def enqueue_ip(self, ip: str, priority: int = 5) -> None:
        if not self.active or not ip or ip == "unknown": return
        try:
            if not ipaddress.ip_address(ip).is_global: return
        except ValueError:
            return
        with self._lock:
            if ip not in self._bad_ips and not self._is_live_cached(ip) and ip not in self._queued_items:
                if len(self._queued_items) >= 10000:
                    return
                self._queued_items.add(ip)
                heapq.heappush(self._queue, (priority, time.time(), ip))
                LOGGER.debug("Enqueued IP for AbuseIPDB live analysis: %s", ip)
                
    def _is_live_cached(self, key: str) -> bool:
        e = self._live_cache.get(key)
        return bool(e and time.time() < e["expires"])

    def _save_live_cache(self) -> None:
        try:
            with self._lock: 
                d = dict(self._live_cache)
            import gzip, json
            tmp_file = self.live_cache_file.with_suffix(".gz.tmp")
            with gzip.open(tmp_file, "wt", encoding="utf-8") as f: 
                json.dump(d, f)
            tmp_file.replace(self.live_cache_file)
            LOGGER.debug("AbuseIPDB live cache flushed to disk atomically[cite: 16, 24].")
        except Exception as exc: 
            LOGGER.error("Failed to save AbuseIPDB live cache: %s[cite: 16, 24]", exc)

    def _load_live_cache(self) -> None:
        if not self.live_cache_file.exists(): 
            return
        try:
            import gzip, json
            with gzip.open(self.live_cache_file, "rt", encoding="utf-8") as f: 
                data = json.load(f)
            now = time.time()
            with self._lock: 
                self._live_cache = {k: v for k, v in data.items() if v.get("expires", 0) > now}
            LOGGER.debug("AbuseIPDB live cache loaded from disk.")
        except Exception as exc: 
            LOGGER.error("Failed to load AbuseIPDB live cache: %s", exc)

    def _live_worker_loop(self) -> None:
        LOGGER.debug("AbuseIPDB live worker loop active.")
        while True:
            import time
            if time.time() < self._quota_exhausted_until:
                time.sleep(60)
                continue
                
            item = None
            with self._lock:
                t = time.strftime("%Y-%m-%d")
                if t != self._today_date: 
                    self._today_count = 0
                    self._today_date = t
                if self._queue and self._today_count < self._DAILY_CAP:
                    import heapq
                    _, _, val = heapq.heappop(self._queue)
                    self._queued_items.discard(val)
                    item = val
                    
            if item is None: 
                time.sleep(5)
                continue
                
            w = self._RATE_DELAY - (time.time() - self._last_req)
            if w > 0: 
                time.sleep(w)
                
            try:
                LOGGER.debug("Executing AbuseIPDB live API query for IP: %s", item)
                res = self._live_query(item)
                with self._lock:
                    cache_ttl = 86400 if res else 3600
                    self._live_cache[item] = {"result": res, "expires": time.time() + cache_ttl}
                    if res is not None: 
                        self._today_count += 1
                    if len(self._live_cache) > 2000: 
                        del self._live_cache[next(iter(self._live_cache))]
                self._save_live_cache()
            except Exception as exc:
                LOGGER.error("AbuseIPDB live worker loop encountered an error: %s", exc)
            finally: 
                self._last_req = time.time()

    def _live_query(self, ip: str) -> dict:
        u = self._CHECK_URL.format(ip)
        from urllib.request import Request, urlopen
        from urllib.error import URLError
        import json
        req = Request(u, headers={"Key": self.api_key, "Accept": "application/json", "User-Agent": "home-ids/1.0"})
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with urlopen(req, timeout=15) as r: 
                    data = json.loads(r.read())
                LOGGER.debug("AbuseIPDB API response success for %s", ip)
                return data.get("data", {})
            except URLError as e:
                import time
                if hasattr(e, 'close'):
                    e.close()
                if hasattr(e, 'code') and e.code == 429:
                    LOGGER.warning("AbuseIPDB Rate limit hit (429). Daily quota likely exhausted.")
                    self._quota_exhausted_until = time.time() + 3600
                    time.sleep(5)
                    break
                elif isinstance(e.reason, TimeoutError) or "timeout" in str(e.reason).lower():
                    LOGGER.warning("AbuseIPDB Connection timeout. Backing off (Attempt %d/%d).", attempt+1, max_retries)
                    time.sleep(2 ** attempt)
                    continue
                LOGGER.error("AbuseIPDB Query failed conclusively for %s: %s", ip, e)
                break
        return None
    
    def _refresh_loop(self) -> None:
        time.sleep(15)
        while True:
            if self.active:
                try:
                    self._refresh()
                except Exception as exc:
                    LOGGER.error("AbuseIPDB refresh loop encountered an exception: %s", exc)
                time.sleep(self.refresh_interval)
            else:
                # Switched off (the default): re-check the live toggle every minute, so turning it on in the web UI
                # fetches the blacklist promptly instead of after a full refresh interval.
                time.sleep(60)
            
    def _refresh(self) -> None:
        if not self.api_key: 
            return
        if self.cache_file.exists() and (time.time() - self.cache_file.stat().st_mtime) < self.refresh_interval: 
            self._load_cache()
            return
        try:
            LOGGER.debug("Fetching AbuseIPDB blacklist API...")
            req = Request(self._BLACKLIST_URL, headers={"Key": self.api_key, "Accept": "text/plain", "User-Agent": "home-ids/1.0"})
            with urlopen(req, timeout=30) as r: 
                data = r.read().decode("utf-8", errors="ignore")
            parsed_ips = self._parse_data(data)
            if parsed_ips:
                with self._lock:
                    self._bad_ips = parsed_ips
                tmp_file = self.cache_file.with_suffix(self.cache_file.suffix + ".tmp")
                tmp_file.write_text(data, encoding="utf-8")
                tmp_file.replace(self.cache_file)
                LOGGER.info("Successfully fetched and updated AbuseIPDB blacklist (%d IPs).", len(parsed_ips))
            else:
                LOGGER.warning("AbuseIPDB response yielded no valid IPs; preserving prior cache.")
            feed_health.record_success("abuseipdb")
        except URLError as exc: 
            if hasattr(exc, "close"):
                try: exc.close()
                except Exception: pass
            LOGGER.warning("AbuseIPDB network fetch failed: %s", exc)
            feed_health.record_failure("abuseipdb", str(exc), feed_health.classify_url_error(exc))
            self._load_cache()
            
    def _parse_data(self, data: str) -> set:
        new_ips = set()
        for line in data.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                try: 
                    ipaddress.ip_address(line)
                    new_ips.add(line)
                except ValueError: 
                    pass
        return new_ips

    def _parse(self, data: str) -> None:
        parsed_ips = self._parse_data(data)
        if parsed_ips:
            with self._lock: 
                self._bad_ips = parsed_ips
            
    def _load_cache(self) -> None:
        if self.cache_file.exists(): 
            try:
                self._parse(self.cache_file.read_text(encoding="utf-8", errors="ignore"))
                LOGGER.debug("Loaded AbuseIPDB cache from disk.")
            except Exception as exc:
                LOGGER.warning("Failed to load AbuseIPDB cache: %s", exc)
                
    def get_live_risk(self, ip: str) -> float:
        if not self.active:
            return 0.0
        import time
        with self._lock:
            e = self._live_cache.get(ip)
            if e and time.time() < e["expires"] and e["result"]:
                score = e["result"].get("abuseConfidenceScore", 0)
                # Cap contribution at 4.0 (like VT)
                return min((score / 100.0) * 6.0, 4.0)
        return 0.0

    def lookup(self, ip: str) -> bool:
        if not self.active:
            return False
        with self._lock: 
            match = ip in self._bad_ips
            if match:
                LOGGER.debug("AbuseIPDB blacklist match for IP: %s", ip)
            return match


class VirusTotalClient:
    """VirusTotal v3 IP/domain reputation, asynchronous and rate-limited.

    Removed 2026-09-29 (the free public API "must not be used in commercial products or services") and restored
    2026-10-01 at the owner's request, OFF by default, for a later paid/opt-in tier: a customer who brings their own
    key decides in the web UI's advanced settings. `enabled_fn` is read on every use, so the toggle is live; the key
    needs a restart. Free-tier limits are 4 requests/minute and 500/day -- hence the 16 s spacing and the daily cap
    with margin; a premium key could raise both (`rate_delay`, `daily_cap`)."""
    _BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, cache_dir: Path, enabled_fn=None, rate_delay: float = 16.0, daily_cap: int = 480):
        self.api_key = api_key
        self._enabled_fn = enabled_fn or (lambda: True)
        self._rate_delay = float(rate_delay)
        self._daily_cap = int(daily_cap)
        self.cache_file = Path(cache_dir) / "vt_cache.json.gz"
        self._cache = {}
        self._queue = []
        self._queued_items = set()
        self._lock = threading.RLock()
        self._last_req = 0.0
        self._today_count = 0
        self._today_date = ""
        self._quota_exhausted_until = 0.0
        # Health manager pauses enrichment under resource pressure (same flag as ThreatIntel/AbuseIPDB).
        self.paused = False
        self._load_cache()
        if api_key:
            threading.Thread(target=self._worker_loop, daemon=True, name="vt-worker").start()

    @property
    def active(self) -> bool:
        try:
            return bool(self.api_key) and not self.paused and bool(self._enabled_fn())
        except Exception:
            return False

    def enqueue_domain(self, domain: str, priority: int = 5) -> None:
        if not self.active or not domain or domain == "unknown":
            return
        self._enqueue("domain", domain, priority)

    def enqueue_ip(self, ip: str, priority: int = 5) -> None:
        if not self.active or not ip or ip == "unknown":
            return
        try:
            if not ipaddress.ip_address(ip).is_global:
                return
        except ValueError:
            return
        self._enqueue("ip", ip, priority)

    def _enqueue(self, ioc_type: str, value: str, priority: int) -> None:
        k = f"{ioc_type}:{value}"
        with self._lock:
            if self._is_cached(k) or k in self._queued_items or len(self._queued_items) >= 10000:
                return
            self._queued_items.add(k)
            heapq.heappush(self._queue, (priority, time.time(), ioc_type, value))

    def get_result(self, ioc_type: str, value: str):
        with self._lock:
            e = self._cache.get(f"{ioc_type}:{value}")
            if e and time.time() < e["expires"]:
                return e["result"]
        return None

    def risk_contribution(self, ioc_type: str, value: str) -> float:
        """0..4 on the same scale as the other reputation sources: the share of engines calling it malicious
        (suspicious counts half), x6, capped at 4."""
        if not self.active or not value:
            return 0.0
        res = self.get_result(ioc_type, value)
        if not res:
            return 0.0
        s = res.get("last_analysis_stats", {})
        total = sum(s.values()) or 1
        return min(((s.get("malicious", 0) + s.get("suspicious", 0) * 0.5) / total) * 6.0, 4.0)

    def _worker_loop(self) -> None:
        while True:
            if not self.active or time.time() < self._quota_exhausted_until:
                time.sleep(30)
                continue
            item = None
            with self._lock:
                today = time.strftime("%Y-%m-%d")
                if today != self._today_date:
                    self._today_count, self._today_date = 0, today
                if self._queue and self._today_count < self._daily_cap:
                    _, _, itype, val = heapq.heappop(self._queue)
                    self._queued_items.discard(f"{itype}:{val}")
                    item = (itype, val)
            if item is None:
                time.sleep(5)
                continue
            wait = self._rate_delay - (time.time() - self._last_req)
            if wait > 0:
                time.sleep(wait)
            itype, val = item
            try:
                res = self._query(itype, val)
                with self._lock:
                    self._cache[f"{itype}:{val}"] = {"result": res, "expires": time.time() + (86400 if res else 3600)}
                    if res:
                        self._today_count += 1
                    while len(self._cache) > 2000:
                        del self._cache[next(iter(self._cache))]
                self._save_cache()
            except Exception as exc:
                LOGGER.error("VirusTotal worker error: %s", exc)
            finally:
                self._last_req = time.time()

    def _query(self, ioc_type: str, value: str) -> dict:
        u = f"{self._BASE}/domains/{value}" if ioc_type == "domain" else f"{self._BASE}/ip_addresses/{value}"
        req = Request(u, headers={"x-apikey": self.api_key, "User-Agent": "home-ids/1.0"})
        last_exc = None
        for attempt in range(3):
            try:
                with urlopen(req, timeout=15) as r:
                    data = json.loads(r.read())
                attrs = data.get("data", {}).get("attributes", {})
                feed_health.record_success("virustotal")
                return {"last_analysis_stats": attrs.get("last_analysis_stats", {}),
                        "reputation": attrs.get("reputation", 0)}
            except URLError as e:
                if hasattr(e, "close"):
                    try:
                        e.close()
                    except Exception:
                        pass
                last_exc = e
                code = getattr(e, "code", None)
                if code == 404:
                    return {}  # VirusTotal has never seen it: a valid "no verdict", not a failure
                if code == 429:
                    LOGGER.warning("VirusTotal rate limit (429) -- pausing lookups for an hour.")
                    self._quota_exhausted_until = time.time() + 3600
                    break
                reason = str(getattr(e, "reason", ""))
                if isinstance(getattr(e, "reason", None), TimeoutError) or "timeout" in reason.lower():
                    time.sleep(2 ** attempt)
                    continue
                break
        if last_exc is not None:
            feed_health.record_failure("virustotal", str(last_exc), feed_health.classify_url_error(last_exc))
        return {}

    def _is_cached(self, key: str) -> bool:
        e = self._cache.get(key)
        return bool(e and time.time() < e["expires"])

    def _save_cache(self) -> None:
        try:
            with self._lock:
                d = dict(self._cache)
            tmp = self.cache_file.with_suffix(".gz.tmp")
            with gzip.open(tmp, "wt", encoding="utf-8") as f:
                json.dump(d, f)
            tmp.replace(self.cache_file)
        except Exception as exc:
            LOGGER.error("Failed to save VirusTotal cache: %s", exc)

    def _load_cache(self) -> None:
        if not self.cache_file.exists():
            return
        try:
            with gzip.open(self.cache_file, "rt", encoding="utf-8") as f:
                data = json.load(f)
            now = time.time()
            with self._lock:
                self._cache = {k: v for k, v in data.items() if v.get("expires", 0) > now}
        except Exception as exc:
            LOGGER.error("Failed to load VirusTotal cache: %s", exc)
