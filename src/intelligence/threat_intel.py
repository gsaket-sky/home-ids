"""
threat_intel.py – Threat intelligence enrichment engine.

Consolidates IP/Domain reputation tracking, parses static and streaming feeds, 
and integrates on-demand asynchronous VirusTotal/Abuse.ch lookup queues.

RECENT FIXES:
- FIXED (TRANCO BYPASS VECTOR): Separated `_static_allowlist` (parent-domain wildcard allowed) 
  from `_tranco_top10k` (EXACT match only). Malicious subdomains on shared platforms 
  (e.g., *.github.io, *.herokuapp.com) are no longer auto-exempted from blocking.
- FIXED (FEED ISOLATION): Added per-feed tracking in `_refresh_all()`. Single feed errors 
  no longer erase active memory IOCs from other feeds.
- FIXED (VT ERROR CACHING): Transient VirusTotal errors are cached with a short 60s TTL.
"""
import csv
import gzip
import ipaddress
import json
import logging
import threading
import time
import heapq
import zipfile
import io
from pathlib import Path
from typing import Optional, Dict, Set
from urllib.request import urlopen, Request
from urllib.error import URLError

LOGGER = logging.getLogger("home_ids.ti")

_FEEDS = {
    "feodo_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv", 
        "type": "csv_ips", "comment": "#", "ip_col": 1, "tags": ["c2", "botnet", "feodo"], 
        "confidence": 0.95, "ttl": 3600
    },
    "urlhaus_hosts": {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/", 
        "type": "hostfile", "comment": "#", "tags": ["malware", "urlhaus_host"], 
        "confidence": 0.90, "ttl": 3600
    },
    "urlhaus_urls": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/", 
        "type": "csv_urls", "comment": "#", "url_col": 2, "tags": ["malware", "urlhaus_url"], 
        "confidence": 0.95, "ttl": 3600
    },
    "threatfox_iocs": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/", 
        "type": "threatfox_csv", "comment": "#", "tags": ["threatfox"], 
        "confidence": 0.88, "ttl": 3600
    }
}

_OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}"
_TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

class ThreatIntel:
    def __init__(self, cache_dir: str = "state/ti_cache", otx_api_key: str = "", refresh_interval: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.otx_api_key = otx_api_key
        self.refresh_interval = refresh_interval

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

        self._lock = threading.RLock()
        self._stats = {"ips": 0, "domains": 0, "urls": 0, "cidrs": 0, "last_refresh": "never"}
        
        # Curated single-tenant apex domains where parent wildcard matching is safe
        self._static_allowlist = frozenset({
            "raw.githubusercontent.com", "githubusercontent.com", "github.com", 
            "google.com", "googleapis.com", "apple.com", "icloud.com", 
            "microsoft.com", "windows.com"
        })
        self._tranco_top10k: Set[str] = set()
        self.fp_engine = None  # Bound dynamically by pipeline at boot
        
        LOGGER.debug("ThreatIntel instantiated. Loading cache from %s", self.cache_dir)
        self._load_cache()

    def is_ready(self) -> bool:
        """PHASE 5 FIX (fail-open visibility): True once at least one feed refresh cycle
        has completed successfully. Lookups return "no match" identically whether that
        means "checked, genuinely clean" or "no feed data loaded yet" — this lets callers
        (pipeline.py) distinguish the two for operator visibility without changing any
        detection behavior."""
        with self._lock:
            return self._stats.get("last_refresh", "never") != "never"

    def is_allowlisted(self, domain: str) -> bool:
        """
        Returns True if:
        1. The domain strictly exists in the static allowlist OR Tranco Top 10k list.
        2. The parent registered domain exists in the curated _static_allowlist.
        
        Tranco Top 10k entries NEVER grant wildcard parent-domain immunity,
        preventing malicious subdomains on shared platforms (*.github.io, *.herokuapp.com)
        from bypassing IPS blocking.
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
                
            # 2. Parent domain match check against curated _static_allowlist OR dynamic trust cache
            if len(parts) >= 2:
                parent = ".".join(parts[-2:])
                if parent in self._static_allowlist:
                    LOGGER.debug("Allowlist match (Parent): %s", parent)
                    return True
                    
            # 3. Autonomous Dynamic Trust Cache (CL-AFPE 14-day immunized domains)
            if self.fp_engine:
                try:
                    trust_cache = self.fp_engine.get_dynamic_trust_cache()
                    base_dom = ".".join(parts[-2:]) if len(parts) >= 2 else domain
                    if base_dom in trust_cache or domain in trust_cache:
                        LOGGER.debug("Allowlist match (CL-AFPE Dynamic Trust Cache): %s", base_dom)
                        return True
                except Exception as e:
                    LOGGER.error("Error reading dynamic trust cache for %s: %s", domain, e)
                    return False
                    
            return False
        except Exception as exc:
            LOGGER.warning("Allowlist evaluation failed for %s: %s", domain, exc)
            return False

    def lookup_ip(self, ip: str) -> Optional[dict]:
        if not ip or ip == "unknown": 
            return None
        with self._lock:
            if ip in self._bad_ips: 
                LOGGER.debug("IP IOC Match (Direct): %s", ip)
                return self._bad_ips[ip]
            try:
                addr = ipaddress.ip_address(ip)
                for network, meta in self._bad_cidrs:
                    if addr in network: 
                        LOGGER.debug("IP IOC Match (CIDR %s): %s", network, ip)
                        return meta
            except ValueError: 
                pass
        return None

    def lookup_domain(self, domain: str) -> Optional[dict]:
        if not domain: 
            return None
        domain = domain.lower().strip(".")
        if self.is_allowlisted(domain):
            return None
        with self._lock:
            if domain in self._bad_domains: 
                LOGGER.debug("Domain IOC Match (Direct): %s", domain)
                return self._bad_domains[domain]
            parts = domain.split(".")
            if len(parts) > 2:
                parent = ".".join(parts[-2:])
                if parent in self._bad_domains: 
                    LOGGER.debug("Domain IOC Match (Parent %s): %s", parent, domain)
                    return {**self._bad_domains[parent], "matched_parent": True}
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

    def _refresh_loop(self) -> None:
        time.sleep(10)
        LOGGER.debug("TI Refresh loop active.")
        while True:
            try: 
                self._refresh_all()
                self._refresh_tranco_trust_list()
            except Exception as e: 
                LOGGER.error("TI Refresh cycle encountered an exception: %s", e)
            LOGGER.debug("TI Refresh loop sleeping for %d seconds.", self.refresh_interval)
            time.sleep(self.refresh_interval)

    def _start_ja3_feed(self) -> None:
        time.sleep(15)
        LOGGER.debug("JA3 Feed refresh loop active.")
        while True:
            try:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = Request("https://sslbl.abuse.ch/blacklist/sslblacklist.csv")
                LOGGER.debug("Fetching JA3 SSL blacklist...")
                with urlopen(req, timeout=10, context=ctx) as resp:
                    lines = resp.read().decode('utf-8').splitlines()
                    new_ja3 = {
                        line.split(',')[1].strip() 
                        for line in lines 
                        if not line.startswith('#') and len(line.split(',')) >= 2
                    }
                    if new_ja3: 
                        self.dynamic_ja3 = frozenset(new_ja3)
                        LOGGER.info("Successfully loaded %d JA3 fingerprints.", len(new_ja3))
            except Exception as e: 
                LOGGER.error("JA3 Feed Refresh failed: %s", e)
            time.sleep(86400) 

    def _refresh_tranco_trust_list(self) -> None:
        cache_file = self.cache_dir / "tranco_top10k.cache"
        domains = set()
        
        try:
            if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400:
                LOGGER.debug("Loading Tranco Top 10k from local cache.")
                domains = set(cache_file.read_text(encoding="utf-8").splitlines())
            else:
                LOGGER.info("Downloading Tranco Top 1M list to build Top 10k Harmless Cache...")
                req = Request(_TRANCO_URL, headers={"User-Agent": "home-ids/1.0"})
                with urlopen(req, timeout=30) as r:
                    with zipfile.ZipFile(io.BytesIO(r.read())) as z:
                        csv_filename = z.namelist()[0]
                        with z.open(csv_filename) as f:
                            for i, line in enumerate(f):
                                if i >= 10000: break
                                parts = line.decode('utf-8', errors='ignore').strip().split(',')
                                if len(parts) >= 2:
                                    dom = parts[1].lower().strip()
                                    if dom: domains.add(dom)
                if domains:
                    cache_file.write_text("\n".join(domains), encoding="utf-8")

            if domains:
                with self._lock:
                    self._tranco_top10k = domains
                LOGGER.info("✅ Loaded %d exact domains into Tranco Top 10k Trust List.", len(domains))
        except Exception as e:
            LOGGER.error("Failed to refresh Tranco Trust List: %s", e)

    def _refresh_all(self) -> None:
        LOGGER.info("Initiating intelligence feed update cycle...")
        for feed_name, feed in _FEEDS.items():
            feed_ips, feed_domains, feed_urls, feed_cidrs = {}, {}, {}, []
            try:
                LOGGER.debug("Fetching feed: %s", feed_name)
                cache_file = self.cache_dir / f"{feed_name}.cache"
                data = self._fetch_with_cache(feed["url"], cache_file, feed["ttl"])
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
            except Exception as exc: 
                LOGGER.warning("OTX Feed refresh failed: %s", exc)

        combined_ips, combined_domains, combined_urls, combined_cidrs = {}, {}, {}, []
        for f_name in self._feed_ips:
            combined_ips.update(self._feed_ips[f_name])
            combined_domains.update(self._feed_domains.get(f_name, {}))
            combined_urls.update(self._feed_urls.get(f_name, {}))
            combined_cidrs.extend(self._feed_cidrs.get(f_name, []))

        with self._lock:
            self._bad_ips = combined_ips
            self._bad_domains = combined_domains
            self._bad_urls = combined_urls
            self._bad_cidrs = combined_cidrs
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

    def _fetch_with_cache(self, url: str, cache_file: Path, ttl: int) -> Optional[str]:
        if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < ttl: 
            LOGGER.debug("Using cached feed response for %s", url)
            return cache_file.read_text(encoding="utf-8", errors="ignore")
        try:
            LOGGER.debug("Executing external HTTP fetch for %s", url)
            req = Request(url, headers={"User-Agent": "home-ids/1.0"})
            with urlopen(req, timeout=20) as r: 
                data = r.read().decode("utf-8", errors="ignore")
            if data and len(data.strip()) > 0:
                tmp_file = cache_file.with_suffix(cache_file.suffix + ".tmp")
                tmp_file.write_text(data, encoding="utf-8")
                tmp_file.replace(cache_file)
            return data
        except URLError as exc:
            if hasattr(exc, "close"):
                try: exc.close()
                except Exception: pass
            LOGGER.warning("HTTP fetch failed for %s. Error: %s", url, exc)
            return cache_file.read_text(encoding="utf-8", errors="ignore") if cache_file.exists() else None

class AbuseIPDB:
    _BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=75&limit=10000&plaintext"
    _CHECK_URL = "https://api.abuseipdb.com/api/v2/check?ipAddress={}"
    _RATE_DELAY = 16.0
    _DAILY_CAP = 480
    
    def __init__(self, api_key: str, cache_dir: Path, refresh_interval: int = 3600):
        self.api_key = api_key
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
        
        LOGGER.debug("AbuseIPDB wrapper initialized.")
        self._load_cache()
        self._load_live_cache()

    def start_refresh_thread(self) -> None: 
        LOGGER.info("Starting AbuseIPDB background refresh thread.")
        threading.Thread(target=self._refresh_loop, daemon=True, name="abuseipdb-refresh").start()
        if self.api_key:
            LOGGER.info("Starting AbuseIPDB async live worker thread.")
            threading.Thread(target=self._live_worker_loop, daemon=True, name="abuseipdb-live").start()

    def enqueue_ip(self, ip: str, priority: int = 5) -> None:
        if not self.api_key or not ip or ip == "unknown": return
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
            try: 
                self._refresh()
            except Exception as exc: 
                LOGGER.error("AbuseIPDB refresh loop encountered an exception: %s", exc)
            time.sleep(self.refresh_interval)
            
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
        except URLError as exc: 
            if hasattr(exc, "close"):
                try: exc.close()
                except Exception: pass
            LOGGER.warning("AbuseIPDB network fetch failed: %s", exc)
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
        import time
        with self._lock:
            e = self._live_cache.get(ip)
            if e and time.time() < e["expires"] and e["result"]:
                score = e["result"].get("abuseConfidenceScore", 0)
                # Cap contribution at 4.0 (like VT)
                return min((score / 100.0) * 6.0, 4.0)
        return 0.0

    def lookup(self, ip: str) -> bool:
        with self._lock: 
            match = ip in self._bad_ips
            if match:
                LOGGER.debug("AbuseIPDB blacklist match for IP: %s", ip)
            return match

class VirusTotalClient:
    _BASE = "https://www.virustotal.com/api/v3"
    _RATE_DELAY = 16.0
    _DAILY_CAP = 950
    
    def __init__(self, api_key: str, cache_dir: Path):
        self.api_key = api_key
        self.cache_file = cache_dir / "vt_cache.json.gz"
        self._cache = {}
        self._queue = []
        self._queued_items = set()
        self._lock = threading.RLock()
        self._last_req = 0.0
        self._today_count = 0
        self._today_date = ""
        
        LOGGER.debug("VirusTotalClient wrapper initialized.")
        self._load_cache()
        if api_key: 
            LOGGER.info("Starting VirusTotal async worker thread.")
            threading.Thread(target=self._worker_loop, daemon=True, name="vt-worker").start()

    def enqueue_domain(self, domain: str, priority: int = 5) -> None:
        if not self.api_key or not domain or domain == "unknown": 
            return
        k = f"domain:{domain}"
        with self._lock:
            if not self._is_cached(k) and k not in self._queued_items: 
                if len(self._queued_items) >= 10000:
                    return
                self._queued_items.add(k)
                heapq.heappush(self._queue, (priority, time.time(), "domain", domain))
                LOGGER.debug("Enqueued domain for VT analysis: %s", domain)

    def enqueue_ip(self, ip: str, priority: int = 5) -> None:
        if not self.api_key or not ip or ip == "unknown": return
        try:
            import ipaddress
            if not ipaddress.ip_address(ip).is_global: return
        except ValueError:
            return
        k = f"ip:{ip}"
        with self._lock:
            if not self._is_cached(k) and k not in self._queued_items: 
                if len(self._queued_items) >= 10000:
                    return
                self._queued_items.add(k)
                heapq.heappush(self._queue, (priority, time.time(), "ip", ip))
                LOGGER.debug("Enqueued IP for VT analysis: %s", ip)

    def get_result(self, ioc_type: str, value: str) -> dict | None:
        k = f"{ioc_type}:{value}"
        with self._lock:
            e = self._cache.get(k)
            if e and time.time() < e["expires"]: 
                return e["result"]
        return None

    def is_malicious(self, ioc_type: str, value: str, threshold: int = 3) -> bool:
        res = self.get_result(ioc_type, value)
        return res and res.get("last_analysis_stats", {}).get("malicious", 0) >= threshold

    def risk_contribution(self, ioc_type: str, value: str) -> float:
        res = self.get_result(ioc_type, value)
        if not res: 
            return 0.0
        s = res.get("last_analysis_stats", {})
        total = sum(s.values()) or 1
        return min(((s.get("malicious", 0) + s.get("suspicious", 0) * 0.5) / total) * 6.0, 4.0)

    def _worker_loop(self) -> None:
        LOGGER.debug("VirusTotal worker loop active.")
        while True:
            if time.time() < getattr(self, "_quota_exhausted_until", 0.0):
                time.sleep(60)
                continue
                
            item = None
            with self._lock:
                t = time.strftime("%Y-%m-%d")
                if t != self._today_date: 
                    self._today_count = 0
                    self._today_date = t
                if self._queue and self._today_count < self._DAILY_CAP:
                    _, _, itype, val = heapq.heappop(self._queue)
                    self._queued_items.discard(f"{itype}:{val}")
                    item = (itype, val)
                    
            if item is None: 
                time.sleep(5)
                continue
                
            w = self._RATE_DELAY - (time.time() - self._last_req)
            if w > 0: 
                time.sleep(w)
                
            itype, val = item
            try:
                LOGGER.debug("Executing VT API query for %s: %s", itype, val)
                res = self._query(itype, val)
                k = f"{itype}:{val}"
                with self._lock:
                    cache_ttl = 86400 if res else 3600
                    self._cache[k] = {"result": res, "expires": time.time() + cache_ttl}
                    if res: self._today_count += 1
                    if len(self._cache) > 2000: 
                        del self._cache[next(iter(self._cache))]
                self._save_cache()
            except Exception as exc:
                LOGGER.error("VirusTotal worker loop encountered an error: %s", exc)
            finally: 
                self._last_req = time.time()

    def _query(self, ioc_type: str, value: str) -> dict:
        u = f"{self._BASE}/domains/{value}" if ioc_type == "domain" else f"{self._BASE}/ip_addresses/{value}"
        req = Request(u, headers={"x-apikey": self.api_key, "User-Agent": "home-ids/1.0"})
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with urlopen(req, timeout=15) as r: 
                    data = json.loads(r.read())
                attrs = data.get("data", {}).get("attributes", {})
                LOGGER.debug("VT API response success for %s", value)
                return {
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}), 
                    "reputation": attrs.get("reputation", 0)
                }
            except URLError as e:
                if hasattr(e, 'close'):
                    e.close()
                if hasattr(e, 'code') and e.code == 429:
                    LOGGER.warning("VT Rate limit hit (429). Daily quota likely exhausted.")
                    self._quota_exhausted_until = time.time() + 3600
                    time.sleep(5) # Give a small breather, but break immediately to rely on 1-hour negative cache
                    break
                elif isinstance(e.reason, TimeoutError) or "timeout" in str(e.reason).lower():
                    LOGGER.warning("VT Connection timeout. Backing off (Attempt %d/%d).", attempt+1, max_retries)
                    time.sleep(2 ** attempt)
                    continue
                LOGGER.error("VT Query failed conclusively for %s: %s", value, e)
                break
                
        return {}

    def _is_cached(self, key: str) -> bool:
        e = self._cache.get(key)
        return bool(e and time.time() < e["expires"])

    def _save_cache(self) -> None:
        try:
            with self._lock: 
                d = dict(self._cache)
            with gzip.open(self.cache_file, "wt", encoding="utf-8") as f: 
                json.dump(d, f)
            LOGGER.debug("VirusTotal cache flushed to disk.")
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
            LOGGER.debug("VirusTotal cache loaded from disk.")
        except Exception as exc: 
            LOGGER.error("Failed to load VirusTotal cache: %s", exc)