"""
geoip.py - GeoIP City (+ optional ASN) lookups for Home IDS.

Cross-references IPs to resolve physical coordinates, country flags, 
and upstream infrastructure providers (Autonomous Systems).

RECENT FIXES:
- FIXED (NULL ISLAND MAP POLLUTION): Replaced numeric `"0"` / `"0.0"` coordinate defaults 
  with `"unknown"` sentinels when GeoIP data is missing. This prevents Grafana geomap panels 
  from clustering unresolvable lookup misses at 0, 0 in the Gulf of Guinea.
- FIXED (PERFORMANCE BOTTLENECK): Wrapped `socket.gethostbyaddr()` inside a `ThreadPoolExecutor` 
  with a strict 1.0s timeout and added an LRU cache (`@lru_cache`).

2026-10-01: iptoasn.com (public domain) is the shipped source -- see intelligence/iptoasn.py. MaxMind files are still
used when present (a customer or owner may supply their own; they give city/coordinates), otherwise iptoasn answers
country (the AS's registration country) and ASN/organization. Only the main engine downloads iptoasn
(run_updater=True); every other process just reads the file it maintains.
"""
import threading
import time
import geoip2.database
import geoip2.errors
import socket
import ipaddress
import logging
import concurrent.futures
from functools import lru_cache
from pathlib import Path
from typing import Optional

LOGGER = logging.getLogger("home_ids.geoip")


class GeoIPEngine:
    """Offline GeoIP: MaxMind files when supplied, otherwise the iptoasn table (see module docstring)."""
    def __init__(self, db_path, asn_db_path: str = "", iptoasn_path: Optional[str] = None,
                 iptoasn_enabled: Optional[bool] = None, run_updater: bool = False):
        try:
            self.reader = geoip2.database.Reader(db_path)
            LOGGER.info("GeoIP City database successfully loaded from %s", db_path)
        except Exception as exc:
            LOGGER.info("No MaxMind City database at %s (%s) -- using iptoasn for country/ASN.", db_path,
                        exc.__class__.__name__)
            self.reader = None

        self.asn_reader = None
        if asn_db_path:
            try:
                self.asn_reader = geoip2.database.Reader(asn_db_path)
                LOGGER.info("GeoIP ASN database loaded from %s", asn_db_path)
            except Exception as exc:
                LOGGER.warning("Could not open GeoIP ASN database: %s", exc)
                self.asn_reader = None

        # BUGFIX: found via a live audit -- 4 workers/1.0s was tight enough that a
        # reactive-capture burst's DNS-evasion audit (which reverse-DNS's every
        # unexplained IP across EVERY device seen in the burst, in one pass) could
        # genuinely saturate this pool: a ThreadPoolExecutor future that times out on
        # the CALLER side does not stop the underlying worker thread, which keeps
        # running (up to its own 1.0s socket timeout) and occupying a slot regardless
        # -- so a handful of near-simultaneous lookups could cascade into later ones
        # queueing behind busy workers and hitting the 1.05s ceiling before even
        # starting, independent of whether the destination's DNS server would have
        # answered promptly. Confirmed live: 4 different devices (a server and three
        # smart-home devices) all got flagged "no matching DNS lookup history" within
        # the same ~2-minute window, right after a reactive-capture burst -- the
        # signature of a shared-resource bottleneck, not four coincidentally-evasive
        # devices. dns_evasion.py's _reverse_dns_explains() currently has no way to
        # tell "genuinely no PTR record" apart from "timed out under load" (both
        # collapse to a None return here) and treats either the same as unexplained,
        # so reducing spurious timeouts directly reduces false dns_evasion_anomaly
        # findings without touching that detector's own logic.
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=12, thread_name_prefix="rev-dns")

        # iptoasn (2026-10-01). Defaults come from config so every constructor in the codebase gets it.
        if iptoasn_path is None or iptoasn_enabled is None:
            try:
                from config import CONFIG
                if iptoasn_path is None:
                    iptoasn_path = CONFIG.get("geoip_iptoasn_path", "state/geoip/ip2asn-combined.tsv.gz")
                if iptoasn_enabled is None:
                    iptoasn_enabled = bool(CONFIG.get("geoip_iptoasn_enabled", True))
                refresh_days = float(CONFIG.get("geoip_iptoasn_refresh_days", 7))
            except Exception:
                refresh_days = 7.0
        else:
            refresh_days = 7.0
        self.iptoasn = None
        self.iptoasn_path = iptoasn_path or ""
        self._iptoasn_enabled = bool(iptoasn_enabled) and bool(self.iptoasn_path)
        if self._iptoasn_enabled and self.reader is not None and self.asn_reader is not None:
            # Both MaxMind files present: they answer every lookup, so the iptoasn table (38 MB, and a weekly
            # download) would never be used.
            LOGGER.info("MaxMind City + ASN files present -- iptoasn not loaded or downloaded.")
            self._iptoasn_enabled = False
        if self._iptoasn_enabled:
            threading.Thread(target=self._iptoasn_loop, args=(run_updater, refresh_days),
                             daemon=True, name="iptoasn").start()

    @property
    def source(self) -> str:
        """"maxmind", "iptoasn" or "none" -- what answers country/ASN lookups right now."""
        if self.reader is not None or self.asn_reader is not None:
            return "maxmind"
        return "iptoasn" if self.iptoasn is not None else "none"

    def _load_iptoasn(self, db=None) -> None:
        from intelligence.iptoasn import IpToAsnDB
        t0 = time.time()
        db = db if db is not None else IpToAsnDB.load(self.iptoasn_path)
        if db is None:
            return
        self.iptoasn = db
        self.lookup.cache_clear()
        self.lookup_asn.cache_clear()
        LOGGER.info("iptoasn table loaded: %d ranges in %.1f s%s.", db.rows, time.time() - t0,
                    "" if self.reader is None else " (MaxMind City present and preferred)")

    def _iptoasn_loop(self, run_updater: bool, refresh_days: float) -> None:
        from intelligence.iptoasn import IpToAsnUpdater
        self._load_iptoasn()
        updater = IpToAsnUpdater(self.iptoasn_path, refresh_days=refresh_days) if run_updater else None
        last_mtime = Path(self.iptoasn_path).stat().st_mtime if Path(self.iptoasn_path).exists() else 0.0
        while True:
            try:
                if updater is not None and updater.due():
                    fresh = updater.update()
                    if fresh is not None:
                        self._load_iptoasn(fresh)
                else:
                    # Readers in other processes pick up the engine's weekly refresh by file mtime.
                    p = Path(self.iptoasn_path)
                    mtime = p.stat().st_mtime if p.exists() else 0.0
                    if mtime and mtime != last_mtime:
                        self._load_iptoasn()
                if Path(self.iptoasn_path).exists():
                    last_mtime = Path(self.iptoasn_path).stat().st_mtime
            except Exception as exc:
                LOGGER.warning("iptoasn loop error: %s", exc)
            time.sleep(3600)

    # BUGFIX (live audit): unlike reverse_dns() below (already @lru_cache'd), these two
    # had no caching at all despite being pure functions of `ip` against a static,
    # in-process-lifetime-immutable MaxMind DB. Confirmed live: the same destination IP
    # gets looked up via lookup_asn() at least twice in one alert cycle (the reasoning-
    # trail asn_owner lookup, then again per-IP in the geofencing scan over the device's
    # whole destination set) with more callers being added (CDN/ASN-org exemption
    # checks) -- each a real, wasted DB re-read. Not a network call like reverse_dns
    # (no timeout risk), just redundant local work.
    @lru_cache(maxsize=4096)
    def lookup(self, ip):
        if not self.reader:
            hit = self.iptoasn.lookup(ip) if self.iptoasn is not None else None
            if hit is None:
                return None
            from intelligence.iptoasn import city_record
            return city_record(hit[1])
        try:
            res = self.reader.city(ip)
            LOGGER.debug("GeoIP City lookup successful for IP: %s", ip)
            return res
        except geoip2.errors.AddressNotFoundError:
            LOGGER.debug("GeoIP City address not found for IP: %s", ip)
            return None
        except Exception as exc:
            LOGGER.debug("GeoIP City lookup exception for %s: %s", ip, exc)
            return None

    @lru_cache(maxsize=4096)
    def lookup_asn(self, ip):
        if not self.asn_reader:
            hit = self.iptoasn.lookup(ip) if self.iptoasn is not None else None
            if hit is None:
                return None
            from intelligence.iptoasn import asn_record
            return asn_record(hit[0], hit[2])
        try:
            res = self.asn_reader.asn(ip)
            LOGGER.debug("GeoIP ASN lookup successful for IP: %s", ip)
            return res
        except geoip2.errors.AddressNotFoundError:
            LOGGER.debug("GeoIP ASN address not found for IP: %s", ip)
            return None
        except Exception as exc:
            LOGGER.debug("GeoIP ASN lookup exception for %s: %s", ip, exc)
            return None

    # BUGFIX (live audit, self-diagnosed in this class's own prior comment but never
    # fixed): a timeout and a genuine "no PTR record" both collapsed to the same `None`
    # return, so every caller (dns_evasion.py's _reverse_dns_explains()) treated a
    # lookup that simply got queued behind other work under load identically to one
    # that cleanly confirmed there's no record -- i.e. "inconclusive" silently became
    # "unexplained" (suspicious). Now returns a (host, timed_out) tuple so callers can
    # tell the two apart and skip evidence generation on a timeout instead of treating
    # it as a negative result. reverse_dns() below keeps the old host-only contract for
    # existing callers that don't need the distinction.
    @lru_cache(maxsize=2048)
    def _timed_reverse_dns_status(self, ip: str) -> "tuple[Optional[str], bool]":
        def _resolve():
            # Set socket timeout for the thread worker
            old_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(2.5)
                host, _, _ = socket.gethostbyaddr(ip)
                return host.lower().rstrip('.')
            finally:
                socket.setdefaulttimeout(old_timeout)

        future = self._executor.submit(_resolve)
        try:
            return future.result(timeout=2.6), False
        except concurrent.futures.TimeoutError:
            LOGGER.debug("Reverse DNS timeout (>2.5s) for IP: %s", ip)
            return None, True
        except socket.herror:
            LOGGER.debug("Reverse DNS host not found for IP: %s", ip)
            return None, False
        except Exception as exc:
            LOGGER.debug("Reverse DNS exception for %s: %s", ip, exc)
            return None, False

    def reverse_dns(self, ip):
        return self.reverse_dns_status(ip)[0]

    def reverse_dns_status(self, ip):
        """Same as reverse_dns(), but returns (host_or_None, timed_out) so a caller
        that needs to treat "inconclusive under load" differently from "confirmed no
        record" can do so -- see the BUGFIX comment on _timed_reverse_dns_status()."""
        try:
            parsed = ipaddress.ip_address(ip)
            if parsed.version in (4, 6):
                return self._timed_reverse_dns_status(ip)
        except ValueError:
            LOGGER.debug("Invalid IP address format for reverse DNS: %s", ip)
            return None, False
        return None, False

    def geo_labels(self, ip):
        """Constructs safe dictionaries for metric exports, preventing NoneType errors."""
        geo = self.lookup(ip)
        if not geo:
            LOGGER.debug("Returning default geo_labels (unknown) for IP: %s", ip)
            return {
                "country": "unknown",
                "city": "unknown",
                "continent": "unknown",
                "latitude": "unknown",
                "longitude": "unknown",
                "asn": "unknown",
                "org": "unknown"
            }
        
        lat = str(geo.location.latitude) if (hasattr(geo, "location") and geo.location.latitude is not None) else "unknown"
        lon = str(geo.location.longitude) if (hasattr(geo, "location") and geo.location.longitude is not None) else "unknown"

        asn_label = "unknown"
        org_label = "unknown"
        asn_record = self.lookup_asn(ip)
        if asn_record is not None:
            if asn_record.autonomous_system_number is not None:
                asn_label = f"AS{asn_record.autonomous_system_number}"
            org_label = asn_record.autonomous_system_organization or "unknown"
            
        return {
            "country": geo.country.iso_code or "unknown",
            "city": geo.city.name or "unknown",
            "continent": geo.continent.code or "unknown",
            "latitude": lat,
            "longitude": lon,
            "asn": asn_label,
            "org": org_label
        }