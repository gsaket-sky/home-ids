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
"""
import geoip2.database
import geoip2.errors
import socket
import ipaddress
import logging
import concurrent.futures
from functools import lru_cache
from typing import Optional

LOGGER = logging.getLogger("home_ids.geoip")


class GeoIPEngine:
    """Manages offline MaxMind databases for high-speed resolution."""
    def __init__(self, db_path, asn_db_path: str = ""):
        try:
            self.reader = geoip2.database.Reader(db_path)
            LOGGER.info("GeoIP City database successfully loaded from %s", db_path)
        except Exception as exc:
            LOGGER.warning("Failed to load primary GeoIP City DB at %s: %s. GeoIP features will be disabled.", db_path, exc)
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

    def lookup(self, ip):
        if not self.reader:
            return None
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

    def lookup_asn(self, ip):
        if not self.asn_reader:
            return None
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

    @lru_cache(maxsize=2048)
    def _timed_reverse_dns(self, ip: str) -> Optional[str]:
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
            return future.result(timeout=2.6)
        except concurrent.futures.TimeoutError:
            LOGGER.debug("Reverse DNS timeout (>2.5s) for IP: %s", ip)
            return None
        except socket.herror:
            LOGGER.debug("Reverse DNS host not found for IP: %s", ip)
            return None
        except Exception as exc:
            LOGGER.debug("Reverse DNS exception for %s: %s", ip, exc)
            return None

    def reverse_dns(self, ip):
        try:
            parsed = ipaddress.ip_address(ip)
            if parsed.version in (4, 6):
                return self._timed_reverse_dns(ip)
        except ValueError:
            LOGGER.debug("Invalid IP address format for reverse DNS: %s", ip)
            return None
        return None

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