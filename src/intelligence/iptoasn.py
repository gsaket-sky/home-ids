"""
iptoasn.py -- the shipped GeoIP source: iptoasn.com's IP-to-ASN table (public domain, PDDL 1.0: no key, no account,
no attribution required). Decided 2026-09-29 to replace MaxMind GeoLite2, whose licence needs a per-user key and
forbids redistributing the database (Documentation/internal/THREAT_INTEL_AND_GEOIP.md §6).

What it provides per address: AS number, the AS's *registration* country, and the AS description (iptoasn uses the
registry handle, e.g. "AMAZON-02", sometimes followed by the company name). No city or coordinates -- those stay
"unknown", which every caller already handles. A customer who wants city-level data can still upload their own
MaxMind files; GeoIPEngine prefers them when present.

Two parts:
  IpToAsnDB       -- in-memory lookup table built from ip2asn-combined.tsv.gz (IPv4 + IPv6 ranges, sorted).
                     "Not routed" rows (AS 0) are dropped. IPv4 lives in compact arrays; IPv6 in int lists.
  IpToAsnUpdater  -- weekly conditional download (ETag / Last-Modified), size and row-count sanity checks, atomic
                     swap; a failed or suspicious download never replaces the last good file.
"""
import bisect
import gzip
import json
import logging
import socket
import time
from array import array
from pathlib import Path
from typing import Optional, Tuple

LOGGER = logging.getLogger("home_ids.iptoasn")

SOURCE_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
_MIN_BYTES = 2_000_000          # the real file is ~9 MB; anything far smaller is an error page or truncated
_MIN_ROWS = 300_000             # ~580k routed ranges at the 2026-10 snapshot


def _v4_int(s: str) -> int:
    return int.from_bytes(socket.inet_aton(s), "big")


def _v6_int(s: str) -> int:
    return int.from_bytes(socket.inet_pton(socket.AF_INET6, s), "big")


class IpToAsnDB:
    def __init__(self):
        self._v4_start = array("I")
        self._v4_end = array("I")
        self._v4_org = array("I")
        self._v6_start: list = []
        self._v6_end: list = []
        self._v6_org = array("I")
        self._orgs: list = []          # index -> (asn, country, description)
        self.rows = 0

    @classmethod
    def load(cls, path) -> Optional["IpToAsnDB"]:
        """Streams the file straight into the arrays. iptoasn publishes it sorted by range start (IPv4 block, then
        IPv6); if a future file is not, the out-of-order family is sorted once at the end."""
        path = Path(path)
        if not path.exists():
            return None
        db = cls()
        org_index: dict = {}
        orgs = db._orgs
        v4s, v4e, v4o = db._v4_start, db._v4_end, db._v4_org
        v6s, v6e, v6o = db._v6_start, db._v6_end, db._v6_org
        inet_aton, inet_pton, AF6, from_bytes = socket.inet_aton, socket.inet_pton, socket.AF_INET6, int.from_bytes
        v4_sorted = v6_sorted = True
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t", 4)
                    if len(parts) < 5 or parts[2] == "0":
                        continue
                    key = (int(parts[2]), "" if parts[3] == "None" else parts[3], parts[4])
                    idx = org_index.get(key)
                    if idx is None:
                        idx = org_index[key] = len(orgs)
                        orgs.append(key)
                    try:
                        if ":" in parts[0]:
                            s_, e_ = from_bytes(inet_pton(AF6, parts[0]), "big"), from_bytes(inet_pton(AF6, parts[1]), "big")
                            if v6s and s_ < v6s[-1]:
                                v6_sorted = False
                            v6s.append(s_); v6e.append(e_); v6o.append(idx)
                        else:
                            s_, e_ = from_bytes(inet_aton(parts[0]), "big"), from_bytes(inet_aton(parts[1]), "big")
                            if v4s and s_ < v4s[-1]:
                                v4_sorted = False
                            v4s.append(s_); v4e.append(e_); v4o.append(idx)
                    except OSError:
                        continue
        except (OSError, EOFError, ValueError) as exc:
            LOGGER.warning("iptoasn: could not read %s: %s", path, exc)
            return None
        if not v4_sorted:
            rows = sorted(zip(v4s, v4e, v4o))
            db._v4_start, db._v4_end, db._v4_org = (array("I", (r[0] for r in rows)), array("I", (r[1] for r in rows)),
                                                    array("I", (r[2] for r in rows)))
        if not v6_sorted:
            rows = sorted(zip(v6s, v6e, v6o))
            db._v6_start, db._v6_end, db._v6_org = [r[0] for r in rows], [r[1] for r in rows], array("I", (r[2] for r in rows))
        db.rows = len(db._v4_start) + len(db._v6_start)
        return db

    def lookup(self, ip: str) -> Optional[Tuple[int, str, str]]:
        """(asn, registration country ISO code or "", AS description) or None."""
        try:
            if ":" in ip:
                x, starts, ends, orgs = _v6_int(ip), self._v6_start, self._v6_end, self._v6_org
            else:
                x, starts, ends, orgs = _v4_int(ip), self._v4_start, self._v4_end, self._v4_org
        except (OSError, TypeError, ValueError):
            return None
        i = bisect.bisect_right(starts, x) - 1
        if i < 0 or x > ends[i]:
            return None
        return self._orgs[orgs[i]]


# ---- geoip2-compatible records (the attributes GeoIPEngine's callers read) -----------------------------------

class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def city_record(country: str):
    return _Obj(country=_Obj(iso_code=country or None, name=None), city=_Obj(name=None),
                continent=_Obj(code=None), location=_Obj(latitude=None, longitude=None))


def asn_record(asn: int, org: str):
    return _Obj(autonomous_system_number=asn, autonomous_system_organization=org or None)


# ---- updater --------------------------------------------------------------------------------------------------

class IpToAsnUpdater:
    def __init__(self, path, refresh_days: float = 7.0, url: str = SOURCE_URL):
        self.path = Path(path)
        self.state_path = self.path.with_name(self.path.name + ".state.json")
        self.refresh_seconds = float(refresh_days) * 86400.0
        self.url = url

    def _state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_state(self, st: dict) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(st), encoding="utf-8")
        tmp.replace(self.state_path)

    def due(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        if not self.path.exists():
            return now >= float(self._state().get("retry_after", 0.0))
        return now >= float(self._state().get("next_due", 0.0))

    def update(self, session=None) -> Optional[IpToAsnDB]:
        """The newly installed table (already parsed -- the caller should use it rather than parse the file again;
        on .94 a parse inside the busy engine took minutes), or None when nothing changed or the download was bad.
        Never raises; never replaces the last good file with a bad one."""
        import requests
        st = self._state()
        headers = {"User-Agent": "home-ids/1.0 (+weekly)"}
        if self.path.exists():
            if st.get("etag"):
                headers["If-None-Match"] = st["etag"]
            if st.get("last_modified"):
                headers["If-Modified-Since"] = st["last_modified"]
        now = time.time()
        try:
            resp = (session or requests).get(self.url, headers=headers, timeout=120, stream=True)
            if resp.status_code == 304:
                st.update(next_due=now + self.refresh_seconds, last_check=now, failures=0)
                self._save_state(st)
                return None
            resp.raise_for_status()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".download")
            with open(tmp, "wb") as f:
                for chunk in resp.iter_content(1 << 16):
                    f.write(chunk)
            if tmp.stat().st_size < _MIN_BYTES:
                raise ValueError(f"download too small ({tmp.stat().st_size} bytes)")
            probe = IpToAsnDB.load(tmp)
            if probe is None or probe.rows < _MIN_ROWS:
                raise ValueError(f"download parsed to {probe.rows if probe else 0} ranges")
            tmp.replace(self.path)
            st.update(etag=resp.headers.get("ETag", ""), last_modified=resp.headers.get("Last-Modified", ""),
                      next_due=now + self.refresh_seconds, last_check=now, last_success=now, failures=0,
                      rows=probe.rows)
            self._save_state(st)
            LOGGER.info("iptoasn: installed a new IP-to-ASN table (%d ranges).", probe.rows)
            return probe
        except Exception as exc:
            failures = int(st.get("failures", 0)) + 1
            backoff = min(3600.0 * (2 ** (failures - 1)), 86400.0)
            st.update(failures=failures, last_check=now, last_error=str(exc)[:200], retry_after=now + backoff,
                      next_due=now + backoff)
            self._save_state(st)
            LOGGER.warning("iptoasn: update failed (%s); keeping the current table, retry in %.0f h.",
                           exc, backoff / 3600)
            try:
                self.path.with_suffix(".download").unlink()
            except OSError:
                pass
            return None
