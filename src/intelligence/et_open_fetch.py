"""
Device-side updater for the ET Open (BSD) ruleset -> local IOC index. No API key, no account.

Publisher etiquette (verified 2026-09-29, rules.emergingthreats.net/OPEN_download_instructions.html):
ET Open is regenerated once a day (weekdays); download at most once a day; excessive requests get
HTTP 429 and a 30-minute cool-down; to check more often, poll the tiny version.txt first. This class
does exactly that: version.txt check -> download only when it changed -> jittered next-due time ->
exponential back-off on 429/errors. So many units sharing one publisher never hammer it.

Hands-off safety (there is no human watching a fleet):
  * a failed/invalid/shrunken download NEVER replaces the last good index (kept until it's replaced
    by something better) -- the device just keeps the old data and reports how old it is;
  * validation before swap: minimum size, and a shrink guard against a truncated/garbled file;
  * the swap is atomic (temp file + rename) so a crash can't leave a half-written index.

`http_get` is injectable so every path (304, 429, garbage, truncation) is unit-testable offline.
"""
from __future__ import annotations

import io
import json
import logging
import os
import random
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterator, Optional, Tuple

from intelligence.local_ioc_index import ParsedIOCs, load_index, parse_et_rules, save_index

LOGGER = logging.getLogger("home_ids.et_open")

VERSION_URL = "https://rules.emergingthreats.net/version.txt"
# Suricata-version-specific rulesets differ in keyword syntax; our parser reads both dns.query and
# dns_query, so any recent one works. Tried in order until one downloads.
RULES_URLS = (
    "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz",
    "https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz",
)
USER_AGENT = "IDS_Product-threat-intel/1.0"
MAX_DOWNLOAD_BYTES = 40 * 1024 * 1024  # the real archive is ~5.6 MB; refuse anything absurd

DAY = 86400.0
_BACKOFF_429_BASE = 1800.0      # publisher's own cool-down
_BACKOFF_ERROR_BASE = 900.0
_BACKOFF_CAP = 12 * 3600.0
_FORCE_ACCEPT_AFTER_REJECTS = 7  # a source that shrinks for a week has probably legitimately changed

HttpGet = Callable[[str, Dict[str, str], float], Tuple[int, Dict[str, str], bytes]]


def default_http_get(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, Dict[str, str], bytes]:
    """Plain urllib GET with certificate verification ON. Non-2xx codes are returned, not raised."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_DOWNLOAD_BYTES + 1)
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, b""


@dataclass
class UpdateResult:
    status: str                       # skipped | unchanged | updated | rejected | rate_limited | error
    detail: str = ""
    parsed: Optional[ParsedIOCs] = None
    meta: Optional[dict] = None


class ETOpenUpdater:
    STATE_FILE = "et_open_state.json"
    INDEX_FILE = "et_open_index.json.gz"

    def __init__(self, cache_dir, *, http_get: Optional[HttpGet] = None, now: Callable[[], float] = time.time,
                 rng: Optional[random.Random] = None, version_url: str = VERSION_URL,
                 rules_urls=RULES_URLS, min_interval: float = DAY, jitter_max: float = 3600.0,
                 min_ips: int = 5000, min_domains: int = 2000, shrink_floor: float = 0.6,
                 timeout: float = 60.0):
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.http_get = http_get or default_http_get
        self.now = now
        self.rng = rng or random.Random()
        self.version_url = version_url
        self.rules_urls = tuple(rules_urls)
        self.min_interval = min_interval
        self.jitter_max = jitter_max
        self.min_ips = min_ips
        self.min_domains = min_domains
        self.shrink_floor = shrink_floor
        self.timeout = timeout

    # ---- state -----------------------------------------------------------------------------
    @property
    def index_path(self) -> Path:
        return self.dir / self.INDEX_FILE

    def _state(self) -> dict:
        try:
            return json.loads((self.dir / self.STATE_FILE).read_text())
        except (OSError, ValueError):
            return {}

    def _save_state(self, st: dict) -> None:
        fd, tmp = tempfile.mkstemp(dir=str(self.dir), prefix=self.STATE_FILE + ".", suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(st, f)
        os.replace(tmp, self.dir / self.STATE_FILE)

    def load_current(self) -> Optional[Tuple[ParsedIOCs, dict]]:
        return load_index(self.index_path)

    def age_seconds(self) -> Optional[float]:
        """Seconds since the last SUCCESSFUL check (fresh download or confirmed unchanged), else None."""
        last = self._state().get("last_success")
        return None if last is None else max(0.0, self.now() - float(last))

    def due(self) -> bool:
        st = self._state()
        t = self.now()
        if t < float(st.get("next_allowed", 0)):
            return False
        if not self.index_path.exists():
            return True
        return t >= float(st.get("next_due", 0))

    # ---- update ----------------------------------------------------------------------------
    def update(self, force: bool = False) -> UpdateResult:
        st = self._state()
        t = self.now()
        if not force and not self.due():
            return UpdateResult("skipped", "not due yet")

        # 1) cheap change check
        try:
            code, _h, body = self.http_get(self.version_url, {}, 15.0)
        except Exception as exc:  # network down etc.
            return self._fail(st, t, f"version check failed: {exc}")
        if code == 429:
            return self._rate_limited(st, t)
        version = body.decode("utf-8", "replace").strip() if code == 200 else ""
        if code != 200 or not version:
            return self._fail(st, t, f"version check HTTP {code}")
        if version == st.get("version") and self.index_path.exists() and not force:
            self._succeed(st, t, version=version)
            return UpdateResult("unchanged", f"version {version} already installed")

        # 2) download the ruleset (first URL that works)
        data = None
        last_err = "no url"
        for url in self.rules_urls:
            headers = {"If-None-Match": st["etag"]} if st.get("etag") and self.index_path.exists() and not force else {}
            try:
                code, hdrs, body = self.http_get(url, headers, self.timeout)
            except Exception as exc:
                last_err = f"{url}: {exc}"
                continue
            if code == 429:
                return self._rate_limited(st, t)
            if code == 304:
                self._succeed(st, t, version=version)
                return UpdateResult("unchanged", "304 not modified")
            if code == 200 and body and len(body) <= MAX_DOWNLOAD_BYTES:
                data, etag = body, hdrs.get("etag", "")
                break
            last_err = f"{url}: HTTP {code} ({len(body)} bytes)"
        if data is None:
            return self._fail(st, t, f"download failed: {last_err}")

        # 3) parse + validate; never replace a good index with a bad one
        try:
            parsed = parse_et_rules(_iter_rule_lines(data))
        except Exception as exc:
            return self._reject(st, t, f"could not parse archive: {exc}")
        problem = self._validate(parsed)
        if problem:
            st["rejects"] = int(st.get("rejects", 0)) + 1
            if st["rejects"] < _FORCE_ACCEPT_AFTER_REJECTS or "shrank" not in problem:
                return self._reject(st, t, problem)
            LOGGER.warning("ET Open shrink guard tripped %d times in a row; accepting the new data (%s)",
                           st["rejects"], problem)

        meta = {"source_version": version, "fetched_at": t}
        save_index(parsed, self.index_path, source_version=version, fetched_at=t)
        st["etag"] = etag
        st["rejects"] = 0
        self._succeed(st, t, version=version)
        LOGGER.info("ET Open index updated to version %s: %s", version, parsed.counts())
        return UpdateResult("updated", f"version {version}", parsed=parsed, meta=meta)

    # ---- helpers ---------------------------------------------------------------------------
    def _validate(self, parsed: ParsedIOCs) -> str:
        ip_total = len(parsed.ips) + len(parsed.cidrs)
        if ip_total < self.min_ips or len(parsed.domains) < self.min_domains:
            return (f"too small to be the real ruleset ({ip_total} IPs/CIDRs, {len(parsed.domains)} domains; "
                    f"need >= {self.min_ips}/{self.min_domains})")
        prev = self.load_current()
        if prev:
            old = prev[0]
            old_total = len(old.ips) + len(old.cidrs) + len(old.domains)
            new_total = ip_total + len(parsed.domains)
            if old_total and new_total < old_total * self.shrink_floor:
                return f"shrank from {old_total} to {new_total} indicators (< {int(self.shrink_floor*100)}% of previous)"
        return ""

    def _succeed(self, st: dict, t: float, *, version: str) -> None:
        st.update({"version": version, "last_check": t, "last_success": t, "failures": 0,
                   "rate_limited": 0, "next_allowed": 0,
                   "next_due": t + self.min_interval + self.rng.uniform(0, self.jitter_max)})
        self._save_state(st)

    def _fail(self, st: dict, t: float, detail: str) -> UpdateResult:
        n = int(st.get("failures", 0)) + 1
        retry_at = t + min(_BACKOFF_CAP, _BACKOFF_ERROR_BASE * (2 ** (n - 1)))
        # next_due follows the back-off: a failure must be retried soon, not on tomorrow's schedule
        st.update({"failures": n, "last_check": t, "next_allowed": retry_at, "next_due": retry_at})
        self._save_state(st)
        LOGGER.warning("ET Open update failed (%d in a row): %s -- keeping the last good index", n, detail)
        return UpdateResult("error", detail)

    def _reject(self, st: dict, t: float, detail: str) -> UpdateResult:
        st.update({"last_check": t, "next_allowed": t + 3600.0, "next_due": t + 3600.0})
        self._save_state(st)
        LOGGER.error("ET Open download REJECTED (%s) -- keeping the last good index", detail)
        return UpdateResult("rejected", detail)

    def _rate_limited(self, st: dict, t: float) -> UpdateResult:
        n = int(st.get("rate_limited", 0)) + 1
        retry_at = t + min(_BACKOFF_CAP, _BACKOFF_429_BASE * (2 ** (n - 1)))
        st.update({"rate_limited": n, "last_check": t, "next_allowed": retry_at, "next_due": retry_at})
        self._save_state(st)
        LOGGER.warning("ET Open returned HTTP 429; backing off (attempt %d)", n)
        return UpdateResult("rate_limited", "HTTP 429")


def _iter_rule_lines(archive: bytes) -> Iterator[str]:
    """Yield every line of every *.rules file inside the .tar.gz, streaming (no full extraction)."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
        for member in tf:
            if member.isfile() and member.name.endswith(".rules"):
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                for raw in io.TextIOWrapper(fh, encoding="utf-8", errors="replace"):
                    yield raw
