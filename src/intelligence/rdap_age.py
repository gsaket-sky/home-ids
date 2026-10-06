"""
rdap_age.py -- how old is a domain? Registration date from the official registry over RDAP (RFC 9083).

Why (MASTER_TODO M2, zero-day-infected device): a C2 domain is usually registered days before use, so its age separates
it from a device's ordinary, long-established names even while the device is still being learned. This module is only
the client: it answers "when was this registered" and enforces every limit. Deciding which names to look up, and what a
young domain changes, is the caller's job (part 2 of the build).

Owner decisions (2026-10-05, the safest option):
  - OFF unless the customer opts in (`rdap_domain_age_enabled`, offered at first setup). While off, nothing is sent to
    anyone and registration_ts() answers None, i.e. the product behaves as if this module did not exist.
  - Each lookup tells the domain's registry that this network asked about that name; nothing else is sent (a generic
    User-Agent, no identifiers). Only the name goes out.
  - Registries only, no third party (no Certificate-Transparency fallback).
  - gTLDs only: ICANN requires public RDAP of every gTLD registry (since 2025-01-28). A country-code TLD (two letters,
    or an `xn--` IDN one) is never queried: many have no RDAP, or publish no creation date (.de), and some registries'
    terms forbid commercial use of the data.
  - Never a local name (utils.is_local_name: the built-in suffixes plus `local_domain_suffixes`). Some home networks
    use a real gTLD as their local suffix (`.sky`, `fritz.box` under `.box`); without this check their own host names
    would be sent to that registry.

Limits (registries' terms forbid "high volume, automated" use without giving a number, so the ceiling is deliberately
low): at most one lookup per MIN_INTERVAL_SECONDS and DAILY_CAP per day for the whole unit; HTTP 429 backs that
registry off for its Retry-After (else BACKOFF_DEFAULT_SECONDS), per RFC 7480 section 5.5. Answers are kept in
SQLite (no JSON state files): a registration date for DATE_TTL_DAYS, "no date" for NO_DATA_TTL_DAYS, so a name is
asked about at most a few times a year. A stored date stays readable after DATE_TTL_DAYS (a registration date does
not change; only a re-registration would, which is what the TTL re-asks for): if it expired for reading, an old C2
domain would stop counting as young and become "normal" again. The registry list is IANA's bootstrap file, refreshed weekly and kept in the
same database; if it cannot be fetched the last copy is used, and with none, nothing is looked up.

Unknown is always "no signal": a failed, refused or undated lookup never makes a domain look young or old.
"""
import contextlib
import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from utils import is_local_name

LOGGER = logging.getLogger("home_ids.rdap_age")

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_REFRESH_SECONDS = 7 * 86400
MIN_INTERVAL_SECONDS = 10.0
DAILY_CAP = 50
DATE_TTL_DAYS = 180
NO_DATA_TTL_DAYS = 30
BACKOFF_DEFAULT_SECONDS = 3600.0
HTTP_TIMEOUT_SECONDS = 10.0
USER_AGENT = "Home-IDS"

# Outcomes of lookup()
CACHED, LOOKED_UP, DISABLED, NOT_GTLD, LOCAL, NO_SERVER, DAILY_LIMIT, TOO_SOON, BACKOFF, ERROR = (
    "cached", "looked_up", "disabled", "not_gtld", "local", "no_server", "daily_limit", "too_soon", "backoff", "error")

HttpGet = Callable[[str, Dict[str, str], float], Tuple[int, str, Dict[str, str]]]


def _default_http_get(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, str, Dict[str, str]]:
    import requests
    r = requests.get(url, headers=headers, timeout=timeout)
    return r.status_code, r.text, {k.lower(): v for k, v in r.headers.items()}


def normalize(name: str) -> str:
    return (name or "").lower().strip(".")


def is_gtld_name(name: str) -> bool:
    """True when the name's top-level domain is a generic one: not a two-letter country code, not an `xn--` IDN
    country code. A bare TLD or a name without a dot is not a lookup candidate."""
    name = normalize(name)
    if "." not in name:
        return False
    tld = name.rsplit(".", 1)[1]
    return bool(tld) and len(tld) != 2 and not tld.startswith("xn--")


def _day(ts: float) -> int:
    return int(ts // 86400)


def _parse_registration(body: str) -> Optional[float]:
    """The 'registration' event date of an RDAP domain object as epoch seconds, or None."""
    try:
        doc = json.loads(body)
    except (TypeError, ValueError):
        return None
    for ev in (doc.get("events") or []) if isinstance(doc, dict) else []:
        if isinstance(ev, dict) and ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                dt = datetime.fromisoformat(str(ev["eventDate"]).replace("Z", "+00:00"))
            except ValueError:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
    return None


class RdapAgeService:
    def __init__(self, db_path, enabled_fn: Callable[[], bool], http_get: Optional[HttpGet] = None,
                 now_fn: Callable[[], float] = time.time):
        """`enabled_fn()` is read on every call, so switching the setting takes effect at once."""
        self.db_path = Path(db_path)
        self.enabled_fn = enabled_fn
        self._http_get = http_get or _default_http_get
        self._now = now_fn
        self._lock = threading.Lock()
        self._last_lookup_at = 0.0
        self._bootstrap_cache: Optional[Dict[str, str]] = None   # tld -> RDAP base url
        self._memo: Dict[str, Tuple[Optional[float], float]] = {}  # name -> (registered, read_at): the novelty gate reads per query
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS answers (name TEXT PRIMARY KEY, registered REAL, checked_at REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS usage (day INTEGER PRIMARY KEY, count INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS backoff (server TEXT PRIMARY KEY, until REAL NOT NULL)")
            row = db.execute("SELECT value FROM meta WHERE key='last_lookup_at'").fetchone()
            if row:
                self._last_lookup_at = float(row[0])

    @contextlib.contextmanager
    def _connect(self):
        db = sqlite3.connect(str(self.db_path), timeout=10)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            with db:
                yield db
        finally:
            db.close()

    # --- reading answers ---------------------------------------------------------------------------------------------

    def enabled(self) -> bool:
        try:
            return bool(self.enabled_fn())
        except Exception:
            return False

    def _answer(self, name: str) -> Optional[Tuple[Optional[float], float]]:
        """(registered or None, checked_at) when a still-fresh answer is stored."""
        with self._connect() as db:
            row = db.execute("SELECT registered, checked_at FROM answers WHERE name=?", (name,)).fetchone()
        if row is None:
            return None
        registered, checked_at = row
        ttl_days = DATE_TTL_DAYS if registered is not None else NO_DATA_TTL_DAYS
        if self._now() - checked_at >= ttl_days * 86400:
            return None
        return registered, checked_at

    MEMO_SECONDS = 300.0
    MEMO_MAX = 20_000

    def registration_ts(self, name: str) -> Optional[float]:
        """Registration time (epoch) from a stored answer, or None: not asked yet, no date published, or the feature is
        switched off. A stored date is returned however old the answer is (see the module docstring). Never sends
        anything; memoised for MEMO_SECONDS because the novelty gate calls this per query."""
        if not self.enabled():
            return None
        name = normalize(name)
        now = self._now()
        hit = self._memo.get(name)
        if hit is not None and now - hit[1] < self.MEMO_SECONDS:
            return hit[0]
        try:
            with self._connect() as db:
                row = db.execute("SELECT registered FROM answers WHERE name=?", (name,)).fetchone()
        except sqlite3.Error as exc:
            LOGGER.warning("rdap age: could not read %s: %s", self.db_path, exc)
            return None
        registered = row[0] if row else None
        if len(self._memo) > self.MEMO_MAX:
            self._memo.clear()
        self._memo[name] = (registered, now)
        return registered

    def has_fresh_answer(self, name: str) -> bool:
        """True while a stored answer is inside its lifetime (lookup() would not ask again)."""
        try:
            return self._answer(normalize(name)) is not None
        except sqlite3.Error:
            return False

    def has_answer(self, name: str) -> bool:
        """True when the registry was ever asked about `name` successfully (date or no date), however long ago."""
        try:
            with self._connect() as db:
                return db.execute("SELECT 1 FROM answers WHERE name=?", (normalize(name),)).fetchone() is not None
        except sqlite3.Error:
            return False

    # --- small persistent key/value store for the scheduler ---------------------------------------------------------

    def get_meta(self, key: str) -> Optional[str]:
        with self._connect() as db:
            row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    # --- limits ------------------------------------------------------------------------------------------------------

    def used_today(self) -> int:
        with self._connect() as db:
            row = db.execute("SELECT count FROM usage WHERE day=?", (_day(self._now()),)).fetchone()
        return int(row[0]) if row else 0

    def seconds_until_next_allowed(self) -> float:
        """0 when a lookup could go out now (ignoring the daily cap and per-registry back-off)."""
        return max(0.0, self._last_lookup_at + MIN_INTERVAL_SECONDS - self._now())

    def status(self) -> dict:
        """For the UI and the health checks."""
        try:
            with self._connect() as db:
                answers = db.execute("SELECT COUNT(*) FROM answers").fetchone()[0]
        except sqlite3.Error:
            answers = None
        return {"enabled": self.enabled(), "used_today": self.used_today(), "daily_cap": DAILY_CAP,
                "answers_stored": answers}

    # --- registry list -----------------------------------------------------------------------------------------------

    def _load_bootstrap(self) -> Dict[str, str]:
        """tld -> RDAP base url (https preferred). Weekly refresh; a failed refresh keeps the last copy."""
        now = self._now()
        with self._connect() as db:
            row = db.execute("SELECT value FROM meta WHERE key='bootstrap'").fetchone()
            fetched = db.execute("SELECT value FROM meta WHERE key='bootstrap_at'").fetchone()
        stored = json.loads(row[0]) if row else None
        fetched_at = float(fetched[0]) if fetched else 0.0
        if stored is not None and now - fetched_at < BOOTSTRAP_REFRESH_SECONDS:
            return stored
        try:
            code, body, _headers = self._http_get(BOOTSTRAP_URL, {"Accept": "application/json", "User-Agent": USER_AGENT},
                                                  HTTP_TIMEOUT_SECONDS)
            if code != 200:
                raise ValueError(f"HTTP {code}")
            servers: Dict[str, str] = {}
            for tlds, urls in json.loads(body).get("services", []):
                https = [u for u in urls if u.startswith("https://")]
                if not (https or urls):
                    continue
                for tld in tlds:
                    servers[normalize(tld)] = (https or urls)[0]
            with self._connect() as db:
                db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('bootstrap', ?)", (json.dumps(servers),))
                db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('bootstrap_at', ?)", (str(now),))
            return servers
        except Exception as exc:
            LOGGER.warning("rdap age: registry list not refreshed (%s); %s", exc,
                           "using the last copy" if stored else "no copy, nothing will be looked up")
            return stored or {}

    def _server_for(self, name: str) -> Optional[str]:
        if self._bootstrap_cache is None:
            self._bootstrap_cache = self._load_bootstrap()
        elif self._now() - self._bootstrap_fetched_at() >= BOOTSTRAP_REFRESH_SECONDS:
            self._bootstrap_cache = self._load_bootstrap()
        return self._bootstrap_cache.get(name.rsplit(".", 1)[1])

    def _bootstrap_fetched_at(self) -> float:
        with self._connect() as db:
            row = db.execute("SELECT value FROM meta WHERE key='bootstrap_at'").fetchone()
        return float(row[0]) if row else 0.0

    # --- the lookup --------------------------------------------------------------------------------------------------

    def lookup(self, name: str) -> str:
        """Ask the registry about `name` if everything allows it. Returns one of the outcome constants; the answer, when
        there is one, is then readable through registration_ts(). At most one lookup runs at a time."""
        if not self.enabled():
            return DISABLED
        name = normalize(name)
        if not is_gtld_name(name):
            return NOT_GTLD
        if is_local_name(name):
            return LOCAL
        with self._lock:
            try:
                return self._lookup_locked(name)
            except sqlite3.Error as exc:
                LOGGER.warning("rdap age: database error (%s)", exc)
                return ERROR

    def _lookup_locked(self, name: str) -> str:
        if self._answer(name) is not None:
            return CACHED
        server = self._server_for(name)
        if not server:
            return NO_SERVER
        now = self._now()
        if self.used_today() >= DAILY_CAP:
            return DAILY_LIMIT
        if self.seconds_until_next_allowed() > 0:
            return TOO_SOON
        with self._connect() as db:
            row = db.execute("SELECT until FROM backoff WHERE server=?", (server,)).fetchone()
        if row and row[0] > now:
            return BACKOFF

        # Every attempt counts against the limits, successful or not.
        self._last_lookup_at = now
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_lookup_at', ?)", (str(now),))
            db.execute("INSERT INTO usage (day, count) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET count = count + 1",
                       (_day(now),))
            db.execute("DELETE FROM usage WHERE day < ?", (_day(now) - 30,))
        url = server.rstrip("/") + "/domain/" + name
        try:
            code, body, headers = self._http_get(url, {"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
                                                 HTTP_TIMEOUT_SECONDS)
        except Exception as exc:
            LOGGER.debug("rdap age: %s failed: %s", url, exc)
            return ERROR
        if code == 429:
            try:
                wait = float(headers.get("retry-after", ""))
            except ValueError:
                wait = BACKOFF_DEFAULT_SECONDS
            with self._connect() as db:
                db.execute("INSERT OR REPLACE INTO backoff (server, until) VALUES (?, ?)", (server, now + max(wait, 1.0)))
            return BACKOFF
        if code == 404:
            self._store(name, None, now)          # the registry has no such domain: no date, not an error
            return LOOKED_UP
        if code != 200:
            return ERROR
        self._store(name, _parse_registration(body), now)
        return LOOKED_UP

    def _store(self, name: str, registered: Optional[float], now: float) -> None:
        self._memo.pop(name, None)
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO answers (name, registered, checked_at) VALUES (?, ?, ?)",
                       (name, registered, now))
