"""
local_popularity.py -- domain popularity learned on this network, replacing the Tranco top-1M list.

Why (decided 2026-09-29, built 2026-10-01): Tranco aggregates several popularity sources, one of them licensed
CC BY-NC, so it cannot ship in a sold unit (Documentation/internal/LICENSING_ALTERNATIVES.md #8). Tranco did two jobs:
  1. an exact-match allowlist (ThreatIntel.is_allowlisted) that shields popular domains from broad suffix matches and
     weak, policy-style indicators, and
  2. feature 0 of the false-positive model (`tranco_rank`).
Both now come from what this network itself uses.

What is learned: for each queried name, and for its registrable domain (eTLD+1), which devices asked for it and on
which days. Queries Pi-hole blocked are ignored (ad/tracker lists must not become "trusted").

  established -- asked for by >= MIN_DEVICES distinct devices on >= MIN_DAYS distinct days. Only established names
                 count for the allowlist. ThreatIntel never lets a learned entry hide a direct, strong threat-list hit
                 (see is_allowlisted there): a learned list can be poisoned (malware several devices talk to daily),
                 so it only overrides suffix matches and weak indicators.
  rank        -- 1 = most used, ordering by distinct devices, then distinct days; 0 = not ranked. Same convention as
                 the Tranco rank it replaces (the false-positive model's feature 0: 1 - rank/1e6, 0 when unranked).

Storage: SQLite (owner requirement: no JSON state files), capped at MAX_ROWS names, pruned by last-seen. The hot path
(observe) only touches an in-memory dict; a flush every FLUSH_SECONDS merges into the database and rebuilds the
lookup snapshot (rank dict + established set) that readers use without locking the database.
"""
import contextlib
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Optional, Set

from utils import is_local_name

LOGGER = logging.getLogger("home_ids.local_popularity")

MIN_DEVICES = 3
MIN_DAYS = 7
MAX_DEVICES_TRACKED = 16       # per name; beyond this the exact count no longer changes anything
DAY_WINDOW = 60                # only days within this window count
MAX_ROWS = 200_000
FLUSH_SECONDS = 300.0

# Novelty (is_preexisting): a name counts as already in use on this network once it was asked for on at least
# NOVELTY_MIN_DAYS distinct days. Until the network itself has HISTORY_WARMUP_ACTIVE_DAYS distinct days of observed
# queries, nothing can be called new (a fresh install, or a unit that ran one afternoon a month ago, has no "before"),
# so novelty-gated detectors stay silent instead of treating every name as new. Both are counts of days with activity,
# never calendar spans.
NOVELTY_MIN_DAYS = 3
HISTORY_WARMUP_ACTIVE_DAYS = 7    # a full weekly rhythm of network history before anything can be called new
_HISTORY_CACHE_TTL = 300.0
_HISTORY_CACHE_MAX = 5000
_LEARNING_MEMO_TTL = 60.0     # observe() is per query; a device's learning status is re-read at most once a minute


def _day(ts: float) -> int:
    return int(ts // 86400)


class LocalPopularity:
    def __init__(self, db_path, etld1_fn=None, now_fn=time.time, learning_fn: Optional[Callable[[str], bool]] = None):
        """`learning_fn(device_id)` -> True while that device is still in its own learning period (set by the
        pipeline from DeviceFamiliarity). None: every device counts as out of learning, the behaviour before the
        learning-adoption ledger existed."""
        self.db_path = Path(db_path)
        self._etld1 = etld1_fn or (lambda d: d)
        self._now = now_fn
        self.learning_fn = learning_fn
        self._lock = threading.Lock()
        # name -> [set(device), set(day), last_seen, set(device first seen using it during its learning period)]
        self._pending: Dict[str, list] = {}
        self._rank: Dict[str, int] = {}
        self._established: Set[str] = set()
        self._last_flush = self._now()
        self._etld_memo: Dict[str, str] = {}
        self._history_cache: Dict[str, tuple] = {}   # name -> (first_seen, n_days, devices, learning, cached_at)
        self._learning_memo: Dict[str, tuple] = {}   # device -> (in learning period, checked_at)
        self._active_days = 0                         # distinct days with any observed query, from the snapshot
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS names (name TEXT PRIMARY KEY, devices TEXT NOT NULL, "
                       "days TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
                       "learning TEXT NOT NULL DEFAULT '')")
            db.execute("CREATE INDEX IF NOT EXISTS names_last_seen ON names(last_seen)")
            # Databases from before the learning-adoption ledger: add the column. Their existing devices read as
            # adopted outside a learning period (unknowable after the fact), i.e. exactly the old behaviour.
            if "learning" not in {r[1] for r in db.execute("PRAGMA table_info(names)")}:
                db.execute("ALTER TABLE names ADD COLUMN learning TEXT NOT NULL DEFAULT ''")
        self._rebuild_snapshot()

    def _device_in_learning(self, device_id: str) -> bool:
        fn = self.learning_fn
        if fn is None or not device_id:
            return False
        now = self._now()
        hit = self._learning_memo.get(device_id)
        if hit is not None and now - hit[1] < _LEARNING_MEMO_TTL:
            return hit[0]
        try:
            learning = bool(fn(device_id))
        except Exception:
            learning = False
        if len(self._learning_memo) > 10_000:
            self._learning_memo.clear()
        self._learning_memo[device_id] = (learning, now)
        return learning

    def _connect(self):
        db = sqlite3.connect(str(self.db_path), timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        return db

    # --- hot path -------------------------------------------------------------------------------------------------

    def observe(self, device_id: str, domain: str, ts: Optional[float] = None) -> None:
        if not device_id or not domain:
            return
        name = domain.lower().strip(".")
        if not name or "." not in name or is_local_name(name):
            return
        ts = float(ts) if ts else self._now()
        base = self._etld_memo.get(name)
        if base is None:
            try:
                base = self._etld1(name) or name
            except Exception:
                base = name
            if len(self._etld_memo) > 50_000:
                self._etld_memo.clear()
            self._etld_memo[name] = base
        day = _day(ts)
        learning = self._device_in_learning(device_id)
        with self._lock:
            for n in ((name,) if base == name else (name, base)):
                e = self._pending.get(n)
                if e is None:
                    e = self._pending[n] = [set(), set(), ts, set()]
                if len(e[0]) < MAX_DEVICES_TRACKED:
                    e[0].add(device_id)
                    if learning:
                        e[3].add(device_id)
                e[1].add(day)
                if ts > e[2]:
                    e[2] = ts

    def start(self) -> None:
        """Flush + snapshot rebuild on a background thread -- never in the detection loop that calls observe()."""
        def _loop():
            while True:
                time.sleep(FLUSH_SECONDS)
                try:
                    self.flush()
                except Exception as exc:
                    LOGGER.warning("local popularity flush loop: %s", exc)
        threading.Thread(target=_loop, daemon=True, name="local-popularity").start()

    # --- readers ----------------------------------------------------------------------------------------------------

    def is_established(self, domain: str) -> bool:
        return bool(domain) and domain.lower().strip(".") in self._established

    def get_rank(self, domain: str) -> int:
        """Rank of the exact name, else of its registrable domain; 0 when unranked."""
        if not domain:
            return 0
        name = domain.lower().strip(".")
        r = self._rank.get(name)
        if r:
            return r
        base = self._etld_memo.get(name)
        if base is None:
            try:
                base = self._etld1(name) or name
            except Exception:
                base = name
        return self._rank.get(base, 0)

    @property
    def established_count(self) -> int:
        return len(self._established)

    # --- novelty (W-04 producers) -----------------------------------------------------------------------------------

    def _base_of(self, name: str) -> str:
        base = self._etld_memo.get(name)
        if base is None:
            try:
                base = self._etld1(name) or name
            except Exception:
                base = name
        return base

    @property
    def active_days(self) -> int:
        """Distinct days (within DAY_WINDOW) on which this network had any learned query. Rebuilt with the snapshot."""
        return self._active_days

    def _name_history(self, name: str) -> tuple:
        """(first_seen or None, distinct days, devices, devices that adopted it during their learning period) from
        the database, cached. A name only in the unflushed buffer (first seen within the last flush interval) reads
        as unknown, i.e. new -- which is what it is."""
        now = self._now()
        with self._lock:
            hit = self._history_cache.get(name)
        if hit is not None and now - hit[4] < _HISTORY_CACHE_TTL:
            return hit[:4]
        first_seen, n_days, devices, learning = None, 0, frozenset(), frozenset()
        try:
            with contextlib.closing(sqlite3.connect(str(self.db_path), timeout=5)) as db:
                row = db.execute("SELECT first_seen, days, devices, learning FROM names WHERE name=?",
                                 (name,)).fetchone()
            if row:
                first_seen = float(row[0])
                n_days = len([d for d in (row[1] or "").split(",") if d])
                devices = frozenset(filter(None, (row[2] or "").split(",")))
                learning = frozenset(filter(None, (row[3] or "").split(",")))
        except sqlite3.Error as exc:
            LOGGER.debug("local popularity: history of %s unavailable: %s", name, exc)
            raise
        with self._lock:
            if len(self._history_cache) >= _HISTORY_CACHE_MAX:
                self._history_cache.clear()
            self._history_cache[name] = (first_seen, n_days, devices, learning, now)
        return first_seen, n_days, devices, learning

    def _unproven_for(self, device_id: Optional[str], devices: frozenset, learning: frozenset) -> bool:
        """True when `device_id`, out of its own learning period, is picking up a name that only devices still in
        their learning period had used (so nobody's baselined behaviour ever vouched for it). Spread from an
        already-infected device -- or from the devices present when the system was first switched on -- to a device
        whose normal behaviour is known. A device's own learning-period names stay its own: from local history
        alone, a camera infected since day one cannot be told from a clean camera polling its vendor since day one,
        so those never count against the device that brought them."""
        if not device_id:
            return False
        others = devices - {device_id}
        if not others or not others <= learning:
            return False          # only this device's own history, or an independent baselined device vouches
        if device_id in learning or self._device_in_learning(device_id):
            return False          # this device's own learning period
        return True

    def is_preexisting(self, domain: str, device_id: Optional[str] = None) -> Optional[bool]:
        """Whether `domain` -- the exact name or its registrable domain -- was already in use on this network: an
        established name, or one asked for on >= NOVELTY_MIN_DAYS distinct days. With `device_id`, a name that only
        learning-period devices ever used does not count as in use for an out-of-learning device picking it up
        (see _unproven_for) -- until it becomes established.

        True: in use here before, so a novelty-gated detector must not act on it. False: new on this network (or,
        for `device_id`, unproven). None: cannot tell (fewer than HISTORY_WARMUP_ACTIVE_DAYS days of observed
        history, or the database is unreadable). Callers treat None exactly like True, so missing or thin history
        never produces evidence."""
        if not domain:
            return None
        if self._active_days < HISTORY_WARMUP_ACTIVE_DAYS:
            return None
        name = domain.lower().strip(".")
        try:
            for n in dict.fromkeys((name, self._base_of(name))):
                if n in self._established:
                    return True
                _first_seen, n_days, devices, learning = self._name_history(n)
                if n_days >= NOVELTY_MIN_DAYS and not self._unproven_for(device_id, devices, learning):
                    return True
        except sqlite3.Error:
            return None
        return False

    # --- persistence ------------------------------------------------------------------------------------------------

    def flush(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, {}
            self._last_flush = self._now()
        if pending:
            try:
                self._merge(pending)
            except Exception as exc:
                LOGGER.warning("local popularity: flush failed (%s); %d names kept for the next try", exc, len(pending))
                with self._lock:
                    for n, e in pending.items():
                        cur = self._pending.setdefault(n, [set(), set(), e[2], set()])
                        cur[0] |= e[0]
                        cur[1] |= e[1]
                        cur[2] = max(cur[2], e[2])
                        cur[3] |= e[3]
                return
        self._rebuild_snapshot()

    def _merge(self, pending: Dict[str, list]) -> None:
        now = self._now()
        oldest_day = _day(now) - DAY_WINDOW
        with self._connect() as db:
            for name, (devices, days, last_seen, learning_new) in pending.items():
                row = db.execute("SELECT devices, days, first_seen, last_seen, learning FROM names WHERE name=?",
                                 (name,)).fetchone()
                if row:
                    devs = set(filter(None, row[0].split(",")))
                    ds = {int(x) for x in row[1].split(",") if x}
                    first, last = row[2], max(row[3], last_seen)
                    learn = set(filter(None, (row[4] or "").split(",")))
                else:
                    devs, ds, first, last, learn = set(), set(), last_seen, last_seen, set()
                # A device's adoption status is fixed at its FIRST use: only devices new to this name can be added.
                learn |= learning_new - devs
                devs |= devices
                if len(devs) > MAX_DEVICES_TRACKED:
                    devs = set(sorted(devs)[:MAX_DEVICES_TRACKED])
                learn &= devs
                ds = {d for d in (ds | days) if d >= oldest_day}
                db.execute("INSERT OR REPLACE INTO names (name, devices, days, first_seen, last_seen, learning) "
                           "VALUES (?,?,?,?,?,?)",
                           (name, ",".join(sorted(devs)), ",".join(str(d) for d in sorted(ds)), first, last,
                            ",".join(sorted(learn))))
            n = db.execute("SELECT COUNT(*) FROM names").fetchone()[0]
            if n > MAX_ROWS:
                db.execute("DELETE FROM names WHERE name IN (SELECT name FROM names ORDER BY last_seen ASC LIMIT ?)",
                           (n - MAX_ROWS,))
            db.execute("DELETE FROM names WHERE last_seen < ?", (now - DAY_WINDOW * 86400,))

    def _rebuild_snapshot(self) -> None:
        oldest_day = _day(self._now()) - DAY_WINDOW
        scored = []
        established = set()
        all_days = set()
        try:
            with self._connect() as db:
                for name, devs, days in db.execute("SELECT name, devices, days FROM names"):
                    n_dev = len([d for d in devs.split(",") if d])
                    name_days = {int(d) for d in days.split(",") if d and int(d) >= oldest_day}
                    n_days = len(name_days)
                    all_days |= name_days
                    if n_dev >= MIN_DEVICES and n_days >= MIN_DAYS:
                        established.add(name)
                    scored.append((n_dev, n_days, name))
        except sqlite3.Error as exc:
            LOGGER.warning("local popularity: could not read %s: %s", self.db_path, exc)
            return
        scored.sort(key=lambda t: (-t[0], -t[1], t[2]))
        self._rank = {name: i + 1 for i, (_, _, name) in enumerate(scored)}
        self._established = established
        self._active_days = len(all_days)
