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
                 the Tranco rank it replaces (fp_engine's feature 0: 1 - rank/1e6, 0 when unranked).

Storage: SQLite (owner requirement: no JSON state files), capped at MAX_ROWS names, pruned by last-seen. The hot path
(observe) only touches an in-memory dict; a flush every FLUSH_SECONDS merges into the database and rebuilds the
lookup snapshot (rank dict + established set) that readers use without locking the database.
"""
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Set

LOGGER = logging.getLogger("home_ids.local_popularity")

MIN_DEVICES = 3
MIN_DAYS = 7
MAX_DEVICES_TRACKED = 16       # per name; beyond this the exact count no longer changes anything
DAY_WINDOW = 60                # only days within this window count
MAX_ROWS = 200_000
FLUSH_SECONDS = 300.0


def _day(ts: float) -> int:
    return int(ts // 86400)


class LocalPopularity:
    def __init__(self, db_path, etld1_fn=None, now_fn=time.time):
        self.db_path = Path(db_path)
        self._etld1 = etld1_fn or (lambda d: d)
        self._now = now_fn
        self._lock = threading.Lock()
        self._pending: Dict[str, list] = {}        # name -> [set(device), set(day), last_seen]
        self._rank: Dict[str, int] = {}
        self._established: Set[str] = set()
        self._last_flush = self._now()
        self._etld_memo: Dict[str, str] = {}
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS names (name TEXT PRIMARY KEY, devices TEXT NOT NULL, "
                       "days TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS names_last_seen ON names(last_seen)")
        self._rebuild_snapshot()

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
        if not name or "." not in name or name.endswith((".arpa", ".local", ".lan", ".home", ".fritz.box")):
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
        with self._lock:
            for n in ((name,) if base == name else (name, base)):
                e = self._pending.get(n)
                if e is None:
                    e = self._pending[n] = [set(), set(), ts]
                if len(e[0]) < MAX_DEVICES_TRACKED:
                    e[0].add(device_id)
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
                        cur = self._pending.setdefault(n, [set(), set(), e[2]])
                        cur[0] |= e[0]
                        cur[1] |= e[1]
                        cur[2] = max(cur[2], e[2])
                return
        self._rebuild_snapshot()

    def _merge(self, pending: Dict[str, list]) -> None:
        now = self._now()
        oldest_day = _day(now) - DAY_WINDOW
        with self._connect() as db:
            for name, (devices, days, last_seen) in pending.items():
                row = db.execute("SELECT devices, days, first_seen, last_seen FROM names WHERE name=?", (name,)).fetchone()
                if row:
                    devs = set(filter(None, row[0].split(",")))
                    ds = {int(x) for x in row[1].split(",") if x}
                    first, last = row[2], max(row[3], last_seen)
                else:
                    devs, ds, first, last = set(), set(), last_seen, last_seen
                devs |= devices
                if len(devs) > MAX_DEVICES_TRACKED:
                    devs = set(sorted(devs)[:MAX_DEVICES_TRACKED])
                ds = {d for d in (ds | days) if d >= oldest_day}
                db.execute("INSERT OR REPLACE INTO names VALUES (?,?,?,?,?)",
                           (name, ",".join(sorted(devs)), ",".join(str(d) for d in sorted(ds)), first, last))
            n = db.execute("SELECT COUNT(*) FROM names").fetchone()[0]
            if n > MAX_ROWS:
                db.execute("DELETE FROM names WHERE name IN (SELECT name FROM names ORDER BY last_seen ASC LIMIT ?)",
                           (n - MAX_ROWS,))
            db.execute("DELETE FROM names WHERE last_seen < ?", (now - DAY_WINDOW * 86400,))

    def _rebuild_snapshot(self) -> None:
        oldest_day = _day(self._now()) - DAY_WINDOW
        scored = []
        established = set()
        try:
            with self._connect() as db:
                for name, devs, days in db.execute("SELECT name, devices, days FROM names"):
                    n_dev = len([d for d in devs.split(",") if d])
                    n_days = len([d for d in days.split(",") if d and int(d) >= oldest_day])
                    if n_dev >= MIN_DEVICES and n_days >= MIN_DAYS:
                        established.add(name)
                    scored.append((n_dev, n_days, name))
        except sqlite3.Error as exc:
            LOGGER.warning("local popularity: could not read %s: %s", self.db_path, exc)
            return
        scored.sort(key=lambda t: (-t[0], -t[1], t[2]))
        self._rank = {name: i + 1 for i, (_, _, name) in enumerate(scored)}
        self._established = established
