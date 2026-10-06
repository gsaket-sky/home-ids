"""
domain_age_scheduler.py -- which names the opt-in domain-age lookups ask about, and when (MASTER_TODO M2, part 2).

intelligence/rdap_age.py is the client and enforces every limit (1 lookup / 10 s, 50 / day, 429 back-off, gTLD only).
This module decides what is worth one of those few lookups. Owner decisions (2026-10-05, the safest option): lookups
only when absolutely necessary, i.e. for names whose age changes something:

  Normal mode -- names first used by a device during its own learning period (the popularity ledger's `learning` set),
  and every name while the network itself is warming up. Each is asked about once; once those are answered and no
  device is learning, nothing is looked up. A device that joins later brings its learning-period names, and only
  those, back into the queue.

  Re-verify (back-check) -- when the setting is switched on (off -> on, including weeks, months or a year after
  installation), every device is re-verified once: every rare registrable domain each device still uses (still in
  the ledger's 60-day window), whether adopted during its learning period or later. Why every name: devices with no
  learning record (ledgers older than that column, merged device ids) would otherwise be skipped, and a C2 that
  started after baselining becomes "in use" after a few days anyway. Devices take turns (round-robin), so each gets
  its first checks early; within a device, names only it uses and names used on the most days go first. Switching
  off stops it; switching on again restarts it (answers already stored are never asked again).

  Candidate filters (both modes): registrable domain only (utils.etld1_strict, fails closed without a public-suffix
  list), not established on this network, not local (utils.is_local_name, checked here too: the ledger keeps names it
  recorded before a local suffix was configured), gTLD with a registry
  in the IANA list, not on the shipped static allowlist, and never asked about before. Normal-mode names go before
  re-verify names.

What a young result changes is not decided here: LocalPopularity.is_young() reads the stored date (no further lookup)
and lifts the "already in use" exemption in is_preexisting(); CL-AFPE keeps automatic trust for it device-scoped.

Progress is kept in rdap_cache.db (meta 'backcheck', JSON) so the web UI can show "re-verifying devices: n of m".
"""
import json
import logging
import threading
import time
from typing import Callable, Dict, List, Optional

from intelligence.rdap_age import (RdapAgeService, is_gtld_name, NOT_GTLD, LOCAL, NO_SERVER, BACKOFF, ERROR,
                                   DAILY_LIMIT, TOO_SOON, DISABLED, MIN_INTERVAL_SECONDS, DAILY_CAP)
from utils import is_local_name, is_network_dns_name

LOGGER = logging.getLogger("home_ids.domain_age_scheduler")

LEDGER_WINDOW_DAYS = 60            # LocalPopularity.DAY_WINDOW: older names are no longer in the ledger
QUEUE_REBUILD_SECONDS = 600.0
DEFER_BACKOFF_SECONDS = 1800.0     # a name whose registry is backed off waits this long before it is tried again
DEFER_ERROR_SECONDS = 6 * 3600.0
_META_ENABLED_SEEN = "enabled_seen"
_META_BACKCHECK = "backcheck"


class DomainAgeScheduler:
    def __init__(self, rdap: RdapAgeService, popularity, registrable_fn: Callable[[str], str],
                 known_good_fn: Optional[Callable[[str], bool]] = None, warmup_days: Optional[int] = None,
                 now_fn: Callable[[], float] = time.time):
        if warmup_days is None:
            from intelligence.local_popularity import HISTORY_WARMUP_ACTIVE_DAYS
            warmup_days = HISTORY_WARMUP_ACTIVE_DAYS
        self.rdap = rdap
        self.popularity = popularity
        self.registrable_fn = registrable_fn
        self.known_good_fn = known_good_fn
        self.warmup_days = int(warmup_days)
        self.now_fn = now_fn
        self._normal: List[str] = []
        self._per_device: Dict[str, List[str]] = {}
        self._rr: List[str] = []           # device order for round-robin
        self._rr_pos = 0
        self._built_at = -1e18
        self._deferred: Dict[str, float] = {}
        self._stop = threading.Event()

    # --- persistent state ------------------------------------------------------------------------------------------

    def backcheck_state(self) -> dict:
        try:
            raw = self.rdap.get_meta(_META_BACKCHECK)
            return json.loads(raw) if raw else {"active": False}
        except Exception:
            return {"active": False}

    def _save_backcheck(self, state: dict) -> None:
        self.rdap.set_meta(_META_BACKCHECK, json.dumps(state))

    def _track_switch(self, enabled: bool) -> None:
        """Off -> on starts a re-verify of every device; on -> off stops it. Persisted, so a restart is not a switch."""
        seen = self.rdap.get_meta(_META_ENABLED_SEEN)
        if enabled and seen != "1":
            self.rdap.set_meta(_META_ENABLED_SEEN, "1")
            self._save_backcheck({"active": True, "started_at": self.now_fn(), "devices_total": None,
                                  "devices_done": 0, "completed_at": None})
            self._built_at = -1e18
            LOGGER.info("Domain age switched on: re-verifying every device's rare names (rate-limited).")
        elif not enabled and seen == "1":
            self.rdap.set_meta(_META_ENABLED_SEEN, "0")
            state = self.backcheck_state()
            if state.get("active"):
                state.update(active=False, stopped_at=self.now_fn())
                self._save_backcheck(state)

    # --- queues ----------------------------------------------------------------------------------------------------

    def _warming(self) -> bool:
        try:
            return int(self.popularity.active_days) < self.warmup_days
        except Exception:
            return False

    def _eligible(self, name: str, now: float) -> bool:
        if (self._deferred.get(name, 0.0) > now or not is_gtld_name(name) or is_local_name(name)
                or is_network_dns_name(name) or self.rdap.has_answer(name)):
            return False
        if self.known_good_fn is not None:
            try:
                if self.known_good_fn(name):
                    return False
            except Exception:
                pass
        return True

    def _rebuild(self, now: float) -> None:
        all_rows = self.popularity.candidate_names(now - LEDGER_WINDOW_DAYS * 86400, self.registrable_fn)
        rows = [r for r in all_rows if self._eligible(r[0], now)]
        # Priority: names only one device uses, then names used on the most days.
        def key(r):
            return (len(r[2]) > 1, -r[3], r[0])
        warming = self._warming()
        self._normal = [r[0] for r in sorted(rows, key=key) if warming or r[4]]
        state = self.backcheck_state()
        self._per_device = {}
        if state.get("active"):
            for r in sorted(rows, key=key):
                for d in r[2]:
                    self._per_device.setdefault(d, []).append(r[0])
            # Every device with a candidate name since the re-verify started, answered or not.
            all_devices = set(state.get("devices_seen") or []) | {d for r in all_rows for d in r[2]}
            done = len(all_devices - set(self._per_device))
            state["devices_seen"] = sorted(all_devices)
            state["devices_total"] = len(all_devices)
            state["devices_done"] = done
            if not self._per_device:
                state.update(active=False, completed_at=now)
                LOGGER.info("Domain age: every device re-verified (%d device(s)).", len(all_devices))
            self._save_backcheck(state)
        self._rr = sorted(self._per_device)
        self._rr_pos = 0
        self._built_at = now

    def _next_name(self, now: float) -> Optional[str]:
        if now - self._built_at >= QUEUE_REBUILD_SECONDS or (not self._normal and not self._per_device):
            self._rebuild(now)
        while self._normal:
            name = self._normal.pop(0)
            if self._eligible(name, now):
                return name
        tries = 0
        while self._rr and tries < len(self._rr) * 2:
            tries += 1
            device = self._rr[self._rr_pos % len(self._rr)]
            self._rr_pos += 1
            queue = self._per_device.get(device) or []
            while queue:
                name = queue.pop(0)
                if self._eligible(name, now):
                    return name
            self._per_device.pop(device, None)
            self._rr = [d for d in self._rr if d in self._per_device]
        return None

    # --- one step / the loop ----------------------------------------------------------------------------------------

    def tick(self) -> str:
        """One scheduling step; returns what happened (for logs and tests)."""
        now = self.now_fn()
        enabled = self.rdap.enabled()
        self._track_switch(enabled)
        if not enabled:
            return DISABLED
        if self.rdap.seconds_until_next_allowed() > 0:
            return TOO_SOON
        if self.rdap.used_today() >= DAILY_CAP:
            return DAILY_LIMIT
        name = self._next_name(now)
        if name is None:
            return "idle"
        outcome = self.rdap.lookup(name)
        if outcome == BACKOFF:
            self._deferred[name] = now + DEFER_BACKOFF_SECONDS
        elif outcome == ERROR:
            self._deferred[name] = now + DEFER_ERROR_SECONDS
        elif outcome in (NOT_GTLD, LOCAL, NO_SERVER):
            self._deferred[name] = now + 7 * 86400   # the registry list is refreshed weekly
        elif outcome in (DAILY_LIMIT, TOO_SOON):
            self._normal.insert(0, name)              # raced the limits; keep its place
        if len(self._deferred) > 50_000:
            self._deferred = {k: v for k, v in self._deferred.items() if v > now}
        return outcome

    def status(self) -> dict:
        state = self.backcheck_state()
        out = dict(self.rdap.status())
        out["reverify"] = {k: state.get(k) for k in ("active", "started_at", "devices_total", "devices_done",
                                                     "completed_at")}
        return out

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True, name="domain-age").start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                outcome = self.tick()
            except Exception as e:
                LOGGER.warning("Domain age scheduling step failed (continuing): %s", e)
                outcome = ERROR
            wait = MIN_INTERVAL_SECONDS
            if outcome in (DISABLED, "idle", DAILY_LIMIT):
                wait = 60.0
            self._stop.wait(wait)
