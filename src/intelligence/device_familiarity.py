"""device_familiarity.py - which destinations each device normally uses.

For every device, counts how often it has used each destination port, network owner (ASN organisation) and
registrable domain in ordinary traffic. A count of OBSERVATIONS_FOR_FULL_FAMILIARITY or more means "fully familiar"
(1.0). Readers use it only as damping evidence, never as a verdict:

  - the decision engine's benign "normal device telemetry" explanation and the AI advisor's validator need a familiar
    destination;
  - the DNS-evasion audit is softened for destinations a device always uses;
  - the false-positive engine refuses to call an unfamiliar destination harmless on similarity alone.

Callers must record only from cycles already classified BENIGN or ANOMALOUS, so a device's attack traffic never
becomes "familiar".

Bounded (at most MAX_ENTRIES_PER_KIND keys per device and kind, least recently seen evicted first), kept in memory and
saved to state/device_familiarity.json by flush() -- atomically, and at most every FLUSH_INTERVAL_SECONDS unless
forced -- so per-cycle observations never turn into per-cycle disk writes. A hard kill loses at most one interval of
counts. One instance per process; the engine shares its instance with the false-positive engine.
"""
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

LOGGER = logging.getLogger("home_ids.device_familiarity")

OBSERVATIONS_FOR_FULL_FAMILIARITY = 5
MAX_ENTRIES_PER_KIND = 200
FLUSH_INTERVAL_SECONDS = 600.0
_KINDS = ("ports", "asn_owners", "domain_bases")
FILE_NAME = "device_familiarity.json"
# Activity actually observed, not calendar time: {"<utc day number>": {"count", "first_seen", "last_seen", "hours"}},
# "hours" a 24-bit mask of the hours of that day with at least one learned (benign/anomalous) cycle. A device that was
# on for one hour a week ago has 1 active day and 1 active hour, however long ago that was. Same entry shape and
# eviction as the other kinds, so at most MAX_ENTRIES_PER_KIND days are kept.
ACTIVE_DAYS_KIND = "active_days"


def _usable(key) -> bool:
    return not (key is None or key == "" or key == "unknown" or key == 0)


class DeviceFamiliarity:
    def __init__(self, state_dir=None):
        """`state_dir` None keeps everything in memory only (tests, tools)."""
        self._path = Path(state_dir) / FILE_NAME if state_dir is not None else None
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Dict[str, dict]]] = {}
        self._dirty = False
        self._last_flush = 0.0
        self._load()

    # --- writes ------------------------------------------------------------------------------------------------
    def record_device_baseline_observation(self, device_id: str, *, dest_port=None, asn_owner: Optional[str] = None,
                                           domain_base: Optional[str] = None, now: Optional[float] = None) -> None:
        if not device_id or device_id == "unknown":
            return
        now = time.time() if now is None else float(now)
        with self._lock:
            device = self._data.setdefault(device_id, {})
            days = device.setdefault(ACTIVE_DAYS_KIND, {})
            day = str(int(now // 86400))
            hour_bit = 1 << int((now % 86400) // 3600)
            entry = days.get(day)
            if entry is None:
                if len(days) >= MAX_ENTRIES_PER_KIND:
                    days.pop(min(days, key=lambda k: days[k].get("last_seen", 0)), None)
                days[day] = {"count": 1, "first_seen": now, "last_seen": now, "hours": hour_bit}
            else:
                entry["count"] = int(entry.get("count", 0)) + 1
                entry["last_seen"] = now
                entry["hours"] = int(entry.get("hours", 0)) | hour_bit
            self._dirty = True
            for kind, key in (("ports", dest_port), ("asn_owners", asn_owner), ("domain_bases", domain_base)):
                if not _usable(key):
                    continue
                key = str(key)
                bucket = device.setdefault(kind, {})
                entry = bucket.get(key)
                if entry is None:
                    if len(bucket) >= MAX_ENTRIES_PER_KIND:
                        bucket.pop(min(bucket, key=lambda k: bucket[k].get("last_seen", 0)), None)
                    bucket[key] = {"count": 1, "first_seen": now, "last_seen": now}
                else:
                    entry["count"] = int(entry.get("count", 0)) + 1
                    entry["last_seen"] = now
                self._dirty = True

    def import_counts(self, device_id: str, baseline: dict) -> int:
        """Adds another store's {kind: {key: {"count", "first_seen", "last_seen"}}} for one device (keys already
        present keep the larger count). Returns how many keys were added or raised."""
        changed = 0
        with self._lock:
            device = self._data.setdefault(device_id, {})
            for kind in _KINDS:
                for key, entry in ((baseline or {}).get(kind) or {}).items():
                    if not isinstance(entry, dict):
                        continue
                    mine = device.setdefault(kind, {}).get(key)
                    if mine is None or int(entry.get("count", 0)) > int(mine.get("count", 0)):
                        device[kind][key] = dict(entry)
                        changed += 1
            # Activity of a merged identity is the union of both: same days, hours OR-ed together.
            for day, entry in ((baseline or {}).get(ACTIVE_DAYS_KIND) or {}).items():
                if not isinstance(entry, dict):
                    continue
                mine = device.setdefault(ACTIVE_DAYS_KIND, {}).get(day)
                if mine is None:
                    device[ACTIVE_DAYS_KIND][day] = dict(entry)
                else:
                    mine["hours"] = int(mine.get("hours", 0)) | int(entry.get("hours", 0))
                    mine["count"] = max(int(mine.get("count", 0)), int(entry.get("count", 0)))
                changed += 1
            for bucket in device.values():   # same bound and eviction as record_device_baseline_observation()
                while isinstance(bucket, dict) and len(bucket) > MAX_ENTRIES_PER_KIND:
                    bucket.pop(min(bucket, key=lambda k: bucket[k].get("last_seen", 0)), None)
            if changed:
                self._dirty = True
        return changed

    def merge_device_profile(self, orphan_id: str, canonical_id: str) -> int:
        """An identity merge: the orphan's learned activity and familiar destinations become the canonical's
        (import_counts(): active days united, hours OR-ed, each destination keeps the larger count), then the orphan
        is forgotten. Both move together, so a merged device never leaves its learning period on days whose learned
        destinations were thrown away. Counts of benign observations of one physical device, not an estimator, so
        nothing is blended. Returns how many keys were added or raised."""
        with self._lock:
            profile = self._data.get(orphan_id)
            profile = json.loads(json.dumps(profile)) if profile else None
        changed = self.import_counts(canonical_id, profile) if profile and canonical_id else 0
        self.discard_device_profile(orphan_id, reason="merge")
        return changed

    def discard_device_profile(self, device_id: str, reason: str = "") -> None:
        """Forgets a device (pruned, or merged into another identity)."""
        with self._lock:
            if self._data.pop(device_id, None) is not None:
                self._dirty = True

    # --- reads -------------------------------------------------------------------------------------------------
    def get_baseline_familiarity(self, device_id: str, *, dest_port=None, asn_owner: Optional[str] = None,
                                 domain_base: Optional[str] = None) -> float:
        """0.0 (never seen, or unknown device) to 1.0, the highest across the dimensions supplied."""
        if not device_id or device_id == "unknown":
            return 0.0
        best = 0.0
        with self._lock:
            device = self._data.get(device_id, {})
            for kind, key in (("ports", dest_port), ("asn_owners", asn_owner), ("domain_bases", domain_base)):
                if not _usable(key):
                    continue
                entry = device.get(kind, {}).get(str(key))
                if entry:
                    best = max(best, min(1.0, int(entry.get("count", 0)) / float(OBSERVATIONS_FOR_FULL_FAMILIARITY)))
        return best

    def learned_activity(self, device_id: str) -> Tuple[int, int]:
        """(active days, active hours) of learned behaviour for this device: distinct days, and distinct (day, hour)
        slots, with at least one benign/anomalous cycle. Calendar time does not count -- a device on for an hour a
        week ago is (1, 1). (0, 0) for an unknown device, and for every device whose history predates this
        bookkeeping, so gates built on it start quiet and open only on activity actually observed."""
        if not device_id or device_id == "unknown":
            return 0, 0
        with self._lock:
            days = self._data.get(device_id, {}).get(ACTIVE_DAYS_KIND, {})
            hours = sum(bin(int(e.get("hours", 0))).count("1") for e in days.values() if isinstance(e, dict))
            return len(days), hours

    def get_baseline_entry_count(self, device_id: str) -> int:
        """Distinct ports/owners/domains tracked for this device -- a size/maturity signal for the dashboards."""
        with self._lock:
            return sum(len(bucket) for kind, bucket in self._data.get(device_id, {}).items()
                       if kind != ACTIVE_DAYS_KIND)

    # --- persistence -------------------------------------------------------------------------------------------
    def flush(self, force: bool = False) -> None:
        if self._path is None or not self._dirty:
            return
        now = time.time()
        if not force and now - self._last_flush < FLUSH_INTERVAL_SECONDS:
            return
        try:
            with self._lock:
                snapshot = json.dumps(self._data)
                self._dirty = False
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(f"{self._path.name}.{os.getpid()}.tmp")
            tmp.write_text(snapshot, encoding="utf-8")
            tmp.replace(self._path)
            self._last_flush = now
        except Exception as exc:
            self._dirty = True
            LOGGER.error("Failed to save %s: %s", self._path, exc)

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._data = {d: v for d, v in raw.items() if isinstance(v, dict)}
        except Exception as exc:
            LOGGER.error("Failed to load %s (starting empty): %s", self._path, exc)
