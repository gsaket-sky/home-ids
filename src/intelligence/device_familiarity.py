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
from typing import Dict, Optional

LOGGER = logging.getLogger("home_ids.device_familiarity")

OBSERVATIONS_FOR_FULL_FAMILIARITY = 5
MAX_ENTRIES_PER_KIND = 200
FLUSH_INTERVAL_SECONDS = 600.0
_KINDS = ("ports", "asn_owners", "domain_bases")
FILE_NAME = "device_familiarity.json"


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
                                           domain_base: Optional[str] = None) -> None:
        if not device_id or device_id == "unknown":
            return
        now = time.time()
        with self._lock:
            device = self._data.setdefault(device_id, {})
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
            if changed:
                self._dirty = True
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

    def get_baseline_entry_count(self, device_id: str) -> int:
        """Distinct ports/owners/domains tracked for this device -- a size/maturity signal for the dashboards."""
        with self._lock:
            return sum(len(bucket) for bucket in self._data.get(device_id, {}).values())

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
