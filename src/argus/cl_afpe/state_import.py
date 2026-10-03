"""state_import.py - one-time import of the per-device learning the earlier false-positive engine kept in flat files.

Before the argus CL-AFPE (argus/cl_afpe/engine.py) kept everything in the graph, these lived in the state dir:

  device_fp_profiles.json      per-device thresholds raised after corrections, plus "_baseline" familiarity counts
  fp_sigma_shifts.json         per-device sensitivity shift
  confirmed_threat_counts.json per-device confirmed-threat counts ("<device>" and "<device>||<signature>")

import_legacy_state() copies what the graph does not already have (the graph's own, newer values always win) into
graph metadata and the DeviceFamiliarity store, then renames each file to "<name>.imported" so it runs once.
The pipeline calls it at start-up. Never raises.
"""
import json
import logging
from pathlib import Path
from typing import Dict

LOGGER = logging.getLogger("home_ids.cl_afpe.import")


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _done(path: Path) -> None:
    try:
        path.rename(path.with_name(path.name + ".imported"))
    except OSError as e:
        LOGGER.warning("Could not rename %s after import: %s", path, e)


def import_legacy_state(state_dir, store, familiarity) -> Dict[str, int]:
    state_dir = Path(state_dir)
    stats = {"profiles": 0, "familiarity": 0, "sigma_shifts": 0, "confirmed_counts": 0}
    try:
        path = state_dir / "device_fp_profiles.json"
        raw = _load(path) if path.exists() else None
        if isinstance(raw, dict):
            for device_id, profile in raw.items():
                if not isinstance(profile, dict):
                    continue
                if isinstance(profile.get("_baseline"), dict):
                    stats["familiarity"] += familiarity.import_counts(device_id, profile["_baseline"])
                current = dict(store.get_device_metadata(device_id).get("fp_profile") or {})
                added = {k: v for k, v in profile.items()
                         if k != "_baseline" and isinstance(v, dict) and "value" in v and k not in current}
                if added:
                    current.update(added)
                    store.update_device_metadata(device_id, {"fp_profile": current})
                    stats["profiles"] += len(added)
            familiarity.flush(force=True)
            _done(path)

        path = state_dir / "fp_sigma_shifts.json"
        raw = _load(path) if path.exists() else None
        if isinstance(raw, dict):
            for device_id, shift in raw.items():
                if isinstance(shift, (int, float)) and "sigma_shift" not in store.get_device_metadata(device_id):
                    store.update_device_metadata(device_id, {"sigma_shift": float(shift)})
                    stats["sigma_shifts"] += 1
            _done(path)

        path = state_dir / "confirmed_threat_counts.json"
        raw = _load(path) if path.exists() else None
        if isinstance(raw, dict):
            per_device: Dict[str, Dict[str, int]] = {}
            for key, count in raw.items():
                if not isinstance(count, (int, float)):
                    continue
                device_id, _, signature = key.partition("||")
                per_device.setdefault(device_id, {})[signature or "_total"] = int(count)
            for device_id, counts in per_device.items():
                if not store.get_device_metadata(device_id).get("confirmed_threat_counts"):
                    store.update_device_metadata(device_id, {"confirmed_threat_counts": counts})
                    stats["confirmed_counts"] += 1
            _done(path)
    except Exception:
        LOGGER.exception("Importing the earlier false-positive engine's state failed (non-fatal)")
    if any(stats.values()):
        LOGGER.info("Imported earlier false-positive engine state: %s", stats)
    return stats
