"""
device_labels.py - WebUI device-labeling confirmations.

An explicit "yes, this is a phone" confirmation through the WebUI's device
inventory page is a higher-trust signal than infer_device_type()'s heuristic
guess or config.yaml's bulk device_type_overrides list -- identity.py's
apply_device_type() checks this file FIRST, above both.

Backed by state/device_labels.json:
  {device_id: {"device_type": "phone", "confirmed_by_user": true, "labeled_at": <epoch>}}

Atomic writes (.tmp + Path.replace()), same convention as state_guard.py's
flush_to_disk(). mtime-cached reads, same pattern as onboarding.py /
metrics_sync.py's _read_relay_file -- this is consulted every identity cycle.
"""
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional

LOGGER = logging.getLogger("home_ids.device_labels")

_FILE_NAME = "device_labels.json"

_cache: Dict[str, Any] = {"mtime": None, "data": None, "path": None}

VALID_DEVICE_TYPES = {
    "laptop", "desktop", "phone", "tablet", "smart_tv", "gaming_console",
    "printer", "nas", "iot", "camera", "server", "unknown",
    "dns_server", "router", "gateway",
}


def _path(state_dir: str) -> Path:
    return Path(state_dir) / _FILE_NAME


def _read_all(state_dir: str = "state") -> Dict[str, Any]:
    path = _path(state_dir)
    try:
        mtime = path.stat().st_mtime if path.exists() else None
    except OSError:
        mtime = None

    if mtime is not None and _cache["path"] == str(path) and _cache["mtime"] == mtime:
        return _cache["data"]

    data: Dict[str, Any] = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8")) or {}
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Failed to parse %s: %s -- treating as empty", path, exc)
            data = {}

    _cache.update(path=str(path), mtime=mtime, data=data)
    return data


def _write_all(data: Dict[str, Any], state_dir: str = "state") -> None:
    path = _path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp_path.replace(path)
    _cache.update(path=None, mtime=None, data=None)  # force a fresh read next call


def get_label(device_id: str, state_dir: str = "state") -> Optional[str]:
    """Returns the confirmed device_type for this device, or None if never
    labeled through the WebUI."""
    entry = _read_all(state_dir).get(device_id)
    return entry.get("device_type") if entry else None


def set_label(device_id: str, device_type: str, state_dir: str = "state") -> None:
    if device_type not in VALID_DEVICE_TYPES:
        raise ValueError(f"'{device_type}' is not a recognized device type")
    data = _read_all(state_dir)
    data[device_id] = {
        "device_type": device_type,
        "confirmed_by_user": True,
        "labeled_at": time.time(),
    }
    _write_all(data, state_dir)


def remove_label(device_id: str, state_dir: str = "state") -> bool:
    """Used by the device-purge maintenance action -- returns True if a label
    existed and was removed."""
    data = _read_all(state_dir)
    if device_id in data:
        del data[device_id]
        _write_all(data, state_dir)
        return True
    return False


def transfer_label(orphan_id: str, canonical_id: str, state_dir: str = "state") -> bool:
    """An identity merge: the orphan's confirmation is about the same physical device, so it moves to the canonical
    (2026-10-05 merge sweep -- it used to stay under the dead id and the device fell back to a guessed type). If both
    were confirmed, the more recent confirmation wins. Returns True if the canonical's label changed."""
    data = _read_all(state_dir)
    orphan = data.get(orphan_id)
    if not orphan:
        return False
    data = dict(data)
    del data[orphan_id]
    mine = data.get(canonical_id)
    changed = not mine or float(orphan.get("labeled_at", 0) or 0) > float(mine.get("labeled_at", 0) or 0)
    if changed:
        data[canonical_id] = dict(orphan)
    _write_all(data, state_dir)
    return changed


def all_labels(state_dir: str = "state") -> Dict[str, Any]:
    return dict(_read_all(state_dir))
