"""
config_api.py -- read/write API for config.yaml's live-tunable values, backing the
console UI's Config tab.

Never writes to config.yaml itself. Values are read via CONFIG.get() (config.py's
LiveConfig, which already layers state/config_overrides.json on top of config.yaml --
see that module's _load_overrides() docstring) and written the same way
scripts/train_fp_classifier.py's own _write_config_override() already does: as an entry
in state/config_overrides.json, never a config.yaml edit. This preserves the existing,
deliberate invariant recorded in requirements.txt's PHASE 13 cleanup note -- "nothing in
this codebase writes to config.yaml at runtime."

Restart-only keys (config.py's _STATIC_KEYS, plus the two RUNTIME_RESTART_KEYS verified
in config_schema.py) are shown but rejected on PATCH/DELETE -- editing those safely
needs a config.yaml edit + restart, not a live overlay.

device_type_overrides is a dict (hostname-substring -> type), not a scalar, so it gets
its own merge-aware endpoints instead of the generic per-key ones.

Dotted keys (scheduler.ollama_soc.enabled etc.) are resolved for GET display only --
PATCH explicitly rejects them for now (see module docs, Documentation/CONFIG_API.md);
building the generic nested-dict merge-write these would need was scoped out of this
pass rather than shipped half-tested.
"""
import json
import threading
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from middleware.auth import verify_token, CONFIG, LOGGER
from middleware.config_schema import CONFIG_SCHEMA, is_restart_required

from config import CONFIG_FILE
from utils import rotate_jsonl_if_oversized

router = APIRouter()

_SCHEMA_BY_KEY = {row["k"]: row for row in CONFIG_SCHEMA}
_STATE_DIR = CONFIG_FILE.parent / "state"
_OVERRIDES_PATH = _STATE_DIR / "config_overrides.json"
_AUDIT_LOG_PATH = _STATE_DIR / "config_changes.jsonl"
_OVERRIDES_LOCK = threading.Lock()

def _touch_sync_signal() -> None:
    """Same sentinel file / same convention mitigation_api.py's own
    _touch_sync_signal() already uses -- prompts the main pipeline process's
    reconciliation pass (core/pipeline.py, right after the IPS sentinel check)
    to act on this write immediately rather than waiting for its own separate
    ~10s config-poll interval AND, for device_type specifically, a device's
    next traffic event (see pipeline.py's own 2026-09-16 bugfix comment at
    that reconciliation block for why the two are different waits)."""
    Path(CONFIG.get("state_path", "state/ids_state.json")).parent.joinpath(".ipc_sync_signal").touch()


DEVICE_TYPE_OVERRIDES_KEY = "device_type_overrides"
DEVICE_TYPES = [
    "laptop", "desktop", "phone", "tablet", "smart_tv", "gaming_console", "printer",
    "nas", "iot", "camera", "server", "unknown", "dns_server", "router", "gateway",
]


# ------------------------------- request bodies -------------------------------

class ConfigValuePayload(BaseModel):
    value: Any
    reason: Optional[str] = None


class DeviceTypePayload(BaseModel):
    type: str
    reason: Optional[str] = None


# ------------------------------- override file I/O -------------------------------

def _read_overrides() -> dict:
    if not _OVERRIDES_PATH.exists():
        return {}
    try:
        return json.loads(_OVERRIDES_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        LOGGER.warning("config_api: failed to parse %s: %s", _OVERRIDES_PATH, exc)
        return {}


def _write_overrides(data: dict) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _OVERRIDES_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(_OVERRIDES_PATH)  # atomic rename on both POSIX and Windows


def _append_audit(entry: dict) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    # BUGFIX (disk-retention audit): human-paced (one entry per operator config
    # edit), so this was low priority, but still genuinely uncapped -- a generous
    # 5MB ceiling (tens of thousands of entries) is effectively invisible in normal
    # use while still bounding a 10-year unattended run.
    rotate_jsonl_if_oversized(_AUDIT_LOG_PATH, max_bytes=5 * 1024 * 1024)
    entry = {"ts": time.time(), **entry}
    with _AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _set_override(key: str, value: Any, set_by: str, reason: Optional[str]) -> dict:
    """Read-modify-write one key into config_overrides.json (preserving every other key
    already present -- this file may hold entries from train_fp_classifier.py's own
    autotune pass too), apply it live immediately, and audit-log it. Returns the entry
    written."""
    with _OVERRIDES_LOCK:
        data = _read_overrides()
        existing = data.get(key)
        baseline = existing["baseline"] if isinstance(existing, dict) and "baseline" in existing else CONFIG.get(key)
        entry = {"value": value, "baseline": baseline, "set_at": time.time(), "set_by": set_by, "reason": reason or ""}
        data[key] = entry
        _write_overrides(data)
    CONFIG._load_overrides()
    _append_audit({"action": "set", "key": key, "value": value, "baseline": baseline, "set_by": set_by, "reason": reason or ""})
    return entry


def _delete_override(key: str, set_by: str) -> bool:
    """Removes key's override entry (if any) and pushes CONFIG back to its config.yaml
    baseline immediately via the new LiveConfig.revert_override(). Returns whether an
    override actually existed to remove."""
    with _OVERRIDES_LOCK:
        data = _read_overrides()
        entry = data.pop(key, None)
        if entry is not None:
            _write_overrides(data)
    if entry is None:
        return False
    baseline = entry.get("baseline") if isinstance(entry, dict) else None
    schema_default = _SCHEMA_BY_KEY.get(key, {}).get("def")
    CONFIG.revert_override(key, baseline if baseline is not None else schema_default)
    _append_audit({"action": "revert", "key": key, "restored_value": baseline, "set_by": set_by})
    return True


def _deep_get(container: Any, path: list) -> Any:
    for part in path:
        if not isinstance(container, dict):
            return None
        container = container.get(part)
    return container


# ------------------------------- coercion / validation -------------------------------

def _coerce(row: dict, raw_value: Any) -> Any:
    t = row["t"]
    if t == "bool":
        if isinstance(raw_value, bool):
            return raw_value
        if isinstance(raw_value, str):
            return raw_value.strip().lower() in ("1", "true", "yes", "on")
        raise HTTPException(status_code=400, detail=f"'{row['k']}' expects a boolean value.")
    if t == "number":
        try:
            f = float(raw_value)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"'{row['k']}' expects a numeric value.")
        return int(f) if isinstance(row["def"], int) and not isinstance(row["def"], bool) and f.is_integer() else f
    if t == "enum":
        options = row.get("options", [])
        if raw_value not in options:
            raise HTTPException(status_code=400, detail=f"'{row['k']}' must be one of {options}.")
        return raw_value
    if t == "list":
        if not isinstance(raw_value, list):
            raise HTTPException(status_code=400, detail=f"'{row['k']}' expects a list value.")
        return raw_value
    return raw_value  # "string"


def _get_schema_row_or_404(key: str) -> dict:
    row = _SCHEMA_BY_KEY.get(key)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Unknown or non-editable config key '{key}'.")
    return row


# ------------------------------- endpoints -------------------------------

@router.get("/api/config")
def get_config(token: str = Depends(verify_token)):
    overrides = _read_overrides()
    rows = []
    for row in CONFIG_SCHEMA:
        key = row["k"]
        restart_required = is_restart_required(key)
        path_parts = key.split(".")
        if len(path_parts) > 1:
            value = _deep_get(CONFIG.get(path_parts[0], {}), path_parts[1:])
            override_entry = None  # nested keys aren't individually overridden -- see module docstring
            editable = False
        else:
            value = CONFIG.get(key, row["def"])
            override_entry = overrides.get(key)
            editable = not restart_required
        rows.append({
            "section": row["s"], "key": key, "type": row["t"], "description": row["desc"],
            "suggested_default": row["def"], "options": row.get("options"),
            "value": value, "restart_required": restart_required, "editable": editable,
            "overridden": override_entry is not None,
            "baseline": override_entry["baseline"] if override_entry else None,
            "set_by": override_entry.get("set_by") if override_entry else None,
            "set_at": override_entry.get("set_at") if override_entry else None,
        })

    dt_overrides = CONFIG.get(DEVICE_TYPE_OVERRIDES_KEY, {}) or {}
    return {
        "rows": rows,
        "device_type_overrides": [{"pattern": k, "type": v} for k, v in dt_overrides.items()],
        "device_types": DEVICE_TYPES,
    }


@router.patch("/api/config/{key}")
def patch_config(key: str, payload: ConfigValuePayload, token: str = Depends(verify_token)):
    if "." in key:
        raise HTTPException(status_code=400, detail=f"'{key}' is a nested field and isn't editable via this API yet.")
    row = _get_schema_row_or_404(key)
    if is_restart_required(key):
        raise HTTPException(status_code=400, detail=f"'{key}' requires a config.yaml edit + service restart -- not writable live.")
    value = _coerce(row, payload.value)
    entry = _set_override(key, value, set_by="console_ui", reason=payload.reason)
    return {"key": key, "value": value, "baseline": entry["baseline"], "overridden": True}


@router.delete("/api/config/{key}")
def delete_config(key: str, token: str = Depends(verify_token)):
    if "." in key:
        raise HTTPException(status_code=400, detail=f"'{key}' is a nested field and isn't editable via this API yet.")
    _get_schema_row_or_404(key)
    if is_restart_required(key):
        raise HTTPException(status_code=400, detail=f"'{key}' requires a config.yaml edit + service restart -- not writable live.")
    existed = _delete_override(key, set_by="console_ui")
    return {"key": key, "value": CONFIG.get(key), "overridden": False, "had_override": existed}


@router.patch("/api/config/device_type_overrides/{pattern}")
def patch_device_type_override(pattern: str, payload: DeviceTypePayload, token: str = Depends(verify_token)):
    if payload.type not in DEVICE_TYPES:
        raise HTTPException(status_code=400, detail=f"type must be one of {DEVICE_TYPES}.")
    current = dict(CONFIG.get(DEVICE_TYPE_OVERRIDES_KEY, {}) or {})
    current[pattern] = payload.type
    _set_override(DEVICE_TYPE_OVERRIDES_KEY, current, set_by="console_ui", reason=payload.reason or f"assigned via console: {pattern} -> {payload.type}")
    # BUGFIX (2026-09-16, user report: "in console the device type change do not
    # get apply"): _set_override() above already reloads THIS process's own CONFIG
    # immediately, but the actual device_type shown in the console comes from
    # ids_state.json, written by the SEPARATE main pipeline process -- which only
    # recomputes it when the affected device generates fresh traffic. Touching the
    # same sentinel mitigation_api.py's operator actions already use prompts that
    # process to re-apply every device's type from the fresh override right away
    # (see pipeline.py's own reconciliation block).
    _touch_sync_signal()
    return {"pattern": pattern, "type": payload.type, "device_type_overrides": current}


@router.delete("/api/config/device_type_overrides/{pattern}")
def delete_device_type_override(pattern: str, token: str = Depends(verify_token)):
    current = dict(CONFIG.get(DEVICE_TYPE_OVERRIDES_KEY, {}) or {})
    if pattern not in current:
        raise HTTPException(status_code=404, detail=f"No device_type_overrides entry for '{pattern}'.")
    del current[pattern]
    _set_override(DEVICE_TYPE_OVERRIDES_KEY, current, set_by="console_ui", reason=f"removed via console: {pattern}")
    _touch_sync_signal()
    return {"pattern": pattern, "device_type_overrides": current}
