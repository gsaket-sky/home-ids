"""
onboarding.py - alert-only grace period for a brand-new install.

The severity gate + CL-AFPE are the only brakes on autonomous blocking today --
for an unknown customer network on day one, that isn't enough runway to build a
real baseline (see PRODUCT_ARCHITECTURE.md's onboarding-flow section). While
onboarding is active, mitigation stays alert-only: Telegram/Grafana/alerts.json
are completely unaffected, only ips.py's autonomous containment actions are
gated -- see mitigate()'s onboarding_active check.

Backed by state/onboarding.json, created lazily on first read so "first boot"
falls out for free with no separate install-time hook:
  {"started_at": <epoch>, "activated_at": <epoch>|null}

`activated_at` is set once, either by the customer clicking "Activate
Protection Now" in the WebUI or by the grace period simply expiring -- once
set, onboarding never re-activates for this install.
"""
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional

LOGGER = logging.getLogger("home_ids.onboarding")

_DEFAULT_STATE_DIR = "state"
_FILE_NAME = "onboarding.json"

# mtime-cached read, same pattern as metrics_sync.py's _read_relay_file --
# this is checked on every mitigate() call, so avoid a disk read each time.
_cache: Dict[str, Any] = {"mtime": None, "data": None, "path": None}


def _state_path(state_dir: str = _DEFAULT_STATE_DIR) -> Path:
    return Path(state_dir) / _FILE_NAME


def _read_or_create(state_dir: str = _DEFAULT_STATE_DIR) -> Dict[str, Any]:
    path = _state_path(state_dir)
    try:
        mtime = path.stat().st_mtime if path.exists() else None
    except OSError:
        mtime = None

    if mtime is not None and _cache["path"] == str(path) and _cache["mtime"] == mtime:
        return _cache["data"]

    data: Optional[Dict[str, Any]] = None
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Failed to parse %s: %s -- treating as first boot", path, exc)

    if data is None:
        data = {"started_at": time.time(), "activated_at": None}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp_path.replace(path)
        except OSError as exc:
            LOGGER.warning("Failed to write %s: %s", path, exc)
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = None

    _cache.update(path=str(path), mtime=mtime, data=data)
    return data


def get_onboarding_status(config, state_dir: str = _DEFAULT_STATE_DIR) -> Dict[str, Any]:
    """Returns {"active", "started_at", "activated_at", "days_remaining",
    "onboarding_mode_days"}. `active` is False whenever onboarding_mode_days is 0
    (disabled), the grace period has expired, or a human already activated
    protection early."""
    days = float(config.get("onboarding_mode_days", 14))
    data = _read_or_create(state_dir)
    started_at = float(data.get("started_at") or time.time())
    activated_at = data.get("activated_at")

    if days <= 0:
        active = False
        days_remaining = 0.0
    elif activated_at:
        active = False
        days_remaining = 0.0
    else:
        elapsed_days = (time.time() - started_at) / 86400.0
        days_remaining = max(0.0, days - elapsed_days)
        active = days_remaining > 0.0

    return {
        "active": active,
        "started_at": started_at,
        "activated_at": activated_at,
        "days_remaining": round(days_remaining, 2),
        "onboarding_mode_days": days,
    }


def is_onboarding_active(config, state_dir: str = _DEFAULT_STATE_DIR) -> bool:
    return get_onboarding_status(config, state_dir)["active"]


def activate_protection_now(state_dir: str = _DEFAULT_STATE_DIR) -> Dict[str, Any]:
    """Ends onboarding mode immediately -- the WebUI's "Activate Protection Now"
    action. Idempotent: calling this again after activation just re-confirms the
    existing activated_at rather than resetting it."""
    path = _state_path(state_dir)
    data = _read_or_create(state_dir)
    if not data.get("activated_at"):
        data["activated_at"] = time.time()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp_path.replace(path)
        except OSError as exc:
            LOGGER.warning("Failed to write %s: %s", path, exc)
        _cache.update(path=None, mtime=None, data=None)  # force a fresh read next call
    return data
