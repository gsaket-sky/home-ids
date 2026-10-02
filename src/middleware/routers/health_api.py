"""
health_api.py -- read-only console surface for the health manager.

Runs in the SEPARATE console/API subprocess, not the same process as the live
HealthManager instance (which lives inside the main pipeline process) -- so
this reads the same files HealthManager itself reads/writes
(health_manager_snapshot.json, component_heartbeat.json, job_health.json,
feed_health.json) directly, same pattern mitigation_api.py's GET
/api/mitigation/state already uses (reads StateManager's on-disk state rather
than reaching into a live object across the process boundary).

health_manager_snapshot.json (HealthManager._write_snapshot_file(), written
once per check cycle) is what makes the console's Health view actually useful
-- without it, this endpoint could only ever see the two cross-process
heartbeats (api_subprocess/scheduler_subprocess) and the raw job/feed files,
with zero visibility into resource-pressure level, the in-process components
(pipeline_main_loop/identity_reconcile_worker/ti_refresh, whose heartbeats
live only in the OTHER process's in-memory HEARTBEATS singleton), or any
state-machine state (HEALTHY/DEGRADED/UNHEALTHY/SAFE_MODE) at all.

Read-only in this phase -- no POST /api/health/recover yet. Triggering a
recovery action on a live HealthManager instance running in a different
process is a second IPC problem (the existing .ipc_sync_signal file mechanism
solves the analogous problem for IPS state), deliberately deferred.
"""
import json
from pathlib import Path

from fastapi import APIRouter, Depends

from middleware.auth import verify_token, CONFIG

router = APIRouter()


def _state_dir() -> Path:
    return Path(CONFIG.get("state_path", "state/ids_state.json")).parent


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


@router.get("/api/health/status")
def get_health_status(token: str = Depends(verify_token)) -> dict:
    state_dir = _state_dir()
    from core.runtime_paths import runtime_dir
    snapshot = _read_json(runtime_dir(state_dir) / "health_manager_snapshot.json")
    component_heartbeats = _read_json(state_dir / "component_heartbeat.json")
    job_health = _read_json(state_dir / "job_health.json")
    feed_health = _read_json(state_dir / "feed_health.json")
    return {
        "health_manager_enabled": bool(CONFIG.get("health_manager_enabled", True)),
        # pressure_level/rss_mb/auto_recovery_enabled/components (state machine,
        # including the in-process components) -- empty until the health manager's
        # first check cycle has written it at least once (e.g. mid-restart).
        "snapshot": snapshot,
        "component_heartbeats": component_heartbeats,
        "job_health": job_health,
        "feed_health": feed_health,
    }
