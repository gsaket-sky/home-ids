"""
webui_ipc.py - loopback-only IPC endpoints backing the WebUI's health/
maintenance panels (PRODUCTIZATION_ROADMAP.md Phase 4). Same trust boundary as
pihole_api.py/fritzbox_api.py -- verify_token()'s Bearer-token-or-loopback-
source gate -- and the same "construct a fresh StateManager from disk, mutate,
flush, touch the IPC sentinel" pattern those routers already use (this process
never shares live memory with the main pipeline loop; that's what the sentinel
file + pipeline.py's reconcile_ips_from_disk() is for).

Every subprocess this file can launch comes from a small, fixed whitelist --
`name` in the URL is never used to build a path directly. This is the entire
security boundary for /run_script/{name}, so treat any change to
_RUNNABLE_SCRIPTS as security-relevant.
"""
import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from middleware.auth import verify_token, CONFIG
from core.state_guard import StateManager
from core.device_labels import remove_label

LOGGER = logging.getLogger("home_ids.webui_ipc")

router = APIRouter()

_SRC_DIR = Path(__file__).resolve().parent.parent.parent

# name -> (relative path from src/, supports --apply flag)
_RUNNABLE_SCRIPTS = {
    # Scheduled jobs (health panel's "Run Now")
    "live_llm_review": ("argus/ops/live_llm_review.py", False),  # replaced ollama_soc upstream
    "live_retro_hunter": ("argus/ops/live_retro_hunter.py", False),  # replaced retro_hunter upstream
    "top_domains_report": ("scripts/top_domains_report.py", False),
    "train_fp_classifier": ("scripts/train_fp_classifier.py", False),
    # Ops-hygiene scripts (maintenance panel's "Preview"/"Apply")
    "audit_stale_multi_device_iocs": ("audit_stale_multi_device_iocs.py", True),
    "clean_confirmed_intel": ("clean_confirmed_intel.py", True),
    # clear_stale_isolation.py is not here: it needs a device argument (CLI only); Release on Devices covers it.
    "identify_corrupted_training_rows": ("identify_corrupted_training_rows.py", True),
    "release_wrongly_blocked_domains": ("release_wrongly_blocked_domains.py", True),
    "merge_fragmented_devices": ("merge_fragmented_devices.py", True),
}

_RUN_TIMEOUT_SECONDS = 300.0


@router.post("/api/ipc/run_script/{name}")
def ipc_run_script(name: str, apply: bool = False, token: str = Depends(verify_token)):
    """Runs one whitelisted script to completion and returns its output. Used both
    for a scheduled job's manual "Run Now" and an ops-hygiene script's "Preview"/
    "Apply" (apply=false/true)."""
    entry = _RUNNABLE_SCRIPTS.get(name)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"'{name}' is not a runnable script")
    rel_path, supports_apply = entry
    if apply and not supports_apply:
        raise HTTPException(status_code=400, detail=f"'{name}' does not support --apply")

    script_path = _SRC_DIR / rel_path
    if not script_path.is_file():
        raise HTTPException(status_code=500, detail=f"Script file missing on disk: {rel_path}")

    cmd = [sys.executable, str(script_path)]
    if apply:
        cmd.append("--apply")

    LOGGER.info("WebUI-triggered script run: %s (apply=%s)", name, apply)
    try:
        result = subprocess.run(
            cmd, cwd=str(_SRC_DIR.parent), capture_output=True, text=True,
            timeout=_RUN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail=f"'{name}' did not finish within {_RUN_TIMEOUT_SECONDS:.0f}s")

    return {
        "name": name,
        "apply": apply,
        "exit_code": result.returncode,
        "stdout": result.stdout[-20000:],  # cap response size against a runaway script
        "stderr": result.stderr[-5000:],
    }


@router.post("/api/ipc/device/{device_id}/purge")
def ipc_purge_device(device_id: str, token: str = Depends(verify_token)):
    """Permanently forgets a device's tracked profile -- the WebUI Maintenance
    page's "Remove Device" action. Removes the StateManager entry plus its
    learned false-positive values in the graph (per-device thresholds, sensitivity
    shift, confirmed-threat counts) and its label, so nothing points at a device_id
    that no longer exists. Irreversible for that device's learned history."""
    state_path = CONFIG.get("state_path", "state/ids_state.json")
    state_dir = str(Path(state_path).parent)
    sm = StateManager(state_path=state_path)
    sm.load_from_disk()

    if not sm.has_device(device_id):
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not tracked")

    sm.remove_device(device_id)
    sm.flush_to_disk()

    # Best-effort: never fatal to the purge itself.
    _purge_learned_fp_values(state_dir, device_id)
    remove_label(device_id, state_dir)

    Path(state_dir).joinpath(".ipc_sync_signal").touch()
    return {"status": "success", "device_id": device_id, "purged": True}


def _purge_learned_fp_values(state_dir: str, device_id: str) -> None:
    from argus.graph.store import GraphStore
    try:
        store = GraphStore(str(Path(state_dir) / "v13_graph.db"))
        try:
            if store.get_device_metadata(device_id):
                store.update_device_metadata(
                    device_id, {"fp_profile": {}, "sigma_shift": 0.0, "confirmed_threat_counts": {}})
        finally:
            store.close()
    except Exception as exc:
        LOGGER.warning("Clearing learned false-positive values for %s failed (non-fatal): %s", device_id, exc)


@router.post("/api/ipc/restart_pipeline")
def ipc_restart_pipeline(token: str = Depends(verify_token)):
    """Graceful self-exit -- relies on docker-compose.yml's `restart: unless-stopped`
    (already set on the pipeline service) to bring the process back up with newly
    written secrets (state/webui_secrets.env, see config.py) loaded. Used by the
    WebUI's threat-intel/GeoIP setup wizard after saving restart-required API keys.
    Responds success BEFORE actually exiting, since the exit itself tears down this
    same HTTP response's connection."""
    import os
    import threading

    LOGGER.warning("🔄 Restart requested via WebUI -- exiting for the container "
                    "supervisor to restart this process with reloaded secrets.")

    def _delayed_exit():
        import time
        time.sleep(0.5)  # let the HTTP response actually flush to the caller first
        os._exit(0)

    threading.Thread(target=_delayed_exit, daemon=True).start()
    return {"status": "restarting"}
