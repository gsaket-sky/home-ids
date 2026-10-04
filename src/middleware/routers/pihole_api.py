import json
import threading
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Depends
from pathlib import Path

from middleware.auth import verify_token, CONFIG, LOGGER
from core.state_guard import StateManager
from mitigation.ips import IPSMitigator
from argus.cl_afpe.engine import ClAfpeEngine
from argus.graph.store import GraphStore

router = APIRouter()

class IPCTargetRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP")

# The CL-AFPE engine behind the operator actions below (mark safe / not a threat, revoke, approve tune-down) and the
# graph store for the operator_actions audit rows, on the same graph db the engine uses. One of each PER THREAD: the
# endpoints are plain `def`s that FastAPI runs on its worker-thread pool, and a sqlite3 connection may only be used by
# the thread that opened it -- a single shared instance failed every request that landed on another thread (found
# 2026-10-03). Tests may set `_test_cl_afpe` / `_test_operator_store` to pin instances.
_thread_local = threading.local()
_test_cl_afpe: Optional[ClAfpeEngine] = None
_test_operator_store: Optional[GraphStore] = None


def _graph_db_path() -> str:
    return str(Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "v13_graph.db")


def _get_argus_cl_afpe_engine() -> ClAfpeEngine:
    if _test_cl_afpe is not None:
        return _test_cl_afpe
    engine = getattr(_thread_local, "cl_afpe", None)
    if engine is None or engine.store.db_path != _graph_db_path():
        engine = _thread_local.cl_afpe = ClAfpeEngine(GraphStore(_graph_db_path()))
    return engine


def _get_graph_store_for_operator_actions() -> GraphStore:
    if _test_operator_store is not None:
        return _test_operator_store
    store = getattr(_thread_local, "operator_store", None)
    if store is None or store.db_path != _graph_db_path():
        store = _thread_local.operator_store = GraphStore(_graph_db_path())
    return store

def _record_operator_action(entry: Optional[Dict[str, Any]], action: str, result: Dict[str, Any]) -> None:
    """Best-effort write of one operator_actions row, IF the ledger entry this
    Telegram tap responded to carries an alert_event_id (see pipeline.py's
    "published_alert" ledger comment for when it does/doesn't -- immunize/revoke
    always do, since they're action_id-addressed against a specific published
    alert; approve/release/block operate on a raw target string instead, with no
    single alert_event to attribute the tap to, so this is a no-op for those,
    not a bug). Never raises -- an operator's Telegram tap must succeed/fail on
    its own real effect (unblock, correction, etc.), never on this audit write."""
    alert_event_id = (entry or {}).get("extra", {}).get("alert_event_id")
    if not alert_event_id:
        return
    try:
        _get_graph_store_for_operator_actions().insert_operator_action(
            alert_event_id, action, result=result)
    except Exception as exc:
        LOGGER.warning("Failed to record operator_action (%s) for alert_event %r: %s",
                        action, alert_event_id, exc)

@router.post("/api/ipc/immunize")
def ipc_immunize(payload: IPCTargetRequest, token: str = Depends(verify_token)):
    return _ipc_immunize_logic(payload.target)

@router.get("/api/ipc/immunize_get")
def ipc_immunize_get(target: str, token: str = Depends(verify_token)):
    return _ipc_immunize_logic(target)

def _looks_like_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ipc_immunize_logic(action_id: str):
    """PHASE 6 (operator-driven self-healing, closed loop): IPC endpoint for the "🛡️ Mark
    False Positive" Telegram button on a published alert. `action_id` refers to the
    "published_alert" ledger entry pipeline.py records for every alert it sends —
    mirrors _ipc_revoke_logic()'s action_id convention below rather than taking a raw
    domain string directly (the earlier design), for three concrete reasons this rewrite
    fixes:

      1. BLAST RADIUS: the earlier version reset fp_count/has_validated_threat on EVERY
         tracked device instead of just the one device the alert was actually about —
         because it never had a device_id to scope to, only a domain. The ledger entry
         carries device_id, so this now touches exactly one device.
      2. TRAINING LOOP: the earlier version never told the FP-classifier retrain pipeline
         about the correction, so train_fp_classifier.py's weekly retrain kept treating
         this exact alert as a confirmed threat (label=0) forever. Delegates to
         fp.mark_false_positive(), which writes a properly-labeled correction sample.
      3. UNBLOCK: the earlier version never reversed an active Pi-hole block on the
         domain, so a device already blocked over the (now-corrected) false positive
         stayed blocked. Calls the already-existing IPSMitigator.unblock_domain().
    """
    LOGGER.info("Received IPC immunize (mark-false-positive) request for action_id: %s", action_id)
    try:
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()

        entry = sm.get_action(action_id)
        if not entry or entry.get("type") != "published_alert":
            raise HTTPException(status_code=404, detail=f"Alert action '{action_id}' not found or expired.")

        target = entry.get("target", "unknown")
        device_id = entry.get("device_id", "unknown")
        alert_payload = entry.get("extra", {}).get("alert_payload", {}) or {}

        return _apply_operator_correction(alert_payload, device_id, target, entry, {"action_id": action_id})
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error("IPC immunize failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

def _apply_operator_correction(alert_payload: dict, device_id: str, target: str,
                               record_entry: Optional[Dict[str, Any]], ref: Dict[str, Any]) -> Dict[str, Any]:
    """An operator's "this is not a threat" for one alert, from Telegram or the web UI: the CL-AFPE correction, the
    device's fp_count, any Pi-hole block under the corrected domain, and the operator_actions audit row."""
    state_path = CONFIG.get("state_path", "state/ids_state.json")
    sm = StateManager(state_path=state_path)
    sm.load_from_disk()
    # CL-AFPE records the correction (trust edge, per-device threshold, sensitivity shift, training record).
    # It refuses hard-stop/verifiable-fact alerts (decoy, ARP spoofing, geofencing, confirmed exploit, tier-5
    # IOC) -- those must not fall through to the fp_count reset / Pi-hole unblock below.
    result = _get_argus_cl_afpe_engine().mark_false_positive(alert_payload, source="operator")
    if result.refused:
        return {
            "status": "refused",
            **ref,
            "reason": result.refused_reason or "Cannot mark this alert as a false positive.",
            "device_id": device_id,
        }
    immunized = result.immunized_destination or ""
    base_domain = "" if _looks_like_ip(immunized) else immunized

    # FIX #1 (blast radius): only the device this specific alert was about, not every
    # tracked device on the network.
    if device_id and device_id != "unknown" and sm.has_device(device_id):
        with sm.lock_device(device_id) as state:
            state.fp_count = getattr(state, "fp_count", 0) + 1
            state.has_validated_threat = False
    else:
        LOGGER.warning(
            "Operator correction: device_id '%s' (%s) no longer tracked — "
            "skipping per-device fp_count/has_validated_threat update (domain "
            "immunization + training correction still applied).", device_id, ref
        )

    # FIX #3 (unblock): undo any active Pi-hole block on the immunized domain.
    # PHASE 16 FIX: was a single unblock_domain(base_domain) call -- but Pi-hole
    # blocks are keyed by the specific queried FQDN, which is almost always a
    # subdomain of base_domain, not base_domain literally (e.g. immunizing
    # 'samsungapps.com' never touched an actual block on 'vas.samsungapps.com').
    # unblock_by_base_domain() sweeps every blocked entry under this base domain.
    unblocked_domains = []
    if base_domain:
        try:
            ips = IPSMitigator(config=CONFIG, state_manager=sm, start_workers=False)
            unblocked_domains = ips.unblock_by_base_domain(base_domain)
        except Exception as exc:
            LOGGER.warning("Failed to unblock domain(s) under '%s' after FP mark: %s", base_domain, exc)
    unblocked = bool(unblocked_domains)

    sm.flush_to_disk()
    Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
    _record_operator_action(record_entry, "immunize", {
        "immunized": immunized or target, "unblocked": unblocked,
    })
    return {
        "status": "success",
        **ref,
        "immunized": immunized or target,
        "device_id": device_id,
        "unblocked": unblocked,
    }


@router.post("/api/ipc/incident/{incident_id}/not_a_threat")
def ipc_incident_not_a_threat(incident_id: str, token: str = Depends(verify_token)):
    """The web UI's "Not a threat" on an incident: the same correction as the Telegram button, applied to the
    incident's newest alert (graph alert_events), so it works for alerts that never went to Telegram."""
    LOGGER.info("Received IPC not-a-threat request for incident: %s", incident_id)
    try:
        row = _get_graph_store_for_operator_actions()._conn.execute(
            "SELECT alert_event_id, device_id, alert_payload_json FROM alert_events WHERE incident_id = ? "
            "ORDER BY timestamp DESC LIMIT 1", (incident_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
        try:
            alert_payload = json.loads(row["alert_payload_json"] or "{}")
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="The incident's alert record is unreadable.")
        ctx = alert_payload.get("network_context", {}) or {}
        target = ctx.get("queried_domain") or ctx.get("destination_ip") or "unknown"
        return _apply_operator_correction(alert_payload, row["device_id"] or "unknown", target,
                                          {"extra": {"alert_event_id": row["alert_event_id"]}},
                                          {"incident_id": incident_id})
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error("IPC not-a-threat failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/ipc/revoke")
def ipc_revoke(payload: IPCTargetRequest, token: str = Depends(verify_token)):
    # NOTE: reuses IPCTargetRequest — for revoke, the Telegram callback's parsed `target`
    # IS the action_id (see mitigation/alerts.py's `elif action == "revoke":` branch).
    return _ipc_revoke_logic(payload.target)

@router.get("/api/ipc/revoke_get")
def ipc_revoke_get(target: str, token: str = Depends(verify_token)):
    return _ipc_revoke_logic(target)

def _ipc_revoke_logic(action_id: str):
    """PHASE 3 (closed-loop autonomous actions): reverses a previously-recorded
    autonomous action (currently only immunize_domain). This is the human-in-the-loop
    half of the closed loop — the system acted immediately and non-blockingly, an
    operator can undo it with one tap, and the undo teaches the system to be more
    cautious about that device going forward (sigma_shift TUNE_UP + has_validated_threat)
    rather than just silently reverting one decision."""
    LOGGER.info("Received IPC revoke request for action_id: %s", action_id)
    try:
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()

        entry = sm.revoke_action(action_id)
        if not entry:
            raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found, already revoked, or expired.")

        result = {"status": "success", "action_id": action_id, "type": entry.get("type"), "target": entry.get("target")}

        if entry.get("type") == "immunize_domain":
            _get_argus_cl_afpe_engine().revoke(entry.get("target", ""))

        device_id = entry.get("device_id", "")
        if device_id and sm.has_device(device_id):
            with sm.lock_device(device_id) as state:
                state.has_validated_threat = True
                state.confirmed_threat_count = getattr(state, "confirmed_threat_count", 0) + 1

        sm.flush_to_disk()
        Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
        return result
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error("IPC revoke failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/ipc/block_domain_get")
def ipc_block_domain_get(target: str, token: str = Depends(verify_token)):
    LOGGER.info("Received IPC block domain request for: %s", target)
    try:
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()
        
        ips = IPSMitigator(config=CONFIG, state_manager=sm, start_workers=False)
        # Block the domain specifically for pi-hole
        success = ips._block_domain(domain=target, hostname="grafana_manual", device_ip="unknown", dev_id="manual", reason="Operator explicitly blocked via Grafana")
        
        if success:
            sm.flush_to_disk()
            return {"status": "success", "blocked_domain": target}
        else:
            raise HTTPException(status_code=500, detail="Pi-hole block failed")
    except Exception as e:
        LOGGER.error("IPC block domain failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/ipc/approve_tune_down")
def ipc_approve_tune_down(payload: IPCTargetRequest, token: str = Depends(verify_token)):
    return _ipc_approve_tune_down_logic(payload.target)

@router.get("/api/ipc/approve_tune_down_get")
def ipc_approve_tune_down_get(target: str, token: str = Depends(verify_token)):
    return _ipc_approve_tune_down_logic(target)

def _ipc_approve_tune_down_logic(device_id: str):
    """Human-approval half of ollama_soc.py's IP-only-benign-verdict TUNE_DOWN
    routing (2026-09-10, AUDIT_V14_REVIEW_RESPONSE.md §2.3): an IP-only alert the
    LLM judges benign no longer applies _apply_sigma_shift(TUNE_DOWN) autonomously
    -- that's exactly the shape a crafted/ambiguous payload aimed at the LLM would
    produce, with no domain to anchor trust on. `device_id` here is the identifier
    directly, not an action_id -- mirrors fritzbox_api.py's own /api/ipc/block
    interactive-approval endpoint shape (no ledger entry needed, the identifier
    alone is enough to re-derive everything -- this device's current hostname, via
    StateManager)."""
    LOGGER.info("Received IPC approve-tune-down request for device_id: %s", device_id)
    try:
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()

        if not sm.has_device(device_id):
            return {"status": "not_found", "device_id": device_id}

        _get_argus_cl_afpe_engine()._apply_sigma_shift(device_id, direction="TUNE_DOWN", source="llm_pending_approval")

        ips = IPSMitigator(config=CONFIG, state_manager=sm, start_workers=False)
        released = ips.release_device(device_id)

        sm.flush_to_disk()
        Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
        return {"status": "success", "device_id": device_id, "released": released}
    except Exception as e:
        LOGGER.error("IPC approve-tune-down failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/ipc/release_domain_get")
def ipc_release_domain_get(target: str, token: str = Depends(verify_token)):
    LOGGER.info("Received IPC release domain request for: %s", target)
    try:
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()
        
        ips = IPSMitigator(config=CONFIG, state_manager=sm, start_workers=False)
        success = ips.unblock_domain(domain=target)
        
        if success:
            sm.flush_to_disk()
            return {"status": "success", "released_domain": target}
        else:
            raise HTTPException(status_code=500, detail="Pi-hole release failed")
    except Exception as e:
        LOGGER.error("IPC release domain failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
