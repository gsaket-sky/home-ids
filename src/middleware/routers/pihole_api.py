from typing import Dict, Any
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Depends
from pathlib import Path

from middleware.auth import verify_token, CONFIG, LOGGER
from core.state_guard import StateManager
from mitigation.ips import IPSMitigator
from intelligence.fp_engine import AutonomousFPEngine

router = APIRouter()

class IPCTargetRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP")

@router.post("/api/ipc/immunize")
def ipc_immunize(payload: IPCTargetRequest, token: str = Depends(verify_token)):
    return _ipc_immunize_logic(payload.target)

@router.get("/api/ipc/immunize_get")
def ipc_immunize_get(target: str, token: str = Depends(verify_token)):
    return _ipc_immunize_logic(target)

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
        hostname = entry.get("hostname", "unknown")
        alert_payload = entry.get("extra", {}).get("alert_payload", {}) or {}

        fp = AutonomousFPEngine(config=CONFIG, state_dir=str(Path(state_path).parent))
        result = fp.mark_false_positive(alert_payload, hostname, target)

        # BUGFIX: mark_false_positive() now refuses hard-stop/verifiable-fact alerts
        # (honeypot, arp_spoofing, geofencing, confirmed exploit, tier-5 confirmed IOC)
        # outright -- must not fall through to the blast-radius fp_count reset / Pi-hole
        # unblock below when it did, or a refused correction would still silently
        # unblock a genuinely malicious domain.
        if result.get("refused"):
            return {
                "status": "refused",
                "action_id": action_id,
                "reason": result.get("refused_reason", "Cannot mark this alert as a false positive."),
                "device_id": device_id,
            }

        # FIX #1 (blast radius): only the device this specific alert was about, not every
        # tracked device on the network.
        if device_id and device_id != "unknown" and sm.has_device(device_id):
            with sm.lock_device(device_id) as state:
                state.fp_count = getattr(state, "fp_count", 0) + 1
                state.has_validated_threat = False
        else:
            LOGGER.warning(
                "IPC immunize: device_id '%s' from action '%s' no longer tracked — "
                "skipping per-device fp_count/has_validated_threat update (domain "
                "immunization + training correction still applied).", device_id, action_id
            )

        # FIX #3 (unblock): undo any active Pi-hole block on the immunized domain.
        # PHASE 16 FIX: was a single unblock_domain(base_domain) call -- but Pi-hole
        # blocks are keyed by the specific queried FQDN, which is almost always a
        # subdomain of base_domain, not base_domain literally (e.g. immunizing
        # 'samsungapps.com' never touched an actual block on 'vas.samsungapps.com').
        # unblock_by_base_domain() sweeps every blocked entry under this base domain.
        unblocked_domains = []
        base_domain = result.get("base_domain", "")
        if base_domain:
            try:
                ips = IPSMitigator(config=CONFIG, state_manager=sm)
                unblocked_domains = ips.unblock_by_base_domain(base_domain)
            except Exception as exc:
                LOGGER.warning("Failed to unblock domain(s) under '%s' after FP mark: %s", base_domain, exc)
        unblocked = bool(unblocked_domains)

        sm.flush_to_disk()
        Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
        return {
            "status": "success",
            "action_id": action_id,
            "immunized": base_domain or result.get("domain", target),
            "device_id": device_id,
            "unblocked": unblocked,
        }
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error("IPC immunize failed: %s", e)
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
            fp = AutonomousFPEngine(config=CONFIG, state_dir=str(Path(state_path).parent))
            fp.revoke_immunization(entry.get("target", ""))

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
        
        ips = IPSMitigator(config=CONFIG, state_manager=sm)
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

@router.get("/api/ipc/release_domain_get")
def ipc_release_domain_get(target: str, token: str = Depends(verify_token)):
    LOGGER.info("Received IPC release domain request for: %s", target)
    try:
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()
        
        ips = IPSMitigator(config=CONFIG, state_manager=sm)
        success = ips.unblock_domain(domain=target)
        
        if success:
            sm.flush_to_disk()
            return {"status": "success", "released_domain": target}
        else:
            raise HTTPException(status_code=500, detail="Pi-hole release failed")
    except Exception as e:
        LOGGER.error("IPC release domain failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
