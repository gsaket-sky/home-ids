"""
hunt_api.py -- thin HTTP wrappers around the real, already-built ad-hoc threat-hunting
functions in src/v13/ops/threat_hunt.py and decision_replay.py, backing the console's
Threat Hunt tab (previously sample data).

Deliberately thin, matching threat_hunt.py's own stated design ("three small functions
over GraphStore's own already-built read methods") -- this module adds no query logic
of its own beyond resolving a free-text destination search into exact destination_id(s)
first (get_devices_targeting() itself needs an exact match) and enriching device_ids
with a hostname for display.
"""
import time
import dataclasses
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from middleware.auth import verify_token, CONFIG
from middleware.graph_client import open_store
from middleware.humanize import label_evidence_type, label_hypothesis
from core.state_guard import StateManager
from v13.ops import threat_hunt, decision_replay

router = APIRouter()


def _since_from_days(since_days: Optional[float]) -> float:
    return time.time() - since_days * 86400 if since_days else 0.0


def _hostname_for(sm: StateManager, device_id: str) -> str:
    if sm.has_device(device_id):
        with sm.lock_device(device_id) as state:
            return state.hostname or "Unknown"
    return "Unknown"


def _evidence_to_dict(ev) -> dict:
    d = dataclasses.asdict(ev)
    d["type_label"], d["type_description"] = label_evidence_type(d.get("evidence_type", ""))
    return d


@router.get("/api/hunt/devices_touching")
def devices_touching(destination: str = Query(..., min_length=1),
                      since_days: Optional[float] = Query(None, ge=0),
                      token: str = Depends(verify_token)):
    since = _since_from_days(since_days)
    sm = StateManager(state_path=CONFIG.get("state_path", "state/ids_state.json"))
    sm.load_from_disk()

    with open_store() as store:
        if store is None:
            return {"destination_query": destination, "matched_destinations": [], "devices": []}
        matched = store.get_destinations_matching(destination)
        device_ids = set()
        for dest_id in matched:
            device_ids.update(threat_hunt.devices_touching(store, dest_id, since=since))
        devices = [{"device_id": d, "hostname": _hostname_for(sm, d)} for d in sorted(device_ids)]

    return {"destination_query": destination, "matched_destinations": matched, "devices": devices}


@router.get("/api/hunt/decision_timeline/{decision_id}")
def decision_timeline(decision_id: str, token: str = Depends(verify_token)):
    with open_store() as store:
        if store is None:
            raise HTTPException(status_code=404, detail="No graph database available.")
        result = threat_hunt.decision_timeline(store, decision_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No decision found with decision_id='{decision_id}'.")
    decision = dict(result["decision"])
    explanation = (decision.get("raw_payload") or {}).get("explanation")
    decision["explanation_label"], decision["explanation_description"] = label_hypothesis(explanation)
    return {
        "decision": decision,
        "evidence": [_evidence_to_dict(e) for e in result["evidence"]],
    }


@router.get("/api/hunt/device_history/{device_id}")
def device_history(device_id: str, since_days: Optional[float] = Query(None, ge=0),
                    token: str = Depends(verify_token)):
    since = _since_from_days(since_days)
    with open_store() as store:
        if store is None:
            raise HTTPException(status_code=404, detail="No graph database available.")
        result = threat_hunt.device_history(store, device_id, since=since)
    decisions = []
    for d in result["decisions"]:
        d = dict(d)
        explanation = (d.get("raw_payload") or {}).get("explanation")
        d["explanation_label"], d["explanation_description"] = label_hypothesis(explanation)
        decisions.append(d)
    return {
        "canonical_device_id": result["canonical_device_id"],
        "evidence": [_evidence_to_dict(e) for e in result["evidence"]],
        "decisions": decisions,
    }


@router.post("/api/hunt/replay/{decision_id}")
def replay_decision(decision_id: str, token: str = Depends(verify_token)):
    with open_store() as store:
        if store is None:
            raise HTTPException(status_code=404, detail="No graph database available.")
        decision = store.get_decision(decision_id)
        if decision is None:
            raise HTTPException(status_code=404, detail=f"No decision found with decision_id='{decision_id}'.")
        result = decision_replay.replay_decision(store, decision, decision_engine=None)
    return result
