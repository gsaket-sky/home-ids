"""
devices_api.py -- real device-list and device-detail endpoints for the console UI,
replacing its original sample data.

There is no persisted "current state/risk" anywhere in DeviceState/state/ids_state.json
(confirmed by direct inspection) -- the real source is each device's most recent v13
decision, the same way Grafana's own "Master Threat Ledger" panel already sources its
State/Risk columns (home_ids_decision_state / home_ids_threat_confidence gauges,
themselves populated from this same per-cycle decision). So a device's identity fields
(hostname, IP, MAC, known_ips, ja4_seen, dhcp_fingerprint) come from StateManager/
DeviceState, while its state/risk_score/confidence come from GraphStore's latest
decision -- two different sources for one device, merged here.

Top 10 domains (all-time) is deliberately NOT implemented here -- see the note in
get_device_detail()'s response. The v13 evidence graph only stores evidence-worthy
events, not general query volume; that data lives in Pi-hole's own query log (same
source scripts/top_domains_report.py already uses, but only for a rolling 24h window).
"""
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from middleware.auth import verify_token, CONFIG
from middleware.graph_client import open_store
from core.state_guard import StateManager

router = APIRouter()

TOP_DOMAINS_NOTE = (
    "Not available yet -- the v13 evidence graph only stores evidence-worthy events, "
    "not general query volume, so an all-time top-domains-per-device view can't be "
    "built from it. The real data lives in Pi-hole's query log (same source "
    "scripts/top_domains_report.py already uses, but only for a rolling 24h window) -- "
    "an all-time version needs a new persistent aggregation, separate follow-up work."
)


def _load_state_manager() -> StateManager:
    sm = StateManager(state_path=CONFIG.get("state_path", "state/ids_state.json"))
    sm.load_from_disk()
    return sm


def _identity_dict(sm: StateManager, device_id: str) -> Optional[Dict[str, Any]]:
    if not sm.has_device(device_id):
        return None
    with sm.lock_device(device_id) as state:
        return state.to_dict()


@router.get("/api/devices")
def list_devices(token: str = Depends(verify_token)):
    sm = _load_state_manager()
    with open_store() as store:
        graph_rows = store.get_devices_with_latest_decision() if store else []

    devices = []
    seen_ids = set()
    for row in graph_rows:
        device_id = row["device_id"]
        seen_ids.add(device_id)
        ds = _identity_dict(sm, device_id)
        devices.append({
            "device_id": device_id,
            "hostname": (ds or {}).get("hostname") or row["display_label"] or "Unknown",
            "ip": (ds or {}).get("client_ip", ""),
            "mac": (ds or {}).get("mac_address", "unknown"),
            "device_type": (ds or {}).get("device_type") or row["device_type"] or "unknown",
            "device_type_is_override": (ds or {}).get("device_type_is_override", False),
            "first_seen": row["first_seen"],
            "last_seen": (ds or {}).get("last_seen") or row["last_seen"],
            "state": row["state"],
            "risk_score": row["risk_score"],
            "confidence": row["confidence"],
            "decision_id": row["decision_id"],
            "decision_timestamp": row["decision_timestamp"],
            "has_graph_history": True,
        })

    # Devices StateManager knows about but with no graph decision/device row yet
    # (e.g. cold-started this cycle, no evaluation has run for it) -- still worth
    # listing rather than silently hiding.
    for device_id in sm.get_all_device_ids():
        if device_id in seen_ids:
            continue
        ds = _identity_dict(sm, device_id) or {}
        devices.append({
            "device_id": device_id,
            "hostname": ds.get("hostname") or "Unknown",
            "ip": ds.get("client_ip", ""),
            "mac": ds.get("mac_address", "unknown"),
            "device_type": ds.get("device_type") or "unknown",
            "device_type_is_override": ds.get("device_type_is_override", False),
            "first_seen": None,
            "last_seen": ds.get("last_seen"),
            "state": None,
            "risk_score": None,
            "confidence": None,
            "decision_id": None,
            "decision_timestamp": None,
            "has_graph_history": False,
        })

    devices.sort(key=lambda d: d["last_seen"] or 0, reverse=True)
    return {"devices": devices}


@router.get("/api/devices/{device_id}")
def get_device_detail(device_id: str, token: str = Depends(verify_token)):
    sm = _load_state_manager()
    graph_meta = None
    merges = []
    with open_store() as store:
        canonical_id = store.resolve_canonical_device_id(device_id) if store else device_id
        if store:
            rows = store.get_devices_with_latest_decision()
            graph_meta = next((r for r in rows if r["device_id"] == canonical_id), None)
            merge_edges = store.get_edges(relation="merged_into", dst_kind="device", dst_id=canonical_id)
            merges = [{"prior_device_id": e["src_id"], "timestamp": e["timestamp"]} for e in merge_edges]

    identity = _identity_dict(sm, canonical_id) or {}
    if not identity and graph_meta is None:
        raise HTTPException(status_code=404, detail=f"No such device '{device_id}'.")

    return {
        "device_id": canonical_id,
        "hostname": identity.get("hostname") or (graph_meta or {}).get("display_label") or "Unknown",
        "device_type": identity.get("device_type") or (graph_meta or {}).get("device_type") or "unknown",
        "device_type_is_override": identity.get("device_type_is_override", False),
        "first_seen": (graph_meta or {}).get("first_seen"),
        "last_seen": identity.get("last_seen") or (graph_meta or {}).get("last_seen"),
        "state": (graph_meta or {}).get("state"),
        "risk_score": (graph_meta or {}).get("risk_score"),
        "confidence": (graph_meta or {}).get("confidence"),
        "mac_address": identity.get("mac_address", "unknown"),
        "known_ips": identity.get("known_ips", []),
        "ja4_seen": identity.get("ja4_seen", []),
        "dhcp_fingerprint": identity.get("dhcp_fingerprint"),
        "confirmed_threat_count": identity.get("confirmed_threat_count", 0),
        "fp_count": identity.get("fp_count", 0),
        "merges": merges,
        "top_domains_available": False,
        "top_domains_note": TOP_DOMAINS_NOTE,
    }
