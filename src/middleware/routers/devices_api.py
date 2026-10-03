"""
devices_api.py -- real device-list and device-detail endpoints for the console UI,
replacing its original sample data.

There is no persisted "current state/risk" anywhere in DeviceState/state/ids_state.json
(confirmed by direct inspection) -- the real source is each device's most recent argus
decision, the same way Grafana's own "Master Threat Ledger" panel already sources its
State/Risk columns (home_ids_decision_state / home_ids_threat_confidence gauges,
themselves populated from this same per-cycle decision). So a device's identity fields
(hostname, IP, MAC, known_ips, ja4_seen, dhcp_fingerprint) come from StateManager/
DeviceState, while its state/risk_score/confidence come from GraphStore's latest
decision -- two different sources for one device, merged here.

Top 10 domains (all-time) is deliberately NOT implemented here -- see the note in
get_device_detail()'s response. The argus evidence graph only stores evidence-worthy
events, not general query volume; that data lives in Pi-hole's own query log (same
source scripts/top_domains_report.py already uses, but only for a rolling 24h window).
"""
import os
import sqlite3
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from middleware.auth import verify_token, CONFIG, LOGGER
from middleware.graph_client import open_store
from core.state_guard import StateManager
from middleware.state_client import get_cached_state_manager

router = APIRouter()

TOP_DOMAINS_NOTE = (
    "Not available yet -- the evidence graph only stores evidence-worthy events, "
    "not general query volume, so an all-time top-domains-per-device view can't be "
    "built from it. The real data lives in Pi-hole's query log (same source "
    "scripts/top_domains_report.py already uses, but only for a rolling 24h window) -- "
    "an all-time version needs a new persistent aggregation, separate follow-up work."
)


def _load_state_manager() -> StateManager:
    # Cached, mtime-invalidated -- see state_client.py's own docstring (chronic
    # console latency, found live 2026-09-22: this endpoint is read-only, so a
    # freshly-restarted-instance-per-request here was pure waste).
    return get_cached_state_manager(CONFIG.get("state_path", "state/ids_state.json"))


def _identity_dict(sm: StateManager, device_id: str) -> Optional[Dict[str, Any]]:
    if not sm.has_device(device_id):
        return None
    with sm.lock_device(device_id) as state:
        return state.to_dict()


def _containment_for(ips_state: Dict[str, Any], ip: str, mac: str, dev_id: str) -> Dict[str, Any]:
    """Pure read of the same tarpit/router/domain dicts IPSMitigator.get_containment_status()
    inspects, WITHOUT instantiating IPSMitigator (that constructor spins up background
    threads -- wrong for something computed on every device list/detail request). Mirrors
    that method's own ip/mac/dev_id fallback matching."""
    tarpit = ips_state.get("tarpit_targets", {})
    router_isolated = ips_state.get("router_isolated_devices", {})
    blocked_domains = ips_state.get("blocked_domains", {})

    tarpitted = ip in tarpit or any(m.get("dev_id") == dev_id for m in tarpit.values())
    router_flag = (mac and mac != "unknown" and mac in router_isolated) or any(
        m.get("dev_id") == dev_id for m in router_isolated.values()
    )
    blocked_domain_count = sum(
        1 for m in blocked_domains.values()
        if m.get("device_id") == dev_id or (ip and ip != "unknown" and m.get("device_ip") == ip)
    )
    return {"tarpitted": bool(tarpitted), "router_isolated": bool(router_flag), "blocked_domain_count": blocked_domain_count}


@router.get("/api/devices")
def list_devices(token: str = Depends(verify_token)):
    sm = _load_state_manager()
    ips_state = sm.get_ips_state()
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
            "containment": _containment_for(ips_state, (ds or {}).get("client_ip", ""), (ds or {}).get("mac_address", "unknown"), device_id),
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
            "containment": _containment_for(ips_state, ds.get("client_ip", ""), ds.get("mac_address", "unknown"), device_id),
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

    ips_state = sm.get_ips_state()
    client_ip = identity.get("client_ip", "")
    mac_address = identity.get("mac_address", "unknown")
    blocked_domains = [
        {"domain": domain, "reason": meta.get("comment", ""), "blocked_at": meta.get("timestamp")}
        for domain, meta in ips_state.get("blocked_domains", {}).items()
        if meta.get("device_id") == canonical_id or (client_ip and meta.get("device_ip") == client_ip)
    ]

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
        "client_ip": client_ip,
        "mac_address": mac_address,
        "known_ips": identity.get("known_ips", []),
        "ja4_seen": identity.get("ja4_seen", []),
        "dhcp_fingerprint": identity.get("dhcp_fingerprint"),
        "confirmed_threat_count": identity.get("confirmed_threat_count", 0),
        "fp_count": identity.get("fp_count", 0),
        "merges": merges,
        "containment": _containment_for(ips_state, client_ip, mac_address, canonical_id),
        "blocked_domains": blocked_domains,
        "top_domains_available": False,
        "top_domains_note": TOP_DOMAINS_NOTE,
    }


_PIHOLE_QUERY_TIMEOUT_SECONDS = 5.0


@router.get("/api/devices/{device_id}/top_domains")
def get_device_top_domains(device_id: str, hours: int = 24, token: str = Depends(verify_token)):
    """On-demand, per-device top-10-domains, reusing the exact query
    scripts/top_domains_report.py already runs against Pi-hole's own query log --
    just scoped to one device's known IPs and run live instead of as a scheduled
    all-device report. Deliberately NOT the "all-time" view TOP_DOMAINS_NOTE above
    says isn't available -- this is honestly a rolling window, same as that script.
    Skips ThreatIntel tagging (the scheduled report's job, not this hot path's) to
    keep this fast enough to call from a device-detail page load."""
    sm = _load_state_manager()
    identity = _identity_dict(sm, device_id)
    if identity is None:
        raise HTTPException(status_code=404, detail=f"No such device '{device_id}'.")
    client_ips = list({identity.get("client_ip")} | set(identity.get("known_ips", []) or []))
    client_ips = [ip for ip in client_ips if ip and ip != "unknown"]
    if not client_ips:
        return {"domains": [], "window_hours": hours, "note": "No known IP address on record for this device yet."}

    db_path = CONFIG.get("pihole_db", "/etc/pihole/pihole-FTL.db")
    if not os.path.exists(db_path):
        raise HTTPException(status_code=503, detail=f"Pi-hole database not found at {db_path} -- is Pi-hole running on this host?")

    since_ts = time.time() - hours * 3600
    placeholders = ",".join("?" for _ in client_ips)
    try:
        with sqlite3.connect(db_path, timeout=_PIHOLE_QUERY_TIMEOUT_SECONDS) as conn:
            cur = conn.execute(
                f"SELECT domain, COUNT(*) AS n FROM queries WHERE client IN ({placeholders}) "
                f"AND timestamp > ? AND type = 1 GROUP BY domain ORDER BY n DESC LIMIT 10",
                (*client_ips, since_ts),
            )
            rows = [{"domain": domain, "count": count} for domain, count in cur.fetchall()]
    except Exception as exc:
        LOGGER.error("top_domains query failed for device %s: %s", device_id, exc)
        raise HTTPException(status_code=502, detail=f"Pi-hole query failed: {exc}")

    return {
        "domains": rows,
        "window_hours": hours,
        "note": f"Last {hours}h, via Pi-hole's query log (client IPs: {', '.join(client_ips)}).",
    }
