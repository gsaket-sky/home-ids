"""
autonomy_api.py -- console visibility into the two live, autonomous,
threshold-changing systems that had NO console surface at all until now
(2026-09-15, console/health audit): the closed-loop autotuner
(argus/autotune/engine.py) and composite trust (argus/cl_afpe/composite_trust.py).
User's own framing: "it should be clear what has happened and how it is tuned
up or down."

Both event logs already exist and are complete, self-explaining, and require
NO new instrumentation:
- threshold_history (GraphStore.get_recent_threshold_history()): every
  autotuner proposal, with old_value/new_value/reason/canary/promotion/
  rollback timestamps already recorded.
- the graph's own `trusts` edges (GraphStore.get_edges(relation='trusts')):
  every corroboration-driven auto-resolution, with a timestamp and a
  metadata.source field distinguishing HOW it was granted (operator tap vs.
  the autonomous Stage 2/3 ML path vs. the autonomous Stage 1b local-origin
  path vs. the original v1-to-Argus migration).
- cl_afpe_trust (GraphStore.get_recent_composite_trust()): the "still
  building trust, not yet resolved" counterpart -- tuples that have SOME
  corroboration but haven't crossed composite_trust.py's own suppression
  floor yet.

Runs in the console/API subprocess, read-only against the same graph DB the
main pipeline writes -- same open_store() pattern graph_api.py/devices_api.py
already use.
"""
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from middleware.auth import verify_token, CONFIG
from middleware.graph_client import open_store
from argus.autotune.engine import TUNABLE_PARAMETERS, _LESS_SENSITIVE_DIRECTION
from argus.cl_afpe.composite_trust import _SUPPRESSION_TRUST_FLOOR
from core.state_guard import StateManager

router = APIRouter()

# Human labels for the composite-trust `source` field -- same "don't leak
# internal jargon to the console" convention core/pipeline.py's own
# _EVIDENCE_FAMILY_LABELS/_on_config_reload-adjacent label dicts already use.
_TRUST_SOURCE_LABELS: Dict[str, str] = {
    "operator": "Marked false positive (Telegram/console)",
    "autonomous_stage23": "Autonomous (Stage 2/3 ML scoring)",
    "autonomous_local_origin": "Autonomous (local-origin auto-corroboration)",
    "migrated_from_v1": "Migrated from legacy trust store",
}


def _direction_label(parameter: str, old_value: float, new_value: float) -> str:
    """tightened (more sensitive) vs. loosened (less sensitive), using each
    parameter's own real-world semantics (_LESS_SENSITIVE_DIRECTION) -- NOT
    just "new > old", since a higher value means MORE sensitive for some
    parameters and LESS for others (e.g. bocpd_hazard_rate: lower = less
    sensitive)."""
    delta = new_value - old_value
    if delta == 0:
        return "unchanged"
    less_sensitive_direction = _LESS_SENSITIVE_DIRECTION.get(parameter, 1)
    moved_less_sensitive = (delta > 0) == (less_sensitive_direction > 0)
    return "loosened" if moved_less_sensitive else "tightened"


def _threshold_status(row: Dict[str, Any]) -> str:
    if row.get("rolled_back_at"):
        return "rolled_back"
    if row.get("promoted_at"):
        return "promoted"
    return "pending_canary"


def _serialize_threshold_history(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        parameter = row.get("parameter", "")
        old_value = float(row.get("old_value") or 0.0)
        new_value = float(row.get("new_value") or 0.0)
        out.append({
            "change_id": row.get("change_id"),
            "device_id": row.get("device_id"),
            # 2026-09-16, per-device/category autotuning plan: a row now has AT
            # MOST ONE of device_id/device_type set -- both None means global.
            "device_type": row.get("device_type"),
            "parameter": parameter,
            "old_value": old_value,
            "new_value": new_value,
            "direction": _direction_label(parameter, old_value, new_value),
            "reason": row.get("reason", ""),
            "proposed_at": row.get("proposed_at"),
            "canary_until": row.get("canary_until"),
            "promoted_at": row.get("promoted_at"),
            "rolled_back_at": row.get("rolled_back_at"),
            "status": _threshold_status(row),
            "bounds": TUNABLE_PARAMETERS.get(parameter),
        })
    return out


def _serialize_trust_grants(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for e in edges:
        meta = e.get("metadata") or {}
        source = meta.get("source", "unknown")
        out.append({
            "device_id": e.get("src_id"),
            "destination_id": e.get("dst_id"),
            "hypothesis": meta.get("hypothesis"),
            "source": source,
            "source_label": _TRUST_SOURCE_LABELS.get(source, source),
            "granted_at": e.get("timestamp"),
            "ttl_seconds": meta.get("ttl_seconds"),
        })
    return out


def _serialize_building_trust(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        trust_value = float(row.get("trust_value") or 0.0)
        out.append({
            "device_id": row.get("device_id"),
            "behavior_fingerprint": row.get("behavior_fingerprint"),
            "destination_class": row.get("destination_class"),
            "hypothesis": row.get("hypothesis_id"),
            "evidence_family": row.get("evidence_family"),
            "trust_value": trust_value,
            "trust_floor": _SUPPRESSION_TRUST_FLOOR,
            "progress_fraction": min(1.0, trust_value / _SUPPRESSION_TRUST_FLOOR) if _SUPPRESSION_TRUST_FLOOR else 0.0,
            "last_updated": row.get("last_updated"),
        })
    return out


@router.get("/api/autonomy")
def get_autonomy(limit: int = Query(50, ge=1, le=200), token: str = Depends(verify_token)):
    with open_store() as store:
        if store is None:
            return {"autotuner": [], "trust_grants": [], "building_trust": []}
        threshold_rows = store.get_recent_threshold_history(limit)
        trust_edges = store.get_edges(relation="trusts", limit_most_recent=limit)
        building_trust_rows = store.get_recent_composite_trust(limit)

    return {
        "autotuner": _serialize_threshold_history(threshold_rows),
        "trust_grants": _serialize_trust_grants(trust_edges),
        "building_trust": _serialize_building_trust(building_trust_rows),
    }


def _load_state_manager() -> StateManager:
    sm = StateManager(state_path=CONFIG.get("state_path", "state/ids_state.json"))
    sm.load_from_disk()
    return sm


def _resolve_hostname(sm: StateManager, device_id: str) -> str:
    """Same 'StateManager is the live hostname source, device_id is the last-resort
    fallback' convention devices_api.py's list_devices() already uses -- no need for
    a second, graph-side display_label lookup here since composite trust/autotuner
    data is only ever interesting for a device StateManager still actively tracks."""
    if device_id and device_id != "unattributed" and sm.has_device(device_id):
        with sm.lock_device(device_id) as st:
            hostname = st.hostname
            if hostname and hostname != "unknown":
                return hostname
    return device_id or "unattributed"


@router.get("/api/autonomy/devices")
def get_autonomy_by_device(limit: int = Query(200, ge=1, le=1000), token: str = Depends(verify_token)):
    """2026-09-16 (user request: "in autonomy, i want to see per device effect/
    status"): groups the SAME composite-trust data /api/autonomy already exposes
    by device, instead of one global timeline -- so "what has autonomy actually
    done for/about THIS device" is directly answerable per device, not something
    the operator has to eyeball out of a mixed-device event log.

    UPDATED same day (per-device/category autotuning plan, Documentation/
    PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md): autotuner threshold changes were
    global-only when this endpoint was first written (threshold_history.device_id
    was NULL for every real row) -- that plan implemented real device- and
    category-scoped tuning on top of the existing global tier, so each device's
    entry now also carries its own `autotuner` array (device-scoped changes
    only), and a sibling `by_category` list covers category-scoped changes the
    same way. Global-scope changes stay in the existing Autotuner Timeline panel
    (/api/autonomy) -- they apply to every device equally, so they don't belong
    in a per-device OR per-category breakdown.

    limit here bounds the RAW trust_grants/building_trust/threshold_history rows
    pulled from the graph before grouping (default 200, wider than
    /api/autonomy's own 50) -- grouping by device means a handful of very active
    devices could otherwise starve a real but quieter device's own history out
    of a small global cap."""
    with open_store() as store:
        if store is None:
            return {"devices": [], "by_category": []}
        trust_edges = store.get_edges(relation="trusts", limit_most_recent=limit)
        building_trust_rows = store.get_recent_composite_trust(limit)
        threshold_rows = store.get_recent_threshold_history(limit)

    sm = _load_state_manager()
    grants = _serialize_trust_grants(trust_edges)
    building = _serialize_building_trust(building_trust_rows)
    autotuner = _serialize_threshold_history(threshold_rows)

    by_device: Dict[str, Dict[str, Any]] = {}
    by_category: Dict[str, Dict[str, Any]] = {}

    def _bucket(device_id: str) -> Dict[str, Any]:
        if device_id not in by_device:
            by_device[device_id] = {
                "device_id": device_id,
                "hostname": _resolve_hostname(sm, device_id),
                "trust_grants": [],
                "building_trust": [],
                "autotuner": [],
                "last_activity_at": None,
            }
        return by_device[device_id]

    def _category_bucket(category: str) -> Dict[str, Any]:
        if category not in by_category:
            by_category[category] = {"device_type": category, "autotuner": [], "last_activity_at": None}
        return by_category[category]

    for g in grants:
        bucket = _bucket(g.get("device_id") or "unattributed")
        bucket["trust_grants"].append(g)
        ts = g.get("granted_at")
        if ts is not None and (bucket["last_activity_at"] is None or ts > bucket["last_activity_at"]):
            bucket["last_activity_at"] = ts

    for b in building:
        bucket = _bucket(b.get("device_id") or "unattributed")
        bucket["building_trust"].append(b)
        ts = b.get("last_updated")
        if ts is not None and (bucket["last_activity_at"] is None or ts > bucket["last_activity_at"]):
            bucket["last_activity_at"] = ts

    for a in autotuner:
        ts = a.get("proposed_at")
        if a.get("device_id"):
            bucket = _bucket(a["device_id"])
            bucket["autotuner"].append(a)
            if ts is not None and (bucket["last_activity_at"] is None or ts > bucket["last_activity_at"]):
                bucket["last_activity_at"] = ts
        elif a.get("device_type"):
            bucket = _category_bucket(a["device_type"])
            bucket["autotuner"].append(a)
            if ts is not None and (bucket["last_activity_at"] is None or ts > bucket["last_activity_at"]):
                bucket["last_activity_at"] = ts
        # else: global scope -- already covered by /api/autonomy's own
        # Autotuner Timeline panel, deliberately not duplicated into either
        # grouping here.

    devices_out = []
    for entry in by_device.values():
        entry["trust_grants_count"] = len(entry["trust_grants"])
        entry["building_trust_count"] = len(entry["building_trust"])
        entry["autotuner_count"] = len(entry["autotuner"])
        devices_out.append(entry)
    devices_out.sort(key=lambda e: e["last_activity_at"] or 0, reverse=True)

    categories_out = []
    for entry in by_category.values():
        entry["autotuner_count"] = len(entry["autotuner"])
        categories_out.append(entry)
    categories_out.sort(key=lambda e: e["last_activity_at"] or 0, reverse=True)

    return {"devices": devices_out, "by_category": categories_out}
