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
  path vs. the original migration to argus).
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
from argus.autotune.engine import AutotuneEngine, TUNABLE_PARAMETERS, _LESS_SENSITIVE_DIRECTION
from argus.cl_afpe.composite_trust import _SUPPRESSION_TRUST_FLOOR
from core.state_guard import StateManager
from middleware.state_client import get_cached_state_manager
from middleware.humanize import resolve_device_identity

# Semantic (real-world) default for each of the 16 TUNABLE_PARAMETERS -- mirrors
# each parameter's own forward generator (backtest_job.py's _XXX_DEFAULT
# constants, population_prior_builder.py's _POOL_* constants), duplicated here
# with a comment citing its source rather than imported directly: backtest_job.py
# alone pulls in argus.synthetic.injector and other heavy transitive imports
# (~5s+ import cost, confirmed by timing it), the wrong tradeoff for this
# lightweight console/API subprocess. Same "duplicated literal + comment citing
# the source of truth" convention those files already use for THEIR OWN
# cross-file default duplication (e.g. backtest_job.py's own
# _TUNE_DEFAULT_SENSITIVITY = 0.9  # matches decision/engine.py's own hardcoded
# default). 2026-09-28 (console audit, user request: "update the console with
# all 16 autotune parameter") -- used ONLY for /api/autonomy/parameters'
# current-value display, never fed into an actual propose_change() decision, so
# a display value drifting stale here (if a source default is ever changed
# without updating this copy) can't corrupt a real autonomous tuning decision
# the way AutotuneEngine.propose_change()'s own default-mismatch bug did.
_PARAMETER_DEFAULTS: Dict[str, float] = {
    "reputation_tier_suspicious_floor": 2.0,        # backtest_job.py's _REPUTATION_SUSPICIOUS_DEFAULT
    "reputation_tier_high_floor": 4.0,               # backtest_job.py's _REPUTATION_HIGH_DEFAULT
    "bocpd_hazard_rate": 1.0 / 500.0,                # backtest_job.py's _BOCPD_HAZARD_DEFAULT
    "hard_stop_candidate_sensitivity": 0.9,          # backtest_job.py's _TUNE_DEFAULT_SENSITIVITY
    "arp_sweep_unique_targets_threshold": 8.0,       # backtest_job.py's _ARP_SWEEP_DEFAULT_THRESHOLD
    "fp_combined_suppress_threshold": 0.80,          # backtest_job.py's _FP_COMBINED_DEFAULT_THRESHOLD
    "peer_deviation_multiplier": 3.0,                # backtest_job.py's _PEER_DEVIATION_MULTIPLIER_DEFAULT
    "peer_deviation_min_absolute_count": 5.0,        # backtest_job.py's _PEER_DEVIATION_MIN_COUNT_DEFAULT
    "combined_uncertain_threshold": 0.55,            # CONFIG's own fp_combined_uncertain_threshold default
    "familiarity_trust_bar": 0.6,                    # backtest_job.py's _FAMILIARITY_TRUST_BAR_DEFAULT
    "trust_cache_ttl_seconds": 14 * 86400.0,         # backtest_job.py's _TRUST_CACHE_TTL_DEFAULT
    "reputation_propagation_ttl_seconds": 86400.0,   # backtest_job.py's _REPUTATION_PROPAGATION_TTL_DEFAULT
    "pool_gaussian_kappa": 5.0,                      # population_prior_builder.py's _POOL_GAUSSIAN_KAPPA
    "pool_gaussian_alpha": 10.0,                     # population_prior_builder.py's _POOL_GAUSSIAN_ALPHA
    "pool_beta_total": 10.0,                         # population_prior_builder.py's _POOL_BETA_TOTAL
    "pool_poisson_rate": 5.0,                        # population_prior_builder.py's _POOL_POISSON_RATE
}

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


def _serialize_threshold_history(rows: List[Dict[str, Any]], sm) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        parameter = row.get("parameter", "")
        old_value = float(row.get("old_value") or 0.0)
        new_value = float(row.get("new_value") or 0.0)
        # 2026-09-28 (console audit, user request: "Display always hostname and
        # ip address instead of device id"): a global/category-scoped row's own
        # device_id is None -- resolve_device_identity() falls back to
        # "unattributed", same convention this file's own by_device grouping
        # below already uses for a None device_id (console.html's own Autotuner
        # Timeline table only ever renders GLOBAL rows anyway, filtered
        # client-side on device_id/device_type both being falsy, so this
        # field is inert there but still correctly resolved for any other
        # consumer).
        identity = resolve_device_identity(row.get("device_id"), sm)
        out.append({
            "change_id": row.get("change_id"),
            "device_id": row.get("device_id"),
            "device_hostname": identity["hostname"],
            "device_ip": identity["ip"],
            "device_display": identity["display"],
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


def _serialize_trust_grants(edges: List[Dict[str, Any]], sm) -> List[Dict[str, Any]]:
    out = []
    for e in edges:
        meta = e.get("metadata") or {}
        source = meta.get("source", "unknown")
        identity = resolve_device_identity(e.get("src_id"), sm)
        out.append({
            "device_id": e.get("src_id"),
            "device_hostname": identity["hostname"],
            "device_ip": identity["ip"],
            "device_display": identity["display"],
            "destination_id": e.get("dst_id"),
            "hypothesis": meta.get("hypothesis"),
            "source": source,
            "source_label": _TRUST_SOURCE_LABELS.get(source, source),
            "granted_at": e.get("timestamp"),
            "ttl_seconds": meta.get("ttl_seconds"),
        })
    return out


def _serialize_building_trust(rows: List[Dict[str, Any]], sm) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        trust_value = float(row.get("trust_value") or 0.0)
        identity = resolve_device_identity(row.get("device_id"), sm)
        out.append({
            "device_id": row.get("device_id"),
            "device_hostname": identity["hostname"],
            "device_ip": identity["ip"],
            "device_display": identity["display"],
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

    sm = _load_state_manager()
    return {
        "autotuner": _serialize_threshold_history(threshold_rows, sm),
        "trust_grants": _serialize_trust_grants(trust_edges, sm),
        "building_trust": _serialize_building_trust(building_trust_rows, sm),
    }


@router.get("/api/autonomy/parameters")
def get_autonomy_parameters(token: str = Depends(verify_token)):
    """All 16 TUNABLE_PARAMETERS at a glance -- current (global-tier) value,
    shipped default, and bounds -- regardless of whether that parameter
    happens to have a recent threshold_history row. 2026-09-28 (console
    audit, user request: "update the console with all 16 autotune
    parameter"): the Autotuner Timeline panel only ever shows parameters
    that HAVE a proposal in threshold_history, so a parameter nothing has
    triggered a change for yet (e.g. combined_uncertain_threshold, on a
    quiet network) was invisible on the console even though it's live and
    tunable."""
    with open_store() as store:
        engine = AutotuneEngine(store) if store is not None else None
        out = []
        for parameter in sorted(TUNABLE_PARAMETERS.keys()):
            bounds = TUNABLE_PARAMETERS[parameter]
            default = _PARAMETER_DEFAULTS.get(parameter)
            current = engine.get_active_value(parameter, default=default) if engine is not None else default
            out.append({
                "parameter": parameter,
                "current_value": current,
                "default_value": default,
                "is_at_default": (
                    default is not None and current is not None and abs(current - default) < 1e-9
                ),
                "bounds": bounds,
                "less_sensitive_direction": _LESS_SENSITIVE_DIRECTION.get(parameter, 1),
            })
    return {"parameters": out}


def _load_state_manager() -> StateManager:
    # Cached, mtime-invalidated -- see state_client.py's own docstring (chronic
    # console latency, found live 2026-09-22: this endpoint is read-only, so a
    # freshly-restarted-instance-per-request here was pure waste).
    return get_cached_state_manager(CONFIG.get("state_path", "state/ids_state.json"))


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
    grants = _serialize_trust_grants(trust_edges, sm)
    building = _serialize_building_trust(building_trust_rows, sm)
    autotuner = _serialize_threshold_history(threshold_rows, sm)

    by_device: Dict[str, Dict[str, Any]] = {}
    by_category: Dict[str, Dict[str, Any]] = {}

    def _bucket(device_id: str) -> Dict[str, Any]:
        # One bucket per physical device: rows recorded under an id since merged away go to the device it is now part of.
        if device_id != "unattributed":
            resolved = sm.resolve_merge_redirect(device_id) if hasattr(sm, "resolve_merge_redirect") else device_id
            device_id = resolved if isinstance(resolved, str) and resolved else device_id
        if device_id not in by_device:
            identity = resolve_device_identity(device_id, sm)
            by_device[device_id] = {
                "device_id": device_id,
                "hostname": identity["hostname"],
                "ip": identity["ip"],
                "display": identity["display"],
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
