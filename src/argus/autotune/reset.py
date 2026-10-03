"""
argus/autotune/reset.py -- Release 15 Sheet 04: per-device snapshots and
reset/undo. The accountability layer the closed loop needs precisely
because there's no human approving each autonomous step: every device has a
legible history of how its own tuning got where it is, and an operator
(never the autonomous loop itself) can roll it back -- a normal admin
capability, the same category as today's manual block/release, not a
re-introduction of human gating into detection itself.
"""
import json
import time
import uuid
from typing import Any, Dict, List, Optional

from argus.graph.store import GraphStore

_VALID_REASONS = frozenset({"scheduled", "pre_regime_change", "pre_autotune_batch", "pre_cl_afpe_suppression", "manual"})

# Same three cross-device-correlation evidence types compute_reset_blast_radius()
# already scans for -- the only evidence_types whose OWN semantics point back at
# a device other than the one they're attributed to (features_json names the
# correlated devices; evidence.device_id is just "which device this row was
# recorded against"). Kept as one module constant so the sole_cause check below
# and the existing blast-radius scan can never drift apart on what counts.
_CROSS_DEVICE_CORRELATION_TYPES = ("coordinated_targeting", "fingerprint_campaign", "dga_seed_campaign")


def _full_evidence_ids_for_decision(store: GraphStore, decision_id: str) -> List[str]:
    """The COMPLETE evidence_id set that supported `decision_id`, not the
    capped-and-edge-represented one -- GraphStore.insert_decision() caps
    'supports' edges at a hardware-profile-driven limit (a real production
    decision was found with 56,073 such edges) and stashes the full,
    uncapped list in raw_payload_json['_all_evidence_ids'] ONLY when the cap
    was actually exceeded (insert_decision()'s own docstring). Reading edges
    directly when that key is absent is still correct in that case -- the
    edge set IS the full set whenever nothing was capped."""
    row = store._conn.execute(
        "SELECT raw_payload_json FROM decisions WHERE decision_id=?", (decision_id,),
    ).fetchone()
    if row is not None:
        payload = json.loads(row["raw_payload_json"] or "{}")
        full_ids = payload.get("_all_evidence_ids")
        if full_ids:
            return list(full_ids)
    edge_rows = store._conn.execute(
        "SELECT src_id FROM edges WHERE dst_kind='decision' AND dst_id=? AND relation='supports' AND src_kind='evidence'",
        (decision_id,),
    ).fetchall()
    return [r["src_id"] for r in edge_rows]


def _decision_is_sole_cause(store: GraphStore, decision_id: str, device_id: str) -> bool:
    """True only if `device_id` resetting its own state would leave THIS
    decision with zero remaining supporting evidence -- i.e. every evidence
    item in its full (uncapped) supporting set is a cross-device-correlation
    item that actually names `device_id`. A single item that is either a
    non-correlation type (that device's own independent signal, untouched by
    resetting a DIFFERENT device) or a correlation item that doesn't even
    mention `device_id` disqualifies it -- this decision would still have
    real support left after the reset, so it's `contributing` at most, never
    `sole_cause`. An empty evidence set is conservatively NOT sole_cause
    (nothing to attribute)."""
    evidence_ids = _full_evidence_ids_for_decision(store, decision_id)
    if not evidence_ids:
        return False
    placeholders = ",".join("?" * len(evidence_ids))
    rows = store._conn.execute(
        f"SELECT evidence_type, features_json FROM evidence WHERE evidence_id IN ({placeholders})",
        evidence_ids,
    ).fetchall()
    if not rows:
        return False
    for row in rows:
        if row["evidence_type"] not in _CROSS_DEVICE_CORRELATION_TYPES:
            return False
        if device_id not in (row["features_json"] or ""):
            return False
    return True


def take_snapshot(store: GraphStore, device_id: str, reason: str, label: Optional[str] = None,
                    now: Optional[float] = None) -> str:
    """Snapshots one device's current posterior state (device_baselines),
    active promoted thresholds (threshold_history) that name this device
    specifically, and cl_afpe_trust rows -- everything reset_device() below
    needs to restore. Taken by CALLERS at the moments the plan specifies
    (before a regime promotion, an autotune batch, a CL-AFPE suppression
    decision, or on request) -- this function itself is a pure "capture
    current state," not a scheduler."""
    if reason not in _VALID_REASONS:
        raise ValueError(f"reason must be one of {sorted(_VALID_REASONS)}, got {reason!r}")
    now = now if now is not None else time.time()
    snapshot_id = uuid.uuid4().hex

    baseline_rows = store._conn.execute(
        "SELECT * FROM device_baselines WHERE device_id=?", (device_id,),
    ).fetchall()
    posterior_params = [dict(r) for r in baseline_rows]

    threshold_rows = store._conn.execute(
        "SELECT * FROM threshold_history WHERE device_id=? AND promoted_at IS NOT NULL AND rolled_back_at IS NULL",
        (device_id,),
    ).fetchall()
    threshold_params = [dict(r) for r in threshold_rows]

    trust_rows = store._conn.execute(
        "SELECT * FROM cl_afpe_trust WHERE device_id=?", (device_id,),
    ).fetchall()
    trust_state = [dict(r) for r in trust_rows]

    store._conn.execute(
        "INSERT INTO baseline_snapshots (snapshot_id, device_id, taken_at, reason, posterior_params_json, "
        "threshold_params_json, cl_afpe_trust_json, label) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (snapshot_id, device_id, now, reason, json.dumps(posterior_params), json.dumps(threshold_params),
         json.dumps(trust_state), label),
    )
    store._maybe_commit()
    return snapshot_id


def list_snapshots(store: GraphStore, device_id: str) -> List[Dict[str, Any]]:
    rows = store._conn.execute(
        "SELECT snapshot_id, taken_at, reason, label FROM baseline_snapshots WHERE device_id=? ORDER BY taken_at DESC",
        (device_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_snapshot(store: GraphStore, snapshot_id: str) -> Optional[Dict[str, Any]]:
    row = store._conn.execute(
        "SELECT * FROM baseline_snapshots WHERE snapshot_id=?", (snapshot_id,),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["posterior_params"] = json.loads(d.pop("posterior_params_json"))
    d["threshold_params"] = json.loads(d.pop("threshold_params_json"))
    d["cl_afpe_trust"] = json.loads(d.pop("cl_afpe_trust_json"))
    return d


def compute_reset_blast_radius(store: GraphStore, device_id: str, since_ts: float) -> Dict[str, Any]:
    """Finds decisions/containment_actions on OTHER devices whose evidence
    references this device via a cross-device-correlation signal
    (coordinated_targeting/fingerprint_campaign/dga_seed_campaign --
    hypotheses/independence.py's own cross_device_correlation family) since
    `since_ts`, the two real pathways one device's state can affect another.

    Finds OTHER devices' evidence whose features_json mentions this
    device_id as a string -- real and useful (cross-device-correlation
    evidence types are exactly the ones the plan's own design already
    scoped as the blast-radius mechanism).

    sole_cause CLASSIFICATION (closes this method's former honest gap): a
    downstream decision is classified `sole_cause` only when its COMPLETE
    supporting-evidence set (the uncapped list, not just the capped
    'supports' edges -- see _full_evidence_ids_for_decision()) consists
    ENTIRELY of cross-device-correlation evidence that actually names this
    device_id -- i.e. resetting this device's own state would leave that
    decision with zero remaining support. A decision with even one item of
    its own independent evidence (a non-correlation signal, or a
    correlation item that doesn't mention this device_id) stays classified
    `contributing` only -- still real and useful (flagged for operator
    review), just not strong enough to auto-release. Still a bounded
    heuristic, not a full causal-graph traversal: it answers "does every
    piece of evidence trace to this device," not the deeper "would the
    VERDICT itself have been different" counterfactual -- but it is a real,
    checkable fact about the evidence graph, not a placeholder.
    """
    other_device_evidence = store._conn.execute(
        "SELECT evidence_id, device_id, evidence_type FROM evidence WHERE "
        "device_id != ? AND evidence_type IN ('coordinated_targeting', 'fingerprint_campaign', 'dga_seed_campaign') "
        "AND timestamp >= ? AND features_json LIKE ?",
        (device_id, since_ts, f"%{device_id}%"),
    ).fetchall()

    affected_device_ids = sorted({r["device_id"] for r in other_device_evidence})
    contributing_decisions: List[Dict[str, Any]] = []
    contributing_containment: List[Dict[str, Any]] = []
    sole_cause_containment: List[Dict[str, Any]] = []
    seen_decision_ids: set = set()

    for ev_row in other_device_evidence:
        edges = store._conn.execute(
            "SELECT dst_id FROM edges WHERE src_kind='evidence' AND src_id=? AND relation='supports' AND dst_kind='decision'",
            (ev_row["evidence_id"],),
        ).fetchall()
        for edge in edges:
            decision = store._conn.execute(
                "SELECT decision_id, device_id, state, timestamp FROM decisions WHERE decision_id=?",
                (edge["dst_id"],),
            ).fetchone()
            if decision is not None:
                contributing_decisions.append(dict(decision))
                containment_rows = store._conn.execute(
                    "SELECT action_id, device_id, action_type, target, status FROM containment_actions "
                    "WHERE decision_id=? AND status='active'",
                    (decision["decision_id"],),
                ).fetchall()
                contributing_containment.extend(dict(r) for r in containment_rows)

                if decision["decision_id"] not in seen_decision_ids:
                    seen_decision_ids.add(decision["decision_id"])
                    if _decision_is_sole_cause(store, decision["decision_id"], device_id):
                        sole_cause_containment.extend(dict(r) for r in containment_rows)

    return {
        "device_id": device_id,
        "since_ts": since_ts,
        "affected_device_ids": affected_device_ids,
        "contributing_decisions": contributing_decisions,
        "contributing_containment_actions": contributing_containment,
        "sole_cause_containment_actions": sole_cause_containment,
    }


def reset_device(store: GraphStore, device_id: str, target_snapshot_id: str,
                   undo_scope: str = "sole_cause_only", now: Optional[float] = None) -> Dict[str, Any]:
    """Restores `device_id`'s own baseline/threshold/trust state to
    `target_snapshot_id`. This is an OPERATOR-INVOKED admin action (the
    plan's own explicit framing), never called autonomously by any of this
    plan's closed loops. `undo_scope='sole_cause_only'` (default) additionally
    releases every containment action compute_reset_blast_radius() classifies
    as `sole_cause` for this device (this device's own reset state was the
    decision's ENTIRE supporting-evidence set -- see that function's own
    docstring for the exact classification); `undo_scope='include_contributing'`
    additionally releases every `contributing`-classified action too (a
    decision this device merely helped support, alongside independent
    evidence of its own) -- an explicit wider action the caller opts into,
    since those decisions may still hold even after this device's reset."""
    if undo_scope not in ("sole_cause_only", "include_contributing"):
        raise ValueError(f"undo_scope must be 'sole_cause_only' or 'include_contributing', got {undo_scope!r}")
    snapshot = get_snapshot(store, target_snapshot_id)
    if snapshot is None:
        raise ValueError(f"no such snapshot: {target_snapshot_id}")
    if snapshot["device_id"] != device_id:
        raise ValueError(f"snapshot {target_snapshot_id} belongs to device {snapshot['device_id']}, not {device_id}")
    now = now if now is not None else time.time()

    store._conn.execute("DELETE FROM device_baselines WHERE device_id=?", (device_id,))
    for row in snapshot["posterior_params"]:
        store._conn.execute(
            "INSERT INTO device_baselines (device_id, metric, hour, regime_id, model_kind, "
            "posterior_params_json, run_length_json, n, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (row["device_id"], row["metric"], row["hour"], row["regime_id"], row["model_kind"],
             row["posterior_params_json"], row["run_length_json"], row["n"], now),
        )

    store._conn.execute("DELETE FROM cl_afpe_trust WHERE device_id=?", (device_id,))
    for row in snapshot["cl_afpe_trust"]:
        store._conn.execute(
            "INSERT INTO cl_afpe_trust (device_id, behavior_fingerprint, destination_class, hypothesis_id, "
            "evidence_family, regime_id, trust_value, n, last_updated, snapshot_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (row["device_id"], row["behavior_fingerprint"], row["destination_class"], row["hypothesis_id"],
             row["evidence_family"], row["regime_id"], row["trust_value"], row["n"], now, target_snapshot_id),
        )

    # Any threshold currently active for this device that was NOT part of
    # the snapshot gets rolled back -- the snapshot is the ground truth being
    # restored to, so anything promoted after it no longer applies.
    snapshot_change_ids = {row["change_id"] for row in snapshot["threshold_params"]}
    active_rows = store._conn.execute(
        "SELECT change_id FROM threshold_history WHERE device_id=? AND promoted_at IS NOT NULL AND rolled_back_at IS NULL",
        (device_id,),
    ).fetchall()
    for row in active_rows:
        if row["change_id"] not in snapshot_change_ids:
            store._conn.execute(
                "UPDATE threshold_history SET rolled_back_at=?, reason=reason || ' | reset_device to ' || ? WHERE change_id=?",
                (now, target_snapshot_id, row["change_id"]),
            )

    released_containment: List[str] = []
    blast_radius = compute_reset_blast_radius(store, device_id, since_ts=snapshot["taken_at"])
    actions_to_release = list(blast_radius["sole_cause_containment_actions"])
    if undo_scope == "include_contributing":
        # sole_cause is always a subset of contributing (every sole_cause
        # finding above also appended to contributing_containment) -- union
        # via action_id so a sole_cause action isn't double-processed.
        seen_action_ids = {a["action_id"] for a in actions_to_release}
        actions_to_release.extend(
            a for a in blast_radius["contributing_containment_actions"] if a["action_id"] not in seen_action_ids
        )
    for action in actions_to_release:
        store._conn.execute(
            "UPDATE containment_actions SET status='released', released_at=? WHERE action_id=? AND status='active'",
            (now, action["action_id"]),
        )
        released_containment.append(action["action_id"])

    store._maybe_commit()
    return {
        "device_id": device_id, "restored_to_snapshot": target_snapshot_id,
        "undo_scope": undo_scope, "released_containment_action_ids": released_containment,
    }
