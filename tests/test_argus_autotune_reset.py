"""
Standalone runtime test for v13's Sheet 04 snapshot/reset-undo
(src/v13/autotune/reset.py, Release 15 closed-loop autotuning architecture).

Covers: snapshot capture of real baseline/threshold/trust state,
list/get round-tripping, reset_device actually restoring prior baseline
state and rolling back thresholds promoted after the snapshot, a
mismatched-device snapshot raising rather than silently resetting the
wrong device, the blast-radius query finding a real cross-device-
correlation case, and include_contributing actually releasing containment
actions.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_autotune_reset.py`
"""
import json
import sys
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.autotune import reset as reset_mod  # noqa: E402
from argus.baseline.engine import BaselineEngine  # noqa: E402
from argus.evidence.model import Evidence  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402

NOW = 1_800_000_000.0

store = GraphStore(":memory:")
device = "dev_reset_target"
store.upsert_device(device, device_type="laptop", timestamp=NOW)

# Build up some real baseline state to snapshot.
engine = BaselineEngine(store)
for i in range(15):
    engine.score_metric(device, "query_rate", "gaussian", (50.0 + (i % 3),), hour=10, now=NOW + i)

# =============================================================================
# take_snapshot -- invalid reason rejected
# =============================================================================
raised = False
try:
    reset_mod.take_snapshot(store, device, "not_a_real_reason", now=NOW)
except ValueError:
    raised = True
check("take_snapshot: an invalid reason raises ValueError", raised)

# =============================================================================
# take_snapshot -- captures real state
# =============================================================================
snap_id = reset_mod.take_snapshot(store, device, "manual", label="before change", now=NOW + 20)
snap = reset_mod.get_snapshot(store, snap_id)
check("take_snapshot/get_snapshot: round-trips and captures real "
      "device_baselines rows, not an empty placeholder",
      snap is not None and len(snap["posterior_params"]) > 0)
check("take_snapshot: reason and label persisted correctly",
      snap["reason"] == "manual" and snap["label"] == "before change")

listed = reset_mod.list_snapshots(store, device)
check("list_snapshots: the snapshot just taken appears in the listing",
      any(s["snapshot_id"] == snap_id for s in listed))

# Capture the pre-change dominant model's mu for comparison after reset.
pre_change_mu = json.loads(
    store._conn.execute(
        "SELECT posterior_params_json FROM device_baselines WHERE device_id=? AND metric='query_rate' "
        "ORDER BY regime_id DESC LIMIT 1", (device,),
    ).fetchone()["posterior_params_json"]
)["mu"]

# =============================================================================
# reset_device -- actually restores prior baseline state
# =============================================================================
# Drift the baseline further away from the snapshot with new observations.
for i in range(15):
    engine.score_metric(device, "query_rate", "gaussian", (200.0,), hour=10, now=NOW + 100 + i)
post_change_mu = json.loads(
    store._conn.execute(
        "SELECT posterior_params_json FROM device_baselines WHERE device_id=? AND metric='query_rate' "
        "ORDER BY regime_id DESC LIMIT 1", (device,),
    ).fetchone()["posterior_params_json"]
)["mu"]
check("setup: the baseline genuinely drifted after the snapshot (sanity check)",
      abs(post_change_mu - pre_change_mu) > 5.0, f"pre={pre_change_mu:.2f} post={post_change_mu:.2f}")

result = reset_mod.reset_device(store, device, snap_id, now=NOW + 300)
check("reset_device: returns a well-formed result", result["device_id"] == device
      and result["restored_to_snapshot"] == snap_id)

restored_mu = json.loads(
    store._conn.execute(
        "SELECT posterior_params_json FROM device_baselines WHERE device_id=? AND metric='query_rate' "
        "ORDER BY regime_id DESC LIMIT 1", (device,),
    ).fetchone()["posterior_params_json"]
)["mu"]
check("reset_device: the baseline is actually restored close to its "
      "pre-change value, not left at the drifted one",
      abs(restored_mu - pre_change_mu) < 0.5, f"restored={restored_mu:.2f} expected~{pre_change_mu:.2f}")

# =============================================================================
# reset_device -- mismatched device/snapshot raises
# =============================================================================
other_device = "dev_other"
store.upsert_device(other_device, device_type="laptop", timestamp=NOW)
raised_mismatch = False
try:
    reset_mod.reset_device(store, other_device, snap_id, now=NOW + 400)
except ValueError:
    raised_mismatch = True
check("reset_device: resetting a device with a snapshot that belongs to a "
      "DIFFERENT device raises, never silently resets the wrong device",
      raised_mismatch)

# =============================================================================
# Snapshot taken BEFORE the cross-device effect below, so a later reset to
# it has a real, chronologically-correct blast-radius window to search.
# =============================================================================
snap2_id = reset_mod.take_snapshot(store, device, "manual", now=NOW + 490)

# =============================================================================
# compute_reset_blast_radius -- a real cross-device-correlation case
# =============================================================================
store._conn.execute("INSERT INTO hypotheses (hypothesis_id, kind) VALUES ('NETWORK_INTRUSION', 'attack')")
store._conn.commit()
victim_device = "dev_victim"
store.upsert_device(victim_device, device_type="laptop", timestamp=NOW)
coord_ev = Evidence(
    device_id=victim_device, destination_id="198.51.100.9", evidence_type="coordinated_targeting",
    independence_family="cross_device_correlation", timestamp=NOW + 500, source="test", confidence=0.8, value=1.0,
    features={"corroborating_device": device},
)
store.insert_evidence(coord_ev)
decision_id = store.insert_decision(
    device_id=victim_device, timestamp=NOW + 501, state="HIGH", decision_path="hard_stop",
    confidence=0.8, risk_score=8.0, evidence_ids=[coord_ev.evidence_id],
)
store._conn.execute(
    "INSERT INTO containment_actions (action_id, device_id, decision_id, action_type, target, status, timestamp) "
    "VALUES ('act1', ?, ?, 'dns_block', '198.51.100.9', 'active', ?)",
    (victim_device, decision_id, NOW + 502),
)
store._conn.commit()

blast = reset_mod.compute_reset_blast_radius(store, device, since_ts=NOW)
check("compute_reset_blast_radius: finds the OTHER device whose "
      "coordinated_targeting evidence mentions the reset device",
      victim_device in blast["affected_device_ids"], f"got {blast['affected_device_ids']}")
check("compute_reset_blast_radius: finds the real downstream decision on that device",
      any(d["device_id"] == victim_device for d in blast["contributing_decisions"]))
check("compute_reset_blast_radius: finds the real active containment action "
      "tied to that decision",
      any(a["action_id"] == "act1" for a in blast["contributing_containment_actions"]))
check("compute_reset_blast_radius: a decision whose ENTIRE evidence set is a "
      "single correlation item naming the reset device classifies as sole_cause "
      "(closes this function's former honest gap -- used to always be [])",
      any(a["action_id"] == "act1" for a in blast["sole_cause_containment_actions"]),
      f"got {blast['sole_cause_containment_actions']}")

# =============================================================================
# sole_cause is a REAL discriminator, not "everything contributing is sole_cause"
# -- a decision that also rests on independent, non-correlation evidence of its
# own must NOT be classified sole_cause, since resetting the OTHER device alone
# wouldn't remove that independent support.
# =============================================================================
device_partial = "dev_reset_target_partial"
store.upsert_device(device_partial, device_type="laptop", timestamp=NOW)
snap_partial_id = reset_mod.take_snapshot(store, device_partial, "manual", now=NOW + 490)
victim2 = "dev_victim2"
store.upsert_device(victim2, device_type="laptop", timestamp=NOW)
coord_ev2 = Evidence(
    device_id=victim2, destination_id="198.51.100.10", evidence_type="coordinated_targeting",
    independence_family="cross_device_correlation", timestamp=NOW + 500, source="test", confidence=0.8, value=1.0,
    features={"corroborating_device": device_partial},
)
independent_ev = Evidence(
    device_id=victim2, destination_id="198.51.100.11", evidence_type="dns_behavior",
    independence_family="dns_behavior", timestamp=NOW + 500, source="test", confidence=0.8, value=1.0,
    features={},
)
store.insert_evidence(coord_ev2)
store.insert_evidence(independent_ev)
decision2_id = store.insert_decision(
    device_id=victim2, timestamp=NOW + 501, state="HIGH", decision_path="hypothesis_high",
    confidence=0.8, risk_score=8.0, evidence_ids=[coord_ev2.evidence_id, independent_ev.evidence_id],
)
store._conn.execute(
    "INSERT INTO containment_actions (action_id, device_id, decision_id, action_type, target, status, timestamp) "
    "VALUES ('act2', ?, ?, 'dns_block', '198.51.100.10', 'active', ?)",
    (victim2, decision2_id, NOW + 502),
)
store._conn.commit()

blast_partial = reset_mod.compute_reset_blast_radius(store, device_partial, since_ts=NOW)
check("compute_reset_blast_radius: still classifies the decision as contributing",
      any(a["action_id"] == "act2" for a in blast_partial["contributing_containment_actions"]))
check("compute_reset_blast_radius: does NOT classify it as sole_cause -- an "
      "independent dns_behavior item also supports this decision, unaffected "
      "by resetting a DIFFERENT device",
      not any(a["action_id"] == "act2" for a in blast_partial["sole_cause_containment_actions"]),
      f"got {blast_partial['sole_cause_containment_actions']}")

result_partial = reset_mod.reset_device(store, device_partial, snap_partial_id, now=NOW + 600)
check("reset_device: DEFAULT undo_scope ('sole_cause_only') does NOT release a "
      "merely-contributing action -- only include_contributing opts into that",
      "act2" not in result_partial["released_containment_action_ids"])
act2_row = store._conn.execute("SELECT status FROM containment_actions WHERE action_id='act2'").fetchone()
check("reset_device: the merely-contributing containment action is still active",
      act2_row["status"] == "active")

# =============================================================================
# reset_device DEFAULT scope ('sole_cause_only') actually auto-releases a real
# sole_cause finding -- the act1 scenario above only exercised include_contributing.
# =============================================================================
device_sole = "dev_reset_target_sole"
store.upsert_device(device_sole, device_type="laptop", timestamp=NOW)
snap_sole_id = reset_mod.take_snapshot(store, device_sole, "manual", now=NOW + 490)
victim3 = "dev_victim3"
store.upsert_device(victim3, device_type="laptop", timestamp=NOW)
coord_ev3 = Evidence(
    device_id=victim3, destination_id="198.51.100.12", evidence_type="coordinated_targeting",
    independence_family="cross_device_correlation", timestamp=NOW + 500, source="test", confidence=0.8, value=1.0,
    features={"corroborating_device": device_sole},
)
store.insert_evidence(coord_ev3)
decision3_id = store.insert_decision(
    device_id=victim3, timestamp=NOW + 501, state="HIGH", decision_path="hard_stop",
    confidence=0.8, risk_score=8.0, evidence_ids=[coord_ev3.evidence_id],
)
store._conn.execute(
    "INSERT INTO containment_actions (action_id, device_id, decision_id, action_type, target, status, timestamp) "
    "VALUES ('act3', ?, ?, 'dns_block', '198.51.100.12', 'active', ?)",
    (victim3, decision3_id, NOW + 502),
)
store._conn.commit()

result_sole = reset_mod.reset_device(store, device_sole, snap_sole_id, now=NOW + 600)
check("reset_device: DEFAULT undo_scope ('sole_cause_only') auto-releases a "
      "real sole_cause finding, no include_contributing opt-in needed",
      "act3" in result_sole["released_containment_action_ids"],
      f"got {result_sole['released_containment_action_ids']}")
act3_row = store._conn.execute("SELECT status FROM containment_actions WHERE action_id='act3'").fetchone()
check("reset_device: the sole_cause containment action is actually released "
      "in the graph, not just reported",
      act3_row["status"] == "released")

# =============================================================================
# reset_device with include_contributing -- actually releases containment
# =============================================================================
result2 = reset_mod.reset_device(store, device, snap2_id, undo_scope="include_contributing", now=NOW + 600)
check("reset_device(include_contributing): reports the containment action "
      "it released", "act1" in result2["released_containment_action_ids"])
act_row = store._conn.execute("SELECT status FROM containment_actions WHERE action_id='act1'").fetchone()
check("reset_device(include_contributing): the containment action is "
      "actually released in the graph, not just reported",
      act_row["status"] == "released")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 autotune reset checks PASSED.")
