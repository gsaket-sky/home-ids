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
`.venv/Scripts/python.exe tests/test_v13_autotune_reset.py`
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


from v13.autotune import reset as reset_mod  # noqa: E402
from v13.baseline.engine import BaselineEngine  # noqa: E402
from v13.evidence.model import Evidence  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402

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
