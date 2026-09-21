"""
Standalone runtime test for v13's Sheet 03a autotuner infrastructure
(src/v13/autotune/engine.py, Release 15 closed-loop autotuning
architecture).

Covers: the closed tunable-parameter allowlist actually rejecting anything
not on it, backtest-gating a proposal cannot even be CREATED without a
passing backtest, bounded-step clamping, cooldown between proposals,
canary-then-promote requiring both an elapsed window and a confirming
backtest, rollback taking effect immediately (not just in the audit trail),
idempotent rollback, and the auto-rollback-on-regression path.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_autotune_engine.py`
"""
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


from argus.autotune.engine import (  # noqa: E402
    AutotuneEngine, TUNABLE_PARAMETERS, compute_drift_result, wilson_lower_bound,
    _MIN_TRIALS_FOR_LOOSENING, _TRUST_RADIUS_MAX_STEPS,
)
from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402

NOW = 1_800_000_000.0


def _insert_backtest(store, run_id, passed, at=NOW):
    store._conn.execute(
        "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass) VALUES (?, ?, ?, ?)",
        (run_id, at, at, 1 if passed else 0),
    )
    store._maybe_commit()


store = GraphStore(":memory:")
engine = AutotuneEngine(store)
_insert_backtest(store, "bt_pass_1", True, at=NOW)
_insert_backtest(store, "bt_fail_1", False, at=NOW)

# =============================================================================
# Allowlist: only TUNABLE_PARAMETERS may ever be proposed
# =============================================================================
r = engine.propose_change("independent_sources_minimum", 1.0, "trying to touch a structural invariant",
                            backtest_run_id="bt_pass_1", now=NOW)
check("propose_change: a parameter NOT on the allowlist is rejected outright "
      "-- the structural guarantee that this module can never touch a "
      "code-level invariant, not just a documented convention",
      r.accepted is False and "not on the tunable allowlist" in r.reason)

# =============================================================================
# Backtest gating: no passing backtest, no proposal at all
# =============================================================================
r_no_bt = engine.propose_change("reputation_tier_suspicious_floor", 3.0, "test", backtest_run_id=None, now=NOW)
check("propose_change: refuses to even CREATE a proposal with no backtest_run_id",
      r_no_bt.accepted is False)

r_failed_bt = engine.propose_change("reputation_tier_suspicious_floor", 3.0, "test",
                                       backtest_run_id="bt_fail_1", now=NOW)
check("propose_change: refuses a proposal backed by a FAILED backtest run",
      r_failed_bt.accepted is False and "did not pass" in r_failed_bt.reason)

# =============================================================================
# Bounded-step clamping
# =============================================================================
bounds = TUNABLE_PARAMETERS["reputation_tier_suspicious_floor"]
huge_jump = bounds["min"] + bounds["max_step"] * 10  # way past the per-change step limit
r_clamped = engine.propose_change("reputation_tier_suspicious_floor", huge_jump, "test",
                                     backtest_run_id="bt_pass_1", now=NOW)
check("propose_change: an oversized requested change is accepted but CLAMPED "
      "to the allowlist's max_step, never applied as a one-shot jump",
      r_clamped.accepted is True)
if r_clamped.accepted:
    row = store._conn.execute("SELECT old_value, new_value FROM threshold_history WHERE change_id=?",
                                (r_clamped.change_id,)).fetchone()
    actual_step = row["new_value"] - row["old_value"]
    check("propose_change: the actual applied step never exceeds max_step",
          actual_step <= bounds["max_step"] + 1e-9, f"got step={actual_step}")

# =============================================================================
# Cooldown between proposals for the same parameter
# =============================================================================
r_cooldown = engine.propose_change("reputation_tier_suspicious_floor", bounds["min"] + 0.1, "second try, too soon",
                                      backtest_run_id="bt_pass_1", now=NOW + 10)
check("propose_change: a second proposal for the SAME parameter+device too "
      "soon after the first is rejected by the cooldown",
      r_cooldown.accepted is False and "cooldown" in r_cooldown.reason)

r_after_cooldown = engine.propose_change("reputation_tier_suspicious_floor", bounds["min"] + 0.1, "after cooldown",
                                             backtest_run_id="bt_pass_1", now=NOW + 4000)
check("propose_change: the SAME parameter can be proposed again once the "
      "cooldown has elapsed", r_after_cooldown.accepted is True)

# =============================================================================
# Promote requires BOTH canary elapsed AND a confirming backtest
# =============================================================================
check("get_active_value: an UNPROMOTED proposal has no effect yet",
      engine.get_active_value("reputation_tier_suspicious_floor") is None)

promoted_too_early = engine.promote_change(r_clamped.change_id, "bt_pass_1", now=NOW + 100)
check("promote_change: refuses promotion before the canary window has elapsed",
      promoted_too_early is False)

_insert_backtest(store, "bt_fail_2", False, at=NOW + 7 * 3600)
promoted_with_failed_confirm = engine.promote_change(r_clamped.change_id, "bt_fail_2", now=NOW + 7 * 3600)
check("promote_change: refuses promotion even after the canary window if "
      "the CONFIRMING backtest failed",
      promoted_with_failed_confirm is False)

_insert_backtest(store, "bt_pass_2", True, at=NOW + 7 * 3600)
promoted = engine.promote_change(r_clamped.change_id, "bt_pass_2", now=NOW + 7 * 3600)
check("promote_change: succeeds once BOTH the canary window elapsed AND a "
      "confirming backtest passed", promoted is True)
# Expected value re-derived from the same clamp formula the code uses (old_value
# was the allowlist midpoint default, no prior promotion existed yet) rather than
# a hardcoded number -- the clamp is relative to old_value, not bounds["min"].
_default_old_value = (bounds["min"] + bounds["max"]) / 2.0
_expected_promoted = _default_old_value + bounds["max_step"]
check("get_active_value: reflects the promoted, step-clamped value immediately",
      abs(engine.get_active_value("reputation_tier_suspicious_floor") - _expected_promoted) < 1e-9,
      f"got {engine.get_active_value('reputation_tier_suspicious_floor')}, expected {_expected_promoted}")

# =============================================================================
# Rollback -- immediate effect, idempotent
# =============================================================================
rolled_back = engine.rollback_change(r_clamped.change_id, "operator says this was wrong", now=NOW + 8 * 3600)
check("rollback_change: succeeds on a promoted change", rolled_back is True)
check("get_active_value: a rolled-back change no longer counts, immediately -- "
      "not just in the audit trail",
      engine.get_active_value("reputation_tier_suspicious_floor") is None)

rolled_back_again = engine.rollback_change(r_clamped.change_id, "trying again", now=NOW + 9 * 3600)
check("rollback_change: rolling back an already-rolled-back change is an "
      "idempotent no-op (returns True), not an error", rolled_back_again is True)

# =============================================================================
# Auto-rollback on regression -- every unconfirmed change tied to a failing backtest
# =============================================================================
r2 = engine.propose_change("bocpd_hazard_rate", 1.0 / 400.0, "test regression path",
                              backtest_run_id="bt_pass_1", now=NOW + 20000)
check("propose_change: second parameter's proposal accepted (sanity check "
      "before the regression test)", r2.accepted is True)
_insert_backtest(store, "bt_regression", False, at=NOW + 20000)
# Re-point this specific change's own backtest_run_id to the regressing run,
# simulating "the backtest that was supposed to confirm this change failed."
store._conn.execute("UPDATE threshold_history SET backtest_run_id=? WHERE change_id=?",
                      ("bt_regression", r2.change_id))
store._maybe_commit()
rolled_back_count = engine.rollback_all_unconfirmed_for_backtest("bt_regression", "nightly backtest regressed")
check("rollback_all_unconfirmed_for_backtest: rolls back every still-in-canary "
      "change tied to a regressing backtest run, the same cycle it's detected",
      rolled_back_count == 1, f"got {rolled_back_count}")


# =============================================================================
# compute_drift_result -- Sheet 00's posterior-trajectory drift check (Sheet
# 02's own former honest gap: drift_result_json used to always be {})
# =============================================================================
def _promote_directly(store, device_id, parameter, new_value, promoted_at):
    """Bypasses propose/canary/promote (already covered above) -- inserts a
    PROMOTED threshold_history row directly, the only state compute_drift_
    result() reads."""
    store._conn.execute(
        "INSERT INTO threshold_history (change_id, device_id, parameter, old_value, new_value, "
        "proposed_at, canary_until, promoted_at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'test')",
        (f"drift_{device_id}_{promoted_at}", device_id, parameter, new_value - 0.5, new_value,
         promoted_at, promoted_at, promoted_at),
    )
    store._maybe_commit()


DRIFT_NOW = NOW + 100000
device_drift_flagged = "dev_drift_unexplained"
store.upsert_device(device_drift_flagged, device_type="laptop", timestamp=DRIFT_NOW)
for i, val in enumerate((2.0, 2.5, 3.0)):
    _promote_directly(store, device_drift_flagged, "reputation_tier_suspicious_floor", val, DRIFT_NOW + i * 3600)

device_drift_explained = "dev_drift_explained"
store.upsert_device(device_drift_explained, device_type="laptop", timestamp=DRIFT_NOW)
for i, val in enumerate((2.0, 2.5, 3.0)):
    _promote_directly(store, device_drift_explained, "reputation_tier_suspicious_floor", val, DRIFT_NOW + i * 3600)
store.insert_evidence(Evidence(
    device_id=device_drift_explained, destination_id=NO_DESTINATION, evidence_type="regime_change",
    independence_family="regime_change", timestamp=DRIFT_NOW + 3600, source="test", confidence=0.8, value=1.0,
    features={},
))

device_drift_noisy = "dev_drift_noisy"
store.upsert_device(device_drift_noisy, device_type="laptop", timestamp=DRIFT_NOW)
for i, val in enumerate((2.0, 3.0, 2.2)):  # up then down -- not a sustained trend
    _promote_directly(store, device_drift_noisy, "reputation_tier_suspicious_floor", val, DRIFT_NOW + i * 3600)

device_drift_sparse = "dev_drift_sparse"
store.upsert_device(device_drift_sparse, device_type="laptop", timestamp=DRIFT_NOW)
for i, val in enumerate((2.0, 3.0)):  # only 2 promotions -- below _MIN_PROMOTIONS_FOR_TREND
    _promote_directly(store, device_drift_sparse, "reputation_tier_suspicious_floor", val, DRIFT_NOW + i * 3600)

drift = compute_drift_result(store, now=DRIFT_NOW + 7200)
flagged_devices = {f["device_id"] for f in drift["findings"] if f["parameter"] == "reputation_tier_suspicious_floor"}

check("compute_drift_result: flags a monotonic, unexplained trend toward "
      "less sensitive (rising suspicious_floor, no matching regime_change)",
      device_drift_flagged in flagged_devices, f"got {flagged_devices}")
check("compute_drift_result: a regime_change evidence item in the same window "
      "explains an otherwise-identical trend -- not flagged",
      device_drift_explained not in flagged_devices, f"got {flagged_devices}")
check("compute_drift_result: a non-monotonic (up-then-down) sequence is not a "
      "sustained trend -- not flagged even though unexplained",
      device_drift_noisy not in flagged_devices, f"got {flagged_devices}")
check("compute_drift_result: fewer than _MIN_PROMOTIONS_FOR_TREND promotions is "
      "not enough evidence of a trend -- not flagged",
      device_drift_sparse not in flagged_devices, f"got {flagged_devices}")
check("compute_drift_result: drift_detected is True when any finding exists",
      drift["drift_detected"] is True)


# =============================================================================
# wilson_lower_bound() -- the safe-threshold statistic (Documentation/
# PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md §3b, user-requested "safe threshold
# value for enough real data to back a promotion")
# =============================================================================
check("wilson_lower_bound: n=0 is 0.0, not a crash or a divide-by-zero",
      wilson_lower_bound(0, 0) == 0.0)
check("wilson_lower_bound: a perfect n=20/20 record sits noticeably BELOW the "
      "raw 1.0 rate -- the whole point of using this over the raw rate",
      0.80 < wilson_lower_bound(20, 20) < 0.90, f"got {wilson_lower_bound(20, 20):.4f}")
check("wilson_lower_bound: the SAME perfect raw rate gets a HIGHER (more "
      "trusted) lower bound as n grows -- more evidence should read as more "
      "trustworthy, not the same",
      wilson_lower_bound(100, 100) > wilson_lower_bound(20, 20) > wilson_lower_bound(5, 5))
check("wilson_lower_bound: an imperfect record (19/20) scores lower than a "
      "perfect one at the same n",
      wilson_lower_bound(19, 20) < wilson_lower_bound(20, 20))
check("wilson_lower_bound: never negative and never exceeds the raw rate "
      "(a lower CONFIDENCE bound, by definition)",
      0.0 <= wilson_lower_bound(7, 10) <= 0.7)


# =============================================================================
# get_active_value() -- 3-tier fallback: device -> category -> global
# (Documentation/PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md)
# =============================================================================
store3 = GraphStore(":memory:")
engine3 = AutotuneEngine(store3)
_insert_backtest(store3, "bt3", True, at=NOW)

store3.upsert_device("tier_dev_a", device_type="iot", timestamp=NOW)
store3.upsert_device("tier_dev_b", device_type="iot", timestamp=NOW)  # same category, no device override

check("get_active_value: falls through all 3 tiers to the caller's default "
      "when nothing has ever been promoted at any scope",
      engine3.get_active_value("hard_stop_candidate_sensitivity", device_id="tier_dev_a",
                                 device_type="iot", default=0.9) == 0.9)

r_global = engine3.propose_change("hard_stop_candidate_sensitivity", 0.80, "global tighten",
                                     backtest_run_id="bt3", now=NOW)
check("propose_change (global): accepted", r_global.accepted, r_global.reason)
# Canary hasn't elapsed yet -- promote directly via SQL instead, matching this
# file's own _promote_directly() convention, to isolate THIS test from the
# canary-timing tests already covered above.
store3._conn.execute("UPDATE threshold_history SET promoted_at=? WHERE change_id=?", (NOW, r_global.change_id))
store3._maybe_commit()
# 0.80 requested from a default_mid of 0.745 (bounds are 0.5-0.99) is a 0.055
# step -- BEYOND max_step (0.05), so it's clamped to 0.795, not applied as
# requested. Reading back the real clamped value here (rather than hardcoding
# 0.80) so this test can't silently drift from _clamp_step()'s own behavior.
GLOBAL3 = engine3.get_active_value("hard_stop_candidate_sensitivity", default=0.9)
check("get_active_value: a device+category with no scoped override of their "
      "own falls through to the GLOBAL value once one is promoted",
      abs(GLOBAL3 - 0.795) < 1e-9, f"got {GLOBAL3}")

r_cat = engine3.propose_change("hard_stop_candidate_sensitivity", 0.75, "category tighten",
                                  device_type="iot", backtest_run_id="bt3", now=NOW)
check("propose_change (category): accepted", r_cat.accepted, r_cat.reason)
store3._conn.execute("UPDATE threshold_history SET promoted_at=? WHERE change_id=?", (NOW, r_cat.change_id))
store3._maybe_commit()

check("get_active_value: a device with no override of its own, but whose "
      "CATEGORY has one, gets the category value -- not global",
      abs(engine3.get_active_value("hard_stop_candidate_sensitivity", device_id="tier_dev_a",
                                      device_type="iot", default=0.9) - 0.75) < 1e-9)
check("get_active_value: a DIFFERENT device of the SAME category also gets "
      "that category's value -- the whole point of category-level tuning",
      abs(engine3.get_active_value("hard_stop_candidate_sensitivity", device_id="tier_dev_b",
                                      device_type="iot", default=0.9) - 0.75) < 1e-9)
check("get_active_value: a device of a DIFFERENT category is unaffected -- "
      "falls through to global, not the 'iot' category's value",
      abs(engine3.get_active_value("hard_stop_candidate_sensitivity", device_id="some_other_dev",
                                      device_type="router", default=0.9) - GLOBAL3) < 1e-9)

# device_type="iot" passed ALONGSIDE device_id -- a parent-tier resolution
# HINT only (see propose_change()'s own docstring for the bug this closes:
# without it, old_value here would incorrectly skip the category tier
# entirely and compare against global instead of the real parent, 0.75).
r_dev = engine3.propose_change("hard_stop_candidate_sensitivity", 0.72, "device tighten",
                                  device_id="tier_dev_a", device_type="iot", backtest_run_id="bt3", now=NOW)
check("propose_change (device, with category hint): accepted", r_dev.accepted, r_dev.reason)
store3._conn.execute("UPDATE threshold_history SET promoted_at=? WHERE change_id=?", (NOW, r_dev.change_id))
store3._maybe_commit()

check("propose_change: the device_type HINT is never written to a device-"
      "scoped row -- the row's own device_type stays NULL",
      store3._conn.execute("SELECT device_type FROM threshold_history WHERE change_id=?",
                              (r_dev.change_id,)).fetchone()["device_type"] is None)
check("get_active_value: a device with its OWN override wins over its "
      "category's -- the most specific tier available",
      abs(engine3.get_active_value("hard_stop_candidate_sensitivity", device_id="tier_dev_a",
                                      device_type="iot", default=0.9) - 0.72) < 1e-9)
check("get_active_value: the OTHER device in the same category is unaffected "
      "by tier_dev_a's own device-specific override -- still sees the category value",
      abs(engine3.get_active_value("hard_stop_candidate_sensitivity", device_id="tier_dev_b",
                                      device_type="iot", default=0.9) - 0.75) < 1e-9)

r_no_hint = engine3.propose_change("hard_stop_candidate_sensitivity", 0.70, "device proposal, no category hint given",
                                      device_id="tier_dev_b", backtest_run_id="bt3", now=NOW)
check("propose_change (device, WITHOUT the category hint): still accepted -- "
      "omitting device_type is not an error, it just means old_value falls "
      "through device -> global directly, skipping the category tier "
      "(REGRESSION GUARD for every pre-existing caller that never passes it)",
      r_no_hint.accepted, r_no_hint.reason)


# =============================================================================
# Trust-radius failsafe -- a scoped value may never diverge from its parent
# tier by more than _TRUST_RADIUS_MAX_STEPS max_steps in the less-sensitive
# direction (Documentation/PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md §4)
# =============================================================================
store4 = GraphStore(":memory:")
engine4 = AutotuneEngine(store4)
_insert_backtest(store4, "bt4", True, at=NOW)
bounds4 = TUNABLE_PARAMETERS["hard_stop_candidate_sensitivity"]  # direction +1: higher == less sensitive
max_step4 = bounds4["max_step"]
radius4 = _TRUST_RADIUS_MAX_STEPS * max_step4

# Clean, known anchor: global promoted to 0.70 directly (bypassing propose_
# change()'s own step-clamp, which is irrelevant to what THIS test is
# isolating -- matches this file's own _promote_directly() convention).
_promote_directly(store4, None, "hard_stop_candidate_sensitivity", 0.70, NOW)
GLOBAL4 = 0.70

# "phone" category sits ONE max_step short of the radius edge -- set up
# directly, not via propose_change(), so the test below exercises ONE clean
# real move (not a 0-step no-op) that lands EXACTLY on the edge.
store4._conn.execute(
    "INSERT INTO threshold_history (change_id, device_id, device_type, parameter, old_value, new_value, "
    "proposed_at, canary_until, promoted_at, reason) VALUES ('phone_setup', NULL, 'phone', "
    "'hard_stop_candidate_sensitivity', ?, ?, ?, ?, ?, 'test setup')",
    (GLOBAL4, GLOBAL4 + radius4 - max_step4, NOW, NOW, NOW),
)
store4._maybe_commit()

r_within = engine4.propose_change("hard_stop_candidate_sensitivity", GLOBAL4 + radius4,
                                     "one real max_step move that lands exactly on the radius edge",
                                     device_type="phone", backtest_run_id="bt4", now=NOW + 4000)
check("propose_change: a category-scoped move that lands exactly AT (not "
      "beyond) the trust-radius edge is accepted -- the cap is a hard limit, "
      "not an off-by-one under-restriction",
      r_within.accepted, r_within.reason)
# Promote it directly (canary hasn't elapsed) so the NEXT proposal below
# resolves its own old_value from THIS edge-sitting value, not the
# still-unpromoted setup row -- get_active_value() only ever reads promoted
# rows, matching every other test in this file.
store4._conn.execute("UPDATE threshold_history SET promoted_at=? WHERE change_id=?", (NOW + 4000, r_within.change_id))
store4._maybe_commit()

r_beyond = engine4.propose_change("hard_stop_candidate_sensitivity", GLOBAL4 + radius4 + max_step4,
                                     "one more max_step beyond the radius edge",
                                     device_type="phone", backtest_run_id="bt4", now=NOW + 8000)
check("propose_change: a category-scoped LOOSENING move that would push "
      "beyond the trust-radius is REJECTED outright, not silently clamped "
      "to the radius edge",
      r_beyond.accepted is False and "trust-radius" in r_beyond.reason, r_beyond.reason)

# Tightening (moving in the MORE-sensitive direction, i.e. down for this
# parameter) is never capped, at any distance from the parent tier.
store4._conn.execute(
    "INSERT INTO threshold_history (change_id, device_id, device_type, parameter, old_value, new_value, "
    "proposed_at, canary_until, promoted_at, reason) VALUES ('server_setup', NULL, 'server', "
    "'hard_stop_candidate_sensitivity', ?, ?, ?, ?, ?, 'test setup')",
    (GLOBAL4, bounds4["min"] + max_step4, NOW, NOW, NOW),
)
store4._maybe_commit()
r_tighten_far = engine4.propose_change("hard_stop_candidate_sensitivity", bounds4["min"],
                                          "tighten hard, far below the parent tier",
                                          device_type="server", backtest_run_id="bt4", now=NOW + 12000)
check("propose_change: a category-scoped TIGHTENING move is accepted "
      "regardless of how far it diverges from the parent tier -- the trust-"
      "radius cap only ever engages for the less-sensitive direction "
      "(becoming MORE cautious than the network default needs no cap)",
      r_tighten_far.accepted, r_tighten_far.reason)


# =============================================================================
# compute_drift_result() -- category-scoped grouping
# (Documentation/PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md §4)
# =============================================================================
store5 = GraphStore(":memory:")
CAT_DRIFT_NOW = NOW + 200000


def _promote_category_directly(store, device_type, parameter, new_value, promoted_at):
    store._conn.execute(
        "INSERT INTO threshold_history (change_id, device_id, device_type, parameter, old_value, new_value, "
        "proposed_at, canary_until, promoted_at, reason) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, 'test')",
        (f"catdrift_{device_type}_{promoted_at}", device_type, parameter, new_value - 0.5, new_value,
         promoted_at, promoted_at, promoted_at),
    )
    store._maybe_commit()


for i, val in enumerate((2.0, 2.5, 3.0)):
    _promote_category_directly(store5, "smart_tv", "reputation_tier_suspicious_floor", val, CAT_DRIFT_NOW + i * 3600)

drift5 = compute_drift_result(store5, now=CAT_DRIFT_NOW + 7200)
cat_findings = [f for f in drift5["findings"] if f.get("device_type") == "smart_tv"]
check("compute_drift_result: a category-scoped (device_type set, device_id "
      "NULL) monotonic trend is flagged too, not just device-scoped ones",
      len(cat_findings) == 1, f"got {drift5['findings']}")
check("compute_drift_result: the category finding's own device_id is None "
      "(never confused with a device-scoped finding)",
      len(cat_findings) == 1 and cat_findings[0]["device_id"] is None)


# =============================================================================
# HANDOVER FOLLOW-UP (2026-09-20): device-scoped reads/writes must resolve an
# identity merge (core/state_guard.py's merge_into_canonical(), mirrored into
# the graph via GraphStore.merge_device()) -- otherwise a device's own tuned
# threshold history, and its cooldown clock, would silently go blind the
# moment that device gets folded into a richer canonical identity.
# =============================================================================
store6 = GraphStore(":memory:")
engine6 = AutotuneEngine(store6)
MERGE_NOW = NOW + 300000
_insert_backtest(store6, "bt6", True, at=MERGE_NOW)
store6.upsert_device("orphan_dev6", device_type="iot", timestamp=MERGE_NOW)

# The device's OWN threshold was promoted BEFORE it existed under its richer
# canonical identity (e.g. tuned while still IP-anchored, before its MAC
# became known and it got folded into a MAC-anchored canonical id).
_promote_directly(store6, "orphan_dev6", "hard_stop_candidate_sensitivity", 0.80, MERGE_NOW)
check("setup: the orphan's own device-scoped value is visible before any merge",
      engine6.get_active_value("hard_stop_candidate_sensitivity", device_id="orphan_dev6") == 0.80)

store6.merge_device("orphan_dev6", "canonical_dev6", timestamp=MERGE_NOW + 10)

check("THE FIX: querying the CANONICAL id after the merge still finds the "
      "orphan's promoted value -- it's the same physical device's tuning "
      "history, not a fresh one that should start at global/category defaults",
      engine6.get_active_value("hard_stop_candidate_sensitivity", device_id="canonical_dev6") == 0.80)
check("THE FIX: querying the now-stale ORPHAN id also still resolves through "
      "to the same value (consistent with get_evidence_for_device()'s own "
      "resolve_merges convention)",
      engine6.get_active_value("hard_stop_candidate_sensitivity", device_id="orphan_dev6") == 0.80)

# A NEW proposal made against the (stale) orphan id must land on the
# canonical id's row, not re-create a dead scope that would go invisible
# again the next time anyone reads by the canonical id.
r_merge_propose = engine6.propose_change(
    "hard_stop_candidate_sensitivity", 0.75, "tuning after the merge",
    device_id="orphan_dev6", backtest_run_id="bt6", now=MERGE_NOW + 20000,
)
check("propose_change: a proposal made against the stale orphan id is accepted",
      r_merge_propose.accepted, r_merge_propose.reason)
written_row = store6._conn.execute(
    "SELECT device_id FROM threshold_history WHERE change_id=?", (r_merge_propose.change_id,),
).fetchone()
check("THE FIX: the new proposal's row is written under the CANONICAL id, "
      "never the stale orphan id it was called with",
      written_row["device_id"] == "canonical_dev6", f"got={dict(written_row)}")

# The cooldown clock must also be shared across the merge -- an immediate
# second proposal against EITHER id is still the same physical device's
# cooldown, not a fresh one.
r_merge_propose_2 = engine6.propose_change(
    "hard_stop_candidate_sensitivity", 0.72, "immediate second attempt",
    device_id="canonical_dev6", backtest_run_id="bt6", now=MERGE_NOW + 20001,
)
check("THE FIX: the cooldown clock is shared across the merge -- an "
      "immediate second proposal (via the canonical id this time) is "
      "rejected on cooldown, not treated as a fresh scope",
      r_merge_propose_2.accepted is False and "cooldown" in r_merge_propose_2.reason,
      r_merge_propose_2.reason)

# =============================================================================
# Asymmetric step clamping (2026-09-21, legacy/Sheet 03a reconciliation) --
# arp_sweep_unique_targets_threshold has genuinely different max_step_up
# (4.0) vs max_step_down (1.0), unlike every other TUNABLE_PARAMETERS entry.
# =============================================================================
store7 = GraphStore(":memory:")
engine7 = AutotuneEngine(store7)
_insert_backtest(store7, "bt7_pass", True, at=NOW)

arp_bounds = TUNABLE_PARAMETERS["arp_sweep_unique_targets_threshold"]
check("TUNABLE_PARAMETERS: arp_sweep_unique_targets_threshold has distinct "
      "max_step_up/max_step_down, not a single symmetric max_step",
      arp_bounds.get("max_step_up") == 4.0 and arp_bounds.get("max_step_down") == 1.0)

store7.upsert_device("arp_dev_a", device_type="iot", timestamp=NOW)
store7.upsert_device("arp_dev_b", device_type="iot", timestamp=NOW)

# A big RAISE (e.g. current=10 -> requested=30) must clamp to old_value + max_step_up (4.0),
# never the (smaller) max_step_down.
r_arp_raise = engine7.propose_change(
    "arp_sweep_unique_targets_threshold", 30.0, "corrected false positives, raising threshold",
    device_id="arp_dev_a", backtest_run_id="bt7_pass", now=NOW,
)
check("propose_change: arp_sweep RAISE is accepted", r_arp_raise.accepted, r_arp_raise.reason)
if r_arp_raise.accepted:
    row = store7._conn.execute(
        "SELECT old_value, new_value FROM threshold_history WHERE change_id=?",
        (r_arp_raise.change_id,),
    ).fetchone()
    applied_step = row["new_value"] - row["old_value"]
    check("propose_change: an oversized RAISE is clamped to max_step_up (4.0), "
          "not the smaller max_step_down (1.0)",
          abs(applied_step - 4.0) < 1e-9, f"got step={applied_step}")

# A big LOWER (e.g. current=10 -> requested=4, a 6-unit drop) must clamp to
# old_value - max_step_down (1.0), never the (bigger) max_step_up.
r_arp_lower = engine7.propose_change(
    "arp_sweep_unique_targets_threshold", 4.0, "confirmed real threats, lowering threshold",
    device_id="arp_dev_b", backtest_run_id="bt7_pass", now=NOW,
)
check("propose_change: arp_sweep LOWER is accepted", r_arp_lower.accepted, r_arp_lower.reason)
if r_arp_lower.accepted:
    row = store7._conn.execute(
        "SELECT old_value, new_value FROM threshold_history WHERE change_id=?",
        (r_arp_lower.change_id,),
    ).fetchone()
    applied_step = row["old_value"] - row["new_value"]
    check("propose_change: an oversized LOWER is clamped to max_step_down (1.0), "
          "not the bigger max_step_up (4.0)",
          abs(applied_step - 1.0) < 1e-9, f"got step={applied_step}")

# fp_combined_suppress_threshold stays a plain symmetric parameter -- confirms
# the optional max_step_up/max_step_down keys don't leak a requirement onto
# parameters that never define them.
fp_bounds = TUNABLE_PARAMETERS["fp_combined_suppress_threshold"]
check("TUNABLE_PARAMETERS: fp_combined_suppress_threshold stays plain-symmetric "
      "(no max_step_up/max_step_down needed)",
      "max_step" in fp_bounds and "max_step_up" not in fp_bounds and "max_step_down" not in fp_bounds)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 autotune engine checks PASSED.")
