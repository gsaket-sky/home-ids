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
`.venv/Scripts/python.exe tests/test_v13_autotune_engine.py`
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


from v13.autotune.engine import AutotuneEngine, TUNABLE_PARAMETERS  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402

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


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 autotune engine checks PASSED.")
