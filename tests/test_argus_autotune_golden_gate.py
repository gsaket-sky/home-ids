"""
Golden guard at the point of use (DETECTION_CORE_REWORK.md H2, MASTER_TODO 0d P0): the autotuner refuses to propose, and
refuses to promote, a value of a decide() parameter under which a golden safety bound breaks that the scope's current
values do not already break ("a missed attack or a newly alerting confounder rejects the challenger at once").

Measured 2026-10-14 with the golden set, inside TUNABLE_PARAMETERS' bounds: reputation_tier_suspicious_floor 1.0 turns
one threat-intel score of 1.5 into a verified-feed containment exception, 5.0 hides a real feed match;
hard_stop_candidate_sensitivity 0.99 drops a corroborated Suricata case to SUSPICIOUS. Before this gate each was
reachable by bounded steps through propose_change/promote_change.

Run directly: `python tests/test_argus_autotune_golden_gate.py`
"""
import sys
from pathlib import Path as _P
from unittest import mock
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.autotune.engine import AutotuneEngine, _DEFAULT_CANARY_SECONDS  # noqa: E402
from argus.golden import guard  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
import argus.ops.live_engine as live_engine  # noqa: E402

NOW = 1_800_000_000.0


def fresh():
    store = GraphStore(":memory:")
    store._conn.execute(
        "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass, golden_set_result_json) "
        "VALUES ('bt', ?, ?, 1, '{\"passed\": true}')", (NOW - 10, NOW - 10))
    store._maybe_commit()
    return store, AutotuneEngine(store)


def promoted(store, parameter, value, device_id=None, device_type=None, at=NOW - 86400):
    if device_id is not None:
        store.ensure_device(device_id, timestamp=at)
    store._conn.execute(
        "INSERT INTO threshold_history (change_id, device_id, device_type, parameter, old_value, new_value, "
        "proposed_at, canary_until, promoted_at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'test')",
        (f"p_{parameter}_{device_id}_{device_type}_{value}", device_id, device_type, parameter, value, value,
         at, at, at))
    store._maybe_commit()


def rows(store, parameter):
    return store._conn.execute("SELECT COUNT(*) AS n FROM threshold_history WHERE parameter=? AND promoted_at IS NULL",
                               (parameter,)).fetchone()["n"]


# --- 1. a floor that turns one weak feed score into a containment exception -----------------------------------------
store, engine = fresh()
promoted(store, "reputation_tier_suspicious_floor", 1.5)
r = engine.propose_change("reputation_tier_suspicious_floor", 1.0, "test", backtest_run_id="bt", now=NOW, default=2.0)
check("a global floor of 1.0 (one weak feed score -> verified-IOC containment) is refused",
      not r.accepted and "golden guard" in r.reason and "reputation_weak_signal_plus_feed_score" in r.reason, r.reason)
check("... and nothing is written", rows(store, "reputation_tier_suspicious_floor") == 0)

# --- 2. a floor that hides a real feed match --------------------------------------------------------------------------
store, engine = fresh()
promoted(store, "reputation_tier_suspicious_floor", 3.5)
r = engine.propose_change("reputation_tier_suspicious_floor", 4.0, "test", backtest_run_id="bt", now=NOW, default=2.0)
check("a global floor of 4.0 (a feed score of 3.5 is no longer a verified IOC) is refused -- also when the current "
      "value already breaks the same bound (a broken parameter may not drift further)",
      not r.accepted and "exception_verified_feed_ioc" in r.reason, r.reason)

store, engine = fresh()
promoted(store, "reputation_tier_suspicious_floor", 5.0)
r = engine.propose_change("reputation_tier_suspicious_floor", 4.5, "test", backtest_run_id="bt", now=NOW, default=2.0)
check("a broken value may move back toward the default in bounded steps (5.0 -> 4.5, still broken, adds nothing)",
      r.accepted, r.reason)

# --- 3. a hard-stop sensitivity that drops a corroborated Suricata case ------------------------------------------------
store, engine = fresh()
promoted(store, "hard_stop_candidate_sensitivity", 0.95)
r = engine.propose_change("hard_stop_candidate_sensitivity", 0.99, "test", backtest_run_id="bt", now=NOW, default=0.9)
check("hard_stop_candidate_sensitivity 0.99 is refused", not r.accepted and "suricata_with_lateral_scan" in r.reason,
      r.reason)

# --- 4. device scope ---------------------------------------------------------------------------------------------------
store, engine = fresh()
promoted(store, "reputation_tier_suspicious_floor", 1.5, device_id="dev-a")
r = engine.propose_change("reputation_tier_suspicious_floor", 1.0, "test", device_id="dev-a", backtest_run_id="bt",
                          now=NOW, default=2.0)
check("a device-scoped value is guarded with that device's values, and the reason names the scope",
      not r.accepted and "device dev-a" in r.reason, r.reason)

# --- 5. harmless values and other parameters pass ----------------------------------------------------------------------
store, engine = fresh()
r = engine.propose_change("familiarity_trust_bar", 0.65, "test", backtest_run_id="bt", now=NOW, default=0.6)
check("a value inside every golden bound is accepted", r.accepted, r.reason)
r = engine.propose_change("bocpd_hazard_rate", 1.0 / 300.0, "test", backtest_run_id="bt", now=NOW, default=1.0 / 250.0)
check("a parameter decide() does not read is not golden-guarded (accepted as before)", r.accepted, r.reason)

# --- 6. differential: a pre-existing failure elsewhere does not freeze all tuning --------------------------------------
store, engine = fresh()
promoted(store, "reputation_tier_suspicious_floor", 5.0, device_id="dev-legacy")   # written before the guard existed
r = engine.propose_change("familiarity_trust_bar", 0.65, "test", backtest_run_id="bt", now=NOW, default=0.6)
check("a global change is not refused for a failure a device already had before it", r.accepted, r.reason)
ok, why = engine.golden_guard_verdict("reputation_tier_suspicious_floor", 3.0)
check("the verdict for a passing value says ok", ok, why)

# --- 7. a global change is guarded for every device that inherits it ----------------------------------------------------
store, engine = fresh()
promoted(store, "hard_stop_candidate_sensitivity", 0.95, device_id="dev-tuned")
promoted(store, "familiarity_trust_bar", 0.7, device_id="dev-own-bar")
seen = []
real_run_guard = guard.run_guard


def recording(cases=None, overrides=None, check_pins=None):
    seen.append(dict(overrides or {}))
    return real_run_guard(cases, overrides, check_pins)


with mock.patch.object(guard, "run_guard", recording):
    r = engine.propose_change("familiarity_trust_bar", 0.65, "test", backtest_run_id="bt", now=NOW, default=0.6)
check("a global proposal is checked for the global scope and for each tuned device that inherits it",
      r.accepted and any(o.get("hard_stop_candidate_sensitivity") == 0.95 and o.get("familiarity_trust_bar") == 0.65
                         for o in seen)
      and any(o.get("hard_stop_candidate_sensitivity") is None and o.get("familiarity_trust_bar") == 0.65 for o in seen),
      seen)
check("a device with its own value for the parameter is not affected by the global change (not checked for it)",
      not any(o.get("familiarity_trust_bar") == 0.7 for o in seen), seen)
check("the live parameter resolution is what the gate mirrors (device tier, then global)",
      engine._effective_decide_values("dev-own-bar")["familiarity_trust_bar"] == 0.7
      and engine._effective_decide_values(None)["familiarity_trust_bar"] == live_engine.CHAMPION_DEFAULTS.familiarity_trust_bar)

# --- 8. promotion re-checks (the code may have changed since the proposal) ---------------------------------------------
store, engine = fresh()
r = engine.propose_change("familiarity_trust_bar", 0.65, "test", backtest_run_id="bt", now=NOW, default=0.6)
store._conn.execute(
    "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass, golden_set_result_json) "
    "VALUES ('bt2', ?, ?, 1, '{\"passed\": true}')", (NOW + 100, NOW + 100))
store._maybe_commit()
real_decide = live_engine.decide


def regressed_decide(gathered, params):
    decision, merged = real_decide(gathered, params)
    if params.familiarity_trust_bar == 0.65:
        decision = {**decision, "state": "BENIGN", "action": "suppress", "single_signal_basis": None,
                    "independent_sources": 0}
    return decision, merged


with mock.patch.object(live_engine, "decide", regressed_decide):
    promoted_ok = engine.promote_change(r.change_id, "bt2", now=NOW + _DEFAULT_CANARY_SECONDS + 1)
row = store._conn.execute("SELECT promoted_at, rolled_back_at, reason FROM threshold_history WHERE change_id=?",
                          (r.change_id,)).fetchone()
check("a canary whose value now breaks a golden bound is not promoted",
      not promoted_ok and row["promoted_at"] is None, dict(row))
check("... it is rolled back with the golden-guard reason (rejected at once, not left in canary)",
      row["rolled_back_at"] is not None and "golden guard" in row["reason"], dict(row))

store, engine = fresh()
r = engine.propose_change("familiarity_trust_bar", 0.65, "test", backtest_run_id="bt", now=NOW, default=0.6)
store._conn.execute(
    "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass, golden_set_result_json) "
    "VALUES ('bt2', ?, ?, 1, '{\"passed\": true}')", (NOW + 100, NOW + 100))
store._maybe_commit()
check("a canary that still passes is promoted as before",
      engine.promote_change(r.change_id, "bt2", now=NOW + _DEFAULT_CANARY_SECONDS + 1))

# --- 9. fail closed: no golden set, no tuning of decide() parameters ---------------------------------------------------
store, engine = fresh()


def _missing(*_a, **_k):
    raise FileNotFoundError("cases.json")


with mock.patch.object(guard, "load_cases", _missing):
    r = engine.propose_change("familiarity_trust_bar", 0.65, "test", backtest_run_id="bt", now=NOW, default=0.6)
    r2 = engine.propose_change("bocpd_hazard_rate", 1.0 / 300.0, "test", backtest_run_id="bt", now=NOW,
                               default=1.0 / 250.0)
check("without the golden set a decide() parameter is never tuned (fail closed)",
      not r.accepted and "unavailable" in r.reason, r.reason)
check("... other parameters are unaffected", r2.accepted, r2.reason)

print("AUTOTUNE GOLDEN GATE", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
