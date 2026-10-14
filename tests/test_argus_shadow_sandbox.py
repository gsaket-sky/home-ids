"""
Standalone runtime test for argus/shadow/sandbox.py -- Phase 7 of the 16-parameter
autonomy-completion effort (Documentation/ARGUS_AUTONOMY_DEPENDENCY_MAP.md).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_shadow_sandbox.py`

Since U7 (2026-10-14) the shadow is live_engine.decide() on the real cycle's EvaluatedCycle
(gathered facts + champion parameters) with one parameter replaced -- no second gather, no
graph transaction. tests/test_argus_shadow_side_effect_free.py covers the in-memory side
effects; this file covers the sandbox's own contract.

Sections:
  A. Writes nothing but its own row: a shadow comparison leaves the graph's evidence/
     decisions row counts unchanged -- only shadow_decisions gains exactly one row,
     carrying the real change_id/device_id/real_state.
  B. The candidate reaches decide(): decide() receives the real cycle's gathered facts
     (the same object) and the champion parameters with exactly the one canary field
     replaced.
  C. Fail-safe: a raising decide() never propagates out of evaluate_candidate_shadow(),
     returns None and records no shadow_decisions row.
  D. ShadowEvaluator candidate-selection preference order: device-scoped canary wins
     over category-scoped, which wins over global -- proven via which change_id was
     actually passed to evaluate_candidate_shadow(), not by inspecting internal state.
  E. Resource-pressure pause: maybe_shadow_evaluate() is a no-op and sets the
     shadow_eval_paused gauge to 1 when pressure is active, 0 otherwise.
  F. shadow_decisions row-count bound: _prune_shadow_decisions_if_oversized() clamps
     back down to the documented cap, oldest rows first.
  G. Only decide-stage parameters (live_engine.DECIDE_PARAMETERS) are shadow-compared: a
     candidate for any other tunable returns None, records no row and never reaches
     decide(); ShadowEvaluator does not select such canaries. (The old thread-local
     autotuner override -- runtime trace run 2, finding 4.4 -- is gone with the re-run:
     the candidate never reaches the autotuner at all.)
"""
import dataclasses
import sys
import tempfile
import uuid
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.hypotheses.evidence import Evidence as V1Evidence  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402
import argus.ops.live_engine as live_engine  # noqa: E402
import argus.shadow.sandbox as sandbox  # noqa: E402
from argus.shadow.sandbox import ShadowEvaluator, evaluate_candidate_shadow  # noqa: E402

NOW = 1_700_000_000.0


def _fresh_store():
    tmpdir = tempfile.mkdtemp(prefix="argus_shadow_sandbox_test_")
    graph_db_path = str(_PathForSysPath(tmpdir) / "graph.db")
    live_engine.configure(graph_db_path)
    return live_engine.get_graph_store()


def _insert_canary(store, parameter, new_value, device_id=None, device_type=None,
                     canary_until=None):
    change_id = uuid.uuid4().hex
    store._conn.execute(
        "INSERT INTO threshold_history "
        "(change_id, device_id, device_type, parameter, old_value, new_value, proposed_at, "
        "canary_until, reason, backtest_run_id, snapshot_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (change_id, device_id, device_type, parameter, 0.5, new_value, NOW,
         canary_until if canary_until is not None else NOW + 3600.0,
         "test canary", "fake_backtest_run", None),
    )
    store._maybe_commit()
    return change_id


def _table_count(store, table):
    return store._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def _quiet_cycle(device_id, device_type=""):
    return live_engine.evaluate_cycle([], ReputationVector(domain="", tier=0), device_type=device_type,
                                      features={}, device_id=device_id, now=NOW)[1]


# --- A. writes nothing but its own row ---

store_a = _fresh_store()
store_a.upsert_device("shadowDevA", timestamp=NOW)
change_id_a = _insert_canary(store_a, "familiarity_trust_bar", 0.9, device_id=None)

ev_a = [V1Evidence(type="zeek_notice_medium", source="zeek", timestamp=NOW, device="shadowDevA",
                     value=1.0, confidence=0.6, domain="example.com")]
rep_a = ReputationVector(domain="example.com", tier=1)
real_decision_a, cycle_a = live_engine.evaluate_cycle(list(ev_a), rep_a, features={}, device_id="shadowDevA",
                                                      now=NOW)

evidence_count_before = _table_count(store_a, "evidence")
decisions_count_before = _table_count(store_a, "decisions")
agree_a = evaluate_candidate_shadow(store_a, change_id_a, "familiarity_trust_bar", 0.9, cycle_a,
                                    real_decision_a["state"], NOW + 1)

check("A: evaluate_candidate_shadow() returns a real bool agreement result", agree_a in (True, False))
check("A: the shadow comparison wrote no evidence row", _table_count(store_a, "evidence") == evidence_count_before)
check("A: the shadow comparison wrote no decisions row",
      _table_count(store_a, "decisions") == decisions_count_before)
check("A: exactly one shadow_decisions row was recorded for the one comparison made",
      _table_count(store_a, "shadow_decisions") == 1)
shadow_row_a = store_a._conn.execute(
    "SELECT change_id, device_id, real_state, shadow_state, agree FROM shadow_decisions"
).fetchone()
check("A: the recorded shadow_decisions row carries the real change_id/device_id",
      shadow_row_a["change_id"] == change_id_a and shadow_row_a["device_id"] == "shadowDevA")
check("A: the recorded row's real_state matches the REAL decision's own state",
      shadow_row_a["real_state"] == real_decision_a["state"])


# --- B. the candidate reaches decide(), nothing else changes ---

store_b = _fresh_store()
store_b.upsert_device("shadowDevB", timestamp=NOW)
change_id_b = _insert_canary(store_b, "peer_deviation_multiplier", 4.5, device_id=None)
cycle_b = _quiet_cycle("shadowDevB")
seen_b = []
_real_decide = live_engine.decide


def _capturing_decide(gathered, params):
    seen_b.append((gathered, params))
    return _real_decide(gathered, params)


live_engine.decide = _capturing_decide
try:
    evaluate_candidate_shadow(store_b, change_id_b, "peer_deviation_multiplier", 4.5, cycle_b, "BENIGN", NOW + 2)
finally:
    live_engine.decide = _real_decide

check("B: decide() was called once, on the real cycle's own gathered facts (same object)",
      len(seen_b) == 1 and seen_b[0][0] is cycle_b.gathered)
check("B: decide() got the CANDIDATE value for the canary parameter",
      bool(seen_b) and seen_b[0][1].peer_deviation_multiplier == 4.5)
check("B: every other parameter is the champion's, unchanged",
      bool(seen_b) and dataclasses.replace(
          seen_b[0][1], peer_deviation_multiplier=cycle_b.params.peer_deviation_multiplier) == cycle_b.params)


# --- C. fail-safe: a raising decide() never propagates ---

store_c = _fresh_store()
store_c.upsert_device("shadowDevC", timestamp=NOW)
change_id_c = _insert_canary(store_c, "familiarity_trust_bar", 0.8, device_id=None)
cycle_c = _quiet_cycle("shadowDevC")


def _exploding_decide(gathered, params):
    raise RuntimeError("simulated shadow decide() failure")


live_engine.decide = _exploding_decide
raised_c = False
result_c = "not run"
try:
    result_c = evaluate_candidate_shadow(store_c, change_id_c, "familiarity_trust_bar", 0.8, cycle_c, "BENIGN",
                                         NOW + 3)
except Exception:
    raised_c = True
finally:
    live_engine.decide = _real_decide

check("C: evaluate_candidate_shadow() never raises out to the caller, even when decide() raises", raised_c is False)
check("C: a failed shadow evaluation returns None, not a fabricated agreement", result_c is None)
check("C: no shadow_decisions row was recorded for the failed comparison",
      _table_count(store_c, "shadow_decisions") == 0)


# --- G. only decide-stage parameters are shadow-compared ---

store_g = _fresh_store()
store_g.upsert_device("shadowDevG", timestamp=NOW)
change_id_g = _insert_canary(store_g, "trust_cache_ttl_seconds", 172800.0, device_id=None)
cycle_g = _quiet_cycle("shadowDevG")
calls_g = []
live_engine.decide = lambda gathered, params: calls_g.append(1) or _real_decide(gathered, params)
try:
    result_g = evaluate_candidate_shadow(store_g, change_id_g, "trust_cache_ttl_seconds", 172800.0, cycle_g,
                                         "BENIGN", NOW + 4)
finally:
    live_engine.decide = _real_decide
check("G: trust_cache_ttl_seconds is not a decide-stage parameter",
      "trust_cache_ttl_seconds" not in live_engine.DECIDE_PARAMETERS)
check("G: a non-decide candidate returns None, never reaches decide(), records no row",
      result_g is None and not calls_g and _table_count(store_g, "shadow_decisions") == 0)
spy_g = []
_real_evaluate_candidate_shadow = sandbox.evaluate_candidate_shadow
sandbox.evaluate_candidate_shadow = lambda *a, **kw: spy_g.append(a[1]) or True
try:
    ShadowEvaluator(store_g).maybe_shadow_evaluate(cycle_g, real_state="BENIGN", now=NOW)
finally:
    sandbox.evaluate_candidate_shadow = _real_evaluate_candidate_shadow
check("G: ShadowEvaluator does not select a canary whose parameter is not decide-stage", spy_g == [], str(spy_g))


# --- D. ShadowEvaluator candidate-selection preference order ---

store_d = _fresh_store()
store_d.upsert_device("shadowDevD", timestamp=NOW)
change_global = _insert_canary(store_d, "familiarity_trust_bar", 0.7, device_id=None)
change_category = _insert_canary(store_d, "familiarity_trust_bar", 0.6, device_id=None, device_type="smart_tv")
change_device = _insert_canary(store_d, "familiarity_trust_bar", 0.5, device_id="shadowDevD")
cycle_d = _quiet_cycle("shadowDevD", device_type="smart_tv")

calls_seen = []


def _spy_evaluate_candidate_shadow(store, change_id, parameter, candidate_value, *a, **kw):
    calls_seen.append(change_id)
    return True


sandbox.evaluate_candidate_shadow = _spy_evaluate_candidate_shadow
try:
    ShadowEvaluator(store_d).maybe_shadow_evaluate(cycle_d, real_state="BENIGN", now=NOW)
finally:
    sandbox.evaluate_candidate_shadow = _real_evaluate_candidate_shadow

check("D: with a device-scoped canary active for this exact device, it is preferred "
      "over both the category- and global-scoped canaries also active",
      calls_seen == [change_device])

store_d._conn.execute("UPDATE threshold_history SET rolled_back_at = ? WHERE change_id = ?", (NOW, change_device))
store_d._maybe_commit()
calls_seen.clear()
sandbox.evaluate_candidate_shadow = _spy_evaluate_candidate_shadow
try:
    ShadowEvaluator(store_d).maybe_shadow_evaluate(cycle_d, real_state="BENIGN", now=NOW)
finally:
    sandbox.evaluate_candidate_shadow = _real_evaluate_candidate_shadow

check("D: once the device-scoped canary is no longer active, the category-scoped one "
      "(matching this device's device_type) is preferred over the global one",
      calls_seen == [change_category])


# --- E. resource-pressure pause ---

store_e = _fresh_store()
store_e.upsert_device("shadowDevE", timestamp=NOW)
_insert_canary(store_e, "familiarity_trust_bar", 0.7, device_id=None)
cycle_e = _quiet_cycle("shadowDevE")

_real_is_pressure = sandbox.is_resource_pressure_active_in_process
sandbox.is_resource_pressure_active_in_process = lambda *a, **kw: True
calls_seen_e = []
sandbox.evaluate_candidate_shadow = lambda *a, **kw: calls_seen_e.append(1) or True
try:
    ShadowEvaluator(store_e).maybe_shadow_evaluate(cycle_e, real_state="BENIGN", now=NOW)
finally:
    sandbox.is_resource_pressure_active_in_process = _real_is_pressure
    sandbox.evaluate_candidate_shadow = _real_evaluate_candidate_shadow

check("E: under active resource pressure, maybe_shadow_evaluate() is a complete no-op "
      "(no shadow comparison attempted at all)",
      len(calls_seen_e) == 0)
check("E: the shadow_eval_paused gauge reads 1 while pressure is active",
      sandbox.shadow_eval_paused._value.get() == 1)

sandbox.is_resource_pressure_active_in_process = lambda *a, **kw: False
try:
    ShadowEvaluator(store_e).maybe_shadow_evaluate(cycle_e, real_state="BENIGN", now=NOW)
finally:
    sandbox.is_resource_pressure_active_in_process = _real_is_pressure

check("E: the shadow_eval_paused gauge clears back to 0 once pressure is no longer active",
      sandbox.shadow_eval_paused._value.get() == 0)


# --- F. shadow_decisions row-count bound ---

store_f = _fresh_store()
store_f.upsert_device("shadowDevF", timestamp=NOW)
change_id_f = _insert_canary(store_f, "familiarity_trust_bar", 0.7, device_id=None)

cap = sandbox._MAX_SHADOW_DECISIONS
for i in range(cap + 25):
    store_f._conn.execute(
        "INSERT INTO shadow_decisions (shadow_id, change_id, device_id, timestamp, real_state, "
        "shadow_state, agree) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (uuid.uuid4().hex, change_id_f, "shadowDevF", NOW + i, "BENIGN", "BENIGN", 1),
    )
store_f._maybe_commit()
check("F: setup wrote more rows than the documented cap",
      _table_count(store_f, "shadow_decisions") == cap + 25)

sandbox._prune_shadow_decisions_if_oversized(store_f)
check("F: pruning brings the row count back down to exactly the documented cap",
      _table_count(store_f, "shadow_decisions") == cap)

remaining_timestamps = [r[0] for r in store_f._conn.execute(
    "SELECT timestamp FROM shadow_decisions ORDER BY timestamp ASC").fetchall()]
check("F: pruning removed the OLDEST rows first, keeping the most recent ones",
      remaining_timestamps[0] == NOW + 25)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All argus/shadow/sandbox.py checks PASSED.")
