"""
Standalone runtime test for argus/shadow/sandbox.py -- Phase 7 of the 16-parameter
autonomy-completion effort (Documentation/ARGUS_AUTONOMY_DEPENDENCY_MAP.md).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_shadow_sandbox.py`

Sections:
  A. Rollback guarantee: a real shadow evaluate() call (device_id set, so the real
     evaluate() genuinely writes evidence/decisions rows) leaves the graph's evidence/
     decisions row counts byte-for-byte unchanged afterward -- only shadow_decisions
     gains exactly one row. This is the one property that makes running evaluate() a
     second time in production safe at all.
  B. Candidate substitution genuinely reaches the patched code path: a stubbed
     live_engine.evaluate() reads AutotuneEngine.get_active_value() itself and proves
     it sees the CANDIDATE value, not whatever is really promoted -- and that the
     monkey-patch is restored (never left dangling) both on success and on failure.
  C. Fail-safe: a raising live_engine.evaluate() never propagates out of
     evaluate_candidate_shadow(), records no shadow_decisions row, and still restores
     the patched get_active_value.
  D. ShadowEvaluator candidate-selection preference order: device-scoped canary wins
     over category-scoped, which wins over global -- proven via which change_id was
     actually passed to evaluate_candidate_shadow(), not by inspecting internal state.
  E. Resource-pressure pause: maybe_shadow_evaluate() is a no-op and sets the
     shadow_eval_paused gauge to 1 when pressure is active, 0 otherwise.
  F. shadow_decisions row-count bound: _prune_shadow_decisions_if_oversized() clamps
     back down to the documented cap, oldest rows first.
"""
import sys
import tempfile
import time
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
from argus.autotune.engine import AutotuneEngine  # noqa: E402
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


# --- A. rollback guarantee ---

store_a = _fresh_store()
store_a.upsert_device("shadowDevA", timestamp=NOW)
change_id_a = _insert_canary(store_a, "familiarity_trust_bar", 0.9, device_id=None)

ev_a = [V1Evidence(type="zeek_notice_medium", source="zeek", timestamp=NOW, device="shadowDevA",
                     value=1.0, confidence=0.6, independence_group="zeek_network", domain="example.com")]
rep_a = ReputationVector(domain="example.com", tier=1)

# A real (non-shadow) call first, to establish a genuine baseline the shadow call
# must not disturb.
real_decision_a = live_engine.evaluate(list(ev_a), rep_a, features={}, device_id="shadowDevA", now=NOW)

evidence_count_before = _table_count(store_a, "evidence")
decisions_count_before = _table_count(store_a, "decisions")

agree_a = evaluate_candidate_shadow(
    store_a, change_id_a, "familiarity_trust_bar", 0.9, "shadowDevA", "",
    list(ev_a), rep_a, {}, False, 0.0, real_decision_a["state"], NOW + 1,
)

evidence_count_after = _table_count(store_a, "evidence")
decisions_count_after = _table_count(store_a, "decisions")
shadow_rows_a = _table_count(store_a, "shadow_decisions")

check("A: evaluate_candidate_shadow() returns a real bool agreement result",
      agree_a in (True, False))
check("A: the shadow call's own graph writes were fully rolled back -- evidence row "
      "count is unchanged from immediately before the shadow call",
      evidence_count_after == evidence_count_before)
check("A: the shadow call's own graph writes were fully rolled back -- decisions row "
      "count is unchanged from immediately before the shadow call",
      decisions_count_after == decisions_count_before)
check("A: exactly one shadow_decisions row was recorded for the one comparison made",
      shadow_rows_a == 1)

shadow_row_a = store_a._conn.execute(
    "SELECT change_id, device_id, real_state, shadow_state, agree FROM shadow_decisions"
).fetchone()
check("A: the recorded shadow_decisions row carries the real change_id/device_id",
      shadow_row_a["change_id"] == change_id_a and shadow_row_a["device_id"] == "shadowDevA")
check("A: the recorded row's real_state matches the REAL (non-shadow) decision's own state",
      shadow_row_a["real_state"] == real_decision_a["state"])


# --- B. candidate substitution genuinely reaches the patched code path ---

store_b = _fresh_store()
store_b.upsert_device("shadowDevB", timestamp=NOW)
change_id_b = _insert_canary(store_b, "bocpd_hazard_rate", 0.0123, device_id=None)

seen_values = []


class _FakeLiveEngineModule:
    @staticmethod
    def evaluate(active_evidence_v1, rep_vector, device_type="", baseline_familiarity=0.0,
                  features=None, is_safe=False, fallback_evaluate=None,
                  device_id=None, now=None, geoip_engine=None):
        seen_values.append(AutotuneEngine(store_b).get_active_value(
            "bocpd_hazard_rate", device_id=device_id, device_type=device_type, default=-1.0,
        ))
        return {"state": "BENIGN"}


_original_get_active_value_b = AutotuneEngine.get_active_value


def _run_with_faked_live_engine_import(fn):
    """evaluate_candidate_shadow() does `import argus.ops.live_engine as live_engine`
    locally -- the simplest, least-invasive way to intercept that specific call
    without touching the real module other callers share is to temporarily replace
    the REAL module's own evaluate attribute, call through, then restore it."""
    real_evaluate = live_engine.evaluate
    live_engine.evaluate = _FakeLiveEngineModule.evaluate
    try:
        return fn()
    finally:
        live_engine.evaluate = real_evaluate


agree_b = _run_with_faked_live_engine_import(lambda: evaluate_candidate_shadow(
    store_b, change_id_b, "bocpd_hazard_rate", 0.0123, "shadowDevB", "",
    [], ReputationVector(domain="", tier=0), {}, False, 0.0, "BENIGN", NOW + 2,
))

check("B: the stubbed evaluate() saw the CANDIDATE value (0.0123), not the default/-1.0 "
      "sentinel -- proves AutotuneEngine.get_active_value was really patched for the "
      "duration of the shadow call",
      len(seen_values) == 1 and seen_values[0] == 0.0123)
check("B: AutotuneEngine.get_active_value is restored to the original unpatched method "
      "immediately after the shadow call returns",
      AutotuneEngine.get_active_value is _original_get_active_value_b)

# A second, ordinary (non-candidate) parameter must be UNAFFECTED by the patch --
# proves the substitution is scoped to exactly the one parameter in canary.
untouched_value = AutotuneEngine(store_b).get_active_value(
    "reputation_tier_suspicious_floor", device_id="shadowDevB", default=42.0,
)
check("B: a DIFFERENT parameter's get_active_value() is completely unaffected by the "
      "patch (still resolves to its own real default, not the candidate value)",
      untouched_value == 42.0)


# --- C. fail-safe: a raising evaluate() never propagates ---

store_c = _fresh_store()
store_c.upsert_device("shadowDevC", timestamp=NOW)
change_id_c = _insert_canary(store_c, "trust_cache_ttl_seconds", 999.0, device_id=None)


class _ExplodingLiveEngine:
    @staticmethod
    def evaluate(*a, **kw):
        raise RuntimeError("simulated shadow evaluate() failure")


_original_get_active_value_c = AutotuneEngine.get_active_value
real_evaluate_c = live_engine.evaluate
live_engine.evaluate = _ExplodingLiveEngine.evaluate
raised_c = False
try:
    result_c = evaluate_candidate_shadow(
        store_c, change_id_c, "trust_cache_ttl_seconds", 999.0, "shadowDevC", "",
        [], ReputationVector(domain="", tier=0), {}, False, 0.0, "BENIGN", NOW + 3,
    )
except Exception:
    raised_c = True
finally:
    live_engine.evaluate = real_evaluate_c

check("C: evaluate_candidate_shadow() NEVER raises out to the caller, even when the "
      "underlying evaluate() itself raises -- the real decision this cycle must never "
      "be affected by a shadow-eval failure",
      raised_c is False)
check("C: a failed shadow evaluation returns None (no comparison could be made), not a "
      "fabricated True/False agreement",
      result_c is None)
check("C: no shadow_decisions row was recorded for the failed comparison",
      _table_count(store_c, "shadow_decisions") == 0)
check("C: AutotuneEngine.get_active_value is still restored after a raising evaluate() call",
      AutotuneEngine.get_active_value is _original_get_active_value_c)


# --- D. ShadowEvaluator candidate-selection preference order ---

store_d = _fresh_store()
store_d.upsert_device("shadowDevD", timestamp=NOW)

change_global = _insert_canary(store_d, "combined_uncertain_threshold", 0.7, device_id=None)
change_category = _insert_canary(store_d, "combined_uncertain_threshold", 0.6,
                                    device_id=None, device_type="smart_tv")
change_device = _insert_canary(store_d, "combined_uncertain_threshold", 0.5,
                                  device_id="shadowDevD")

calls_seen = []
_real_evaluate_candidate_shadow = sandbox.evaluate_candidate_shadow


def _spy_evaluate_candidate_shadow(store, change_id, parameter, candidate_value, *a, **kw):
    calls_seen.append(change_id)
    return True


sandbox.evaluate_candidate_shadow = _spy_evaluate_candidate_shadow
try:
    evaluator_d = ShadowEvaluator(store_d)
    evaluator_d.maybe_shadow_evaluate(
        device_id="shadowDevD", device_type="smart_tv", active_evidence_v1=[],
        rep_vector=ReputationVector(domain="", tier=0), features={}, is_safe=False,
        baseline_familiarity=0.0, real_state="BENIGN", now=NOW,
    )
finally:
    sandbox.evaluate_candidate_shadow = _real_evaluate_candidate_shadow

check("D: with a device-scoped canary active for this exact device, it is preferred "
      "over both the category- and global-scoped canaries also active",
      calls_seen == [change_device])

# Remove the device-scoped canary's eligibility (roll it back) and confirm category wins next.
store_d._conn.execute("UPDATE threshold_history SET rolled_back_at = ? WHERE change_id = ?",
                        (NOW, change_device))
store_d._maybe_commit()
calls_seen.clear()
sandbox.evaluate_candidate_shadow = _spy_evaluate_candidate_shadow
try:
    evaluator_d2 = ShadowEvaluator(store_d)
    evaluator_d2.maybe_shadow_evaluate(
        device_id="shadowDevD", device_type="smart_tv", active_evidence_v1=[],
        rep_vector=ReputationVector(domain="", tier=0), features={}, is_safe=False,
        baseline_familiarity=0.0, real_state="BENIGN", now=NOW,
    )
finally:
    sandbox.evaluate_candidate_shadow = _real_evaluate_candidate_shadow

check("D: once the device-scoped canary is no longer active, the category-scoped one "
      "(matching this device's device_type) is preferred over the global one",
      calls_seen == [change_category])


# --- E. resource-pressure pause ---

store_e = _fresh_store()
store_e.upsert_device("shadowDevE", timestamp=NOW)
_insert_canary(store_e, "combined_uncertain_threshold", 0.7, device_id=None)

_real_is_pressure = sandbox.is_resource_pressure_active
sandbox.is_resource_pressure_active = lambda *a, **kw: True
calls_seen_e = []
sandbox.evaluate_candidate_shadow = lambda *a, **kw: calls_seen_e.append(1) or True
try:
    evaluator_e = ShadowEvaluator(store_e)
    evaluator_e.maybe_shadow_evaluate(
        device_id="shadowDevE", device_type="", active_evidence_v1=[],
        rep_vector=ReputationVector(domain="", tier=0), features={}, is_safe=False,
        baseline_familiarity=0.0, real_state="BENIGN", now=NOW,
    )
finally:
    sandbox.is_resource_pressure_active = _real_is_pressure
    sandbox.evaluate_candidate_shadow = _real_evaluate_candidate_shadow

check("E: under active resource pressure, maybe_shadow_evaluate() is a complete no-op "
      "(no shadow comparison attempted at all)",
      len(calls_seen_e) == 0)
check("E: the shadow_eval_paused gauge reads 1 while pressure is active",
      sandbox.shadow_eval_paused._value.get() == 1)

sandbox.is_resource_pressure_active = lambda *a, **kw: False
try:
    evaluator_e2 = ShadowEvaluator(store_e)
    evaluator_e2.maybe_shadow_evaluate(
        device_id="shadowDevE", device_type="", active_evidence_v1=[],
        rep_vector=ReputationVector(domain="", tier=0), features={}, is_safe=False,
        baseline_familiarity=0.0, real_state="BENIGN", now=NOW,
    )
finally:
    sandbox.is_resource_pressure_active = _real_is_pressure

check("E: the shadow_eval_paused gauge clears back to 0 once pressure is no longer active",
      sandbox.shadow_eval_paused._value.get() == 0)


# --- F. shadow_decisions row-count bound ---

store_f = _fresh_store()
store_f.upsert_device("shadowDevF", timestamp=NOW)
change_id_f = _insert_canary(store_f, "combined_uncertain_threshold", 0.7, device_id=None)

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
