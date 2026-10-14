"""
U7 (DETECTION_CORE_REWORK section I, handover 2026-10-14): a shadow evaluation of an autotune canary leaves the engine
exactly as a cycle without it would.

The shadow re-ran the whole live_engine.evaluate() inside a graph transaction it rolled back. The rollback undoes graph
rows only; evaluate() also changes in-memory state: the BOCPD baseline trackers observed the cycle a second time, the
Markov activity model learned a spurious "same state again" transition, _last_risk_score / _last_decision_key /
_last_decision_id took the shadow's values (_last_decision_id could name a rolled-back row), and a bocpd_hazard_rate
candidate was written into the champion's warm tracker in place.

Two devices get identical inputs on every cycle; only device B also gets a shadow evaluation. (Written against the old
shadow API first, where the BOCPD, Markov, _last_decision_key/_id and duplicate-row checks failed -- Markov 18 vs 6
counts, 3 vs 1 decision rows; the shadow now re-decides the real cycle's live_engine.EvaluatedCycle.) Everything the engine
keeps per device must be identical for A and B afterwards. Device ids are anonymous test ids; no addresses.

Run directly: `python tests/test_argus_shadow_side_effect_free.py`
"""
import sys
import tempfile
import time
import uuid
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.reputation.classifier import ReputationVector  # noqa: E402
import argus.ops.live_engine as live_engine  # noqa: E402
import argus.baseline.engine as baseline_engine_mod  # noqa: E402
from argus.shadow.sandbox import evaluate_candidate_shadow  # noqa: E402

live_engine.configure(str(_P(tempfile.mkdtemp(prefix="argus_shadow_pure_")) / "graph.db"))
store = live_engine.get_graph_store()
T0 = time.time() - 7200.0          # baseline learning keys on the local hour of `now`; any fixed past time works
WARM = 1900.0                      # the first decision row starts the learning cooldown (1800 s); measure after it
A, B = "devShadowA", "devShadowB"
for dev in (A, B):
    store.upsert_device(dev, timestamp=T0)


def canary(parameter, value, device_id):
    change_id = uuid.uuid4().hex
    store._conn.execute(
        "INSERT INTO threshold_history (change_id, device_id, device_type, parameter, old_value, new_value, "
        "proposed_at, canary_until, reason, backtest_run_id, snapshot_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (change_id, device_id, None, parameter, 0.0, value, T0, T0 + 86400.0, "test canary", "test", None))
    store._maybe_commit()
    return change_id


def inputs(dev, i, ts):
    # Quiet cycles (no attack evidence): baseline learning pauses during and after an incident, and the in-memory
    # learners this test watches only move while it is not paused -- the ordinary state of most devices.
    features = {"query_rate": 10.0 + 7 * i, "entropy_avg": 2.0 + 0.3 * i, "unique_domains": 5 + 2 * i,
                "zeek_outbound_bytes": 1000.0 * (i + 1), "total": 50.0, "nxdomain_ratio": 0.02 * i,
                "blocked_ratio": 0.01}
    return [], ReputationVector(domain="example.com", tier=1), features


change_bar = canary("familiarity_trust_bar", 0.9, B)
change_hazard = canary("bocpd_hazard_rate", 1.0 / 150.0, B)
results = {}
for dev in (A, B):                  # one identical warm-up cycle each, then past the cooldown
    ev, rep, feats = inputs(dev, 0, T0)
    live_engine.evaluate(list(ev), rep, features=dict(feats), device_id=dev, now=T0)
for i in range(6):
    ts = T0 + WARM + 60.0 * i
    for dev in (A, B):
        ev, rep, feats = inputs(dev, i, ts)
        real, cycle = live_engine.evaluate_cycle(list(ev), rep, features=dict(feats), device_id=dev, now=ts)
        if dev == B:
            for change_id, param, value in ((change_bar, "familiarity_trust_bar", 0.9),
                                            (change_hazard, "bocpd_hazard_rate", 1.0 / 150.0)):
                results.setdefault(param, []).append(
                    evaluate_candidate_shadow(store, change_id, param, value, cycle, real["state"], ts))

eng = live_engine._get_baseline_engine()


def trackers(dev):
    out = {}
    for (d, metric, hour), tr in eng._trackers.items():
        if d == dev:
            out[(metric, hour)] = (tr.hazard_rate, [(rl, m.to_dict(), round(w, 12)) for rl, m, w in tr._hypotheses])
    return out


ta, tb = trackers(A), trackers(B)
check("learning is active for both devices (otherwise nothing below is exercised)",
      not eng.is_learning_paused(A, T0 + WARM + 400) and not eng.is_learning_paused(B, T0 + WARM + 400))
check("both devices have baseline trackers (the cycles reached the baseline engine)", bool(ta) and set(ta) == set(tb),
      f"A={sorted(ta)} B={sorted(tb)}")
check("BOCPD tracker posteriors identical: the shadow did not observe the cycle a second time",
      all(ta[k][1] == tb[k][1] for k in ta if k in tb),
      str([k for k in ta if k in tb and ta[k][1] != tb[k][1]]))
check("no hazard leak: B's live trackers keep the champion hazard, not the shadow candidate",
      all(ta[k][0] == tb[k][0] for k in ta if k in tb),
      str({k: (ta[k][0], tb[k][0]) for k in ta if k in tb and ta[k][0] != tb[k][0]}))


def markov(dev):
    m = eng._markov.get((dev, "activity_state"))
    return (m.to_dict() if m is not None else None, eng._last_state.get((dev, "activity_state")))


check("Markov activity model identical: no spurious self-transition learned", markov(A) == markov(B),
      f"A={markov(A)} B={markov(B)}")
check("_last_risk_score identical", live_engine._last_risk_score.get(A) == live_engine._last_risk_score.get(B),
      f"{live_engine._last_risk_score.get(A)} vs {live_engine._last_risk_score.get(B)}")
check("_last_decision_key identical", live_engine._last_decision_key.get(A) == live_engine._last_decision_key.get(B),
      f"{live_engine._last_decision_key.get(A)} vs {live_engine._last_decision_key.get(B)}")
bid = live_engine._last_decision_id.get(B)
row = store._conn.execute("SELECT 1 FROM decisions WHERE decision_id=?", (bid,)).fetchone() if bid else None
check("_last_decision_id of B names a decision row that exists (not a rolled-back shadow row)", row is not None, str(bid))
n_a = store._conn.execute("SELECT COUNT(*) FROM decisions WHERE device_id=?", (A,)).fetchone()[0]
n_b = store._conn.execute("SELECT COUNT(*) FROM decisions WHERE device_id=?", (B,)).fetchone()[0]
check("same number of persisted decision rows for A and B", n_a == n_b, f"{n_a} vs {n_b}")
ev_a = store._conn.execute("SELECT COUNT(*) FROM evidence WHERE device_id=?", (A,)).fetchone()[0]
ev_b = store._conn.execute("SELECT COUNT(*) FROM evidence WHERE device_id=?", (B,)).fetchone()[0]
check("same number of persisted evidence rows for A and B", ev_a == ev_b, f"{ev_a} vs {ev_b}")
shadow_rows = store._conn.execute("SELECT change_id FROM shadow_decisions").fetchall()
check("the decide-stage candidate (familiarity_trust_bar) got its shadow comparisons recorded",
      sum(1 for r in shadow_rows if r[0] == change_bar) == 6 and all(r in (True, False) for r in results.get(
          "familiarity_trust_bar", [])), f"{len(shadow_rows)} {results}")
check("a non-decide parameter (bocpd_hazard_rate acts in a stateful learner) is not shadow-compared: no row, None",
      not any(r[0] == change_hazard for r in shadow_rows) and set(results.get("bocpd_hazard_rate", [])) == {None},
      str(results.get("bocpd_hazard_rate")))

# --- Scenario 2: a candidate that changes the decision. The real decision is SUSPICIOUS, the shadow's (lower
# reputation floor) CRITICAL. The shadow must not move the device's "last decision" bookkeeping: before, it took the
# shadow's key and the id of a row that was then rolled back, so the next real cycle wrote a duplicate row.
from intelligence.hypotheses.evidence import Evidence as V1Evidence  # noqa: E402
from intelligence.reputation.classifier import ReputationClassifier  # noqa: E402

C, D = "devShadowC", "devShadowD"
for dev in (C, D):
    store.upsert_device(dev, timestamp=T0)
rep2 = ReputationClassifier().classify("flagged.example.net", vt_score=0.0, afpe_score=0.0, is_new=False,
                                       ti_score=1.5, abuse_score=0.0, asn_owner="")
change_floor = canary("reputation_tier_suspicious_floor", 1.0, D)
states = {}
ids_after_first = {}
for i in range(3):
    ts = T0 + WARM + 1000.0 + 60.0 * i
    for dev in (C, D):
        ev2 = [V1Evidence(type="dns_rate", source="dns", timestamp=ts, device=dev, value=3.0, confidence=0.5, domain="flagged.example.net")]
        real2, cycle2 = live_engine.evaluate_cycle(list(ev2), rep2, features={}, device_id=dev, now=ts)
        states.setdefault(dev, []).append(real2["state"])
        if dev == D:
            evaluate_candidate_shadow(store, change_floor, "reputation_tier_suspicious_floor", 1.0, cycle2,
                                      real2["state"], ts)
        if i == 0:
            ids_after_first[dev] = live_engine._last_decision_id.get(dev)
shadow_states = [r[0] for r in store._conn.execute(
    "SELECT shadow_state FROM shadow_decisions WHERE change_id=?", (change_floor,)).fetchall()]
check("scenario 2 setup: real decisions SUSPICIOUS, the shadow's CRITICAL (the candidate changes the verdict)",
      states.get(D, [None])[0] == "SUSPICIOUS" and "CRITICAL" in shadow_states, f"real={states} shadow={shadow_states}")
check("scenario 2: _last_decision_key of D is the real decision's, as for C",
      live_engine._last_decision_key.get(C) == live_engine._last_decision_key.get(D),
      f"{live_engine._last_decision_key.get(C)} vs {live_engine._last_decision_key.get(D)}")
row_d = store._conn.execute("SELECT 1 FROM decisions WHERE decision_id=?", (ids_after_first.get(D),)).fetchone()
check("scenario 2: after the first shadow, D's _last_decision_id names a row that exists", row_d is not None,
      str(ids_after_first.get(D)))
n_c = store._conn.execute("SELECT COUNT(*) FROM decisions WHERE device_id=?", (C,)).fetchone()[0]
n_d = store._conn.execute("SELECT COUNT(*) FROM decisions WHERE device_id=?", (D,)).fetchone()[0]
check("scenario 2: no duplicate decision rows for D (same count as C)", n_c == n_d, f"C={n_c} D={n_d}")

# --- decide() is pure: the same cycle and parameters give the same decision, and nothing it is given changes ---
features_before = dict(cycle2.gathered.features or {})
first, _ = live_engine.decide(cycle2.gathered, cycle2.params)
second, _ = live_engine.decide(cycle2.gathered, cycle2.params)
keys = ("state", "explanation", "threat_confidence", "decision_path", "independent_sources", "evidence_families")
check("decide() twice on one cycle gives the same decision", all(first.get(k) == second.get(k) for k in keys),
      str({k: (first.get(k), second.get(k)) for k in keys}))
check("decide() leaves the gathered features unchanged (read-only copy)",
      dict(cycle2.gathered.features or {}) == features_before)
try:
    cycle2.gathered.features["injected"] = 1
    check("the gathered features cannot be written", False, "write succeeded")
except TypeError:
    check("the gathered features cannot be written", True)

print("SHADOW SIDE-EFFECT FREE", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
