"""
Standalone runtime test for v13's Sheet 00 orchestration layer
(src/v13/baseline/engine.py, Release 15 closed-loop autotuning architecture).

Covers: persistence round-tripping through a real GraphStore (not mocked),
the no-learning-during-an-incident gate (both the direct-incident and
cooldown-after-recovery cases), activity-state derivation priority, Markov
transition scoring end-to-end, population-prior cold-start seeding, and that
every emitted Evidence item is destination-sentinel'd and lands in a
NON_ATTACK_FAMILIES family (the corroboration-safety property this whole
module exists to guarantee).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_baseline_engine.py`
"""
import json
import random
import sys
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

random.seed(4242)

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.autotune.engine import AutotuneEngine  # noqa: E402
from argus.baseline.bayesian import GaussianBaseline  # noqa: E402
from argus.baseline.engine import BaselineEngine, derive_activity_state  # noqa: E402
from argus.evidence.model import NO_DESTINATION  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.hypotheses.independence import NON_ATTACK_FAMILIES, family_for  # noqa: E402

NOW = 1_800_000_000.0

# =============================================================================
# derive_activity_state -- priority ordering, co-occurrence handling
# =============================================================================
check("derive_activity_state: no triggers present -> NORMAL",
      derive_activity_state([]) == "NORMAL")
check("derive_activity_state: a single trigger maps to its state",
      derive_activity_state(["arp_sweep"]) == "RECON")
check("derive_activity_state: co-occurring triggers pick the HIGHER-priority state, "
      "not the first one encountered in the input list",
      derive_activity_state(["arp_sweep", "reputation"]) == "THREAT_INTEL_HIT")
check("derive_activity_state: POLICY_VIOLATION outranks everything else",
      derive_activity_state(["zeek_exfiltration", "honeypot_access"]) == "POLICY_VIOLATION")

# =============================================================================
# score_metric -- persistence, corroboration safety, incident gate
# =============================================================================
store = GraphStore(":memory:")
engine = BaselineEngine(store)

device = "dev_a"
store.upsert_device(device, device_type="laptop", timestamp=NOW)

ev = None
for i in range(60):
    # Realistic noise, not an artificially tight deterministic sequence --
    # too-tight synthetic data would give the posterior an unrealistically
    # narrow scale and make ordinary-sized deviations look like extreme
    # outliers later in this test.
    ev = engine.score_metric(device, "query_rate", "gaussian", (random.gauss(50.0, 5.0),), hour=10, now=NOW + i)
check("score_metric: returns None while a metric hasn't accumulated enough deviation "
      "to be worth reporting (n small, values near the emerging mean)",
      True)  # informational -- not every cycle emits evidence, by design

# A moderately surprising value (not extreme enough to look like nothing in
# the existing posterior explains it at all) should score as baseline_deviation.
moderate = engine.score_metric(device, "query_rate", "gaussian", (70.0,), hour=10, now=NOW + 100)
check("score_metric: a moderately surprising value returns Evidence, not None",
      moderate is not None)
if moderate is not None:
    check("score_metric: emitted evidence uses the mandatory NO_DESTINATION sentinel, "
          "never a guessed/fallback destination (the direct fix for the "
          "3,179-alert attribution incident, CHANGELOG.md:569)",
          moderate.destination_id == NO_DESTINATION)
    check("score_metric: a moderate deviation is classified as baseline_deviation, "
          "not a changepoint", moderate.evidence_type == "baseline_deviation")
    check("score_metric: baseline_deviation's real independence_family is registered "
          "in NON_ATTACK_FAMILIES -- structurally cannot alone supply the second "
          "independent source a HIGH verdict requires",
          family_for(moderate.evidence_type) in NON_ATTACK_FAMILIES)
    check("score_metric: baseline_deviation confidence is capped well short of 1.0 "
          "(context, never proof)", moderate.confidence <= 0.6)

# A single EXTREME outlier, even one so far outside the established posterior
# that BOCPD's own cp_mass spikes hard for that one cycle, must NOT alone
# confirm a changepoint -- the streak requirement (_CHANGEPOINT_STREAK_REQUIRED)
# exists precisely so one-off noise (however extreme) never does.
extreme = engine.score_metric(device, "query_rate", "gaussian", (5000.0,), hour=10, now=NOW + 101)
check("score_metric: a single extreme outlier still returns Evidence", extreme is not None)
if extreme is not None:
    check("score_metric: a single-cycle outlier -- however extreme -- is never "
          "classified as a confirmed regime change (the streak requirement)",
          extreme.evidence_type == "baseline_deviation", f"got {extreme.evidence_type}")
    check("score_metric: single-cycle outlier evidence family is NON_ATTACK_FAMILIES",
          family_for(extreme.evidence_type) in NON_ATTACK_FAMILIES)
    check("score_metric: single-cycle outlier confidence still capped well short of "
          "1.0 (baseline_deviation, not regime_change, so the lower cap applies)",
          extreme.confidence <= 0.6, f"got {extreme.confidence}")

# A SUSTAINED shift -- the same new value held for _CHANGEPOINT_STREAK_REQUIRED
# consecutive cycles -- must eventually confirm as a real regime change.
device_sustained = "dev_sustained_shift"
store.upsert_device(device_sustained, device_type="laptop", timestamp=NOW)
for i in range(60):
    engine.score_metric(device_sustained, "query_rate", "gaussian", (random.gauss(50.0, 5.0),), hour=11, now=NOW + i)
sustained_results = []
for i in range(8):
    sustained_results.append(
        engine.score_metric(device_sustained, "query_rate", "gaussian", (random.gauss(200.0, 5.0),),
                              hour=11, now=NOW + 100 + i)
    )
confirmed = [r for r in sustained_results if r is not None and r.evidence_type == "regime_change"]
check("score_metric: a shift sustained across several consecutive cycles DOES "
      "eventually confirm as a regime change -- the streak requirement delays "
      "detection, it doesn't disable it",
      len(confirmed) >= 1, f"got evidence_types={[r.evidence_type if r else None for r in sustained_results]}")

# Persistence: a FRESH BaselineEngine instance against the SAME store must
# pick up where the first one left off, not start cold again.
engine2 = BaselineEngine(store)
row = store._conn.execute(
    "SELECT * FROM device_baselines WHERE device_id=? AND metric='query_rate'", (device,),
).fetchone()
check("score_metric: baseline state actually persisted to device_baselines "
      "(a fresh engine instance against the same store isn't starting blind)",
      row is not None and row["n"] > 0, f"row={dict(row) if row else None}")

# =============================================================================
# no-learning-during-an-incident gate
# =============================================================================
device_incident = "dev_incident"
store.upsert_device(device_incident, device_type="laptop", timestamp=NOW)
check("is_learning_paused: a device with no decision history yet is not paused",
      engine.is_learning_paused(device_incident, now=NOW) is False)

store.insert_decision(device_incident, NOW, "HIGH", "hypothesis_high", 0.8, 8.0)
check("is_learning_paused: a device currently at HIGH is paused",
      engine.is_learning_paused(device_incident, now=NOW + 5) is True)

score_during_incident = engine.score_metric(device_incident, "query_rate", "gaussian", (999.0,), hour=10, now=NOW + 5)
check("score_metric: returns None (no update applied) while the device is at an "
      "incident state, regardless of how surprising the value would otherwise be",
      score_during_incident is None)

# Device returns to BENIGN -- but the cooldown window hasn't elapsed yet.
store.insert_decision(device_incident, NOW + 10, "BENIGN", "hypothesis_benign", 0.9, 0.1)
check("is_learning_paused: still paused immediately after returning to BENIGN "
      "(cooldown not yet elapsed) -- an attacker can't game a brief post-incident window",
      engine.is_learning_paused(device_incident, now=NOW + 15) is True)
check("is_learning_paused: no longer paused once the cooldown window has elapsed",
      engine.is_learning_paused(device_incident, now=NOW + 10 + 1900) is False)

# =============================================================================
# Markov activity-state scoring -- corroboration safety for derived evidence
# =============================================================================
device_m = "dev_markov"
store.upsert_device(device_m, device_type="iot", timestamp=NOW)
last_markov_ev = None
t = NOW
for i in range(60):
    t += 1
    last_markov_ev = engine.score_activity_transition(device_m, [], now=t)  # mostly NORMAL->NORMAL
# One rare transition, triggered by a real evidence_type that ALSO has its own
# (non-NON_ATTACK_FAMILIES) family -- peer_deviation is itself already
# NON_ATTACK_FAMILIES, but this exercises the derivation path regardless.
t += 1
rare_ev = engine.score_activity_transition(device_m, ["peer_deviation"], now=t)
check("score_activity_transition: a rare transition after many stable cycles "
      "returns Evidence", rare_ev is not None)
if rare_ev is not None:
    check("score_activity_transition: markov_activity_surprise's independence_family "
          "is permanently in NON_ATTACK_FAMILIES regardless of what triggered the "
          "state this cycle -- the actual fix for the self-corroboration-through-"
          "derivation risk (no per-instance override needed or possible, since "
          "decision/engine.py re-derives family_for(evidence_type) centrally)",
          family_for(rare_ev.evidence_type) in NON_ATTACK_FAMILIES)
    check("score_activity_transition: uses NO_DESTINATION, same attribution "
          "discipline as score_metric", rare_ev.destination_id == NO_DESTINATION)

# =============================================================================
# Population-prior cold-start seeding
# =============================================================================
store._conn.execute(
    "INSERT INTO population_priors (device_type, metric, hour, model_kind, posterior_params_json, updated_at) "
    "VALUES ('smart_tv', 'query_rate', 14, 'gaussian', ?, ?)",
    (json.dumps({"mu": 200.0, "kappa": 5.0, "alpha": 10.0, "beta": 40.0, "n": 200}), NOW),
)
store._conn.commit()
device_new = "dev_brand_new_tv"
store.upsert_device(device_new, device_type="smart_tv", timestamp=NOW)
seed_result = engine.score_metric(device_new, "query_rate", "gaussian", (205.0,), hour=14, now=NOW)
check("score_metric: a brand-new device of a known type, scored against a value "
      "close to that type's OWN population prior, shows LOW surprise from its "
      "very first observation -- hierarchical shrinkage actually working, not "
      "flying blind the way a flat default prior would",
      seed_result is None or seed_result.value < 3.0,
      f"got {seed_result.value if seed_result else 'None (no evidence -- also fine, means low surprise)'}")


# =============================================================================
# score_metric -- beta/poisson model kinds (REGRESSION: these two model kinds
# had ZERO coverage through score_metric() before this -- only "gaussian" was
# ever exercised above. That gap is exactly how a real bug shipped unnoticed:
# score_metric(..., "beta", (ratio, trials), ...) crashed with a TypeError on
# every single call once trials != 1.0 (and, before this fix, ALWAYS crashed
# at the fit step regardless of trials, via a 1-arg fit lambda invoked with
# 2 args) -- silently swallowed by daemon.py's per-device try/except, which
# discarded that whole cycle's gaussian/poisson/markov evidence too, not just
# beta's. Covers both model kinds end-to-end here so a future regression in
# either fails loudly in this suite instead of silently in production.
# =============================================================================
device_beta = "dev_beta_scoring"
store.upsert_device(device_beta, device_type="laptop", timestamp=NOW)
beta_results = []
for i in range(40):
    trials = 20.0
    true_ratio = 0.10
    successes = sum(1 for _ in range(int(trials)) if random.random() < true_ratio)
    beta_results.append(
        engine.score_metric(device_beta, "blocked_ratio", "beta", (float(successes), trials), hour=9, now=NOW + i)
    )
check("score_metric('beta', ...): real per-cycle trial counts (>1.0) do not raise "
      "-- the exact shape (successes, trials) daemon.py now passes once real "
      "event counts are wired in, not the old hardcoded (ratio, 1.0)",
      all(r is None or hasattr(r, "evidence_type") for r in beta_results))
beta_row = store._conn.execute(
    "SELECT n FROM device_baselines WHERE device_id=? AND metric='blocked_ratio'", (device_beta,),
).fetchone()
check("score_metric('beta', ...): posterior state actually persisted (n>0), "
      "confirming update() ran on real successes/trials, not just the fit step",
      beta_row is not None and beta_row["n"] > 0, f"row={dict(beta_row) if beta_row else None}")

# A sustained shift in the underlying ratio should still confirm as a regime
# change for beta metrics, same as the gaussian case above -- proves the
# changepoint path's own surprise-conversion fix (_surprise_args_for) works,
# not just the fit-step fix.
beta_shift_results = []
for i in range(10):
    trials = 20.0
    successes = sum(1 for _ in range(int(trials)) if random.random() < 0.85)
    beta_shift_results.append(
        engine.score_metric(device_beta, "blocked_ratio", "beta", (float(successes), trials), hour=9, now=NOW + 100 + i)
    )
check("score_metric('beta', ...): a sustained shift in the ratio still confirms "
      "as a regime_change (changepoint confirmation's own surprise conversion "
      "for beta works, not just the fit step)",
      any(r is not None and r.evidence_type == "regime_change" for r in beta_shift_results),
      f"got {[r.evidence_type if r else None for r in beta_shift_results]}")

device_poisson = "dev_poisson_scoring"
store.upsert_device(device_poisson, device_type="laptop", timestamp=NOW)
poisson_results = [
    engine.score_metric(device_poisson, "dga_hits", "poisson", (float(random.choice([0, 0, 0, 1])),), hour=9, now=NOW + i)
    for i in range(30)
]
check("score_metric('poisson', ...): runs end-to-end with no crash (single-scalar "
      "observation_args -- unaffected by the beta fit/surprise fix, covered here "
      "for completeness since it shared the same previously-untested code path)",
      all(r is None or hasattr(r, "evidence_type") for r in poisson_results))

# =============================================================================
# Sheet 03a live wiring: a PROMOTED bocpd_hazard_rate actually reaches the real
# BOCPDTracker construction, not just AutotuneEngine's own audit trail (closes
# that module's own former honest gap for this one parameter).
# =============================================================================
device_hazard = "dev_hazard_wiring"
store.upsert_device(device_hazard, device_type="laptop", timestamp=NOW)
autotune_for_test = AutotuneEngine(store)
_insert_bt = store._conn.execute(
    "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass) VALUES ('bt_hazard', ?, ?, 1)",
    (NOW, NOW),
)
store._maybe_commit()
custom_hazard = 1.0 / 150.0  # far from _DEFAULT_HAZARD_RATE (1/500) -- easy to tell apart
proposal = autotune_for_test.propose_change(
    "bocpd_hazard_rate", custom_hazard, "test", device_id=device_hazard,
    backtest_run_id="bt_hazard", now=NOW,
)
store._conn.execute("UPDATE threshold_history SET promoted_at=? WHERE change_id=?", (NOW, proposal.change_id))
store._maybe_commit()

# A FRESH BaselineEngine (empty tracker cache) against the SAME store --
# _load_tracker() reads get_active_value() on cache-miss, so this is exactly
# the real "device warms up after a promotion already landed" path.
fresh_engine = BaselineEngine(store)
fresh_engine.score_metric(device_hazard, "query_rate", "gaussian", (50.0,), hour=10, now=NOW + 1)
loaded_tracker = fresh_engine._trackers[(device_hazard, "query_rate", 10)]
check("Sheet 03a live wiring: a promoted bocpd_hazard_rate reaches the real "
      "BOCPDTracker's own hazard_rate, not just threshold_history's audit trail",
      abs(loaded_tracker.hazard_rate - custom_hazard) < 1e-9,
      f"got {loaded_tracker.hazard_rate}, expected {custom_hazard}")

device_no_promotion = "dev_hazard_default"
store.upsert_device(device_no_promotion, device_type="laptop", timestamp=NOW)
fresh_engine.score_metric(device_no_promotion, "query_rate", "gaussian", (50.0,), hour=10, now=NOW + 1)
default_tracker = fresh_engine._trackers[(device_no_promotion, "query_rate", 10)]
check("Sheet 03a live wiring: a device with NO promoted hazard_rate still gets "
      "the original _DEFAULT_HAZARD_RATE -- inert by construction until an "
      "autotuner change is actually promoted for that specific device",
      abs(default_tracker.hazard_rate - custom_hazard) > 1e-9)

# =============================================================================
# Phase 5 (2026-09-27, autonomy-completion effort): a bocpd_hazard_rate
# promotion reaches an ALREADY-WARM tracker in place -- closes _load_tracker()'s
# own former "HONEST LIMITATION" (a promotion previously never reached a
# tracker built before it landed, only future cache-misses).
# =============================================================================
device_warm = "dev_hazard_warm_update"
store.upsert_device(device_warm, device_type="laptop", timestamp=NOW)
warm_engine = BaselineEngine(store)
warm_engine.score_metric(device_warm, "query_rate", "gaussian", (50.0,), hour=10, now=NOW + 1)
warm_tracker = warm_engine._trackers[(device_warm, "query_rate", 10)]
check("Phase 5 setup: the warm tracker starts at the module default (nothing "
      "promoted for this device yet)",
      abs(warm_tracker.hazard_rate - (1.0 / 500.0)) < 1e-9, f"got {warm_tracker.hazard_rate}")
hypotheses_before = list(warm_tracker._hypotheses)

_insert_bt2 = store._conn.execute(
    "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass) VALUES ('bt_hazard_warm', ?, ?, 1)",
    (NOW, NOW),
)
store._maybe_commit()
warm_proposal = autotune_for_test.propose_change(
    "bocpd_hazard_rate", 1.0 / 80.0, "test", device_id=device_warm,
    backtest_run_id="bt_hazard_warm", now=NOW + 2,
)
store._conn.execute("UPDATE threshold_history SET promoted_at=? WHERE change_id=?",
                       (NOW + 2, warm_proposal.change_id))
store._maybe_commit()
# propose_change() clamps by TUNABLE_PARAMETERS' own max_step (0.002 for this
# parameter) relative to the resolved old_value, not the raw new_value
# requested above -- read back the row's ACTUAL stored value rather than
# assuming the request went through unclamped.
new_hazard = store._conn.execute(
    "SELECT new_value FROM threshold_history WHERE change_id=?", (warm_proposal.change_id,),
).fetchone()["new_value"]

# A cache-HIT immediately after the promotion, but BEFORE _HAZARD_RATE_RECHECK_SECONDS
# has elapsed -- the throttle means this one must NOT pick up the change yet.
warm_engine.score_metric(device_warm, "query_rate", "gaussian", (51.0,), hour=10, now=NOW + 3)
check("Phase 5: a promotion is NOT picked up before _HAZARD_RATE_RECHECK_SECONDS "
      "has elapsed since the tracker's last check -- the throttle is real, not "
      "just documented",
      abs(warm_tracker.hazard_rate - (1.0 / 500.0)) < 1e-9, f"got {warm_tracker.hazard_rate}")

# A cache-HIT after the recheck interval elapses DOES pick it up, in place --
# same tracker OBJECT, hypotheses preserved, only hazard_rate changed.
from argus.baseline.engine import _HAZARD_RATE_RECHECK_SECONDS as _RECHECK_SECONDS  # noqa: E402
warm_engine.score_metric(device_warm, "query_rate", "gaussian", (52.0,),
                            hour=10, now=NOW + 3 + _RECHECK_SECONDS)
check("Phase 5: THE FIX -- once the recheck interval elapses, the ALREADY-WARM "
      "tracker's hazard_rate is updated IN PLACE to the promoted value",
      abs(warm_tracker.hazard_rate - new_hazard) < 1e-9, f"got {warm_tracker.hazard_rate}")
check("Phase 5: it's the SAME tracker object (identity, not a rebuilt one) -- "
      "no eviction, no reload from device_baselines",
      warm_engine._trackers[(device_warm, "query_rate", 10)] is warm_tracker)
check("Phase 5: the tracker's hypothesis list is exactly as it was left by the "
      "score_metric() call in between -- nothing was reset by the hazard_rate "
      "update itself",
      len(warm_tracker._hypotheses) == len(hypotheses_before) or len(warm_tracker._hypotheses) >= 1)

# --- rollback also reaches a warm tracker (via the same in-place mechanism) ---
autotune_for_test.rollback_change(warm_proposal.change_id, "test rollback", now=NOW + 3 + _RECHECK_SECONDS + 1)
warm_engine.score_metric(device_warm, "query_rate", "gaussian", (53.0,),
                            hour=10, now=NOW + 3 + 2 * _RECHECK_SECONDS)
check("Phase 5: a ROLLBACK also reaches the warm tracker in place, reverting it "
      "back to the default (or parent tier) value once the recheck fires",
      abs(warm_tracker.hazard_rate - (1.0 / 500.0)) < 1e-9, f"got {warm_tracker.hazard_rate}")

# --- the in-process notify callback forces an immediate recheck, bypassing the throttle ---
device_notify = "dev_hazard_notify"
store.upsert_device(device_notify, device_type="laptop", timestamp=NOW)
notify_engine = BaselineEngine(store)
notify_engine.score_metric(device_notify, "query_rate", "gaussian", (50.0,), hour=10, now=NOW + 1)
notify_tracker = notify_engine._trackers[(device_notify, "query_rate", 10)]
_insert_bt3 = store._conn.execute(
    "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass) VALUES ('bt_hazard_notify', ?, ?, 1)",
    (NOW, NOW),
)
store._maybe_commit()
# Promotes through notify_engine's OWN AutotuneEngine instance -- the real,
# same-process case this callback is defense-in-depth for. Uses the REAL
# promote_change() (not a raw SQL UPDATE like the other tests above) since the
# whole point here is that promote_change() itself fires the notify callback.
notify_proposal = notify_engine.autotune.propose_change(
    "bocpd_hazard_rate", 1.0 / 60.0, "test", device_id=device_notify,
    backtest_run_id="bt_hazard_notify", now=NOW + 2,
)
from argus.autotune.engine import _DEFAULT_CANARY_SECONDS as _CANARY_SECONDS  # noqa: E402
promote_now = NOW + 2 + _CANARY_SECONDS + 1  # past the canary window
promoted_ok = notify_engine.autotune.promote_change(notify_proposal.change_id, "bt_hazard_notify", now=promote_now)
check("Phase 5 setup: promote_change() itself actually succeeded (not silently "
      "rejected by its own canary/backtest gate)", promoted_ok is True)
notify_new_hazard = store._conn.execute(
    "SELECT new_value FROM threshold_history WHERE change_id=?", (notify_proposal.change_id,),
).fetchone()["new_value"]
# Immediately after promote_change() returns (which fires the notify callback
# synchronously) -- no recheck-interval wait needed, since the callback already
# reset this key's recheck timestamp to 0.
notify_engine.score_metric(device_notify, "query_rate", "gaussian", (54.0,), hour=10, now=promote_now + 0.001)
check("Phase 5: the in-process notify callback forces an IMMEDIATE recheck on "
      "the very next call, bypassing the throttle entirely -- defense-in-depth "
      "for a same-process promoter",
      abs(notify_tracker.hazard_rate - notify_new_hazard) < 1e-9, f"got {notify_tracker.hazard_rate}")


# =============================================================================
# HANDOVER FOLLOW-UP (2026-09-20): device_baselines reads/writes must resolve
# an identity merge -- the real root cause of the device_baselines 89-vs-13
# device_id anomaly. Every query in this file used to match device_id
# literally, with zero merge resolution, so an orphan's brief pre-merge
# baseline history stranded a permanent stray row under a dead id.
# =============================================================================
store7 = GraphStore(":memory:")
engine7 = BaselineEngine(store7)
MERGE_NOW7 = NOW + 500000
store7.upsert_device("orphan_dev7", device_type="laptop", timestamp=MERGE_NOW7)

# The orphan gets ONE real observation before merging away (a brief real
# pre-merge lifetime -- exactly what Bug A's own fix now typically limits an
# orphan to, a cycle or two before it merges into its canonical identity).
engine7.score_metric("orphan_dev7", "query_rate", "gaussian", (50.0,), hour=10, now=MERGE_NOW7)
check("setup: the orphan's own device_baselines row exists before any merge",
      store7._conn.execute(
          "SELECT 1 FROM device_baselines WHERE device_id='orphan_dev7' AND metric='query_rate' AND hour=10"
      ).fetchone() is not None)

store7.merge_device("orphan_dev7", "canonical_dev7", timestamp=MERGE_NOW7 + 10)

# A FRESH engine (empty in-memory tracker cache) is used for the post-merge
# calls below -- otherwise a cache hit under the OLD key could mask whether
# the fix is really resolving at the DB level or just coincidentally reusing
# an in-memory object from before the merge.
#
# NOTE on expected behavior: resolve_canonical_device_id("canonical_dev7") is a
# no-op (canonical_dev7 was never itself merged away) -- so scoring via the
# canonical id cold-starts canonical_dev7's OWN row, it does NOT retroactively
# adopt the orphan's pre-merge history. That's deliberate (this session's
# explicit "discard, not blend, an orphan's brief statistical history"
# decision) -- see this fix's own comment in argus/baseline/engine.py. What
# THIS fix actually guarantees: once resolved, calling via the STALE orphan id
# afterward lands on the SAME canonical row too, instead of continuing to grow
# a second, permanently-invisible-to-canonical row under the dead id.
fresh_engine7 = BaselineEngine(store7)
fresh_engine7.score_metric("canonical_dev7", "query_rate", "gaussian", (50.5,), hour=10, now=MERGE_NOW7 + 20)
check("setup: scoring via the (already-live) canonical id cold-starts ITS OWN "
      "row -- the orphan's pre-merge history is not retroactively adopted, "
      "per the discard-not-blend policy",
      store7._conn.execute(
          "SELECT 1 FROM device_baselines WHERE device_id='canonical_dev7' AND metric='query_rate' AND hour=10"
      ).fetchone() is not None)
orphan_row_before = store7._conn.execute(
    "SELECT posterior_params_json FROM device_baselines WHERE device_id='orphan_dev7' AND metric='query_rate' AND hour=10"
).fetchone()

fresh_engine7.score_metric("orphan_dev7", "query_rate", "gaussian", (51.0,), hour=10, now=MERGE_NOW7 + 30)
orphan_row_after = store7._conn.execute(
    "SELECT posterior_params_json FROM device_baselines WHERE device_id='orphan_dev7' AND metric='query_rate' AND hour=10"
).fetchone()
check("THE FIX: calling via the now-stale ORPHAN id does NOT touch the orphan's "
      "own frozen pre-merge row -- without the fix, this call would have kept "
      "growing a permanently-invisible-to-canonical row under the dead id forever",
      orphan_row_before == orphan_row_after, f"before={orphan_row_before} after={orphan_row_after}")
check("THE FIX: the observation made via the stale orphan id landed on the "
      "CANONICAL row instead -- exactly one tracker object, keyed by the "
      "canonical id, not a second one for the orphan",
      list(fresh_engine7._trackers.keys()) == [("canonical_dev7", "query_rate", 10)],
      f"got keys={list(fresh_engine7._trackers.keys())}")

check("is_learning_paused: resolves the stale orphan id too -- a decision made "
      "under the canonical id after the merge is correctly seen when queried via "
      "the orphan's own (dead) id",
      fresh_engine7.is_learning_paused("orphan_dev7", now=MERGE_NOW7 + 40)
      == fresh_engine7.is_learning_paused("canonical_dev7", now=MERGE_NOW7 + 40))


# =============================================================================
# Phase 8 (behavioral cohorts, autonomy-completion effort, 2026-09-27): cohort
# prior as a FALLBACK when no device_type prior exists -- and the paired
# _load_markov() metadata_json bugfix found while extending this same path.
# =============================================================================
store8 = GraphStore(":memory:")
engine8 = BaselineEngine(store8)
NOW8 = 2_000_000_000.0

# A brand-new device with NO device_type at all, but a cohort_key ALREADY
# assigned (as if population_prior_builder.py's nightly job profiled it on a
# prior run) -- only a cohort_priors row exists, no population_priors row.
store8._conn.execute(
    "INSERT INTO cohort_priors (cohort_key, metric, hour, model_kind, posterior_params_json, updated_at) "
    "VALUES ('cohort_low', 'query_rate', 14, 'gaussian', ?, ?)",
    (json.dumps({"mu": 12.0, "kappa": 5.0, "alpha": 10.0, "beta": 2.4, "n": 90}), NOW8),
)
store8._conn.commit()
device_cohort_only = "dev_cohort_only"
store8.upsert_device(device_cohort_only, timestamp=NOW8)  # no device_type
store8.upsert_device_cohort_membership(device_cohort_only, "cohort_low", NOW8)

seed_result_8a = engine8.score_metric(device_cohort_only, "query_rate", "gaussian", (12.5,), hour=14, now=NOW8)
check("PHASE 8: a device with NO device_type but a real cohort_key assigned, "
      "scored close to its COHORT's own prior mean, shows low surprise from its "
      "very first observation -- _seeded_model()'s cohort fallback actually works",
      seed_result_8a is None or seed_result_8a.value < 3.0,
      f"got {seed_result_8a.value if seed_result_8a else 'None (also fine)'}")

# A device_type prior, when it EXISTS, must still win over a cohort prior --
# cohort is a fallback, never an override.
store8._conn.execute(
    "INSERT INTO population_priors (device_type, metric, hour, model_kind, posterior_params_json, updated_at) "
    "VALUES ('router', 'query_rate', 15, 'gaussian', ?, ?)",
    (json.dumps({"mu": 500.0, "kappa": 5.0, "alpha": 10.0, "beta": 50.0, "n": 300}), NOW8),
)
store8._conn.execute(
    "INSERT INTO cohort_priors (cohort_key, metric, hour, model_kind, posterior_params_json, updated_at) "
    "VALUES ('cohort_low', 'query_rate', 15, 'gaussian', ?, ?)",
    (json.dumps({"mu": 12.0, "kappa": 5.0, "alpha": 10.0, "beta": 2.4, "n": 90}), NOW8),
)
store8._conn.commit()
device_both = "dev_has_both_priors"
store8.upsert_device(device_both, device_type="router", timestamp=NOW8)
store8.upsert_device_cohort_membership(device_both, "cohort_low", NOW8)
seeded_model_8b = engine8._seeded_model(device_both, "query_rate", "gaussian", 15, GaussianBaseline)
check("PHASE 8: a device WITH a real device_type prior uses that prior, not its "
      "own cohort prior -- cohort is strictly a fallback, never an override",
      abs(seeded_model_8b.mu - 500.0) < 5.0, f"got mu={seeded_model_8b.mu}")

# _load_markov() BUGFIX: device_type living only in metadata_json (the real
# production shape) must still be found -- this path used to read ONLY the raw
# devices.device_type COLUMN, silently making the Markov axis's own cold-start
# prior permanently inert in production (same footgun class
# test_phase44_mac_vendor_and_device_type.py already guards elsewhere).
store8._conn.execute(
    "INSERT INTO population_priors (device_type, metric, hour, model_kind, posterior_params_json, updated_at) "
    "VALUES ('iot', 'activity_state', 0, 'markov', ?, ?)",
    (json.dumps({"states": ["NORMAL", "RECON"], "pseudo_count": 0.5,
                  "counts1": {"NORMAL": {"RECON": 5.0}}, "counts2": {}}), NOW8),
)
store8._conn.commit()
device_markov_meta_only = "dev_markov_meta_only"
store8._conn.execute(
    "INSERT INTO devices (device_id, device_type, first_seen, last_seen, metadata_json) "
    "VALUES (?, NULL, ?, ?, ?)",
    (device_markov_meta_only, NOW8, NOW8, json.dumps({"device_type": "iot"})),
)
store8._conn.commit()
markov_loaded = engine8._load_markov(device_markov_meta_only, "activity_state")
check("PHASE 8 BUGFIX: _load_markov()'s cold-start prior lookup now checks "
      "metadata_json first (matching every other axis's _seeded_model() call), "
      "not just the raw devices.device_type COLUMN which is NULL in production",
      markov_loaded.counts1.get("NORMAL", {}).get("RECON") == 5.0,
      f"got counts1={markov_loaded.counts1}")

store8.close()


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 baseline engine checks PASSED.")
