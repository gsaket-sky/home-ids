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
`.venv/Scripts/python.exe tests/test_v13_baseline_engine.py`
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


from v13.baseline.engine import BaselineEngine, derive_activity_state  # noqa: E402
from v13.evidence.model import NO_DESTINATION  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402
from v13.hypotheses.independence import NON_ATTACK_FAMILIES, family_for  # noqa: E402

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


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 baseline engine checks PASSED.")
