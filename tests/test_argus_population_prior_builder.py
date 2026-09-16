"""
Standalone runtime test for argus/ops/population_prior_builder.py -- the
population_priors writer (Release 15 Sheet 00 follow-up, 2026-09-16).

Covers: real per-device posteriors (built through BaselineEngine.score_metric()/
score_activity_transition(), not hand-crafted JSON) pooling into a real
population_priors row; contributor eligibility (enough of their own history, not
currently in an incident state, a real device_type); the minimum-contributors floor;
Gaussian/Beta/Poisson/Markov pooling math; idempotent rebuilds; a later-found-
compromised contributor actually dropping out on rebuild; and the closed loop --
BaselineEngine's own pre-existing _seeded_model() read path actually picks up what
this writer produces.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_population_prior_builder.py`
"""
import json
import random
import sys
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

random.seed(777)

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.baseline.engine import BaselineEngine  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
import argus.ops.population_prior_builder as ppb  # noqa: E402

NOW = 1_900_000_000.0


def _seed_gaussian_device(store, engine, device_id, device_type, mean, n=50, hour=10, seed_ts=NOW):
    """n=50, not exactly the eligibility floor (20): BOCPDTracker.dominant_model()'s
    own 'n' can meaningfully lag the real call count early on -- the mixture's
    dominant (highest-weight) hypothesis isn't always the oldest one for the first
    several cycles, so a device fed exactly ~20-25 real calls can easily land with
    its OWN dominant hypothesis's n below the eligibility floor by chance (confirmed
    directly while writing this test). test_argus_baseline_engine.py's own
    established convention already uses 60 stable iterations for the same reason --
    50 here gives the same safety margin."""
    store.upsert_device(device_id, device_type=device_type, timestamp=seed_ts)
    for i in range(n):
        engine.score_metric(device_id, "query_rate", "gaussian",
                              (random.gauss(mean, 2.0),), hour, now=seed_ts + i)


# =============================================================================
# A. Basic Gaussian pooling across 3 clean, well-sampled contributors
# =============================================================================
store = GraphStore(":memory:")
engine = BaselineEngine(store)

_seed_gaussian_device(store, engine, "devA1", "iot", mean=50.0)
_seed_gaussian_device(store, engine, "devA2", "iot", mean=54.0)
_seed_gaussian_device(store, engine, "devA3", "iot", mean=46.0)

result_a = ppb.build_population_priors(store, now=NOW + 1000)
check("A: build_population_priors() reports at least 1 pool written for a real "
      "3-contributor group", result_a["written"] >= 1, f"got {result_a}")

row_a = store._conn.execute(
    "SELECT posterior_params_json, contributed_by_json FROM population_priors "
    "WHERE device_type='iot' AND metric='query_rate' AND hour=10"
).fetchone()
check("A: a real population_priors row was written for (iot, query_rate, hour=10)",
      row_a is not None)
if row_a is not None:
    params_a = json.loads(row_a["posterior_params_json"])
    contributors_a = json.loads(row_a["contributed_by_json"])
    check("A: all 3 clean, well-sampled devices contributed",
          sorted(contributors_a) == ["devA1", "devA2", "devA3"], f"got {contributors_a}")
    check("A: pooled mu is close to the real mean of the 3 contributors' own means "
          "(50, 54, 46 -> 50), not a hardcoded/flat default",
          abs(params_a["mu"] - 50.0) < 3.0, f"got {params_a['mu']}")
    check("A: the pool uses the FIXED, modest pseudo-count constants (kappa=5.0, "
          "alpha=10.0), not a pseudo-count that scales with the real sample sizes "
          "pooled (~150 real observations went into this) -- a population prior "
          "must stay a WEAK prior a new device's real data quickly outweighs",
          params_a["kappa"] == 5.0 and params_a["alpha"] == 10.0, f"got {params_a}")
    check("A: the pool's own 'n' field records a real, substantial total "
          "observation count pooled (audit/transparency, separate from the "
          "pseudo-count kappa/alpha a new device actually inherits) -- not zero, "
          "not a value that could only come from one contributor alone",
          params_a["n"] >= 100, f"got {params_a['n']}")

# =============================================================================
# B. Contributor eligibility -- too little of its own history is excluded
# =============================================================================
_seed_gaussian_device(store, engine, "devB_thin", "iot", mean=200.0, n=5)  # well below the n>=20 floor
result_b = ppb.build_population_priors(store, now=NOW + 2000)
row_b = store._conn.execute(
    "SELECT contributed_by_json FROM population_priors "
    "WHERE device_type='iot' AND metric='query_rate' AND hour=10"
).fetchone()
contributors_b = json.loads(row_b["contributed_by_json"]) if row_b else []
check("B: a device with fewer than 20 real observations of its own never "
      "contributes, even though it's otherwise eligible (real device_type, no "
      "incident history)",
      "devB_thin" not in contributors_b, f"got {contributors_b}")
check("B: the OTHER 3 legitimate contributors are unaffected by the thin device's "
      "presence in the same device_type/metric/hour group",
      set(contributors_b) == {"devA1", "devA2", "devA3"}, f"got {contributors_b}")

# =============================================================================
# C. Contributor eligibility -- a device CURRENTLY in an incident state is excluded
# =============================================================================
_seed_gaussian_device(store, engine, "devC_flagged", "iot", mean=48.0)  # otherwise eligible
store.insert_decision("devC_flagged", NOW + 2500, "HIGH", "hypothesis_high", 0.85, 8.5)
result_c = ppb.build_population_priors(store, now=NOW + 3000)
row_c = store._conn.execute(
    "SELECT contributed_by_json FROM population_priors "
    "WHERE device_type='iot' AND metric='query_rate' AND hour=10"
).fetchone()
contributors_c = json.loads(row_c["contributed_by_json"]) if row_c else []
check("C: a device whose MOST RECENT real decision is HIGH/CRITICAL never "
      "contributes, even with plenty of its own history -- 'currently clean' means "
      "what is_learning_paused() already means, not a separately-invented rule",
      "devC_flagged" not in contributors_c, f"got {contributors_c}")

# =============================================================================
# D. Minimum-contributors floor -- a lone eligible device is not a 'population'
# =============================================================================
store_d = GraphStore(":memory:")
engine_d = BaselineEngine(store_d)
_seed_gaussian_device(store_d, engine_d, "devD_alone", "camera", mean=30.0)
result_d = ppb.build_population_priors(store_d, now=NOW + 1000)
row_d = store_d._conn.execute(
    "SELECT * FROM population_priors WHERE device_type='camera'"
).fetchone()
check("D: a single eligible device (below the 2-contributor floor) produces NO "
      "population_priors row at all -- matches live_engine.py's own peer-deviation "
      "precedent (>=2 needed for a statistically meaningful comparison)",
      row_d is None)
check("D: this group is correctly counted as skipped-for-insufficient-contributors",
      result_d["skipped_insufficient_contributors"] >= 1, f"got {result_d}")

# =============================================================================
# E. "unknown"/empty device_type is never pooled
# =============================================================================
store_e = GraphStore(":memory:")
engine_e = BaselineEngine(store_e)
_seed_gaussian_device(store_e, engine_e, "devE1", "unknown", mean=40.0)
_seed_gaussian_device(store_e, engine_e, "devE2", "unknown", mean=42.0)
_seed_gaussian_device(store_e, engine_e, "devE3", "", mean=44.0)
result_e = ppb.build_population_priors(store_e, now=NOW + 1000)
row_e = store_e._conn.execute(
    "SELECT * FROM population_priors WHERE device_type IN ('unknown', '')"
).fetchone()
check("E: 'unknown' and empty device_type are never pooled, matching every other "
      "device_type-keyed feature in this codebase's own established convention "
      "(peer-deviation cohorts, etc.) -- no fake cohort of unrelated unidentified "
      "devices",
      row_e is None)

# =============================================================================
# F. Beta pooling
# =============================================================================
store_f = GraphStore(":memory:")
engine_f = BaselineEngine(store_f)
# Deterministic per-cycle successes (not a fresh Bernoulli draw each call) --
# confirmed directly while writing this test: real per-cycle sampling noise around
# a large trial count (needed for a non-degenerate ratio) makes a/b accumulate fast
# enough that ordinary binomial variance in the NEXT cycle reads as a huge outlier
# against an already-overconfident posterior, spuriously confirming a regime change
# almost every cycle (test_argus_baseline_engine.py's own Beta test hits the same
# dynamic and only ever asserts n>0, never a real floor, for exactly this reason).
# An exact, unchanging ratio every cycle is unrealistic but keeps this test about
# the WRITER's pooling logic, not about re-deriving BOCPD's own noise tolerance
# (already covered by test_argus_bayesian_baseline.py).
for dev, true_ratio in (("devF1", 0.10), ("devF2", 0.20)):
    store_f.upsert_device(dev, device_type="router", timestamp=NOW)
    trials = 20.0
    successes = round(trials * true_ratio)
    for i in range(30):
        engine_f.score_metric(dev, "nxdomain_ratio", "beta", (float(successes), trials),
                                 hour=9, now=NOW + i)
result_f = ppb.build_population_priors(store_f, now=NOW + 1000)
row_f = store_f._conn.execute(
    "SELECT posterior_params_json FROM population_priors "
    "WHERE device_type='router' AND metric='nxdomain_ratio' AND hour=9"
).fetchone()
check("F: Beta pooling produces a real population_priors row for 2 clean contributors",
      row_f is not None)
if row_f is not None:
    params_f = json.loads(row_f["posterior_params_json"])
    pooled_ratio_f = params_f["a"] / (params_f["a"] + params_f["b"])
    check("F: the pooled ratio (a/(a+b)) is close to the real mean of the two "
          "contributors' own ratios (0.10, 0.20 -> ~0.15)",
          abs(pooled_ratio_f - 0.15) < 0.06, f"got {pooled_ratio_f}")
    check("F: the pool total (a+b) is the fixed pseudo-count (10.0), not scaled by "
          "real trial counts",
          abs((params_f["a"] + params_f["b"]) - 10.0) < 1e-6, f"got {params_f}")

# =============================================================================
# G. Poisson pooling
# =============================================================================
store_g = GraphStore(":memory:")
engine_g = BaselineEngine(store_g)
# Same deterministic-input reasoning as the Beta section above -- a fixed count
# every cycle (not a fresh Bernoulli draw) avoids spurious regime churn from
# ordinary sampling noise, keeping this test about the writer's pooling logic.
for dev, count in (("devG1", 0.0), ("devG2", 1.0)):
    store_g.upsert_device(dev, device_type="nas", timestamp=NOW)
    for i in range(30):
        engine_g.score_metric(dev, "dga_hits", "poisson", (count,), hour=11, now=NOW + i)
result_g = ppb.build_population_priors(store_g, now=NOW + 1000)
row_g = store_g._conn.execute(
    "SELECT posterior_params_json FROM population_priors "
    "WHERE device_type='nas' AND metric='dga_hits' AND hour=11"
).fetchone()
check("G: Poisson pooling produces a real population_priors row", row_g is not None)
if row_g is not None:
    params_g = json.loads(row_g["posterior_params_json"])
    pooled_mean_g = params_g["shape"] / params_g["rate"]
    check("G: the pooled mean (shape/rate) is close to the real average of the two "
          "contributors' own means (0.0 and 1.0 -> ~0.5), not either one alone",
          0.3 <= pooled_mean_g <= 0.7, f"got {pooled_mean_g}")
    check("G: the pool uses the fixed pseudo-exposure (rate=5.0)",
          params_g["rate"] == 5.0, f"got {params_g}")

# =============================================================================
# H. Markov pooling -- real transition counts summed, capped/scaled if excessive
# =============================================================================
store_h = GraphStore(":memory:")
engine_h = BaselineEngine(store_h)
for dev in ("devH1", "devH2"):
    store_h.upsert_device(dev, device_type="phone", timestamp=NOW)
    # Alternate NORMAL/RECON via arp_sweep evidence types across many calls -- first
    # call always returns None (no prev_state yet), matches score_activity_
    # transition()'s own documented contract.
    for i in range(30):
        types = ["arp_sweep"] if i % 3 == 0 else []
        engine_h.score_activity_transition(dev, types, now=NOW + i)
result_h = ppb.build_population_priors(store_h, now=NOW + 1000)
row_h = store_h._conn.execute(
    "SELECT posterior_params_json FROM population_priors "
    "WHERE device_type='phone' AND metric='activity_state' AND hour=0"
).fetchone()
check("H: Markov pooling produces a real population_priors row at hour=0 (no "
      "diurnal bucketing for the activity-state axis, matching _load_markov()'s "
      "own read convention)",
      row_h is not None)
if row_h is not None:
    params_h = json.loads(row_h["posterior_params_json"])
    total_h = sum(v for bucket in params_h["counts1"].values() for v in bucket.values())
    check("H: the pooled counts1 table has real, nonzero transition mass -- actual "
          "counts from both contributors were summed, not left empty",
          total_h > 0, f"got counts1={params_h['counts1']}")
    check("H: the pooled total never exceeds the cap (50.0) -- a device-type with "
          "many/long-lived contributors doesn't end up with an oversized, "
          "hard-to-override prior",
          total_h <= 50.0 + 1e-6, f"got {total_h}")

# =============================================================================
# I. Idempotent rebuild -- running twice does not duplicate or corrupt the row
# =============================================================================
count_before = store._conn.execute("SELECT COUNT(*) AS c FROM population_priors").fetchone()["c"]
ppb.build_population_priors(store, now=NOW + 5000)
count_after = store._conn.execute("SELECT COUNT(*) AS c FROM population_priors").fetchone()["c"]
check("I: rebuilding immediately afterward does not create duplicate rows "
      "(ON CONFLICT(device_type, metric, hour) DO UPDATE, matching the table's "
      "own real PRIMARY KEY)",
      count_before == count_after, f"got {count_before} -> {count_after}")

# =============================================================================
# J. A later-found-compromised contributor actually drops out on rebuild -- the
# CORE promise the schema's own comment makes ("a later-found-compromised
# contributor can be identified and the prior rebuilt without them")
# =============================================================================
row_j_before = store._conn.execute(
    "SELECT contributed_by_json FROM population_priors "
    "WHERE device_type='iot' AND metric='query_rate' AND hour=10"
).fetchone()
contributors_j_before = json.loads(row_j_before["contributed_by_json"])
check("J: before any incident, devA1 is a real contributor",
      "devA1" in contributors_j_before, f"got {contributors_j_before}")

store.insert_decision("devA1", NOW + 5500, "CRITICAL", "tier5_confirmed", 0.99, 9.9)
ppb.build_population_priors(store, now=NOW + 6000)
row_j_after = store._conn.execute(
    "SELECT contributed_by_json, posterior_params_json FROM population_priors "
    "WHERE device_type='iot' AND metric='query_rate' AND hour=10"
).fetchone()
contributors_j_after = json.loads(row_j_after["contributed_by_json"])
check("J: once devA1 is found compromised (a real CRITICAL decision), the VERY "
      "NEXT rebuild drops it from the pool -- no separate invalidation step needed, "
      "since every rebuild re-evaluates 'currently clean' from scratch",
      "devA1" not in contributors_j_after and set(contributors_j_after) == {"devA2", "devA3"},
      f"got {contributors_j_after}")

# =============================================================================
# K. THE CLOSED LOOP -- BaselineEngine's own pre-existing read path
# (_seeded_model()/_load_population_prior()) actually picks up what this writer
# produces, for a BRAND NEW device of the same type
# =============================================================================
store_k = GraphStore(":memory:")
engine_k = BaselineEngine(store_k)
_seed_gaussian_device(store_k, engine_k, "devK1", "speaker", mean=100.0)
_seed_gaussian_device(store_k, engine_k, "devK2", "speaker", mean=104.0)
ppb.build_population_priors(store_k, now=NOW + 1000)

# A genuinely brand-new device of the same type, scored close to the pool's own
# mean (~102), should show LOW surprise on its very first observation -- the
# hierarchical-shrinkage cold start actually working, not a flat mu=0 prior that
# would find 102 wildly surprising on sight.
store_k.upsert_device("devK_new", device_type="speaker", timestamp=NOW + 2000)
seed_result = engine_k.score_metric("devK_new", "query_rate", "gaussian",
                                       (102.0,), hour=10, now=NOW + 2000)
check("K: THE CLOSED LOOP -- a brand-new device of a type this writer just built a "
      "real population prior for, scored close to that prior's own mean on its "
      "VERY FIRST observation, shows low/no surprise (either no baseline_deviation "
      "evidence at all, or a low-value one) -- the writer and the pre-existing "
      "reader are actually connected end-to-end, not just independently correct",
      seed_result is None or seed_result.value < 2.0,
      f"got {seed_result.value if seed_result else None}")

# =============================================================================
# L. BUGFIX regression -- a pool that drops BELOW the minimum-contributor floor on
# rebuild is DELETED, not left with a stale contributed_by_json/posterior_params_json
# naming a device that's no longer eligible. Found by this exact test file before
# this module ever shipped (see _delete_population_prior_if_present()'s own
# docstring) -- a real production gap, not just a test-flakiness fix.
# =============================================================================
store_l = GraphStore(":memory:")
engine_l = BaselineEngine(store_l)
_seed_gaussian_device(store_l, engine_l, "devL1", "camera", mean=20.0)
_seed_gaussian_device(store_l, engine_l, "devL2", "camera", mean=22.0)
result_l1 = ppb.build_population_priors(store_l, now=NOW + 1000)
row_l1 = store_l._conn.execute(
    "SELECT contributed_by_json FROM population_priors "
    "WHERE device_type='camera' AND metric='query_rate' AND hour=10"
).fetchone()
check("L: a real pool with exactly 2 contributors is written first (setup step, "
      "confirms the scenario before testing the drop-below-floor case)",
      row_l1 is not None and sorted(json.loads(row_l1["contributed_by_json"])) == ["devL1", "devL2"],
      f"got {row_l1}")

# devL1 is found compromised -- only devL2 remains eligible, below _MIN_CONTRIBUTORS.
store_l.insert_decision("devL1", NOW + 1500, "CRITICAL", "tier5_confirmed", 0.99, 9.9)
result_l2 = ppb.build_population_priors(store_l, now=NOW + 2000)
row_l2 = store_l._conn.execute(
    "SELECT * FROM population_priors WHERE device_type='camera' AND metric='query_rate' AND hour=10"
).fetchone()
check("L: BUGFIX -- once only 1 eligible contributor remains, the STALE row is "
      "actually DELETED on the next rebuild, not left behind still naming the "
      "now-excluded devL1 -- 'rebuilt without them' includes removal, not just "
      "exclusion from future additions",
      row_l2 is None, f"got {dict(row_l2) if row_l2 else None}")
check("L: the deletion is correctly counted in the return dict",
      result_l2["removed_stale"] >= 1, f"got {result_l2}")

store.close()
store_d.close()
store_e.close()
store_f.close()
store_g.close()
store_h.close()
store_l.close()
store_k.close()

print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All population_prior_builder checks PASSED.")
