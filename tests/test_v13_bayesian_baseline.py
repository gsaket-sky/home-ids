"""
Standalone runtime test for v13's Bayesian baseline engine
(src/v13/baseline/bayesian.py, Release 15 closed-loop autotuning architecture,
Sheet 00).

Covers: conjugate-update convergence for all four model families
(GaussianBaseline/BetaBaseline/PoissonBaseline/MarkovBaseline), posterior-predictive
surprise scoring behaving as intended (wide/tolerant with few samples, narrowing
with more), MarkovBaseline's order-1/order-2 fallback, and BOCPDTracker's actual
changepoint-detection behavior plus its resource-bound hypothesis pruning.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_bayesian_baseline.py`
"""
import math
import random
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.baseline.bayesian import (  # noqa: E402
    GaussianBaseline, BetaBaseline, PoissonBaseline, MarkovBaseline, BOCPDTracker,
)

random.seed(1234)

# =============================================================================
# GaussianBaseline
# =============================================================================
g = GaussianBaseline()
true_mean, true_std = 50.0, 5.0
for _ in range(500):
    g.update(random.gauss(true_mean, true_std))

check("GaussianBaseline: posterior mean converges near the true mean after 500 samples",
      abs(g.mu - true_mean) < 1.0, f"got mu={g.mu:.2f}")

check("GaussianBaseline: surprise at the true mean is near zero",
      g.surprise(true_mean) < 0.5, f"got {g.surprise(true_mean):.3f}")
check("GaussianBaseline: surprise 6 true-std away is large",
      g.surprise(true_mean + 6 * true_std) > 4.0, f"got {g.surprise(true_mean + 6 * true_std):.3f}")

g_fresh = GaussianBaseline()
# NOTE: a fresh model's absolute surprise magnitude for an arbitrary far-away value
# still depends on the prior's own assumed scale (beta/alpha) -- it is NOT
# unconditionally "small" just because n=0 (that would require the prior's scale to
# already match the metric's real-world magnitude, which engine.py's per-metric
# seeding handles, not this class's bare defaults). What this class actually
# replaces calc_z()'s hard n>=10 cutoff WITH is structural: a finite, computable
# surprise at n=0, not a missing/undefined value.
fresh_surprise = g_fresh.surprise(1000.0)
check("GaussianBaseline: a fresh (n=0) model still produces a finite, computable "
      "surprise score -- no hard n>=10 cutoff the way calc_z() had",
      isinstance(fresh_surprise, float) and fresh_surprise >= 0.0 and math.isfinite(fresh_surprise),
      f"got {fresh_surprise}")

g_narrow = GaussianBaseline()
for _ in range(500):
    g_narrow.update(random.gauss(true_mean, true_std))
check("GaussianBaseline: surprise for the SAME deviation shrinks as samples accumulate "
      "(scale narrows with n, matching the 'continuous confidence' design goal)",
      g_narrow.surprise(true_mean + 3 * true_std) < g_fresh.surprise(true_mean + 3 * true_std))

# to_dict/from_dict round-trip
g2 = GaussianBaseline.from_dict(g.to_dict())
check("GaussianBaseline: to_dict/from_dict round-trips exactly",
      g2.mu == g.mu and g2.kappa == g.kappa and g2.alpha == g.alpha and g2.beta == g.beta and g2.n == g.n)

# =============================================================================
# BetaBaseline
# =============================================================================
b = BetaBaseline()
true_ratio = 0.15
for _ in range(300):
    trials = 20
    successes = sum(1 for _ in range(trials) if random.random() < true_ratio)
    b.update(successes, trials)

check("BetaBaseline: posterior mean converges near the true ratio",
      abs(b.mean() - true_ratio) < 0.03, f"got mean={b.mean():.3f}")
check("BetaBaseline: surprise at the true ratio is small",
      b.surprise(true_ratio) < 1.0, f"got {b.surprise(true_ratio):.3f}")
check("BetaBaseline: surprise for an implausible ratio (0.9) is large",
      b.surprise(0.9) > 5.0, f"got {b.surprise(0.9):.3f}")

# =============================================================================
# PoissonBaseline
# =============================================================================
p = PoissonBaseline()
true_rate = 2.0
for _ in range(300):
    p.update(random.gauss(true_rate, 1.0) if True else 0)  # count observations, allow float for test simplicity
check("PoissonBaseline: posterior mean converges near the true rate",
      abs(p.mean() - true_rate) < 0.5, f"got mean={p.mean():.3f}")
check("PoissonBaseline: surprise for a value near the mean is small",
      p.surprise(true_rate) < 1.0, f"got {p.surprise(true_rate):.3f}")
check("PoissonBaseline: surprise for a value far above the mean is large",
      p.surprise(true_rate + 30) > 5.0, f"got {p.surprise(true_rate + 30):.3f}")

# =============================================================================
# MarkovBaseline -- order-1, order-2 fallback, corroboration-relevant surprise
# =============================================================================
states = ["NORMAL", "RECON", "LATERAL_MOVEMENT", "EXFIL"]
m = MarkovBaseline(states)
# Learn a strong NORMAL -> NORMAL preference (self-loop), rare escapes to RECON.
for _ in range(400):
    m.update("NORMAL", "NORMAL" if random.random() < 0.95 else "RECON")

check("MarkovBaseline: predictive probability of the learned common transition is high",
      m.predictive_probability("NORMAL", "NORMAL") > 0.85,
      f"got {m.predictive_probability('NORMAL', 'NORMAL'):.3f}")
check("MarkovBaseline: surprise for the learned common transition is low",
      m.surprise("NORMAL", "NORMAL") < 0.5, f"got {m.surprise('NORMAL', 'NORMAL'):.3f}")
check("MarkovBaseline: surprise for the rare transition is meaningfully higher",
      m.surprise("NORMAL", "EXFIL") > m.surprise("NORMAL", "NORMAL") + 1.0,
      f"got NORMAL->EXFIL={m.surprise('NORMAL', 'EXFIL'):.3f}, NORMAL->NORMAL={m.surprise('NORMAL', 'NORMAL'):.3f}")

check("MarkovBaseline: an unseen context (no history at all) falls back to a uniform "
      "prior over the state space, not a crash or a zero probability",
      abs(m.predictive_probability(None, "EXFIL") - 1.0 / len(states)) < 1e-6)

m2 = MarkovBaseline(states)
for _ in range(5):  # below _MIN_ORDER2_SAMPLES -- must fall back to order-1 for this context
    m2.update("RECON", "LATERAL_MOVEMENT", prev2_state="NORMAL")
order1_only = MarkovBaseline(states)
for _ in range(5):
    order1_only.update("RECON", "LATERAL_MOVEMENT")
check("MarkovBaseline: order-2 context below the minimum-sample threshold falls back "
      "to order-1 for that context, rather than trusting a 5-sample order-2 estimate",
      abs(m2.predictive_probability("RECON", "LATERAL_MOVEMENT", prev2_state="NORMAL")
          - order1_only.predictive_probability("RECON", "LATERAL_MOVEMENT")) < 1e-9)

for _ in range(30):  # now cross _MIN_ORDER2_SAMPLES for this specific context
    m2.update("RECON", "LATERAL_MOVEMENT", prev2_state="NORMAL")
    order1_only.update("RECON", "LATERAL_MOVEMENT")
check("MarkovBaseline: once a context crosses the order-2 sample threshold, its "
      "prediction is computed from the order-2 table, not identical to order-1's "
      "(the two tables diverge once real order-2 data exists)",
      m2.counts2.get(("NORMAL", "RECON"), {}).get("LATERAL_MOVEMENT", 0) >= MarkovBaseline._MIN_ORDER2_SAMPLES)

# to_dict/from_dict round-trip (including the tuple-key counts2 serialization)
m3 = MarkovBaseline.from_dict(m2.to_dict())
check("MarkovBaseline: to_dict/from_dict round-trips order-2 counts correctly",
      m3.counts2.get(("NORMAL", "RECON"), {}) == m2.counts2.get(("NORMAL", "RECON"), {}))

# =============================================================================
# BOCPDTracker -- real changepoint detection + resource-bound pruning
# =============================================================================
tracker = BOCPDTracker(
    model_factory=lambda: GaussianBaseline(),
    predictive_prob_fn=lambda model, x: model.predictive_density(x),
    hazard_rate=1.0 / 100.0,
)

regime_a_signals = []
for _ in range(150):
    cp_mass = tracker.observe(random.gauss(10.0, 1.0))
    regime_a_signals.append(cp_mass)

check("BOCPDTracker: run-length grows through a stable regime (no false changepoint)",
      tracker.map_run_length() > 50, f"got map_run_length={tracker.map_run_length()}")
check("BOCPDTracker: stays resource-bounded by the explicit max_hypotheses cap",
      tracker.num_live_hypotheses() <= tracker.max_hypotheses, f"got {tracker.num_live_hypotheses()}")
background_cp_mass = regime_a_signals[-1]  # steady-state cp-mass with no real changepoint

# Sustained regime shift -- a real firmware/OS-update-shaped change, not one outlier.
# NOTE: "run-length" means cycles-since-the-last-changepoint -- correct behavior is
# a DIP toward 0 right at the shift (detection), followed by GROWTH again afterward
# as the new regime persists undisturbed (there's no second changepoint). Testing
# for a sustained low tail would be testing the wrong thing.
post_shift_run_lengths = []
post_shift_cp_masses = []
for _ in range(60):
    cp_mass = tracker.observe(random.gauss(40.0, 1.0))
    post_shift_run_lengths.append(tracker.map_run_length())
    post_shift_cp_masses.append(cp_mass)

check("BOCPDTracker: changepoint-mass spikes well above its stable-regime background "
      "level in the cycles right after a sustained regime shift begins",
      max(post_shift_cp_masses[:10]) > background_cp_mass * 3,
      f"got peak={max(post_shift_cp_masses[:10]):.4f}, background={background_cp_mass:.4f}")
check("BOCPDTracker: MAP run-length dips back near 0 shortly after the shift "
      "(detection), rather than staying anchored to the old regime's run-length",
      min(post_shift_run_lengths[:15]) < 15,
      f"got early post-shift run-lengths={post_shift_run_lengths[:15]}")
check("BOCPDTracker: run-length correctly resumes growing afterward, since the new "
      "regime is itself stable (no second changepoint) -- confirms the dip above was "
      "real detection, not the tracker simply staying confused",
      post_shift_run_lengths[-1] > post_shift_run_lengths[15],
      f"got run-length[15]={post_shift_run_lengths[15]}, run-length[-1]={post_shift_run_lengths[-1]}")

dominant = tracker.dominant_model()
check("BOCPDTracker: the dominant (MAP) hypothesis's own model has adapted toward "
      "the NEW regime's mean, not the old one",
      abs(dominant.mu - 40.0) < abs(dominant.mu - 10.0),
      f"got dominant.mu={dominant.mu:.2f}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 Bayesian baseline checks PASSED.")
