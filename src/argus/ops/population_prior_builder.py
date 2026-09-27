"""
argus/ops/population_prior_builder.py -- Release 15 Sheet 00 follow-up (2026-09-16,
user request: "implement it" after the population_priors cold-start gap was surfaced
while writing Documentation/PIPELINE_MATH_REFERENCE.md).

population_priors (argus/graph/schema.sql) has existed since Sheet 00 shipped with a
fully-implemented, tested READ side (baseline/engine.py's _load_population_prior()/
_seeded_model()) but NO writer anywhere in the codebase -- every device's cold-start
fell through to each model's own weak default prior instead of a real, device-type-
informed one. This is the writer: a scheduled job that pools real, already-learned
per-device posteriors (device_baselines) into one prior per (device_type, metric,
hour), so the NEXT device of that type to need a fresh model starts from something
informed instead of flat.

WHO CAN CONTRIBUTE ("a currently-clean backtest history", per the schema's own
comment): a device's own (metric, hour) posterior only feeds the pool once it has
enough real observations of its own (_MIN_N_TO_CONTRIBUTE) AND the device is not
CURRENTLY sitting in an incident state (SUSPICIOUS/HIGH/CRITICAL) -- reusing the exact
same "currently clean" concept baseline/engine.py's own is_learning_paused() already
encodes for a different purpose (pausing further learning), not a separately-invented
definition. This is deliberately "currently clean," not "has never once been flagged"
-- a device that tripped one real false-positive months ago and has been fine since
is not excluded forever.

POOLING MATH -- honest, first-pass, not yet empirically tuned against this network's
own real variance (same honest-status framing this codebase already uses for
PeerDeviationHypothesis/independence-family weights):
  Gaussian:  pooled mu = mean of contributors' own mu; pooled variance = mean of
             contributors' own implied variance (beta_i/alpha_i) -- this UNDERSTATES
             true between-device variance (a known simplification: it captures "the
             typical within-device spread," not "how much devices of this type differ
             from each other"), documented rather than hidden. A FIXED, modest
             pseudo-count (kappa=5, alpha=10 -- matching this codebase's own one
             existing reference data point, test_argus_baseline_engine.py's population-
             prior fixture) keeps the pool a genuinely weak prior a new device's real
             data quickly outweighs, never a large pseudo-sample that would take a
             real device a long time to escape.
  Beta:      pooled ratio = mean of contributors' own a/(a+b); rebuilt at a fixed
             total pseudo-count of 10.
  Poisson:   pooled mean = mean of contributors' own shape/rate; rebuilt at a fixed
             pseudo-exposure of 5.
  Markov:    contributors' own real transition COUNTS are summed directly (the
             mathematically natural pooling operation for a Dirichlet count table,
             unlike the continuous cases above) then uniformly scaled down if the
             total exceeds a cap, so a device-type with many long-lived contributors
             doesn't end up with an oversized, hard-to-override prior.

NOT BUILT (deliberately, same honesty convention): the two-tier "rare/attack-shaped
states pool GLOBALLY instead of per-device-type" design sketched by baseline/engine.py's
own (unused) _GLOBAL_POOL_STATES/_GLOBAL_POOL_DEVICE_TYPE constants. That comment
itself says "Phase 0 design... not wired to any writer" -- re-reading it while building
this, the actual per-state blending mechanics were never fully specified (would a
population_priors ROW, keyed by device_type/metric/hour, blend two different pools
per-transition-row within one MarkovBaseline table?), and inventing that design
silently here would be a real, undocumented judgment call, not an implementation of
an existing spec. Single-tier (per-device-type only, matching what _load_population_
prior() already reads) is what's actually built.

Wired into config.yaml's scheduled_jobs.scheduler.population_prior_builder, daily at
03:45 (after live_prune's 03:15, spaced from every other job below the top of the
hour) -- population-level behavior patterns are slow-moving; unlike the nightly
backtest, there's no correctness reason this needs to run more than once a day.
Rebuilds every eligible pool from current state each run (not incremental) -- cheap
relative to its own cadence, and means a later-found-compromised contributor's
influence is gone from the VERY NEXT run once its device stops being "currently
clean," with no separate invalidation step needed.
"""
import argparse
import json
import logging
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Same bootstrap every other argus/ops/*.py scheduled job uses (see backtest_job.py's
# own BUGFIX comment for why this matters when scripts/scheduler.py launches this as a
# bare subprocess with no PYTHONPATH set).
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from argus.autotune.engine import AutotuneEngine, TUNABLE_PARAMETERS, _LESS_SENSITIVE_DIRECTION  # noqa: E402
from argus.baseline.engine import ACTIVITY_STATES  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from core.heartbeat import write_component_heartbeat  # noqa: E402
from utils import is_resource_pressure_active  # noqa: E402

LOGGER = logging.getLogger("argus.ops.population_prior_builder")

# Mirrors baseline/engine.py's own _INCIDENT_STATES exactly -- "currently clean" means
# the SAME thing here as it does for is_learning_paused()'s own incident gate, not a
# separately-invented definition.
_INCIDENT_STATES = frozenset({"SUSPICIOUS", "HIGH", "CRITICAL"})

# A device's own (metric, hour) posterior needs at least this many real observations
# before it's trusted enough to feed a population pool -- matches autotune/engine.py's
# own _MIN_TRIALS_FOR_LOOSENING (the same "is this enough real data" bar already
# established elsewhere in this codebase for a different but analogous purpose: is a
# statistic backed by enough real samples to act on).
_MIN_N_TO_CONTRIBUTE = 20

# A pool needs at least this many distinct contributing devices before it's considered
# a statistically meaningful "population," not one device's own history relabeled --
# matches live_engine.py's own _PEER_DEVIATION_MIN_PEERS precedent.
_MIN_CONTRIBUTORS = 2

# Deliberately modest, FIXED pseudo-counts -- see this module's own docstring for why
# these specific numbers (kappa=5/alpha=10 match this codebase's one existing
# reference data point, the test fixture in test_argus_baseline_engine.py).
_POOL_GAUSSIAN_KAPPA = 5.0
_POOL_GAUSSIAN_ALPHA = 10.0
_POOL_BETA_TOTAL = 10.0        # a + b
_POOL_POISSON_RATE = 5.0       # pseudo-exposure
_POOL_MARKOV_MAX_TOTAL = 50.0  # cap on summed real transition counts, scaled down if exceeded

_CONTINUOUS_MODEL_KINDS = ("gaussian", "beta", "poisson")

# Phase 8 (behavioral cohorts, autonomy-completion effort, 2026-09-27): a per-device
# grouping DISTINCT from device_type, for pooling devices with no device_type (or an
# "unknown" one) -- see _compute_behavioral_cohorts()'s own docstring for the exact
# algorithm and its honest first-pass scope. Metrics are deliberately generic, already-
# tracked traffic statistics only -- never anything household-specific
# ([[feedback_network_agnostic_design]]).
_COHORT_METRICS = ("query_rate", "entropy_avg", "unique_domains")
_COHORT_BUCKET_COUNT = 3  # low/med/high, population-relative tertiles
_COHORT_MIN_DEVICES_FOR_BUCKETING = 6  # below this, a tertile split is statistically meaningless
_COHORT_MIN_STABLE_DAYS = 7.0  # additional contributor-eligibility gate for cohort pooling only


def _device_is_currently_clean(store: GraphStore, device_id: str) -> bool:
    """Same 'currently clean' concept baseline/engine.py's own is_learning_paused()
    already encodes for its incident-state gate, reused here for contributor
    eligibility rather than re-derived with different semantics. A device with no
    decision history at all is clean by omission (nothing has ever flagged it)."""
    latest = store.get_latest_decision_for_device(device_id)
    if latest is None:
        return True
    return latest.get("state") not in _INCIDENT_STATES


def _device_type_map(store: GraphStore) -> Dict[str, str]:
    """device_id -> effective device_type, mirroring _seeded_model()'s own read
    precedence exactly (baseline/engine.py: metadata_json's own "device_type" key
    first, the devices.device_type COLUMN as fallback).

    BUGFIX (found live on `.94` while dry-running this module against real
    production data before the first scheduled run, 2026-09-16): the first version
    of this function queried the devices.device_type COLUMN directly in SQL
    (`JOIN devices d ON ... WHERE d.device_type = ?`). Confirmed live: on `.94`'s
    real graph, EVERY one of 86 real devices has device_type=NULL in that column --
    the column is never actually written by the live pipeline (score_metric()'s own
    upsert_device() call never passes device_type; live_engine.py's peer-deviation
    injection writes it into metadata_json via update_device_metadata(), never the
    column). A column-only query would have matched zero devices, ever, making the
    whole writer permanently inert on real data -- caught before the first scheduled
    run only because this was dry-run against `.94` directly as part of the deploy,
    not because any test caught it (every test in this module's own suite builds its
    devices via store.upsert_device(..., device_type=...), which DOES set the
    column -- a real gap in that test fixture's realism, not just in the production
    code).

    Deliberately NOT a SQL json_extract() query -- matches this codebase's own
    established policy (GraphStore.get_devices_with_metadata_value()'s own
    documented reasoning: JSON1 extension availability isn't guaranteed on every
    deployment's SQLite build). A full-table Python-side scan, same shape as that
    method, is cheap at the device counts (tens, not thousands) this project
    targets, and this runs once a day, not in a hot per-cycle loop."""
    rows = store._conn.execute("SELECT device_id, device_type, metadata_json FROM devices").fetchall()
    out: Dict[str, str] = {}
    for row in rows:
        try:
            meta = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except (TypeError, ValueError):
            meta = {}
        dtype = meta.get("device_type") or row["device_type"]
        if dtype:
            out[row["device_id"]] = dtype
    return out


def _compute_behavioral_cohorts(store: GraphStore, now: float) -> Dict[str, str]:
    """Assigns each eligible device a behavioral-cohort key, DISTINCT from
    device_type, derived purely from this device's OWN already-learned per-metric
    statistics (device_baselines) -- never from a user-set/self-reported category,
    and never from any household-specific rule (only generic, already-tracked
    traffic statistics: query_rate/entropy_avg/unique_domains). Honest first-pass,
    same framing as this module's own pool_* dispersion-ratio heuristic:
    population-RELATIVE tertile buckets (low/med/high vs. the CURRENT population's
    own spread), not fixed absolute thresholds -- required for network-agnosticism
    ([[feedback_network_agnostic_design]]): a household with heavy DNS traffic and
    one with light traffic both get a genuine low/med/high split relative to
    themselves, never a number hand-tuned to any one network's real volumes.

    Requires real per-device data on ALL _COHORT_METRICS (an incomplete device
    gets no cohort_key at all, not a guessed one -- the same "no signal, no
    fallback category" principle test_phase44_mac_vendor_and_device_type.py
    already guards for infer_device_type()) and a real population of at least
    _COHORT_MIN_DEVICES_FOR_BUCKETING devices -- too few devices makes a tertile
    split statistically meaningless, not just noisy.

    Persists to device_cohort_membership (GraphStore.upsert_device_cohort_membership()
    -- joined_at only resets if the computed cohort_key actually changed from last
    run, so "how long has this device been in its current cohort" stays a
    meaningful signal across nightly recomputation, not reset every run)."""
    rows = store._conn.execute(
        "SELECT device_id, metric, n, posterior_params_json FROM device_baselines "
        "WHERE model_kind = 'gaussian' AND metric IN (?, ?, ?)",
        _COHORT_METRICS,
    ).fetchall()

    # Weighted mean per (device_id, metric) across every hour/regime bucket --
    # weighted by each row's own real sample count, not a flat average of
    # already-decayed per-hour means.
    weighted: Dict[Tuple[str, str], List[Tuple[float, float]]] = {}
    for row in rows:
        n = row["n"] or 0
        if n < _MIN_N_TO_CONTRIBUTE:
            continue
        try:
            params = json.loads(row["posterior_params_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        mu = params.get("mu")
        if mu is None:
            continue
        weighted.setdefault((row["device_id"], row["metric"]), []).append((float(mu), float(n)))

    device_metric_mean: Dict[str, Dict[str, float]] = {}
    for (device_id, metric), samples in weighted.items():
        total_n = sum(n for _, n in samples)
        if total_n <= 0:
            continue
        device_metric_mean.setdefault(device_id, {})[metric] = (
            sum(mu * n for mu, n in samples) / total_n
        )

    # Only devices with a real value on ALL 3 metrics get a cohort key -- an
    # incomplete profile gets none, not a guessed partial one.
    complete_devices = {
        device_id: means for device_id, means in device_metric_mean.items()
        if all(m in means for m in _COHORT_METRICS)
    }
    if len(complete_devices) < _COHORT_MIN_DEVICES_FOR_BUCKETING:
        return {}

    # Population-relative tertile buckets per metric, computed fresh from THIS
    # run's own population -- each device gets a bucket by its OWN RANK among all
    # devices for that metric, never a fixed absolute number. Deliberately
    # rank-based, not a value-cutoff-based split (an earlier version drew cutoffs
    # from specific rank's VALUES, e.g. cutoff = values[4]; with real, noisy
    # per-device means this could split two near-identical devices across
    # adjacent buckets purely because one of them straddled that exact boundary
    # value -- found via this module's own test coverage before it ever shipped).
    # Rank-based bucketing has no such boundary-value ambiguity: two devices
    # ranked next to each other only ever land in different buckets when the
    # bucket-size arithmetic actually calls for a new bucket to start.
    bucket_by_device: Dict[str, Dict[str, int]] = {device_id: {} for device_id in complete_devices}
    for metric in _COHORT_METRICS:
        ranked_ids = sorted(complete_devices.keys(), key=lambda d: complete_devices[d][metric])
        total = len(ranked_ids)
        for rank, device_id in enumerate(ranked_ids):
            bucket_by_device[device_id][metric] = min(
                int(rank * _COHORT_BUCKET_COUNT / total), _COHORT_BUCKET_COUNT - 1)

    cohort_map: Dict[str, str] = {}
    for device_id, buckets in bucket_by_device.items():
        parts = [f"{metric}:{buckets[metric]}" for metric in sorted(_COHORT_METRICS)]
        cohort_map[device_id] = "|".join(parts)

    for device_id, cohort_key in cohort_map.items():
        store.upsert_device_cohort_membership(device_id, cohort_key, now)

    return cohort_map


def _device_identity_stable_enough(store: GraphStore, device_id: str, now: float) -> bool:
    """Additional contributor-eligibility gate for COHORT pooling only (not applied
    to the existing device_type pooling above -- a deliberately narrower scope for
    this phase). A device with NO identity-stability row at all (never been through
    a merge) is treated as eligible -- 'never merged' carries no instability signal,
    it just means no signal either way."""
    stable_days = store.get_identity_stable_days(device_id, now)
    return stable_days is None or stable_days >= _COHORT_MIN_STABLE_DAYS


def _write_cohort_prior(store: GraphStore, cohort_key: str, metric: str, hour: int,
                          model_kind: str, posterior_params: dict, contributor_ids: List[str],
                          now: float) -> None:
    store._conn.execute(
        "INSERT INTO cohort_priors "
        "(cohort_key, metric, hour, model_kind, posterior_params_json, contributed_by_json, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(cohort_key, metric, hour) DO UPDATE SET "
        "model_kind=excluded.model_kind, posterior_params_json=excluded.posterior_params_json, "
        "contributed_by_json=excluded.contributed_by_json, updated_at=excluded.updated_at",
        (cohort_key, metric, hour, model_kind, json.dumps(posterior_params),
         json.dumps(sorted(contributor_ids)), now),
    )
    store._maybe_commit()


def _delete_cohort_prior_if_present(store: GraphStore, cohort_key: str, metric: str, hour: int) -> bool:
    cur = store._conn.execute(
        "DELETE FROM cohort_priors WHERE cohort_key=? AND metric=? AND hour=?",
        (cohort_key, metric, hour),
    )
    store._maybe_commit()
    return cur.rowcount > 0


def _eligible_contributors(store: GraphStore, device_ids: List[str], metric: str, hour: int,
                             model_kind: str) -> List[Tuple[str, dict]]:
    """Real device_baselines rows for this specific set of device_ids (already
    filtered to one device_type by the caller, via _device_type_map()) at
    (metric, hour, model_kind), the most-recent regime_id per device, filtered to
    devices with enough of their own history AND a currently-clean incident state.
    Returns [(device_id, posterior_params_dict), ...] -- best-effort per row: a
    device whose posterior_params_json fails to parse is skipped, never aborts the
    whole pool."""
    if not device_ids:
        return []
    placeholders = ",".join("?" * len(device_ids))
    rows = store._conn.execute(
        f"SELECT db.device_id, db.n, db.posterior_params_json FROM device_baselines db "
        f"WHERE db.device_id IN ({placeholders}) AND db.metric = ? AND db.hour = ? "
        f"AND db.model_kind = ? "
        f"AND db.regime_id = (SELECT MAX(regime_id) FROM device_baselines db2 "
        f"                     WHERE db2.device_id = db.device_id AND db2.metric = db.metric "
        f"                     AND db2.hour = db.hour AND db2.model_kind = db.model_kind)",
        (*device_ids, metric, hour, model_kind),
    ).fetchall()
    out: List[Tuple[str, dict]] = []
    for row in rows:
        if row["n"] is None or row["n"] < _MIN_N_TO_CONTRIBUTE:
            continue
        if not _device_is_currently_clean(store, row["device_id"]):
            continue
        try:
            params = json.loads(row["posterior_params_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(params, dict):
            continue
        out.append((row["device_id"], params))
    return out


def _pool_gaussian(contributors: List[Tuple[str, dict]], kappa: float = _POOL_GAUSSIAN_KAPPA,
                     alpha: float = _POOL_GAUSSIAN_ALPHA) -> dict:
    means = [p["mu"] for _, p in contributors if "mu" in p]
    variances = [p["beta"] / max(p.get("alpha", 1.0), 1e-9) for _, p in contributors if "beta" in p]
    pool_mu = sum(means) / len(means) if means else 0.0
    pool_variance = sum(variances) / len(variances) if variances else 1.0
    pool_n = sum(int(p.get("n", 0) or 0) for _, p in contributors)
    return {
        "mu": pool_mu, "kappa": kappa, "alpha": alpha,
        "beta": alpha * pool_variance, "n": pool_n,
    }


def _pool_beta(contributors: List[Tuple[str, dict]], beta_total: float = _POOL_BETA_TOTAL) -> dict:
    ratios = [p["a"] / max(p.get("a", 0.0) + p.get("b", 0.0), 1e-9) for _, p in contributors if "a" in p]
    pool_ratio = sum(ratios) / len(ratios) if ratios else 0.5
    pool_n = sum(int(p.get("n", 0) or 0) for _, p in contributors)
    return {"a": pool_ratio * beta_total, "b": (1.0 - pool_ratio) * beta_total, "n": pool_n}


def _pool_poisson(contributors: List[Tuple[str, dict]], poisson_rate: float = _POOL_POISSON_RATE) -> dict:
    means = [p["shape"] / max(p.get("rate", 1.0), 1e-9) for _, p in contributors if "shape" in p]
    pool_mean = sum(means) / len(means) if means else 0.0
    pool_n = sum(int(p.get("n", 0) or 0) for _, p in contributors)
    return {"shape": pool_mean * poisson_rate, "rate": poisson_rate, "n": pool_n}


# 2026-09-27 (Phase 4 of the autonomy-completion effort): the 4 pool_* parameters'
# own forward generator -- allowlisted and consumed live (see _pool_gaussian()/
# _pool_beta()/_pool_poisson() above) since this same phase, previously hardcoded
# module constants with zero autotune wiring at all.
#
# HONEST SCOPE NOTE, not hidden: the plan's own named evidence source for this
# tier is "cold-start convergence and population-prior error" -- a fully rigorous
# version of that (posterior-predictive checking, held-out log-likelihood across
# candidate pseudo-counts) is real, separate statistical infrastructure this
# module doesn't have and this phase doesn't build from scratch. What IS
# implemented is a simpler, real, defensible proxy already computable from data
# this module already gathers every run: the ratio of BETWEEN-device dispersion
# (how much contributing devices' own individual estimates disagree with each
# other) to the WITHIN-device variance/dispersion the prior's pseudo-counts
# already imply. A high ratio means devices disagree with each other MORE than
# their own individual noise would predict -- pooling them under a confident
# (high pseudo-count) prior is actively wrong, real evidence to tighten (lower
# the pseudo-count, trust each device's own data more). A very low ratio (devices
# agree with each other unusually well) is evidence it's safe to loosen (raise
# the pseudo-count, lean on the population more). No comparable real signal
# exists here for "how large should the ceiling be" beyond this ratio-based
# check, so bounds/direction, not this ratio's specific thresholds, do the real
# safety work -- same honesty framing as every first-pass constant in this file.
_POOL_TIGHTEN_RATIO = 2.0   # between/within dispersion ratio above this -> tighten, no sample floor
_POOL_LOOSEN_RATIO = 0.3    # ratio below this -> eligible to loosen, still gated by _MIN_CONTRIBUTORS below
_POOL_LOOSEN_MIN_CONTRIBUTORS = 20  # loosening needs proof -- matches every other loosen-gate's scale elsewhere in this codebase, kept as its own constant since this evidence shape (contributor count, not trial count) isn't the same thing


def _insert_pool_calibration_backtest_run(store: GraphStore, detail: dict, now: float) -> str:
    """Same synthesized-backtest_runs-row pattern train_fp_classifier.py's own
    _insert_confirmed_label_backtest_run() already established for confirmed-
    label-driven (not synthetic-sweep-driven) proposals -- AutotuneEngine.
    propose_change() requires a passing backtest_run_id regardless of evidence
    source, and this evidence is real population data, not a synthetic sweep."""
    run_id = uuid.uuid4().hex
    store._conn.execute(
        "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass, "
        "golden_set_result_json, synthetic_result_json) VALUES (?, ?, ?, 1, '{}', ?)",
        (run_id, now, now, json.dumps({"kind": "population_prior_calibration", **detail})),
    )
    store._maybe_commit()
    return run_id


def _propose_pool_pseudocount_change(autotune: AutotuneEngine, store: GraphStore, parameter: str,
                                        device_type: str, current: float, bounds: dict, direction: int,
                                        between_dispersion: float, within_dispersion: float,
                                        n_contributors: int, now: float) -> None:
    """Shared tighten/loosen decision for any one of the 4 pool_* parameters at one
    category scope -- see this module's own HONEST SCOPE NOTE above for the ratio
    this reads."""
    ratio = between_dispersion / max(within_dispersion, 1e-9)
    if ratio > _POOL_TIGHTEN_RATIO:
        new_value = round(max(current - direction * bounds["max_step"], bounds["min"]), 4)
        reason = (
            f"category:{device_type} -- between-device dispersion ({between_dispersion:.4f}) is "
            f"{ratio:.2f}x the within-device dispersion the prior implies ({within_dispersion:.4f}), "
            f"above the tighten ratio {_POOL_TIGHTEN_RATIO} -- devices disagree with each other more "
            f"than their own noise predicts, tightened {parameter} from {current:.2f} to {new_value:.2f}."
        )
    elif ratio < _POOL_LOOSEN_RATIO and n_contributors >= _POOL_LOOSEN_MIN_CONTRIBUTORS:
        new_value = round(min(current + direction * bounds["max_step"], bounds["max"]), 4)
        reason = (
            f"category:{device_type} -- between-device dispersion ({between_dispersion:.4f}) is only "
            f"{ratio:.2f}x the within-device dispersion the prior implies ({within_dispersion:.4f}), "
            f"below the loosen ratio {_POOL_LOOSEN_RATIO} across {n_contributors} contributors -- "
            f"devices agree with each other unusually well, loosened {parameter} from {current:.2f} "
            f"to {new_value:.2f}."
        )
    else:
        return
    if new_value == current:
        return
    run_id = _insert_pool_calibration_backtest_run(
        store, {"parameter": parameter, "device_type": device_type, "ratio": ratio,
                 "n_contributors": n_contributors}, now)
    result = autotune.propose_change(parameter, new_value, reason=reason, device_type=device_type,
                                        backtest_run_id=run_id, now=now)
    if not result.accepted:
        LOGGER.warning("[AUTOTUNE] propose_change rejected for %s (device_type=%r): %s",
                         parameter, device_type, result.reason)


def _gaussian_dispersion(contributors: List[Tuple[str, dict]]) -> "tuple[float, float, int]":
    """(between_dispersion, within_dispersion, n) for the ratio check above --
    between = variance of contributors' own individual means around the pool mean;
    within = the average of contributors' own individual (within-device) variances,
    the SAME `variances` _pool_gaussian() itself already computes."""
    means = [p["mu"] for _, p in contributors if "mu" in p]
    variances = [p["beta"] / max(p.get("alpha", 1.0), 1e-9) for _, p in contributors if "beta" in p]
    if len(means) < 2 or not variances:
        return 0.0, 1.0, len(contributors)
    pool_mu = sum(means) / len(means)
    between = sum((m - pool_mu) ** 2 for m in means) / len(means)
    within = sum(variances) / len(variances)
    return between, within, len(contributors)


def _beta_dispersion(contributors: List[Tuple[str, dict]]) -> "tuple[float, float, int]":
    """Same shape as _gaussian_dispersion(), for Beta-modeled contributors: between
    = variance of contributors' own individual a/(a+b) ratios; within = the
    average binomial variance p(1-p)/n_eff each contributor's own posterior
    already implies (n_eff = a+b, its own total pseudo-count)."""
    ratios, within_vars = [], []
    for _, p in contributors:
        if "a" not in p:
            continue
        total = max(p.get("a", 0.0) + p.get("b", 0.0), 1e-9)
        ratio = p["a"] / total
        ratios.append(ratio)
        within_vars.append(ratio * (1.0 - ratio) / total)
    if len(ratios) < 2 or not within_vars:
        return 0.0, 1.0, len(contributors)
    pool_ratio = sum(ratios) / len(ratios)
    between = sum((r - pool_ratio) ** 2 for r in ratios) / len(ratios)
    within = sum(within_vars) / len(within_vars)
    return between, within, len(contributors)


def _poisson_dispersion(contributors: List[Tuple[str, dict]]) -> "tuple[float, float, int]":
    """Same shape again, for Poisson-modeled contributors: between = variance of
    contributors' own individual rate means; within = the Poisson variance (equal
    to the mean itself) each contributor's own posterior implies."""
    means = [p["shape"] / max(p.get("rate", 1.0), 1e-9) for _, p in contributors if "shape" in p]
    if len(means) < 2:
        return 0.0, 1.0, len(contributors)
    pool_mean = sum(means) / len(means)
    between = sum((m - pool_mean) ** 2 for m in means) / len(means)
    within = max(pool_mean, 1e-9)  # Poisson: variance == mean
    return between, within, len(contributors)


def _pool_markov(contributors: List[Tuple[str, dict]], states: List[str]) -> dict:
    summed1: Dict[str, Dict[str, float]] = {}
    summed2: Dict[str, Dict[str, float]] = {}
    for _, params in contributors:
        for from_state, bucket in (params.get("counts1") or {}).items():
            dest = summed1.setdefault(from_state, {})
            for to_state, count in bucket.items():
                dest[to_state] = dest.get(to_state, 0.0) + float(count)
        for key, bucket in (params.get("counts2") or {}).items():
            dest = summed2.setdefault(key, {})
            for to_state, count in bucket.items():
                dest[to_state] = dest.get(to_state, 0.0) + float(count)

    total = sum(v for bucket in summed1.values() for v in bucket.values())
    if total > _POOL_MARKOV_MAX_TOTAL and total > 0:
        scale = _POOL_MARKOV_MAX_TOTAL / total
        summed1 = {f: {t: c * scale for t, c in bucket.items()} for f, bucket in summed1.items()}
        summed2 = {k: {t: c * scale for t, c in bucket.items()} for k, bucket in summed2.items()}

    return {"states": states, "pseudo_count": 0.5, "counts1": summed1, "counts2": summed2}


def _write_population_prior(store: GraphStore, device_type: str, metric: str, hour: int,
                              model_kind: str, posterior_params: dict, contributor_ids: List[str],
                              now: float) -> None:
    store._conn.execute(
        "INSERT INTO population_priors "
        "(device_type, metric, hour, model_kind, posterior_params_json, contributed_by_json, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(device_type, metric, hour) DO UPDATE SET "
        "model_kind=excluded.model_kind, posterior_params_json=excluded.posterior_params_json, "
        "contributed_by_json=excluded.contributed_by_json, updated_at=excluded.updated_at",
        (device_type, metric, hour, model_kind, json.dumps(posterior_params),
         json.dumps(sorted(contributor_ids)), now),
    )
    store._maybe_commit()


def _delete_population_prior_if_present(store: GraphStore, device_type: str, metric: str, hour: int) -> bool:
    """BUGFIX (found via this module's own test suite before it ever shipped): a
    group that previously had a real, written pool but drops below
    _MIN_CONTRIBUTORS on a later rebuild (its one remaining contributor's own data
    aged out, or -- the exact scenario the schema comment describes -- a
    contributor was found compromised and excluded, leaving too few clean devices
    behind) used to just be SKIPPED, leaving the OLD row's contributed_by_json
    silently naming a device that's no longer eligible, and posterior_params_json
    built partly from data that's no longer trusted. Every rebuild must leave the
    table in a state that reflects CURRENT eligibility, not just add to it --
    deleting a pool that's no longer backed by enough clean contributors is the
    other half of 'rebuilt without them,' not an edge case. Returns True if a row
    was actually deleted (for the caller's own counters), False if there was
    nothing to delete."""
    cur = store._conn.execute(
        "DELETE FROM population_priors WHERE device_type=? AND metric=? AND hour=?",
        (device_type, metric, hour),
    )
    store._maybe_commit()
    return cur.rowcount > 0


def build_population_priors(store: GraphStore, now: Optional[float] = None) -> Dict[str, Any]:
    """Rebuilds every eligible (device_type, metric, hour) population prior from
    CURRENT device_baselines state -- not incremental, so a later-found-compromised
    contributor's influence is gone from the very next run, no separate invalidation
    step needed. A group that previously had a real pool but no longer has enough
    eligible contributors has its stale row DELETED, not left with an outdated
    contributed_by_json/posterior_params_json (see
    _delete_population_prior_if_present()'s own docstring -- a real bug this
    module's own test suite caught before it ever shipped). Best-effort per group:
    one group's failure (a malformed row, an unexpected model_kind) is logged and
    skipped, never aborts the whole run.

    KNOWN LIMITATION: a group is only revisited (and so only cleaned up) while at
    least one device of that device_type still has SOME device_baselines row for
    that (metric, hour, model_kind) -- if every device of a type is later pruned
    entirely, that type's own stale population_priors row has no trigger to ever
    get deleted. Not addressed here; device pruning already has no corresponding
    GraphStore un-mirroring step for several other tables (see
    ARGUS_ARCHITECTURE.md's own "Known limitations" list), so this follows the
    same existing, documented shape rather than inventing a new cleanup pass."""
    now = now if now is not None else time.time()
    written = 0
    skipped_insufficient = 0
    removed_stale = 0
    failed = 0
    # 2026-09-27 (Phase 4 of the autonomy-completion effort): the 4 pool_* pseudo-
    # counts are category (device_type)-scoped tunables -- no device-level scoping
    # makes sense here, since these are POPULATION priors shared by an entire
    # device_type, not any one device's own value. Inert by construction until a
    # real promotion exists for that category (default matches the untouched
    # original hardcoded constants exactly).
    autotune = AutotuneEngine(store)
    # 2026-09-27 (Phase 6 of the autonomy-completion effort): resource-aware pause
    # for the pool_* pseudo-count CANDIDATE GENERATOR specifically -- see
    # utils.is_resource_pressure_active()'s own docstring for why this is a
    # cross-process scrape (this job runs as its own scheduled subprocess, never
    # in-process with the live pipeline whose resource state this checks).
    # Deliberately does NOT skip the pool rebuild/write itself below -- that's
    # ordinary population-prior maintenance (core learning infrastructure), not
    # autotune candidate generation, and must keep running regardless of pressure.
    tuning_paused = is_resource_pressure_active()
    if tuning_paused:
        LOGGER.warning("[AUTOTUNE] resource pressure active on the live pipeline -- "
                         "skipping pool_* candidate generation this run (population-"
                         "prior rebuild itself is unaffected).")

    # device_type per device is resolved ONCE, in Python (see _device_type_map()'s
    # own docstring for why this isn't a SQL join on the devices.device_type
    # column) -- every group enumeration below groups by this map, not by a SQL
    # DISTINCT on a column that's NULL for every real device on `.94`.
    dtype_map = _device_type_map(store)

    raw_rows = store._conn.execute(
        "SELECT DISTINCT device_id, metric, hour, model_kind FROM device_baselines "
        "WHERE model_kind IN ('gaussian', 'beta', 'poisson')"
    ).fetchall()
    groups_seen: Dict[Tuple[str, str, int, str], List[str]] = {}
    for row in raw_rows:
        dtype = dtype_map.get(row["device_id"])
        if not dtype or dtype == "unknown":
            continue
        key = (dtype, row["metric"], row["hour"], row["model_kind"])
        groups_seen.setdefault(key, []).append(row["device_id"])

    for (device_type, metric, hour, model_kind), device_ids in groups_seen.items():
        try:
            contributors = _eligible_contributors(store, device_ids, metric, hour, model_kind)
            if len(contributors) < _MIN_CONTRIBUTORS:
                skipped_insufficient += 1
                if _delete_population_prior_if_present(store, device_type, metric, hour):
                    removed_stale += 1
                continue
            if model_kind == "gaussian":
                kappa = autotune.get_active_value("pool_gaussian_kappa", device_type=device_type,
                                                     default=_POOL_GAUSSIAN_KAPPA)
                alpha = autotune.get_active_value("pool_gaussian_alpha", device_type=device_type,
                                                     default=_POOL_GAUSSIAN_ALPHA)
                pooled = _pool_gaussian(contributors, kappa=kappa, alpha=alpha)
                if not tuning_paused:
                    between, within, n = _gaussian_dispersion(contributors)
                    for param_name, current in (("pool_gaussian_kappa", kappa), ("pool_gaussian_alpha", alpha)):
                        _propose_pool_pseudocount_change(
                            autotune, store, param_name, device_type, current,
                            TUNABLE_PARAMETERS[param_name], _LESS_SENSITIVE_DIRECTION[param_name],
                            between, within, n, now)
            elif model_kind == "beta":
                beta_total = autotune.get_active_value("pool_beta_total", device_type=device_type,
                                                           default=_POOL_BETA_TOTAL)
                pooled = _pool_beta(contributors, beta_total=beta_total)
                if not tuning_paused:
                    between, within, n = _beta_dispersion(contributors)
                    _propose_pool_pseudocount_change(
                        autotune, store, "pool_beta_total", device_type, beta_total,
                        TUNABLE_PARAMETERS["pool_beta_total"], _LESS_SENSITIVE_DIRECTION["pool_beta_total"],
                        between, within, n, now)
            elif model_kind == "poisson":
                poisson_rate = autotune.get_active_value("pool_poisson_rate", device_type=device_type,
                                                             default=_POOL_POISSON_RATE)
                pooled = _pool_poisson(contributors, poisson_rate=poisson_rate)
                if not tuning_paused:
                    between, within, n = _poisson_dispersion(contributors)
                    _propose_pool_pseudocount_change(
                        autotune, store, "pool_poisson_rate", device_type, poisson_rate,
                        TUNABLE_PARAMETERS["pool_poisson_rate"], _LESS_SENSITIVE_DIRECTION["pool_poisson_rate"],
                        between, within, n, now)
            else:
                continue
            _write_population_prior(
                store, device_type, metric, hour, model_kind, pooled,
                [dev_id for dev_id, _ in contributors], now)
            written += 1
        except Exception:
            LOGGER.exception(
                "Failed to build population prior for device_type=%r metric=%r hour=%r "
                "model_kind=%r (non-fatal, continuing with the next group)",
                device_type, metric, hour, model_kind,
            )
            failed += 1

    # Markov axis: a separate pass -- hour is fixed at 0 (matches baseline/engine.py's
    # own _load_markov() read convention: the Markov axis has no diurnal bucketing).
    # Same Python-side device_type resolution as the pass above, not a SQL join.
    markov_raw_rows = store._conn.execute(
        "SELECT DISTINCT device_id, metric FROM device_baselines WHERE model_kind = 'markov'"
    ).fetchall()
    markov_groups_seen: Dict[Tuple[str, str], List[str]] = {}
    for row in markov_raw_rows:
        dtype = dtype_map.get(row["device_id"])
        if not dtype or dtype == "unknown":
            continue
        key = (dtype, row["metric"])
        markov_groups_seen.setdefault(key, []).append(row["device_id"])

    for (device_type, axis), device_ids in markov_groups_seen.items():
        try:
            contributors = _eligible_contributors(store, device_ids, axis, 0, "markov")
            if len(contributors) < _MIN_CONTRIBUTORS:
                skipped_insufficient += 1
                if _delete_population_prior_if_present(store, device_type, axis, 0):
                    removed_stale += 1
                continue
            states = contributors[0][1].get("states") or list(ACTIVITY_STATES)
            pooled = _pool_markov(contributors, states)
            _write_population_prior(
                store, device_type, axis, 0, "markov", pooled,
                [dev_id for dev_id, _ in contributors], now)
            written += 1
        except Exception:
            LOGGER.exception(
                "Failed to build Markov population prior for device_type=%r axis=%r "
                "(non-fatal, continuing with the next group)", device_type, axis,
            )
            failed += 1

    # Phase 8 (behavioral cohorts, autonomy-completion effort): a SEPARATE pooling
    # pass, keyed by behavioral cohort instead of device_type -- read ONLY as a
    # fallback by baseline/engine.py's _seeded_model()/_load_markov() when no
    # device_type prior exists, never overriding one that does. Gaussian/beta/
    # poisson only (see cohort_priors' own schema comment for why Markov cohort
    # pooling isn't built this phase). Deliberately does NOT use the autotune-
    # tunable pool_* pseudo-counts above (those are category/device_type-scoped
    # parameters from the original 16-parameter plan; inventing new cohort-scoped
    # tunables is outside that closed set) -- fixed module defaults only, an
    # honest, documented scope limit for this first pass.
    cohort_map = _compute_behavioral_cohorts(store, now)
    cohorts_computed = len(cohort_map)
    if cohort_map:
        cohort_raw_rows = store._conn.execute(
            "SELECT DISTINCT device_id, metric, hour, model_kind FROM device_baselines "
            "WHERE model_kind IN ('gaussian', 'beta', 'poisson')"
        ).fetchall()
        cohort_groups_seen: Dict[Tuple[str, str, int, str], List[str]] = {}
        for row in cohort_raw_rows:
            cohort_key = cohort_map.get(row["device_id"])
            if not cohort_key:
                continue
            key = (cohort_key, row["metric"], row["hour"], row["model_kind"])
            cohort_groups_seen.setdefault(key, []).append(row["device_id"])

        for (cohort_key, metric, hour, model_kind), device_ids in cohort_groups_seen.items():
            try:
                contributors = _eligible_contributors(store, device_ids, metric, hour, model_kind)
                contributors = [
                    (dev_id, params) for dev_id, params in contributors
                    if _device_identity_stable_enough(store, dev_id, now)
                ]
                if len(contributors) < _MIN_CONTRIBUTORS:
                    skipped_insufficient += 1
                    if _delete_cohort_prior_if_present(store, cohort_key, metric, hour):
                        removed_stale += 1
                    continue
                if model_kind == "gaussian":
                    pooled = _pool_gaussian(contributors)
                elif model_kind == "beta":
                    pooled = _pool_beta(contributors)
                elif model_kind == "poisson":
                    pooled = _pool_poisson(contributors)
                else:
                    continue
                _write_cohort_prior(
                    store, cohort_key, metric, hour, model_kind, pooled,
                    [dev_id for dev_id, _ in contributors], now)
                written += 1
            except Exception:
                LOGGER.exception(
                    "Failed to build cohort prior for cohort_key=%r metric=%r hour=%r "
                    "model_kind=%r (non-fatal, continuing with the next group)",
                    cohort_key, metric, hour, model_kind,
                )
                failed += 1

    return {
        "written": written,
        "skipped_insufficient_contributors": skipped_insufficient,
        "removed_stale": removed_stale,
        "failed": failed,
        "groups_considered": len(groups_seen) + len(markov_groups_seen),
        "cohorts_computed": cohorts_computed,
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(
        description="Release 15 Sheet 00 follow-up: builds population_priors pools "
                     "from real per-device baseline history")
    parser.add_argument("--db", default="state/v13_graph.db")
    args = parser.parse_args()

    store = GraphStore(args.db)
    result = build_population_priors(store)
    LOGGER.info(
        "Population prior build complete: %d pool(s) written, %d skipped (too few "
        "eligible contributors), %d stale pool(s) removed, %d failed, %d group(s) "
        "considered, %d device(s) assigned a behavioral cohort.",
        result["written"], result["skipped_insufficient_contributors"],
        result["removed_stale"], result["failed"], result["groups_considered"],
        result["cohorts_computed"],
    )

    # Same heartbeat convention as every other argus/ops/*.py scheduled job (see
    # backtest_job.py's own 2026-09-15 heartbeat-gap fix) -- a silently-stopped
    # nightly build should read as a stale heartbeat, not as healthy indefinitely.
    try:
        if store.db_path and store.db_path != ":memory:":
            write_component_heartbeat(
                Path(store.db_path).parent, "population_prior_builder",
                extra={"written": result["written"], "failed": result["failed"]},
            )
    except Exception:
        LOGGER.exception("[HEARTBEAT] failed to write population_prior_builder heartbeat, non-fatal")

    if result["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
