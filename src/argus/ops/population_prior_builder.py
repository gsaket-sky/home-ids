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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Same bootstrap every other argus/ops/*.py scheduled job uses (see backtest_job.py's
# own BUGFIX comment for why this matters when scripts/scheduler.py launches this as a
# bare subprocess with no PYTHONPATH set).
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from argus.baseline.engine import ACTIVITY_STATES  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from core.heartbeat import write_component_heartbeat  # noqa: E402

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


def _device_is_currently_clean(store: GraphStore, device_id: str) -> bool:
    """Same 'currently clean' concept baseline/engine.py's own is_learning_paused()
    already encodes for its incident-state gate, reused here for contributor
    eligibility rather than re-derived with different semantics. A device with no
    decision history at all is clean by omission (nothing has ever flagged it)."""
    latest = store.get_latest_decision_for_device(device_id)
    if latest is None:
        return True
    return latest.get("state") not in _INCIDENT_STATES


def _eligible_contributors(store: GraphStore, device_type: str, metric: str, hour: int,
                             model_kind: str) -> List[Tuple[str, dict]]:
    """Real device_baselines rows for this (device_type, metric, hour, model_kind),
    the most-recent regime_id per device, filtered to devices with enough of their
    own history AND a currently-clean incident state. Returns
    [(device_id, posterior_params_dict), ...] -- best-effort per row: a device whose
    posterior_params_json fails to parse is skipped, never aborts the whole pool."""
    rows = store._conn.execute(
        "SELECT db.device_id, db.n, db.posterior_params_json FROM device_baselines db "
        "JOIN devices d ON d.device_id = db.device_id "
        "WHERE d.device_type = ? AND db.metric = ? AND db.hour = ? AND db.model_kind = ? "
        "AND db.regime_id = (SELECT MAX(regime_id) FROM device_baselines db2 "
        "                     WHERE db2.device_id = db.device_id AND db2.metric = db.metric "
        "                     AND db2.hour = db.hour AND db2.model_kind = db.model_kind)",
        (device_type, metric, hour, model_kind),
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


def _pool_gaussian(contributors: List[Tuple[str, dict]]) -> dict:
    means = [p["mu"] for _, p in contributors if "mu" in p]
    variances = [p["beta"] / max(p.get("alpha", 1.0), 1e-9) for _, p in contributors if "beta" in p]
    pool_mu = sum(means) / len(means) if means else 0.0
    pool_variance = sum(variances) / len(variances) if variances else 1.0
    pool_n = sum(int(p.get("n", 0) or 0) for _, p in contributors)
    return {
        "mu": pool_mu, "kappa": _POOL_GAUSSIAN_KAPPA, "alpha": _POOL_GAUSSIAN_ALPHA,
        "beta": _POOL_GAUSSIAN_ALPHA * pool_variance, "n": pool_n,
    }


def _pool_beta(contributors: List[Tuple[str, dict]]) -> dict:
    ratios = [p["a"] / max(p.get("a", 0.0) + p.get("b", 0.0), 1e-9) for _, p in contributors if "a" in p]
    pool_ratio = sum(ratios) / len(ratios) if ratios else 0.5
    pool_n = sum(int(p.get("n", 0) or 0) for _, p in contributors)
    return {"a": pool_ratio * _POOL_BETA_TOTAL, "b": (1.0 - pool_ratio) * _POOL_BETA_TOTAL, "n": pool_n}


def _pool_poisson(contributors: List[Tuple[str, dict]]) -> dict:
    means = [p["shape"] / max(p.get("rate", 1.0), 1e-9) for _, p in contributors if "shape" in p]
    pool_mean = sum(means) / len(means) if means else 0.0
    pool_n = sum(int(p.get("n", 0) or 0) for _, p in contributors)
    return {"shape": pool_mean * _POOL_POISSON_RATE, "rate": _POOL_POISSON_RATE, "n": pool_n}


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

    groups = store._conn.execute(
        "SELECT DISTINCT d.device_type, db.metric, db.hour, db.model_kind "
        "FROM device_baselines db JOIN devices d ON d.device_id = db.device_id "
        "WHERE d.device_type IS NOT NULL AND d.device_type != '' AND d.device_type != 'unknown' "
        "AND db.model_kind IN ('gaussian', 'beta', 'poisson')"
    ).fetchall()

    for group in groups:
        device_type, metric, hour, model_kind = (
            group["device_type"], group["metric"], group["hour"], group["model_kind"])
        try:
            contributors = _eligible_contributors(store, device_type, metric, hour, model_kind)
            if len(contributors) < _MIN_CONTRIBUTORS:
                skipped_insufficient += 1
                if _delete_population_prior_if_present(store, device_type, metric, hour):
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
    markov_groups = store._conn.execute(
        "SELECT DISTINCT d.device_type, db.metric FROM device_baselines db "
        "JOIN devices d ON d.device_id = db.device_id "
        "WHERE d.device_type IS NOT NULL AND d.device_type != '' AND d.device_type != 'unknown' "
        "AND db.model_kind = 'markov'"
    ).fetchall()
    for row in markov_groups:
        device_type, axis = row["device_type"], row["metric"]
        try:
            contributors = _eligible_contributors(store, device_type, axis, 0, "markov")
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

    return {
        "written": written,
        "skipped_insufficient_contributors": skipped_insufficient,
        "removed_stale": removed_stale,
        "failed": failed,
        "groups_considered": len(groups) + len(markov_groups),
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
        "considered.",
        result["written"], result["skipped_insufficient_contributors"],
        result["removed_stale"], result["failed"], result["groups_considered"],
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
