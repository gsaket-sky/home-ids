"""
v13/ops/backtest_job.py -- Release 15 Sheet 02: scheduled nightly backtest
harness.

Combines two real checks that existed before this file only as separate,
manual tools -- tests/test_real_world_alert_regression.py (curated
real-incident golden set, previously run by hand) and Sheet 01's synthetic
injection sweep (src/v13/synthetic/injector.py) -- into one scheduled job
whose pass/fail becomes Sheet 03's actual autotuner gate.

DELIBERATE DEVIATION FROM THE PLAN'S ORIGINAL WORDING, noted honestly: the
plan said to turn the golden-set script into an "importable library." This
runs it as a subprocess instead. That file encodes real, hard-won
production-incident reproductions (named device IDs, real timestamps, real
destinations) -- refactoring its internals under time pressure risks
silently corrupting one of those reproductions in a way that wouldn't be
obvious from a diff. Subprocess + exit code is lower-risk and fully
sufficient for what this job actually needs (a pass/fail gate), at the cost
of parsed-stdout detail instead of structured per-check results. A real
refactor into an importable library remains legitimate future work, done
carefully and separately, not bundled into this commit.

Wired into config.yaml's scheduled_jobs.scheduler.backtest_job (Release 15
follow-up), nightly at 3:30am, same "script" override pattern every other
v13/ops/*.py scheduled job uses. This module is written to be callable
either as a scheduled subprocess via its own __main__, or directly imported
and called, matching every other v13/ops/*.py module's shape.
"""
import argparse
import json
import logging
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

# BUGFIX (found live on .94 while dynamically testing this job ahead of its
# first-ever scheduled run): this module had NO sys.path setup at all, unlike
# every other v13/ops/*.py scheduled job (live_prune.py, live_retro_hunter.py,
# etc., all `sys.path.append(.../src)` before their own v13.* imports).
# Running it directly (as config.yaml's scheduler.backtest_job now does every
# night, or as scripts/scheduler.py's own bare `subprocess.Popen([sys.executable,
# script_path])` with no PYTHONPATH) failed immediately with `ModuleNotFoundError:
# No module named 'v13'`, silently -- scheduler.py doesn't capture or check
# subprocess output/exit codes, so this would have failed every single night
# with nothing surfacing it. This never showed up in this module's own test
# suite because that suite already sets up sys.path itself before importing.
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from argus.autotune.engine import (  # noqa: E402
    AutotuneEngine, TUNABLE_PARAMETERS, _LESS_SENSITIVE_DIRECTION, compute_drift_result,
    wilson_lower_bound, _MIN_TRIALS_FOR_LOOSENING,
)
from argus.decision.engine import _HARD_STOP_FRESHNESS_SECONDS  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.synthetic.injector import sweep  # noqa: E402
from core.heartbeat import write_component_heartbeat  # noqa: E402

LOGGER = logging.getLogger("v13.ops.backtest_job")

_GOLDEN_SET_SCRIPT = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "test_real_world_alert_regression.py"
_GOLDEN_SET_TIMEOUT_SECONDS = 120

# First-pass, not-yet-empirically-tuned constant (this codebase's own
# established honesty framing) -- the minimum fraction of synthetic attack
# classes a device sample must detect for the sweep to pass.
_DEFAULT_ATTACK_FLOOR = 0.5

# Release 15 Sheet 03a triggering logic (2026-09-15): propose_change() had zero
# production callers before this -- the autotuner's safety infrastructure (canary,
# backtest-gate, bounded steps, rollback) was fully built with nothing driving it.
# Scoped to hard_stop_candidate_sensitivity ONLY at the time, deliberately, not all
# four TUNABLE_PARAMETERS: it's the one parameter with a real, grounded signal in
# this run's own synthetic-sweep data (a per-class detection rate). The other three
# (reputation_tier_suspicious_floor/high_floor, bocpd_hazard_rate) had no comparable
# signal here -- the synthetic attack generators are behavioral, not reputation/IOC-
# based, so they never stressed the reputation-tier floors.
#
# CORRECTED 2026-09-27 (Phase 1 of the autonomy-completion effort): the claim that
# bocpd_hazard_rate "has ZERO live consumer on .94" was true when written but is
# stale -- a later session (2026-09-16, "Baseline/BOCPD now live on .94") wired
# BaselineEngine into live_engine.py's own evaluate() (see _get_baseline_engine()
# there), which IS the live .94 pipeline; argus/ingest/daemon.py's separate
# BaselineEngine instance on .19 is a different, out-of-scope process, not the only
# one. bocpd_hazard_rate's own forward generator now lives in
# _propose_bocpd_hazard_changes() below, added the same session this comment was
# corrected -- reads baseline/engine.py's persisted `regime_change` evidence and
# decisions.raw_payload_json ground truth, the same real signal every other
# generator in this file uses, not synthetic sweep data.
_TUNE_PARAMETER = "hard_stop_candidate_sensitivity"
_TUNE_TIGHTEN_FLOOR = 0.70   # any class below this proposes tightening
_TUNE_LOOSEN_CEILING = 1.0   # every class's RAW detection rate must be at 100% to even consider loosening
_TUNE_DEFAULT_SENSITIVITY = 0.9  # matches decision/engine.py's own hardcoded default

# 2026-09-16, per-device/category autotuning (Documentation/
# PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md §3b): the safe-threshold gate this plan's
# user request explicitly asked for -- closes a real gap that existed even for
# the GLOBAL-only tuning above: _TUNE_LOOSEN_CEILING alone never checked HOW MANY
# synthetic trials backed a "100%" rate, so 1/1 counted identically to 200/200.
#
# _MIN_TRIALS_FOR_LOOSENING (imported from autotune.engine, shared with its own
# trust-radius/scope logic) is a coarse PRE-filter: below it, a scope isn't even
# considered for loosening. The real statistical gate is
# _TUNE_LOOSEN_WILSON_FLOOR, checked against the Wilson score interval's 95%
# lower bound of the observed rate (wilson_lower_bound()), not the raw rate --
# since _TUNE_LOOSEN_CEILING already requires a perfect 100% raw rate first, the
# Wilson lower bound at that point is a pure function of n:
# wilson_lower_bound(n, n) = 1 / (1 + z^2/n). At n=_MIN_TRIALS_FOR_LOOSENING (20),
# that's ~0.836 -- deliberately BELOW this floor, so 20 alone is necessary but not
# sufficient; a perfect record needs ~22 trials in practice to actually clear
# 0.85. This is intentional: the coarse pre-filter and the real statistical gate
# are meant to disagree slightly, so the system asks for a bit more evidence than
# the bare minimum before actually trusting a loosening move.
_TUNE_LOOSEN_WILSON_FLOOR = 0.85

# Caps how many additional synthetic sweep passes a small category's devices get
# in one night (beyond the base run_synthetic_sweep() pass every device already
# gets) purely to accumulate enough trials to be EVALUATED for loosening -- see
# augment_small_category_sweeps(). A category with too few devices to reach
# _MIN_TRIALS_FOR_LOOSENING even at this cap correctly stays below it and
# inherits its parent tier -- the honest outcome for a category this network
# genuinely doesn't have enough of to specialize a threshold for, not a bug to
# engineer around further.
_MAX_SWEEP_REPETITIONS_PER_DEVICE = 5


def _device_type_lookup(store: GraphStore, device_ids: List[str]) -> Dict[str, Optional[str]]:
    """device_id -> effective device_type (or None) for the given devices, one query.

    BUGFIX (found 2026-09-21 while investigating a real .94 OOM incident, NOT
    by inspection): this used to read the devices.device_type COLUMN directly
    (`SELECT device_id, device_type FROM devices ...`). Confirmed live: on
    .94's real graph, ALL 56 devices have device_type=NULL in that column --
    the live pipeline never writes it (score_metric()'s own upsert_device()
    call never passes device_type; live_engine.py's peer-deviation injection
    writes it into metadata_json via update_device_metadata(), never the
    column). This is the SAME landmine population_prior_builder.py's own
    _device_type_map() already hit and fixed on 2026-09-16 (see that
    function's docstring) -- a second, independent instance of it here meant
    every category/device-scoped tuning proposal in this module
    (augment_small_category_sweeps(), _propose_scoped_tuning_changes())
    silently produced zero proposals, ever: devices_by_category always came
    back empty since every entry's device_type was None. Fixed the same way:
    metadata_json's own "device_type" key first, the column as fallback."""
    if not device_ids:
        return {}
    placeholders = ",".join("?" * len(device_ids))
    rows = store._conn.execute(
        f"SELECT device_id, device_type, metadata_json FROM devices WHERE device_id IN ({placeholders})",
        device_ids,
    ).fetchall()
    out: Dict[str, Optional[str]] = {}
    for row in rows:
        try:
            meta = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except (TypeError, ValueError):
            meta = {}
        out[row["device_id"]] = meta.get("device_type") or row["device_type"]
    return out


def _flatten_trials(per_device: Dict[str, Any], device_type_of: Dict[str, Optional[str]]) -> List[Dict[str, Any]]:
    """One entry per real sweep result (device_id/device_type/result), skipping
    error entries (no attack_results to learn anything from)."""
    out = []
    for device_id, result in per_device.items():
        if "attack_results" not in result:
            continue
        out.append({"device_id": device_id, "device_type": device_type_of.get(device_id), "result": result})
    return out


def augment_small_category_sweeps(store: GraphStore, base_synthetic: Dict[str, Any],
                                     device_type_of: Dict[str, Optional[str]],
                                     now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Runs additional synthetic sweep passes against devices in any category
    whose base-pass trial count is below _MIN_TRIALS_FOR_LOOSENING, up to
    _MAX_SWEEP_REPETITIONS_PER_DEVICE total passes per device (including the
    base pass already run by run_synthetic_sweep()) -- see Documentation/
    PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md §3b. Deliberately does NOT try to force
    every category up to the floor -- a category with too few devices to ever
    reach it even at the repetition cap correctly stays below it (inherits its
    parent tier), which is the honest, intended outcome, not a bug.

    Returns the FULL flat trial list (base pass + every repeat), each entry
    tagged with device_id/device_type -- the single input every scope's rate
    calculation below reads from, so nothing downstream has to know which
    entries came from the base pass vs. a repeat."""
    now = now if now is not None else time.time()
    base_trials = _flatten_trials(base_synthetic.get("per_device", {}), device_type_of)

    devices_by_category: Dict[str, List[str]] = {}
    for entry in base_trials:
        if entry["device_type"]:
            devices_by_category.setdefault(entry["device_type"], []).append(entry["device_id"])

    all_trials = list(base_trials)
    for category, device_ids in devices_by_category.items():
        base_count = len(device_ids)  # each device contributes exactly 1 trial/class in one pass
        if base_count >= _MIN_TRIALS_FOR_LOOSENING:
            continue  # already enough from the base pass alone -- no repeats needed
        passes_needed = -(-_MIN_TRIALS_FOR_LOOSENING // base_count)  # ceil(floor / base_count)
        extra_passes = max(0, min(passes_needed - 1, _MAX_SWEEP_REPETITIONS_PER_DEVICE - 1))
        for _ in range(extra_passes):
            for device_id in device_ids:
                try:
                    result = sweep(store, device_id, now=now)
                except Exception as exc:
                    LOGGER.warning("Repeat sweep failed for %s (category %s), recorded as fewer trials, "
                                     "not a hard failure: %s", device_id, category, exc)
                    continue
                all_trials.append({"device_id": device_id, "device_type": category, "result": result})
    return all_trials


def _hits_and_totals_by_class(trials: List[Dict[str, Any]]) -> Dict[str, "tuple[int, int]"]:
    """(hits, n) per attack class from a flat trial list already filtered to
    the desired scope by the caller."""
    by_class: Dict[str, List[bool]] = {}
    for entry in trials:
        for cls, r in entry["result"].get("attack_results", {}).items():
            if isinstance(r, dict) and "detected" in r:
                by_class.setdefault(cls, []).append(bool(r["detected"]))
    return {cls: (sum(hits), len(hits)) for cls, hits in by_class.items() if hits}


def _scope_has_drift(drift: Dict[str, Any], parameter: str, device_id: Optional[str],
                       device_type: Optional[str]) -> bool:
    """True if compute_drift_result()'s findings include THIS exact scope --
    not just drift.get('drift_detected') anywhere on the network, which would
    incorrectly block an unrelated scope's loosening proposal over a totally
    different device/category's drift."""
    for finding in drift.get("findings", []):
        if finding.get("parameter") == parameter and finding.get("device_id") == device_id \
                and finding.get("device_type") == device_type:
            return True
    return False


def _decide_scoped_change(current: float, bounds: Dict[str, float], direction: int,
                             class_hits_totals: Dict[str, "tuple[int, int]"],
                             drift_at_scope: bool, scope_label: str, run_id: str,
                             allow_loosen: bool) -> Optional["tuple[float, str]"]:
    """The shared tighten/loosen decision for ANY scope (global, category, or
    device) -- deliberately asymmetric, matching the plan's own safe-threshold
    design:

    TIGHTEN: fires on any class whose RAW rate falls below _TUNE_TIGHTEN_FLOOR,
    with NO minimum sample size -- a single confirmed miss is real information
    worth tightening on immediately ("fails safe toward more detection, no
    waiting"). Under-reacting to a miss is the actually-dangerous failure mode,
    not over-reacting to a small sample.

    LOOSEN: requires EVERY class to (a) have at least _MIN_TRIALS_FOR_LOOSENING
    trials, (b) show a perfect _TUNE_LOOSEN_CEILING raw rate (unchanged from
    the original global-only logic), AND (c) have a Wilson-lower-bound rate
    clearing _TUNE_LOOSEN_WILSON_FLOOR -- see that constant's own docstring for
    why both (b) and (c) are needed together. `allow_loosen=False` lets a
    caller skip loosening evaluation entirely for a scope where it structurally
    doesn't apply (kept as an explicit caller decision, not inferred here)."""
    if not class_hits_totals:
        return None
    worst_cls, (worst_hits, worst_n) = min(
        class_hits_totals.items(), key=lambda kv: (kv[1][0] / kv[1][1]) if kv[1][1] else 1.0
    )
    worst_rate = (worst_hits / worst_n) if worst_n else 1.0

    if worst_rate < _TUNE_TIGHTEN_FLOOR:
        new_value = current - direction * bounds["max_step"]
        reason = (f"backtest {run_id} [{scope_label}]: synthetic detection for '{worst_cls}' fell to "
                   f"{worst_rate:.2f} (floor {_TUNE_TIGHTEN_FLOOR}, n={worst_n}) -- tightening")
        return new_value, reason

    if not allow_loosen:
        return None
    if any(n < _MIN_TRIALS_FOR_LOOSENING for _, n in class_hits_totals.values()):
        return None  # not enough evidence anywhere to even evaluate loosening for this scope
    if worst_rate < _TUNE_LOOSEN_CEILING:
        return None
    min_wilson = min(wilson_lower_bound(hits, n) for hits, n in class_hits_totals.values())
    if min_wilson >= _TUNE_LOOSEN_WILSON_FLOOR and not drift_at_scope:
        min_n = min(n for _, n in class_hits_totals.values())
        new_value = current + direction * bounds["max_step"]
        reason = (f"backtest {run_id} [{scope_label}]: every synthetic class at "
                   f"{_TUNE_LOOSEN_CEILING:.0%} raw detection with a Wilson-lower-bound rate "
                   f">= {_TUNE_LOOSEN_WILSON_FLOOR:.0%} (min n={min_n}), no drift detected for this "
                   f"scope -- easing back toward its parent tier")
        return new_value, reason
    return None


def _propose_tuning_change(store: GraphStore, synthetic: Dict[str, Any], drift: Dict[str, Any],
                              run_id: str, now: float) -> Optional[Dict[str, Any]]:
    """GLOBAL-scope proposal -- unchanged in shape/behavior from before this
    session's per-device/category work, EXCEPT the loosening path now also
    requires _MIN_TRIALS_FOR_LOOSENING/_TUNE_LOOSEN_WILSON_FLOOR (a real,
    pre-existing gap: this direction previously trusted a 100% raw rate off as
    few as 1-2 synthetic trials). Tightening's behavior is byte-for-byte
    identical to before -- no sample floor there, by design (see
    _decide_scoped_change()'s own docstring)."""
    by_class: Dict[str, List[bool]] = {}
    for device_result in synthetic.get("per_device", {}).values():
        for cls, r in device_result.get("attack_results", {}).items():
            if isinstance(r, dict) and "detected" in r:
                by_class.setdefault(cls, []).append(bool(r["detected"]))
    class_hits_totals = {cls: (sum(hits), len(hits)) for cls, hits in by_class.items() if hits}
    if not class_hits_totals:
        return None

    engine = AutotuneEngine(store)
    bounds = TUNABLE_PARAMETERS[_TUNE_PARAMETER]
    direction = _LESS_SENSITIVE_DIRECTION[_TUNE_PARAMETER]
    current = engine.get_active_value(_TUNE_PARAMETER, default=_TUNE_DEFAULT_SENSITIVITY)

    decision = _decide_scoped_change(
        current, bounds, direction, class_hits_totals,
        drift_at_scope=_scope_has_drift(drift, _TUNE_PARAMETER, None, None),
        scope_label="global", run_id=run_id,
        allow_loosen=(current != _TUNE_DEFAULT_SENSITIVITY),  # unchanged global-only guard
    )
    if decision is None:
        return None
    new_value, reason = decision

    result = engine.propose_change(_TUNE_PARAMETER, new_value, reason=reason,
                                     backtest_run_id=run_id, now=now)
    return {"accepted": result.accepted, "change_id": result.change_id, "reason": result.reason,
            "parameter": _TUNE_PARAMETER, "proposed_new_value": new_value}


def _propose_scoped_tuning_changes(store: GraphStore, all_trials: List[Dict[str, Any]], drift: Dict[str, Any],
                                      run_id: str, now: float) -> List[Dict[str, Any]]:
    """Category- and device-scoped proposals -- the actual per-device/category
    half of this plan, layered on TOP of _propose_tuning_change()'s existing
    global proposal, never replacing it. Each scope is evaluated completely
    independently (its own trial count, its own Wilson bound, its own drift
    check, its own trust-radius cap enforced inside AutotuneEngine.
    propose_change() itself) -- a category or device with too little data
    simply produces no proposal at all and silently keeps inheriting its
    parent tier via get_active_value()'s own fallback, exactly the intended
    behavior, not an error.

    Returns the list of accepted-or-rejected proposal dicts (same shape as
    _propose_tuning_change()'s single return, one per scope actually
    evaluated) for backtest_runs' own record."""
    engine = AutotuneEngine(store)
    bounds = TUNABLE_PARAMETERS[_TUNE_PARAMETER]
    direction = _LESS_SENSITIVE_DIRECTION[_TUNE_PARAMETER]
    results: List[Dict[str, Any]] = []

    # --- category scope ---
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for entry in all_trials:
        if entry["device_type"]:
            by_category.setdefault(entry["device_type"], []).append(entry)
    for category, entries in by_category.items():
        class_hits_totals = _hits_and_totals_by_class(entries)
        current = engine.get_active_value(_TUNE_PARAMETER, device_type=category, default=_TUNE_DEFAULT_SENSITIVITY)
        decision = _decide_scoped_change(
            current, bounds, direction, class_hits_totals,
            drift_at_scope=_scope_has_drift(drift, _TUNE_PARAMETER, None, category),
            scope_label=f"category:{category}", run_id=run_id, allow_loosen=True,
        )
        if decision is None:
            continue
        new_value, reason = decision
        result = engine.propose_change(_TUNE_PARAMETER, new_value, reason=reason, device_type=category,
                                         backtest_run_id=run_id, now=now)
        results.append({"accepted": result.accepted, "change_id": result.change_id, "reason": result.reason,
                          "parameter": _TUNE_PARAMETER, "proposed_new_value": new_value,
                          "device_type": category})

    # --- device scope ---
    by_device: Dict[str, List[Dict[str, Any]]] = {}
    for entry in all_trials:
        by_device.setdefault(entry["device_id"], []).append(entry)
    for device_id, entries in by_device.items():
        device_type = entries[0]["device_type"]
        class_hits_totals = _hits_and_totals_by_class(entries)
        current = engine.get_active_value(_TUNE_PARAMETER, device_id=device_id, device_type=device_type,
                                             default=_TUNE_DEFAULT_SENSITIVITY)
        decision = _decide_scoped_change(
            current, bounds, direction, class_hits_totals,
            drift_at_scope=_scope_has_drift(drift, _TUNE_PARAMETER, device_id, None),
            scope_label=f"device:{device_id}", run_id=run_id, allow_loosen=True,
        )
        if decision is None:
            continue
        new_value, reason = decision
        # device_type passed alongside device_id as a parent-tier resolution
        # HINT only (propose_change() never writes it to a device-scoped row)
        # -- without it, old_value/trust-radius would incorrectly skip this
        # device's own category tier and compare straight against global.
        result = engine.propose_change(_TUNE_PARAMETER, new_value, reason=reason, device_id=device_id,
                                         device_type=device_type, backtest_run_id=run_id, now=now)
        results.append({"accepted": result.accepted, "change_id": result.change_id, "reason": result.reason,
                          "parameter": _TUNE_PARAMETER, "proposed_new_value": new_value,
                          "device_id": device_id})

    return results


def _promote_eligible_tuning_changes(store: GraphStore, run_id: str, now: float) -> List[str]:
    """The other genuinely missing half of 'fully automatic': propose_change()
    creating a row was never enough on its own -- promote_change() ALSO had zero
    production callers before this, so nothing would ever have promoted a
    canary-elapsed proposal even after this same module started creating them.
    Called only when overall_pass is True for THIS run (checked by the caller),
    since a real backtest pass is exactly what promote_change() itself requires
    as the confirming run for any change whose canary window has elapsed --
    this run serves as that confirmation for every eligible pending change, not
    only ones it personally proposed. Returns the list of change_ids actually
    promoted this cycle."""
    engine = AutotuneEngine(store)
    rows = store._conn.execute(
        "SELECT change_id FROM threshold_history WHERE promoted_at IS NULL "
        "AND rolled_back_at IS NULL AND canary_until <= ?",
        (now,),
    ).fetchall()
    promoted = []
    for row in rows:
        change_id = row["change_id"]
        try:
            if engine.promote_change(change_id, confirming_backtest_run_id=run_id, now=now):
                promoted.append(change_id)
        except Exception:
            LOGGER.exception("[AUTOTUNE_TRIGGER] promote_change(%s) failed, non-fatal", change_id)
    return promoted


# 2026-09-16, per-device/category autotuning plan §4, item 4 (user-requested:
# "implement it and a hit should trigger an immediate autonomous rollback"):
# the retroactive circuit-breaker. Every OTHER failsafe (canary+confirming-
# backtest, drift detection, trust-radius cap) validates a scoped change
# against SYNTHETIC attack data or STATISTICAL trends -- none of them can see
# a real attack slipping through specifically BECAUSE a scope was loosened,
# since that never happened in the synthetic world. This closes that blind
# spot using real, already-recorded ground truth: decisions.raw_payload_json's
# own fp_verdict field (the SAME CONFIRMED_THREAT signal overview_api.py's
# fp_confirmed_threats tile and ai_soc.py's DeterministicValidator already
# treat as ground truth elsewhere in this codebase -- not a new definition of
# "confirmed" invented here).
# Same 7-day window compute_drift_result()'s own _DEFAULT_DRIFT_LOOKBACK_SECONDS
# uses (argus/autotune/engine.py) -- not imported directly since that name is
# module-private there too; kept as its own constant here rather than reaching
# across the module boundary for a private name a second time in this file.
_RETROACTIVE_MISS_LOOKBACK_SECONDS = 7 * 86400.0


def _iter_active_loosened_scopes(store: GraphStore, engine: AutotuneEngine, parameter: str,
                                    default: float):
    """Shared traversal used by every retroactive-circuit-breaker check in this
    file: finds every currently-active (promoted, not yet rolled back) device- or
    category-scoped override of `parameter` that's LOOSENED relative to its
    parent tier, resolves that parent's own current value, and the concrete
    device_id set the scope covers. Yields (change_id, scope_device_id,
    scope_device_type, scope_value, parent_value, band_lo, band_hi, device_ids)
    tuples -- callers do their own parameter-specific near-miss/confirmation
    lookup against `device_ids`.

    2026-09-21 (legacy/Sheet 03a autotune reconciliation, Phase F): extracted
    from check_retroactive_misses_and_rollback() (originally hand-scoped to
    _TUNE_PARAMETER only) so arp_sweep_unique_targets_threshold/
    fp_combined_suppress_threshold's own checks below don't duplicate this
    traversal -- their near-miss signal and ground-truth confirmation differ
    from hard_stop_candidate_sensitivity's, but "which scopes are even
    eligible" does not."""
    direction = _LESS_SENSITIVE_DIRECTION[parameter]
    active_scoped_rows = store._conn.execute(
        "SELECT change_id, device_id, device_type, new_value FROM threshold_history WHERE parameter=? "
        "AND promoted_at IS NOT NULL AND rolled_back_at IS NULL "
        "AND (device_id IS NOT NULL OR device_type IS NOT NULL)",
        (parameter,),
    ).fetchall()

    for row in active_scoped_rows:
        scope_device_id = row["device_id"]
        scope_device_type = row["device_type"]
        scope_value = float(row["new_value"])

        parent_device_type = scope_device_type if scope_device_id else None
        parent_value = engine.get_active_value(parameter, device_id=None, device_type=parent_device_type,
                                                  default=default)

        # Only a LOOSENED scope can have missed something its parent would
        # have caught -- a tightened scope is strictly MORE cautious than its
        # parent, so it can never be the cause of a real miss.
        if not ((scope_value - parent_value) * direction > 0):
            continue
        band_lo, band_hi = (parent_value, scope_value) if direction > 0 else (scope_value, parent_value)

        if scope_device_id:
            device_ids = [scope_device_id]
        else:
            device_ids = [r["device_id"] for r in store._conn.execute(
                "SELECT device_id FROM devices WHERE device_type=? AND merged_into_device_id IS NULL",
                (scope_device_type,),
            ).fetchall()]
        if not device_ids:
            continue

        yield (row["change_id"], scope_device_id, scope_device_type, scope_value,
               parent_value, band_lo, band_hi, device_ids)


def check_retroactive_misses_and_rollback(store: GraphStore, now: Optional[float] = None,
                                             lookback_seconds: float = _RETROACTIVE_MISS_LOOKBACK_SECONDS
                                             ) -> List[Dict[str, Any]]:
    """For every currently-active (promoted, not yet rolled back) device- or
    category-scoped _TUNE_PARAMETER override that's LOOSENED relative to its
    parent tier: finds real suricata_signature_match evidence, for a device in
    that scope, whose confidence falls in the band [parent_value, scope_value)
    -- i.e. would have cleared the PARENT tier's stricter hard-stop bar but
    does not clear this scope's own looser one. For each such near-miss, checks
    whether a decision for that same device within _HARD_STOP_FRESHNESS_SECONDS
    of it was later recorded as fp_verdict.verdict == "CONFIRMED_THREAT" (the
    established ground truth). Any hit rolls back that EXACT scoped override
    immediately, in this same pass -- no canary, no confirming backtest, no
    operator approval gate, matching the user's own explicit choice ("a hit
    should trigger an immediate autonomous rollback"): unlike a NEW proposal,
    which is inherently a guess being cautiously introduced, this is undoing
    an override that real evidence has already shown was wrong.

    Deliberately scoped to _TUNE_PARAMETER here -- the evidence-CONFIDENCE-
    vs-threshold band comparison this function does is only meaningful for a
    hard-stop min-confidence bar. arp_sweep_unique_targets_threshold and
    fp_combined_suppress_threshold get their OWN checks below
    (check_arp_sweep_retroactive_misses_and_rollback() /
    check_fp_combined_retroactive_misses_and_rollback()), sharing this
    function's scope-traversal (_iter_active_loosened_scopes()) but not its
    near-miss/confirmation logic, which doesn't generalize cleanly to either.

    Runs independently of overall_pass -- a real confirmed miss from an
    already-promoted override is worth rolling back even on a night the
    synthetic backtest itself failed for an unrelated reason. Best-effort at
    the call site (run_backtest() wraps this in its own try/except, same
    "never take down the run" framing as every other autotune trigger there).

    Returns the list of {change_id, device_id, device_type, reason} dicts for
    everything actually rolled back this pass."""
    now = now if now is not None else time.time()
    since = now - lookback_seconds
    engine = AutotuneEngine(store)
    rolled_back: List[Dict[str, Any]] = []

    for (change_id, scope_device_id, scope_device_type, scope_value, parent_value,
         band_lo, band_hi, device_ids) in _iter_active_loosened_scopes(
             store, engine, _TUNE_PARAMETER, _TUNE_DEFAULT_SENSITIVITY):
        placeholders = ",".join("?" * len(device_ids))

        near_misses = store._conn.execute(
            f"SELECT device_id, timestamp FROM evidence WHERE evidence_type='suricata_signature_match' "
            f"AND device_id IN ({placeholders}) AND timestamp >= ? AND confidence >= ? AND confidence < ?",
            (*device_ids, since, band_lo, band_hi),
        ).fetchall()
        if not near_misses:
            continue

        confirming_reason = None
        for ev in near_misses:
            decision_rows = store._conn.execute(
                "SELECT decision_id, raw_payload_json FROM decisions WHERE device_id=? "
                "AND timestamp >= ? AND timestamp <= ?",
                (ev["device_id"], ev["timestamp"] - _HARD_STOP_FRESHNESS_SECONDS,
                 ev["timestamp"] + _HARD_STOP_FRESHNESS_SECONDS),
            ).fetchall()
            for drow in decision_rows:
                try:
                    payload = json.loads(drow["raw_payload_json"] or "{}")
                except (TypeError, ValueError):
                    continue
                if (payload.get("fp_verdict") or {}).get("verdict") == "CONFIRMED_THREAT":
                    confirming_reason = (
                        f"retroactive circuit-breaker: decision {drow['decision_id']} for device "
                        f"{ev['device_id']} was CONFIRMED_THREAT, near a suricata_signature_match "
                        f"evidence item (confidence in [{band_lo:.3f}, {band_hi:.3f})) that this scope's "
                        f"value {scope_value:.3f} would not hard-stop but the parent tier's "
                        f"{parent_value:.3f} would have"
                    )
                    break
            if confirming_reason:
                break

        if confirming_reason is None:
            continue

        if engine.rollback_change(change_id, confirming_reason, now=now):
            LOGGER.critical("[AUTOTUNE_CIRCUIT_BREAKER] %s", confirming_reason)
            rolled_back.append({"change_id": change_id, "device_id": scope_device_id,
                                  "device_type": scope_device_type, "reason": confirming_reason})

    return rolled_back


_ARP_SWEEP_PARAMETER = "arp_sweep_unique_targets_threshold"
_ARP_SWEEP_DEFAULT_THRESHOLD = 8.0  # matches pipeline.py's own config.get(..., 8) default


def check_arp_sweep_retroactive_misses_and_rollback(store: GraphStore, now: Optional[float] = None,
                                                        lookback_seconds: float = _RETROACTIVE_MISS_LOOKBACK_SECONDS
                                                        ) -> List[Dict[str, Any]]:
    """Same shape as check_retroactive_misses_and_rollback(), for
    arp_sweep_unique_targets_threshold. The re-scorable signal here is
    evidence.VALUE (the raw unique-target count), not confidence --
    threat_signals.py computes arp_sweep evidence's confidence FROM the
    threshold already in force at write time (0.5 + (count-threshold)*0.05,
    confirmed via the evidence-bridge trace this phase's own investigation
    did), so re-banding that confidence against a hypothetical parent
    threshold would double-count the original threshold. The raw count is
    threshold-independent and safe to re-band directly. Confirmation is the
    SAME mechanism as the hard-stop check: a decision for that device, within
    _HARD_STOP_FRESHNESS_SECONDS of the near-miss evidence, later recorded as
    fp_verdict.verdict == "CONFIRMED_THREAT"."""
    now = now if now is not None else time.time()
    since = now - lookback_seconds
    engine = AutotuneEngine(store)
    rolled_back: List[Dict[str, Any]] = []

    for (change_id, scope_device_id, scope_device_type, scope_value, parent_value,
         band_lo, band_hi, device_ids) in _iter_active_loosened_scopes(
             store, engine, _ARP_SWEEP_PARAMETER, _ARP_SWEEP_DEFAULT_THRESHOLD):
        placeholders = ",".join("?" * len(device_ids))

        near_misses = store._conn.execute(
            f"SELECT device_id, timestamp FROM evidence WHERE evidence_type='arp_sweep' "
            f"AND device_id IN ({placeholders}) AND timestamp >= ? AND value >= ? AND value < ?",
            (*device_ids, since, band_lo, band_hi),
        ).fetchall()
        if not near_misses:
            continue

        confirming_reason = None
        for ev in near_misses:
            decision_rows = store._conn.execute(
                "SELECT decision_id, raw_payload_json FROM decisions WHERE device_id=? "
                "AND timestamp >= ? AND timestamp <= ?",
                (ev["device_id"], ev["timestamp"] - _HARD_STOP_FRESHNESS_SECONDS,
                 ev["timestamp"] + _HARD_STOP_FRESHNESS_SECONDS),
            ).fetchall()
            for drow in decision_rows:
                try:
                    payload = json.loads(drow["raw_payload_json"] or "{}")
                except (TypeError, ValueError):
                    continue
                if (payload.get("fp_verdict") or {}).get("verdict") == "CONFIRMED_THREAT":
                    confirming_reason = (
                        f"retroactive circuit-breaker: decision {drow['decision_id']} for device "
                        f"{ev['device_id']} was CONFIRMED_THREAT, near an arp_sweep evidence item "
                        f"(unique-target count in [{band_lo:.1f}, {band_hi:.1f})) that this scope's "
                        f"threshold {scope_value:.1f} would not flag but the parent tier's "
                        f"{parent_value:.1f} would have"
                    )
                    break
            if confirming_reason:
                break

        if confirming_reason is None:
            continue

        if engine.rollback_change(change_id, confirming_reason, now=now):
            LOGGER.critical("[AUTOTUNE_CIRCUIT_BREAKER] %s", confirming_reason)
            rolled_back.append({"change_id": change_id, "device_id": scope_device_id,
                                  "device_type": scope_device_type, "reason": confirming_reason})

    return rolled_back


_FP_COMBINED_PARAMETER = "fp_combined_suppress_threshold"
_FP_COMBINED_DEFAULT_THRESHOLD = 0.80  # matches fp_engine.py's own _DEFAULT_COMBINED_SUPPRESS_THRESHOLD


def check_fp_combined_retroactive_misses_and_rollback(store: GraphStore, now: Optional[float] = None,
                                                          lookback_seconds: float = _RETROACTIVE_MISS_LOOKBACK_SECONDS
                                                          ) -> List[Dict[str, Any]]:
    """Same protective intent as the other two checks, for
    fp_combined_suppress_threshold -- structurally different from both,
    because a LOOSENED (lowered) suppress threshold doesn't fail to catch a
    piece of EVIDENCE, it SUPPRESSES an alert outright (no evidence row to
    re-band; the decision itself carries fp_verdict.confidence, the value that
    drove suppression).

    Near-miss: a decision in scope whose fp_verdict.confidence falls in
    [scope_value, parent_value) -- i.e. would NOT have been suppressed by the
    parent tier's higher bar, but WAS suppressed by this scope's lower one
    (fp_verdict.suppress True). Confirmation: a LATER decision for the SAME
    device, any time up to `now`, reaching fp_verdict.verdict ==
    "CONFIRMED_THREAT" -- since the near-miss decision itself was suppressed
    (never published, never seen by an operator to correct), the ground truth
    has to come from a DIFFERENT, later alert on that device establishing it's
    genuinely malicious, the same "this device has since proven hostile"
    reasoning the other two checks apply to a freshness-windowed decision,
    just necessarily a coarser window here since there's no operator-visible
    event at the moment of the near-miss to anchor a tight one to."""
    now = now if now is not None else time.time()
    since = now - lookback_seconds
    engine = AutotuneEngine(store)
    rolled_back: List[Dict[str, Any]] = []

    for (change_id, scope_device_id, scope_device_type, scope_value, parent_value,
         band_lo, band_hi, device_ids) in _iter_active_loosened_scopes(
             store, engine, _FP_COMBINED_PARAMETER, _FP_COMBINED_DEFAULT_THRESHOLD):
        placeholders = ",".join("?" * len(device_ids))

        candidate_rows = store._conn.execute(
            f"SELECT decision_id, device_id, timestamp, raw_payload_json FROM decisions "
            f"WHERE device_id IN ({placeholders}) AND timestamp >= ?",
            (*device_ids, since),
        ).fetchall()

        near_misses = []
        for row in candidate_rows:
            try:
                payload = json.loads(row["raw_payload_json"] or "{}")
            except (TypeError, ValueError):
                continue
            fp_verdict = payload.get("fp_verdict") or {}
            confidence = fp_verdict.get("confidence")
            if fp_verdict.get("suppress") and isinstance(confidence, (int, float)) \
                    and band_lo <= confidence < band_hi:
                near_misses.append(row)
        if not near_misses:
            continue

        confirming_reason = None
        for miss_row in near_misses:
            later_confirmed = store._conn.execute(
                "SELECT decision_id, raw_payload_json FROM decisions WHERE device_id=? AND timestamp > ?",
                (miss_row["device_id"], miss_row["timestamp"]),
            ).fetchall()
            for drow in later_confirmed:
                try:
                    payload = json.loads(drow["raw_payload_json"] or "{}")
                except (TypeError, ValueError):
                    continue
                if (payload.get("fp_verdict") or {}).get("verdict") == "CONFIRMED_THREAT":
                    confirming_reason = (
                        f"retroactive circuit-breaker: decision {miss_row['decision_id']} for device "
                        f"{miss_row['device_id']} was SUPPRESSED at fp_verdict.confidence in "
                        f"[{band_lo:.3f}, {band_hi:.3f}) (this scope's threshold {scope_value:.3f} "
                        f"would suppress it, the parent tier's {parent_value:.3f} would not) -- a "
                        f"LATER decision {drow['decision_id']} for the same device was CONFIRMED_THREAT"
                    )
                    break
            if confirming_reason:
                break

        if confirming_reason is None:
            continue

        if engine.rollback_change(change_id, confirming_reason, now=now):
            LOGGER.critical("[AUTOTUNE_CIRCUIT_BREAKER] %s", confirming_reason)
            rolled_back.append({"change_id": change_id, "device_id": scope_device_id,
                                  "device_type": scope_device_type, "reason": confirming_reason})

    return rolled_back


_REPUTATION_SUSPICIOUS_PARAMETER = "reputation_tier_suspicious_floor"
_REPUTATION_HIGH_PARAMETER = "reputation_tier_high_floor"
_REPUTATION_SUSPICIOUS_DEFAULT = 2.0  # matches classifier.py's own confirmed_vt_ti_floor default
_REPUTATION_HIGH_DEFAULT = 4.0        # matches classifier.py's own confirmed_abuse_floor default

# 2026-09-27 (Phase 1 of the autonomy-completion effort): the forward generator for
# BOTH reputation floors -- allowlisted and consumed live since Sheet 03a, but with
# zero real proposals ever on .94 (confirmed via direct query of threshold_history,
# not guessed): unlike hard_stop_candidate_sensitivity/arp_sweep_unique_targets_threshold,
# no synthetic attack class stresses these -- classifier.py's own confirmed_ioc check
# (`vt_score > suspicious_floor or ti_score > suspicious_floor or abuse_score >=
# high_floor`) needs the RAW vt/ti/abuse scores a real destination scored at decision
# time, which weren't being recorded anywhere before this same effort's fix to
# live_engine.py's autotune_state block (see that file's own 2026-09-27 comment) --
# historical decisions before that fix carry no such record, an honest, stated gap,
# not silently backfilled.
#
# Evidence model: for each scope, recall of the CURRENT floor at catching destinations
# that were LATER independently confirmed malicious (fp_verdict.verdict ==
# CONFIRMED_THREAT, the same ground truth every other retroactive/generator check in
# this file already treats as authoritative) -- "opportunities" (n) are confirmed-
# malicious decisions that carried a recorded raw score; "hits" are the ones where that
# raw score already cleared the current floor. This plugs directly into the SAME
# _decide_scoped_change() every other scoped generator in this file uses: a confirmed
# threat the current floor MISSED (recall below _TUNE_TIGHTEN_FLOOR) tightens
# (LOWERS the floor -- direction=+1 for both these parameters, "higher floor -> harder
# to reach", so tighten moves opposite that) with no sample-size floor, matching the
# "a single confirmed miss is real information" convention; a perfect,
# Wilson-gated recall across enough confirmed threats safely raises the floor a
# bounded step, matching the same asymmetry as every other parameter in this file.
_REPUTATION_LOOKBACK_SECONDS = _RETROACTIVE_MISS_LOOKBACK_SECONDS  # same 7-day window as everything else here


def _reputation_score_and_floor(payload: Dict[str, Any], parameter: str) -> "tuple[Optional[float], Optional[float]]":
    """(raw_score, floor_in_effect_at_decision_time) for `parameter` from a decision's
    already-parsed raw_payload_json, or (None, None) if this decision predates the
    2026-09-27 autotune_state instrumentation or lacks the relevant field. Shared by
    the retroactive-rollback check below and (in spirit -- that one reads scores
    directly, not via this helper, since it needs a hits/n aggregate rather than a
    single band comparison) _reputation_recall_hits_totals()."""
    state = payload.get("_autotune_state") or {}
    if parameter == _REPUTATION_SUSPICIOUS_PARAMETER:
        vt = state.get("reputation_vt_score")
        ti = state.get("reputation_ti_score")
        candidates = [v for v in (vt, ti) if isinstance(v, (int, float))]
        score = max(candidates) if candidates else None
        floor_at_decision = state.get(_REPUTATION_SUSPICIOUS_PARAMETER)
    else:
        score = state.get("reputation_abuse_score")
        score = score if isinstance(score, (int, float)) else None
        floor_at_decision = state.get(_REPUTATION_HIGH_PARAMETER)
    if not isinstance(floor_at_decision, (int, float)):
        floor_at_decision = None
    return score, floor_at_decision


def check_reputation_floor_retroactive_misses_and_rollback(
        store: GraphStore, parameter: str, now: Optional[float] = None,
        lookback_seconds: float = _RETROACTIVE_MISS_LOOKBACK_SECONDS) -> List[Dict[str, Any]]:
    """Same protective intent as the other retroactive checks in this file, for
    either reputation floor (`parameter` is one of _REPUTATION_SUSPICIOUS_PARAMETER/
    _REPUTATION_HIGH_PARAMETER) -- a clean fit for the same "scalar value vs. a band"
    pattern arp_sweep/hard_stop use, since classifier.py's own confirmed_ioc check is
    itself a scalar-vs-floor comparison.

    Near-miss: a decision in scope whose recorded raw score (see
    _reputation_score_and_floor()) falls in [scope_value, parent_value) -- i.e. the
    parent tier's stricter (lower) floor would have classified this destination as
    suspicious/high, but this scope's own looser (higher) floor did not. Confirmation:
    that same decision (or a later one for the same device within
    _HARD_STOP_FRESHNESS_SECONDS) reached fp_verdict.verdict == "CONFIRMED_THREAT" --
    the established ground truth every other check in this file already uses. Only
    ever evaluates decisions carrying the 2026-09-27 autotune_state instrumentation;
    an older decision with no recorded score simply can't be re-banded, an honest
    limitation, not a silent skip disguised as "no near-miss found"."""
    now = now if now is not None else time.time()
    since = now - lookback_seconds
    engine = AutotuneEngine(store)
    rolled_back: List[Dict[str, Any]] = []
    default = _REPUTATION_SUSPICIOUS_DEFAULT if parameter == _REPUTATION_SUSPICIOUS_PARAMETER \
        else _REPUTATION_HIGH_DEFAULT

    for (change_id, scope_device_id, scope_device_type, scope_value, parent_value,
         band_lo, band_hi, device_ids) in _iter_active_loosened_scopes(store, engine, parameter, default):
        placeholders = ",".join("?" * len(device_ids))

        candidate_rows = store._conn.execute(
            f"SELECT decision_id, device_id, timestamp, raw_payload_json FROM decisions "
            f"WHERE device_id IN ({placeholders}) AND timestamp >= ?",
            (*device_ids, since),
        ).fetchall()

        near_misses = []
        for row in candidate_rows:
            try:
                payload = json.loads(row["raw_payload_json"] or "{}")
            except (TypeError, ValueError):
                continue
            score, _floor = _reputation_score_and_floor(payload, parameter)
            if score is not None and band_lo <= score < band_hi:
                near_misses.append((row, payload))
        if not near_misses:
            continue

        confirming_reason = None
        for miss_row, miss_payload in near_misses:
            if (miss_payload.get("fp_verdict") or {}).get("verdict") == "CONFIRMED_THREAT":
                confirming_reason = (
                    f"retroactive circuit-breaker: decision {miss_row['decision_id']} for device "
                    f"{miss_row['device_id']} scored in [{band_lo:.3f}, {band_hi:.3f}) for {parameter} "
                    f"(this scope's floor {scope_value:.3f} would not classify it suspicious/high, "
                    f"the parent tier's {parent_value:.3f} would have) and was itself CONFIRMED_THREAT"
                )
                break
            later_confirmed = store._conn.execute(
                "SELECT decision_id, raw_payload_json FROM decisions WHERE device_id=? "
                "AND timestamp > ? AND timestamp <= ?",
                (miss_row["device_id"], miss_row["timestamp"], miss_row["timestamp"] + _HARD_STOP_FRESHNESS_SECONDS),
            ).fetchall()
            for drow in later_confirmed:
                try:
                    later_payload = json.loads(drow["raw_payload_json"] or "{}")
                except (TypeError, ValueError):
                    continue
                if (later_payload.get("fp_verdict") or {}).get("verdict") == "CONFIRMED_THREAT":
                    confirming_reason = (
                        f"retroactive circuit-breaker: decision {miss_row['decision_id']} for device "
                        f"{miss_row['device_id']} scored in [{band_lo:.3f}, {band_hi:.3f}) for {parameter} "
                        f"(this scope's floor {scope_value:.3f} would not classify it suspicious/high, "
                        f"the parent tier's {parent_value:.3f} would have) -- a LATER decision "
                        f"{drow['decision_id']} for the same device was CONFIRMED_THREAT"
                    )
                    break
            if confirming_reason:
                break

        if confirming_reason is None:
            continue

        if engine.rollback_change(change_id, confirming_reason, now=now):
            LOGGER.critical("[AUTOTUNE_CIRCUIT_BREAKER] %s", confirming_reason)
            rolled_back.append({"change_id": change_id, "device_id": scope_device_id,
                                  "device_type": scope_device_type, "reason": confirming_reason})

    return rolled_back


def _reputation_recall_hits_totals(store: GraphStore, device_ids: List[str], parameter: str,
                                      since: float) -> Dict[str, "tuple[int, int]"]:
    """One pseudo-class ("reputation_recall") hits/n across `device_ids`: n = decisions
    carrying a recorded raw score for `parameter` (see _reputation_score_and_floor())
    whose fp_verdict.verdict was CONFIRMED_THREAT; hits = the subset where that score
    already cleared this SAME decision's own recorded floor -- the floor that was
    actually in effect when the decision was made, not today's (a decision made under
    a since-changed floor must be judged against the floor it actually saw, or a
    promotion during the window would corrupt this recall calculation)."""
    if not device_ids:
        return {}
    placeholders = ",".join("?" * len(device_ids))
    rows = store._conn.execute(
        f"SELECT raw_payload_json FROM decisions WHERE device_id IN ({placeholders}) "
        f"AND timestamp >= ? AND raw_payload_json LIKE '%CONFIRMED_THREAT%'",
        [*device_ids, since],
    ).fetchall()
    hits = 0
    n = 0
    for row in rows:
        try:
            payload = json.loads(row["raw_payload_json"] or "{}")
        except (TypeError, ValueError):
            continue
        if (payload.get("fp_verdict") or {}).get("verdict") != "CONFIRMED_THREAT":
            continue
        score, floor_at_decision = _reputation_score_and_floor(payload, parameter)
        if score is None or floor_at_decision is None:
            continue
        n += 1
        comparison = score > floor_at_decision if parameter == _REPUTATION_SUSPICIOUS_PARAMETER \
            else score >= floor_at_decision
        if comparison:
            hits += 1
    return {"reputation_recall": (hits, n)} if n else {}


def _propose_reputation_floor_changes(store: GraphStore, drift: Dict[str, Any], run_id: str,
                                         now: float) -> List[Dict[str, Any]]:
    """Global-, category-, and device-scoped proposals for both reputation floors,
    same shape as _propose_tuning_change()/_propose_scoped_tuning_changes() above --
    one independent evaluation per (parameter, scope), each with its own trial count,
    Wilson bound, drift check, and trust-radius cap (enforced inside
    AutotuneEngine.propose_change() itself, unchanged)."""
    since = now - _REPUTATION_LOOKBACK_SECONDS
    engine = AutotuneEngine(store)
    results: List[Dict[str, Any]] = []

    all_device_rows = store._conn.execute(
        "SELECT device_id FROM devices WHERE merged_into_device_id IS NULL",
    ).fetchall()
    all_device_ids = [r["device_id"] for r in all_device_rows]
    device_type_of = _device_type_lookup(store, all_device_ids)
    by_category: Dict[str, List[str]] = {}
    for device_id, device_type in device_type_of.items():
        if device_type:
            by_category.setdefault(device_type, []).append(device_id)

    for parameter in (_REPUTATION_SUSPICIOUS_PARAMETER, _REPUTATION_HIGH_PARAMETER):
        bounds = TUNABLE_PARAMETERS[parameter]
        direction = _LESS_SENSITIVE_DIRECTION[parameter]
        param_default = _REPUTATION_SUSPICIOUS_DEFAULT if parameter == _REPUTATION_SUSPICIOUS_PARAMETER \
            else _REPUTATION_HIGH_DEFAULT

        # --- global scope ---
        global_hits = _reputation_recall_hits_totals(store, all_device_ids, parameter, since)
        current = engine.get_active_value(parameter, default=param_default)
        decision = _decide_scoped_change(
            current, bounds, direction, global_hits,
            drift_at_scope=_scope_has_drift(drift, parameter, None, None),
            scope_label="global", run_id=run_id, allow_loosen=True,
        )
        if decision is not None:
            new_value, reason = decision
            result = engine.propose_change(parameter, new_value, reason=reason, backtest_run_id=run_id, now=now)
            results.append({"accepted": result.accepted, "change_id": result.change_id, "reason": result.reason,
                              "parameter": parameter, "proposed_new_value": new_value})

        # --- category scope ---
        for category, device_ids in by_category.items():
            hits_totals = _reputation_recall_hits_totals(store, device_ids, parameter, since)
            current = engine.get_active_value(parameter, device_type=category, default=param_default)
            decision = _decide_scoped_change(
                current, bounds, direction, hits_totals,
                drift_at_scope=_scope_has_drift(drift, parameter, None, category),
                scope_label=f"category:{category}", run_id=run_id, allow_loosen=True,
            )
            if decision is None:
                continue
            new_value, reason = decision
            result = engine.propose_change(parameter, new_value, reason=reason, device_type=category,
                                              backtest_run_id=run_id, now=now)
            results.append({"accepted": result.accepted, "change_id": result.change_id, "reason": result.reason,
                              "parameter": parameter, "proposed_new_value": new_value, "device_type": category})

        # --- device scope ---
        for device_id in all_device_ids:
            hits_totals = _reputation_recall_hits_totals(store, [device_id], parameter, since)
            if not hits_totals:
                continue
            device_type = device_type_of.get(device_id)
            current = engine.get_active_value(parameter, device_id=device_id, device_type=device_type,
                                                 default=param_default)
            decision = _decide_scoped_change(
                current, bounds, direction, hits_totals,
                drift_at_scope=_scope_has_drift(drift, parameter, device_id, None),
                scope_label=f"device:{device_id}", run_id=run_id, allow_loosen=True,
            )
            if decision is None:
                continue
            new_value, reason = decision
            result = engine.propose_change(parameter, new_value, reason=reason, device_id=device_id,
                                              device_type=device_type, backtest_run_id=run_id, now=now)
            results.append({"accepted": result.accepted, "change_id": result.change_id, "reason": result.reason,
                              "parameter": parameter, "proposed_new_value": new_value, "device_id": device_id})

    return results


_BOCPD_HAZARD_PARAMETER = "bocpd_hazard_rate"
_BOCPD_HAZARD_DEFAULT = 1.0 / 500.0  # matches baseline/engine.py's own _DEFAULT_HAZARD_RATE
_BOCPD_LOOKBACK_SECONDS = _RETROACTIVE_MISS_LOOKBACK_SECONDS  # same 7-day window as everything else here
# A scope whose regime_change flags fire this many times in the window with NOT ONE
# of them ever preceding a real confirmed incident is real information that this
# scope is too trigger-happy -- see _propose_bocpd_hazard_changes()'s own docstring
# for why this is the flapping half of "regime flapping versus delayed verified
# shifts" (the plan's own named evidence source for this parameter). First-pass,
# not-yet-empirically-tuned constant, same honesty framing as this file's others.
_BOCPD_FLAP_MIN_UNCORROBORATED = 5


def _propose_bocpd_hazard_changes(store: GraphStore, drift: Dict[str, Any], run_id: str,
                                     now: float) -> List[Dict[str, Any]]:
    """bocpd_hazard_rate's forward generator (2026-09-27, Phase 1 of the
    autonomy-completion effort -- see this file's own corrected module-level
    comment on _TUNE_PARAMETER for why this was previously left untriggered and why
    that's no longer true). Evidence model, matching the plan's own named source for
    this parameter ("regime flapping versus delayed verified shifts"):

    DELAYED SHIFT (a real confirmed incident with no preceding regime_change flag --
    reused directly as one pseudo-class "regime_shift_detection" hits/n, fed into the
    SAME _decide_scoped_change() every other generator in this file uses): n = decisions
    for devices in scope reaching fp_verdict.verdict == CONFIRMED_THREAT in the lookback
    window; hits = the subset preceded by a `regime_change` evidence item for that same
    device within _HARD_STOP_FRESHNESS_SECONDS beforehand. A confirmed incident BOCPD
    never flagged in advance is exactly a missed regime shift -- tightens (raises the
    hazard rate, direction=-1 so tighten moves opposite that, i.e. current + step)
    with no sample floor, same "a single confirmed miss is real information" framing
    every other tighten path in this file uses. A perfect, Wilson-gated record (every
    confirmed incident WAS preceded by a flag) safely loosens (lowers the hazard rate)
    a bounded step, same asymmetry as every other parameter here.

    FLAPPING (at least _BOCPD_FLAP_MIN_UNCORROBORATED regime_change events for a scope
    that never preceded a real incident -- independent of whether OTHER regime_change
    events for that same scope DID; a run of noise is worth caution even alongside some
    genuine hits): passed into _decide_scoped_change() as an ADDITIONAL veto OR'd onto
    the ordinary drift check -- that parameter already means exactly "don't loosen this
    scope right now", so a flapping scope is blocked from loosening (though a confirmed
    miss can still force a tighten regardless -- becoming MORE cautious is never
    something flapping evidence should block)."""
    since = now - _BOCPD_LOOKBACK_SECONDS
    engine = AutotuneEngine(store)
    bounds = TUNABLE_PARAMETERS[_BOCPD_HAZARD_PARAMETER]
    direction = _LESS_SENSITIVE_DIRECTION[_BOCPD_HAZARD_PARAMETER]
    results: List[Dict[str, Any]] = []

    all_device_rows = store._conn.execute(
        "SELECT device_id FROM devices WHERE merged_into_device_id IS NULL",
    ).fetchall()
    all_device_ids = [r["device_id"] for r in all_device_rows]
    device_type_of = _device_type_lookup(store, all_device_ids)
    by_category: Dict[str, List[str]] = {}
    for device_id, device_type in device_type_of.items():
        if device_type:
            by_category.setdefault(device_type, []).append(device_id)

    def hits_totals_and_flapping(device_ids: List[str]) -> "tuple[Dict[str, tuple], bool]":
        if not device_ids:
            return {}, False
        placeholders = ",".join("?" * len(device_ids))
        incident_rows = store._conn.execute(
            f"SELECT device_id, timestamp, raw_payload_json FROM decisions WHERE device_id IN ({placeholders}) "
            f"AND timestamp >= ? AND raw_payload_json LIKE '%CONFIRMED_THREAT%'",
            [*device_ids, since],
        ).fetchall()
        regime_rows = store._conn.execute(
            f"SELECT device_id, timestamp FROM evidence WHERE evidence_type='regime_change' "
            f"AND device_id IN ({placeholders}) AND timestamp >= ?",
            [*device_ids, since],
        ).fetchall()
        regime_by_device: Dict[str, List[float]] = {}
        for r in regime_rows:
            regime_by_device.setdefault(r["device_id"], []).append(float(r["timestamp"]))

        hits = 0
        n = 0
        corroborated_regime_ts = set()
        for row in incident_rows:
            try:
                payload = json.loads(row["raw_payload_json"] or "{}")
            except (TypeError, ValueError):
                continue
            if (payload.get("fp_verdict") or {}).get("verdict") != "CONFIRMED_THREAT":
                continue
            n += 1
            preceding = [
                ts for ts in regime_by_device.get(row["device_id"], [])
                if row["timestamp"] - _HARD_STOP_FRESHNESS_SECONDS <= ts <= row["timestamp"]
            ]
            if preceding:
                hits += 1
                corroborated_regime_ts.update((row["device_id"], ts) for ts in preceding)

        total_regime_events = sum(len(v) for v in regime_by_device.values())
        uncorroborated = total_regime_events - len(corroborated_regime_ts)
        # Deliberately independent of whether OTHER regime_change events for this same
        # scope DID corroborate a real incident -- a substantial run of flags that
        # never once correlated with anything real is itself worth caution regardless
        # of whether the scope also has some genuine hits elsewhere.
        flapping = uncorroborated >= _BOCPD_FLAP_MIN_UNCORROBORATED

        return ({"regime_shift_detection": (hits, n)} if n else {}), flapping

    # --- global scope ---
    hits_totals, flapping = hits_totals_and_flapping(all_device_ids)
    current = engine.get_active_value(_BOCPD_HAZARD_PARAMETER, default=_BOCPD_HAZARD_DEFAULT)
    decision = _decide_scoped_change(
        current, bounds, direction, hits_totals,
        drift_at_scope=(_scope_has_drift(drift, _BOCPD_HAZARD_PARAMETER, None, None) or flapping),
        scope_label="global", run_id=run_id, allow_loosen=True,
    )
    if decision is not None:
        new_value, reason = decision
        result = engine.propose_change(_BOCPD_HAZARD_PARAMETER, new_value, reason=reason,
                                          backtest_run_id=run_id, now=now)
        results.append({"accepted": result.accepted, "change_id": result.change_id, "reason": result.reason,
                          "parameter": _BOCPD_HAZARD_PARAMETER, "proposed_new_value": new_value})

    # --- category scope ---
    for category, device_ids in by_category.items():
        hits_totals, flapping = hits_totals_and_flapping(device_ids)
        if not hits_totals:
            continue
        current = engine.get_active_value(_BOCPD_HAZARD_PARAMETER, device_type=category, default=_BOCPD_HAZARD_DEFAULT)
        decision = _decide_scoped_change(
            current, bounds, direction, hits_totals,
            drift_at_scope=(_scope_has_drift(drift, _BOCPD_HAZARD_PARAMETER, None, category) or flapping),
            scope_label=f"category:{category}", run_id=run_id, allow_loosen=True,
        )
        if decision is None:
            continue
        new_value, reason = decision
        result = engine.propose_change(_BOCPD_HAZARD_PARAMETER, new_value, reason=reason, device_type=category,
                                          backtest_run_id=run_id, now=now)
        results.append({"accepted": result.accepted, "change_id": result.change_id, "reason": result.reason,
                          "parameter": _BOCPD_HAZARD_PARAMETER, "proposed_new_value": new_value,
                          "device_type": category})

    # --- device scope ---
    for device_id in all_device_ids:
        hits_totals, flapping = hits_totals_and_flapping([device_id])
        if not hits_totals:
            continue
        device_type = device_type_of.get(device_id)
        current = engine.get_active_value(_BOCPD_HAZARD_PARAMETER, device_id=device_id, device_type=device_type,
                                             default=_BOCPD_HAZARD_DEFAULT)
        decision = _decide_scoped_change(
            current, bounds, direction, hits_totals,
            drift_at_scope=(_scope_has_drift(drift, _BOCPD_HAZARD_PARAMETER, device_id, None) or flapping),
            scope_label=f"device:{device_id}", run_id=run_id, allow_loosen=True,
        )
        if decision is None:
            continue
        new_value, reason = decision
        result = engine.propose_change(_BOCPD_HAZARD_PARAMETER, new_value, reason=reason, device_id=device_id,
                                          device_type=device_type, backtest_run_id=run_id, now=now)
        results.append({"accepted": result.accepted, "change_id": result.change_id, "reason": result.reason,
                          "parameter": _BOCPD_HAZARD_PARAMETER, "proposed_new_value": new_value,
                          "device_id": device_id})

    return results


def run_golden_set() -> Dict[str, Any]:
    """Runs the existing real-incident regression suite as a subprocess.
    Zero tolerance: any real-incident regression (non-zero exit) fails this
    check outright -- see this module's own docstring for why this isn't a
    refactored import."""
    if not _GOLDEN_SET_SCRIPT.exists():
        return {"ran": False, "passed": False, "detail": f"golden-set script not found at {_GOLDEN_SET_SCRIPT}"}
    try:
        result = subprocess.run(
            [sys.executable, str(_GOLDEN_SET_SCRIPT)],
            capture_output=True, text=True, timeout=_GOLDEN_SET_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        return {"ran": False, "passed": False, "detail": f"failed to run golden-set script: {exc}"}
    return {
        "ran": True, "passed": result.returncode == 0,
        "detail": "all checks passed" if result.returncode == 0 else result.stdout[-4000:],
    }


def run_synthetic_sweep(store: GraphStore, device_ids: List[str],
                          attack_floor: float = _DEFAULT_ATTACK_FLOOR,
                          max_devices: Optional[int] = None,
                          now: Optional[float] = None) -> Dict[str, Any]:
    """Synthetic sweep across a device sample -- the heavier, gracefully-
    degradable half of the backtest (Health & Degradation section of the
    plan: under resource pressure, callers pass a smaller `max_devices` or a
    pre-filtered `device_ids`, reducing COVERAGE, never changing this
    method's own pass/fail logic). Reports per-device detection_rate/
    false_positive plus overall pass/fail against `attack_floor`.

    Coverage is always recorded explicitly (devices_covered vs.
    devices_total) so a reduced-coverage pass is never silently treated as
    equivalent to a full sweep by a caller (the same principle already
    applied to Sheet 00's changepoint confirmation: a degraded check must
    not look as strong as a full one)."""
    sampled = device_ids[:max_devices] if max_devices is not None else list(device_ids)
    per_device: Dict[str, Any] = {}
    for device_id in sampled:
        try:
            per_device[device_id] = sweep(store, device_id, now=now)
        except Exception as exc:
            LOGGER.exception("Synthetic sweep failed for %s (recorded as an error, not skipped silently)", device_id)
            per_device[device_id] = {"error": str(exc)}

    valid = [r for r in per_device.values() if "detection_rate" in r]
    avg_detection = (sum(r["detection_rate"] for r in valid) / len(valid)) if valid else 0.0
    any_false_positive = any(r.get("false_positive") for r in valid)

    return {
        "devices_covered": sampled,
        "devices_total": len(device_ids),
        "coverage_fraction": (len(sampled) / len(device_ids)) if device_ids else 1.0,
        "per_device": per_device,
        "avg_detection_rate": avg_detection,
        "any_false_positive": any_false_positive,
        "passed": bool(valid) and avg_detection >= attack_floor and not any_false_positive,
    }


def run_backtest(store: GraphStore, device_ids: Optional[List[str]] = None,
                   max_devices: Optional[int] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """The full nightly backtest cycle: golden-set (zero tolerance) +
    synthetic sweep (gracefully degradable coverage). Persists to
    backtest_runs and returns the summary Sheet 03's autotuner (not yet
    built) gates on.

    Drift check (Sheet 00's posterior-trajectory drift check, this module's
    own former honest gap -- drift_result_json used to be written as an
    empty {} placeholder every run): v13.autotune.engine.compute_drift_result()
    flags a tunable parameter whose promoted changes trend monotonically
    toward "everything looks more benign" with no matching regime_change to
    explain it. Deliberately NOT folded into `overall_pass` -- a real,
    considered scope limit, not an oversight: drift is a slower-moving,
    op-review-worthy signal (does this device's tuning trajectory make
    sense in hindsight), not a fast pass/fail correctness gate the way the
    golden-set/synthetic checks are -- surfaced in drift_result_json for an
    operator (or a future, separate alerting hook) to act on."""
    now = now if now is not None else time.time()
    run_id = uuid.uuid4().hex
    started_at = now

    golden = run_golden_set()

    if device_ids is None:
        rows = store._conn.execute(
            "SELECT device_id FROM devices WHERE merged_into_device_id IS NULL",
        ).fetchall()
        device_ids = [r["device_id"] for r in rows]
    synthetic = run_synthetic_sweep(store, device_ids, max_devices=max_devices, now=now)
    drift = compute_drift_result(store, now=now)

    overall_pass = golden["passed"] and synthetic["passed"]

    store._conn.execute(
        "INSERT INTO backtest_runs "
        "(run_id, started_at, finished_at, golden_set_result_json, synthetic_result_json, "
        "drift_result_json, coverage_json, overall_pass) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, started_at, time.time(), json.dumps(golden), json.dumps(synthetic), json.dumps(drift),
         json.dumps({"devices_covered": len(synthetic["devices_covered"]), "devices_total": synthetic["devices_total"]}),
         1 if overall_pass else 0),
    )
    store._maybe_commit()

    # 2026-09-16, per-device/category autotuning plan §4 (user-requested: "a hit
    # should trigger an immediate autonomous rollback"): runs BEFORE any new
    # proposal/promotion this cycle, and deliberately OUTSIDE the `if
    # overall_pass:` gate below -- a real confirmed miss from an
    # ALREADY-PROMOTED override is worth rolling back even on a night tonight's
    # OWN synthetic backtest failed for some unrelated reason; the two checks
    # are about different things (tonight's synthetic pass/fail vs. a
    # previously-promoted override's real-world track record). Best-effort,
    # same "never take down the run" framing as every other trigger here.
    circuit_breaker_rollbacks: List[Dict[str, Any]] = []
    try:
        circuit_breaker_rollbacks = check_retroactive_misses_and_rollback(store, now=now)
    except Exception:
        LOGGER.exception("[AUTOTUNE_CIRCUIT_BREAKER] retroactive-miss check failed, non-fatal")
    # 2026-09-21 (legacy/Sheet 03a autotune reconciliation, Phase F): same protection,
    # extended to the two parameters legacy's write side now proposes through this
    # same AutotuneEngine infrastructure (see train_fp_classifier.py's
    # _propose_and_promote()) -- each check is independent and best-effort, same
    # framing as the one above.
    try:
        circuit_breaker_rollbacks += check_arp_sweep_retroactive_misses_and_rollback(store, now=now)
    except Exception:
        LOGGER.exception("[AUTOTUNE_CIRCUIT_BREAKER] arp_sweep retroactive-miss check failed, non-fatal")
    try:
        circuit_breaker_rollbacks += check_fp_combined_retroactive_misses_and_rollback(store, now=now)
    except Exception:
        LOGGER.exception("[AUTOTUNE_CIRCUIT_BREAKER] fp_combined retroactive-miss check failed, non-fatal")
    # 2026-09-27 (Phase 1 of the autonomy-completion effort): same protection for both
    # reputation floors, now that they have a real forward generator that can actually
    # promote a loosened scope. bocpd_hazard_rate deliberately has NO equivalent check
    # here -- it governs an entire changepoint-detection algorithm's dynamics, not a
    # single scalar value crossing a band, so the "near-miss value in [scope, parent)"
    # pattern every other check (including these two) relies on doesn't structurally
    # apply to it; its own protection is the ordinary canary/backtest-confirmation gate
    # plus this same generator re-evaluating (and proposing a tighten) every night a
    # delayed shift keeps recurring -- an honest scope limit, not an oversight.
    try:
        circuit_breaker_rollbacks += check_reputation_floor_retroactive_misses_and_rollback(
            store, _REPUTATION_SUSPICIOUS_PARAMETER, now=now)
    except Exception:
        LOGGER.exception("[AUTOTUNE_CIRCUIT_BREAKER] reputation_tier_suspicious_floor retroactive-miss check failed, non-fatal")
    try:
        circuit_breaker_rollbacks += check_reputation_floor_retroactive_misses_and_rollback(
            store, _REPUTATION_HIGH_PARAMETER, now=now)
    except Exception:
        LOGGER.exception("[AUTOTUNE_CIRCUIT_BREAKER] reputation_tier_high_floor retroactive-miss check failed, non-fatal")

    # Release 15 Sheet 03a (2026-09-15): the triggering logic that was the autotuner's
    # one genuine remaining gap -- see _propose_tuning_change()'s own docstring for
    # exactly what's scoped in/out and why. Gated on overall_pass: a failing backtest
    # run should never be the basis for a NEW tuning proposal, only golden/synthetic
    # regressions matter at that point. Best-effort -- a failure here must never take
    # down the backtest run itself, which has already committed its own row above.
    tuning_proposal = None
    scoped_tuning_proposals: List[Dict[str, Any]] = []
    tuning_promoted: List[str] = []
    if overall_pass:
        try:
            tuning_proposal = _propose_tuning_change(store, synthetic, drift, run_id, now)
        except Exception:
            LOGGER.exception("[AUTOTUNE_TRIGGER] tuning proposal evaluation failed, non-fatal")
        # 2026-09-16, per-device/category autotuning (Documentation/
        # PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md): layered ON TOP of the global
        # proposal above, never replacing it -- augments small categories with
        # repeat sweep passes, then evaluates every category and device scope
        # independently. Best-effort, same "never take down the run" framing.
        try:
            device_type_of = _device_type_lookup(store, synthetic["devices_covered"])
            all_trials = augment_small_category_sweeps(store, synthetic, device_type_of, now=now)
            scoped_tuning_proposals = _propose_scoped_tuning_changes(store, all_trials, drift, run_id, now)
        except Exception:
            LOGGER.exception("[AUTOTUNE_TRIGGER] scoped (per-device/category) tuning proposal evaluation failed, non-fatal")
        # 2026-09-27 (Phase 1 of the autonomy-completion effort): the two reputation
        # floors' own forward generator -- see _propose_reputation_floor_changes()'s
        # own docstring. Independent of the synthetic-sweep-driven proposals above
        # (different evidence source entirely), same best-effort framing.
        try:
            reputation_tuning_proposals = _propose_reputation_floor_changes(store, drift, run_id, now)
            scoped_tuning_proposals += reputation_tuning_proposals
        except Exception:
            LOGGER.exception("[AUTOTUNE_TRIGGER] reputation-floor tuning proposal evaluation failed, non-fatal")
        # 2026-09-27 (Phase 1 of the autonomy-completion effort): bocpd_hazard_rate's
        # own forward generator -- see _propose_bocpd_hazard_changes()'s own docstring.
        try:
            bocpd_tuning_proposals = _propose_bocpd_hazard_changes(store, drift, run_id, now)
            scoped_tuning_proposals += bocpd_tuning_proposals
        except Exception:
            LOGGER.exception("[AUTOTUNE_TRIGGER] bocpd_hazard_rate tuning proposal evaluation failed, non-fatal")
        try:
            tuning_promoted = _promote_eligible_tuning_changes(store, run_id, now)
        except Exception:
            LOGGER.exception("[AUTOTUNE_TRIGGER] promotion pass failed, non-fatal")

    # Release 15 heartbeat gap fix (2026-09-15): this job previously reported no
    # heartbeat at all -- a silently-stopped nightly backtest read as healthy
    # indefinitely. state_dir mirrors scheduler.py's own pattern (heartbeat file
    # lives next to the state the component actually touches); guarded since
    # store.db_path is the literal string ":memory:" in tests, which has no
    # meaningful parent directory.
    try:
        if store.db_path and store.db_path != ":memory:":
            write_component_heartbeat(
                Path(store.db_path).parent, "backtest_job",
                extra={"run_id": run_id, "overall_pass": overall_pass},
            )
    except Exception:
        LOGGER.exception("[HEARTBEAT] failed to write backtest_job heartbeat, non-fatal")

    return {"run_id": run_id, "golden_set": golden, "synthetic": synthetic, "drift": drift,
            "overall_pass": overall_pass, "tuning_proposal": tuning_proposal,
            "scoped_tuning_proposals": scoped_tuning_proposals,
            "tuning_promoted": tuning_promoted,
            "circuit_breaker_rollbacks": circuit_breaker_rollbacks}


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(description="Release 15 Sheet 02 nightly backtest")
    parser.add_argument("--db", default="state/v13_graph.db")
    parser.add_argument("--max-devices", type=int, default=None)
    args = parser.parse_args()

    store = GraphStore(args.db)
    result = run_backtest(store, max_devices=args.max_devices)
    LOGGER.info(
        "Backtest run %s: overall_pass=%s golden_set=%s synthetic_detection=%.2f coverage=%d/%d",
        result["run_id"], result["overall_pass"], result["golden_set"]["passed"],
        result["synthetic"]["avg_detection_rate"],
        len(result["synthetic"]["devices_covered"]), result["synthetic"]["devices_total"],
    )
    if result["drift"]["drift_detected"]:
        # Never gates overall_pass (see run_backtest()'s own docstring) --
        # logged at WARNING so it's visible to an operator without being a
        # scheduled-job failure.
        LOGGER.warning("Posterior-trajectory drift detected: %s", result["drift"]["findings"])
    if result["circuit_breaker_rollbacks"]:
        # Each individual rollback is already logged at CRITICAL as it happens
        # (check_retroactive_misses_and_rollback's own [AUTOTUNE_CIRCUIT_BREAKER]
        # line) -- this is the run-level summary, same CRITICAL level since a
        # real confirmed miss is a genuine, already-acted-on safety event, not
        # routine tuning activity.
        LOGGER.critical("[AUTOTUNE_CIRCUIT_BREAKER] %d scoped override(s) rolled back this run: %s",
                          len(result["circuit_breaker_rollbacks"]), result["circuit_breaker_rollbacks"])
    if result["tuning_proposal"]:
        LOGGER.info("[AUTOTUNE_TRIGGER] %s", result["tuning_proposal"])
    if result["scoped_tuning_proposals"]:
        LOGGER.info("[AUTOTUNE_TRIGGER] per-device/category: %s", result["scoped_tuning_proposals"])
    if result["tuning_promoted"]:
        LOGGER.info("[AUTOTUNE_TRIGGER] promoted: %s", result["tuning_promoted"])
    if not result["overall_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
