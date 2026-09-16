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
# Scoped to hard_stop_candidate_sensitivity ONLY, deliberately, not all four
# TUNABLE_PARAMETERS: it's the one parameter with a real, grounded signal in this
# run's own synthetic-sweep data (a per-class detection rate). The other three
# (reputation_tier_suspicious_floor/high_floor, bocpd_hazard_rate) have no
# comparable signal here -- the synthetic attack generators are behavioral, not
# reputation/IOC-based, so they don't stress the reputation-tier floors at all;
# bocpd_hazard_rate in particular has ZERO live consumer on .94 today
# (BaselineEngine, Release 15 Sheet 00, only runs on the out-of-scope .19 shadow
# host, confirmed this session) -- proposing changes to it would be motion with no
# real effect. Left genuinely untriggered because there's no sound signal to act
# on, not silently deferred out of caution -- see ARGUS_DECISIONS.md.
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
    """device_id -> device_type (or None) for the given devices, one query."""
    if not device_ids:
        return {}
    placeholders = ",".join("?" * len(device_ids))
    rows = store._conn.execute(
        f"SELECT device_id, device_type FROM devices WHERE device_id IN ({placeholders})",
        device_ids,
    ).fetchall()
    return {r["device_id"]: r["device_type"] for r in rows}


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
            "tuning_promoted": tuning_promoted}


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
