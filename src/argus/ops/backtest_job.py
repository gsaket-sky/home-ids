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

from argus.autotune.engine import compute_drift_result  # noqa: E402
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

    return {"run_id": run_id, "golden_set": golden, "synthetic": synthetic, "drift": drift, "overall_pass": overall_pass}


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
    if not result["overall_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
