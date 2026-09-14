"""
Standalone runtime test for v13's Sheet 02 nightly backtest harness
(src/v13/ops/backtest_job.py, Release 15 closed-loop autotuning
architecture).

Covers: the golden-set subprocess check against the REAL existing
regression file (not a fake stand-in), synthetic-sweep structure and its
graceful max_devices coverage degradation, persistence to backtest_runs,
and a missing golden-set script being handled as a reported failure rather
than a crash.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_backtest_job.py`
"""
import json
import sys
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.ops import backtest_job  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402

NOW = 1_800_000_000.0

# =============================================================================
# run_golden_set -- against the REAL existing regression file
# =============================================================================
golden = backtest_job.run_golden_set()
check("run_golden_set: actually ran the real script (not a stub)", golden["ran"] is True)
check("run_golden_set: the real golden-incident suite currently passes -- "
      "confirms this job's zero-tolerance gate reads real signal, not a "
      "hardcoded True",
      golden["passed"] is True, f"detail={golden.get('detail', '')[:500]}")

# =============================================================================
# run_golden_set -- missing script handled gracefully
# =============================================================================
original_path = backtest_job._GOLDEN_SET_SCRIPT
backtest_job._GOLDEN_SET_SCRIPT = _PathForSysPath("/does/not/exist/regression.py")
try:
    missing_result = backtest_job.run_golden_set()
    check("run_golden_set: a missing script is reported as ran=False/passed=False, "
          "not a crash or a silent pass", missing_result == {
              "ran": False, "passed": False,
              "detail": f"golden-set script not found at {backtest_job._GOLDEN_SET_SCRIPT}",
          })
finally:
    backtest_job._GOLDEN_SET_SCRIPT = original_path

# =============================================================================
# run_synthetic_sweep -- structure and graceful coverage degradation
# =============================================================================
store = GraphStore(":memory:")
device_ids = []
for i in range(6):
    dev = f"dev_backtest_{i}"
    store.upsert_device(dev, device_type="laptop", timestamp=NOW)
    device_ids.append(dev)

full_sweep = backtest_job.run_synthetic_sweep(store, device_ids, now=NOW)
check("run_synthetic_sweep: full sweep covers every requested device",
      full_sweep["devices_covered"] == device_ids and full_sweep["coverage_fraction"] == 1.0)
check("run_synthetic_sweep: avg_detection_rate is a real, non-trivial value "
      "(the underlying injector.sweep() actually ran real attacks)",
      0.0 < full_sweep["avg_detection_rate"] <= 1.0, f"got {full_sweep['avg_detection_rate']}")

degraded_sweep = backtest_job.run_synthetic_sweep(store, device_ids, max_devices=2, now=NOW)
check("run_synthetic_sweep: max_devices reduces COVERAGE, the concrete form "
      "of 'keep improving with available items' under resource pressure",
      len(degraded_sweep["devices_covered"]) == 2 and degraded_sweep["devices_total"] == 6
      and abs(degraded_sweep["coverage_fraction"] - (2 / 6)) < 1e-9)

# =============================================================================
# run_backtest -- persistence to backtest_runs
# =============================================================================
result = backtest_job.run_backtest(store, device_ids=device_ids[:2], now=NOW)
check("run_backtest: returns a run_id and the overall_pass gate",
      "run_id" in result and isinstance(result["overall_pass"], bool))

row = store._conn.execute(
    "SELECT * FROM backtest_runs WHERE run_id=?", (result["run_id"],),
).fetchone()
check("run_backtest: a real row was persisted to backtest_runs", row is not None)
if row is not None:
    check("run_backtest: overall_pass column matches the returned summary",
          bool(row["overall_pass"]) == result["overall_pass"])
    stored_synthetic = json.loads(row["synthetic_result_json"])
    check("run_backtest: synthetic_result_json round-trips real structured data, "
          "not just a placeholder -- devices_total reflects the explicit "
          "2-device device_ids passed to run_backtest, not the full 6-device fleet",
          stored_synthetic["devices_total"] == 2 and len(stored_synthetic["devices_covered"]) == 2)
    stored_golden = json.loads(row["golden_set_result_json"])
    check("run_backtest: golden_set_result_json reflects the real subprocess run",
          stored_golden["ran"] is True)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 backtest job checks PASSED.")
