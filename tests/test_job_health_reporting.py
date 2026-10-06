"""
Scheduled-job reporting and the golden set in the image (2026-10-06, found on .94).

- backtest_job and population_prior_builder never wrote job_health.json, so the web UI showed "Not run yet" for jobs
  that ran every night.
- The Docker image had no tests/ directory, so the backtest's golden-set script was "not found" and every nightly
  backtest since the move to Docker failed its zero-tolerance gate (overall_pass = 0 on 6 of 6 nights), which also
  blocks the autotuner from proposing or promoting anything.

Run: python -m pytest tests/test_job_health_reporting.py   (or python tests/test_job_health_reporting.py)
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


# -- the golden set ships in the image ---------------------------------------------------------------------------------

def test_golden_set_script_is_copied_into_the_image():
    from argus.ops import backtest_job
    script = backtest_job._GOLDEN_SET_SCRIPT
    assert script.exists(), "the golden-set script must exist in the repository"
    rel = script.relative_to(ROOT).as_posix()                       # tests/test_real_world_alert_regression.py
    dockerfile = (ROOT / "docker" / "pipeline" / "Dockerfile").read_text(encoding="utf-8")
    assert f"COPY {rel} ./{rel}" in dockerfile                      # the engine and scheduler share this image
    lines = [l.strip() for l in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()]
    # "tests/" would exclude the whole directory and a later "!" cannot bring a file back from an excluded directory
    assert "tests/" not in lines and "tests/*" in lines and f"!{rel}" in lines
    assert lines.index("tests/*") < lines.index(f"!{rel}")


def test_golden_set_runs_and_passes_from_the_repository():
    from argus.ops.backtest_job import run_golden_set
    result = run_golden_set()
    assert result["ran"] and result["passed"], result["detail"]


# -- jobs record their result --------------------------------------------------------------------------------------------

def _health(tmp_path):
    return json.loads((tmp_path / "job_health.json").read_text(encoding="utf-8"))


def _backtest_result(overall, golden=True, synthetic=True):
    return {"run_id": "r1", "overall_pass": overall, "golden_set": {"passed": golden, "detail": "golden-set script not found"},
            "synthetic": {"passed": synthetic, "avg_detection_rate": 0.86, "devices_covered": ["a", "b"],
                          "devices_total": 2}, "drift": {"drift_detected": False, "findings": []},
            "circuit_breaker_rollbacks": [], "tuning_proposal": None, "scoped_tuning_proposals": [],
            "tuning_promoted": []}


def _run_backtest_main(monkeypatch, tmp_path, result=None, error=None):
    from argus.ops import backtest_job

    def fake_run(store, max_devices=None):
        if error:
            raise error
        return result
    monkeypatch.setattr(backtest_job, "run_backtest", fake_run)
    monkeypatch.setattr(sys, "argv", ["backtest_job.py", "--db", str(tmp_path / "v13_graph.db")])
    backtest_job.main()


def test_backtest_pass_is_recorded_as_a_success(monkeypatch, tmp_path):
    _run_backtest_main(monkeypatch, tmp_path, _backtest_result(True))
    entry = _health(tmp_path)["backtest_job"]
    assert entry["last_success"] and "last_failure" not in entry and entry["overall_pass"] is True


def test_backtest_failure_is_recorded_with_the_failed_gate_and_still_exits_1(monkeypatch, tmp_path):
    with pytest.raises(SystemExit) as exc:
        _run_backtest_main(monkeypatch, tmp_path, _backtest_result(False, golden=False))
    assert exc.value.code == 1
    entry = _health(tmp_path)["backtest_job"]
    assert entry["last_failure"] and "golden set" in entry["error"] and "autotuning is paused" in entry["error"]


def test_backtest_crash_is_recorded(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError):
        _run_backtest_main(monkeypatch, tmp_path, error=RuntimeError("boom"))
    assert "boom" in _health(tmp_path)["backtest_job"]["error"]


def _run_prior_main(monkeypatch, tmp_path, result=None, error=None):
    from argus.ops import population_prior_builder as ppb

    def fake_build(store):
        if error:
            raise error
        return result
    monkeypatch.setattr(ppb, "build_population_priors", fake_build)
    monkeypatch.setattr(sys, "argv", ["population_prior_builder.py", "--db", str(tmp_path / "v13_graph.db")])
    ppb.main()


_PRIORS = {"written": 5, "skipped_insufficient_contributors": 2, "removed_stale": 1, "failed": 0,
           "groups_considered": 8, "cohorts_computed": 3}


def test_population_builder_success_is_recorded(monkeypatch, tmp_path):
    _run_prior_main(monkeypatch, tmp_path, dict(_PRIORS))
    entry = _health(tmp_path)["population_prior_builder"]
    assert entry["last_success"] and entry["written"] == 5 and "last_failure" not in entry


def test_population_builder_failed_pools_are_recorded_and_exit_1(monkeypatch, tmp_path):
    with pytest.raises(SystemExit) as exc:
        _run_prior_main(monkeypatch, tmp_path, {**_PRIORS, "failed": 2})
    assert exc.value.code == 1
    assert "2 pool(s)" in _health(tmp_path)["population_prior_builder"]["error"]


def test_population_builder_crash_is_recorded(monkeypatch, tmp_path):
    with pytest.raises(ValueError):
        _run_prior_main(monkeypatch, tmp_path, error=ValueError("bad"))
    assert "bad" in _health(tmp_path)["population_prior_builder"]["error"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
