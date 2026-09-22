"""
Regression test for the 2026-09-22 OOM crash-loop: fp_engine.py's
_weekly_retrain_loop() used to import train_and_export_onnx() and call it
IN-PROCESS, on the same background thread as the live detection engine. Loading
the full alerts.json (hundreds of MB) via json.loads() and training LightGBM
inside that process routinely spiked memory past the cgroup's hard MemoryMax
faster than health_manager's debounced self-heal could react (CRITICAL
pressure must sustain 3x15s checks before it proactively restarts), so the
kernel's OOM-killer SIGKILLed the whole engine -- instantly, before
.last_retrain could ever be written. That meant the very next restart
re-triggered the identical retrain 2 minutes later, forever. Confirmed live on
.94: this ran in a continuous crash loop for 25+ straight hours (Sep 21 12:16 -
Sep 22 13:11) before being caught.

Fix: the trainer now runs as a real subprocess -- exactly how the scheduler's
daily 3am cron already invokes this same script's main() -- isolating the
memory spike in its own address space. A worst-case OOM there kills only the
trainer, not the live engine.
"""
import subprocess
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from intelligence import fp_engine as fp_engine_module  # noqa: E402


class _StopLoop(Exception):
    """Sentinel used to break _weekly_retrain_loop()'s `while True` after one pass."""


def _make_engine(tmp_path):
    engine = fp_engine_module.AutonomousFPEngine.__new__(fp_engine_module.AutonomousFPEngine)
    engine.config = {}
    engine._state_dir = tmp_path
    return engine


def _run_one_iteration(monkeypatch, engine):
    sleep_calls = []

    def fake_sleep(seconds):
        sleep_calls.append(seconds)
        if len(sleep_calls) >= 2:
            raise _StopLoop()

    monkeypatch.setattr(fp_engine_module.time, "sleep", fake_sleep)
    with pytest.raises(_StopLoop):
        engine._weekly_retrain_loop()
    return sleep_calls


def test_retrain_launches_trainer_as_subprocess_not_in_process(tmp_path, monkeypatch):
    """The trainer must be launched via subprocess.run(), never imported and
    called directly on this thread -- that in-process call is exactly what let a
    training-memory spike take the whole live engine down with it."""
    engine = _make_engine(tmp_path)
    load_calls = []
    engine._load_lgbm_model = lambda: load_calls.append(True)

    captured = {}

    def fake_run(cmd, timeout=None, capture_output=None, text=None):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(fp_engine_module.subprocess, "run", fake_run)

    _run_one_iteration(monkeypatch, engine)

    assert captured["cmd"][0] == sys.executable
    assert captured["cmd"][1].endswith("train_fp_classifier.py")
    assert captured["timeout"] and captured["timeout"] > 0

    last_retrain_file = tmp_path / "models" / ".last_retrain"
    assert last_retrain_file.exists()
    assert load_calls == [True]


def test_failed_trainer_subprocess_does_not_mark_retrain_done(tmp_path, monkeypatch):
    """A non-zero exit code must NOT write .last_retrain or hot-reload the model
    -- otherwise a failed retrain would be silently treated as done. The next
    boot's interval check (still >= 7 days) is the real retry mechanism."""
    engine = _make_engine(tmp_path)
    load_calls = []
    engine._load_lgbm_model = lambda: load_calls.append(True)

    def fake_run(cmd, timeout=None, capture_output=None, text=None):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(fp_engine_module.subprocess, "run", fake_run)

    _run_one_iteration(monkeypatch, engine)

    last_retrain_file = tmp_path / "models" / ".last_retrain"
    assert not last_retrain_file.exists()
    assert load_calls == []


def test_retrain_skipped_when_last_retrain_is_recent(tmp_path, monkeypatch):
    """If .last_retrain is fresh (< 7 days), the trainer must not be launched at
    all -- proves the interval gate still works, independent of the
    subprocess-vs-in-process change."""
    engine = _make_engine(tmp_path)
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    (models_dir / ".last_retrain").write_text(str(time.time()))

    called = []
    monkeypatch.setattr(fp_engine_module.subprocess, "run", lambda *a, **kw: called.append(True))

    _run_one_iteration(monkeypatch, engine)

    assert called == []
