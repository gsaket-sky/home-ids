"""
Regression tests for the 2026-09-22 OOM crash-loop fix (fp_engine.py's
_weekly_retrain_loop() used to run the retrain IN-PROCESS, causing a 25+ hour crash
loop -- see git history for the full incident writeup) AND the follow-up
resource-aware scheduling work (Documentation/RESOURCE_AWARE_SCHEDULING.md): the
retrain now runs as a subprocess coordinated through core/job_coordinator.py's
shared mutex/priority/pause-resume protocol -- delaying its own start under system
pressure, yielding (SIGSTOP) to a higher-priority job and resuming afterward, and
self-throttling under sustained CRITICAL pressure even with nothing else competing
for the slot.
"""
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from intelligence import fp_engine as fp_engine_module  # noqa: E402
from core import job_coordinator  # noqa: E402
from core import resource_gate  # noqa: E402


class _StopLoop(Exception):
    """Sentinel used to break _weekly_retrain_loop()'s `while True` after one pass."""


class _FakeProc:
    """Stand-in for subprocess.Popen -- poll_sequence is consumed one value per
    .poll() call (None = still running, an int = exited with that code); the last
    value repeats once exhausted."""

    def __init__(self, pid=4242, poll_sequence=(None, 0)):
        self.pid = pid
        self._poll_sequence = list(poll_sequence)
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        if self._poll_sequence:
            val = self._poll_sequence.pop(0)
        else:
            val = self.returncode if self.returncode is not None else 0
        if val is not None:
            self.returncode = val
        return val

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


def _make_engine(tmp_path, config=None):
    engine = fp_engine_module.AutonomousFPEngine.__new__(fp_engine_module.AutonomousFPEngine)
    engine.config = config if config is not None else {}
    engine._state_dir = tmp_path
    return engine


def _run_one_hourly_iteration(monkeypatch, engine):
    """Drives _weekly_retrain_loop() through exactly one pass of its outer hourly
    check, without exercising the inner poll loop at all -- callers mock
    engine._run_weekly_retrain_subprocess directly for that."""
    sleep_calls = []

    def fake_sleep(seconds):
        sleep_calls.append(seconds)
        if len(sleep_calls) >= 2:
            raise _StopLoop()

    monkeypatch.setattr(fp_engine_module.time, "sleep", fake_sleep)
    with pytest.raises(_StopLoop):
        engine._weekly_retrain_loop()
    return sleep_calls


# ---------------------------------------------------------------------------------
# Outer loop: 7-day gate + persist-on-success / no-persist-on-failure
# ---------------------------------------------------------------------------------

def test_retrain_skipped_when_last_retrain_is_recent(tmp_path, monkeypatch):
    """If .last_retrain is fresh (< 7 days), the subprocess runner must not be
    invoked at all -- the interval gate itself is independent of everything below it."""
    engine = _make_engine(tmp_path)
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    (models_dir / ".last_retrain").write_text(str(time.time()))

    called = []
    monkeypatch.setattr(engine, "_run_weekly_retrain_subprocess", lambda: called.append(True) or True)

    _run_one_hourly_iteration(monkeypatch, engine)
    assert called == []


def test_successful_subprocess_run_persists_and_reloads(tmp_path, monkeypatch):
    engine = _make_engine(tmp_path)
    load_calls = []
    engine._load_lgbm_model = lambda: load_calls.append(True)
    monkeypatch.setattr(engine, "_run_weekly_retrain_subprocess", lambda: True)

    _run_one_hourly_iteration(monkeypatch, engine)

    assert (tmp_path / "models" / ".last_retrain").exists()
    assert load_calls == [True]


def test_failed_subprocess_run_does_not_persist_or_reload(tmp_path, monkeypatch):
    """A failed/denied/timed-out run must NOT write .last_retrain or hot-reload --
    otherwise it would be silently treated as done. The next hourly check (interval
    still >= 7 days) is the real retry mechanism."""
    engine = _make_engine(tmp_path)
    load_calls = []
    engine._load_lgbm_model = lambda: load_calls.append(True)
    monkeypatch.setattr(engine, "_run_weekly_retrain_subprocess", lambda: False)

    _run_one_hourly_iteration(monkeypatch, engine)

    assert not (tmp_path / "models" / ".last_retrain").exists()
    assert load_calls == []


# ---------------------------------------------------------------------------------
# _run_weekly_retrain_subprocess(): the actual coordinator-integrated launcher
# ---------------------------------------------------------------------------------

def _patch_common(monkeypatch, engine, proc_factory, *, may_admit=True, peek=True,
                   acquire_outcome=job_coordinator.GRANTED, owns_slot=True,
                   should_resume=False, pressure_tier=resource_gate.NORMAL):
    monkeypatch.setattr(fp_engine_module.subprocess, "Popen", lambda *a, **kw: proc_factory(kw))
    monkeypatch.setattr(fp_engine_module.resource_gate, "may_admit_new_job", lambda cfg: may_admit)
    monkeypatch.setattr(fp_engine_module.job_coordinator, "peek_admission", lambda sd, pr: peek)
    monkeypatch.setattr(fp_engine_module.job_coordinator, "acquire_or_preempt",
                         lambda sd, jn, pid, pr, pausable, mrm: acquire_outcome)
    monkeypatch.setattr(fp_engine_module.job_coordinator, "owns_slot", lambda sd, jn, pid: owns_slot)
    monkeypatch.setattr(fp_engine_module.job_coordinator, "should_resume", lambda sd, jn, pid: should_resume)
    monkeypatch.setattr(fp_engine_module.resource_gate, "get_job_pressure_tier", lambda cfg: pressure_tier)
    monkeypatch.setattr(fp_engine_module.time, "sleep", lambda s: None)  # don't actually block in tests
    calls = {"release": [], "pause": [], "resume": [], "mark_running": [], "mark_paused": []}
    monkeypatch.setattr(fp_engine_module.job_coordinator, "release", lambda sd, jn, pid: calls["release"].append(pid))
    monkeypatch.setattr(fp_engine_module.job_coordinator, "pause_process", lambda pid: calls["pause"].append(pid))
    monkeypatch.setattr(fp_engine_module.job_coordinator, "resume_process", lambda pid: calls["resume"].append(pid))
    monkeypatch.setattr(fp_engine_module.job_coordinator, "mark_running", lambda sd, jn, pid: calls["mark_running"].append(pid))
    monkeypatch.setattr(fp_engine_module.job_coordinator, "mark_paused", lambda sd, jn, pid: calls["mark_paused"].append(pid))
    return calls


def test_happy_path_launches_as_subprocess_and_reports_success(tmp_path, monkeypatch):
    engine = _make_engine(tmp_path)
    proc_holder = {}

    def proc_factory(kwargs):
        assert kwargs.get("start_new_session") is True  # orphan-prevention: own process group
        proc = _FakeProc(pid=4242, poll_sequence=(None, None, 0))
        proc_holder["proc"] = proc
        return proc

    calls = _patch_common(monkeypatch, engine, proc_factory)

    result = engine._run_weekly_retrain_subprocess()

    assert result is True
    assert calls["release"] == [4242]


def test_deferred_by_pressure_never_launches_subprocess(tmp_path, monkeypatch):
    engine = _make_engine(tmp_path)
    popen_calls = []
    monkeypatch.setattr(fp_engine_module.subprocess, "Popen", lambda *a, **kw: popen_calls.append(1))
    monkeypatch.setattr(fp_engine_module.resource_gate, "may_admit_new_job", lambda cfg: False)

    result = engine._run_weekly_retrain_subprocess()

    assert result is False
    assert popen_calls == []


def test_deferred_by_mutex_never_launches_subprocess(tmp_path, monkeypatch):
    engine = _make_engine(tmp_path)
    popen_calls = []
    monkeypatch.setattr(fp_engine_module.subprocess, "Popen", lambda *a, **kw: popen_calls.append(1))
    monkeypatch.setattr(fp_engine_module.resource_gate, "may_admit_new_job", lambda cfg: True)
    monkeypatch.setattr(fp_engine_module.job_coordinator, "peek_admission", lambda sd, pr: False)

    result = engine._run_weekly_retrain_subprocess()

    assert result is False
    assert popen_calls == []


def test_lost_claim_race_terminates_just_launched_subprocess(tmp_path, monkeypatch):
    """peek_admission() is only advisory -- if the real claim loses the race
    (acquire_or_preempt returns DENIED), the subprocess just launched must be
    stopped, not left running unowned outside the coordinator's view."""
    engine = _make_engine(tmp_path)
    proc = _FakeProc(pid=555, poll_sequence=(None,))

    calls = _patch_common(monkeypatch, engine, lambda kw: proc, acquire_outcome=job_coordinator.DENIED)

    result = engine._run_weekly_retrain_subprocess()

    assert result is False
    assert proc.terminated is True
    assert calls["release"] == []  # never owned the slot -- nothing to release


def test_preempted_mid_run_waits_then_resumes(tmp_path, monkeypatch):
    """Simulates a higher-priority job preempting this one mid-run (owns_slot()
    goes False, meaning someone else now holds the top-level slot), then being
    promoted back and told it's safe to resume."""
    engine = _make_engine(tmp_path)
    proc = _FakeProc(pid=777, poll_sequence=(None, None, None, 0))

    owns_slot_sequence = [False, False, True]  # preempted for 2 polls, then promoted back
    should_resume_sequence = [False, True]      # not yet safe, then safe

    def owns_slot_fn(sd, jn, pid):
        return owns_slot_sequence.pop(0) if owns_slot_sequence else True

    def should_resume_fn(sd, jn, pid):
        return should_resume_sequence.pop(0) if should_resume_sequence else False

    calls = _patch_common(
        monkeypatch, engine, lambda kw: proc,
        acquire_outcome=f"{job_coordinator.PREEMPTED_PREFIX}999",
    )
    monkeypatch.setattr(fp_engine_module.job_coordinator, "owns_slot", owns_slot_fn)
    monkeypatch.setattr(fp_engine_module.job_coordinator, "should_resume", should_resume_fn)

    result = engine._run_weekly_retrain_subprocess()

    assert result is True
    assert 999 in calls["pause"]           # the OLD lower-priority occupant was paused to admit us
    assert calls["resume"] == [777]        # WE resumed after being preempted ourselves
    assert calls["mark_running"] == [777]


def test_self_throttles_under_sustained_critical_pressure_then_resumes(tmp_path, monkeypatch):
    """No preemption from another job -- pauses itself once CRITICAL pressure
    sustains for 2 polls, then resumes itself once pressure drops back for 2 polls."""
    engine = _make_engine(tmp_path)
    proc = _FakeProc(pid=888, poll_sequence=(None, None, None, None, None, 0))

    tier_sequence = [
        resource_gate.NORMAL,
        resource_gate.CRITICAL, resource_gate.CRITICAL,   # 2 in a row -> self-pause
        resource_gate.NORMAL, resource_gate.NORMAL,        # 2 in a row -> self-resume
    ]

    def tier_fn(cfg):
        return tier_sequence.pop(0) if tier_sequence else resource_gate.NORMAL

    calls = _patch_common(monkeypatch, engine, lambda kw: proc)
    monkeypatch.setattr(fp_engine_module.resource_gate, "get_job_pressure_tier", tier_fn)

    result = engine._run_weekly_retrain_subprocess()

    assert result is True
    assert calls["pause"] == [888]
    assert calls["mark_paused"] == [888]
    assert calls["resume"] == [888]
    assert calls["mark_running"] == [888]


def test_exceeding_max_runtime_kills_and_reports_failure(tmp_path, monkeypatch):
    """The wall-clock budget is enforced on UNPAUSED elapsed time -- simulated here
    via a monotonic clock that jumps well past the configured budget on the very
    first poll."""
    engine = _make_engine(tmp_path, config={"autotune_max_runtime_minutes": 1})
    proc = _FakeProc(pid=999, poll_sequence=(None, None))

    calls = _patch_common(monkeypatch, engine, lambda kw: proc)

    mono_values = iter([0.0, 1000.0, 1000.0])  # first tick establishes baseline, second blows the 1-min budget
    monkeypatch.setattr(fp_engine_module.time, "monotonic", lambda: next(mono_values, 1000.0))

    result = engine._run_weekly_retrain_subprocess()

    assert result is False
    assert proc.killed is True
    assert calls["release"] == [999]
