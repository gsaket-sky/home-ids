"""
Tests for core/job_coordinator.py -- the shared mutex/priority/pause-resume/orphan-
reconciliation coordinator every scheduled subprocess job (scripts/scheduler.py's
cron jobs and fp_engine.py's weekly retrain) goes through before launching.
Documentation/RESOURCE_AWARE_SCHEDULING.md has the full design rationale.

Uses REAL short-lived subprocesses (python -c "...") for liveness checks -- pid
liveness is the one thing that can't be meaningfully faked without either mocking
os.kill everywhere (which would stop testing the actual stale-pid self-healing this
module exists for) or forking a real process. SIGSTOP/SIGCONT themselves are POSIX-
only and skipped on Windows (the real deployment target, .94, is Linux) -- the
priority/mutex/preemption-bookkeeping logic under test here is itself platform-
independent and always runs.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core import job_coordinator  # noqa: E402

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="SIGSTOP/SIGCONT/killpg are POSIX-only; .94 (the real deployment target) is Linux")


def _spawn_sleeper(seconds=30):
    return subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({seconds})"])


def test_empty_slot_grants_immediately(tmp_path):
    proc = _spawn_sleeper()
    try:
        outcome = job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc.pid, 2, True, 30)
        assert outcome == job_coordinator.GRANTED
        slot = json.loads((tmp_path / job_coordinator.LOCK_FILENAME).read_text())
        assert slot["job"] == "jobA" and slot["pid"] == proc.pid
    finally:
        proc.terminate()
        proc.wait()


def test_lower_priority_requester_is_denied(tmp_path):
    proc_a = _spawn_sleeper()
    try:
        job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc_a.pid, 2, True, 30)
        outcome = job_coordinator.acquire_or_preempt(tmp_path, "jobB", 99999999, 5, True, 30)
        assert outcome == job_coordinator.DENIED
    finally:
        proc_a.terminate()
        proc_a.wait()


def test_equal_priority_requester_is_denied(tmp_path):
    proc_a = _spawn_sleeper()
    try:
        job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc_a.pid, 3, True, 30)
        outcome = job_coordinator.acquire_or_preempt(tmp_path, "jobB", 99999999, 3, True, 30)
        assert outcome == job_coordinator.DENIED
    finally:
        proc_a.terminate()
        proc_a.wait()


def test_higher_priority_preempts_pausable_occupant(tmp_path):
    proc_a = _spawn_sleeper()
    proc_c = _spawn_sleeper()
    try:
        job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc_a.pid, 2, True, 30)
        outcome = job_coordinator.acquire_or_preempt(tmp_path, "jobC", proc_c.pid, 1, True, 30)
        assert outcome == f"{job_coordinator.PREEMPTED_PREFIX}{proc_a.pid}"
        slot = json.loads((tmp_path / job_coordinator.LOCK_FILENAME).read_text())
        assert slot["job"] == "jobC" and slot["pid"] == proc_c.pid
        assert slot["preempted"]["job"] == "jobA" and slot["preempted"]["pid"] == proc_a.pid
    finally:
        proc_a.terminate(); proc_a.wait()
        proc_c.terminate(); proc_c.wait()


def test_higher_priority_cannot_preempt_non_pausable_occupant(tmp_path):
    proc_a = _spawn_sleeper()
    try:
        job_coordinator.acquire_or_preempt(tmp_path, "live_prune", proc_a.pid, 1, False, 30)
        outcome = job_coordinator.acquire_or_preempt(tmp_path, "jobC", 99999999, 0, True, 30)
        assert outcome == job_coordinator.DENIED
    finally:
        proc_a.terminate()
        proc_a.wait()


def test_no_double_stacking_of_preempted_jobs(tmp_path):
    """At most one job may be parked underneath the active occupant -- a second
    preemption attempt while one is already parked must be denied, not stacked."""
    proc_a = _spawn_sleeper()
    proc_c = _spawn_sleeper()
    try:
        job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc_a.pid, 2, True, 30)
        job_coordinator.acquire_or_preempt(tmp_path, "jobC", proc_c.pid, 1, True, 30)
        outcome = job_coordinator.acquire_or_preempt(tmp_path, "jobD", 99999999, 0, True, 30)
        assert outcome == job_coordinator.DENIED
    finally:
        proc_a.terminate(); proc_a.wait()
        proc_c.terminate(); proc_c.wait()


@POSIX_ONLY  # os.kill(pid, 0) doesn't reliably detect death on Windows (confirmed:
             # it succeeds even against an already-exited process there) -- correct
             # POSIX semantics (ProcessLookupError) are what is_pid_alive() relies on,
             # and .94 (the real deployment target) is Linux.
def test_dead_pid_self_heals_to_empty_slot(tmp_path):
    """The actual correctness guarantee: a slot referencing a PID that's no longer
    alive (finished, crashed, or OOM-killed without ever calling release()) reads
    back as empty on the very next check -- from ANY process, not dependent on the
    original owner's own cleanup ever running."""
    proc = _spawn_sleeper(seconds=1)
    job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc.pid, 2, True, 30)
    proc.wait()  # let it actually finish and become a dead pid
    time.sleep(0.2)
    assert job_coordinator.peek_admission(tmp_path, 5) is True
    outcome = job_coordinator.acquire_or_preempt(tmp_path, "jobB", 99999999, 5, True, 30)
    assert outcome == job_coordinator.GRANTED


@POSIX_ONLY  # relies on the same os.kill(pid, 0) death-detection as above
def test_dead_active_occupant_promotes_paused_job_underneath(tmp_path):
    """If the ACTIVE occupant dies without calling release() (crash/OOM), a job
    parked underneath it must be promoted back to the top-level slot, marked
    'paused', on the very next read -- this is release()'s real safety net, proven
    here by never calling release() at all."""
    proc_a = _spawn_sleeper()
    proc_c = _spawn_sleeper(seconds=1)
    try:
        job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc_a.pid, 2, True, 30)
        job_coordinator.acquire_or_preempt(tmp_path, "jobC", proc_c.pid, 1, True, 30)
        proc_c.wait()  # jobC dies WITHOUT ever calling release()
        time.sleep(0.2)

        assert job_coordinator.owns_slot(tmp_path, "jobA", proc_a.pid) is True
        assert job_coordinator.should_resume(tmp_path, "jobA", proc_a.pid) is True
        slot = json.loads((tmp_path / job_coordinator.LOCK_FILENAME).read_text())
        assert slot["state"] == "paused"
    finally:
        proc_a.terminate()
        proc_a.wait()


def test_release_promotes_paused_job_and_mark_running_flips_state(tmp_path):
    proc_a = _spawn_sleeper()
    proc_c = _spawn_sleeper(seconds=1)
    try:
        job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc_a.pid, 2, True, 30)
        job_coordinator.acquire_or_preempt(tmp_path, "jobC", proc_c.pid, 1, True, 30)
        assert job_coordinator.owns_slot(tmp_path, "jobA", proc_a.pid) is False

        proc_c.wait()
        job_coordinator.release(tmp_path, "jobC", proc_c.pid)

        assert job_coordinator.should_resume(tmp_path, "jobA", proc_a.pid) is True
        job_coordinator.mark_running(tmp_path, "jobA", proc_a.pid)
        slot = json.loads((tmp_path / job_coordinator.LOCK_FILENAME).read_text())
        assert slot["job"] == "jobA" and slot["state"] == "running"
    finally:
        proc_a.terminate()
        proc_a.wait()


def test_release_with_no_preempted_job_clears_slot(tmp_path):
    proc = _spawn_sleeper()
    job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc.pid, 2, True, 30)
    proc.terminate()
    proc.wait()
    job_coordinator.release(tmp_path, "jobA", proc.pid)
    assert not (tmp_path / job_coordinator.LOCK_FILENAME).exists()


def test_corrupt_lock_file_reads_as_empty(tmp_path):
    (tmp_path / job_coordinator.LOCK_FILENAME).write_text("{not valid json")
    assert job_coordinator.peek_admission(tmp_path, 5) is True
    outcome = job_coordinator.acquire_or_preempt(tmp_path, "jobA", 99999999, 5, True, 30)
    assert outcome == job_coordinator.GRANTED


def test_lock_file_write_is_atomic_temp_then_replace(tmp_path, monkeypatch):
    """Assert the actual crash-safety mechanism is used -- os.replace() is an OS-level
    atomic rename; this test confirms the code path takes it, not that a torn write
    is literally impossible to observe (that's the OS's own guarantee)."""
    proc = _spawn_sleeper()
    try:
        replaced = []
        import os as os_module
        real_replace = os_module.replace

        def spy_replace(src, dst):
            assert str(src).endswith(".tmp")
            replaced.append((str(src), str(dst)))
            return real_replace(src, dst)

        monkeypatch.setattr(job_coordinator.os, "replace", spy_replace)
        job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc.pid, 2, True, 30)
        assert replaced, "expected the lock file write to go through a temp-file + os.replace()"
    finally:
        proc.terminate()
        proc.wait()


def test_stale_claim_sentinel_is_recovered(tmp_path):
    """A claim sentinel left behind by a dead claimant (crashed mid-claim) must be
    recognized as stale and cleared, not wedge every future acquire forever."""
    claim_path = tmp_path / job_coordinator.CLAIM_FILENAME
    claim_path.write_text(json.dumps({"pid": 99999999, "ts": time.time()}))
    proc = _spawn_sleeper()
    try:
        outcome = job_coordinator.acquire_or_preempt(tmp_path, "jobA", proc.pid, 2, True, 30)
        assert outcome == job_coordinator.GRANTED
    finally:
        proc.terminate()
        proc.wait()


@POSIX_ONLY
def test_reconcile_reclaims_orphan_past_its_own_budget(tmp_path):
    """A slot occupant that's still alive but has outlived its own recorded
    max_runtime_minutes (a genuinely stuck orphan, or one that survived a restart of
    whichever process launched it) must be killed and the slot cleared -- the actual
    starvation backstop, safe because it never requires bypassing the mutex."""
    proc = _spawn_sleeper(seconds=60)
    try:
        job_coordinator._atomic_write_json(tmp_path / job_coordinator.LOCK_FILENAME, {
            "job": "stuck_job", "pid": proc.pid, "priority": 1, "pausable": False,
            "state": "running", "started_at": time.time() - 3600, "paused_at": None,
            "max_runtime_minutes": 5,
        })
        job_coordinator.reconcile_on_boot(tmp_path)
        time.sleep(0.3)
        assert job_coordinator.is_pid_alive(proc.pid) is False
        assert not (tmp_path / job_coordinator.LOCK_FILENAME).exists()
    finally:
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.terminate()
            proc.wait()


def test_reconcile_leaves_job_within_budget_alone(tmp_path):
    proc = _spawn_sleeper()
    try:
        job_coordinator._atomic_write_json(tmp_path / job_coordinator.LOCK_FILENAME, {
            "job": "jobA", "pid": proc.pid, "priority": 1, "pausable": False,
            "state": "running", "started_at": time.time(), "paused_at": None,
            "max_runtime_minutes": 30,
        })
        job_coordinator.reconcile_on_boot(tmp_path)
        assert job_coordinator.is_pid_alive(proc.pid) is True
        slot = json.loads((tmp_path / job_coordinator.LOCK_FILENAME).read_text())
        assert slot["job"] == "jobA"
    finally:
        proc.terminate()
        proc.wait()
