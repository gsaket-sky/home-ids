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


def _spawn_sleeper(seconds=30, own_session=False):
    """own_session=True mirrors how scheduler.py really launches jobs
    (start_new_session=True). REQUIRED for anything reconcile_on_boot() may reclaim:
    it kills the victim's whole process group, which -- without a session of its own --
    is the test runner's group (found running this suite on Linux for the first time:
    pytest itself was SIGKILLed)."""
    return subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({seconds})"],
                            start_new_session=own_session)


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
    proc = _spawn_sleeper(seconds=60, own_session=True)
    try:
        job_coordinator._atomic_write_json(tmp_path / job_coordinator.LOCK_FILENAME, {
            "job": "stuck_job", "pid": proc.pid, "priority": 1, "pausable": False,
            "state": "running", "started_at": time.time() - 3600, "paused_at": None,
            "max_runtime_minutes": 5,
        })
        job_coordinator.reconcile_on_boot(tmp_path)
        # wait() (reap) rather than sleep + is_pid_alive(): on Linux a killed child stays
        # a zombie until its parent reaps it, and os.kill(pid, 0) succeeds on a zombie.
        assert proc.wait(timeout=5) == -9
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


# ---------------------------------------------------------------------------
# 2026-09-23 (live incident): live_llm_review/train_fp_classifier were reclaimed on
# every run -- paused time was charged against the budget, a promoted job inherited its
# preemptor's clock, and a reclaim silently dropped the job parked underneath.
# ---------------------------------------------------------------------------

def test_active_minutes_excludes_closed_and_open_paused_intervals():
    now = 10_000.0
    running = {"started_at": now - 600, "paused_seconds": 120.0, "state": "running"}
    assert job_coordinator.active_minutes(running, now) == pytest.approx(8.0)
    paused = {"started_at": now - 600, "paused_seconds": 120.0, "state": "paused", "paused_at": now - 180}
    assert job_coordinator.active_minutes(paused, now) == pytest.approx(5.0)


def test_mark_running_accumulates_paused_interval(tmp_path):
    proc = _spawn_sleeper()
    try:
        job_coordinator._atomic_write_json(tmp_path / job_coordinator.LOCK_FILENAME, {
            "job": "jobA", "pid": proc.pid, "priority": 3, "pausable": True,
            "state": "paused", "started_at": time.time() - 600, "paused_at": time.time() - 300,
            "paused_seconds": 60.0, "max_runtime_minutes": 30,
        })
        job_coordinator.mark_running(tmp_path, "jobA", proc.pid)
        slot = json.loads((tmp_path / job_coordinator.LOCK_FILENAME).read_text())
        assert slot["state"] == "running" and slot["paused_at"] is None
        assert slot["paused_seconds"] == pytest.approx(360.0, abs=5)
    finally:
        proc.terminate()
        proc.wait()


def test_paused_time_does_not_burn_the_budget(tmp_path):
    """40 min wall, 35 of them paused, 30 min budget: only 5 active minutes -- must not be reclaimed."""
    proc = _spawn_sleeper()
    try:
        now = time.time()
        job_coordinator._atomic_write_json(tmp_path / job_coordinator.LOCK_FILENAME, {
            "job": "jobA", "pid": proc.pid, "priority": 4, "pausable": True,
            "state": "paused", "started_at": now - 40 * 60, "paused_at": now - 35 * 60,
            "paused_seconds": 0.0, "max_runtime_minutes": 30,
        })
        job_coordinator.reconcile_on_boot(tmp_path)
        assert job_coordinator.is_pid_alive(proc.pid) is True
        assert json.loads((tmp_path / job_coordinator.LOCK_FILENAME).read_text())["job"] == "jobA"
    finally:
        proc.terminate()
        proc.wait()


@POSIX_ONLY
def test_preempted_job_keeps_its_own_clock_when_promoted(tmp_path):
    proc_a = _spawn_sleeper()
    proc_b = _spawn_sleeper(seconds=1)
    try:
        own_start = time.time() - 900
        job_coordinator._atomic_write_json(tmp_path / job_coordinator.LOCK_FILENAME, {
            "job": "low", "pid": proc_a.pid, "priority": 4, "pausable": True,
            "state": "running", "started_at": own_start, "paused_at": None,
            "paused_seconds": 30.0, "max_runtime_minutes": 30,
        })
        outcome = job_coordinator.acquire_or_preempt(tmp_path, "high", proc_b.pid, 1, False, 30)
        assert outcome.startswith(job_coordinator.PREEMPTED_PREFIX)
        proc_b.wait()  # preemptor finishes -> the parked job is promoted on next read
        slot = job_coordinator._read_slot(tmp_path)
        assert slot["job"] == "low" and slot["state"] == "paused"
        assert slot["started_at"] == pytest.approx(own_start)
        assert slot["paused_seconds"] == pytest.approx(30.0)
    finally:
        proc_a.terminate()
        proc_a.wait()


@POSIX_ONLY
def test_wall_clock_cap_reclaims_a_job_parked_forever(tmp_path):
    proc = _spawn_sleeper(seconds=60, own_session=True)
    try:
        now = time.time()
        job_coordinator._atomic_write_json(tmp_path / job_coordinator.LOCK_FILENAME, {
            "job": "parked", "pid": proc.pid, "priority": 4, "pausable": True,
            "state": "paused", "started_at": now - 100 * 60, "paused_at": now - 99 * 60,
            "paused_seconds": 0.0, "max_runtime_minutes": 30,
        })
        job_coordinator.reconcile_on_boot(tmp_path)
        proc.wait(timeout=5)
        assert not (tmp_path / job_coordinator.LOCK_FILENAME).exists()
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()


@POSIX_ONLY
def test_reclaim_promotes_parked_job_and_reports_the_kill(tmp_path):
    stuck = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    parked = _spawn_sleeper()
    try:
        now = time.time()
        job_coordinator._atomic_write_json(tmp_path / job_coordinator.LOCK_FILENAME, {
            "job": "stuck", "pid": stuck.pid, "priority": 1, "pausable": False,
            "state": "running", "started_at": now - 3600, "paused_at": None,
            "max_runtime_minutes": 5,
            "preempted": {"job": "parked", "pid": parked.pid, "priority": 4, "pausable": True,
                          "max_runtime_minutes": 30, "started_at": now - 4000,
                          "paused_seconds": 0.0, "paused_at": now - 3600},
        })
        reclaimed = job_coordinator.reconcile_on_boot(tmp_path)
        stuck.wait(timeout=5)
        slot = json.loads((tmp_path / job_coordinator.LOCK_FILENAME).read_text())
        assert slot["job"] == "parked" and slot["state"] == "paused"
        assert reclaimed["job"] == "stuck" and reclaimed["budget_minutes"] == 5
        assert reclaimed["active_minutes"] > 5
    finally:
        for p in (stuck, parked):
            if p.poll() is None:
                p.terminate()
                p.wait()


# --- persisted starvation-backstop clock (2026-09-28 root-cause fix) -----------
# live_prune (one cron slot/day) was silently deferred every night for a week
# because the old in-memory `pending_since` dict in scheduler.py got wiped on
# every soc.service restart, before its clock could ever reach the 60-minute
# backstop. These functions move that clock into disk-persisted state so it
# survives a scheduler.py restart.

def test_deferral_start_is_recorded_and_persists_across_a_fresh_read(tmp_path):
    first_seen = job_coordinator.record_deferral_start(tmp_path, "live_prune")
    assert (tmp_path / job_coordinator.PENDING_FILENAME).exists()
    # A second call (simulating the next scheduler tick, or a brand-new process
    # after a restart reading the same state_dir) must NOT reset the clock.
    second_seen = job_coordinator.record_deferral_start(tmp_path, "live_prune")
    assert second_seen == first_seen


def test_get_deferred_minutes_reflects_elapsed_time_since_first_seen(tmp_path):
    ninety_minutes_ago = time.time() - 90 * 60
    job_coordinator._atomic_write_json(
        tmp_path / job_coordinator.PENDING_FILENAME, {"live_prune": ninety_minutes_ago}
    )
    minutes = job_coordinator.get_deferred_minutes(tmp_path, "live_prune")
    assert 89.0 <= minutes <= 91.0


def test_get_deferred_minutes_is_zero_for_a_job_never_recorded(tmp_path):
    assert job_coordinator.get_deferred_minutes(tmp_path, "never_seen") == 0.0


def test_clear_deferral_resets_the_clock_for_next_time(tmp_path):
    job_coordinator.record_deferral_start(tmp_path, "live_prune")
    job_coordinator.clear_deferral(tmp_path, "live_prune")
    assert job_coordinator.get_deferred_minutes(tmp_path, "live_prune") == 0.0
    # A subsequent deferral starts a brand-new clock, not the old one.
    restarted = job_coordinator.record_deferral_start(tmp_path, "live_prune")
    assert time.time() - restarted < 1.0


def test_deferral_clock_for_one_job_does_not_affect_another(tmp_path):
    job_coordinator._atomic_write_json(
        tmp_path / job_coordinator.PENDING_FILENAME,
        {"live_prune": time.time() - 3600},
    )
    job_coordinator.record_deferral_start(tmp_path, "top_domains_report")
    assert job_coordinator.get_deferred_minutes(tmp_path, "live_prune") >= 59.0
    assert job_coordinator.get_deferred_minutes(tmp_path, "top_domains_report") < 1.0


def test_corrupt_pending_file_self_heals_instead_of_crashing(tmp_path):
    (tmp_path / job_coordinator.PENDING_FILENAME).write_text("{not valid json", encoding="utf-8")
    assert job_coordinator.get_deferred_minutes(tmp_path, "live_prune") == 0.0
    # record_deferral_start must recover (treat corrupt as empty) rather than raise.
    first_seen = job_coordinator.record_deferral_start(tmp_path, "live_prune")
    assert time.time() - first_seen < 1.0
