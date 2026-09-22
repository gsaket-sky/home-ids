"""
job_coordinator.py -- single global mutex + priority + pause/resume + orphan
reconciliation for every scheduled subprocess job (scripts/scheduler.py's cron jobs and
intelligence/fp_engine.py's weekly retrain), so at most one runs at a time system-wide
and a higher-priority job can preempt (SIGSTOP) a lower-priority *pausable* one instead
of just waiting behind it.

Crash-safety is the point of this module, not an afterthought:
  - Every write to the lock file is atomic (temp file + os.replace()) -- a SIGKILL
    (OOM-killer or a forced restart) mid-write can never leave a half-written/corrupt
    file at the live path.
  - Every read treats a missing file, an unparseable file, or a recorded PID that's no
    longer alive as "slot empty" -- never trusts stale claimed state. This is the
    ACTUAL correctness guarantee (not release(), which is just the well-behaved fast
    path): if a job finishes, crashes, or is OOM-killed without ever calling release(),
    the very next read from ANY process self-heals the slot, promoting a paused
    occupant back to the front if one was parked underneath.
  - Every launched job forms its own process group (callers must pass
    start_new_session=True to subprocess.Popen()) so a stuck orphan can be reclaimed
    with its whole tree, not just the one tracked PID.

See Documentation/RESOURCE_AWARE_SCHEDULING.md for the full design rationale, the
per-job priority/pausable table, and why this is deliberately separate from
health_manager.py's own pressure classifier.
"""
import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Optional

LOGGER = logging.getLogger("job_coordinator")

LOCK_FILENAME = "scheduled_job_slot.json"
CLAIM_FILENAME = "scheduled_job_slot.claim"
_CLAIM_STALE_SECONDS = 10.0  # claiming should be near-instant; anything older is orphaned

GRANTED = "granted"
DENIED = "denied"
PREEMPTED_PREFIX = "preempted:"


def _lock_path(state_dir) -> Path:
    return Path(state_dir) / LOCK_FILENAME


def _claim_path(state_dir) -> Path:
    return Path(state_dir) / CLAIM_FILENAME


def is_pid_alive(pid) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just owned by someone else -- still alive
    except Exception:
        return False


def _atomic_write_json(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # atomic rename -- never leaves a half-written file at `path`


def _acquire_claim(state_dir) -> bool:
    """Atomic O_CREAT|O_EXCL claim on a sentinel file so two processes (scheduler.py
    and fp_engine.py's retrain thread) racing to update the slot can't both succeed.
    The sentinel's own content records ITS claimant's pid+timestamp so a claimant that
    died mid-claim can be recognized and cleared rather than wedging every future
    claim forever."""
    claim_path = _claim_path(state_dir)
    for _ in range(2):  # one retry, to clear a stale sentinel and try again
        try:
            fd = os.open(str(claim_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, json.dumps({"pid": os.getpid(), "ts": time.time()}).encode("utf-8"))
            finally:
                os.close(fd)
            return True
        except FileExistsError:
            try:
                existing = json.loads(claim_path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
            age = time.time() - float(existing.get("ts", 0))
            if age > _CLAIM_STALE_SECONDS or not is_pid_alive(existing.get("pid")):
                try:
                    claim_path.unlink()
                except FileNotFoundError:
                    pass
                continue  # retry the exclusive create
            return False  # a live claimant is genuinely mid-claim right now
    return False


def _release_claim(state_dir) -> None:
    try:
        _claim_path(state_dir).unlink()
    except FileNotFoundError:
        pass


def _promote_or_clear(path: Path, dead_slot: dict) -> Optional[dict]:
    """The active occupant recorded at `path` is dead. If a job was parked underneath
    it (preempted), promote that job back to the top-level slot, marked 'paused', so
    its own owner notices via should_resume() and resumes it. Otherwise clear the
    file entirely. Best-effort: a lost race here just means one of two equivalent
    writes wins, both converge to the same correct state."""
    preempted = dead_slot.get("preempted")
    if preempted and is_pid_alive(preempted.get("pid")):
        promoted = {
            "job": preempted.get("job"), "pid": preempted.get("pid"),
            "priority": preempted.get("priority", 0),
            "pausable": preempted.get("pausable", False), "state": "paused",
            "started_at": dead_slot.get("started_at"), "paused_at": time.time(),
            "max_runtime_minutes": preempted.get("max_runtime_minutes", 60.0),
        }
        try:
            _atomic_write_json(path, promoted)
        except Exception:
            pass
        return promoted
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    return None


def _read_slot(state_dir) -> Optional[dict]:
    """Returns the current slot, or None if empty/missing/corrupt -- self-healing on
    every read, not dependent on any process's release() ever having run."""
    path = _lock_path(state_dir)
    if not path.exists():
        return None
    try:
        slot = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None  # corrupt file -- next write replaces it; nothing to recover
    if not slot:
        return None
    if is_pid_alive(slot.get("pid")):
        return slot
    return _promote_or_clear(path, slot)


def peek_admission(state_dir, priority: int) -> bool:
    """Read-only, non-claiming preview of whether acquire_or_preempt() would
    plausibly succeed for a job of this priority right now -- lets a caller avoid
    launching a subprocess just to immediately lose the claim race and have to kill
    it again. NOT authoritative on its own (the real claim can still race and lose,
    since this doesn't hold the claim lock) -- callers must still go through
    acquire_or_preempt() with the REAL pid once actually launched."""
    current = _read_slot(state_dir)
    if current is None:
        return True
    if current.get("priority", 0) <= priority:
        return False  # occupant is equal-or-more urgent
    if current.get("preempted"):
        return False  # already one job parked underneath -- no further stacking
    return bool(current.get("pausable", False))


def acquire_or_preempt(state_dir, job_name: str, pid: int, priority: int, pausable: bool,
                        max_runtime_minutes: float = 60.0) -> str:
    """Returns GRANTED, DENIED, or "preempted:<old_pid>". On a preempt result, the
    CALLER (which holds the actual subprocess handle/permissions) must SIGSTOP
    old_pid itself -- this function only decides, matching the same
    decide-vs-execute split every other self-heal action in this codebase uses.
    Lower `priority` number = more urgent. At most one job may be parked (paused)
    underneath the active one at a time -- a further preemption attempt while one is
    already parked is DENIED, deliberately, to keep the model a simple 2-deep stack
    at most, never unbounded."""
    if not _acquire_claim(state_dir):
        return DENIED  # someone else is mid-claim; caller retries next tick/poll
    try:
        current = _read_slot(state_dir)
        if current is None:
            _atomic_write_json(_lock_path(state_dir), {
                "job": job_name, "pid": pid, "priority": priority, "pausable": pausable,
                "state": "running", "started_at": time.time(), "paused_at": None,
                "max_runtime_minutes": max_runtime_minutes,
            })
            return GRANTED
        if current.get("priority", 0) <= priority:
            return DENIED  # occupant is equal-or-more urgent -- requester waits
        if current.get("preempted"):
            return DENIED  # already one job parked underneath -- no further stacking
        if not current.get("pausable", False):
            return DENIED  # occupant is less urgent but not safe to pause (e.g. live_prune)
        old_pid = current["pid"]
        _atomic_write_json(_lock_path(state_dir), {
            "job": job_name, "pid": pid, "priority": priority, "pausable": pausable,
            "state": "running", "started_at": time.time(), "paused_at": None,
            "max_runtime_minutes": max_runtime_minutes,
            "preempted": {
                "job": current.get("job"), "pid": old_pid,
                "priority": current.get("priority", 0),
                "pausable": current.get("pausable", False),
                "max_runtime_minutes": current.get("max_runtime_minutes", 60.0),
            },
        })
        return f"{PREEMPTED_PREFIX}{old_pid}"
    finally:
        _release_claim(state_dir)


def release(state_dir, job_name: str, pid: int) -> None:
    """Called by a job's owner once its subprocess has exited. Fast-path only -- if
    this never runs (the owner also crashed/was killed before calling it), the
    self-healing _read_slot() path above still promotes/clears correctly on the next
    read from anyone. Best-effort: if the claim can't be acquired right now, does
    nothing and relies on that same self-healing read path."""
    if not _acquire_claim(state_dir):
        return
    try:
        path = _lock_path(state_dir)
        if not path.exists():
            return
        try:
            slot = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        if slot.get("pid") != pid or slot.get("job") != job_name:
            return  # already reclaimed/promoted by someone else
        _promote_or_clear(path, slot)
    finally:
        _release_claim(state_dir)


def owns_slot(state_dir, job_name: str, pid: int) -> bool:
    """True if this (job_name, pid) is still the visible top-level slot occupant --
    running OR paused, doesn't matter which. False means someone else preempted it
    (it's now only referenced, invisibly, inside the preemptor's own 'preempted'
    field) -- the job's own poll loop uses this to tell "I'm still in charge of my
    own self-throttle decisions" apart from "I've been preempted, just wait for
    should_resume()"."""
    slot = _read_slot(state_dir)
    return bool(slot) and slot.get("job") == job_name and slot.get("pid") == pid


def should_resume(state_dir, job_name: str, pid: int) -> bool:
    """Called by a PAUSED job's own owner (the thread/process that still holds a live
    handle able to SIGCONT it -- a lock file alone can't signal a process someone
    else must send the signal). True once this job is the current slot occupant AND
    marked 'paused' -- meaning whatever preempted it has finished or was reclaimed."""
    slot = _read_slot(state_dir)
    return bool(slot) and slot.get("pid") == pid and slot.get("state") == "paused"


def mark_running(state_dir, job_name: str, pid: int) -> None:
    """Call right after SIGCONT-ing a job should_resume() said was ready, to flip its
    recorded state back from 'paused' to 'running'."""
    if not _acquire_claim(state_dir):
        return
    try:
        path = _lock_path(state_dir)
        try:
            slot = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        if slot.get("pid") == pid and slot.get("job") == job_name:
            slot["state"] = "running"
            slot["paused_at"] = None
            _atomic_write_json(path, slot)
    finally:
        _release_claim(state_dir)


def mark_paused(state_dir, job_name: str, pid: int) -> None:
    """Counterpart to mark_running() -- call after self-throttling (pausing your own
    still-active job under general system pressure, independent of any other job
    trying to preempt you) so the slot's recorded state stays accurate for any other
    process/console inspecting it. Purely observational: peek_admission()/
    acquire_or_preempt() don't treat 'paused' any differently from 'running' for
    admission decisions (the occupying job hasn't finished either way) -- this only
    keeps the ground truth honest."""
    if not _acquire_claim(state_dir):
        return
    try:
        path = _lock_path(state_dir)
        try:
            slot = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        if slot.get("pid") == pid and slot.get("job") == job_name:
            slot["state"] = "paused"
            slot["paused_at"] = time.time()
            _atomic_write_json(path, slot)
    finally:
        _release_claim(state_dir)


def pause_process(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGSTOP)
    except Exception as exc:
        LOGGER.warning("job_coordinator: failed to SIGSTOP pid %s: %s", pid, exc)


def resume_process(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGCONT)
    except Exception as exc:
        LOGGER.warning("job_coordinator: failed to SIGCONT pid %s: %s", pid, exc)


def reconcile_on_boot(state_dir) -> None:
    """Call once at the very top of every coordinator participant's startup
    (scripts/scheduler.py's main(), and fp_engine.py's retrain-thread startup) BEFORE
    doing anything else -- AND ALSO call every scheduler tick / retrain poll
    thereafter (the name reflects its original motivating case, but it's a general
    watchdog, not boot-only: this is what turns "a job denied the slot for too long"
    into a safe starvation backstop -- reclaiming the stuck occupant automatically --
    rather than needing to bypass the mutex and risk a real double-run). A dead
    occupant is already cleared/promoted by _read_slot()'s own self-healing; this
    adds the one thing that needs an explicit check: an occupant that's still ALIVE
    but has outlived its own recorded max_runtime_minutes -- whether because it's
    genuinely hung, or because it survived a restart of whichever process originally
    launched it and has nothing left enforcing its budget. Kills the whole process
    group (not just the tracked pid) so anything it spawned internally is cleaned up
    too."""
    slot = _read_slot(state_dir)
    if slot is None:
        return
    started_at = slot.get("started_at")
    if started_at is None:
        return
    max_runtime = float(slot.get("max_runtime_minutes", 60.0))
    age_minutes = (time.time() - float(started_at)) / 60.0
    if age_minutes <= max_runtime:
        return  # legitimately still running within its own budget -- leave it alone
    pid = slot.get("pid")
    LOGGER.error(
        "job_coordinator: reclaiming stuck orphan job=%r pid=%s (running %.1f min, "
        "budget was %.1f min) -- killing its process group.",
        slot.get("job"), pid, age_minutes, max_runtime,
    )
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    try:
        _lock_path(state_dir).unlink()
    except FileNotFoundError:
        pass
