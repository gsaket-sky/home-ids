"""
healing_actions.py -- the Level 2-4 healing-action catalog, scoped to components
that actually have a real recovery lever in this codebase.

Deliberately NOT a catalog entry for zeek/suricata/pihole/threat-intel feeds --
all four are either external to this codebase entirely (no systemd unit files
even exist in-repo for zeek/suricata/pi-hole-FTL, no systemctl permission has
ever been granted to this process) or, for TI feeds, already have their own
alerting via feed_health.py with no restart concept of their own (an API feed
can't be "restarted"). ACTIONS having no entry for these is itself the design --
HealthManager treats a component with no ACTIONS entry as alert-only, forever
(see health_manager.py's state machine).

Every in-process component's ONLY real recovery lever is a clean process
self-restart: Python cannot safely kill-and-revive a single hung daemon thread
from inside the same process, but soc.service's own systemd unit already has
Restart=on-failure / RestartSec=10 -- so a graceful self-exit is sufficient, no
sudo/systemctl call needed. restart_own_process() below sends itself SIGTERM
(NOT sys.exit() -- see that function's own bugfix comment for why a bare
sys.exit() from this background thread silently doesn't work at all) to reuse
main.py's existing shutdown_handler.
"""
import logging
import os
import signal
import threading
import time
from typing import Callable, Dict, Tuple, TYPE_CHECKING

from core import subprocess_launchers

if TYPE_CHECKING:
    from core.health_manager import HealthManager

LOGGER = logging.getLogger("home_ids.healing_actions")


_SIGKILL_ESCALATION_ATTEMPT = 3  # see BUGFIX #2 below
_HARD_FALLBACK_TIMEOUT_SECONDS = 45.0  # matches soc.service's own TimeoutStopSec


def _arm_hard_fallback_kill(timeout: float = _HARD_FALLBACK_TIMEOUT_SECONDS) -> None:
    """BUGFIX #3 (found live, 2026-09-21, same OOM/pressure incident as BUGFIX #2):
    confirmed live that a self-triggered SIGTERM's own graceful shutdown sequence
    can itself get stuck (this time inside state_guard.py's flush_to_disk(), fixed
    separately) for 20+ minutes with ZERO external supervision -- systemd's own
    TimeoutStopSec=45s only ever applies when SYSTEMD requests the stop
    (systemctl stop/restart); a process sending itself a signal is completely
    invisible to that machinery. The existing attempt-3 SIGKILL escalation above
    depends on RecoveryBackoff's own schedule re-evaluating the component as still
    unhealthy on a LATER health_manager cycle -- which, live, didn't happen fast
    enough (or possibly at all) while _check_cycle() itself was intermittently
    timing out under the same pressure. This is independent of that: a bare
    OS-level timer, armed the moment ANY self-restart attempt fires (not just the
    3rd), that unconditionally SIGKILLs this process after `timeout` seconds --
    no condition to check, no cycle to depend on. If the graceful shutdown
    succeeds first, this process (and this daemon thread with it) is simply gone
    before the timer ever fires; sending a real SIGKILL to an already-exited PID
    is otherwise harmless."""
    def _watchdog():
        time.sleep(timeout)
        LOGGER.critical(
            "Health manager's hard fallback fired: this process is still alive "
            "%.0fs after a self-restart was triggered (the graceful shutdown "
            "itself is stuck, or never received/processed the signal) -- "
            "escalating to an unconditional SIGKILL now.", timeout,
        )
        os.kill(os.getpid(), getattr(signal, "SIGKILL", signal.SIGTERM))

    threading.Thread(target=_watchdog, daemon=True, name="health_manager_hard_fallback").start()


def restart_own_process(hm: "HealthManager", component: str) -> Tuple[bool, str]:
    """The main pipeline process restarting itself.

    BUGFIX (found live, 2026-09-14, minutes after this subsystem's first
    deploy): this used to call sys.exit(1) directly. HealthManager runs as a
    background daemon thread, NOT the main thread -- sys.exit() raises
    SystemExit, which only unwinds the CALLING thread. Python's threading
    module catches an uncaught SystemExit at the top of Thread.run() and
    treats it as a normal thread exit; the rest of the process (main thread,
    every other thread) keeps running completely unaffected. Confirmed live:
    the log showed "triggered a self-restart" followed by systemd reporting
    the SAME PID/NRestarts=0 six minutes later -- the health manager thread
    had simply died, silently disabling ALL further health monitoring and
    auto-recovery for the rest of the process's life, while the "self-restart"
    itself never happened at all.

    Fixed by sending SIGTERM to this process's own PID instead -- signals are
    delivered to the process (handled on the main thread) regardless of which
    thread calls os.kill(), so this correctly reuses main.py's EXISTING
    shutdown_handler (graceful subprocess cleanup, health_manager.stop(),
    pipeline.stop(), then a real sys.exit(0) called FROM the main thread,
    which does terminate the process) instead of a bare, thread-local, silently
    no-op exit.

    BUGFIX #2 (found live, 2026-09-21 OOM incident investigation): confirmed
    this SIGTERM path can itself silently fail to work at all under severe
    cgroup memory/swap pressure -- CPython only delivers a caught signal to
    Python code at the next bytecode-eval-loop check, which never comes if
    the main thread is stuck thrashing on swapped-out pages (page faults are
    serviced entirely in the kernel, with no bytecode running in between).
    Live evidence: this fired for `pipeline_main_loop` FIVE times over 31
    minutes (RecoveryBackoff's own 0/30/120/600s schedule), each logged as
    "succeeded... verifying", while the component's heartbeat staleness kept
    climbing the entire time (302s -> 1139s) -- the process never actually
    exited on its own. The engine sat with zero detection coverage,
    believing it was healing itself, until the kernel's OOM-killer ended it
    45 minutes after the first attempt. From the 3rd attempt onward (i.e.
    once TWO prior SIGTERMs have demonstrably not worked -- this action is
    only ever invoked again because the component is still unhealthy),
    escalate to SIGKILL: unlike SIGTERM it cannot be caught, blocked, or
    queued waiting for a bytecode boundary -- the kernel enforces it
    unconditionally without any cooperation from this (possibly wedged)
    process. This skips main.py's graceful shutdown_handler (state saves
    etc.), the correct tradeoff at this point: systemd's Restart=always
    relaunches it either way, and the alternative already demonstrated live
    is an unbounded, silent coverage gap rather than a clean shutdown."""
    backoff_attempt = 0
    try:
        backoff_attempt = hm._get_record(component)["backoff"].attempt_count
    except Exception:
        pass
    escalate = backoff_attempt >= _SIGKILL_ESCALATION_ATTEMPT
    # getattr fallback: SIGKILL doesn't exist on Windows (this project's own
    # dev environment) -- every real deployment target (.94, the eventual Pi)
    # is Linux, where it's always present, but this must not crash a dev-
    # machine test run over a platform difference that never occurs in
    # production.
    sig = getattr(signal, "SIGKILL", signal.SIGTERM) if escalate else signal.SIGTERM
    action_detail = (
        "SIGKILL sent to self (graceful SIGTERM already failed to take effect)"
        if escalate else "SIGTERM sent to self"
    )

    try:
        if hm.alert_manager is not None:
            hm.alert_manager.send(
                f"🔁 *Health Manager*: restarting the main engine process "
                f"(triggered by `{component}`, attempt {backoff_attempt}). "
                f"Expect a ~10-45s detection gap while systemd relaunches it."
            )
    except Exception:
        pass
    LOGGER.critical(
        "Health manager triggered a self-restart (component=%s, attempt=%d). %s.",
        component, backoff_attempt, action_detail,
    )
    if not escalate:
        # Only needed ahead of a plain SIGTERM -- an escalated SIGKILL here is
        # already unconditional and immediate, nothing to fall back FROM.
        _arm_hard_fallback_kill()
    os.kill(os.getpid(), sig)
    return True, action_detail


def restart_fastapi_subprocess(hm: "HealthManager", component: str) -> Tuple[bool, str]:
    old_proc = hm.fastapi_proc
    if old_proc is not None and old_proc.poll() is None:
        try:
            old_proc.terminate()
            old_proc.wait(timeout=3)
        except Exception:
            try:
                old_proc.kill()
            except Exception:
                pass
    if hm.fastapi_log_file is not None and not hm.fastapi_log_file.closed:
        try:
            hm.fastapi_log_file.close()
        except Exception:
            pass

    proc, log_file = subprocess_launchers.start_fastapi_subprocess(hm.config)
    hm.fastapi_proc = proc
    hm.fastapi_log_file = log_file
    if proc is None:
        return False, "relaunch failed (see log)"
    return True, f"relaunched, pid={proc.pid}"


def restart_scheduler_subprocess(hm: "HealthManager", component: str) -> Tuple[bool, str]:
    old_proc = hm.scheduler_proc
    if old_proc is not None and old_proc.poll() is None:
        try:
            old_proc.terminate()
            old_proc.wait(timeout=3)
        except Exception:
            try:
                old_proc.kill()
            except Exception:
                pass
    if hm.scheduler_log_file is not None and not hm.scheduler_log_file.closed:
        try:
            hm.scheduler_log_file.close()
        except Exception:
            pass

    proc, log_file = subprocess_launchers.start_scheduler_subprocess()
    hm.scheduler_proc = proc
    hm.scheduler_log_file = log_file
    if proc is None:
        return False, "relaunch failed (see log)"
    return True, f"relaunched, pid={proc.pid}"


ACTIONS: Dict[str, Callable[["HealthManager", str], Tuple[bool, str]]] = {
    "pipeline_main_loop": restart_own_process,
    "identity_reconcile_worker": restart_own_process,
    "ti_refresh": restart_own_process,
    "resource_pressure": restart_own_process,
    "api_subprocess": restart_fastapi_subprocess,
    "scheduler_subprocess": restart_scheduler_subprocess,
}
