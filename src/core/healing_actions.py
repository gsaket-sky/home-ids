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
import time
from typing import Callable, Dict, Tuple, TYPE_CHECKING

from core import subprocess_launchers

if TYPE_CHECKING:
    from core.health_manager import HealthManager

LOGGER = logging.getLogger("home_ids.healing_actions")


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
    no-op exit."""
    try:
        if hm.alert_manager is not None:
            hm.alert_manager.send(
                f"🔁 *Health Manager*: restarting the main engine process "
                f"(triggered by `{component}`). Expect a ~10-45s detection gap "
                f"while systemd relaunches it."
            )
    except Exception:
        pass
    LOGGER.critical("Health manager triggered a self-restart (component=%s). Sending SIGTERM to self for graceful shutdown.", component)
    os.kill(os.getpid(), signal.SIGTERM)
    return True, "SIGTERM sent to self"


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
