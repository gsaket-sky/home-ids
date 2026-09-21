"""
Tests for core/healing_actions.py. Uses a lightweight SimpleNamespace standing
in for HealthManager (healing_actions.py only ever reads/writes a handful of
its attributes, doesn't need a real instance) -- direct-call style, matching
the rest of this session's tests. sys.exit is monkeypatched throughout so this
never actually exits the test process.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core import healing_actions  # noqa: E402

# Captured before the autouse fixture below ever patches the module attribute,
# so the one test that needs the REAL timer (not the autouse-mocked no-op) can
# still reach it.
_REAL_ARM_HARD_FALLBACK_KILL = healing_actions._arm_hard_fallback_kill


@pytest.fixture(autouse=True)
def _no_real_hard_fallback_timer(monkeypatch):
    """SAFETY: restart_own_process() now arms _arm_hard_fallback_kill() on every
    non-escalated (SIGTERM) call -- a REAL 45s background thread that ends in an
    unconditional os.kill(os.getpid(), SIGKILL). Left unpatched, that thread
    outlives any single test function and fires AFTER pytest's own monkeypatch
    fixture has already reverted os.kill back to the real one -- which would
    kill this actual test process/runner 45 seconds after any such test ran.
    Autouse so every test in this file (existing and future) is protected
    without needing to remember to patch it individually; dedicated tests below
    verify _arm_hard_fallback_kill()'s own real timer behavior in isolation,
    with a short timeout and explicit synchronization instead of relying on
    this default."""
    calls = []
    monkeypatch.setattr(healing_actions, "_arm_hard_fallback_kill", lambda *a, **k: calls.append((a, k)))
    return calls


class FakeAlertManager:
    def __init__(self):
        self.sent = []

    def send(self, message, **kwargs):
        self.sent.append(message)


def _fake_hm(**overrides):
    base = dict(
        alert_manager=FakeAlertManager(),
        config=SimpleNamespace(get=lambda k, d=None: d),
        fastapi_proc=None,
        fastapi_log_file=None,
        scheduler_proc=None,
        scheduler_log_file=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# --- restart_own_process ----------------------------------------------------------
#
# BUGFIX regression (found live, 2026-09-14, minutes after first deploy):
# restart_own_process() used to call sys.exit(1) directly. HealthManager runs
# as a background daemon thread, not the main thread -- sys.exit() there only
# unwinds the CALLING thread (Python's threading module swallows an uncaught
# SystemExit at the top of Thread.run()), so the process never actually
# restarted; the health manager thread just silently died instead, disabling
# all further monitoring. Fixed to send itself SIGTERM (delivered to the
# process regardless of which thread calls os.kill()), reusing main.py's
# existing graceful shutdown_handler. These tests assert THAT mechanism, not
# the old (broken) sys.exit() one.

def test_restart_own_process_sends_sigterm_to_self(monkeypatch):
    kills = []
    monkeypatch.setattr(healing_actions.os, "kill", lambda pid, sig: kills.append((pid, sig)))
    hm = _fake_hm()
    success, detail = healing_actions.restart_own_process(hm, "pipeline_main_loop")
    assert kills == [(healing_actions.os.getpid(), healing_actions.signal.SIGTERM)]
    assert success is True
    assert len(hm.alert_manager.sent) == 1
    assert "pipeline_main_loop" in hm.alert_manager.sent[0]


def test_restart_own_process_survives_no_alert_manager(monkeypatch):
    """alert_manager=None must not raise -- a health manager built before the
    pipeline finished constructing its own AlertManager shouldn't crash the
    one recovery lever that matters most."""
    monkeypatch.setattr(healing_actions.os, "kill", lambda pid, sig: None)
    hm = _fake_hm(alert_manager=None)
    healing_actions.restart_own_process(hm, "resource_pressure")  # must not raise


# BUGFIX #2 regression (found live, 2026-09-21 OOM incident): a graceful
# SIGTERM can silently never take effect if the main thread is too busy
# thrashing on swapped-out pages to ever reach a bytecode boundary --
# confirmed live, pipeline_main_loop sent itself SIGTERM 5 times over 31
# minutes with zero actual effect, until the kernel's OOM-killer ended it.
# From the 3rd attempt onward, escalate to SIGKILL, which the kernel enforces
# unconditionally with no cooperation from this process required.

def _fake_hm_with_backoff(attempt_count, **overrides):
    return _fake_hm(
        _get_record=lambda component: {"backoff": SimpleNamespace(attempt_count=attempt_count)},
        **overrides,
    )


@pytest.mark.parametrize("attempt_count", [1, 2])
def test_restart_own_process_still_uses_sigterm_below_escalation_threshold(monkeypatch, attempt_count):
    kills = []
    monkeypatch.setattr(healing_actions.os, "kill", lambda pid, sig: kills.append((pid, sig)))
    hm = _fake_hm_with_backoff(attempt_count)
    success, detail = healing_actions.restart_own_process(hm, "pipeline_main_loop")
    assert kills == [(healing_actions.os.getpid(), healing_actions.signal.SIGTERM)]
    assert success is True
    assert "SIGTERM" in detail


@pytest.mark.parametrize("attempt_count", [3, 4, 5])
def test_restart_own_process_escalates_to_sigkill_after_repeated_failed_attempts(monkeypatch, attempt_count):
    # getattr, not a bare signal.SIGKILL reference: this dev environment is
    # Windows, which has no SIGKILL at all -- every real deployment target is
    # Linux, where it's always present (see healing_actions.py's own comment).
    expected_sig = getattr(healing_actions.signal, "SIGKILL", healing_actions.signal.SIGTERM)
    kills = []
    monkeypatch.setattr(healing_actions.os, "kill", lambda pid, sig: kills.append((pid, sig)))
    hm = _fake_hm_with_backoff(attempt_count)
    success, detail = healing_actions.restart_own_process(hm, "pipeline_main_loop")
    assert kills == [(healing_actions.os.getpid(), expected_sig)]
    assert success is True
    if expected_sig != healing_actions.signal.SIGTERM:
        assert "SIGKILL" in detail


# BUGFIX #3 regression (found live, 2026-09-21, same OOM/pressure incident as
# BUGFIX #2): a self-triggered SIGTERM's own graceful shutdown can itself get
# stuck (that specific time, inside state_guard.py's flush_to_disk(), fixed
# separately) with ZERO external supervision -- systemd's TimeoutStopSec only
# ever applies when SYSTEMD requests the stop, not a self-sent signal. The
# existing attempt-3 SIGKILL escalation depends on a LATER health_manager cycle
# re-evaluating the component as still unhealthy, which live, didn't happen
# fast enough while _check_cycle() itself was intermittently timing out under
# the same pressure. _arm_hard_fallback_kill() is independent of that: a bare
# timer armed on every attempt, not just the 3rd.

def test_restart_own_process_arms_hard_fallback_on_a_plain_sigterm_attempt(monkeypatch, _no_real_hard_fallback_timer):
    monkeypatch.setattr(healing_actions.os, "kill", lambda pid, sig: None)
    hm = _fake_hm()
    healing_actions.restart_own_process(hm, "pipeline_main_loop")
    assert len(_no_real_hard_fallback_timer) == 1


def test_restart_own_process_does_not_double_arm_on_an_already_escalated_sigkill(monkeypatch, _no_real_hard_fallback_timer):
    # An escalated SIGKILL is already unconditional and immediate -- there is
    # nothing for a fallback timer to fall back FROM.
    monkeypatch.setattr(healing_actions.os, "kill", lambda pid, sig: None)
    hm = _fake_hm_with_backoff(3)
    healing_actions.restart_own_process(hm, "pipeline_main_loop")
    assert _no_real_hard_fallback_timer == []


def test_arm_hard_fallback_kill_sends_sigkill_after_the_process_is_still_alive(monkeypatch):
    """Real timer, real thread -- but a tiny timeout and an explicit join so
    this test controls exactly when it fires instead of trusting real time."""
    import threading as _threading
    kills = []
    fired = _threading.Event()

    def _fake_kill(pid, sig):
        kills.append((pid, sig))
        fired.set()

    monkeypatch.setattr(healing_actions.os, "kill", _fake_kill)
    _REAL_ARM_HARD_FALLBACK_KILL(timeout=0.05)
    assert fired.wait(timeout=2.0), "hard fallback timer never fired"
    assert kills == [(healing_actions.os.getpid(), getattr(healing_actions.signal, "SIGKILL", healing_actions.signal.SIGTERM))]


def test_restart_own_process_missing_get_record_defaults_to_sigterm(monkeypatch):
    """_fake_hm() (no _get_record at all, like a minimal stand-in) must not
    crash -- the attempt-count lookup is best-effort, defaulting to the safe
    (non-escalated) SIGTERM behavior rather than raising."""
    kills = []
    monkeypatch.setattr(healing_actions.os, "kill", lambda pid, sig: kills.append((pid, sig)))
    hm = _fake_hm()
    success, detail = healing_actions.restart_own_process(hm, "pipeline_main_loop")
    assert kills == [(healing_actions.os.getpid(), healing_actions.signal.SIGTERM)]


# --- restart_fastapi_subprocess ----------------------------------------------------

def test_restart_fastapi_subprocess_terminates_old_and_launches_new(monkeypatch):
    terminated = []
    old_proc = SimpleNamespace(poll=lambda: None, terminate=lambda: terminated.append(True), wait=lambda timeout=None: None)
    new_proc = SimpleNamespace(pid=999)
    monkeypatch.setattr(healing_actions.subprocess_launchers, "start_fastapi_subprocess", lambda config: (new_proc, "new_log_handle"))

    hm = _fake_hm(fastapi_proc=old_proc, fastapi_log_file=None)
    success, detail = healing_actions.restart_fastapi_subprocess(hm, "api_subprocess")

    assert terminated == [True]
    assert success is True
    assert hm.fastapi_proc is new_proc
    assert hm.fastapi_log_file == "new_log_handle"
    assert "999" in detail


def test_restart_fastapi_subprocess_skips_terminate_if_already_exited(monkeypatch):
    terminated = []
    old_proc = SimpleNamespace(poll=lambda: 0, terminate=lambda: terminated.append(True))  # poll() != None -> already exited
    new_proc = SimpleNamespace(pid=1000)
    monkeypatch.setattr(healing_actions.subprocess_launchers, "start_fastapi_subprocess", lambda config: (new_proc, None))

    hm = _fake_hm(fastapi_proc=old_proc)
    healing_actions.restart_fastapi_subprocess(hm, "api_subprocess")
    assert terminated == []


def test_restart_fastapi_subprocess_reports_failure_when_relaunch_fails(monkeypatch):
    monkeypatch.setattr(healing_actions.subprocess_launchers, "start_fastapi_subprocess", lambda config: (None, None))
    hm = _fake_hm()
    success, detail = healing_actions.restart_fastapi_subprocess(hm, "api_subprocess")
    assert success is False
    assert hm.fastapi_proc is None


# --- restart_scheduler_subprocess --------------------------------------------------

def test_restart_scheduler_subprocess_terminates_old_and_launches_new(monkeypatch):
    terminated = []
    old_proc = SimpleNamespace(poll=lambda: None, terminate=lambda: terminated.append(True), wait=lambda timeout=None: None)
    new_proc = SimpleNamespace(pid=2000)
    monkeypatch.setattr(healing_actions.subprocess_launchers, "start_scheduler_subprocess", lambda: (new_proc, "log2"))

    hm = _fake_hm(scheduler_proc=old_proc)
    success, detail = healing_actions.restart_scheduler_subprocess(hm, "scheduler_subprocess")

    assert terminated == [True]
    assert success is True
    assert hm.scheduler_proc is new_proc
    assert hm.scheduler_log_file == "log2"


def test_restart_scheduler_subprocess_reports_failure_when_relaunch_fails(monkeypatch):
    monkeypatch.setattr(healing_actions.subprocess_launchers, "start_scheduler_subprocess", lambda: (None, None))
    hm = _fake_hm()
    success, detail = healing_actions.restart_scheduler_subprocess(hm, "scheduler_subprocess")
    assert success is False


# --- ACTIONS catalog: structural enforcement of the alert-only design -------------

def test_actions_catalog_has_no_entry_for_externally_managed_components():
    """zeek/suricata/pihole/threat-intel feeds are deliberately alert-only --
    this asserts the design decision structurally, not just by convention, so a
    future PR can't silently reintroduce an auto-restart for something this
    process has no systemctl permission to touch."""
    for component in ("zeek", "suricata", "pihole"):
        assert component not in healing_actions.ACTIONS


def test_actions_catalog_covers_every_real_recovery_lever():
    expected = {
        "pipeline_main_loop", "identity_reconcile_worker", "ti_refresh",
        "resource_pressure", "api_subprocess", "scheduler_subprocess",
    }
    assert set(healing_actions.ACTIONS.keys()) == expected


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
