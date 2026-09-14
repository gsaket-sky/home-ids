"""
Tests for core/health_manager.py's per-component state machine (HEALTHY ->
DEGRADED -> UNHEALTHY -> RECOVERY_ATTEMPT -> RECOVERY_FAILED -> SAFE_MODE ->
HEALTHY) and the two heartbeat/probe classification helpers that feed it.
Direct-call style -- no real network/psutil/subprocess, monkeypatched
ACTIONS entries where recovery needs to be exercised.
"""
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core import health_manager as hm_module  # noqa: E402
from core.health_manager import (  # noqa: E402
    HealthManager, HEALTHY, DEGRADED, UNHEALTHY, RECOVERY_FAILED, SAFE_MODE,
)


class FakeConfig:
    def __init__(self, **overrides):
        self._data = {
            "health_manager_recovery_max_attempts": 5,
            "health_manager_auto_recovery_enabled": True,
            "telegram_enabled": True,
        }
        self._data.update(overrides)

    def get(self, key, default=None):
        return self._data.get(key, default)


class FakeAlertManager:
    def __init__(self):
        self.sent = []

    def send(self, message, **kwargs):
        self.sent.append(message)


@pytest.fixture
def hm(tmp_path):
    return HealthManager(config=FakeConfig(), alert_manager=FakeAlertManager(), state_dir=str(tmp_path))


# --- basic transitions, no recovery lever involved -----------------------------

def test_healthy_signal_stays_healthy(hm):
    hm._apply_signal("comp_a", HEALTHY, "ok")
    assert hm._component_state["comp_a"]["state"] == HEALTHY


def test_degraded_signal_transitions_from_healthy(hm):
    hm._apply_signal("comp_a", DEGRADED, "slow")
    assert hm._component_state["comp_a"]["state"] == DEGRADED


def test_unhealthy_with_no_action_entry_stays_unhealthy_forever(hm):
    """comp_a has no ACTIONS entry -- this is the design for zeek/suricata/
    pihole/feeds/jobs: alert-only, no auto-recovery ever attempted."""
    hm._apply_signal("comp_a", UNHEALTHY, "dead")
    assert hm._component_state["comp_a"]["state"] == UNHEALTHY
    hm._apply_signal("comp_a", UNHEALTHY, "still dead")
    assert hm._component_state["comp_a"]["state"] == UNHEALTHY


def test_recovering_from_degraded_back_to_healthy_resets_backoff(hm):
    hm._apply_signal("comp_a", DEGRADED, "slow")
    backoff = hm._get_record("comp_a")["backoff"]
    backoff.record_attempt(now=0.0)
    hm._apply_signal("comp_a", HEALTHY, "back to normal")
    assert hm._component_state["comp_a"]["state"] == HEALTHY
    assert backoff.attempt_count == 0


# --- recovery-attempt path, using a monkeypatched ACTIONS entry -----------------

def test_unhealthy_with_action_triggers_recovery(hm, monkeypatch):
    calls = []

    def fake_action(hm_, component):
        calls.append(component)
        return True, "restarted"

    monkeypatch.setitem(hm_module.ACTIONS, "recoverable", fake_action)
    hm._apply_signal("recoverable", UNHEALTHY, "dead")
    assert calls == ["recoverable"]
    assert hm._component_state["recoverable"]["state"] == HEALTHY  # optimistic; next real check confirms/corrects


def test_recovery_backoff_gates_repeated_attempts(hm, monkeypatch):
    calls = []

    def fake_action(hm_, component):
        calls.append(component)
        return False, "still broken"

    monkeypatch.setitem(hm_module.ACTIONS, "flaky", fake_action)
    hm._apply_signal("flaky", UNHEALTHY, "dead")  # 1st attempt: immediate
    assert len(calls) == 1
    assert hm._component_state["flaky"]["state"] == RECOVERY_FAILED
    hm._apply_signal("flaky", UNHEALTHY, "dead")  # 2nd needs 30s -- must NOT fire again yet
    assert len(calls) == 1


def test_exhausted_backoff_enters_safe_mode_with_exactly_one_alert(hm, monkeypatch):
    def fake_action(hm_, component):
        return False, "still broken"

    monkeypatch.setitem(hm_module.ACTIONS, "hopeless", fake_action)
    backoff = hm._get_record("hopeless")["backoff"]
    for _ in range(5):  # pre-exhaust it directly rather than waiting out real backoff timers
        backoff.record_attempt(now=0.0)
    assert backoff.exhausted()

    hm._apply_signal("hopeless", UNHEALTHY, "dead")
    assert hm._component_state["hopeless"]["state"] == SAFE_MODE
    assert len(hm.alert_manager.sent) == 1

    hm._apply_signal("hopeless", UNHEALTHY, "dead")  # repeated UNHEALTHY signals must not re-alert
    assert len(hm.alert_manager.sent) == 1


def test_safe_mode_exits_on_its_own_when_healthy_again(hm):
    rec = hm._get_record("safe_comp")
    rec["state"] = SAFE_MODE
    rec["alerted_safe_mode"] = True
    hm._apply_signal("safe_comp", HEALTHY, "recovered on its own")
    assert hm._component_state["safe_comp"]["state"] == HEALTHY
    assert len(hm.alert_manager.sent) == 1  # the recovery notification


def test_auto_recovery_disabled_never_attempts_anything(monkeypatch, tmp_path):
    hm2 = HealthManager(
        config=FakeConfig(health_manager_auto_recovery_enabled=False),
        alert_manager=FakeAlertManager(),
        state_dir=str(tmp_path),
    )
    calls = []

    def fake_action(hm_, component):
        calls.append(component)
        return True, "ok"

    monkeypatch.setitem(hm_module.ACTIONS, "guarded", fake_action)
    hm2._apply_signal("guarded", UNHEALTHY, "dead")
    assert calls == []
    assert hm2._component_state["guarded"]["state"] == UNHEALTHY


# --- classification helpers that feed _apply_signal -----------------------------

def test_evaluate_heartbeat_component_classifies_by_age(hm):
    now = 1000.0
    hm._evaluate_heartbeat_component("hb", {"last_heartbeat": now - 1.0}, now, expected_interval=2.0)
    assert hm._component_state["hb"]["state"] == HEALTHY
    hm._evaluate_heartbeat_component("hb", {"last_heartbeat": now - 5.0}, now, expected_interval=2.0)
    assert hm._component_state["hb"]["state"] == DEGRADED
    hm._evaluate_heartbeat_component("hb", {"last_heartbeat": now - 11.0}, now, expected_interval=2.0)
    assert hm._component_state["hb"]["state"] == UNHEALTHY


def test_evaluate_heartbeat_component_no_entry_yet_is_a_noop(hm):
    """Never having seen a heartbeat (cold boot) must not alarm."""
    hm._evaluate_heartbeat_component("never_beaten", None, 1000.0, expected_interval=5.0)
    assert "never_beaten" not in hm._component_state


def test_pipeline_main_loop_default_interval_tolerates_slow_cold_start_step(hm):
    """BUGFIX regression (found live, 2026-09-14, 44 seconds after this
    subsystem's first-ever boot): pipeline_main_loop's expected interval used
    to be based on raw poll_interval (2.0s default), so a single slow _step()
    call (a cold-start backlog, a burst of devices/evidence -- NOT a hung loop)
    stale enough to be 21s old crossed the old 5x=10s UNHEALTHY threshold and
    triggered a real self-restart while the pipeline was still actively
    working. health_manager_pipeline_loop_expected_interval_seconds (default
    60.0) is a deliberately generous, separately-tunable floor for exactly
    this -- this asserts the exact real-world age (21s) that caused the
    incident now stays comfortably HEALTHY."""
    now = 1000.0
    expected_interval = max(60.0, 2.0)  # health_manager_pipeline_loop_expected_interval_seconds default vs poll_interval
    hm._evaluate_heartbeat_component("pipeline_main_loop", {"last_heartbeat": now - 21.0}, now, expected_interval=expected_interval)
    assert hm._component_state["pipeline_main_loop"]["state"] == HEALTHY


def test_evaluate_probe_component_fail_streak_escalates_then_recovers(hm):
    hm._evaluate_probe_component("probe_x", (False, "down"))
    assert hm._component_state["probe_x"]["state"] == DEGRADED
    hm._evaluate_probe_component("probe_x", (False, "still down"))
    assert hm._component_state["probe_x"]["state"] == DEGRADED
    hm._evaluate_probe_component("probe_x", (False, "still down"))
    assert hm._component_state["probe_x"]["state"] == UNHEALTHY
    hm._evaluate_probe_component("probe_x", (True, "back up"))
    assert hm._component_state["probe_x"]["state"] == HEALTHY


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
