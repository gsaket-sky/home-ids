"""
Tests for core/health_manager.py's per-component state machine (HEALTHY ->
DEGRADED -> UNHEALTHY -> RECOVERY_ATTEMPT -> RECOVERY_FAILED -> SAFE_MODE ->
HEALTHY) and the two heartbeat/probe classification helpers that feed it.
Direct-call style -- no real network/psutil/subprocess, monkeypatched
ACTIONS entries where recovery needs to be exercised.
"""
import json
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core import health_manager as hm_module  # noqa: E402
from core.health_manager import (  # noqa: E402
    HealthManager, HEALTHY, DEGRADED, UNHEALTHY, RECOVERY_FAILED, SAFE_MODE, RETIRED,
    _estimate_cron_interval_seconds,
)
from core.heartbeat import write_component_heartbeat  # noqa: E402


class FakeConfig:
    def __init__(self, overrides_path=None, **overrides):
        self._data = {
            "health_manager_recovery_max_attempts": 5,
            "health_manager_auto_recovery_enabled": True,
            "telegram_enabled": True,
        }
        self._data.update(overrides)
        # 2026-09-16: matches the REAL LiveConfig's own attribute name exactly
        # (config.py's _overrides_path) -- _describe_disabled_reason() reads
        # this directly, same pattern health_manager.py's own
        # _set_config_override() already uses.
        self._overrides_path = overrides_path

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


# --- job-health: per-job cron-derived staleness + retired-job handling ----------
# BUGFIX (2026-09-15, console/health audit -- user report: shadow_watcher and
# gap_monitor permanently showing "degraded"). See _evaluate_job_health_components()'s
# own docstring for the full incident.

def test_estimate_cron_interval_matches_every_real_schedule_in_config_yaml():
    assert _estimate_cron_interval_seconds("*/15 * * * *") == 15 * 60
    assert _estimate_cron_interval_seconds("30 */4 * * *") == 4 * 3600
    assert _estimate_cron_interval_seconds("30 2,6,10,14,18,22 * * *") == 4 * 3600  # 6x/day
    assert _estimate_cron_interval_seconds("0 2 * * *") == 86400
    assert _estimate_cron_interval_seconds("0 6 * * *") == 86400
    assert _estimate_cron_interval_seconds("15 3 * * *") == 86400
    assert _estimate_cron_interval_seconds("45 2 * * *") == 86400
    assert _estimate_cron_interval_seconds("30 3 * * *") == 86400
    assert _estimate_cron_interval_seconds("0 3 * * *") == 86400
    assert _estimate_cron_interval_seconds("0 4 1 * *") == pytest.approx(30 * 86400)


def test_estimate_cron_interval_handles_weekly_and_malformed():
    assert _estimate_cron_interval_seconds("0 4 * * 1") == 7 * 86400  # weekly (fixed weekday)
    assert _estimate_cron_interval_seconds("not a cron") is None
    assert _estimate_cron_interval_seconds("") is None
    assert _estimate_cron_interval_seconds(None) is None


def test_retired_job_never_reaches_degraded(hm):
    """shadow_watcher/gap_monitor's real incident: a job present in
    job_health.json but absent from the current scheduler.scheduler config
    must show RETIRED, never DEGRADED/UNHEALTHY, no matter how stale."""
    hm.config = FakeConfig(scheduler={"retro_hunter": {"enabled": True, "cron": "0 2 * * *"}})
    now = 1_000_000_000.0
    job_health_data = {"shadow_watcher": {"last_success": now - 300 * 3600}}  # 300h stale
    (Path(hm.state_dir) / "job_health.json").write_text(
        json.dumps(job_health_data), encoding="utf-8"
    )
    hm._evaluate_job_health_components(now)
    assert hm._component_state["job:shadow_watcher"]["state"] == RETIRED
    assert "300" in hm._component_state["job:shadow_watcher"]["detail"] or "no longer scheduled" in hm._component_state["job:shadow_watcher"]["detail"]


def test_disabled_scheduler_job_is_also_retired_not_degraded(hm):
    hm.config = FakeConfig(scheduler={"retro_hunter": {"enabled": False, "cron": "0 2 * * *"}})
    now = 1_000_000_000.0
    (Path(hm.state_dir) / "job_health.json").write_text(
        json.dumps({"retro_hunter": {"last_success": now - 100 * 3600}}), encoding="utf-8"
    )
    hm._evaluate_job_health_components(now)
    assert hm._component_state["job:retro_hunter"]["state"] == RETIRED


def test_active_daily_job_uses_its_own_cron_derived_threshold(hm):
    hm.config = FakeConfig(scheduler={"retro_hunter": {"enabled": True, "cron": "0 2 * * *"}})
    now = 1_000_000_000.0
    # 20h stale -- well within a daily job's 2x-cron (48h) threshold.
    (Path(hm.state_dir) / "job_health.json").write_text(
        json.dumps({"retro_hunter": {"last_success": now - 20 * 3600}}), encoding="utf-8"
    )
    hm._evaluate_job_health_components(now)
    assert hm._component_state["job:retro_hunter"]["state"] == HEALTHY


def test_active_15min_job_flags_degraded_much_sooner_than_the_old_uniform_30h(hm):
    """THE FIX: cl_afpe_flip_monitor (every 15 minutes) used to be held to the
    SAME 30h bar as a daily job -- a real failure wouldn't surface for up to
    30 hours. Now its own cron (2x = 30 minutes) catches it almost immediately."""
    hm.config = FakeConfig(scheduler={"cl_afpe_flip_monitor": {"enabled": True, "cron": "*/15 * * * *"}})
    now = 1_000_000_000.0
    (Path(hm.state_dir) / "job_health.json").write_text(
        json.dumps({"cl_afpe_flip_monitor": {"last_success": now - 3600}}), encoding="utf-8"  # 1h stale
    )
    hm._evaluate_job_health_components(now)
    assert hm._component_state["job:cl_afpe_flip_monitor"]["state"] == DEGRADED


def test_active_monthly_job_is_not_wrongly_flagged_degraded_under_the_old_uniform_30h(hm):
    """THE OTHER HALF of the fix: live_decision_archive (monthly) would show
    'degraded' ~29 days out of 30 under the old uniform 30h rule the moment it
    got a first entry. Its own cron (2x = ~60 days) correctly tolerates this."""
    hm.config = FakeConfig(scheduler={"live_decision_archive": {"enabled": True, "cron": "0 4 1 * *"}})
    now = 1_000_000_000.0
    (Path(hm.state_dir) / "job_health.json").write_text(
        json.dumps({"live_decision_archive": {"last_success": now - 20 * 86400}}), encoding="utf-8"  # 20 days
    )
    hm._evaluate_job_health_components(now)
    assert hm._component_state["job:live_decision_archive"]["state"] == HEALTHY


def test_train_fp_classifier_uses_the_autotune_schedule_cron_pair(hm):
    hm.config = FakeConfig(scheduler={}, autotune_enabled=True, autotune_schedule_cron="0 3 * * *")
    now = 1_000_000_000.0
    (Path(hm.state_dir) / "job_health.json").write_text(
        json.dumps({"train_fp_classifier": {"last_success": now - 34.8 * 3600}}), encoding="utf-8"
    )
    hm._evaluate_job_health_components(now)
    # 34.8h stale vs a daily job's 48h (2x) threshold -- still healthy, matches
    # the real .94 data this was found against (34.8h was one of the "degraded"
    # jobs under the OLD uniform-30h rule; it should NOT be degraded under a
    # correctly daily-cadence-aware 48h one).
    assert hm._component_state["job:train_fp_classifier"]["state"] == HEALTHY


def test_train_fp_classifier_retired_when_autotune_disabled(hm):
    hm.config = FakeConfig(scheduler={}, autotune_enabled=False, autotune_schedule_cron="0 3 * * *")
    now = 1_000_000_000.0
    (Path(hm.state_dir) / "job_health.json").write_text(
        json.dumps({"train_fp_classifier": {"last_success": now - 3600}}), encoding="utf-8"
    )
    hm._evaluate_job_health_components(now)
    assert hm._component_state["job:train_fp_classifier"]["state"] == RETIRED


# --- console visibility: snapshot() / _write_snapshot_file() ---------------------
# Added so the console's Health view has something to read -- without this,
# /api/health/status (running in a SEPARATE process from this HealthManager
# instance) had zero visibility into pressure level, in-process component
# heartbeats, or any state-machine state at all.

def test_apply_signal_records_detail_and_timestamp(hm):
    hm._apply_signal("comp_a", DEGRADED, "heartbeat age 12s")
    rec = hm._component_state["comp_a"]
    assert rec["detail"] == "heartbeat age 12s"
    assert rec["last_updated"] is not None


def test_snapshot_includes_every_tracked_component(hm):
    hm._apply_signal("comp_a", HEALTHY, "ok")
    hm._apply_signal("comp_b", DEGRADED, "slow")
    snap = hm.snapshot()
    assert set(snap["components"].keys()) == {"comp_a", "comp_b"}
    assert snap["components"]["comp_a"]["state"] == HEALTHY
    assert snap["components"]["comp_b"]["state"] == DEGRADED
    assert snap["components"]["comp_b"]["detail"] == "slow"
    assert "pressure_level" in snap
    assert "rss_mb" in snap
    assert "written_at" in snap


def test_write_snapshot_file_round_trips_through_disk(hm, tmp_path):
    import json
    hm._apply_signal("comp_a", HEALTHY, "ok")
    hm._write_snapshot_file()
    path = tmp_path / "health_manager_snapshot.json"
    assert path.exists()
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["components"]["comp_a"]["state"] == HEALTHY


def test_check_cycle_writes_snapshot_file(hm, tmp_path, monkeypatch):
    """Full _check_cycle() (as the real check loop calls it) must always end
    with a fresh snapshot on disk, even though most of its own sub-checks
    (psutil, file probes) are no-ops in this fake environment."""
    hm._check_cycle()
    assert (tmp_path / "health_manager_snapshot.json").exists()


# --- suricata_scan / pihole_poll: real "did it actually run" recency, distinct
# from suricata/pihole's own binary-presence/connectivity-only checks ------------
# BUGFIX (2026-09-15, console/health audit -- user report: "check if suricata ran
# properly or not, it should be visible in health... the same logic should apply
# for all other subsystems"). See _check_cycle()'s own comment for the full
# incident (56+ real hours of stalled Suricata scans earlier this session, wholly
# invisible to health because the binary/rules check alone stayed "healthy"
# throughout).

def test_check_cycle_picks_up_a_fresh_suricata_scan_heartbeat(hm, tmp_path):
    write_component_heartbeat(tmp_path, "suricata_scan", extra={"outcome": "completed"})
    hm._check_cycle()
    assert hm._component_state["suricata_scan"]["state"] == HEALTHY


def test_check_cycle_flags_a_stale_suricata_scan_heartbeat(hm, tmp_path):
    """A scan attempt from well beyond the expected interval (default 4h, so
    2x=8h/5x=20h) must surface as DEGRADED/UNHEALTHY, not silently pass."""
    old_ts = time.time() - 30 * 3600  # 30h old -- past the 5x=20h UNHEALTHY bar
    (tmp_path / "component_heartbeat.json").write_text(
        json.dumps({"suricata_scan": {"last_heartbeat": old_ts, "last_success": old_ts, "outcome": "completed"}}),
        encoding="utf-8",
    )
    hm._check_cycle()
    assert hm._component_state["suricata_scan"]["state"] == UNHEALTHY


def test_check_cycle_picks_up_a_fresh_pihole_poll_heartbeat(hm, tmp_path):
    write_component_heartbeat(tmp_path, "pihole_poll", extra={"new_rows": 12})
    hm._check_cycle()
    assert hm._component_state["pihole_poll"]["state"] == HEALTHY


def test_suricata_binary_check_and_scan_recency_are_tracked_as_separate_components(hm, tmp_path, monkeypatch):
    """THE ACTUAL FIX: these must be two INDEPENDENT components, never merged,
    so a healthy binary can't mask a stalled scan (or vice versa) -- matches the
    real incident where check_suricata_health() stayed green the whole time."""
    monkeypatch.setattr(hm_module.HealthManager, "_check_suricata", lambda self: (True, "binary OK"))
    # No suricata_scan heartbeat written at all -- cold-boot grace period, per
    # _evaluate_heartbeat_component()'s own documented "entry is None -> no-op."
    hm._check_cycle()
    assert hm._component_state["suricata"]["state"] == HEALTHY
    assert "suricata_scan" not in hm._component_state  # cold boot -- not yet alarmed, not faked healthy either


# --- _describe_disabled_reason / _check_suricata's "disabled" detail text ------
# BUGFIX (2026-09-16, user report: "in health, suricata is shown disabled").
# Confirmed live on .94: NOT a bug in the disable decision itself -- the box was
# genuinely at pressure_level=conservation and _apply_pressure_level() had
# correctly auto-disabled reactive_capture_suricata_enabled via the exact same
# config-override channel the console's manual toggles use. The real problem
# was the bare word "disabled" giving the operator no way to tell "you turned
# this off" from "the system throttled itself under memory pressure and will
# re-enable automatically" -- these tests cover that distinction.

def test_describe_disabled_reason_no_overrides_file_at_all(tmp_path):
    hm = HealthManager(config=FakeConfig(overrides_path=tmp_path / "does_not_exist.json"),
                          alert_manager=FakeAlertManager(), state_dir=str(tmp_path))
    reason = hm._describe_disabled_reason("reactive_capture_suricata_enabled")
    assert "config.yaml" in reason


def test_describe_disabled_reason_operator_console_override(tmp_path):
    overrides_path = tmp_path / "config_overrides.json"
    overrides_path.write_text(json.dumps({
        "reactive_capture_suricata_enabled": {
            "value": False, "baseline": True, "set_at": time.time(),
            "set_by": "console_ui", "reason": "manual",
        },
    }), encoding="utf-8")
    hm = HealthManager(config=FakeConfig(overrides_path=overrides_path),
                          alert_manager=FakeAlertManager(), state_dir=str(tmp_path))
    reason = hm._describe_disabled_reason("reactive_capture_suricata_enabled")
    assert "operator override" in reason
    assert "auto-disabled" not in reason  # must not be mislabeled as automatic


def test_describe_disabled_reason_health_manager_auto_disable_names_current_pressure(tmp_path):
    """THE CORE FIX: an entry set_by='health_manager' (the exact shape
    _set_config_override() writes) must be labeled as automatic resource-
    pressure throttling, name the CURRENT pressure level, and say it
    self-recovers -- not read as an unexplained fault."""
    overrides_path = tmp_path / "config_overrides.json"
    set_at = time.time() - 3600
    overrides_path.write_text(json.dumps({
        "reactive_capture_suricata_enabled": {
            "value": False, "baseline": True, "set_at": set_at,
            "set_by": "health_manager", "reason": "resource pressure",
        },
    }), encoding="utf-8")
    hm = HealthManager(config=FakeConfig(overrides_path=overrides_path),
                          alert_manager=FakeAlertManager(), state_dir=str(tmp_path))
    hm._pressure_state = "conservation"
    reason = hm._describe_disabled_reason("reactive_capture_suricata_enabled")
    assert "auto-disabled" in reason
    assert "conservation" in reason
    assert "automatically" in reason  # says it self-recovers, not stuck forever


def test_check_suricata_disabled_detail_includes_the_reason(tmp_path):
    """End-to-end: _check_suricata() itself (not just the helper in isolation)
    produces the full, explained detail string an operator actually sees in
    the console -- the exact real .94 shape (config says enabled=True at
    baseline, but health_manager's own override currently reads False)."""
    overrides_path = tmp_path / "config_overrides.json"
    overrides_path.write_text(json.dumps({
        "reactive_capture_suricata_enabled": {
            "value": False, "baseline": True, "set_at": time.time(),
            "set_by": "health_manager", "reason": "resource pressure",
        },
    }), encoding="utf-8")
    hm = HealthManager(
        config=FakeConfig(overrides_path=overrides_path, reactive_capture_suricata_enabled=False),
        alert_manager=FakeAlertManager(), state_dir=str(tmp_path),
    )
    hm._pressure_state = "conservation"
    healthy, detail = hm._check_suricata()
    assert healthy is True  # still correctly non-alarming -- a throttle, not a fault
    assert detail.startswith("disabled")
    assert "resource-pressure" in detail


def test_describe_disabled_reason_survives_a_corrupt_overrides_file(tmp_path):
    """Never lets a diagnostic-clarity nicety become a health-check failure --
    a corrupt/unreadable overrides file degrades to an empty suffix, not an
    exception bubbling out of _check_suricata()."""
    overrides_path = tmp_path / "config_overrides.json"
    overrides_path.write_text("{not valid json", encoding="utf-8")
    hm = HealthManager(config=FakeConfig(overrides_path=overrides_path),
                          alert_manager=FakeAlertManager(), state_dir=str(tmp_path))
    reason = hm._describe_disabled_reason("reactive_capture_suricata_enabled")
    assert reason == ""


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
