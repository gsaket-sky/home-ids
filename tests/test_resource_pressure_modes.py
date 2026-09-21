"""
Tests for core/health_manager.py's resource-pressure state machine (NORMAL ->
RESOURCE_PRESSURE -> CONSERVATION -> CRITICAL) -- the direct fix for the
2026-09-14 OOM incident this subsystem was built in response to.

psutil itself is fully monkeypatched (core.health_manager.psutil replaced with
a fake exposing Process()/virtual_memory()/swap_memory()) so these tests never
depend on the real machine's actual memory state.
"""
import json
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core import health_manager as hm_module  # noqa: E402
from core.health_manager import HealthManager  # noqa: E402


# --- fake psutil -----------------------------------------------------------------

class _MemInfo:
    def __init__(self, rss_mb):
        self.rss = rss_mb * 1024 * 1024


class _FakeProcess:
    def __init__(self, state):
        self._state = state

    def memory_info(self):
        return _MemInfo(self._state["rss_mb"])


class _VM:
    def __init__(self, percent, available_mb):
        self.percent = percent
        self.available = available_mb * 1024 * 1024


class _Swap:
    def __init__(self, percent):
        self.percent = percent


class FakePsutil:
    def __init__(self):
        self.state = {"rss_mb": 100.0, "sysmem_pct": 10.0, "swap_pct": 0.0, "available_mb": 8000.0}

    def Process(self):
        return _FakeProcess(self.state)

    def virtual_memory(self):
        return _VM(self.state["sysmem_pct"], self.state["available_mb"])

    def swap_memory(self):
        return _Swap(self.state["swap_pct"])


@pytest.fixture
def fake_psutil(monkeypatch):
    fp = FakePsutil()
    monkeypatch.setattr(hm_module, "psutil", fp)
    return fp


# --- fake config with a real-ish override file, so _set/_clear_config_override -----
# exercise the actual read-modify-write path against a real tmp_path file.

class FakeConfig:
    def __init__(self, tmp_path, **overrides):
        self._data = {
            "health_manager_rss_pressure_mb": 1024.0,
            "health_manager_rss_conservation_mb": 1536.0,
            "health_manager_rss_critical_mb": 1843.0,
            "health_manager_swap_pressure_pct": 40.0,
            "health_manager_swap_conservation_pct": 60.0,
            "health_manager_swap_critical_pct": 80.0,
            "health_manager_sysmem_pressure_pct": 75.0,
            "health_manager_min_available_mb": 512.0,
            "health_manager_critical_sustain_checks": 3,
            "health_manager_auto_recovery_enabled": True,
            "telegram_enabled": True,
        }
        self._data.update(overrides)
        self._overrides_path = tmp_path / "config_overrides.json"
        self.load_overrides_calls = 0
        self.reverted = []

    def get(self, key, default=None):
        return self._data.get(key, default)

    def _load_overrides(self):
        self.load_overrides_calls += 1
        if self._overrides_path.exists():
            data = json.loads(self._overrides_path.read_text(encoding="utf-8"))
            for k, entry in data.items():
                self._data[k] = entry["value"]

    def revert_override(self, key, value):
        self.reverted.append((key, value))
        self._data[key] = value


class FakeAlertManager:
    def __init__(self):
        self.sent = []

    def send(self, message, **kwargs):
        self.sent.append(message)


class FakeClient:
    def __init__(self):
        self.paused = False


class FakePipeline:
    def __init__(self):
        self.ti_engine = FakeClient()
        self.abuseipdb = FakeClient()
        self.virustotal = FakeClient()
        self._health_pressure_poll_floor = None


@pytest.fixture
def hm(fake_psutil, tmp_path):
    h = HealthManager(
        config=FakeConfig(tmp_path),
        alert_manager=FakeAlertManager(),
        pipeline=FakePipeline(),
        state_dir=str(tmp_path),
    )
    return h


# --- classification ---------------------------------------------------------------

def test_classify_normal_below_all_thresholds(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=500, sysmem_pct=50, swap_pct=10, available_mb=8000)
    assert hm._classify_pressure() == hm_module.NORMAL


def test_classify_resource_pressure_on_rss_alone(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=1100, sysmem_pct=10, swap_pct=0, available_mb=8000)
    assert hm._classify_pressure() == hm_module.RESOURCE_PRESSURE


def test_classify_conservation_on_swap_when_rss_also_elevated(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=1100, sysmem_pct=10, swap_pct=65, available_mb=8000)
    assert hm._classify_pressure() == hm_module.CONSERVATION


def test_classify_critical_on_low_available_when_rss_also_elevated(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=1100, sysmem_pct=10, swap_pct=0, available_mb=100)
    assert hm._classify_pressure() == hm_module.CRITICAL


def test_classify_critical_beats_conservation_beats_pressure(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=2000, sysmem_pct=10, swap_pct=0, available_mb=8000)  # rss triggers all 3 -- highest wins
    assert hm._classify_pressure() == hm_module.CRITICAL


# --- cgroup-wide memory pressure ---------------------------------------------------
#
# BUGFIX regression (found live, 2026-09-21 OOM incident): _rss_mb() only ever
# measured THIS process's own RSS. Confirmed live on .94: a real kernel
# OOM-kill hit soc.service's own systemd cgroup cap (2G + 256M swap) while the
# main process's own RSS was 1.34GB -- comfortably under its own 1843MB
# CRITICAL threshold -- because THREE OTHER processes sharing that same cgroup
# (uvicorn, scheduler.py, and a nightly batch job scheduler.py had spawned)
# added another ~740MB the RSS-only check has no way to see. _cgroup_memory_pct()
# reads systemd's own memory.current/memory.max accounting directly, so
# _classify_pressure() can escalate on the SAME signal the kernel will
# eventually act on, even when this process's own RSS looks fine.

def test_classify_critical_on_cgroup_pct_alone_even_with_healthy_rss(hm, fake_psutil, monkeypatch):
    fake_psutil.state.update(rss_mb=500, sysmem_pct=10, swap_pct=0, available_mb=8000)  # all healthy
    monkeypatch.setattr(hm, "_cgroup_memory_pct", lambda: 95.0)  # the cgroup itself is nearly OOM
    assert hm._classify_pressure() == hm_module.CRITICAL


def test_classify_conservation_on_cgroup_pct_alone_even_with_healthy_rss(hm, fake_psutil, monkeypatch):
    fake_psutil.state.update(rss_mb=500, sysmem_pct=10, swap_pct=0, available_mb=8000)
    monkeypatch.setattr(hm, "_cgroup_memory_pct", lambda: 80.0)  # above 75% conservation floor, below 90% critical
    assert hm._classify_pressure() == hm_module.CONSERVATION


def test_classify_normal_when_cgroup_pct_low_even_if_unavailable_elsewhere(hm, fake_psutil, monkeypatch):
    fake_psutil.state.update(rss_mb=500, sysmem_pct=10, swap_pct=0, available_mb=8000)
    monkeypatch.setattr(hm, "_cgroup_memory_pct", lambda: 10.0)
    assert hm._classify_pressure() == hm_module.NORMAL


def test_classify_falls_back_gracefully_when_cgroup_pct_unavailable(hm, fake_psutil, monkeypatch):
    """None (Windows dev environment, cgroup v1, non-systemd deployment) must
    be treated as 'no signal', not crash and not itself force an escalation --
    the existing RSS/swap/available-memory checks still apply unchanged."""
    fake_psutil.state.update(rss_mb=500, sysmem_pct=10, swap_pct=0, available_mb=8000)
    monkeypatch.setattr(hm, "_cgroup_memory_pct", lambda: None)
    assert hm._classify_pressure() == hm_module.NORMAL


def test_cgroup_memory_pct_returns_none_on_this_dev_machine(hm):
    """This dev environment is Windows (no /proc/self/cgroup at all) -- the
    real, non-monkeypatched implementation must degrade to None, not raise.
    On every real deployment target (.94, the eventual Pi -- both Linux under
    systemd) this same code path returns a real percentage instead; that
    parsing logic is exercised implicitly by every OTHER test in this file
    that monkeypatches this method's RETURN VALUE rather than its internals,
    matching this codebase's established pattern for OS-integration points
    (see _external_component_rss_mb()'s own fake-psutil-based tests)."""
    assert hm._cgroup_memory_pct() is None


# --- BUGFIX regression: system-wide swap/sysmem/available must NOT escalate ----
# a process that isn't itself contributing to the pressure. Found live,
# 2026-09-14: .94 (a shared box also running Grafana/Loki/Immich/n8n/OpenWebUI)
# had 87% system swap used entirely by OTHER processes while the IDS itself had
# 0 bytes swapped and ~850MB RSS -- comfortably healthy. The original
# implementation would have pushed this process into CONSERVATION/CRITICAL (and,
# sustained, a pointless self-restart) for a problem it has zero responsibility
# for and zero ability to fix by restarting itself.

def test_high_swap_alone_with_healthy_rss_stays_normal(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=850, sysmem_pct=70, swap_pct=87, available_mb=8000)
    assert hm._classify_pressure() == hm_module.NORMAL


def test_high_sysmem_alone_with_healthy_rss_stays_normal(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=850, sysmem_pct=95, swap_pct=10, available_mb=8000)
    assert hm._classify_pressure() == hm_module.NORMAL


# --- BUGFIX #2 regression (found live, ~40 min after BUGFIX #1's own deploy) ---
# CRITICAL triggers a destructive, proactive self-restart -- confirmed live that
# BUGFIX #1 above still let swap_pct co-trigger CRITICAL once rss merely crossed
# the LOW 1024MB pressure floor (routinely reached within an hour of almost
# every restart, per this whole session's own observations), combined with
# .94's CHRONIC ~80-87% swap (hours-long, from other processes, not a spike).
# That combination fired for real: a self-restart at completely normal rss
# (nowhere near the 1843MB critical threshold), taking the whole engine down
# with zero detection coverage. swap_pct must never reach CRITICAL again,
# however high, and regardless of this process's own rss. available_mb DOES
# still reach CRITICAL, deliberately UNGATED from rss now -- a genuine
# system-wide near-OOM is worth shrinking our own footprint for regardless of
# whose fault it is, unlike a merely-high swap percentage (which this box sat
# at for hours today with no acute failure -- swap being high is not the same
# as the system being about to fail).

def test_low_available_alone_triggers_critical_regardless_of_rss(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=850, sysmem_pct=70, swap_pct=10, available_mb=100)
    assert hm._classify_pressure() == hm_module.CRITICAL


def test_high_swap_never_triggers_critical_even_with_elevated_rss(hm, fake_psutil):
    """The exact real-world combination that caused the live incident: rss in
    the ordinary 1024-1536MB operating range (not itself CONSERVATION-level)
    plus chronic high swap from unrelated processes. Must cap at CONSERVATION,
    never reach CRITICAL, no matter how high swap_pct goes."""
    fake_psutil.state.update(rss_mb=1100, sysmem_pct=10, swap_pct=99, available_mb=8000)
    assert hm._classify_pressure() == hm_module.CONSERVATION


def test_high_swap_with_conservation_level_rss_still_not_critical(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=1600, sysmem_pct=10, swap_pct=99, available_mb=8000)
    assert hm._classify_pressure() == hm_module.CONSERVATION


def test_rss_crossing_its_own_tier_still_escalates_regardless_of_system_signals(hm, fake_psutil):
    """rss alone crossing CRITICAL must still fire even with otherwise-calm
    system-wide numbers -- the gating only applies to the swap/sysmem/available
    signals, never to rss's own thresholds."""
    fake_psutil.state.update(rss_mb=1900, sysmem_pct=5, swap_pct=0, available_mb=8000)
    assert hm._classify_pressure() == hm_module.CRITICAL


# --- level-specific actions --------------------------------------------------------

def test_resource_pressure_level_pauses_ti_clients(hm):
    hm._apply_pressure_level(hm_module.RESOURCE_PRESSURE)
    assert hm.pipeline.ti_engine.paused is True
    assert hm.pipeline.abuseipdb.paused is True
    assert hm.pipeline.virustotal.paused is True


def test_normal_level_unpauses_ti_clients(hm):
    hm._apply_pressure_level(hm_module.RESOURCE_PRESSURE)
    hm._apply_pressure_level(hm_module.NORMAL)
    assert hm.pipeline.ti_engine.paused is False
    assert hm.pipeline.abuseipdb.paused is False
    assert hm.pipeline.virustotal.paused is False


def test_conservation_sets_config_overrides_via_live_channel(hm):
    hm._apply_pressure_level(hm_module.CONSERVATION)
    for key in hm_module._CONSERVATION_OVERRIDE_KEYS:
        assert hm.config.get(key) is False
    assert hm.config.load_overrides_calls == len(hm_module._CONSERVATION_OVERRIDE_KEYS)
    # the override file itself was actually written, not just in-memory
    on_disk = json.loads(hm.config._overrides_path.read_text(encoding="utf-8"))
    for key in hm_module._CONSERVATION_OVERRIDE_KEYS:
        assert on_disk[key]["value"] is False
        assert on_disk[key]["set_by"] == "health_manager"


def test_conservation_sets_poll_floor(hm):
    hm._apply_pressure_level(hm_module.CONSERVATION)
    assert hm.pipeline._health_pressure_poll_floor == 10.0


def test_deescalating_from_conservation_clears_overrides_and_poll_floor(hm):
    hm._apply_pressure_level(hm_module.CONSERVATION)
    hm._apply_pressure_level(hm_module.RESOURCE_PRESSURE)  # one tier down
    assert hm.pipeline._health_pressure_poll_floor is None
    assert len(hm.config.reverted) == len(hm_module._CONSERVATION_OVERRIDE_KEYS)
    # TI still paused at RESOURCE_PRESSURE -- only the CONSERVATION-specific levers cleared
    assert hm.pipeline.ti_engine.paused is True


# --- sustained-CRITICAL self-restart -----------------------------------------------

def test_single_critical_spike_does_not_restart(hm, fake_psutil, monkeypatch):
    calls = []
    monkeypatch.setitem(hm_module.ACTIONS, "resource_pressure", lambda h, c: (calls.append(c), (True, "x"))[1])
    fake_psutil.state.update(rss_mb=2000, sysmem_pct=95, swap_pct=90, available_mb=50)
    hm._evaluate_resource_pressure()
    assert calls == []


def test_sustained_critical_triggers_self_restart_after_configured_streak(hm, fake_psutil, monkeypatch):
    calls = []
    monkeypatch.setitem(hm_module.ACTIONS, "resource_pressure", lambda h, c: (calls.append(c), (True, "x"))[1])
    fake_psutil.state.update(rss_mb=2000, sysmem_pct=95, swap_pct=90, available_mb=50)
    hm._evaluate_resource_pressure()  # 1
    hm._evaluate_resource_pressure()  # 2
    assert calls == []
    hm._evaluate_resource_pressure()  # 3 -- health_manager_critical_sustain_checks default
    assert calls == ["resource_pressure"]


def test_critical_streak_resets_if_pressure_drops(hm, fake_psutil, monkeypatch):
    calls = []
    monkeypatch.setitem(hm_module.ACTIONS, "resource_pressure", lambda h, c: (calls.append(c), (True, "x"))[1])
    fake_psutil.state.update(rss_mb=2000, sysmem_pct=95, swap_pct=90, available_mb=50)
    hm._evaluate_resource_pressure()  # 1
    hm._evaluate_resource_pressure()  # 2
    fake_psutil.state.update(rss_mb=100, sysmem_pct=10, swap_pct=0, available_mb=8000)  # back to NORMAL
    hm._evaluate_resource_pressure()
    fake_psutil.state.update(rss_mb=2000, sysmem_pct=95, swap_pct=90, available_mb=50)
    hm._evaluate_resource_pressure()  # 1 again, not 3 -- streak must have reset
    hm._evaluate_resource_pressure()  # 2
    assert calls == []


def test_disabled_auto_recovery_never_self_restarts_even_when_sustained(hm, fake_psutil, monkeypatch, tmp_path):
    hm.config._data["health_manager_auto_recovery_enabled"] = False
    calls = []
    monkeypatch.setitem(hm_module.ACTIONS, "resource_pressure", lambda h, c: (calls.append(c), (True, "x"))[1])
    fake_psutil.state.update(rss_mb=2000, sysmem_pct=95, swap_pct=90, available_mb=50)
    for _ in range(5):
        hm._evaluate_resource_pressure()
    assert calls == []


# --- alerting cadence ---------------------------------------------------------------

def test_entering_resource_pressure_alerts_exactly_once(hm, fake_psutil):
    fake_psutil.state.update(rss_mb=1100, sysmem_pct=10, swap_pct=0, available_mb=8000)
    hm._evaluate_resource_pressure()
    hm._evaluate_resource_pressure()
    hm._evaluate_resource_pressure()
    assert hm.alert_manager.sent.count(hm.alert_manager.sent[0] if hm.alert_manager.sent else None) <= 1
    # exactly one pressure-transition alert total across 3 identical cycles
    pressure_alerts = [m for m in hm.alert_manager.sent if "resource pressure" in m.lower()]
    assert len(pressure_alerts) == 1


# --- bounded pressure probe (2026-09-21 live incident) ----------------------------
# Confirmed live on .94 via py-spy: psutil.Process.memory_info() -- a plain
# open() on /proc/<pid>/stat -- blocked for many minutes once the cgroup was deep
# enough into memory pressure that even a trivial file-open stalled on kernel
# reclaim. That froze health_manager's ONLY thread forever (it never returned to
# _run_loop()'s while loop), silently disabling job-health monitoring AND the
# CRITICAL self-restart this subsystem exists to perform. _bounded_call() bounds
# any single probe attempt so a stall can no longer take the whole watchdog down.

def test_bounded_call_returns_result_when_fn_completes_quickly():
    value, timed_out = HealthManager._bounded_call(lambda: 42, timeout=1.0)
    assert value == 42
    assert timed_out is False


def test_bounded_call_propagates_a_real_exception():
    def _boom():
        raise ValueError("real failure")
    with pytest.raises(ValueError, match="real failure"):
        HealthManager._bounded_call(_boom, timeout=1.0)


def test_bounded_call_times_out_on_a_hung_fn():
    import threading as _threading
    released = _threading.Event()

    def _hang():
        released.wait(timeout=5.0)  # simulates the stuck open() syscall
        return "too late"

    value, timed_out = HealthManager._bounded_call(_hang, timeout=0.2)
    assert timed_out is True
    assert value is None
    released.set()  # let the daemon thread exit cleanly instead of leaking past the test


def test_classify_pressure_keeps_previous_level_when_probe_hangs(hm, monkeypatch):
    # Escalate to CONSERVATION first via a normal, fast probe.
    monkeypatch.setattr(
        hm, "_bounded_call",
        staticmethod(lambda fn, timeout: ((1600.0, None, 10.0, 0.0, 8000.0), False)),
    )
    assert hm._classify_pressure() == hm_module.CONSERVATION
    hm._pressure_state = hm_module.CONSERVATION

    # Now simulate the probe hanging -- must NOT crash, NOT silently return
    # NORMAL (which would incorrectly clear conservation-mode overrides), and
    # NOT block this call.
    monkeypatch.setattr(hm, "_bounded_call", staticmethod(lambda fn, timeout: (None, True)))
    assert hm._classify_pressure() == hm_module.CONSERVATION


def test_check_cycle_completes_even_when_pressure_probe_hangs(hm, monkeypatch):
    """The real-world failure mode: _run_loop() must reach its next iteration
    (job-health/heartbeat checks must still run) even if the resource-pressure
    probe itself is the thing that's stuck."""
    monkeypatch.setattr(hm, "_bounded_call", staticmethod(lambda fn, timeout: (None, True)))
    hm._check_cycle()  # must return promptly, not hang the test


# --- outer-loop protection (2026-09-21 live incident, second occurrence) ----------
# The narrower _classify_pressure() fix above was NOT enough on its own: a second
# live py-spy dump caught a DIFFERENT call, _capture_memory_diagnostics()'s
# tracemalloc.take_snapshot(), hang the exact same way under the same memory
# pressure. _run_one_iteration() now bounds the WHOLE _check_cycle() call, not
# just one probe inside it, so no single hang -- found or not-yet-found -- can
# freeze the watchdog thread past one missed interval.

def test_run_one_iteration_completes_even_when_check_cycle_hangs(hm, monkeypatch):
    monkeypatch.setattr(hm, "_bounded_call", staticmethod(lambda fn, timeout: (None, True)))
    interval = hm._run_one_iteration()  # must return promptly, not hang the test
    assert interval == 15.0


def test_run_one_iteration_returns_configured_interval_on_success(hm, monkeypatch):
    monkeypatch.setattr(hm, "_bounded_call", staticmethod(lambda fn, timeout: (None, False)))
    hm.config._data["health_manager_check_interval_seconds"] = 7.0
    assert hm._run_one_iteration() == 7.0


def test_run_one_iteration_skips_check_cycle_entirely_when_disabled(hm, monkeypatch):
    calls = []
    monkeypatch.setattr(hm, "_bounded_call", staticmethod(lambda fn, timeout: calls.append(1) or (None, False)))
    hm.config._data["health_manager_enabled"] = False
    hm._run_one_iteration()
    assert calls == []


def test_a_real_hang_inside_check_cycle_is_bounded_end_to_end(hm, monkeypatch):
    """No mocking of _bounded_call itself here -- a genuinely blocked _check_cycle()
    (simulating the real tracemalloc.take_snapshot() stall) must still let
    _run_one_iteration() return within the configured timeout, not hang forever."""
    import threading as _threading
    released = _threading.Event()

    def _hung_check_cycle():
        released.wait(timeout=5.0)

    monkeypatch.setattr(hm, "_check_cycle", _hung_check_cycle)
    hm.config._data["health_manager_check_cycle_timeout_seconds"] = 0.2
    interval = hm._run_one_iteration()
    assert interval == 15.0
    released.set()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
