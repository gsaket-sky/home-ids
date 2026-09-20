"""
Tests for core/health_manager.py's memory-diagnostics capture (memory-restart
root-cause investigation, 2026-09-20) -- a tracemalloc + gc snapshot taken at
the one moment it matters most: an ESCALATING transition into CONSERVATION or
CRITICAL resource pressure, since a sustained CRITICAL streak can trigger a
self-restart within a few cycles that would otherwise erase every clue about
what was actually holding memory.

psutil is fully monkeypatched (same pattern as test_resource_pressure_modes.py)
so these tests never depend on the real machine's actual memory state.
"""
import json
import sqlite3
import sys
import tracemalloc
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core import health_manager as hm_module  # noqa: E402
from core.health_manager import HealthManager  # noqa: E402


# --- fake psutil, same shape as test_resource_pressure_modes.py's own ------------

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


class _FakeSystemProcess:
    """Simulates one entry from psutil.process_iter(['name']) -- .info is how
    real psutil exposes attrs requested at iteration time, without a second
    round-trip syscall per process."""
    def __init__(self, name, rss_mb, raises=None):
        self.info = {"name": name}
        self._rss_mb = rss_mb
        self._raises = raises  # an Exception class/instance to raise from memory_info(), simulating AccessDenied/ZombieProcess/etc.

    def memory_info(self):
        if self._raises:
            raise self._raises
        return _MemInfo(self._rss_mb)


class _FakeChildProcess:
    def __init__(self, pid, cmdline, rss_mb, raises=None):
        self.pid = pid
        self._cmdline = cmdline
        self._rss_mb = rss_mb
        self._raises = raises

    def cmdline(self):
        return self._cmdline

    def name(self):
        return self._cmdline[-1] if self._cmdline else "?"

    def memory_info(self):
        if self._raises:
            raise self._raises
        return _MemInfo(self._rss_mb)


class _FakeSchedulerParentProcess:
    def __init__(self, children):
        self._children = children

    def children(self, recursive=False):
        return self._children


class FakePsutil:
    def __init__(self):
        self.state = {"rss_mb": 100.0, "sysmem_pct": 10.0, "swap_pct": 0.0, "available_mb": 8000.0}
        self.system_processes = []  # list of _FakeSystemProcess, for process_iter()
        self.scheduler_pid = None
        self.scheduler_children = []  # list of _FakeChildProcess

    def Process(self, pid=None):
        if pid is not None and pid == self.scheduler_pid:
            return _FakeSchedulerParentProcess(self.scheduler_children)
        return _FakeProcess(self.state)

    def virtual_memory(self):
        return _VM(self.state["sysmem_pct"], self.state["available_mb"])

    def swap_memory(self):
        return _Swap(self.state["swap_pct"])

    def process_iter(self, attrs=None):
        return iter(self.system_processes)


@pytest.fixture
def fake_psutil(monkeypatch):
    fp = FakePsutil()
    monkeypatch.setattr(hm_module, "psutil", fp)
    return fp


class FakeConfig:
    def __init__(self, tmp_path, **overrides):
        self._data = {
            "health_manager_rss_pressure_mb": 1024.0,
            "health_manager_rss_conservation_mb": 1536.0,
            "health_manager_rss_critical_mb": 1843.0,
            "health_manager_swap_conservation_pct": 60.0,
            "health_manager_sysmem_pressure_pct": 75.0,
            "health_manager_min_available_mb": 512.0,
            "health_manager_critical_sustain_checks": 3,
            "health_manager_auto_recovery_enabled": True,
            "health_manager_memory_diagnostics_enabled": True,
            "telegram_enabled": False,
        }
        self._data.update(overrides)
        self._overrides_path = tmp_path / "config_overrides.json"

    def get(self, key, default=None):
        return self._data.get(key, default)


class FakeAlertManager:
    def __init__(self):
        self.sent = []

    def send(self, message, **kwargs):
        self.sent.append(message)


@pytest.fixture
def hm(fake_psutil, tmp_path):
    return HealthManager(config=FakeConfig(tmp_path), alert_manager=FakeAlertManager(), state_dir=str(tmp_path))


@pytest.fixture(autouse=True)
def tracing():
    """Simulates main.py's own tracemalloc.start() at process boot -- without
    this, tracemalloc.is_tracing() is False and every capture is a no-op by
    design (see _capture_memory_diagnostics()'s own early-return comment)."""
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    yield
    if not was_tracing:
        tracemalloc.stop()


def _read_diagnostics(tmp_path):
    path = tmp_path / "memory_diagnostics.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --- when a capture fires -----------------------------------------------------

def test_escalating_to_conservation_captures_diagnostics(hm, fake_psutil, tmp_path):
    fake_psutil.state.update(rss_mb=1600)  # crosses the 1536 conservation floor
    hm._evaluate_resource_pressure()
    entries = _read_diagnostics(tmp_path)
    assert len(entries) == 1
    assert entries[0]["pressure_level"] == "conservation"


def test_escalating_to_critical_captures_diagnostics(hm, fake_psutil, tmp_path):
    fake_psutil.state.update(rss_mb=2000)
    hm._evaluate_resource_pressure()
    entries = _read_diagnostics(tmp_path)
    assert len(entries) == 1
    assert entries[0]["pressure_level"] == "critical"


def test_escalating_only_to_resource_pressure_does_not_capture(hm, fake_psutil, tmp_path):
    # Crosses the 1024 pressure floor but stays well under conservation (1536) --
    # this tier has no destructive consequence, capturing here would just be noise.
    fake_psutil.state.update(rss_mb=1100)
    hm._evaluate_resource_pressure()
    assert _read_diagnostics(tmp_path) == []


def test_deescalating_back_to_normal_does_not_capture(hm, fake_psutil, tmp_path):
    fake_psutil.state.update(rss_mb=2000)
    hm._evaluate_resource_pressure()  # captures once, entering critical
    fake_psutil.state.update(rss_mb=100)
    hm._evaluate_resource_pressure()  # de-escalating back to normal
    assert len(_read_diagnostics(tmp_path)) == 1  # still just the one from entering


def test_staying_at_the_same_level_does_not_capture_again(hm, fake_psutil, monkeypatch, tmp_path):
    # 3 consecutive CRITICAL reads hits health_manager_critical_sustain_checks'
    # default of 3, which would otherwise invoke the REAL resource_pressure
    # action -- monkeypatched to a no-op, same precedent as
    # test_resource_pressure_modes.py's own sustained-critical tests.
    monkeypatch.setitem(hm_module.ACTIONS, "resource_pressure", lambda h, c: (True, "x"))
    fake_psutil.state.update(rss_mb=2000)
    hm._evaluate_resource_pressure()
    hm._evaluate_resource_pressure()
    hm._evaluate_resource_pressure()
    assert len(_read_diagnostics(tmp_path)) == 1  # only the FIRST transition captured


def test_config_disabled_never_captures_even_on_critical_escalation(fake_psutil, tmp_path):
    h = HealthManager(
        config=FakeConfig(tmp_path, health_manager_memory_diagnostics_enabled=False),
        alert_manager=FakeAlertManager(), state_dir=str(tmp_path),
    )
    fake_psutil.state.update(rss_mb=2000)
    h._evaluate_resource_pressure()
    assert _read_diagnostics(tmp_path) == []


# --- entry shape and correctness ----------------------------------------------

def test_captured_entry_has_the_expected_shape(hm, fake_psutil, tmp_path):
    fake_psutil.state.update(rss_mb=2000)
    hm._evaluate_resource_pressure()
    entry = _read_diagnostics(tmp_path)[0]
    assert "timestamp" in entry
    assert "process_rss_mb" in entry and "main" in entry["process_rss_mb"]
    assert isinstance(entry["top_allocations"], list)
    assert isinstance(entry["top_object_types"], list)
    assert entry["top_object_types"]  # gc.get_objects() is never empty in a real process
    assert "graph_db" in entry


def test_graph_db_stats_reads_real_size_and_row_counts(hm, tmp_path):
    db_path = tmp_path / "v13_graph.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE decisions (decision_id TEXT)")
    conn.execute("CREATE TABLE edges (edge_id INTEGER)")
    conn.execute("INSERT INTO decisions VALUES ('a'), ('b')")
    conn.execute("INSERT INTO edges VALUES (1), (2), (3)")
    conn.commit()
    conn.close()
    stats = hm._graph_db_diagnostic_stats()
    assert stats["decisions_rows"] == 2
    assert stats["edges_rows"] == 3
    assert stats["size_mb"] >= 0  # a tiny synthetic db can legitimately round to 0.0 MB
    assert db_path.stat().st_size > 0  # the real, unrounded check that the file has content


def test_graph_db_stats_is_empty_dict_when_no_db_exists(hm):
    assert hm._graph_db_diagnostic_stats() == {}


def test_not_tracing_is_a_safe_noop(hm, fake_psutil, tmp_path):
    tracemalloc.stop()  # simulates the config flag having been off at process startup
    fake_psutil.state.update(rss_mb=2000)
    hm._evaluate_resource_pressure()  # must not raise
    assert _read_diagnostics(tmp_path) == []
    tracemalloc.start()  # restore for the autouse fixture's own teardown bookkeeping


def test_a_failure_inside_capture_never_propagates_to_the_real_pressure_logic(hm, fake_psutil, monkeypatch):
    def _boom(*a, **kw):
        raise RuntimeError("simulated failure")
    monkeypatch.setattr(hm, "_graph_db_diagnostic_stats", _boom)
    fake_psutil.state.update(rss_mb=2000)
    hm._evaluate_resource_pressure()  # must not raise -- best-effort by design
    assert hm._pressure_state == "critical"  # the REAL pressure-response logic still ran


# --- bounded rotation ------------------------------------------------------------

def test_diagnostics_file_is_bounded_not_unbounded(hm, fake_psutil, tmp_path, monkeypatch):
    monkeypatch.setattr(hm_module.HealthManager, "_MAX_DIAGNOSTIC_ENTRIES", 3)
    for i in range(6):
        fake_psutil.state.update(rss_mb=2000)
        hm._evaluate_resource_pressure()
        fake_psutil.state.update(rss_mb=100)
        hm._evaluate_resource_pressure()
    entries = _read_diagnostics(tmp_path)
    assert len(entries) == 3  # 6 escalations happened, but the file never grows past the cap


# --- external component RSS attribution (2026-09-20, explicit user request) ------

def test_external_components_are_matched_and_summed(hm, fake_psutil):
    fake_psutil.system_processes = [
        _FakeSystemProcess("zeek", 150.0),
        _FakeSystemProcess("bash", 5.0),  # the zeekctl wrapper -- must NOT be counted as zeek
        _FakeSystemProcess("prometheus", 80.0),
        _FakeSystemProcess("prometheus-node-e", 20.0),  # truncated comm, still prometheus-node-exporter
        _FakeSystemProcess("promtail", 30.0),
        _FakeSystemProcess("loki", 60.0),
    ]
    totals = hm._external_component_rss_mb()
    assert totals["zeek"] == 150.0
    assert "bash" not in totals
    assert totals["prometheus"] == 80.0
    assert totals["prometheus_node_exporter"] == 20.0
    assert totals["promtail"] == 30.0
    assert totals["loki"] == 60.0


def test_grafana_plugin_subprocesses_are_summed_into_one_total(hm, fake_psutil):
    # Real shape found live on .94: 14 separate gpx_*-named plugin processes,
    # none of which contain "grafana" in their own process name at all.
    fake_psutil.system_processes = [
        _FakeSystemProcess("grafana", 100.0),
        _FakeSystemProcess("gpx_grafana-pro", 15.0),
        _FakeSystemProcess("gpx_sqlite-data", 10.0),
        _FakeSystemProcess("gpx_grafana-lok", 12.0),
    ]
    totals = hm._external_component_rss_mb()
    assert totals["grafana"] == 137.0  # 100 + 15 + 10 + 12, all four bucketed together


def test_grafanas_loki_plugin_does_not_get_double_counted_as_loki(hm, fake_psutil):
    # gpx_grafana-lok's own comm is truncated and contains "lok", but this
    # must land ONLY in "grafana" (via the gpx_ prefix), never also in "loki"
    # (which matches on EXACT name -- this is exactly the false-positive risk
    # a naive substring match would have hit).
    fake_psutil.system_processes = [_FakeSystemProcess("gpx_grafana-lok", 12.0)]
    totals = hm._external_component_rss_mb()
    assert totals.get("loki") is None
    assert totals["grafana"] == 12.0


def test_ollama_absent_today_reports_nothing_not_zero(hm, fake_psutil):
    fake_psutil.system_processes = [_FakeSystemProcess("zeek", 150.0)]
    totals = hm._external_component_rss_mb()
    assert "ollama" not in totals  # confirmed not installed on .94 -- absent, not a fabricated 0.0


def test_a_zombie_or_access_denied_process_is_skipped_not_fatal(hm, fake_psutil):
    fake_psutil.system_processes = [
        _FakeSystemProcess("suricata", 0.0, raises=ProcessLookupError("zombie")),
        _FakeSystemProcess("zeek", 150.0),
    ]
    totals = hm._external_component_rss_mb()
    assert "suricata" not in totals
    assert totals["zeek"] == 150.0


def test_external_component_scan_failure_is_a_safe_empty_result(hm, monkeypatch):
    def _boom(*a, **kw):
        raise RuntimeError("simulated psutil failure")
    monkeypatch.setattr(hm_module.psutil, "process_iter", _boom)
    assert hm._external_component_rss_mb() == {}


def test_captured_entry_includes_external_components(hm, fake_psutil, tmp_path):
    fake_psutil.system_processes = [_FakeSystemProcess("zeek", 150.0)]
    fake_psutil.state.update(rss_mb=2000)
    hm._evaluate_resource_pressure()
    entry = _read_diagnostics(tmp_path)[0]
    assert entry["process_rss_mb"]["zeek"] == 150.0
    assert entry["process_rss_mb"]["main"] == 2000.0  # the existing "main" key still present


# --- active scheduled job attribution ---------------------------------------------

class _FakeSchedulerProc:
    def __init__(self, pid):
        self.pid = pid


def test_no_scheduler_proc_returns_empty_list(hm):
    assert hm._active_scheduled_job_processes() == []


def test_active_scheduled_job_is_reported_by_script_name(fake_psutil, tmp_path):
    fake_psutil.scheduler_pid = 999
    fake_psutil.scheduler_children = [
        _FakeChildProcess(1001, ["python3", "src/argus/ops/live_llm_review.py"], 45.0),
    ]
    h = HealthManager(config=FakeConfig(tmp_path), alert_manager=FakeAlertManager(),
                        state_dir=str(tmp_path), scheduler_proc=_FakeSchedulerProc(999))
    jobs = h._active_scheduled_job_processes()
    assert len(jobs) == 1
    assert jobs[0]["script"] == "src/argus/ops/live_llm_review.py"
    assert jobs[0]["rss_mb"] == 45.0
    assert jobs[0]["pid"] == 1001


def test_no_active_scheduled_jobs_is_an_empty_list_not_an_error(fake_psutil, tmp_path):
    fake_psutil.scheduler_pid = 999
    fake_psutil.scheduler_children = []
    h = HealthManager(config=FakeConfig(tmp_path), alert_manager=FakeAlertManager(),
                        state_dir=str(tmp_path), scheduler_proc=_FakeSchedulerProc(999))
    assert h._active_scheduled_job_processes() == []


def test_a_failing_child_process_lookup_is_skipped_not_fatal(fake_psutil, tmp_path):
    fake_psutil.scheduler_pid = 999
    fake_psutil.scheduler_children = [
        _FakeChildProcess(1001, ["python3", "src/argus/ops/backtest_job.py"], 0.0, raises=ProcessLookupError("gone")),
        _FakeChildProcess(1002, ["python3", "src/argus/ops/live_prune.py"], 30.0),
    ]
    h = HealthManager(config=FakeConfig(tmp_path), alert_manager=FakeAlertManager(),
                        state_dir=str(tmp_path), scheduler_proc=_FakeSchedulerProc(999))
    jobs = h._active_scheduled_job_processes()
    assert len(jobs) == 1
    assert jobs[0]["script"] == "src/argus/ops/live_prune.py"


def test_captured_entry_includes_active_scheduled_jobs(fake_psutil, tmp_path):
    fake_psutil.scheduler_pid = 999
    fake_psutil.scheduler_children = [
        _FakeChildProcess(1001, ["python3", "src/argus/ops/live_llm_review.py"], 45.0),
    ]
    h = HealthManager(config=FakeConfig(tmp_path), alert_manager=FakeAlertManager(),
                        state_dir=str(tmp_path), scheduler_proc=_FakeSchedulerProc(999))
    fake_psutil.state.update(rss_mb=2000)
    h._evaluate_resource_pressure()
    entry = _read_diagnostics(tmp_path)[0]
    assert entry["active_scheduled_jobs"] == [{"script": "src/argus/ops/live_llm_review.py", "pid": 1001, "rss_mb": 45.0}]
