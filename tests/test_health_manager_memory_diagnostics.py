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


class FakePsutil:
    def __init__(self):
        self.state = {"rss_mb": 100.0, "sysmem_pct": 10.0, "swap_pct": 0.0, "available_mb": 8000.0}

    def Process(self, pid=None):
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
