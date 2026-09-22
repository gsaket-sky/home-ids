"""
Tests for core/resource_gate.py -- the pressure signal resource-aware scheduling
(Documentation/RESOURCE_AWARE_SCHEDULING.md) uses to decide whether a new scheduled
job may start. Deliberately independent from health_manager.py's own pressure
classifier (see resource_gate.py's own module docstring for why), so these tests
mock resource_gate's own probes directly rather than health_manager's.
"""
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core import resource_gate  # noqa: E402


def test_normal_when_nothing_elevated(monkeypatch):
    monkeypatch.setattr(resource_gate, "cgroup_memory_pct", lambda: 10.0)
    monkeypatch.setattr(resource_gate, "load_per_core", lambda: 0.1)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.NORMAL


def test_missing_signals_never_escalate(monkeypatch):
    """Best-effort: an unreadable cgroup file or unavailable loadavg (e.g. Windows
    dev environment) must never be treated as pressure on its own -- only an actual
    high reading escalates."""
    monkeypatch.setattr(resource_gate, "cgroup_memory_pct", lambda: None)
    monkeypatch.setattr(resource_gate, "load_per_core", lambda: None)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.NORMAL
    assert resource_gate.may_admit_new_job({}) is True


def test_cgroup_memory_drives_each_tier(monkeypatch):
    monkeypatch.setattr(resource_gate, "load_per_core", lambda: 0.0)

    monkeypatch.setattr(resource_gate, "cgroup_memory_pct", lambda: 50.0)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.NORMAL

    monkeypatch.setattr(resource_gate, "cgroup_memory_pct", lambda: 65.0)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.RESOURCE_PRESSURE

    monkeypatch.setattr(resource_gate, "cgroup_memory_pct", lambda: 80.0)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.CONSERVATION

    monkeypatch.setattr(resource_gate, "cgroup_memory_pct", lambda: 95.0)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.CRITICAL


def test_cpu_load_alone_can_drive_each_tier(monkeypatch):
    """CPU load is the genuinely new signal (nothing in this codebase measured it
    before) -- must independently escalate even with memory completely idle."""
    monkeypatch.setattr(resource_gate, "cgroup_memory_pct", lambda: 5.0)

    monkeypatch.setattr(resource_gate, "load_per_core", lambda: 0.5)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.NORMAL

    monkeypatch.setattr(resource_gate, "load_per_core", lambda: 1.2)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.RESOURCE_PRESSURE

    monkeypatch.setattr(resource_gate, "load_per_core", lambda: 1.7)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.CONSERVATION

    monkeypatch.setattr(resource_gate, "load_per_core", lambda: 2.5)
    assert resource_gate.get_job_pressure_tier({}) == resource_gate.CRITICAL


def test_thresholds_are_config_overridable(monkeypatch):
    monkeypatch.setattr(resource_gate, "load_per_core", lambda: 0.0)
    monkeypatch.setattr(resource_gate, "cgroup_memory_pct", lambda: 40.0)
    config = {"job_gate_cgroup_pressure_pct": 30}
    assert resource_gate.get_job_pressure_tier(config) == resource_gate.RESOURCE_PRESSURE


def test_may_admit_new_job_respects_ceiling(monkeypatch):
    monkeypatch.setattr(resource_gate, "load_per_core", lambda: 0.0)
    monkeypatch.setattr(resource_gate, "cgroup_memory_pct", lambda: 80.0)  # CONSERVATION
    assert resource_gate.may_admit_new_job({}) is False  # default ceiling is RESOURCE_PRESSURE

    config = {"job_admission_max_pressure_tier": "conservation"}
    assert resource_gate.may_admit_new_job(config) is True
