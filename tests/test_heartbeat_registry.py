"""
Tests for core/heartbeat.py -- the health manager's two heartbeat channels
(in-process HeartbeatRegistry, cross-process write_component_heartbeat/
read_component_heartbeats file pair). Direct-call style, matching
test_ips_operator_actions.py's convention.
"""
import sys
import threading
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.heartbeat import (  # noqa: E402
    HeartbeatRegistry,
    write_component_heartbeat,
    read_component_heartbeats,
)


def test_beat_records_last_heartbeat_and_last_success():
    reg = HeartbeatRegistry()
    before = time.time()
    reg.beat("worker_a")
    entry = reg.get("worker_a")
    assert entry is not None
    assert entry["last_heartbeat"] >= before
    assert entry["last_success"] >= before


def test_beat_records_optional_fields():
    reg = HeartbeatRegistry()
    reg.beat("worker_b", events_processed=42, processing_latency=0.5, queue_depth=3, health_state="healthy")
    entry = reg.get("worker_b")
    assert entry["events_processed"] == 42
    assert entry["processing_latency"] == 0.5
    assert entry["queue_depth"] == 3
    assert entry["health_state"] == "healthy"


def test_beat_degraded_health_state_does_not_bump_last_success():
    reg = HeartbeatRegistry()
    reg.beat("worker_c", health_state="healthy")
    first = reg.get("worker_c")["last_success"]
    time.sleep(0.01)
    reg.beat("worker_c", health_state="degraded")
    entry = reg.get("worker_c")
    assert entry["health_state"] == "degraded"
    assert entry["last_success"] == first  # unchanged -- a degraded beat isn't a success


def test_get_unknown_component_returns_none():
    reg = HeartbeatRegistry()
    assert reg.get("never_beaten") is None


def test_get_all_returns_every_component():
    reg = HeartbeatRegistry()
    reg.beat("a")
    reg.beat("b")
    all_entries = reg.get_all()
    assert set(all_entries.keys()) == {"a", "b"}


def test_beat_is_thread_safe():
    reg = HeartbeatRegistry()
    errors = []

    def hammer(n):
        try:
            for _ in range(200):
                reg.beat(f"component_{n}", events_processed=n)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(reg.get_all()) == 8


def test_write_and_read_component_heartbeat_round_trip(tmp_path):
    write_component_heartbeat(tmp_path, "api_subprocess", extra={"pid": 1234})
    entries = read_component_heartbeats(tmp_path)
    assert "api_subprocess" in entries
    assert entries["api_subprocess"]["pid"] == 1234
    assert "last_heartbeat" in entries["api_subprocess"]


def test_write_component_heartbeat_preserves_other_components(tmp_path):
    write_component_heartbeat(tmp_path, "api_subprocess", extra={"pid": 1})
    write_component_heartbeat(tmp_path, "scheduler_subprocess", extra={"pid": 2})
    entries = read_component_heartbeats(tmp_path)
    assert set(entries.keys()) == {"api_subprocess", "scheduler_subprocess"}


def test_read_component_heartbeats_missing_file_returns_empty(tmp_path):
    assert read_component_heartbeats(tmp_path / "does_not_exist") == {}


def test_read_component_heartbeats_corrupt_file_returns_empty(tmp_path):
    path = tmp_path / "component_heartbeat.json"
    path.write_text("{not valid json", encoding="utf-8")
    assert read_component_heartbeats(tmp_path) == {}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
