"""
Tests for src/middleware/routers/health_api.py -- calls the handler function
directly (no TestClient/HTTP layer), same convention test_config_api.py already
established for this repo's middleware routers.
"""
import json
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from middleware.routers import health_api  # noqa: E402


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(health_api, "_state_dir", lambda: tmp_path)
    return tmp_path


def test_empty_state_dir_returns_empty_everything(state_dir):
    result = health_api.get_health_status(token="test")
    assert result["snapshot"] == {}
    assert result["component_heartbeats"] == {}
    assert result["job_health"] == {}
    assert result["feed_health"] == {}


def test_reads_snapshot_file_written_by_health_manager(state_dir):
    snapshot = {
        "written_at": 123.0,
        "pressure_level": "resource_pressure",
        "rss_mb": 1100.0,
        "auto_recovery_enabled": True,
        "components": {
            "pipeline_main_loop": {"state": "healthy", "detail": "heartbeat age 2s", "recovery_attempts": 0},
        },
    }
    (state_dir / "health_manager_snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
    result = health_api.get_health_status(token="test")
    assert result["snapshot"]["pressure_level"] == "resource_pressure"
    assert result["snapshot"]["components"]["pipeline_main_loop"]["state"] == "healthy"


def test_reads_component_heartbeat_job_and_feed_files(state_dir):
    (state_dir / "component_heartbeat.json").write_text(json.dumps({"api_subprocess": {"pid": 1}}), encoding="utf-8")
    (state_dir / "job_health.json").write_text(json.dumps({"retro_hunter": {"last_success": 5.0}}), encoding="utf-8")
    (state_dir / "feed_health.json").write_text(json.dumps({"otx": {"consecutive_failures": 0}}), encoding="utf-8")
    result = health_api.get_health_status(token="test")
    assert result["component_heartbeats"]["api_subprocess"]["pid"] == 1
    assert result["job_health"]["retro_hunter"]["last_success"] == 5.0
    assert result["feed_health"]["otx"]["consecutive_failures"] == 0


def test_corrupt_json_file_degrades_to_empty_not_a_500(state_dir):
    (state_dir / "health_manager_snapshot.json").write_text("{not valid json", encoding="utf-8")
    result = health_api.get_health_status(token="test")  # must not raise
    assert result["snapshot"] == {}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
