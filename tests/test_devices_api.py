"""
Tests for src/middleware/routers/devices_api.py.

Direct-call style, no TestClient/httpx -- same convention as test_config_api.py.
Builds a small real GraphStore (temp SQLite file) and a real StateManager (temp JSON
file) via monkeypatch, rather than mocking either -- both are cheap and exercising the
actual SQL/serialization code is the point.
"""
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from v13.graph.store import GraphStore  # noqa: E402
from core.state_guard import StateManager  # noqa: E402
from middleware import graph_client  # noqa: E402
from middleware.routers import devices_api  # noqa: E402


@pytest.fixture
def graph_db(tmp_path, monkeypatch):
    db_path = tmp_path / "v13_graph.db"
    store = GraphStore(str(db_path))
    now = time.time()
    store.upsert_device("dev_a", display_label="dev_a_label", device_type="laptop", timestamp=now)
    store.insert_decision("dev_a", now, "SUSPICIOUS", "hard_stop", 0.8, 6.5)
    store.upsert_device("dev_b_no_state", display_label="dev_b_label", device_type="iot", timestamp=now)
    store.close()
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", db_path)
    return db_path


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    path = tmp_path / "ids_state.json"
    sm = StateManager(state_path=str(path))
    sm.get_or_create("dev_a", "192.168.1.50", "workstation-1")
    sm.flush_to_disk()
    monkeypatch.setattr(devices_api, "CONFIG", type("C", (), {"get": staticmethod(lambda k, d=None: str(path) if k == "state_path" else d)})())
    return path


def test_list_devices_merges_graph_and_state(graph_db, state_file):
    result = devices_api.list_devices(token="test")
    by_id = {d["device_id"]: d for d in result["devices"]}

    assert by_id["dev_a"]["hostname"] == "workstation-1"
    assert by_id["dev_a"]["state"] == "SUSPICIOUS"
    assert by_id["dev_a"]["risk_score"] == 6.5
    assert by_id["dev_a"]["has_graph_history"] is True

    # dev_b_no_state has a graph row but no StateManager entry -- falls back to
    # the graph's own display_label, no state/risk (never evaluated).
    assert by_id["dev_b_no_state"]["hostname"] == "dev_b_label"
    assert by_id["dev_b_no_state"]["state"] is None


def test_device_detail_includes_identity_and_top_domains_note(graph_db, state_file):
    result = devices_api.get_device_detail("dev_a", token="test")
    assert result["hostname"] == "workstation-1"
    assert result["state"] == "SUSPICIOUS"
    assert result["mac_address"] == "unknown"
    assert isinstance(result["known_ips"], list)
    assert result["top_domains_available"] is False
    assert "evidence-worthy events" in result["top_domains_note"]


def test_device_detail_unknown_device_404(graph_db, state_file):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        devices_api.get_device_detail("nonexistent-device", token="test")
    assert exc.value.status_code == 404


def test_list_devices_handles_missing_graph_db(tmp_path, monkeypatch, state_file):
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", tmp_path / "does_not_exist.db")
    result = devices_api.list_devices(token="test")
    # StateManager still knows about dev_a even with no graph db at all.
    assert any(d["device_id"] == "dev_a" and d["has_graph_history"] is False for d in result["devices"])
