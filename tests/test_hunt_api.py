"""Tests for src/middleware/routers/hunt_api.py -- direct-call style, real GraphStore
against a temp SQLite file, following test_config_api.py's convention."""
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from v13.graph.store import GraphStore  # noqa: E402
from v13.evidence.model import Evidence  # noqa: E402
from middleware import graph_client  # noqa: E402
from middleware.routers import hunt_api  # noqa: E402


@pytest.fixture
def graph_db(tmp_path, monkeypatch):
    db_path = tmp_path / "v13_graph.db"
    store = GraphStore(str(db_path))
    now = time.time()
    ev = Evidence(device_id="dev_a", destination_id="203.0.113.44", evidence_type="reputation_hit",
                   independence_family="network_intel", timestamp=now, source="test", confidence=0.9)
    store.insert_evidence(ev)
    decision_id = store.insert_decision("dev_a", now, "SUSPICIOUS", "hard_stop", 0.8, 6.5,
                                         evidence_ids=[ev.evidence_id])
    store.close()
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", db_path)
    return {"decision_id": decision_id, "evidence_id": ev.evidence_id}


def test_devices_touching_finds_via_substring(graph_db):
    result = hunt_api.devices_touching(destination="203.0.113", since_days=None, token="test")
    assert "203.0.113.44" in result["matched_destinations"]
    assert any(d["device_id"] == "dev_a" for d in result["devices"])


def test_devices_touching_no_match(graph_db):
    result = hunt_api.devices_touching(destination="not-a-real-destination", since_days=None, token="test")
    assert result["devices"] == []


def test_decision_timeline_returns_evidence(graph_db):
    result = hunt_api.decision_timeline(graph_db["decision_id"], token="test")
    assert result["decision"]["state"] == "SUSPICIOUS"
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["evidence_id"] == graph_db["evidence_id"]


def test_decision_timeline_unknown_id_404(graph_db):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        hunt_api.decision_timeline("not-a-real-id", token="test")
    assert exc.value.status_code == 404


def test_device_history(graph_db):
    result = hunt_api.device_history("dev_a", since_days=None, token="test")
    assert result["canonical_device_id"] == "dev_a"
    assert len(result["evidence"]) == 1
    assert len(result["decisions"]) == 1


def test_replay_decision(graph_db):
    result = hunt_api.replay_decision(graph_db["decision_id"], token="test")
    assert result["decision_id"] == graph_db["decision_id"]
    assert result["old_state"] == "SUSPICIOUS"
    assert "outcome" in result


def test_replay_unknown_decision_404(graph_db):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        hunt_api.replay_decision("not-a-real-id", token="test")
    assert exc.value.status_code == 404


def test_no_graph_db_returns_empty_not_error(tmp_path, monkeypatch):
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", tmp_path / "missing.db")
    result = hunt_api.devices_touching(destination="anything", since_days=None, token="test")
    assert result["devices"] == []
