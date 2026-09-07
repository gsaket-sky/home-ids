"""Tests for src/middleware/routers/graph_api.py -- direct-call style, real GraphStore
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
from middleware.routers import graph_api  # noqa: E402


@pytest.fixture
def graph_db(tmp_path, monkeypatch):
    db_path = tmp_path / "v13_graph.db"
    store = GraphStore(str(db_path))
    now = time.time()
    for i in range(3):
        ev = Evidence(device_id=f"dev_{i}", destination_id=f"1.2.3.{i}", evidence_type="reputation_hit",
                      independence_family="network_intel", timestamp=now + i, source="test", confidence=0.9)
        store.insert_evidence(ev)
        store.insert_decision(f"dev_{i}", now + i, "SUSPICIOUS", "hard_stop", 0.8, 6.5,
                               evidence_ids=[ev.evidence_id],
                               raw_payload={"explanation": "TEST_HYPOTHESIS"})
    store.close()
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", db_path)


def test_graph_returns_all_kinds(graph_db):
    result = graph_api.get_graph(limit=25, token="test")
    kinds = {n["kind"] for n in result["nodes"]}
    assert kinds == {"device", "evidence", "destination", "decision"}
    assert result["decision_count"] == 3


def test_graph_respects_limit(graph_db):
    result = graph_api.get_graph(limit=1, token="test")
    assert result["decision_count"] == 1
    decision_nodes = [n for n in result["nodes"] if n["kind"] == "decision"]
    assert len(decision_nodes) == 1


def test_graph_winning_hypothesis_from_raw_payload(graph_db):
    result = graph_api.get_graph(limit=25, token="test")
    decision_nodes = [n for n in result["nodes"] if n["kind"] == "decision"]
    assert all(n["winning_hypothesis"] == "TEST_HYPOTHESIS" for n in decision_nodes)


def test_graph_edges_link_device_evidence_decision(graph_db):
    result = graph_api.get_graph(limit=25, token="test")
    relations = {e["relation"] for e in result["edges"]}
    assert "observed" in relations
    assert "targets" in relations
    assert "supports" in relations


def test_graph_caps_evidence_per_noisy_decision(tmp_path, monkeypatch):
    """Real-world finding: one production decision had 56,073 supporting edges (one
    device alone accounted for ~79% of all evidence in the whole database). A single
    noisy decision must not blow up the response regardless of the decision `limit`."""
    db_path = tmp_path / "v13_graph.db"
    store = GraphStore(str(db_path))
    now = time.time()
    evidence_ids = []
    for i in range(30):
        ev = Evidence(device_id="noisy_device", destination_id=f"10.0.0.{i}", evidence_type="volume_anomaly",
                      independence_family="behavioral_baseline", timestamp=now + i, source="test")
        store.insert_evidence(ev)
        evidence_ids.append(ev.evidence_id)
    store.insert_decision("noisy_device", now + 30, "SUSPICIOUS", "hard_stop", 0.5, 4.0,
                           evidence_ids=evidence_ids)
    store.close()
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", db_path)

    result = graph_api.get_graph(limit=25, token="test")
    evidence_nodes = [n for n in result["nodes"] if n["kind"] == "evidence"]
    decision_nodes = [n for n in result["nodes"] if n["kind"] == "decision"]
    assert len(evidence_nodes) == graph_api.EVIDENCE_PER_DECISION_CAP
    assert decision_nodes[0]["evidence_total"] == 30
    assert decision_nodes[0]["evidence_truncated"] is True


def test_no_graph_db_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", tmp_path / "missing.db")
    result = graph_api.get_graph(limit=25, token="test")
    assert result == {"nodes": [], "edges": [], "decision_count": 0}
