"""Tests for src/middleware/routers/graph_api.py -- direct-call style, real GraphStore
against a temp SQLite file, following test_config_api.py's convention."""
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from argus.graph.store import GraphStore  # noqa: E402
from argus.evidence.model import Evidence  # noqa: E402
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


# --- BUGFIX regression: repeated same-type evidence gets compressed into one node ---
# Real finding against .94's live data: 147 of 230 evidence nodes in a typical
# limit=25 response (64%) were just zeek_notice_weak/zeek_notice_medium repeated
# for the same device against the same destination -- "similar entries, different
# timestamp" per the user's own report. Grouped by
# (device_id, evidence_type, independence_family, destination_id).

def _seed_repeated_evidence(tmp_path, monkeypatch, count, same_destination=True):
    db_path = tmp_path / "v13_graph.db"
    store = GraphStore(str(db_path))
    now = time.time()
    evidence_ids = []
    for i in range(count):
        dest = "8.8.8.8" if same_destination else f"8.8.8.{i}"
        ev = Evidence(device_id="dev_a", destination_id=dest, evidence_type="zeek_notice_weak",
                      independence_family="network_behavior", timestamp=now + i,
                      source="zeek", confidence=0.1 + i * 0.01)
        store.insert_evidence(ev)
        evidence_ids.append(ev.evidence_id)
    store.insert_decision("dev_a", now + count, "BENIGN", "hypothesis_low", 0.2, 1.0,
                           evidence_ids=evidence_ids, raw_payload={"explanation": "UNKNOWN_BENIGN"})
    store.close()
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", db_path)
    return evidence_ids


def test_repeated_same_type_evidence_compresses_to_one_node(tmp_path, monkeypatch):
    _seed_repeated_evidence(tmp_path, monkeypatch, count=8, same_destination=True)
    result = graph_api.get_graph(limit=25, token="test")
    evidence_nodes = [n for n in result["nodes"] if n["kind"] == "evidence"]
    assert len(evidence_nodes) == 1
    assert evidence_nodes[0]["count"] == 8
    assert evidence_nodes[0]["id"].startswith("evidence-group:")


def test_grouped_node_confidence_is_max_and_timestamp_is_newest(tmp_path, monkeypatch):
    _seed_repeated_evidence(tmp_path, monkeypatch, count=5, same_destination=True)
    result = graph_api.get_graph(limit=25, token="test")
    node = next(n for n in result["nodes"] if n["kind"] == "evidence")
    assert node["confidence"] == pytest.approx(0.1 + 4 * 0.01)  # the last (i=4) member had the highest confidence
    assert node["timestamp"] > node["first_timestamp"]


def test_different_destinations_are_not_grouped_together(tmp_path, monkeypatch):
    _seed_repeated_evidence(tmp_path, monkeypatch, count=4, same_destination=False)
    result = graph_api.get_graph(limit=25, token="test")
    evidence_nodes = [n for n in result["nodes"] if n["kind"] == "evidence"]
    assert len(evidence_nodes) == 4
    assert all("count" not in n for n in evidence_nodes)


def test_single_evidence_item_keeps_original_id_shape_and_no_count(graph_db):
    """Non-repeated evidence (the common case for anything that isn't a noisy
    recurring signal) must render exactly as before this change -- no `count`
    field, same evidence:<id> node id."""
    result = graph_api.get_graph(limit=25, token="test")
    evidence_nodes = [n for n in result["nodes"] if n["kind"] == "evidence"]
    assert len(evidence_nodes) == 3
    for n in evidence_nodes:
        assert n["id"].startswith("evidence:")
        assert not n["id"].startswith("evidence-group:")
        assert "count" not in n


def test_grouped_node_decision_edges_are_deduped_not_repeated(tmp_path, monkeypatch):
    """8 member evidence items all supporting the SAME single decision must
    produce exactly ONE evidence-group->decision edge, not 8 overlapping ones."""
    _seed_repeated_evidence(tmp_path, monkeypatch, count=8, same_destination=True)
    result = graph_api.get_graph(limit=25, token="test")
    group_node = next(n for n in result["nodes"] if n["kind"] == "evidence")
    decision_edges = [e for e in result["edges"] if e["from"] == group_node["id"] and e["to"].startswith("decision:")]
    assert len(decision_edges) == 1


def test_grouped_node_has_one_observed_edge_from_device(tmp_path, monkeypatch):
    _seed_repeated_evidence(tmp_path, monkeypatch, count=6, same_destination=True)
    result = graph_api.get_graph(limit=25, token="test")
    group_node = next(n for n in result["nodes"] if n["kind"] == "evidence")
    observed_edges = [e for e in result["edges"] if e["to"] == group_node["id"] and e["relation"] == "observed"]
    assert len(observed_edges) == 1
    assert observed_edges[0]["from"] == "device:dev_a"
