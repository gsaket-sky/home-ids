"""
Tests for src/middleware/routers/suricata_api.py -- the console's new "Suricata" tab,
reading state/alerts.json directly (JSONL, tailed backward in bounded chunks -- see that
module's own docstring for why). Direct-call style, same convention as the other
middleware tests in this suite.
"""
import json
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from middleware.routers import suricata_api  # noqa: E402


def _write_jsonl(path, records):
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def test_iter_lines_reverse_yields_most_recent_first(tmp_path):
    path = tmp_path / "log.jsonl"
    _write_jsonl(path, [{"n": 1}, {"n": 2}, {"n": 3}])
    lines = list(suricata_api._iter_lines_reverse(path))
    parsed = [json.loads(l)["n"] for l in lines]
    assert parsed == [3, 2, 1]


def test_iter_lines_reverse_empty_file(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    assert list(suricata_api._iter_lines_reverse(path)) == []


def test_iter_lines_reverse_respects_chunk_boundaries(tmp_path, monkeypatch):
    # Force tiny chunks so a real record spans a chunk boundary -- exercises the
    # partial-line-carry logic, not just the happy path of one big read.
    monkeypatch.setattr(suricata_api, "_CHUNK_BYTES", 10)
    path = tmp_path / "log.jsonl"
    _write_jsonl(path, [{"hello": "world-record-one"}, {"hello": "world-record-two"}])
    lines = list(suricata_api._iter_lines_reverse(path))
    parsed = [json.loads(l)["hello"] for l in lines]
    assert parsed == ["world-record-two", "world-record-one"]


def test_is_suricata_record_new_schema():
    assert suricata_api._is_suricata_record({"hee_evidence_types": ["suricata_signature_match", "dns_rate"]})


def test_is_suricata_record_old_schema_top_level_signature():
    assert suricata_api._is_suricata_record({"signature": "SIGNATURE_MATCHED_THREAT"})


def test_is_suricata_record_hee_hypotheses():
    assert suricata_api._is_suricata_record({"hee_hypotheses": {"attack": {"name": "SIGNATURE_MATCHED_THREAT"}}})


def test_is_suricata_record_negative():
    assert not suricata_api._is_suricata_record({"hee_evidence_types": ["dns_rate"], "signature": "NETWORK_INTRUSION"})


def test_get_recent_suricata_end_to_end(tmp_path, monkeypatch):
    alerts_path = tmp_path / "alerts.json"
    _write_jsonl(alerts_path, [
        {"timestamp": 1.0, "device": {"id": "dev1", "hostname": "host1", "ip": "10.0.0.1"},
         "network_context": {"destination_ip": "1.2.3.4"}, "risk": 4.0, "signature": "NETWORK_INTRUSION"},
        {"timestamp": 2.0, "device": {"id": "dev2", "hostname": "host2", "ip": "10.0.0.2"},
         "network_context": {"destination_ip": "5.6.7.8"}, "hee_evidence_types": ["suricata_signature_match"],
         "suricata_matches": [{"signature_id": "1", "category": "trojan", "signature": "ET TROJAN test"}]},
        {"timestamp": 3.0, "device": {"id": "dev3", "hostname": "host3", "ip": "10.0.0.3"},
         "network_context": {"destination_ip": "9.9.9.9"}, "signature": "SIGNATURE_MATCHED_THREAT"},
    ])
    monkeypatch.setattr(suricata_api, "CONFIG", {"alert_json_path": str(alerts_path)})

    result = suricata_api.get_recent_suricata(limit=50, token="test")
    device_ids = [d["device_id"] for d in result["detections"]]
    assert device_ids == ["dev3", "dev2"]  # most recent first, dev1 excluded (not a suricata match)
    dev2 = next(d for d in result["detections"] if d["device_id"] == "dev2")
    assert dev2["detail_recorded"] is True
    assert dev2["matches"][0]["signature"] == "ET TROJAN test"
    dev3 = next(d for d in result["detections"] if d["device_id"] == "dev3")
    assert dev3["detail_recorded"] is False


def test_get_recent_suricata_respects_limit(tmp_path, monkeypatch):
    alerts_path = tmp_path / "alerts.json"
    _write_jsonl(alerts_path, [
        {"timestamp": float(i), "device": {"id": f"dev{i}"}, "network_context": {}, "signature": "SIGNATURE_MATCHED_THREAT"}
        for i in range(5)
    ])
    monkeypatch.setattr(suricata_api, "CONFIG", {"alert_json_path": str(alerts_path)})
    result = suricata_api.get_recent_suricata(limit=2, token="test")
    assert len(result["detections"]) == 2
    assert result["detections"][0]["device_id"] == "dev4"


def test_get_recent_suricata_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(suricata_api, "CONFIG", {"alert_json_path": str(tmp_path / "does_not_exist.json")})
    result = suricata_api.get_recent_suricata(limit=50, token="test")
    assert result["detections"] == []
