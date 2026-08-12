import os
import sys
import json
import inspect
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import threading

from core.decision_engine import DecisionEngine, DecisionState
from intelligence.detectors.zeek_network import ZeekNetworkDetector
from intelligence.hypotheses.evidence import Evidence
from intelligence.reputation.classifier import ReputationClassifier, ReputationVector
from mitigation.ips import IPSMitigator
from intelligence.ai_soc import DeterministicValidator
from scripts import train_fp_classifier as _trainer

FP_FEATURE_DIM = getattr(_trainer, "FP_FEATURE_DIM", 9)
SYNTHETIC_X = getattr(_trainer, "SYNTHETIC_X", [])
extract_features_from_alert = _trainer.extract_features_from_alert
_load_dataset_raw = _trainer.load_dataset

try:
    from intelligence.fp_engine import FP_STAGE2_FEATURE_DIM
except Exception:
    FP_STAGE2_FEATURE_DIM = 9

def _load_dataset_compat(state_dir: Path, alert_stream_path: Path | None = None):
    sig = inspect.signature(_load_dataset_raw)
    if "alert_stream_path" in sig.parameters:
        return _load_dataset_raw(state_dir, alert_stream_path=alert_stream_path)
    out = _load_dataset_raw(state_dir)
    # supports both (X,y) and (X,y,stats)
    return out[:2] if isinstance(out, tuple) and len(out) >= 2 else out

def test_zeek_detector_uses_canonical_evidence_types():
    detector = ZeekNetworkDetector()
    events = [
        {"type": "malicious_ja3", "confidence": 0.95},
        {"type": "zeek_notice", "confidence": 0.75},
    ]

    results = detector.detect("device-1", events)

    assert [e.type for e in results] == ["malicious_ja3", "zeek_notice"]


def test_confirmed_ioc_escalates_reputation_tier_to_five():
    classifier = ReputationClassifier()

    rep = classifier.classify("evil.example", vt_score=0.0, ti_score=4.0, abuse_score=4.0)

    assert rep.tier == 5


def test_decision_engine_counts_reputation_and_zeek_groups_as_independent_sources():
    engine = DecisionEngine()
    evidence = [
        Evidence(type="dns_rate", source="pihole", timestamp=1.0, device="device-1", value=120.0, confidence=0.8, independence_group="dns_behavior", provenance="test:dns_rate"),
        Evidence(type="reputation", source="threat_intel", timestamp=1.0, device="device-1", value=4.0, confidence=0.95, independence_group="reputation", provenance="test:reputation"),
        Evidence(type="zeek_lateral_scan", source="zeek", timestamp=1.0, device="device-1", value=2.0, confidence=0.9, independence_group="zeek_network", provenance="test:zeek_lateral"),
    ]

    decision = engine.evaluate(evidence, ReputationVector(domain="evil.example", tier=3))

    assert decision["independent_sources"] >= 3
    assert decision["state"] in {DecisionState.SUSPICIOUS, DecisionState.HIGH, DecisionState.CRITICAL}


def test_dead_letter_prunes_to_maximum_size():
    mitigator = object.__new__(IPSMitigator)
    mitigator._lock = threading.RLock()
    mitigator._dead_letter = {}
    mitigator._retry_queue = {}

    for index in range(501):
        mitigator._dead_letter[f"domain-{index}"] = {"ts": float(index)}

    mitigator._prune_dead_letter_entries(now=500.0, max_items=500)

    assert len(mitigator._dead_letter) == 500
    assert "domain-0" not in mitigator._dead_letter
    assert "domain-500" in mitigator._dead_letter


def test_unblock_domain_uses_configured_pihole_api_path():
    class _DummySession:
        def __init__(self):
            self.last_url = None
        def delete(self, url, **kwargs):
            self.last_url = url
            class _Resp: pass
            return _Resp()

    class _DummyStateManager:
        def __init__(self):
            self._global_lock = threading.RLock()
            self._ips_state = {"blocked_domains": {"bad.example": {"hostname": "h", "device_id": "d"}}}
        def get_ips_state(self):
            return self._ips_state
        def save_ips_state(self, state):
            self._ips_state = state
        def flush_to_disk(self):
            pass

    mitigator = object.__new__(IPSMitigator)
    mitigator.config = {
        "pihole_api_url": "http://pihole.local",
        "pihole_api_path": "/custom/domains",
        "ips_pihole_enabled": True,
        "pihole_api_timeout_seconds": 1.0,
    }
    mitigator.session = _DummySession()
    mitigator.state_manager = _DummyStateManager()

    assert mitigator.unblock_domain("bad.example") is True
    assert mitigator.session.last_url == "http://pihole.local/custom/domains"


def test_ai_soc_validator_handles_non_numeric_reputation_values():
    validator = DeterministicValidator()
    evidence = [
        Evidence(
            type="reputation",
            source="threat_intel",
            timestamp=1.0,
            device="device-1",
            value="not-a-number",
            confidence=0.8,
            independence_group="reputation",
            provenance="test:validator",
        )
    ]
    recommendation = {"classification": "benign", "reason": "telemetry update"}
    assert validator.validate(recommendation, evidence) is True


def test_train_fp_classifier_loads_jsonl_alert_stream_and_nested_muted_entries(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    alert_stream = tmp_path / "SOC" / "alerts_stream.jsonl"
    alert_stream.parent.mkdir(parents=True, exist_ok=True)
    alert_doc = {
        "device": {"type": "laptop"},
        "network_context": {"queried_domain": "example.com"},
        "features": {
            "tranco_rank": 1000,
            "max_label_length": 8,
            "outbound_bytes_z": 0.2,
            "zeek_lateral_moves": 0,
            "zeek_s0_rej_count": 0,
            "zeek_app_protocol_weight": 0.2,
        },
    }
    alert_stream.write_text(json.dumps(alert_doc) + "\n", encoding="utf-8")

    muted_outer = {
        "reasons": ["dynamic trust cache hit"],
        "original_alert": {
            "device": {"type": "phone"},
            "network_context": {"queried_domain": "telemetry.vendor.com"},
            "features": {
                "tranco_rank": 2000,
                "max_label_length": 12,
                "outbound_bytes_z": 0.1,
                "zeek_lateral_moves": 0,
                "zeek_s0_rej_count": 0,
                "zeek_app_protocol_weight": 0.2,
            },
        },
    }
    (state_dir / "autonomous_muted.jsonl").write_text(json.dumps(muted_outer) + "\n", encoding="utf-8")

    X, y = _load_dataset_compat(state_dir, alert_stream_path=alert_stream)

    assert len(X) == 2
    assert sorted(y) == [0, 1]
    assert all(len(row) == FP_FEATURE_DIM for row in X)


def test_train_fp_classifier_drops_non_finite_rows(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    alert_stream = tmp_path / "alerts_stream.jsonl"
    good = {
        "device": {"type": "laptop"},
        "network_context": {"queried_domain": "good.example"},
        "features": {"tranco_rank": 1234, "max_label_length": 10, "outbound_bytes_z": 0.3},
    }
    bad = {
        "device": {"type": "laptop"},
        "network_context": {"queried_domain": "bad.example"},
        "features": {"tranco_rank": "nan", "max_label_length": 10, "outbound_bytes_z": 0.3},
    }
    alert_stream.write_text(json.dumps(good) + "\n" + json.dumps(bad) + "\n", encoding="utf-8")

    X, y = _load_dataset_compat(state_dir, alert_stream_path=alert_stream)

    assert len(X) == 1
    assert y == [0]


def test_fp_trainer_schema_dimension_matches_runtime_stage2_contract():
    assert FP_FEATURE_DIM == 9
    assert FP_STAGE2_FEATURE_DIM == 9
    assert FP_FEATURE_DIM == FP_STAGE2_FEATURE_DIM
    assert all(len(row) == FP_FEATURE_DIM for row in SYNTHETIC_X)


def test_fp_trainer_extracts_nested_original_alert_payload():
    muted_doc = {
        "type": "AUTONOMOUS_FP_SUPPRESSED",
        "original_alert": {
            "device": {"type": "laptop"},
            "network_context": {"queried_domain": "o123.ingest.sentry.io"},
            "features": {
                "tranco_rank": 1500,
                "max_label_length": 18,
                "outbound_bytes_z": 0.3,
                "zeek_lateral_moves": 0,
                "zeek_s0_rej_count": 0,
                "zeek_app_protocol_weight": 0.2,
            },
        },
        "reasons": ["Base domain in trust cache"],
    }
    row = extract_features_from_alert(muted_doc)
    assert len(row) == FP_FEATURE_DIM
    assert row[5] == 1.0  # historical FP flag from trust-cache reason
