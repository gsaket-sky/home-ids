import os
import sys

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
        Evidence(type="dns_rate", source="pihole", timestamp=1.0, device="device-1", value=120.0, independence_group="dns_behavior"),
        Evidence(type="reputation", source="threat_intel", timestamp=1.0, device="device-1", value=4.0, independence_group="reputation"),
        Evidence(type="zeek_lateral_scan", source="zeek", timestamp=1.0, device="device-1", value=2.0, independence_group="zeek_network"),
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
