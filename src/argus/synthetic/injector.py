"""
argus/synthetic/injector.py -- Release 15 Sheet 01: runs attacks.py's
generators through the REAL DecisionEngine, against an ISOLATED in-memory
clone of a device's own recent graph state -- never the live database. This
is the exact safety boundary the plan calls for: synthetic evidence must be
able to test the real decision logic without any possibility of it reaching
the live evidence graph, a real decision row, or influencing any other
device's peer-cohort/population-prior computations.
"""
import time
from typing import Any, Dict, List, Optional

from intelligence.reputation.classifier import ReputationClassifier
from argus.decision.engine import DecisionEngine
from argus.evidence.model import Evidence, NO_DESTINATION
from argus.graph.store import GraphStore
from argus.graph.window import RollingWindowView
from argus.synthetic.attacks import ATTACK_GENERATORS, benign_drift

_DETECTED_STATES = frozenset({"SUSPICIOUS", "HIGH", "CRITICAL"})

# Live, some decision rules read a raw feature, not the evidence store: the honeypot hard stop checks
# features["zeek_honeypot_hits"] (argus/decision/engine.py), the same count pipeline.py creates the
# honeypot_access evidence from. A synthetic attack injects only the evidence, so the sweep supplies the feature the
# live pipeline would have had (2026-10-07: without it the honeypot class scored 0-10 % every night and drove a
# tighten-only autotune proposal that could never fix it).
_LIVE_FEATURE_FOR_EVIDENCE = {"honeypot_access": "zeek_honeypot_hits"}


def _live_features(synthetic_items: List[Evidence]) -> Dict[str, float]:
    features: Dict[str, float] = {}
    for ev in synthetic_items:
        name = _LIVE_FEATURE_FOR_EVIDENCE.get(ev.evidence_type)
        if name:
            features[name] = features.get(name, 0.0) + float(ev.value or 0.0)
    return features


def clone_device_state(source_store: GraphStore, device_id: str,
                         lookback_seconds: float = 86400.0, now: Optional[float] = None) -> GraphStore:
    """Copies one device's real device row and recent evidence into a fresh,
    isolated in-memory GraphStore -- the real context a synthetic attack is
    injected against, so scoring reflects that device's actual recent
    baseline/history rather than an empty graph. Never touches the source
    store; never copies OTHER devices, so no peer-cohort/population data
    leaks into the isolated clone either."""
    now = now if now is not None else time.time()
    clone = GraphStore(":memory:")

    device_row = source_store._conn.execute(
        "SELECT * FROM devices WHERE device_id=?", (device_id,),
    ).fetchone()
    if device_row is not None:
        clone.upsert_device(device_id, display_label=device_row["display_label"],
                              device_type=device_row["device_type"], timestamp=device_row["first_seen"])
        clone._conn.execute("UPDATE devices SET last_seen=? WHERE device_id=?",
                              (device_row["last_seen"], device_id))
    else:
        clone.upsert_device(device_id, timestamp=now)

    evidence_rows = source_store._conn.execute(
        "SELECT * FROM evidence WHERE device_id=? AND timestamp >= ?",
        (device_id, now - lookback_seconds),
    ).fetchall()
    for row in evidence_rows:
        clone.insert_evidence(Evidence.from_row(dict(row)))

    return clone


def inject_and_evaluate(source_store: GraphStore, device_id: str, attack_class: str,
                          intensity: str = "high", now: Optional[float] = None,
                          window_seconds: Optional[float] = None,
                          decision_engine: Optional[DecisionEngine] = None,
                          reputation_classifier: Optional[ReputationClassifier] = None) -> Dict[str, Any]:
    """Injects one synthetic attack of `attack_class` into an isolated clone
    of `device_id`'s real recent state, runs it through the real
    DecisionEngine, and reports whether/how it fired -- never writes
    anything back to `source_store`."""
    if attack_class not in ATTACK_GENERATORS:
        raise ValueError(f"unknown attack_class: {attack_class!r} -- known: {sorted(ATTACK_GENERATORS)}")
    now = now if now is not None else time.time()

    clone = clone_device_state(source_store, device_id, now=now)
    try:
        synthetic_items = ATTACK_GENERATORS[attack_class](device_id, now=now, intensity=intensity)
        for ev in synthetic_items:
            clone.insert_evidence(ev)

        window = RollingWindowView(clone)
        window_seconds = window_seconds if window_seconds is not None else RollingWindowView.LONG_WINDOW_SECONDS
        evidence_list = window.evidence_in_window(device_id, window_seconds, now=now)

        target_domain = ""
        for ev in reversed(evidence_list):
            if ev.destination_id != NO_DESTINATION:
                target_domain = ev.destination_id
                break
        rep = (reputation_classifier or ReputationClassifier()).classify(target_domain)
        decision = (decision_engine or DecisionEngine()).evaluate(
            evidence_list, rep, features=_live_features(synthetic_items) or None, now=now)
    finally:
        clone.close()

    return {
        "attack_class": attack_class, "intensity": intensity, "device_id": device_id,
        "state": decision["state"], "decision_path": decision["decision_path"],
        "detected": decision["state"] in _DETECTED_STATES,
        "synthetic_evidence_types": [e.evidence_type for e in synthetic_items],
    }


def inject_benign_drift_and_evaluate(source_store: GraphStore, device_id: str,
                                        now: Optional[float] = None,
                                        window_seconds: Optional[float] = None,
                                        decision_engine: Optional[DecisionEngine] = None,
                                        reputation_classifier: Optional[ReputationClassifier] = None) -> Dict[str, Any]:
    """The companion check to inject_and_evaluate(): injects deliberately
    BENIGN, weird-but-harmless drift and confirms it does NOT fire -- a
    false-positive-resistance test, not a detection-recall one. A tuner that
    passes every inject_and_evaluate() floor by becoming maximally
    aggressive should fail this check instead.

    BUGFIX (2026-09-20, found while investigating why Sheet 03a's nightly
    backtest gate had never once passed): `false_positive` used to be just
    `decision["state"] in _DETECTED_STATES` -- flagging a device as a false
    positive whenever it was non-BENIGN AFTER adding the synthetic evidence,
    with no check for whether it was ALREADY non-BENIGN BEFORE adding it.
    Confirmed live on `.94`: 3 of the 6 devices failing this check every
    single night for 5 nights straight were already SUSPICIOUS from their
    own real, ongoing evidence (zeek_notice_medium/dns_tunnel_v2) -- exactly
    matching this project's own documented, already-tested behavior
    (test_real_world_alert_regression.py's own DNS_COVERT_TUNNELING case:
    "a single dns_behavior-family finding stays SUSPICIOUS"). The synthetic
    first_contact item had ZERO effect on those 3 devices' outcome (verified
    directly: identical state with and without it) -- this test was
    penalizing the nightly backtest gate for a device's own correct,
    pre-existing classification, not for anything the synthetic injection
    actually caused. Now compares against a BASELINE evaluation (the same
    cloned real evidence, WITHOUT the synthetic addition) and only counts it
    as a false positive if the synthetic evidence caused a NEW escalation
    the device wasn't already at -- the actual thing this test exists to
    catch."""
    now = now if now is not None else time.time()
    clone = clone_device_state(source_store, device_id, now=now)
    try:
        window = RollingWindowView(clone)
        window_seconds = window_seconds if window_seconds is not None else RollingWindowView.LONG_WINDOW_SECONDS
        rep_classifier = reputation_classifier or ReputationClassifier()
        engine = decision_engine or DecisionEngine()

        def _evaluate_current_clone_state() -> Dict[str, Any]:
            evidence_list = window.evidence_in_window(device_id, window_seconds, now=now)
            target_domain = ""
            for ev in reversed(evidence_list):
                if ev.destination_id != NO_DESTINATION:
                    target_domain = ev.destination_id
                    break
            rep = rep_classifier.classify(target_domain)
            return engine.evaluate(evidence_list, rep, now=now)

        baseline_decision = _evaluate_current_clone_state()

        synthetic_items = benign_drift(device_id, now=now)
        for ev in synthetic_items:
            clone.insert_evidence(ev)
        decision = _evaluate_current_clone_state()
    finally:
        clone.close()

    baseline_was_benign = baseline_decision["state"] not in _DETECTED_STATES
    return {
        "device_id": device_id, "state": decision["state"], "decision_path": decision["decision_path"],
        "baseline_state": baseline_decision["state"],
        "false_positive": decision["state"] in _DETECTED_STATES and baseline_was_benign,
        "synthetic_evidence_types": [e.evidence_type for e in synthetic_items],
    }


def sweep(source_store: GraphStore, device_id: str, now: Optional[float] = None,
           attack_classes: Optional[List[str]] = None, intensity: str = "high") -> Dict[str, Any]:
    """One device's full synthetic validation sweep -- every attack class
    (detection-recall) plus one benign-drift check (false-positive-
    resistance). This is the per-device unit Sheet 02's nightly backtest job
    calls; degrading COVERAGE under resource pressure means calling this
    with a smaller `attack_classes` subset, not changing its own logic."""
    now = now if now is not None else time.time()
    classes = attack_classes if attack_classes is not None else sorted(ATTACK_GENERATORS)
    results = {cls: inject_and_evaluate(source_store, device_id, cls, intensity=intensity, now=now)
                for cls in classes}
    drift_result = inject_benign_drift_and_evaluate(source_store, device_id, now=now)
    return {
        "device_id": device_id, "attack_results": results, "benign_drift_result": drift_result,
        "detection_rate": sum(1 for r in results.values() if r["detected"]) / len(results) if results else 0.0,
        "false_positive": drift_result["false_positive"],
    }
