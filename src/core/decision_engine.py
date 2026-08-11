from typing import List, Dict, Any
from intelligence.hypotheses.evidence import Evidence
from intelligence.hypotheses.engine import HypothesisEngine
from intelligence.reputation.classifier import ReputationVector

def _safe_float(val: Any) -> float:
        try:
            return float(val) if val is not None else 0.0
        except (ValueError, TypeError):
            return 0.0

class DecisionState:
    BENIGN = "BENIGN"
    ANOMALOUS = "ANOMALOUS"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DecisionEngine:
    def __init__(self):
        self.hypothesis_engine = HypothesisEngine()

    def evaluate(self, ev_store: List[Evidence], rep: ReputationVector) -> Dict[str, Any]:
        hyp_results = self.hypothesis_engine.evaluate_all(ev_store, rep)
        
        attack_score = hyp_results["attack"]["score"]
        benign_score = hyp_results["benign"]["score"]
        evidence_verification_required = False
        hypothesis_weight = 0.0

        partial_support = [e for e in ev_store if e.independence_group in {"dns_behavior", "zeek_network", "reputation", "honeypot"}]
        if partial_support:
            hypothesis_weight = sum(min(1.0, max(0.0, e.confidence)) for e in partial_support) / max(1, len(partial_support))
            has_meaningful_partial_signal = any(
                e.confidence >= 0.5 and abs(_safe_float(e.value)) > 0.0 for e in partial_support
            )
            evidence_verification_required = hypothesis_weight >= 0.5 and (
                attack_score >= 2.0 or has_meaningful_partial_signal
            )
        
        # Calculate independence groups from the evidence that materially contributes to attack scoring.
        attack_evidence = [
            e for e in ev_store
            if e.type.startswith("dns") or e.type == "reputation" or e.type.startswith("zeek") or e.independence_group in {"reputation", "zeek_network", "honeypot"}
        ]
        independence_groups = {e.independence_group for e in attack_evidence if e.independence_group}
        num_independent_sources = len(independence_groups)
        
        state = DecisionState.BENIGN
        action = "suppress"
        explanation = hyp_results["benign"]["name"]
        threat_confidence = 0.0

        if any(e.type == "honeypot_access" for e in ev_store):
            state = DecisionState.CRITICAL
            action = "block"
            explanation = "Internal Honeypot Accessed"
            threat_confidence = 1.0
            
        elif rep.tier == 5:
            state = DecisionState.CRITICAL
            action = "block"
            explanation = "Confirmed Malicious IOC"
            threat_confidence = 0.99
            
        elif attack_score > benign_score and attack_score >= 2.0:
            explanation = hyp_results["attack"]["name"]
            if num_independent_sources >= 2 and attack_score >= 3.0:
                state = DecisionState.HIGH
                action = "alert"
                threat_confidence = 0.85
            else:
                state = DecisionState.SUSPICIOUS
                action = "monitor"
                threat_confidence = 0.40
                
        elif any(e.type == "ml_anomaly" and e.value > 0.90 for e in ev_store):
            state = DecisionState.ANOMALOUS
            action = "log"
            explanation = "ML Anomaly Only"
            threat_confidence = 0.10

        return {
            "state": state,
            "action": action,
            "explanation": explanation,
            "threat_confidence": threat_confidence,
            "independent_sources": num_independent_sources,
            "hypotheses": hyp_results,
            "evidence_verification_required": evidence_verification_required,
            "hypothesis_weight": hypothesis_weight,
        }
