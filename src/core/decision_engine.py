from typing import List, Dict, Any
from intelligence.hypotheses.evidence import Evidence
from intelligence.hypotheses.engine import HypothesisEngine
from intelligence.reputation.classifier import ReputationVector

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
        
        # Calculate independence groups
        attack_evidence = [e for e in ev_store if e.type.startswith("dns") or e.type == "reputation"]
        independence_groups = set(e.independence_group for e in attack_evidence)
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
            "hypotheses": hyp_results
        }
