from typing import List, Dict, Any
from intelligence.hypotheses.evidence import Evidence, EvidenceStore
from intelligence.reputation.classifier import ReputationVector

class Hypothesis:
    def __init__(self, name: str):
        self.name = name
        self.required_satisfied = False
        self.strong_score = 0.0
        self.supporting_score = 0.0
        self.contradicting_score = 0.0

    def _reset_eval_state(self) -> None:
        self.required_satisfied = False
        self.strong_score = 0.0
        self.supporting_score = 0.0
        self.contradicting_score = 0.0

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector) -> float:
        """Returns confidence score 0-4"""
        raise NotImplementedError

class DNSTunnelingHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("DNS_TUNNELING")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector) -> float:
        self._reset_eval_state()
        # Check requirements
        has_high_rate = any(e.type == "dns_rate" and e.value > 100 for e in ev_store)
        has_high_entropy = any(e.type == "dns_entropy" and e.value > 4.0 for e in ev_store)
        
        self.required_satisfied = has_high_rate and has_high_entropy
        if not self.required_satisfied:
            return 0.0

        # Strong
        if any(e.type == "dns_unique_ratio" and e.value > 0.8 for e in ev_store):
            self.strong_score += 1.0

        # Contradicting
        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0

        score = 2.0 # Suspicious
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0 # Probable
        if self.strong_score > 0.5 and self.contradicting_score == 0 and rep_vector.tier in (3, 4):
            score = 4.0 # High

        return score


class NetworkIntrusionHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("NETWORK_INTRUSION")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector) -> float:
        self._reset_eval_state()
        # Check requirements: Zeek evidence
        has_lateral_scan = any(e.type == "zeek_lateral_scan" and e.value > 0 for e in ev_store)
        has_malicious_tls = any(e.type in ("malicious_ja3", "malicious_ja4", "zeek_notice") for e in ev_store)
        
        self.required_satisfied = has_lateral_scan or has_malicious_tls
        if not self.required_satisfied:
            return 0.0

        # Strong
        if has_lateral_scan and has_malicious_tls:
            self.strong_score += 1.0

        # Contradicting
        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0

        score = 2.0 # Suspicious
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0 # Probable
        if self.strong_score > 0.5 and self.contradicting_score == 0 and rep_vector.tier in (3, 4, 5):
            score = 4.0 # High
            
        # Hard escalate for lateral scans (very rarely benign on a home network)
        if has_lateral_scan and self.contradicting_score == 0:
            score = 4.0

        return score

class AdvertisingBurstHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("ADVERTISING_BURST")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector) -> float:
        self._reset_eval_state()
        has_high_rate = any(e.type == "dns_rate" and e.value > 50 for e in ev_store)
        
        self.required_satisfied = has_high_rate and (rep_vector.tier == 2)
        if not self.required_satisfied:
            return 0.0
            
        score = 3.0
        if not any(e.type == "dns_entropy" and e.value > 4.0 for e in ev_store):
            score = 4.0 # High confidence it's just ads
            
        return score

class HypothesisEngine:
    def __init__(self):
        self.attack_hypotheses = [DNSTunnelingHypothesis(), NetworkIntrusionHypothesis()]
        self.benign_hypotheses = [AdvertisingBurstHypothesis()]

    def evaluate_all(self, ev_store: List[Evidence], rep: ReputationVector) -> Dict[str, Any]:
        best_attack = None
        best_attack_score = -1.0
        
        for h in self.attack_hypotheses:
            score = h.evaluate(ev_store, rep)
            if score > best_attack_score:
                best_attack_score = score
                best_attack = h

        best_benign = None
        best_benign_score = -1.0
        
        for h in self.benign_hypotheses:
            score = h.evaluate(ev_store, rep)
            if score > best_benign_score:
                best_benign_score = score
                best_benign = h

        return {
            "attack": {"name": best_attack.name if best_attack else "None", "score": best_attack_score},
            "benign": {"name": best_benign.name if best_benign else "None", "score": best_benign_score}
        }
