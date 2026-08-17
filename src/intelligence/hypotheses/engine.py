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

# ══════════════════════════════════════════════════════════════════════════════════════
# PHASE 1: Hypotheses ported from the dead mitigation/scoring.py RiskScorer. scoring.py
# computed these signal categories but was never imported by the live pipeline (confirmed
# dead code — see audit Finding #1). threat_signals.py's ThreatSignalDetector now emits
# the underlying Evidence; these hypotheses are what actually consumes it and lets it
# reach DecisionEngine.
# ══════════════════════════════════════════════════════════════════════════════════════

class DGAHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("DGA_BOTNET_C2")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "dns_dga_burst"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.type == "dns_rate" and e.value > 100 for e in ev_store):
            self.strong_score += 1.0

        score = 2.0  # Suspicious
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0  # Probable
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0 and rep_vector.tier in (3, 4, 5):
            score = 4.0  # High
        return score


class ExfiltrationHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("DATA_EXFILTRATION")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "zeek_exfiltration"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.type in ("zeek_beaconing", "reputation") for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.contradicting_score == 0:
            score = 4.0
        return score


class BeaconingHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("C2_BEACONING")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "zeek_beaconing"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.type in ("zeek_exfiltration", "reputation", "malicious_ja3", "malicious_ja4") for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        return score


class DNSTunnelingV2Hypothesis(Hypothesis):
    """Distinct from DNSTunnelingHypothesis above (which is really a rate+entropy burst
    detector despite its name). This one uses the actual tunneling signals scoring.py
    computed: long/encoded subdomain labels, TXT/NULL query abuse, and suspicious-TLD
    concentration — broadens coverage rather than replacing the existing hypothesis."""

    def __init__(self):
        super().__init__("DNS_COVERT_TUNNELING")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "dns_tunnel_v2"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)
        # PHASE 1 FIX: provenance format is
        # "detector:threat_signals:dns_tunnel_v2:{subtag}:{note}" — split(":", 4) with
        # maxsplit=4 yields exactly 5 parts, so index [3] is always the stable category
        # subtag (e.g. "txt_null_abuse"), never the free-text note (which varies
        # cycle-to-cycle). The previous `rsplit(":", 1)[0]` grouped ALL dns_tunnel_v2 hits
        # under the same prefix regardless of which of the three tunneling checks fired,
        # so this "2+ distinct categories" bonus could never actually trigger.
        distinct_signals = len({
            e.provenance.split(":", 4)[3] if e.provenance.count(":") >= 3 else e.provenance
            for e in hits
        })

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if distinct_signals >= 2:
            self.strong_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0 and rep_vector.tier in (3, 4):
            score = 4.0
        return score


class ConnectionAbuseHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("CONNECTION_ABUSE")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector) -> float:
        self._reset_eval_state()
        scan_hits = [e for e in ev_store if e.type == "zeek_conn_abuse"]
        long_hits = [e for e in ev_store if e.type == "zeek_long_conn"]
        self.required_satisfied = bool(scan_hits or long_hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in (scan_hits + long_hits))

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if scan_hits and long_hits:
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        return score


class HypothesisEngine:
    def __init__(self):
        self.attack_hypotheses = [
            DNSTunnelingHypothesis(), NetworkIntrusionHypothesis(),
            DGAHypothesis(), ExfiltrationHypothesis(), BeaconingHypothesis(),
            DNSTunnelingV2Hypothesis(), ConnectionAbuseHypothesis(),
        ]
        self.benign_hypotheses = [AdvertisingBurstHypothesis()]

    def evaluate_all(self, ev_store: List[Evidence], rep: ReputationVector) -> Dict[str, Any]:
        best_attack = None
        best_attack_score = 0.0
        
        for h in self.attack_hypotheses:
            score = h.evaluate(ev_store, rep)
            if score > best_attack_score:
                best_attack_score = score
                best_attack = h

        best_benign = None
        best_benign_score = 0.0
        
        for h in self.benign_hypotheses:
            score = h.evaluate(ev_store, rep)
            if score > best_benign_score:
                best_benign_score = score
                best_benign = h

        return {
            "attack": {"name": best_attack.name if best_attack else "DIRECT_IOC_HIT", "score": best_attack_score},
            "benign": {"name": best_benign.name if best_benign else "UNKNOWN_BENIGN", "score": best_benign_score}
        }
