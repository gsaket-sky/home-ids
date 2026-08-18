from typing import List, Dict, Any
from intelligence.hypotheses.evidence import Evidence
from intelligence.hypotheses.engine import HypothesisEngine
from intelligence.reputation.classifier import ReputationVector

def _safe_float(val: Any) -> float:
    try:
        return float(val) if val is not None else 0.0
    except (ValueError, TypeError):
        return 0.0

def _safe_confidence(val: Any) -> float:
    return min(1.0, max(0.0, _safe_float(val)))

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
            hypothesis_weight = sum(_safe_confidence(e.confidence) for e in partial_support) / max(1, len(partial_support))
            has_meaningful_partial_signal = any(
                _safe_confidence(e.confidence) >= 0.5 and abs(_safe_float(e.value)) > 0.0 for e in partial_support
            )
            evidence_verification_required = hypothesis_weight >= 0.5 and (
                attack_score >= 2.0 or has_meaningful_partial_signal
            )
        
        # Calculate independence groups from the evidence that materially contributes to attack scoring.
        attack_evidence = [
            e for e in ev_store
            if e.type.startswith("dns") or e.type == "reputation" or e.type.startswith("zeek") or e.type == "ml_anomaly" or e.independence_group in {"reputation", "zeek_network", "honeypot", "ml_anomaly"}
        ]
        independence_groups = {e.independence_group for e in attack_evidence if e.independence_group}
        num_independent_sources = len(independence_groups)

        # PHASE 8 FIX: a human-readable record of what this evaluation actually checked, in
        # the order it checked it, built alongside the decision itself (not reconstructed
        # after the fact from the final numbers) so a Telegram alert can show the real
        # reasoning chain instead of two disconnected, sometimes-contradicting subsystems
        # concatenated together. rep fields are read via getattr() since some callers
        # (e.g. tests/regression_tester.py's MockRep) intentionally duck-type only `.tier`.
        rep_owner = getattr(rep, "asn_owner", None) or "Unknown"
        rep_domain = getattr(rep, "domain", "") or "n/a"
        rep_vt = getattr(rep, "vt_detection_ratio", 0.0) or 0.0
        rep_ti = getattr(rep, "ti_risk", 0.0) or 0.0
        rep_abuse = getattr(rep, "abuse_risk", 0.0) or 0.0

        has_honeypot = any(e.type == "honeypot_access" for e in ev_store)
        has_arp_spoof = any(e.type == "arp_spoofing" for e in ev_store)
        has_geofence = any(e.type == "geofencing_violation" for e in ev_store)

        # PHASE 10 FIX: "tier" is context/prior about a destination (how much prior trust or
        # suspicion attaches to it), not a threat verdict — tier 4 means "one unconfirmed
        # signal exists", not "this is 4x more dangerous than tier 1". Spelling that out
        # inline (rather than just printing the bare number) is a direct response to a
        # third-party review of a real alert: "tier=4, IP owner='Telegram'" read side by
        # side looked like the system was calling known infrastructure suspicious, when the
        # actual claim is much narrower — one unconfirmed reputation signal, nothing more.
        tier_note = {
            0: "local/internal", 1: "trusted", 2: "known infrastructure",
            3: "unclassified — neutral, not malicious",
            4: "one unconfirmed signal — context, not a verdict",
            5: "corroborated across independent sources",
        }.get(rep.tier, "unrecognized")

        trail: List[str] = [
            (
                f"Hard-stop checks: honeypot={'YES' if has_honeypot else 'no'}, "
                f"arp_spoofing={'YES' if has_arp_spoof else 'no'}, "
                f"geofencing={'YES' if has_geofence else 'no'}"
            ),
            (
                f"Reputation context: tier={rep.tier} ({tier_note}) — target='{rep_domain}', "
                f"VT={rep_vt:.1f}, TI={rep_ti:.1f}, AbuseIPDB={rep_abuse:.1f}, "
                f"IP owner='{rep_owner}'"
            ),
        ]
        hyp_line = (
            f"Hypotheses: attack='{hyp_results['attack']['name']}' (score={attack_score:.1f}) "
            f"vs benign='{hyp_results['benign']['name']}' (score={benign_score:.1f}) — "
            f"{num_independent_sources} independent evidence source(s)"
        )
        if attack_score == 0.0 and benign_score == 0.0:
            # Neither hypothesis found supporting evidence — this is a materially different
            # situation from "the engine weighed the evidence and leaned suspicious"; say so
            # explicitly rather than leaving a reader to infer it from two zeros.
            hyp_line += " — no hypothesis explains this evidence either way; verdict below rests on reputation context alone"
        trail.append(hyp_line)

        state = DecisionState.BENIGN
        action = "suppress"
        explanation = hyp_results["benign"]["name"]
        threat_confidence = 0.0
        # PHASE 18: which branch below actually resolved this evaluation -- exported as
        # home_ids_decision_path_total{path} so the mix (hard_stop/tier5 share shrinking,
        # benign share growing over weeks) is the direct, graphable "is the system getting
        # smarter over time" signal across all of Brain 1, not just CL-AFPE.
        decision_path = "benign"

        if has_honeypot:
            state = DecisionState.CRITICAL
            action = "block"
            explanation = "Internal Honeypot Accessed"
            threat_confidence = 1.0
            decision_path = "hard_stop"
            
        elif has_arp_spoof:
            state = DecisionState.CRITICAL
            action = "block"
            explanation = "Layer-2 ARP Spoofing Detected"
            threat_confidence = 1.0
            decision_path = "hard_stop"
            
        elif has_geofence:
            state = DecisionState.CRITICAL
            action = "block"
            explanation = "Geofencing Policy Violation"
            threat_confidence = 1.0
            decision_path = "hard_stop"
            
        elif rep.tier == 5:
            state = DecisionState.CRITICAL
            action = "block"
            explanation = "Confirmed Malicious IOC"
            threat_confidence = 0.99
            decision_path = "tier5_confirmed"
            
        elif attack_score > benign_score and attack_score >= 2.0:
            explanation = hyp_results["attack"]["name"]
            if num_independent_sources >= 2 and attack_score >= 3.0:
                state = DecisionState.HIGH
                action = "alert"
                threat_confidence = 0.85
                decision_path = "hypothesis_high"
            else:
                state = DecisionState.SUSPICIOUS
                action = "monitor"
                threat_confidence = 0.40
                decision_path = "hypothesis_suspicious"

        elif rep.tier == 4 and max(rep_vt, rep_ti, rep_abuse) >= 1.5:
            # PHASE 8 FIX: before this branch existed, a reputation signal that never rose
            # to "confirmed" (tier 5) had exactly one path through this function: silence.
            # The ONLY thing standing between "99% Confirmed Malicious IOC" and "nothing at
            # all" was a single classify() threshold — there was no representation for "a
            # real but unconfirmed signal, worth a human's attention, not worth an
            # auto-block" (exactly the 149.154.166.110/Telegram case). Mirrors the tier==5
            # branch above at lower confidence and "monitor" instead of "block": reputation
            # alone never auto-contains unless it's corroborated (tier 5) or paired with
            # real behavioral evidence (the attack_score branch above already covers that).
            state = DecisionState.SUSPICIOUS
            action = "monitor"
            explanation = "Elevated Reputation Signal (Unconfirmed)"
            threat_confidence = 0.45
            decision_path = "tier4_unconfirmed"

        elif any(e.type == "ml_anomaly" and e.value > 0.90 for e in ev_store):
            state = DecisionState.ANOMALOUS
            action = "log"
            explanation = "ML Anomaly Only"
            threat_confidence = 0.10
            decision_path = "ml_anomaly"

        trail.append(f"Verdict: {state} / {action} — {explanation} (confidence={threat_confidence:.2f})")

        return {
            "state": state,
            "action": action,
            "explanation": explanation,
            "threat_confidence": threat_confidence,
            "independent_sources": num_independent_sources,
            "hypotheses": hyp_results,
            "evidence_verification_required": evidence_verification_required,
            "hypothesis_weight": hypothesis_weight,
            "reasoning_trail": trail,
            "decision_path": decision_path,
        }
