"""
v13 DecisionEngine (Phase 1/3 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Faithful port of core/decision_engine.py (495 lines, read in full this session
before writing anything). Scoring thresholds, the Gap-64 domain-linkage reputation
redesign, and every branch's decision_path/explanation/confidence are copied
exactly. Two structural changes, both deliberate and matching the plan, not
accidents:

1. NO SHADOW-MODE MACHINERY. v-current's shadow_state/shadow_explanation/
   shadow_decision_path/shadow_changed apparatus exists to compare "live vs a
   proposed fix" WITHIN v-current's own incremental-flip history -- a mechanism
   specific to that project's evidentiary discipline for flipping ONE mechanism
   at a time. v13 doesn't need an internal shadow concept: v13's own verdict IS
   the "shadow" relative to v-current during the whole-system parallel run (the
   plan's own comparator job, not something to duplicate inside this file).

2. HARD-STOPS ARE A PLUGGABLE REGISTRY, FRESHNESS-AWARE BY DEFAULT. v-current
   still hardcodes 4 elif branches, and only honeypot's freshness check is live
   (arp_spoof/geofence/confirmed_exploit's freshness checks exist but stay
   shadow-only, pending real divergence evidence -- Gap 3, DECISION_LOGIC_DEPENDENCY_MAP.md).
   v13 uses DEFAULT_HARD_STOP_REGISTRY (a plain list, extensible without touching
   this function) and makes every rule freshness-aware from day one -- this is a
   genuine behavioral difference from v-current's CURRENT LIVE behavior (though
   it matches v-current's own SHADOW computation for these three), and is exactly
   what the parallel run's divergence log is for: generating the live evidence
   Gap 3 has been waiting on, as a side effect of this rewrite rather than a
   separate effort.
"""
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from v13.evidence.model import Evidence, NO_DESTINATION
from v13.hypotheses.engine import HypothesisEngine, HYPOTHESIS_RELEVANT_EVIDENCE_TYPES, ScoredEvidence
from v13.hypotheses.independence import INDEPENDENCE_FAMILY_MAP, NON_ATTACK_FAMILIES, family_for

# Same 120s value core/decision_engine.py's own (now-removed, 2026-09-07 cleanup)
# shadow-only freshness constant used -- this is v13's real, LIVE equivalent.
_HARD_STOP_FRESHNESS_SECONDS = 120

# Matches decision_engine.py's partial_support family set -- adapted for v13's finer
# family split (independence.py's own documented discrepancy from v-current's
# EVIDENCE_FAMILIES): v1's {"dns_behavior", "zeek_network", "reputation", "honeypot"}
# becomes these five v13 families to cover the same conceptual ground now that
# "zeek_network" is split three ways and "honeypot" is named "direct_observation".
_PARTIAL_SUPPORT_FAMILIES = frozenset({
    "dns_behavior", "tls_fingerprint", "network_behavior", "data_transfer_pattern",
    "reputation", "direct_observation",
})


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


def _fresh_evidence_exists(ev_store: List[Evidence], evidence_type: str, now: float,
                             ttl_seconds: float, min_confidence: Optional[float] = None) -> bool:
    for e in ev_store:
        if e.evidence_type != evidence_type:
            continue
        if min_confidence is not None and e.confidence < min_confidence:
            continue
        if (now - e.timestamp) <= ttl_seconds:
            return True
    return False


@dataclass
class HardStopRule:
    name: str
    explanation: str
    confidence: float
    decision_path: str
    check: Callable[[List[Evidence], Optional[Dict[str, Any]], bool, float], bool]
    requires_corroboration: bool = False
    uncorroborated_state: str = DecisionState.HIGH
    uncorroborated_explanation: str = ""
    uncorroborated_confidence: float = 0.0
    uncorroborated_decision_path: str = ""


# Honeypot reads features["zeek_honeypot_hits"] directly (matches v-current's
# fresh_honeypot exactly -- the same raw signal pipeline.py itself gates evidence
# creation on, sidestepping the evidence-store timing question entirely) plus the
# is_safe exemption (BUGFIX precedent in v-current: safe_ips devices touching the
# honeypot for benign reasons is expected). The other three use fresh evidence-store
# presence, freshness-aware by default -- see this module's own docstring for why
# that's a deliberate generational difference from v-current's current live behavior.
DEFAULT_HARD_STOP_REGISTRY: List[HardStopRule] = [
    HardStopRule(
        name="honeypot",
        explanation="Internal Honeypot Accessed",
        confidence=1.0,
        decision_path="hard_stop",
        check=lambda ev_store, features, is_safe, now: (
            bool(features) and _safe_float((features or {}).get("zeek_honeypot_hits", 0)) > 0
            and not is_safe
        ),
    ),
    HardStopRule(
        name="arp_spoof",
        explanation="Layer-2 ARP Spoofing Detected",
        confidence=1.0,
        decision_path="hard_stop",
        check=lambda ev_store, features, is_safe, now: _fresh_evidence_exists(
            ev_store, "arp_spoofing", now, _HARD_STOP_FRESHNESS_SECONDS),
    ),
    HardStopRule(
        name="geofence",
        explanation="Geofencing Policy Violation",
        confidence=0.95,
        decision_path="hard_stop",
        check=lambda ev_store, features, is_safe, now: _fresh_evidence_exists(
            ev_store, "geofencing_violation", now, _HARD_STOP_FRESHNESS_SECONDS),
        requires_corroboration=True,
        uncorroborated_state=DecisionState.HIGH,
        uncorroborated_explanation="Geofencing Policy Violation (Uncorroborated)",
        uncorroborated_confidence=0.70,
        uncorroborated_decision_path="geofence_uncorroborated",
    ),
    HardStopRule(
        name="confirmed_exploit",
        explanation="Confirmed Exploit/Malware Signature (Suricata)",
        confidence=0.98,
        decision_path="hard_stop",
        check=lambda ev_store, features, is_safe, now: _fresh_evidence_exists(
            ev_store, "suricata_signature_match", now, _HARD_STOP_FRESHNESS_SECONDS, min_confidence=0.9),
    ),
]


class DecisionEngine:
    def __init__(self, hard_stop_registry: Optional[List[HardStopRule]] = None):
        self.hypothesis_engine = HypothesisEngine()
        # Pluggable -- a deployment can add/remove/reorder hard-stop rules without
        # touching evaluate() at all, unlike v-current's 4 hardcoded elif branches.
        self.hard_stop_registry = hard_stop_registry if hard_stop_registry is not None else DEFAULT_HARD_STOP_REGISTRY

    def evaluate(self, evidence_list: List[Evidence], rep, device_type: str = "",
                  baseline_familiarity: float = 0.0, features: Optional[dict] = None,
                  is_safe: bool = False, now: Optional[float] = None) -> Dict[str, Any]:
        now = now if now is not None else time.time()
        hyp_results = self.hypothesis_engine.evaluate_all(
            evidence_list, rep, device_type, baseline_familiarity, now=now)

        attack_score = hyp_results["attack"]["score"]
        benign_score = hyp_results["benign"]["score"]
        evidence_verification_required = False
        hypothesis_weight = 0.0

        # ev_store here is the raw (unfiltered-by-freshness) evidence_list -- hard-stop
        # checks and the partial-support/attack-evidence logic below all want to see
        # everything with its OWN freshness semantics (hard-stops use their own TTL;
        # HypothesisEngine already applied its own TTL internally above).
        ev_store = evidence_list

        partial_support = [e for e in ev_store if family_for(e.evidence_type) in _PARTIAL_SUPPORT_FAMILIES]
        if partial_support:
            hypothesis_weight = sum(_safe_confidence(e.confidence) for e in partial_support) / max(1, len(partial_support))
            has_meaningful_partial_signal = any(
                _safe_confidence(e.confidence) >= 0.5 and abs(_safe_float(e.value)) > 0.0 for e in partial_support
            )
            evidence_verification_required = hypothesis_weight >= 0.5 and (
                attack_score >= 2.0 or has_meaningful_partial_signal
            )

        attack_evidence = [e for e in ev_store if family_for(e.evidence_type) not in NON_ATTACK_FAMILIES]

        # Gap-64 domain-linkage redesign, ported exactly (decision_engine.py:100-129):
        # strip a reputation-family item ONLY when it carries a destination that
        # AFFIRMATIVELY differs from the winning attack hypothesis's own relevant
        # evidence destinations -- never when either side lacks that info. Monotonic:
        # can only demote, never escalate.
        winning_attack_name = hyp_results["attack"]["name"]
        relevant_types = HYPOTHESIS_RELEVANT_EVIDENCE_TYPES.get(winning_attack_name)
        hyp_destinations = {
            e.destination_id for e in attack_evidence
            if relevant_types and e.evidence_type in relevant_types and e.destination_id != NO_DESTINATION
        } if relevant_types else set()
        if hyp_destinations:
            attack_evidence = [
                e for e in attack_evidence
                if not (
                    family_for(e.evidence_type) == "reputation"
                    and e.destination_id != NO_DESTINATION
                    and e.destination_id not in hyp_destinations
                )
            ]

        independence_families = {family_for(e.evidence_type) for e in attack_evidence}
        num_independent_sources = len(independence_families)

        trail: List[str] = []
        hyp_line = (
            f"Hypotheses: attack='{winning_attack_name}' (score={attack_score:.1f}) "
            f"vs benign='{hyp_results['benign']['name']}' (score={benign_score:.1f}) — "
            f"{num_independent_sources} independent evidence source(s)"
        )
        if attack_score == 0.0 and benign_score == 0.0:
            hyp_line += " — no hypothesis explains this evidence either way; verdict below rests on reputation context alone"
        trail.append(hyp_line)

        state = DecisionState.BENIGN
        action = "suppress"
        explanation = hyp_results["benign"]["name"]
        threat_confidence = 0.0
        decision_path = "benign"

        # --- pluggable hard-stop registry (replaces v-current's 4 hardcoded elifs) ---
        hard_stop_fired = None
        for rule in self.hard_stop_registry:
            if rule.check(ev_store, features, is_safe, now):
                hard_stop_fired = rule
                break

        if hard_stop_fired:
            rule = hard_stop_fired
            trail.append(f"Hard-stop fired: {rule.name}")
            if rule.requires_corroboration:
                if num_independent_sources >= 1 and attack_score > benign_score:
                    state = DecisionState.CRITICAL
                    action = "block"
                    explanation = rule.explanation
                    threat_confidence = rule.confidence
                    decision_path = rule.decision_path
                else:
                    state = rule.uncorroborated_state
                    action = "alert"
                    explanation = rule.uncorroborated_explanation
                    threat_confidence = rule.uncorroborated_confidence
                    decision_path = rule.uncorroborated_decision_path
            else:
                state = DecisionState.CRITICAL
                action = "block"
                explanation = rule.explanation
                threat_confidence = rule.confidence
                decision_path = rule.decision_path

        elif rep.tier == 5:
            if getattr(rep, "verified_ioc", False):
                state = DecisionState.CRITICAL
                action = "block"
                explanation = "Confirmed Malicious IOC"
                threat_confidence = 0.99
                decision_path = "tier5_confirmed"
            # TIGHTENED (third-party architecture review, 2026-09-09): was
            # `>= 1` -- rep.tier==5 here (not verified_ioc) can be reached by a
            # bare crowd-sourced AbuseIPDB score (>=4.0) alone, not a curated
            # threat-intel feed match. Reaching CRITICAL from that plus just ONE
            # weak, possibly-single-family corroborating hint was the weakest path
            # to auto-block in the whole engine -- weaker than HIGH's own bar.
            # CRITICAL should never require LESS corroboration than HIGH; now it
            # requires the same >=2-independent-family bar.
            elif num_independent_sources >= 2 and attack_score > benign_score:
                state = DecisionState.CRITICAL
                action = "block"
                explanation = "Corroborated Reputation Signal"
                threat_confidence = 0.85
                decision_path = "tier5_corroborated"
            else:
                state = DecisionState.SUSPICIOUS
                action = "monitor"
                explanation = "Elevated Reputation Signal (Unconfirmed, Tier 5 Score)"
                threat_confidence = 0.45
                decision_path = "tier5_uncorroborated"

        elif attack_score > benign_score and attack_score >= 2.0:
            explanation = winning_attack_name
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

        else:
            rep_vt = getattr(rep, "vt_detection_ratio", 0.0) or 0.0
            rep_ti = getattr(rep, "ti_risk", 0.0) or 0.0
            rep_abuse = getattr(rep, "abuse_risk", 0.0) or 0.0
            if rep.tier == 4 and max(rep_vt, rep_ti, rep_abuse) >= 1.5:
                state = DecisionState.SUSPICIOUS
                action = "monitor"
                explanation = "Elevated Reputation Signal (Unconfirmed)"
                threat_confidence = 0.45
                decision_path = "tier4_unconfirmed"
            elif any(e.evidence_type == "ml_anomaly" and (e.value or 0.0) > 0.90 for e in ev_store):
                state = DecisionState.ANOMALOUS
                action = "log"
                explanation = "ML Anomaly Only"
                threat_confidence = 0.10
                decision_path = "ml_anomaly"

        trail.append(f"Verdict: {state} / {action} — {explanation} (confidence={threat_confidence:.2f})")

        # BUGFIX (live audit, 2026-09-09): pipeline.py's alert-building step has its
        # own destination-attribution switch (per primary_sig_base) that reaches back
        # into active_evidence for the real evidence-linked domain/IP a given
        # signature fired on -- but that switch can only see pipeline.py's OWN v1
        # Evidence store, never the v13-only synthetic evidence
        # (coordinated_targeting/peer_deviation, live_engine.py's
        # _inject_graph_derived_evidence()/_inject_peer_deviation_evidence()) that
        # only ever existed inside THIS evaluate() call's evidence_list. Confirmed
        # live: COORDINATED_TARGETING/PEER_COHORT_DEVIATION alerts (the two highest-
        # volume signatures, ~57% of unsuppressed HIGH alerts in a 7h sample)
        # displayed "Contacted <most-recent-connection>" -- almost always multicast
        # (mDNS/SSDP/ICMPv6) since that's simply the most frequent LAN traffic --
        # completely unrelated to the real coordinated destination or peer-cohort
        # statistic that actually satisfied the hypothesis.
        #
        # BUGFIX (found live, same day, checking a real sent alert -- NEVER actually
        # worked since the day it was written): this used to filter from
        # attack_evidence, which excludes NON_ATTACK_FAMILIES members --
        # peer_cohort_deviation (peer_deviation's own family) is one of those (this
        # session's own earlier fix, generalizing the third-party review's original
        # exclusion). PeerDeviationHypothesis's RELEVANT_EVIDENCE_TYPES is ONLY
        # {"peer_deviation"} -- so for every PEER_COHORT_DEVIATION-winning cycle ever,
        # winning_evidence was structurally guaranteed empty, and pipeline.py's own
        # "Talked to N distinct destinations vs peer average" behavioral-stat line
        # (added the same original session as this field) silently never fired,
        # falling through to the generic "Contacted `unknown`" line instead -- exactly
        # what every real PEER_COHORT_DEVIATION alert this whole conversation has
        # shown. Excluding a family from CORROBORATION-counting (why it's in
        # NON_ATTACK_FAMILIES) is a different question from whether that hypothesis's
        # own evidence should be DISPLAYABLE -- reads from ev_store (the raw,
        # unfiltered-by-NON_ATTACK_FAMILIES evidence list) instead. Safe widening for
        # every OTHER consumer (COORDINATED_TARGETING/DATA_EXFILTRATION/C2_BEACONING's
        # own relevant types are all real attack families already, never excluded by
        # NON_ATTACK_FAMILIES, so this changes nothing for them) -- and Gap-64's own
        # domain-linkage stripping above only ever touches "reputation"-family items,
        # never peer_deviation/coordinated_targeting/zeek_exfiltration/zeek_beaconing,
        # so nothing Gap-64 would have stripped is reintroduced here either.
        winning_evidence = [
            {"evidence_type": e.evidence_type, "destination_id": e.destination_id, "features": e.features,
             "value": e.value, "confidence": e.confidence}
            for e in ev_store if relevant_types and e.evidence_type in relevant_types
        ]

        # BUGFIX (live audit, 2026-09-09, third-party ChatGPT review): pipeline.py's
        # persisted hee_evidence_families/hee_evidence_types have ALWAYS been recomputed
        # independently from active_evidence (pipeline.py's own v1 evidence store) rather
        # than read from here -- confirmed live via a real 24h extraction: 34 of 121
        # would-send alerts show hee_evidence_families=[] (empty) while
        # hee_independent_sources correctly shows 2-4 and attack_score 3.0-4.0, EVERY one
        # of them a v13-only-synthetic-evidence-driven signature (COORDINATED_TARGETING/
        # PEER_COHORT_DEVIATION -- family cross_device_correlation/peer_cohort_deviation
        # never exists in active_evidence, same root cause f027a6f already fixed for
        # alert_dest_ip alone). The Telegram message's own "WHY (N independent evidence
        # families)" line reads this same buggy computation, so it displayed a HIGH/85%
        # verdict alongside "0 independent evidence families" -- looks like (and was
        # flagged as) an invariant violation, even though num_independent_sources/
        # independence_families computed just above -- the ACTUAL values that gated the
        # verdict -- were always correct. independence_families here already IS the
        # ground truth num_independent_sources counts against -- exposing it directly
        # instead of pipeline.py re-deriving a different, incomplete answer.
        evidence_families = sorted(independence_families)
        evidence_types = sorted({e.evidence_type for e in attack_evidence})

        # BUGFIX (live audit, 2026-09-09, real production alerts): winning_evidence
        # above is scoped to just the WINNING hypothesis's own RELEVANT_EVIDENCE_TYPES
        # -- correct for destination attribution (pipeline.py's alert_dest_ip switch),
        # but wrong for the Telegram WHY-block's evidence list, which needs EVERY
        # family that actually backs independent_sources, not just the winning
        # hypothesis's own. Confirmed live: a real PEER_COHORT_DEVIATION HIGH alert
        # persisted hee_independent_sources=4/hee_evidence_families correctly (this
        # session's own evidence_families fix, above) but the ACTUAL SENT TELEGRAM
        # TEXT showed only 1 (sometimes 0) families -- because pipeline.py's WHY-block
        # loops over its OWN active_evidence (a short ~600s-TTL local snapshot,
        # EvidenceStore.get_for_device()), while independence_families here draws on
        # v13's graph-window query (up to 86400s / 24h, live_engine.py's
        # _query_graph_window()) -- corroborating evidence older than ~10 minutes is
        # still valid for THIS decision but has already aged out of pipeline.py's own
        # short-TTL list, so the WHY-block literally cannot see it no matter how the
        # display code is written, UNLESS the decision hands it over explicitly.
        # attack_evidence is exactly that -- the full post-domain-stripping set
        # independent_sources counts against -- serialized (Evidence isn't JSON-safe
        # as-is) the same way winning_evidence already is, plus independence_family so
        # pipeline.py doesn't need its own type-to-family mapping to consume it.
        full_attack_evidence = [
            {"evidence_type": e.evidence_type, "destination_id": e.destination_id, "features": e.features,
             "value": e.value, "confidence": e.confidence, "independence_family": family_for(e.evidence_type)}
            for e in attack_evidence
        ]

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
            "winning_evidence": winning_evidence,
            "evidence_families": evidence_families,
            "evidence_types": evidence_types,
            "attack_evidence": full_attack_evidence,
        }
