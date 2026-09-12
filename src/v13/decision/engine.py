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
from typing import Any, Callable, Dict, FrozenSet, List, Optional

from v13.evidence.model import Evidence, NO_DESTINATION
from v13.hypotheses.engine import HypothesisEngine, HYPOTHESIS_RELEVANT_EVIDENCE_TYPES, score_evidence
from v13.hypotheses.independence import INDEPENDENCE_FAMILY_MAP, NON_ATTACK_FAMILIES, family_for
from utils import ZEEK_NOTICE_EVIDENCE_TYPES, ZEEK_NOTICE_ATTACK_SHAPED_EVIDENCE_TYPES

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


def _is_attack_shaped(e: Evidence) -> bool:
    """False for weak-tier zeek_notice evidence -- utils.py's
    ZEEK_NOTICE_ATTACK_SHAPED_EVIDENCE_TYPES already classifies it as
    "contributes nothing" (NetworkIntrusionHypothesis's own scoring already
    zeroes it out via _zeek_notice_weight(), utils.py's
    ZEEK_NOTICE_TIER_SCORE_WEIGHT["weak"]=0.0 -- a TCP-capture/protocol-edge-case
    artifact, not attacker behavior, per that hypothesis's own comment). Before
    this fix, attack_evidence never checked this -- a weak notice that
    contributed exactly zero to attack_score still counted as one of the
    independent families required to reach HIGH. True for every other evidence
    type -- this only ever narrows what ZEEK_NOTICE_EVIDENCE_TYPES itself
    already covers, not a new exclusion category."""
    if e.evidence_type in ZEEK_NOTICE_EVIDENCE_TYPES:
        return e.evidence_type in ZEEK_NOTICE_ATTACK_SHAPED_EVIDENCE_TYPES
    return True


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
    # BUGFIX (2026-09-12, caught by tests/test_real_world_alert_regression.py's own
    # Suricata scenario, no real fired alert of this shape existed to catch it live):
    # families this rule's OWN triggering evidence belongs to -- excluded from the
    # corroboration count checked below for THIS rule specifically, so a rule can't
    # satisfy its own `requires_corroboration` bar just by counting the very evidence
    # that fired it. geofence never needed this in practice (geofencing_violation's
    # family, "policy", is already globally excluded via NON_ATTACK_FAMILIES) --
    # but confirmed_exploit did: suricata_signature_match's family ("signature_match")
    # is NOT globally excluded (it must still be able to corroborate a DIFFERENT
    # hypothesis's verdict), so a lone Suricata match was trivially satisfying its
    # own >=1-independent-source requirement by counting itself, reaching CRITICAL
    # with zero real corroboration -- exactly the autonomy the 2026-09-10 policy
    # decision was supposed to remove. Set explicitly for both rules rather than
    # relying on geofence's exclusion being global-by-coincidence.
    own_families: FrozenSet[str] = field(default_factory=frozenset)


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
        own_families=frozenset({"policy"}),
    ),
    HardStopRule(
        name="confirmed_exploit",
        explanation="Confirmed Exploit/Malware Signature (Suricata)",
        confidence=0.98,
        decision_path="hard_stop",
        check=lambda ev_store, features, is_safe, now: _fresh_evidence_exists(
            ev_store, "suricata_signature_match", now, _HARD_STOP_FRESHNESS_SECONDS, min_confidence=0.9),
        # 2026-09-10 policy decision (AUDIT_V14_REVIEW_RESPONSE.md §2.1, user's explicit
        # choice): a lone Suricata severity=1 match used to auto-CRITICAL/block with no
        # corroboration -- unlike every other hard-stop here except geofence, a single
        # rule match (even against a curated ruleset) can still be a noisy Emerging
        # Threats false positive, and this rule was the one path left that could
        # autonomously tarpit a device off ONE signal. Same corroboration shape as
        # `geofence` above: a genuinely corroborated match (a second independent
        # evidence family, with the hypothesis engine agreeing attack > benign) still
        # reaches CRITICAL/block same as before; an uncorroborated one is HIGH/alert
        # (visible to the operator, not autonomously blocking) instead of a silent
        # auto-containment on a single rule hit.
        requires_corroboration=True,
        uncorroborated_state=DecisionState.HIGH,
        uncorroborated_explanation="Confirmed Exploit/Malware Signature (Suricata, Uncorroborated)",
        uncorroborated_confidence=0.75,
        uncorroborated_decision_path="suricata_uncorroborated",
        # BUGFIX (2026-09-12): unlike geofencing_violation, suricata_signature_match's
        # own family ("signature_match") is NOT in NON_ATTACK_FAMILIES -- it must stay
        # able to corroborate a DIFFERENT hypothesis's verdict -- so without this, a
        # lone Suricata match satisfied its OWN >=1-independent-source requirement by
        # counting itself, reaching CRITICAL with zero real corroboration. See
        # HardStopRule.own_families's own docstring for the full incident.
        own_families=frozenset({"signature_match"}),
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

        # BUGFIX (2026-09-10, user-identified): this used to be the raw, unfiltered
        # evidence_list. attack_score/benign_score two lines up are freshness-aware --
        # score_evidence() inside evaluate_all() already drops anything past its TTL
        # (600s default, 86400s for the "reputation" family) before scoring -- but
        # num_independent_sources/attack_evidence/evidence_families below had NO
        # freshness filter at all, so a stale item excluded from the SCORE could still
        # count as one of the >=2 independent families required to REACH a verdict.
        # Concretely: a dns_behavior anomaly from 20 hours ago (correctly excluded from
        # attack_score, long past its 600s TTL) could still pad num_independent_sources
        # to 2 alongside one genuinely fresh signal, reaching HIGH on evidence that in
        # reality was one live signal plus one dead one -- exactly backwards from "the
        # ground for alerts should be corroborative events, not events that happened in
        # the past, especially if no longer active." The same unfiltered set is also
        # what pipeline.py's Telegram WHY-block displays as "why this fired," so this
        # fixes both the escalation gate and what the operator sees justifying it.
        # Reuses score_evidence() -- the exact same function/TTLs evaluate_all() already
        # applied two lines up -- rather than inventing separate freshness logic. Safe
        # for the hard-stop checks below too: their own TTL (120s,
        # _HARD_STOP_FRESHNESS_SECONDS) is strictly tighter than the 600s/86400s bound
        # applied here, so nothing a 120s check would find is ever excluded by this.
        ev_store = [scored.evidence for scored in score_evidence(evidence_list, now=now)]

        partial_support = [e for e in ev_store if family_for(e.evidence_type) in _PARTIAL_SUPPORT_FAMILIES]
        if partial_support:
            hypothesis_weight = sum(_safe_confidence(e.confidence) for e in partial_support) / max(1, len(partial_support))
            has_meaningful_partial_signal = any(
                _safe_confidence(e.confidence) >= 0.5 and abs(_safe_float(e.value)) > 0.0 for e in partial_support
            )
            evidence_verification_required = hypothesis_weight >= 0.5 and (
                attack_score >= 2.0 or has_meaningful_partial_signal
            )

        # BUGFIX (2026-09-11, user-identified): zeek_notice_weak used to count
        # here despite _is_attack_shaped() -- see that function's own docstring.
        attack_evidence = [
            e for e in ev_store
            if family_for(e.evidence_type) not in NON_ATTACK_FAMILIES and _is_attack_shaped(e)
        ]

        # Gap-64 domain-linkage redesign, originally ported from
        # decision_engine.py:100-129, EXTENDED 2026-09-11 (user-identified, from a
        # real PEER_COHORT_DEVIATION alert: 3 evidence items about 3 unrelated
        # destinations -- one about Telegram's IP, one about Google's IP, one about
        # a Datacamp IP -- all counted as "independent evidence families" for a
        # verdict that isn't about any of them). Two gaps in the original version:
        #   1. Only checked family_for(e.evidence_type) == "reputation" -- a
        #      destination-mismatched dns_behavior/network_behavior item was never
        #      checked at all, even though "does this evidence actually relate to
        #      the winning hypothesis's own destination(s)?" applies just as much
        #      to those families as to reputation.
        #   2. Only ran under `if hyp_destinations:` -- a hypothesis whose OWN
        #      relevant evidence structurally never carries a destination
        #      (peer_deviation is created with destination_id=NO_DESTINATION by
        #      construction, live_engine.py -- PEER_COHORT_DEVIATION is a pure
        #      aggregate/volume statistic, "433 destinations vs a peer average of
        #      29.4," not about any one destination) leaves hyp_destinations
        #      permanently empty, so the whole check silently never engaged --
        #      every other family's evidence, about whatever destination it
        #      happened to be about, stayed in unfiltered. That's structurally
        #      different from "this hypothesis's evidence just didn't attribute a
        #      destination THIS cycle" (the original monotonic "never strip on
        #      missing info" reasoning) -- it's "this hypothesis is never ABOUT a
        #      destination," so there is nothing for other destination-carrying
        #      evidence to legitimately corroborate.
        # Fix: any evidence item carrying a real destination_id (not just
        # reputation-family) is only trusted as real corroboration when the
        # winning hypothesis itself supplies at least one destination to compare
        # against, AND that destination actually matches. No destination anchor
        # at all -> no destination-carrying evidence counts (nothing to verify
        # relatedness against); an anchor exists -> only evidence pointing at one
        # of those same destinations counts. Still monotonic (can only demote
        # attack_evidence, never add to it) and never touches destination-less
        # evidence (NO_DESTINATION items -- e.g. peer_deviation/
        # coordinated_targeting's own relevant evidence) either way.
        winning_attack_name = hyp_results["attack"]["name"]
        relevant_types = HYPOTHESIS_RELEVANT_EVIDENCE_TYPES.get(winning_attack_name)
        hyp_destinations = {
            e.destination_id for e in attack_evidence
            if relevant_types and e.evidence_type in relevant_types and e.destination_id != NO_DESTINATION
        } if relevant_types else set()
        attack_evidence = [
            e for e in attack_evidence
            if e.destination_id == NO_DESTINATION or e.destination_id in hyp_destinations
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
                # BUGFIX (2026-09-12): exclude this rule's OWN family from the count --
                # see HardStopRule.own_families's own docstring. Computed from
                # independence_families (not num_independent_sources) so a rule with no
                # own_families set (e.g. any future rule that doesn't need this) is
                # completely unaffected -- identical to the plain count.
                corroborating_sources = len(independence_families - rule.own_families)
                if corroborating_sources >= 1 and attack_score > benign_score:
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
        # BUGFIX (live audit, 2026-09-09): provenance was never serialized here, so a
        # zeek_notice item reaching pipeline.py's WHY-block through THIS bridge (real
        # corroborating evidence beyond the winning hypothesis's own RELEVANT_
        # EVIDENCE_TYPES slice) lost the real Notice::Type entirely -- confirmed live,
        # a real PEER_COHORT_DEVIATION alert showed the generic "Zeek policy notice
        # fired for this connection" with no note type, right alongside a DIFFERENT
        # alert (via winning_evidence/active_evidence, which DOES carry provenance)
        # showing the real type + tier correctly for the exact same evidence shape.
        full_attack_evidence = [
            {"evidence_type": e.evidence_type, "destination_id": e.destination_id, "features": e.features,
             "value": e.value, "confidence": e.confidence, "independence_family": family_for(e.evidence_type),
             "provenance": e.provenance}
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
