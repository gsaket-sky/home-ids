import logging
from typing import Dict, Any, List, Optional
from intelligence.hypotheses.evidence import Evidence, ATTACK_SHAPED_EVIDENCE_TYPES
from intelligence.fp_engine import FAMILIARITY_TRUST_BAR

# PHASE 58b: reputation tiers treated as "trusted/known infrastructure" -- matches
# DeviceProfileBenignHypothesis's own is_trusted_destination check (hypotheses/
# engine.py: `rep_vector.tier in (0, 1, 2)`) verbatim, so the validator requires the
# SAME bar the deterministic engine already requires before it will let a device-type
# explanation stand in for genuine evidence.
_TRUSTED_REP_TIERS = frozenset({0, 1, 2})

LOGGER = logging.getLogger(__name__)

def _safe_float(val: Any) -> float:
    try:
        return float(val) if val is not None else 0.0
    except (TypeError, ValueError):
        return 0.0

# PHASE 50 (ollama_soc.py HEE ground-truth wiring): decision_engine.py's own
# `decision_path` values that represent a genuinely corroborated attack conclusion --
# either a hard-stop (honeypot/ARP-spoof/geofence/confirmed-exploit), a tier-5 IOC
# confirmed or corroborated across independent families, or a named attack hypothesis
# that cleared the >=2-independent-family / attack_score>=3.0 HIGH bar
# (hypotheses/engine.py, decision_engine.py:236-247). If THIS SAME ALERT already
# reached one of these paths when the live pipeline first evaluated it, an LLM
# free-text "benign, suppress" verdict reviewing it hours later is disagreeing with a
# multi-family-corroborated deterministic finding, not just a low/ambiguous score --
# exactly the situation the evidence-family concept exists to make un-overridable by a
# single paragraph of LLM reasoning.
_STRONG_ATTACK_DECISION_PATHS = frozenset({
    "hard_stop", "tier5_confirmed", "tier5_corroborated", "hypothesis_high",
})

# PHASE 57 (evidence fingerprint + validator-schema versioning): bump this any time
# DeterministicValidator.validate()'s logic changes. ollama_soc.py folds this into its
# persistent cache key (_persistent_cache_key()), so a version bump makes every
# previously-cached verdict unreachable by lookup immediately -- the next run re-derives
# it fresh under the new rules instead of trusting a `validator_passed` boolean that was
# computed under logic that no longer exists. Set to 2 here because Phase 51 (commit
# 3a3c21c, 2026-09-03) already replaced the original 2-rule validator (bare IOC>=4.0 veto,
# "telemetry"-substring veto only) with today's structured-evidence-aware logic -- that
# was version 1, implicitly, before this constant existed; this is the first change to
# formally version it. See Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's Gap 6 root
# cause for the live bug this closes: cache hits previously never re-ran validate() at
# all, so the pre-Phase-51 validator's verdicts on already-cached patterns were still
# being trusted indefinitely, unchanged, well after Phase 51 shipped.
#
# Bumped to 3 by Phase 58 (attack-shaped-evidence check, see below) -- the first actual
# use of this versioning mechanism to invalidate existing cache entries the way it was
# built for. Bumped to 4 by Phase 58b (destination-ownership/baseline-familiarity check).
# Bumped to 5 by Phase 63 (hypothesis-independence check, see below).
VALIDATOR_SCHEMA_VERSION = 5

class DeterministicValidator:
    def validate(self, recommendation: Dict[str, Any], ev_store: List[Evidence],
                 original_risk: Optional[float] = None,
                 ground_truth: Optional[Dict[str, Any]] = None,
                 baseline_familiarity: float = 0.0) -> bool:
        """`ground_truth` (PHASE 50, optional/defaulted -- every existing caller that
        hasn't been updated, e.g. tests, is unaffected) is the ORIGINAL alert's own
        `hee_decision_path`/`hee_hypotheses`/`hee_independent_sources`, as persisted by
        pipeline.py at publish time (see alert_payload's own comment there). Absent for
        alerts published before this existed -- degrades to the pre-PHASE-50 behavior
        below, not an error. `baseline_familiarity` (PHASE 58b, optional/defaulted --
        every existing caller unaffected) is the CALLER's own
        AutonomousFPEngine.get_baseline_familiarity() result for this device+
        port/ASN/domain -- 0.0 (the safe default) for any caller that hasn't threaded
        it through yet. `ground_truth["candidate_hypotheses"]` (PHASE 63, optional --
        absent/empty is a no-op) is every OTHER named hypothesis whose relevant
        evidence types overlap this alert's own, computed independently of the LLM's
        response -- see ollama_soc.py's _candidate_alternate_hypotheses()."""
        # Prevent LLM hallucination poisoning
        classification = recommendation.get("classification", "").lower()
        reason = recommendation.get("reason", "").lower()

        if classification == "benign":
            # Deterministic check: Is there a confirmed malicious IOC?
            has_ioc = any(e.type == "reputation" and _safe_float(e.value) >= 4.0 for e in ev_store)
            if has_ioc:
                LOGGER.warning("[VALIDATOR] Rejected Ollama recommendation: Malicious IOC present.")
                return False

            # If Ollama claims it's OS Telemetry, verify reputation tier <= 2
            if "telemetry" in reason:
                has_bad_rep = any(e.type == "reputation" and _safe_float(e.value) >= 3.0 for e in ev_store)
                if has_bad_rep:
                    LOGGER.warning("[VALIDATOR] Rejected Ollama recommendation: Bad reputation for telemetry claim.")
                    return False

            # PHASE 50: reject "benign" outright if the deterministic engine already
            # corroborated an attack conclusion for THIS alert across >=2 independent
            # evidence families (or a hard-stop / confirmed-IOC path) when it was first
            # evaluated -- see _STRONG_ATTACK_DECISION_PATHS' own comment. This is the
            # actual "AI proposes, deterministic code disposes" gate: previously the only
            # things that could reject a benign verdict were a bare IOC>=4.0 evidence item
            # reconstructed from features, or the literal word "telemetry" -- neither of
            # which requires the LLM's verdict to actually agree with what
            # HypothesisEngine/DecisionEngine already found.
            decision_path = (ground_truth or {}).get("decision_path", "")
            if decision_path in _STRONG_ATTACK_DECISION_PATHS:
                hyp = (ground_truth or {}).get("hypotheses", {}) or {}
                attack_name = hyp.get("attack", {}).get("name", "unknown")
                sources = (ground_truth or {}).get("independent_sources", 0)
                LOGGER.warning(
                    "[VALIDATOR] Rejected Ollama recommendation: this alert's original "
                    "HEE verdict already corroborated attack hypothesis '%s' across %d "
                    "independent evidence famil%s (decision_path=%s) -- an LLM 'benign' "
                    "verdict does not override that without new counter-evidence.",
                    attack_name, sources, "y" if sources == 1 else "ies", decision_path,
                )
                return False

            # PHASE 58 (Gap 6 item 2, device-identity/attack-shaped-evidence check): the
            # deterministic engine already refuses to let a device-type label rescue a
            # "benign" verdict against genuine attack-shaped evidence -- see
            # hypotheses/engine.py's DeviceProfileBenignHypothesis.has_competing_attack_evidence
            # -- but that guard only ever applied at the LIVE alert-scoring pass. This
            # mirrors it here, on the LLM's free-text re-review of an already-published
            # alert (hours or days later, in a different process), which previously had
            # NO independent check against the raw evidence at all -- only against the
            # original alert's decision_path reaching one of _STRONG_ATTACK_DECISION_PATHS
            # (the check just above). A pattern that hadn't yet escalated that far (e.g.
            # still `hypothesis_suspicious`, or a single arp_sweep/MAC-flip not yet
            # corroborated by a second source) could still be talked into "benign,
            # suppress" by a device-type explanation that never engaged with the actual
            # trigger at all -- confirmed live, not hypothetical: both
            # example_smarttv_fritz_box immunizations in the 2026-09-03 SOC report
            # justified suppressing NETWORK_INTRUSION using DNS-hygiene language (query
            # rate, unique domains, entropy) -- evidence types
            # NetworkIntrusionHypothesis.evaluate() never reads at all (hypotheses/
            # engine.py:104-120 only reads zeek_lateral_scan/malicious_ja3/ja4/
            # arp_spoof_pending/zeek_notice). Structural check, deliberately not
            # content-judging WHICH evidence the model's own reasoning cites (same
            # philosophy as the supporting_evidence-emptiness check below -- a much more
            # fragile string-matching heuristic for marginal extra benefit).
            evidence_types = set((ground_truth or {}).get("evidence_types", []) or [])
            attack_shaped_present = evidence_types & ATTACK_SHAPED_EVIDENCE_TYPES
            if attack_shaped_present:
                LOGGER.warning(
                    "[VALIDATOR] Rejected Ollama recommendation: attack-shaped evidence "
                    "%s is present on this alert's own evaluation -- a 'benign' verdict "
                    "does not override that regardless of device-type reasoning.",
                    sorted(attack_shaped_present),
                )
                return False

            # PHASE 58b (Gap 6 item 2, destination-ownership/baseline-familiarity check):
            # a "benign" verdict needs SOME deterministic corroboration, not just the
            # LLM's own say-so -- mirrors DeviceProfileBenignHypothesis's own
            # requirement (hypotheses/engine.py) that a device-profile explanation only
            # holds when the destination is EITHER already-trusted/known infrastructure
            # (rep_vector.tier in (0,1,2)) OR this specific device has personally,
            # repeatedly used this exact port/ASN/domain before without incident
            # (baseline_familiarity >= FAMILIARITY_TRUST_BAR). If NEITHER holds -- an
            # unclassified/unreputable destination this device has never really talked
            # to before -- a "benign" verdict is unsupported regardless of how the LLM
            # phrases its reasoning. Absent rep_tier (pre-Phase-58b alert) degrades to a
            # no-op, same backward-compat treatment as every other ground_truth field.
            rep_tier = (ground_truth or {}).get("rep_tier")
            if (rep_tier is not None and rep_tier not in _TRUSTED_REP_TIERS
                    and baseline_familiarity < FAMILIARITY_TRUST_BAR):
                LOGGER.warning(
                    "[VALIDATOR] Rejected Ollama recommendation: destination reputation "
                    "tier %s is not trusted/known infrastructure, and this device has no "
                    "learned familiarity with it (%.2f < %.2f) -- a 'benign' verdict "
                    "needs deterministic corroboration, not just the LLM's own reasoning.",
                    rep_tier, baseline_familiarity, FAMILIARITY_TRUST_BAR,
                )
                return False

            # PHASE 63 (Gap 6 item 4, hypothesis independence at the LLM layer): the
            # deterministic engine already scores every attack hypothesis independently
            # and takes the max (HypothesisEngine.evaluate_all()) -- weakening one
            # hypothesis provably cannot touch another's score there. Nothing forced the
            # SAME discipline on the LLM's free-text reasoning: it could generalize
            # "this evidence weakens hypothesis A" into "therefore benign overall"
            # without ever checking B/C/D. ollama_soc.py's ground_truth now carries
            # `candidate_hypotheses` -- every OTHER named hypothesis whose
            # RELEVANT_EVIDENCE_TYPES overlaps this alert's own evidence, computed
            # independently of the LLM's response (see
            # _candidate_alternate_hypotheses()). A "benign" verdict must address every
            # one of them in its own `hypotheses_ruled_out` list -- structural substring
            # check, deliberately not content-judging the quality of each reason (same
            # philosophy as the Phase 58 attack-shaped-evidence check above: a much more
            # fragile string-matching heuristic would buy little extra confidence).
            candidate_hypotheses = set((ground_truth or {}).get("candidate_hypotheses", []) or [])
            if candidate_hypotheses:
                ruled_out_text = " ".join(
                    str(x).lower() for x in (recommendation.get("hypotheses_ruled_out") or [])
                )
                unaddressed = {c for c in candidate_hypotheses if c.lower() not in ruled_out_text}
                if unaddressed:
                    LOGGER.warning(
                        "[VALIDATOR] Rejected Ollama recommendation: 'benign' verdict "
                        "does not address candidate hypothesis(es) %s in "
                        "hypotheses_ruled_out -- weakening the named hypothesis does not "
                        "by itself clear these.",
                        sorted(unaddressed),
                    )
                    return False

            # PHASE 51 (structured evidence contract): reject a "benign" verdict that
            # doesn't actually justify itself. Per the evidence-family principle this
            # whole gate exists for -- unknown reputation is NEUTRAL, not proof of
            # innocence -- an LLM asserting "benign" with an empty supporting_evidence
            # list is an assertion, not a finding, and must not reach an autonomous
            # action any more than a "telemetry" free-text claim used to be trusted
            # unchecked. The system_prompt (ollama_soc.py) now explicitly tells the
            # model the absence of a TI/VT/AbuseIPDB hit is not supporting evidence on
            # its own; this check enforces the structural half of that (a real list is
            # present) -- it does not attempt to content-judge each item, which would be
            # a much more fragile string-matching heuristic for marginal extra benefit.
            supporting = [s for s in (recommendation.get("supporting_evidence") or []) if str(s).strip()]
            if not supporting:
                LOGGER.warning(
                    "[VALIDATOR] Rejected Ollama recommendation: 'benign' verdict has no "
                    "supporting_evidence -- an assertion, not a finding."
                )
                return False

            # A verdict that lists its OWN contradicting evidence but still recommends
            # suppressing the alert is internally inconsistent -- the model itself found
            # a reason not to trust its classification and recommended an action anyway.
            contradicting = [c for c in (recommendation.get("contradicting_evidence") or []) if str(c).strip()]
            if contradicting and recommendation.get("recommended_action") == "suppress":
                LOGGER.warning(
                    "[VALIDATOR] Rejected Ollama recommendation: verdict lists its own "
                    "contradicting_evidence (%s) but still recommends suppress -- "
                    "self-contradictory.", contradicting,
                )
                return False

        # VERSION 10 (#15/#16, Ollama circular-reasoning guard): the model is no longer
        # shown risk/signature/factors/fp_verdict at all (see ollama_soc.py's
        # _build_evidence_only_payload -- found via a third-party review that the old
        # prompt handed the LLM the whole raw alert_payload undiscriminated, letting it
        # simply reflect an existing "risk": 9.9 verdict back as "confirmation" instead
        # of reasoning from evidence). If a "malicious" verdict's own free-text
        # justification cites the EXACT prior risk score anyway, that's a strong signal
        # of leaked/circular context (a stale cached prompt, a coincidentally-specific
        # hallucination, or a future regression reintroducing the score into the
        # prompt) rather than independently-derived reasoning -- reject it the same way
        # a hallucinated benign-despite-IOC verdict is rejected above.
        if classification == "malicious" and original_risk is not None and original_risk > 0:
            risk_strings = {f"{original_risk:.1f}", f"{original_risk:.2f}", str(original_risk)}
            if any(s in reason for s in risk_strings):
                LOGGER.warning(
                    "[VALIDATOR] Rejected Ollama recommendation: reasoning cites the exact "
                    "original risk score it was never shown -- circular reasoning, not "
                    "independent evidence-based verification."
                )
                return False

        return True
