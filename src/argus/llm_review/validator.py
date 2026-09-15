"""
v13 DeterministicValidator (Phase 5 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Faithful port of intelligence/ai_soc.py's DeterministicValidator (256 lines, read in
full before writing anything). Every rejection rule and its ordering is copied
exactly: confirmed-IOC veto, telemetry-claim-vs-reputation veto, the
_STRONG_ATTACK_DECISION_PATHS override-block, the attack-shaped-evidence structural
check, the destination-ownership/baseline-familiarity check, the hypothesis-
independence check, the empty-supporting-evidence check, the self-contradiction
check, and the circular-reasoning-on-malicious check. Constants
(ATTACK_SHAPED_EVIDENCE_TYPES, FAMILIARITY_TRUST_BAR) are the SAME ones already
ported onto v13's DeviceProfileBenignHypothesis (hypotheses/engine.py) -- imported
from there, not redefined, so the two consumers can never silently drift apart the
way Gap 6 found they had in v-current before the fix.

ground_truth is assembled by build_ground_truth() (below) from v13's own
DecisionEngine result + evidence list -- v13's decision engine doesn't persist
hee_* fields onto an alert_payload the way v-current's pipeline.py does (v13 has no
such payload yet), so this module builds the equivalent structure directly.
"""
import logging
from typing import Any, Dict, List, Optional

from argus.evidence.model import Evidence
from argus.hypotheses.engine import DeviceProfileBenignHypothesis, HYPOTHESIS_RELEVANT_EVIDENCE_TYPES

_TRUSTED_REP_TIERS = frozenset({0, 1, 2})
_STRONG_ATTACK_DECISION_PATHS = frozenset({
    "hard_stop", "tier5_confirmed", "tier5_corroborated", "hypothesis_high",
})
VALIDATOR_SCHEMA_VERSION = 1  # v13's own versioning starts fresh -- not a continuation of v-current's counter

LOGGER = logging.getLogger(__name__)


def _safe_float(val: Any) -> float:
    try:
        return float(val) if val is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def candidate_alternate_hypotheses(winning_attack_name: str, present_evidence_types: set) -> List[str]:
    """Matches ollama_soc.py's _candidate_alternate_hypotheses(): every OTHER named
    hypothesis whose RELEVANT_EVIDENCE_TYPES overlaps this alert's own evidence,
    deduped by underlying frozenset identity (not just name) so dynamic-name
    aliases of the SAME class (e.g. NETWORK_INTRUSION/LATERAL_MOVEMENT) never both
    appear as if they were two different candidates."""
    winning_set_id = id(HYPOTHESIS_RELEVANT_EVIDENCE_TYPES.get(winning_attack_name))
    seen_set_ids = {winning_set_id}
    candidates = []
    for name, relevant_types in HYPOTHESIS_RELEVANT_EVIDENCE_TYPES.items():
        if name == winning_attack_name:
            continue
        if id(relevant_types) in seen_set_ids:
            continue
        if relevant_types & present_evidence_types:
            candidates.append(name)
            seen_set_ids.add(id(relevant_types))
    return candidates


def build_ground_truth(decision_result: Dict[str, Any], evidence_list: List[Evidence],
                          rep_tier: Optional[int] = None) -> Dict[str, Any]:
    """Assembles the ground_truth dict DeterministicValidator.validate() expects,
    from argus's own DecisionEngine.evaluate() output -- the v13-native equivalent of
    v-current's pipeline.py persisting hee_evidence_types/hee_rep_tier/etc. onto an
    alert_payload for ollama_soc.py to read back later."""
    winning_attack_name = decision_result.get("hypotheses", {}).get("attack", {}).get("name", "")
    present_evidence_types = {e.evidence_type for e in evidence_list}
    return {
        "decision_path": decision_result.get("decision_path", ""),
        "hypotheses": decision_result.get("hypotheses", {}),
        "independent_sources": decision_result.get("independent_sources", 0),
        "evidence_types": list(present_evidence_types),
        "rep_tier": rep_tier,
        "candidate_hypotheses": candidate_alternate_hypotheses(winning_attack_name, present_evidence_types),
    }


class DeterministicValidator:
    def validate(self, recommendation: Dict[str, Any], evidence_list: List[Evidence],
                  original_risk: Optional[float] = None,
                  ground_truth: Optional[Dict[str, Any]] = None,
                  baseline_familiarity: float = 0.0) -> bool:
        classification = recommendation.get("classification", "").lower()
        reason = recommendation.get("reason", "").lower()

        if classification == "benign":
            has_ioc = any(e.evidence_type == "reputation" and _safe_float(e.value) >= 4.0 for e in evidence_list)
            if has_ioc:
                LOGGER.warning("[VALIDATOR] Rejected: Malicious IOC present.")
                return False

            if "telemetry" in reason:
                has_bad_rep = any(e.evidence_type == "reputation" and _safe_float(e.value) >= 3.0 for e in evidence_list)
                if has_bad_rep:
                    LOGGER.warning("[VALIDATOR] Rejected: Bad reputation for telemetry claim.")
                    return False

            decision_path = (ground_truth or {}).get("decision_path", "")
            if decision_path in _STRONG_ATTACK_DECISION_PATHS:
                LOGGER.warning(
                    "[VALIDATOR] Rejected: this alert's original decision already corroborated "
                    "an attack conclusion (decision_path=%s) -- a 'benign' verdict does not "
                    "override that without new counter-evidence.", decision_path,
                )
                return False

            evidence_types = set((ground_truth or {}).get("evidence_types", []) or [])
            attack_shaped_present = evidence_types & DeviceProfileBenignHypothesis.ATTACK_SHAPED_EVIDENCE_TYPES
            if attack_shaped_present:
                LOGGER.warning(
                    "[VALIDATOR] Rejected: attack-shaped evidence %s is present -- a 'benign' "
                    "verdict does not override that regardless of device-type reasoning.",
                    sorted(attack_shaped_present),
                )
                return False

            rep_tier = (ground_truth or {}).get("rep_tier")
            if (rep_tier is not None and rep_tier not in _TRUSTED_REP_TIERS
                    and baseline_familiarity < DeviceProfileBenignHypothesis.FAMILIARITY_TRUST_BAR):
                LOGGER.warning(
                    "[VALIDATOR] Rejected: destination reputation tier %s is not trusted, and "
                    "no learned familiarity (%.2f < %.2f) -- 'benign' needs corroboration.",
                    rep_tier, baseline_familiarity, DeviceProfileBenignHypothesis.FAMILIARITY_TRUST_BAR,
                )
                return False

            candidate_hypotheses = set((ground_truth or {}).get("candidate_hypotheses", []) or [])
            if candidate_hypotheses:
                ruled_out_text = " ".join(
                    str(x).lower() for x in (recommendation.get("hypotheses_ruled_out") or [])
                )
                unaddressed = {c for c in candidate_hypotheses if c.lower() not in ruled_out_text}
                if unaddressed:
                    LOGGER.warning(
                        "[VALIDATOR] Rejected: 'benign' verdict does not address candidate "
                        "hypothesis(es) %s in hypotheses_ruled_out.", sorted(unaddressed),
                    )
                    return False

            supporting = [s for s in (recommendation.get("supporting_evidence") or []) if str(s).strip()]
            if not supporting:
                LOGGER.warning("[VALIDATOR] Rejected: 'benign' verdict has no supporting_evidence.")
                return False

            contradicting = [c for c in (recommendation.get("contradicting_evidence") or []) if str(c).strip()]
            if contradicting and recommendation.get("recommended_action") == "suppress":
                LOGGER.warning(
                    "[VALIDATOR] Rejected: verdict lists its own contradicting_evidence (%s) "
                    "but still recommends suppress -- self-contradictory.", contradicting,
                )
                return False

        if classification == "malicious" and original_risk is not None and original_risk > 0:
            risk_strings = {f"{original_risk:.1f}", f"{original_risk:.2f}", str(original_risk)}
            if any(s in reason for s in risk_strings):
                LOGGER.warning(
                    "[VALIDATOR] Rejected: reasoning cites the exact original risk score it "
                    "was never shown -- circular reasoning."
                )
                return False

        return True
