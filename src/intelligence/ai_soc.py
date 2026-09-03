import logging
from typing import Dict, Any, List, Optional
from intelligence.hypotheses.evidence import Evidence

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

class DeterministicValidator:
    def validate(self, recommendation: Dict[str, Any], ev_store: List[Evidence],
                 original_risk: Optional[float] = None,
                 ground_truth: Optional[Dict[str, Any]] = None) -> bool:
        """`ground_truth` (PHASE 50, optional/defaulted -- every existing caller that
        hasn't been updated, e.g. tests, is unaffected) is the ORIGINAL alert's own
        `hee_decision_path`/`hee_hypotheses`/`hee_independent_sources`, as persisted by
        pipeline.py at publish time (see alert_payload's own comment there). Absent for
        alerts published before this existed -- degrades to the pre-PHASE-50 behavior
        below, not an error."""
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
