import logging
from typing import Dict, Any, List, Optional
from intelligence.hypotheses.evidence import Evidence

LOGGER = logging.getLogger(__name__)

def _safe_float(val: Any) -> float:
    try:
        return float(val) if val is not None else 0.0
    except (TypeError, ValueError):
        return 0.0

class DeterministicValidator:
    def validate(self, recommendation: Dict[str, Any], ev_store: List[Evidence],
                 original_risk: Optional[float] = None) -> bool:
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
