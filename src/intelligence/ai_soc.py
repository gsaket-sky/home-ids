import logging
from typing import Dict, Any, List
from intelligence.hypotheses.evidence import Evidence

LOGGER = logging.getLogger(__name__)

def _safe_float(val: Any) -> float:
    try:
        return float(val) if val is not None else 0.0
    except (TypeError, ValueError):
        return 0.0

class DeterministicValidator:
    def validate(self, recommendation: Dict[str, Any], ev_store: List[Evidence]) -> bool:
        # Prevent LLM hallucination poisoning
        classification = recommendation.get("classification", "").lower()
        if classification == "benign":
            # Deterministic check: Is there a confirmed malicious IOC?
            has_ioc = any(e.type == "reputation" and _safe_float(e.value) >= 4.0 for e in ev_store)
            if has_ioc:
                LOGGER.warning("[VALIDATOR] Rejected Ollama recommendation: Malicious IOC present.")
                return False

            # If Ollama claims it's OS Telemetry, verify reputation tier <= 2
            reason = recommendation.get("reason", "").lower()
            if "telemetry" in reason:
                has_bad_rep = any(e.type == "reputation" and _safe_float(e.value) >= 3.0 for e in ev_store)
                if has_bad_rep:
                    LOGGER.warning("[VALIDATOR] Rejected Ollama recommendation: Bad reputation for telemetry claim.")
                    return False
        return True
