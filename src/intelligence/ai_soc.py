import json
import logging
import requests
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

class OllamaSOCAnalyst:
    def __init__(self, endpoint="http://127.0.0.1:11434", model="llama3.1"):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.validator = DeterministicValidator()
        self.explanation_cache: Dict[str, Dict[str, Any]] = {}

    def analyze(self, device: str, ev_store: List[Evidence], hypotheses: Dict[str, Any]) -> None:
        """
        Asynchronously ranks hypotheses using a local Ollama LLM.
        """
        evidence_graph = [
            {"group": e.independence_group, "type": e.type, "value": e.value, "confidence": e.confidence}
            for e in ev_store
        ]
        
        system_prompt = (
            "You are an autonomous Tier 2 SOC Analyst for a Home Intrusion Detection System. "
            "You will be given a JSON object containing an 'evidence_graph' and a set of 'hypotheses'. "
            "Your job is to analyze the evidence and determine if the activity is benign (e.g. telemetry, ads) or malicious. "
            "You must respond ONLY with a valid JSON object matching this schema: "
            "{\"classification\": \"benign|malicious\", \"confidence\": 0.0-1.0, \"reason\": \"<short explanation>\", \"recommended_action\": \"suppress|block\"}"
        )
        
        prompt_data = {
            "evidence_graph": evidence_graph,
            "hypotheses": hypotheses
        }

        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": json.dumps(prompt_data),
            "format": "json",
            "stream": False
        }

        try:
            LOGGER.debug("Querying Ollama at %s with model %s for device %s", self.endpoint, self.model, device)
            resp = requests.post(f"{self.endpoint}/api/generate", json=payload, timeout=30.0)
            resp.raise_for_status()
            
            result = resp.json().get("response", "")
            response_json = json.loads(result)
            
            if self.validator.validate(response_json, ev_store):
                LOGGER.info("[OLLAMA SOC] Validated explanation for %s. Caching.", device)
                self.explanation_cache[device] = response_json
            else:
                LOGGER.warning("[OLLAMA SOC] Explanation for %s rejected by Deterministic Validator.", device)
                
        except requests.exceptions.RequestException as e:
            LOGGER.error("[OLLAMA SOC] API Request failed: %s", e)
        except json.JSONDecodeError as e:
            LOGGER.error("[OLLAMA SOC] Failed to parse JSON from model: %s", e)
        except Exception as e:
            LOGGER.error("[OLLAMA SOC] Unexpected error: %s", e)
