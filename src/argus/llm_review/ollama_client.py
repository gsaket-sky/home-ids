"""
v13 dual-tier Ollama client (Phase 5 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Implements decision #3's resolution (2026-09-05, real-data evidence, see the
dependency map's Ollama spike sections): full structured Tier-2 analysis always
goes to a remote, capable model -- exactly like v-current's ollama_soc.py/
_query_ollama() (scripts/ollama_soc.py:796-818, read directly) -- while a local
small model on-device only ever does lightweight triage (a coarse "does this need
deeper review" signal), never the full multi-field contract that real-data testing
found no small model (0.5B-3B) reliable at.

THE ONE FIXED, NON-NEGOTIABLE DESIGN REQUIREMENT, regardless of model or tier:
real JSON-schema-constrained `format` (an actual JSON Schema object with `enum`
constraints, decoded at the token level), NEVER a prose-described schema. Round 1
of the Phase 0 spike found EVERY model (0.5B through 3B) literally echoing a
prose-described `"benign|malicious"` placeholder verbatim instead of picking a
value; Round 2 fixed this completely by switching to a real schema. This is
carried into both FULL_ANALYSIS_SCHEMA and TRIAGE_SCHEMA below -- there is no
prose-schema code path in this client at all, unlike v-current's `_query_ollama()`
which still uses `"format": "json"` (a bug this client structurally cannot have).
"""
import json
import urllib.request
from typing import Any, Dict, Optional

# Matches ollama_soc.py's real system prompt content (lines 1011-1046, read
# directly) -- the exact prompt already validated in this session's own benchmark.
FULL_ANALYSIS_SYSTEM_PROMPT = (
    "You are an autonomous Tier 2 SOC Analyst for a Home Intrusion Detection System. "
    "You are given RAW EVIDENCE ONLY for one network alert -- device info, connection "
    "details, and measured features (DNS query patterns, Zeek flow statistics, threat-"
    "intelligence/reputation scores such as ti_risk/abuse_risk/vt_risk). You are "
    "deliberately NOT told this system's own prior risk score, signature name, or "
    "verdict -- you must independently determine whether the activity is benign (e.g. "
    "telemetry, ads, routine device chatter) or malicious purely from the evidence "
    "given, not by assuming any classification already exists. "
    "Reason like a hypothesis test, not a vibe check: name the SPECIFIC benign or "
    "attack explanation you believe fits (use this system's own vocabulary when it "
    "applies -- benign: DEVICE_PROFILE_TELEMETRY, LOCAL_DEVICE_DISCOVERY, "
    "ADVERTISING_BURST; attack: NETWORK_INTRUSION, DNS_COVERT_TUNNELING, "
    "DGA_BOTNET_C2, CONNECTION_ABUSE, DATA_EXFILTRATION, C2_BEACONING, "
    "DNS_POLICY_BYPASS -- or a short specific name if none of these fit), then list "
    "the concrete evidence that supports it and the concrete evidence that argues "
    "against it. The ABSENCE of a threat-intel hit (ti_risk/abuse_risk/vt_risk all "
    "0.0) is NOT supporting evidence for benign -- it is simply unknown, and must not "
    "be the sole item in supporting_evidence. Only cite evidence literally present in "
    "the given payload -- never invent details not present. "
    "If the prompt lists 'Other candidate hypotheses' for this alert, you must "
    "independently rule out EVERY one of them before classifying benign."
)

FULL_ANALYSIS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "hypothesis": {"type": "string"},
        "classification": {"type": "string", "enum": ["benign", "malicious"]},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
        "supporting_evidence": {"type": "array", "items": {"type": "string"}},
        "contradicting_evidence": {"type": "array", "items": {"type": "string"}},
        "missing_evidence": {"type": "array", "items": {"type": "string"}},
        "hypotheses_ruled_out": {"type": "array", "items": {"type": "string"}},
        "recommended_action": {"type": "string", "enum": ["suppress", "block", "none"]},
        "ttl_seconds": {"type": "number"},
    },
    "required": ["hypothesis", "classification", "confidence", "reason",
                 "supporting_evidence", "contradicting_evidence", "recommended_action"],
}

# The simpler task local mode is scoped to -- validated in this session's own
# triage spike: recall solved (up to 10/10 on real threats), specificity not yet
# (near-0/5 on constructed routine cases) -- safe (never silently drops a real
# threat) but not yet a real filter. See the dependency map for the honest numbers.
TRIAGE_SYSTEM_PROMPT = (
    "You are a fast, lightweight triage filter for a Home Intrusion Detection "
    "System, running on resource-constrained hardware. You will see evidence for "
    "one network alert. Your ONLY job is to flag whether this looks routine (safe "
    "to defer, no deeper review needed right now) or unusual enough to warrant a "
    "full review by a more capable analysis system. Bias strongly toward flagging "
    "anything with ANY hint of irregularity -- unusual reputation scores, "
    "unfamiliar destinations, high query rates/entropy, or attack-shaped signals "
    "(JA3/JA4 fingerprint matches, DGA-like patterns, lateral movement indicators) "
    "-- as needing review. A missed real threat is far worse than one unnecessary "
    "extra review. Respond with a JSON object only."
)

TRIAGE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "needs_review": {"type": "boolean"},
        "reason": {"type": "string"},
    },
    "required": ["needs_review", "reason"],
}


class OllamaClient:
    def __init__(self, remote_url: str, remote_model: str,
                  local_url: Optional[str] = None, local_model: Optional[str] = None,
                  timeout_seconds: float = 900.0):
        # Matches ollama_soc.py's own timeout=900.0 exactly (scripts/ollama_soc.py:808)
        # -- confirmed necessary this session: a naive 180s test timeout produced 16
        # false "timed out" results against production's real 8B model before this
        # was caught and fixed. Never lower this without re-confirming against real
        # hardware load first.
        self.remote_url = remote_url
        self.remote_model = remote_model
        self.local_url = local_url
        self.local_model = local_model
        self.timeout_seconds = timeout_seconds

    def _query(self, url: str, model: str, system_prompt: str, prompt_text: str,
                schema: Dict[str, Any], timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        body = json.dumps({
            "model": model, "system": system_prompt, "prompt": prompt_text,
            "format": schema, "stream": False,
        }).encode("utf-8")
        req = urllib.request.Request(f"{url}/api/generate", data=body,
                                       headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout_seconds) as resp:
                outer = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None
        try:
            return json.loads(outer.get("response", ""))
        except (json.JSONDecodeError, TypeError):
            return None

    def query_full_analysis(self, prompt_text: str, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Always remote -- the full structured Tier-2 contract, matching
        v-current's own architecture for the hard cases. Never routed to a local
        model; that's the whole point of decision #3's resolution."""
        return self._query(self.remote_url, self.remote_model, FULL_ANALYSIS_SYSTEM_PROMPT,
                             prompt_text, FULL_ANALYSIS_SCHEMA, timeout=timeout)

    def query_triage(self, prompt_text: str, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Local-model-eligible -- the simpler task real testing found tractable
        for recall (though not yet for specificity/actual filtering value). Uses
        local_url/local_model if configured, else falls back to remote (a
        deployment with no local model at all -- e.g. still on x86 dev hardware --
        gets identical behavior to always using remote for both tiers)."""
        url = self.local_url or self.remote_url
        model = self.local_model or self.remote_model
        return self._query(url, model, TRIAGE_SYSTEM_PROMPT, prompt_text, TRIAGE_SCHEMA, timeout=timeout)


def build_evidence_prompt(device_id: str, evidence_list, relevance: Optional[Dict[str, Any]] = None,
                            candidate_hypotheses: Optional[list] = None) -> str:
    """v13-native prompt builder -- operates on v13 Evidence objects directly
    (evidence_type/value/confidence/destination_id/timestamp), not v-current's
    already-published alert_payload dict shape (ollama_soc.py's
    _build_evidence_only_payload operates on THAT, a structurally different input
    v13 doesn't have since nothing gets 'published' to a v1-shaped alert log)."""
    payload = {
        "device_id": device_id,
        "evidence": [
            {
                "type": e.evidence_type,
                "value": e.value,
                "confidence": e.confidence,
                "destination": e.destination_id,
                "age_seconds_ago": None,  # filled by caller if a `now` reference is available
            }
            for e in evidence_list
        ],
    }
    prompt_text = f"Alert Evidence:\n{json.dumps(payload, indent=2)}"
    if relevance:
        prompt_text += f"\n\nEvidence relevance for the leading hypothesis:\n{json.dumps(relevance, indent=2)}"
    if candidate_hypotheses:
        prompt_text += (
            f"\n\nOther candidate hypotheses whose relevant evidence is ALSO present: "
            f"{json.dumps(candidate_hypotheses)}. You must independently rule out each one "
            f"before classifying benign."
        )
    return prompt_text
