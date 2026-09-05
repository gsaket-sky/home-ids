"""
Standalone runtime test for v13's dual-tier Ollama client (src/v13/llm_review/ollama_client.py,
Phase 5 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: the fixed JSON-schema-constrained design requirement (no prose-schema code
path exists at all), that query_full_analysis() ALWAYS targets the remote
endpoint regardless of local config (the actual point of decision #3's
resolution), that query_triage() prefers local when configured and falls back to
remote otherwise, graceful handling of network errors and malformed JSON (network
mocked -- no live Ollama server required), and build_evidence_prompt()'s payload
construction from real v13 Evidence objects.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_llm_review_client.py`
"""
import sys
import json
import urllib.request
from unittest.mock import patch, MagicMock
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from v13.llm_review.ollama_client import (  # noqa: E402
    OllamaClient, FULL_ANALYSIS_SCHEMA, TRIAGE_SCHEMA, build_evidence_prompt,
)

# --- fixed schema-constrained design requirement ---
check("FULL_ANALYSIS_SCHEMA is a real JSON Schema object with an enum-constrained "
      "classification field -- never a prose string like today's ollama_soc.py",
      isinstance(FULL_ANALYSIS_SCHEMA, dict)
      and FULL_ANALYSIS_SCHEMA["properties"]["classification"]["enum"] == ["benign", "malicious"])
check("TRIAGE_SCHEMA is also a real JSON Schema object, not a prose description",
      isinstance(TRIAGE_SCHEMA, dict) and TRIAGE_SCHEMA["properties"]["needs_review"]["type"] == "boolean")


def _mock_response(payload_dict):
    """Builds a fake urlopen() context manager returning Ollama's real response shape."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"response": json.dumps(payload_dict)}).encode("utf-8")
    mock_resp.__enter__ = lambda self: mock_resp
    mock_resp.__exit__ = lambda self, *a: False
    return mock_resp


# --- query_full_analysis ALWAYS targets remote, regardless of local config ---
client = OllamaClient(remote_url="http://remote:11434", remote_model="llama3.1",
                        local_url="http://local:11434", local_model="qwen2.5:0.5b")

captured_requests = []


def _capturing_urlopen(req, timeout=None):
    captured_requests.append(req.full_url)
    return _mock_response({"classification": "benign", "hypothesis": "x", "confidence": 0.9,
                             "reason": "y", "supporting_evidence": ["z"], "contradicting_evidence": [],
                             "recommended_action": "suppress"})


with patch("urllib.request.urlopen", side_effect=_capturing_urlopen):
    client.query_full_analysis("some prompt")
check("query_full_analysis() ALWAYS calls the REMOTE endpoint, even though a local "
      "model is configured -- the actual point of decision #3's resolution",
      captured_requests[-1] == "http://remote:11434/api/generate")

with patch("urllib.request.urlopen", side_effect=_capturing_urlopen):
    client.query_triage("some prompt")
check("query_triage() prefers the LOCAL endpoint when one is configured",
      captured_requests[-1] == "http://local:11434/api/generate")

client_no_local = OllamaClient(remote_url="http://remote:11434", remote_model="llama3.1")
with patch("urllib.request.urlopen", side_effect=_capturing_urlopen):
    client_no_local.query_triage("some prompt")
check("query_triage() falls back to remote when no local model is configured at all",
      captured_requests[-1] == "http://remote:11434/api/generate")

# --- request body actually carries the schema, not a plain 'json' string ---
sent_bodies = []


def _body_capturing_urlopen(req, timeout=None):
    sent_bodies.append(json.loads(req.data.decode("utf-8")))
    return _mock_response({"classification": "malicious", "hypothesis": "x", "confidence": 0.9,
                             "reason": "y", "supporting_evidence": ["z"], "contradicting_evidence": [],
                             "recommended_action": "block"})


with patch("urllib.request.urlopen", side_effect=_body_capturing_urlopen):
    client.query_full_analysis("prompt text")
check("the request body's 'format' field is the real schema object, never the literal string 'json' "
      "-- this client structurally cannot reproduce the Round-1 placeholder-echo bug",
      sent_bodies[-1]["format"] == FULL_ANALYSIS_SCHEMA)
check("the request timeout defaults to 900s, matching ollama_soc.py's own real production "
      "timeout -- confirmed necessary this session after a 180s test timeout produced false "
      "results against the real production model", client.timeout_seconds == 900.0)

# --- graceful error handling (network mocked, no live server needed) ---
def _raising_urlopen(req, timeout=None):
    raise TimeoutError("simulated network timeout")


with patch("urllib.request.urlopen", side_effect=_raising_urlopen):
    result = client.query_full_analysis("prompt")
check("a network/timeout error returns None cleanly, not an unhandled exception", result is None)


def _malformed_json_urlopen(req, timeout=None):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"response": "not valid json{{{"}).encode("utf-8")
    mock_resp.__enter__ = lambda self: mock_resp
    mock_resp.__exit__ = lambda self, *a: False
    return mock_resp


with patch("urllib.request.urlopen", side_effect=_malformed_json_urlopen):
    result = client.query_full_analysis("prompt")
check("a malformed (non-JSON) model response returns None cleanly, not an unhandled exception",
      result is None)

# --- build_evidence_prompt: v13-native payload construction ---
evidence_list = [
    Evidence(device_id="dev1", destination_id="evil.example.com", evidence_type="dns_tunnel_v2",
              independence_family="dns_behavior", timestamp=1.0, source="s", value=4.5, confidence=0.9),
    Evidence(device_id="dev1", destination_id=NO_DESTINATION, evidence_type="arp_sweep",
              independence_family="network_recon", timestamp=2.0, source="s", value=1.0),
]
prompt = build_evidence_prompt("dev1", evidence_list)
check("build_evidence_prompt includes the device_id", '"dev1"' in prompt)
check("build_evidence_prompt includes each evidence item's type and destination",
      "dns_tunnel_v2" in prompt and "evil.example.com" in prompt)

prompt_with_relevance = build_evidence_prompt(
    "dev1", evidence_list, relevance={"present_relevant": ["dns_tunnel_v2"]},
    candidate_hypotheses=["DGA_BOTNET_C2"],
)
check("build_evidence_prompt appends relevance context when supplied",
      "present_relevant" in prompt_with_relevance)
check("build_evidence_prompt appends candidate-hypothesis context when supplied",
      "DGA_BOTNET_C2" in prompt_with_relevance and "rule out" in prompt_with_relevance)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 LLM-review client checks PASSED.")
