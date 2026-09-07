"""
Standalone runtime test for src/v13/ops/live_llm_review.py -- the scheduled batch
job that runs v13's own LLM-review (src/v13/llm_review/) against .94's own live
graph (v13 full-architecture plan, Phase 5).

Network is fully mocked -- no real Ollama server required, matching
tests/test_v13_llm_review_client.py's/test_v13_retro_hunter.py's own established
convention for exactly this reason.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_live_llm_review.py`
"""
import json
import sys
import tempfile
import time
from unittest.mock import patch
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import v13.ops.live_llm_review as live_llm_review  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402
from v13.evidence.model import Evidence  # noqa: E402

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="live_llm_review_test_"))


class _FakeClient:
    """Replaces OllamaClient entirely -- returns canned responses in call order,
    tracks how many times it was actually invoked (the real point of the query-cap
    tests below: confirming it's never called more than the configured max)."""
    _responses = []
    calls = 0

    def __init__(self, remote_url=None, remote_model=None):
        pass

    def query_full_analysis(self, prompt_text, timeout=None):
        _FakeClient.calls += 1
        if _FakeClient._responses:
            return _FakeClient._responses.pop(0)
        return {"classification": "malicious", "confidence": 0.9, "reason": "test",
                "supporting_evidence": ["x"], "contradicting_evidence": [],
                "recommended_action": "block"}


def _reset_fake_client(responses=None):
    _FakeClient._responses = list(responses or [])
    _FakeClient.calls = 0


BASE_CONFIG = {"state_path": None, "ollama_url": "http://fake:11434", "ollama_model": "fake-model"}


def _config_for(dir_path):
    cfg = dict(BASE_CONFIG)
    cfg["state_path"] = str(dir_path / "ids_state.json")
    return cfg


# --- no db yet: a clean no-op, not an error ---
_no_db_dir = TMPDIR / "no_db"
_no_db_dir.mkdir()
live_llm_review.CONFIG = _config_for(_no_db_dir)
live_llm_review.main()
check("main() is a clean no-op when the graph db doesn't exist yet",
      not (_no_db_dir / "v13_graph.db").exists())
check("main() still writes job_health.json even on the no-op path",
      json.loads((_no_db_dir / "job_health.json").read_text())["live_llm_review"]["skipped"] == "no_db_yet")

# --- ollama not configured: a clean skip, not an error ---
_no_ollama_dir = TMPDIR / "no_ollama"
_no_ollama_dir.mkdir()
GraphStore(str(_no_ollama_dir / "v13_graph.db")).close()
live_llm_review.CONFIG = {"state_path": str(_no_ollama_dir / "ids_state.json")}
live_llm_review.main()
check("main() skips cleanly when ollama_url/ollama_model aren't configured",
      json.loads((_no_ollama_dir / "job_health.json").read_text())["live_llm_review"]["skipped"]
      == "ollama_not_configured")


# --- real review: one SUSPICIOUS decision gets reviewed, one BENIGN doesn't ---
_real_dir = TMPDIR / "real"
_real_dir.mkdir()
db_path = _real_dir / "v13_graph.db"
output_path = _real_dir / "ollama_analysis_v13.jsonl"
store = GraphStore(str(db_path))
NOW = time.time()

store.insert_evidence(Evidence(device_id="dev1", destination_id="evil.example.com",
                                 evidence_type="zeek_lateral_scan", independence_family="network_behavior",
                                 timestamp=NOW - 100, source="zeek", value=1.0))
susp_decision_id = store.insert_decision(
    device_id="dev1", timestamp=NOW - 90, state="SUSPICIOUS", decision_path="hypothesis_suspicious",
    confidence=0.4, risk_score=2.0, raw_payload={"hypotheses": {"attack": {"name": "NETWORK_INTRUSION"}}},
)
benign_decision_id = store.insert_decision(
    device_id="dev2", timestamp=NOW - 90, state="BENIGN", decision_path="benign",
    confidence=0.0, risk_score=0.0, raw_payload={"hypotheses": {"attack": {"name": "DIRECT_IOC_HIT"}}},
)
store.close()

live_llm_review.CONFIG = _config_for(_real_dir)
_reset_fake_client([{
    "classification": "malicious", "confidence": 0.85, "reason": "lateral scan pattern",
    "supporting_evidence": ["zeek_lateral_scan present"], "contradicting_evidence": [],
    "recommended_action": "block",
}])
with patch.object(live_llm_review, "OllamaClient", _FakeClient):
    live_llm_review.main()

check("main() called the (fake) Ollama client exactly once -- one reviewable decision",
      _FakeClient.calls == 1)

lines = [json.loads(l) for l in output_path.read_text().splitlines() if l.strip()]
check("exactly one entry was written for the one SUSPICIOUS decision",
      len(lines) == 1)
check("the reviewed entry is for the SUSPICIOUS decision, not the BENIGN one",
      lines and lines[0]["decision_id"] == susp_decision_id)
check("the BENIGN decision was never reviewed at all",
      not any(l["decision_id"] == benign_decision_id for l in lines))
check("the entry carries the real recommendation from the (fake) LLM",
      lines and lines[0]["recommendation"]["classification"] == "malicious")
check("the validator ran and accepted this well-formed malicious recommendation",
      lines and lines[0]["validator_accepted"] is True)

health = json.loads((_real_dir / "job_health.json").read_text())
check("job_health.json records reviewed=1, errors=0",
      health["live_llm_review"]["reviewed"] == 1 and health["live_llm_review"]["errors"] == 0)


# --- idempotency: a second run does NOT re-review the same decision ---
_reset_fake_client()
with patch.object(live_llm_review, "OllamaClient", _FakeClient):
    live_llm_review.main()
check("a second run makes ZERO new Ollama calls -- the already-reviewed decision_id "
      "is correctly skipped (the output file itself is the cache)",
      _FakeClient.calls == 0)
lines_after_second_run = [json.loads(l) for l in output_path.read_text().splitlines() if l.strip()]
check("the output file still has exactly one entry after the second run",
      len(lines_after_second_run) == 1)


# --- the validator's REAL rejection logic actually runs (not a stub) ---
_val_dir = TMPDIR / "validator"
_val_dir.mkdir()
val_store = GraphStore(str(_val_dir / "v13_graph.db"))
val_store.insert_evidence(Evidence(device_id="dev3", destination_id="evil2.example.com",
                                     evidence_type="reputation", independence_family="reputation",
                                     timestamp=NOW - 100, source="ti", value=5.0))  # confirmed-IOC-tier
val_decision_id = val_store.insert_decision(
    device_id="dev3", timestamp=NOW - 90, state="HIGH", decision_path="hypothesis_high",
    confidence=0.8, risk_score=8.0, raw_payload={"hypotheses": {"attack": {"name": "DATA_EXFILTRATION"}}},
)
val_store.close()

live_llm_review.CONFIG = _config_for(_val_dir)
_reset_fake_client([{
    # A "benign" verdict despite a confirmed-IOC-tier reputation item present --
    # DeterministicValidator.validate() must reject this (its own #1 rule).
    "classification": "benign", "confidence": 0.6, "reason": "looks like telemetry",
    "supporting_evidence": ["routine traffic"], "contradicting_evidence": [],
    "recommended_action": "suppress",
}])
with patch.object(live_llm_review, "OllamaClient", _FakeClient):
    live_llm_review.main()
val_lines = [json.loads(l) for l in (_val_dir / "ollama_analysis_v13.jsonl").read_text().splitlines() if l.strip()]
check("the REAL DeterministicValidator ran (not a stub) and rejected a benign verdict "
      "contradicted by a confirmed-IOC-tier reputation item -- its own #1 rejection rule",
      val_lines and val_lines[0]["validator_accepted"] is False)


# --- query cap: more reviewable decisions than the per-run limit ---
_cap_dir = TMPDIR / "cap"
_cap_dir.mkdir()
cap_store = GraphStore(str(_cap_dir / "v13_graph.db"))
decision_ids = []
for i in range(4):
    cap_store.insert_evidence(Evidence(device_id=f"cap_dev{i}", destination_id="x.example.com",
                                         evidence_type="dns_rate", independence_family="dns_behavior",
                                         timestamp=NOW - 200 + i, source="s", value=10.0))
    did = cap_store.insert_decision(
        device_id=f"cap_dev{i}", timestamp=NOW - 200 + i, state="SUSPICIOUS",
        decision_path="hypothesis_suspicious", confidence=0.4, risk_score=2.0,
        raw_payload={"hypotheses": {"attack": {"name": "DGA_BOTNET_C2"}}},
    )
    decision_ids.append(did)
cap_store.close()

live_llm_review.CONFIG = dict(_config_for(_cap_dir), ollama_v13_max_queries_per_run=2)
_reset_fake_client()
with patch.object(live_llm_review, "OllamaClient", _FakeClient):
    live_llm_review.main()
check("the per-run query cap is honored -- only 2 of 4 reviewable decisions get "
      "reviewed in one run", _FakeClient.calls == 2)
cap_lines = [json.loads(l) for l in (_cap_dir / "ollama_analysis_v13.jsonl").read_text().splitlines() if l.strip()]
check("the output file has exactly 2 entries after the capped run", len(cap_lines) == 2)
cap_health = json.loads((_cap_dir / "job_health.json").read_text())
check("job_health.json correctly reports 2 deferred to next run",
      cap_health["live_llm_review"]["deferred"] == 2)

# a second run picks up the remaining 2 (oldest-first fairness)
_reset_fake_client()
with patch.object(live_llm_review, "OllamaClient", _FakeClient):
    live_llm_review.main()
check("a second run picks up the remaining deferred decisions -- the cap defers, "
      "it doesn't drop", _FakeClient.calls == 2)
cap_lines_final = [json.loads(l) for l in (_cap_dir / "ollama_analysis_v13.jsonl").read_text().splitlines() if l.strip()]
check("all 4 decisions are reviewed exactly once each across the two runs, no "
      "duplicates and none skipped",
      sorted(l["decision_id"] for l in cap_lines_final) == sorted(decision_ids))


# --- a failed/unparseable LLM response fails safe, doesn't crash the run ---
_err_dir = TMPDIR / "err"
_err_dir.mkdir()
err_store = GraphStore(str(_err_dir / "v13_graph.db"))
err_store.insert_evidence(Evidence(device_id="err_dev", destination_id="y.example.com",
                                     evidence_type="dns_rate", independence_family="dns_behavior",
                                     timestamp=NOW - 50, source="s", value=10.0))
err_store.insert_decision(
    device_id="err_dev", timestamp=NOW - 40, state="SUSPICIOUS", decision_path="hypothesis_suspicious",
    confidence=0.4, risk_score=2.0, raw_payload={"hypotheses": {"attack": {"name": "DGA_BOTNET_C2"}}},
)
err_store.close()

live_llm_review.CONFIG = _config_for(_err_dir)
_reset_fake_client([None])  # simulates OllamaClient's own real "network error / unparseable" return
with patch.object(live_llm_review, "OllamaClient", _FakeClient):
    live_llm_review.main()
err_lines = [json.loads(l) for l in (_err_dir / "ollama_analysis_v13.jsonl").read_text().splitlines() if l.strip()]
check("a None response from the LLM client is recorded as an error entry, not a crash",
      err_lines and err_lines[0].get("llm_error") == "no_response_or_unparseable")
err_health = json.loads((_err_dir / "job_health.json").read_text())
check("job_health.json counts the failed query as an error, still reviewed=1 "
      "(a review attempt was made and recorded, even though it failed)",
      err_health["live_llm_review"]["errors"] == 1 and err_health["live_llm_review"]["reviewed"] == 1)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All live_llm_review.py checks PASSED.")
