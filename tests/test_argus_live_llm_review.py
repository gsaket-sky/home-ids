"""
Standalone runtime test for src/v13/ops/live_llm_review.py -- the scheduled batch
job that runs v13's own LLM-review (src/v13/llm_review/) against .94's own live
graph (v13 full-architecture plan, Phase 5).

Network is fully mocked -- no real Ollama server required, matching
tests/test_argus_llm_review_client.py's/test_argus_retro_hunter.py's own established
convention for exactly this reason.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_live_llm_review.py`
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


import argus.ops.live_llm_review as live_llm_review  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.evidence.model import Evidence  # noqa: E402

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


# --- Phase 8a: pattern-level persistent cache -- SAME run, two decisions sharing
# a pattern (device|attack-hypothesis|decision_path + evidence fingerprint) ---
_cache_dir = TMPDIR / "persistent_cache"
_cache_dir.mkdir()
cache_store = GraphStore(str(_cache_dir / "v13_graph.db"))
# Two SEPARATE decision rows, same device/hypothesis/decision_path/evidence shape
# (a recurring pattern), just different timestamps -- this is exactly the
# "multiple decisions describing the same underlying recurring pattern" case
# Phase 8a/8b exist to collapse into one real Ollama call.
for i in range(2):
    cache_store.insert_evidence(Evidence(
        device_id="pattern_dev", destination_id="recurring.example.com",
        evidence_type="dns_dga_burst", independence_family="dns_behavior",
        timestamp=NOW - 300 + i, source="s", value=1.0, confidence=0.8))
pattern_decision_ids = []
for i in range(2):
    did = cache_store.insert_decision(
        device_id="pattern_dev", timestamp=NOW - 300 + i, state="SUSPICIOUS",
        decision_path="hypothesis_suspicious", confidence=0.4, risk_score=2.0,
        raw_payload={"hypotheses": {"attack": {"name": "DGA_BOTNET_C2"}}},
        evidence_ids=[],
    )
    pattern_decision_ids.append(did)
cache_store.close()

live_llm_review.CONFIG = _config_for(_cache_dir)
_reset_fake_client()
with patch.object(live_llm_review, "OllamaClient", _FakeClient):
    live_llm_review.main()
check("Phase 8a: two decisions sharing the SAME pattern key make only ONE real "
      "Ollama call in a single run -- the second is served from the in-memory "
      "cache populated by the first, satisfying Phase 8b's grouping goal too",
      _FakeClient.calls == 1)
pattern_lines = [json.loads(l) for l in (_cache_dir / "ollama_analysis_v13.jsonl").read_text().splitlines() if l.strip()]
check("both decisions were still written as their own entries (2 total)",
      len(pattern_lines) == 2)
by_did = {l["decision_id"]: l for l in pattern_lines}
served_from_cache = [l for l in pattern_lines if l.get("served_from_persistent_cache")]
check("exactly one of the two entries is marked served_from_persistent_cache",
      len(served_from_cache) == 1)
check("the cache-served entry carries the SAME recommendation as the one that "
      "made the real call, not a fabricated/empty one",
      served_from_cache[0]["recommendation"] ==
      [l for l in pattern_lines if not l.get("served_from_persistent_cache")][0]["recommendation"])
cache_health = json.loads((_cache_dir / "job_health.json").read_text())
check("job_health.json's new cache_hits/queries_made keys reflect the real split",
      cache_health["live_llm_review"]["cache_hits"] == 1
      and cache_health["live_llm_review"]["queries_made"] == 1)


# --- Phase 8a: CROSS-RUN persistence -- a brand-new decision matching an
# already-cached pattern from a PRIOR run is served from cache too, not just
# within the same run's in-memory dict ---
cache_store2 = GraphStore(str(_cache_dir / "v13_graph.db"))
# Deliberately NO new evidence inserted here -- evidence_in_window() has no
# upper timestamp bound (RollingWindowView.evidence_in_window(), confirmed via
# direct read), so a NEW evidence item for this device would change every
# fingerprint going forward, including the two already-cached entries' own
# recomputed one. This decision reuses the SAME evidence already in the graph
# from the two decisions above -- a genuinely identical pattern, the real case
# this test means to prove.
new_pattern_decision_id = cache_store2.insert_decision(
    device_id="pattern_dev", timestamp=NOW - 100, state="SUSPICIOUS",
    decision_path="hypothesis_suspicious", confidence=0.4, risk_score=2.0,
    raw_payload={"hypotheses": {"attack": {"name": "DGA_BOTNET_C2"}}},
)
cache_store2.close()
_reset_fake_client()
with patch.object(live_llm_review, "OllamaClient", _FakeClient):
    live_llm_review.main()
check("Phase 8a: a NEW decision_id matching an already-cached pattern from a "
      "PRIOR run makes ZERO new Ollama calls -- the persistent (on-disk) cache, "
      "not just the in-memory one, actually works across runs",
      _FakeClient.calls == 0)
cross_run_lines = [json.loads(l) for l in (_cache_dir / "ollama_analysis_v13.jsonl").read_text().splitlines() if l.strip()]
new_entry = next((l for l in cross_run_lines if l["decision_id"] == new_pattern_decision_id), None)
check("the new decision's own entry was written and correctly marked cache-served",
      new_entry is not None and new_entry.get("served_from_persistent_cache") is True)


# --- Phase 8a: a genuinely DIFFERENT evidence fingerprint does NOT cache-hit,
# even with the same device/hypothesis/decision_path ---
fp_store = GraphStore(str(_cache_dir / "v13_graph.db"))
fp_store.insert_evidence(Evidence(
    device_id="pattern_dev", destination_id="recurring.example.com",
    evidence_type="dns_dga_burst", independence_family="dns_behavior",
    timestamp=NOW - 50, source="s", value=1.0, confidence=0.8))
# A genuinely NEW evidence type appearing (arp_sweep) -- the fingerprint must change.
fp_store.insert_evidence(Evidence(
    device_id="pattern_dev", destination_id="recurring.example.com",
    evidence_type="arp_sweep", independence_family="network_recon",
    timestamp=NOW - 50, source="s", value=1.0, confidence=0.9))
fp_decision_id = fp_store.insert_decision(
    device_id="pattern_dev", timestamp=NOW - 50, state="SUSPICIOUS",
    decision_path="hypothesis_suspicious", confidence=0.4, risk_score=2.0,
    raw_payload={"hypotheses": {"attack": {"name": "DGA_BOTNET_C2"}}},
)
fp_store.close()
_reset_fake_client()
with patch.object(live_llm_review, "OllamaClient", _FakeClient):
    live_llm_review.main()
check("Phase 8a: a NEW piece of evidence (arp_sweep newly present) on an "
      "otherwise-identical pattern invalidates the cache -- a real Ollama call "
      "is made, not silently served a stale verdict",
      _FakeClient.calls == 1)


# --- Phase 8d: Telegram digest ---
digest_none = live_llm_review.build_llm_review_digest_message([])
check("build_llm_review_digest_message returns None for an empty run (nothing to report)",
      digest_none is None)

digest_msg = live_llm_review.build_llm_review_digest_message([
    {"device_id": "d1", "decision_path": "hypothesis_high", "validator_accepted": True,
     "recommendation": {"classification": "malicious"}},
    {"device_id": "d2", "decision_path": "hypothesis_high", "validator_accepted": False,
     "recommendation": {"classification": "benign", "reason": "looked like telemetry"}},
    {"device_id": "d3", "decision_path": "hypothesis_high", "served_from_persistent_cache": True,
     "validator_accepted": True, "recommendation": {"classification": "malicious"}},
    {"device_id": "d4", "decision_path": "hypothesis_high", "llm_error": "no_response_or_unparseable"},
])
check("the digest counts reviewed/cache-hit/accepted/rejected/error correctly",
      "4 decision(s) reviewed" in digest_msg and "1 served from the persistent pattern cache" in digest_msg
      and "2 LLM verdict(s) accepted" in digest_msg and "1 LLM verdict(s) REJECTED" in digest_msg
      and "1 error(s)" in digest_msg)
check("the digest includes the rejected entry's own device/reason detail",
      "d2" in digest_msg and "looked like telemetry" in digest_msg)
check("the digest never exceeds Telegram's real 4096-char hard limit",
      len(digest_msg) <= 4096)

# end-to-end: main() actually sends the digest when telegram IS configured
_digest_dir = TMPDIR / "digest_e2e"
_digest_dir.mkdir()
digest_store = GraphStore(str(_digest_dir / "v13_graph.db"))
digest_store.insert_evidence(Evidence(device_id="digest_dev", destination_id="z.example.com",
                                        evidence_type="dns_rate", independence_family="dns_behavior",
                                        timestamp=NOW - 50, source="s", value=10.0))
digest_store.insert_decision(
    device_id="digest_dev", timestamp=NOW - 40, state="SUSPICIOUS", decision_path="hypothesis_suspicious",
    confidence=0.4, risk_score=2.0, raw_payload={"hypotheses": {"attack": {"name": "DGA_BOTNET_C2"}}},
)
digest_store.close()
live_llm_review.CONFIG = dict(_config_for(_digest_dir), telegram_token="fake", telegram_chat_id="fake")
_reset_fake_client()
with patch.object(live_llm_review, "OllamaClient", _FakeClient), \
     patch.object(live_llm_review, "send_telegram") as mock_send_telegram:
    live_llm_review.main()
check("main() sends exactly one Telegram digest for a run with real reviews",
      mock_send_telegram.call_count == 1)
check("the sent digest message reports the real reviewed count (device-name detail "
      "only appears for REJECTED entries -- this one was accepted, matching the "
      "digest's own 'most actionable signal first' design)",
      mock_send_telegram.call_count == 1
      and "1 decision(s) reviewed" in mock_send_telegram.call_args.args[1]
      and "1 LLM verdict(s) accepted" in mock_send_telegram.call_args.args[1])

# no-op run (everything already reviewed) sends NO digest -- nothing new to report
_reset_fake_client()
with patch.object(live_llm_review, "OllamaClient", _FakeClient), \
     patch.object(live_llm_review, "send_telegram") as mock_send_telegram_noop:
    live_llm_review.main()
check("a run that reviews nothing new sends NO Telegram digest",
      mock_send_telegram_noop.call_count == 0)


# --- Release 14, Workstream 4: cross-device correlation + GeoIP enrichment ---

from argus.graph.window import RollingWindowView  # noqa: E402

# _inject_coordinated_targeting: a second device touching the SAME destination
# within the window gets a synthetic coordinated_targeting item; a lone device does not
ct_store = GraphStore(str((TMPDIR / "ct_inject").with_suffix(".db")))
ct_window = RollingWindowView(ct_store)
ct_store.insert_evidence(Evidence(device_id="ct_dev1", destination_id="shared.example.com",
                                    evidence_type="dns_rate", independence_family="dns_behavior",
                                    timestamp=NOW - 60, source="s", value=5.0))
evidence_alone = ct_window.evidence_in_window("ct_dev1", RollingWindowView.LONG_WINDOW_SECONDS, now=NOW)
result_alone = live_llm_review._inject_coordinated_targeting(ct_store, ct_window, "ct_dev1", evidence_alone, NOW)
check("_inject_coordinated_targeting: no OTHER device touching the destination -> unchanged list",
      result_alone == evidence_alone
      and not any(e.evidence_type == "coordinated_targeting" for e in result_alone))

ct_store.insert_evidence(Evidence(device_id="ct_dev2", destination_id="shared.example.com",
                                    evidence_type="dns_rate", independence_family="dns_behavior",
                                    timestamp=NOW - 30, source="s", value=5.0))
result_two = live_llm_review._inject_coordinated_targeting(ct_store, ct_window, "ct_dev1", evidence_alone, NOW)
check("_inject_coordinated_targeting: REGRESSION GUARD (third-party architecture "
      "review, 2026-09-09) -- a SECOND device (2 total) touching the same "
      "destination does NOT add coordinated_targeting anymore, matching "
      "live_engine.py's own raised bar",
      not any(e.evidence_type == "coordinated_targeting" for e in result_two))

ct_store.insert_evidence(Evidence(device_id="ct_dev3", destination_id="shared.example.com",
                                    evidence_type="dns_rate", independence_family="dns_behavior",
                                    timestamp=NOW - 20, source="s", value=5.0))
result_shared = live_llm_review._inject_coordinated_targeting(ct_store, ct_window, "ct_dev1", evidence_alone, NOW)
ct_items = [e for e in result_shared if e.evidence_type == "coordinated_targeting"]
check("_inject_coordinated_targeting: a THIRD device touching the same destination "
      "-> a synthetic coordinated_targeting item is added (the real gap this closes: "
      "live_engine.py computes this at decision time but never persists it)",
      len(ct_items) == 1 and ct_items[0].value == 3.0)
check("_inject_coordinated_targeting: the ORIGINAL list is never mutated in place",
      len(evidence_alone) == 1 and not any(e.evidence_type == "coordinated_targeting" for e in evidence_alone))

# fail-safe: a raising window never blocks the review
class _ExplodingWindow:
    def devices_targeting(self, *a, **kw):
        raise RuntimeError("simulated graph failure")


result_failsafe = live_llm_review._inject_coordinated_targeting(
    ct_store, _ExplodingWindow(), "ct_dev1", evidence_alone, NOW,
)
check("_inject_coordinated_targeting: FAIL-SAFE -- a raising window degrades to the "
      "original evidence_list unchanged, never raises",
      result_failsafe == evidence_alone)
ct_store.close()

# _representative_destination
rep_dest = live_llm_review._representative_destination([
    Evidence(device_id="d", destination_id="low.example.com", evidence_type="x",
             independence_family="f", timestamp=NOW, source="s", value=1.0, confidence=0.3),
    Evidence(device_id="d", destination_id="high.example.com", evidence_type="x",
             independence_family="f", timestamp=NOW, source="s", value=1.0, confidence=0.9),
])
check("_representative_destination picks the HIGHEST-confidence real destination",
      rep_dest == "high.example.com")
check("_representative_destination returns '' when no real destination is present",
      live_llm_review._representative_destination([]) == "")

# _geo_note: matches the established convention -- '' for a non-IP/missing engine,
# never raises even against a malformed value
check("_geo_note returns '' for a domain name (not an IP) -- no lookup path for it",
      live_llm_review._geo_note(None, "example.com") == "")
check("_geo_note returns '' when geoip_engine is None", live_llm_review._geo_note(None, "8.8.8.8") == "")
check("_geo_note returns '' for an empty/unknown ip", live_llm_review._geo_note(None, "unknown") == "")

# digest: a destination on a rejected entry is surfaced in the detail line (geoip_engine
# omitted -- degrades to no geo annotation, never crashes)
digest_with_dest = live_llm_review.build_llm_review_digest_message([
    {"device_id": "d5", "decision_path": "hypothesis_high", "validator_accepted": False,
     "destination": "evil.example.com", "recommendation": {"classification": "benign", "reason": "test"}},
])
check("the digest surfaces a rejected entry's destination in its detail line",
      "evil.example.com" in digest_with_dest)

# end-to-end: a decision reviewed while another device recently shares its destination
# actually gets coordinated_targeting evidence in the real prompt sent to the LLM --
# proves the fix closes the structural gap, not just the helper function in isolation
_e2e_dir = TMPDIR / "ct_e2e"
_e2e_dir.mkdir()
e2e_store = GraphStore(str(_e2e_dir / "v13_graph.db"))
e2e_store.insert_evidence(Evidence(device_id="e2e_dev1", destination_id="campaign.example.com",
                                     evidence_type="zeek_lateral_scan", independence_family="network_behavior",
                                     timestamp=NOW - 60, source="s", value=1.0))
e2e_store.insert_evidence(Evidence(device_id="e2e_dev2", destination_id="campaign.example.com",
                                     evidence_type="dns_rate", independence_family="dns_behavior",
                                     timestamp=NOW - 30, source="s", value=1.0))
# THIRD device (third-party architecture review, 2026-09-09): the coordination
# bar is now 3 total devices, not 2 -- see live_engine.py's own comment.
e2e_store.insert_evidence(Evidence(device_id="e2e_dev3", destination_id="campaign.example.com",
                                     evidence_type="dns_rate", independence_family="dns_behavior",
                                     timestamp=NOW - 20, source="s", value=1.0))
e2e_decision_id = e2e_store.insert_decision(
    device_id="e2e_dev1", timestamp=NOW - 10, state="SUSPICIOUS", decision_path="hypothesis_suspicious",
    confidence=0.4, risk_score=2.0, raw_payload={"hypotheses": {"attack": {"name": "NETWORK_INTRUSION"}}},
)
e2e_store.close()

captured_prompts = []


class _PromptCapturingClient(_FakeClient):
    def query_full_analysis(self, prompt_text, timeout=None):
        captured_prompts.append(prompt_text)
        return super().query_full_analysis(prompt_text, timeout=timeout)


live_llm_review.CONFIG = _config_for(_e2e_dir)
_reset_fake_client([{"classification": "malicious", "confidence": 0.8, "reason": "shared campaign infra",
                      "supporting_evidence": ["x"], "contradicting_evidence": [], "recommended_action": "block"}])
with patch.object(live_llm_review, "OllamaClient", _PromptCapturingClient):
    live_llm_review.main()
check("END-TO-END: the real prompt sent to the LLM for e2e_dev1's decision includes "
      "coordinated_targeting -- the actual structural gap this workstream closes "
      "(this evidence was NEVER written to the graph by the live decision path; it "
      "only exists because this review re-derived it)",
      len(captured_prompts) == 1 and "coordinated_targeting" in captured_prompts[0])
e2e_lines = [json.loads(l) for l in (_e2e_dir / "ollama_analysis_v13.jsonl").read_text().splitlines() if l.strip()]
check("END-TO-END: the written entry carries the representative destination for "
      "GeoIP-enriched reporting",
      e2e_lines and e2e_lines[0].get("destination") == "campaign.example.com")


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All live_llm_review.py checks PASSED.")
