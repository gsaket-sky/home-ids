"""
Standalone runtime test for src/v13/ops/decision_replay.py -- Release 14's
decision replay / regression testing harness (net-new capability N3,
Documentation/V13_FULL_ARCHITECTURE_SHIFT_PLAN.md).

Not part of the pytest suite -- run directly:
`python3 tests/test_argus_decision_replay.py`

Sections:
  A. get_decision_evidence: resolves a decision's real supporting evidence via
     its 'supports' edges; a decision with no supports edges (e.g. one made
     before A14's evidence_ids wiring) correctly returns [], not a crash
  B. replay_decision: a decision whose evidence still reaches the SAME verdict
     under current code is "unchanged"; one that now reaches a DIFFERENT verdict
     (simulated by re-scoring against evidence that wouldn't have supported the
     original verdict) is "changed", with both old and new state/decision_path
     reported
  C. replay_decision: no evidence available -> a distinct outcome, never a
     misleading "changed to BENIGN" comparison against zero evidence
  D. replay_decision: a raising DecisionEngine fails safe as "replay_error",
     never crashes the batch
  E. replay_range: filters by since/until/device_id correctly, end-to-end
     against a real GraphStore
"""
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import argus.ops.decision_replay as decision_replay  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.evidence.model import Evidence  # noqa: E402

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="v13_decision_replay_test_"))
NOW = time.time()


# --- A. get_decision_evidence ---
store_a = GraphStore(str(TMPDIR / "a.db"))
ev1 = Evidence(device_id="dev_a", destination_id="evil.example.com",
                evidence_type="dns_dga_burst", independence_family="dns_behavior",
                timestamp=NOW - 100, source="zeek", value=1.0)
ev2 = Evidence(device_id="dev_a", destination_id="evil.example.com",
                evidence_type="malicious_ja3", independence_family="tls_fingerprint",
                timestamp=NOW - 90, source="zeek", value=1.0)
store_a.insert_evidence(ev1)
store_a.insert_evidence(ev2)
decision_id_a = store_a.insert_decision(
    device_id="dev_a", timestamp=NOW - 80, state="HIGH", decision_path="hypothesis_high",
    confidence=0.85, risk_score=3.0, raw_payload={"hypotheses": {"attack": {"name": "NETWORK_INTRUSION"}}},
    evidence_ids=[ev1.evidence_id, ev2.evidence_id],
)
resolved_evidence = decision_replay.get_decision_evidence(store_a, {"decision_id": decision_id_a, "device_id": "dev_a"})
check("A: get_decision_evidence resolves exactly the 2 real evidence items via the "
      "decision's own 'supports' edges", len(resolved_evidence) == 2)
check("A: the resolved evidence is the REAL evidence, not a placeholder",
      {e.evidence_type for e in resolved_evidence} == {"dns_dga_burst", "malicious_ja3"})

# A decision with no supports edges at all (e.g. pre-A14) -- correctly returns []
decision_id_no_edges = store_a.insert_decision(
    device_id="dev_a", timestamp=NOW - 70, state="BENIGN", decision_path="benign",
    confidence=0.0, risk_score=0.0, raw_payload={},
)
check("A: a decision with zero supports edges resolves to an empty evidence list, "
      "not a crash or a fabricated result",
      decision_replay.get_decision_evidence(store_a, {"decision_id": decision_id_no_edges, "device_id": "dev_a"}) == [])


# --- B. replay_decision: unchanged vs changed ---
result_unchanged = decision_replay.replay_decision(
    store_a, {"decision_id": decision_id_a, "device_id": "dev_a", "timestamp": NOW - 80,
              "state": "HIGH", "decision_path": "hypothesis_high"},
)
check("B: the SAME real evidence, re-scored by the SAME current code, correctly "
      "reports 'unchanged' -- proves the harness isn't spuriously flagging drift "
      "that doesn't exist",
      result_unchanged["outcome"] == "unchanged"
      and result_unchanged["new_state"] == "HIGH" and result_unchanged["new_decision_path"] == "hypothesis_high")

# Simulate a genuine historical mismatch: the RECORDED old verdict claims BENIGN,
# but the real evidence (2 independent families, a real attack pattern) actually
# scores HIGH under current code -- exactly the "would this decision come out
# differently today" question this tool exists to answer.
result_changed = decision_replay.replay_decision(
    store_a, {"decision_id": decision_id_a, "device_id": "dev_a", "timestamp": NOW - 80,
              "state": "BENIGN", "decision_path": "benign"},
)
check("B: a real verdict mismatch against the recorded old state is correctly "
      "reported as 'changed', with BOTH the old and the new state/decision_path",
      result_changed["outcome"] == "changed"
      and result_changed["old_state"] == "BENIGN"
      and result_changed["new_state"] == "HIGH" and result_changed["new_decision_path"] == "hypothesis_high")


# --- C. no evidence available ---
result_no_evidence = decision_replay.replay_decision(
    store_a, {"decision_id": decision_id_no_edges, "device_id": "dev_a", "timestamp": NOW - 70,
              "state": "BENIGN", "decision_path": "benign"},
)
check("C: a decision with no resolvable evidence reports 'no_evidence_available', "
      "NEVER a misleading 'changed to BENIGN against zero evidence' comparison",
      result_no_evidence["outcome"] == "no_evidence_available")
store_a.close()


# --- D. FAIL-SAFE: a raising DecisionEngine never crashes the batch ---
store_d = GraphStore(str(TMPDIR / "d.db"))
ev_d = Evidence(device_id="dev_d", destination_id="x.example.com",
                  evidence_type="dns_rate", independence_family="dns_behavior",
                  timestamp=NOW - 50, source="s", value=1.0)
store_d.insert_evidence(ev_d)
decision_id_d = store_d.insert_decision(
    device_id="dev_d", timestamp=NOW - 40, state="SUSPICIOUS", decision_path="hypothesis_suspicious",
    confidence=0.4, risk_score=2.0, raw_payload={}, evidence_ids=[ev_d.evidence_id],
)


class _ExplodingDecisionEngine:
    def evaluate(self, *a, **kw):
        raise RuntimeError("simulated decision-engine failure")


result_error = decision_replay.replay_decision(
    store_d, {"decision_id": decision_id_d, "device_id": "dev_d", "timestamp": NOW - 40,
              "state": "SUSPICIOUS", "decision_path": "hypothesis_suspicious"},
    decision_engine=_ExplodingDecisionEngine(),
)
check("D: FAIL-SAFE -- a raising DecisionEngine reports 'replay_error' with the "
      "real error message, never propagates or crashes the batch",
      result_error["outcome"] == "replay_error" and "simulated" in result_error.get("error", ""))
store_d.close()


# --- E. replay_range: since/until/device_id filtering, end-to-end ---
store_e = GraphStore(str(TMPDIR / "e.db"))
ev_e1 = Evidence(device_id="dev_e1", destination_id="y.example.com",
                   evidence_type="dns_rate", independence_family="dns_behavior",
                   timestamp=NOW - 200, source="s", value=1.0)
store_e.insert_evidence(ev_e1)
store_e.insert_decision(device_id="dev_e1", timestamp=NOW - 190, state="SUSPICIOUS",
                          decision_path="hypothesis_suspicious", confidence=0.4, risk_score=2.0,
                          raw_payload={}, evidence_ids=[ev_e1.evidence_id])
ev_e2 = Evidence(device_id="dev_e2", destination_id="z.example.com",
                   evidence_type="dns_rate", independence_family="dns_behavior",
                   timestamp=NOW - 20, source="s", value=1.0)
store_e.insert_evidence(ev_e2)
store_e.insert_decision(device_id="dev_e2", timestamp=NOW - 10, state="SUSPICIOUS",
                          decision_path="hypothesis_suspicious", confidence=0.4, risk_score=2.0,
                          raw_payload={}, evidence_ids=[ev_e2.evidence_id])

all_results = decision_replay.replay_range(store_e, since=NOW - 300)
check("E: replay_range against a wide window picks up BOTH decisions", len(all_results) == 2)

recent_only = decision_replay.replay_range(store_e, since=NOW - 100)
check("E: a narrower 'since' window correctly excludes the older decision",
      len(recent_only) == 1 and recent_only[0]["device_id"] == "dev_e2")

filtered_by_device = decision_replay.replay_range(store_e, since=NOW - 300, device_id="dev_e1")
check("E: device_id filtering returns only that device's decision(s)",
      len(filtered_by_device) == 1 and filtered_by_device[0]["device_id"] == "dev_e1")

until_filtered = decision_replay.replay_range(store_e, since=NOW - 300, until=NOW - 100)
check("E: 'until' correctly excludes a decision newer than the window",
      len(until_filtered) == 1 and until_filtered[0]["device_id"] == "dev_e1")
store_e.close()


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All decision_replay.py checks PASSED.")
