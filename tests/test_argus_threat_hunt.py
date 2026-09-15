"""
Standalone runtime test for src/v13/ops/threat_hunt.py -- Release 14's ad-hoc
historical threat-hunting surface (net-new capability N1, Documentation/
V13_FULL_ARCHITECTURE_SHIFT_PLAN.md).

Not part of the pytest suite -- run directly:
`python3 tests/test_argus_threat_hunt.py`

Sections:
  A. devices_touching: every device that ever touched a destination, with a
     `since` floor; a device outside that floor is correctly excluded
  B. decision_timeline: the full evidence timeline behind one decision, in
     chronological order; a nonexistent decision_id returns None, not a crash
  C. device_history: one device's full evidence + decision history, merged and
     canonicalized (a merged orphan's history is included transparently)
"""
import sys
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import argus.ops.threat_hunt as threat_hunt  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.evidence.model import Evidence  # noqa: E402

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="v13_threat_hunt_test_"))
NOW = 9_000_000.0


# --- A. devices_touching ---
store_a = GraphStore(str(TMPDIR / "a.db"))
store_a.insert_evidence(Evidence(device_id="th_dev1", destination_id="shared.example.com",
                                   evidence_type="dns_rate", independence_family="dns_behavior",
                                   timestamp=NOW - 100, source="s", value=1.0))
store_a.insert_evidence(Evidence(device_id="th_dev2", destination_id="shared.example.com",
                                   evidence_type="dns_rate", independence_family="dns_behavior",
                                   timestamp=NOW - 50, source="s", value=1.0))
store_a.insert_evidence(Evidence(device_id="th_dev_old", destination_id="shared.example.com",
                                   evidence_type="dns_rate", independence_family="dns_behavior",
                                   timestamp=NOW - 1_000_000, source="s", value=1.0))

all_time = threat_hunt.devices_touching(store_a, "shared.example.com")
check("A: devices_touching with since=0.0 (default) finds EVERY device across all "
      "retained history, including the old one",
      set(all_time) == {"th_dev1", "th_dev2", "th_dev_old"}, f"got {all_time}")

recent_only = threat_hunt.devices_touching(store_a, "shared.example.com", since=NOW - 500)
check("A: a real `since` floor correctly excludes the old device",
      set(recent_only) == {"th_dev1", "th_dev2"}, f"got {recent_only}")

check("A: a destination nobody ever touched returns an empty list, not a crash",
      threat_hunt.devices_touching(store_a, "never-touched.example.com") == [])
store_a.close()


# --- B. decision_timeline ---
store_b = GraphStore(str(TMPDIR / "b.db"))
ev1 = Evidence(device_id="th_devB", destination_id="evil.example.com",
                evidence_type="zeek_lateral_scan", independence_family="network_behavior",
                timestamp=NOW - 100, source="zeek", value=1.0)
ev2 = Evidence(device_id="th_devB", destination_id="evil.example.com",
                evidence_type="malicious_ja3", independence_family="tls_fingerprint",
                timestamp=NOW - 90, source="zeek", value=1.0)
store_b.insert_evidence(ev1)
store_b.insert_evidence(ev2)
decision_id_b = store_b.insert_decision(
    device_id="th_devB", timestamp=NOW - 80, state="HIGH", decision_path="hypothesis_high",
    confidence=0.85, risk_score=3.0, raw_payload={"hypotheses": {"attack": {"name": "NETWORK_INTRUSION"}}},
    evidence_ids=[ev1.evidence_id, ev2.evidence_id],
)

timeline = threat_hunt.decision_timeline(store_b, decision_id_b)
check("B: decision_timeline finds the real decision", timeline is not None and timeline["decision"]["state"] == "HIGH")
check("B: decision_timeline resolves exactly the 2 real supporting evidence items",
      len(timeline["evidence"]) == 2)
check("B: the evidence is returned in CHRONOLOGICAL order (oldest first)",
      timeline["evidence"][0].timestamp < timeline["evidence"][1].timestamp)
check("B: decision_timeline returns None for a decision_id that doesn't exist, "
      "not a crash -- a real, expected case for a manual lookup",
      threat_hunt.decision_timeline(store_b, "nonexistent-id") is None)
store_b.close()


# --- C. device_history ---
store_c = GraphStore(str(TMPDIR / "c.db"))
store_c.insert_evidence(Evidence(device_id="th_devC", destination_id="a.example.com",
                                   evidence_type="dns_rate", independence_family="dns_behavior",
                                   timestamp=NOW - 200, source="s", value=1.0))
store_c.insert_decision(device_id="th_devC", timestamp=NOW - 190, state="SUSPICIOUS",
                          decision_path="hypothesis_suspicious", confidence=0.4, risk_score=2.0,
                          raw_payload={})
store_c.insert_decision(device_id="th_other_dev", timestamp=NOW - 190, state="BENIGN",
                          decision_path="benign", confidence=0.0, risk_score=0.0, raw_payload={})

history = threat_hunt.device_history(store_c, "th_devC")
check("C: device_history returns the real evidence for this device", len(history["evidence"]) == 1)
check("C: device_history returns only THIS device's decisions, not another device's",
      len(history["decisions"]) == 1 and history["decisions"][0]["device_id"] == "th_devC")
check("C: device_history reports the canonical device_id", history["canonical_device_id"] == "th_devC")

# A merged orphan's history is included transparently
store_c.insert_evidence(Evidence(device_id="th_devC_orphan", destination_id="b.example.com",
                                   evidence_type="dns_rate", independence_family="dns_behavior",
                                   timestamp=NOW - 180, source="s", value=1.0))
store_c.merge_device("th_devC_orphan", "th_devC", timestamp=NOW - 170)
history_after_merge = threat_hunt.device_history(store_c, "th_devC")
check("C: device_history includes a merged orphan's own evidence transparently "
      "(2 evidence items now, not 1)", len(history_after_merge["evidence"]) == 2)
check("C: looking up the ORPHAN id directly still resolves to the canonical device's "
      "full history (not just the orphan's own slice)",
      threat_hunt.device_history(store_c, "th_devC_orphan")["canonical_device_id"] == "th_devC")
store_c.close()


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All threat_hunt.py checks PASSED.")
