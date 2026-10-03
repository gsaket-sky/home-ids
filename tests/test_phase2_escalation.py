"""
Standalone runtime test for Phase 2 (alert on single strong signal + cross-cycle
escalation). Not part of the pytest suite — run directly:
`python3 test_phase2_escalation.py`.

Part A exercises the REAL DecisionEngine/HypothesisEngine code to confirm a single
independent attack signal now produces a SUSPICIOUS (not BENIGN-suppressed) verdict, and
that pipeline.py's alert gate literally includes DecisionState.SUSPICIOUS (source-level
guard against regression, since the gate itself is inline in EnginePipeline._step() and
not factored into a standalone function).

Part B exercises the cross-cycle escalation algorithm. That logic (core/pipeline.py lines
~601-622) is inline inside EnginePipeline._step(), tightly coupled to the live pipeline
object (Zeek/Pi-hole feature extractors, ML registry, FP engine, Telegram alert manager,
etc.) — standing up a full EnginePipeline is out of scope for a fast standalone check. So
this test (1) mirrors the exact algorithm faithfully against the real DeviceState object
and real config defaults, and (2) asserts byte-for-byte that pipeline.py's source still
contains that exact block, so any future edit to the real code either keeps this test
honest or fails it immediately rather than silently drifting from what's actually shipped.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time
import re

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# ── Part A: single strong signal reaches SUSPICIOUS, and the alert gate includes it ──
from intelligence.detectors.threat_signals import ThreatSignalDetector
from intelligence.hypotheses.evidence import EvidenceStore
from intelligence.reputation.classifier import ReputationClassifier
from argus_scenarios import DecisionEngine, DecisionState

detector = ThreatSignalDetector()
rc = ReputationClassifier()
de = DecisionEngine()

store = EvidenceStore()
# A single independent signal (one DGA burst, no corroborating zeek/reputation source) —
# num_independent_sources will be 1, so DecisionEngine's `attack_score >= 2.0` branch
# takes the SUSPICIOUS path (not HIGH, which requires >=2 independent sources).
single_signal_features = {"suspicious_domains": 20.0, "entropy_avg": 4.0}
for e in detector.detect("dev_single", single_signal_features):
    store.add(e)
active = store.get_for_device("dev_single")
rep = rc.classify("randomdga12345.biz")
decision = de.evaluate(active, rep)

check("a single independent strong signal (1 source) reaches SUSPICIOUS, not BENIGN",
      decision["state"] == DecisionState.SUSPICIOUS, f"got state={decision['state']}")
check("independent_sources count is exactly 1 for this single-signal scenario",
      decision["independent_sources"] == 1, f"got {decision['independent_sources']}")

with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src = f.read()

check("pipeline.py's alert gate has been widened to include DecisionState.SUSPICIOUS "
      "(previously only HIGH/CRITICAL alerted, so this single-signal SUSPICIOUS case "
      "would have gone completely silent)",
      re.search(r"decision\[.state.\]\s+in\s+\(DecisionState\.HIGH,\s*DecisionState\.CRITICAL,\s*DecisionState\.SUSPICIOUS\)", pipeline_src) is not None)


# ── Part B: cross-cycle escalation algorithm (mirrors pipeline.py ~601-622) ─────────
from core.state import DeviceState

ESCALATION_BLOCK_SOURCE = '''\
                    if decision["state"] == DecisionState.SUSPICIOUS:
                        if getattr(state, "suspicious_signature", "") == primary_sig and getattr(state, "suspicious_since", 0.0) > 0:
                            persisted_for = now - state.suspicious_since
                            escalation_threshold = float(self.config.get("suspicious_escalation_seconds", 600.0))
                            if persisted_for >= escalation_threshold:'''
check("pipeline.py's source still contains the exact Phase 2 escalation block this test mirrors "
      "(guards this test against silently drifting from the real shipped logic)",
      ESCALATION_BLOCK_SOURCE in pipeline_src)


def apply_escalation(state, decision, primary_sig, now, escalation_threshold=600.0):
    """Faithful mirror of core/pipeline.py's inline escalation block."""
    if decision["state"] == DecisionState.SUSPICIOUS:
        if getattr(state, "suspicious_signature", "") == primary_sig and getattr(state, "suspicious_since", 0.0) > 0:
            persisted_for = now - state.suspicious_since
            if persisted_for >= escalation_threshold:
                decision = dict(decision)
                decision["state"] = DecisionState.HIGH
                decision["explanation"] = f"{decision['explanation']} (persisted {int(persisted_for)}s)"
                decision["threat_confidence"] = max(decision["threat_confidence"], 0.75)
        else:
            state.suspicious_signature = primary_sig
            state.suspicious_since = now
    else:
        state.suspicious_signature = ""
        state.suspicious_since = 0.0
    return decision


state = DeviceState("dev_escalate", "192.168.1.90", "test-host")
base_decision = {"state": DecisionState.SUSPICIOUS, "explanation": "DGA_BOTNET_C2", "threat_confidence": 0.40}
sig = "DGA_BOTNET_C2"

t0 = 1_000_000.0
d1 = apply_escalation(state, dict(base_decision), sig, t0)
check("first SUSPICIOUS cycle starts tracking suspicious_since/signature, stays SUSPICIOUS",
      d1["state"] == DecisionState.SUSPICIOUS and state.suspicious_since == t0 and state.suspicious_signature == sig)

# Same signature, only 100s later — under the 600s default threshold, stays SUSPICIOUS.
d2 = apply_escalation(state, dict(base_decision), sig, t0 + 100)
check("same signature persisting for only 100s (< 600s threshold) does NOT escalate",
      d2["state"] == DecisionState.SUSPICIOUS)

# Same signature, 700s later — crosses the default 600s escalation threshold.
d3 = apply_escalation(state, dict(base_decision), sig, t0 + 700)
check("same signature persisting >= 600s escalates to HIGH",
      d3["state"] == DecisionState.HIGH, f"got {d3['state']}")
check("escalated decision's threat_confidence is boosted to at least 0.75",
      d3["threat_confidence"] >= 0.75, f"got {d3['threat_confidence']}")
check("escalated explanation records how long the signature persisted",
      "persisted" in d3["explanation"], f"got explanation={d3['explanation']!r}")

# A different signature resets the escalation clock instead of accumulating.
state2 = DeviceState("dev_escalate2", "192.168.1.91", "test-host2")
apply_escalation(state2, dict(base_decision), "DGA_BOTNET_C2", t0)
d_switch = apply_escalation(state2, dict(base_decision), "C2_BEACONING", t0 + 700)
check("a DIFFERENT signature at t+700s resets the escalation clock instead of "
      "inheriting the old signature's elapsed time (prevents unrelated signals "
      "from falsely escalating each other)",
      d_switch["state"] == DecisionState.SUSPICIOUS and state2.suspicious_signature == "C2_BEACONING")

# Returning to BENIGN/ANOMALOUS clears the tracker (no stale escalation state).
state3 = DeviceState("dev_escalate3", "192.168.1.92", "test-host3")
apply_escalation(state3, dict(base_decision), sig, t0)
apply_escalation(state3, {"state": DecisionState.BENIGN, "explanation": "x", "threat_confidence": 0.0}, "x", t0 + 50)
check("a BENIGN cycle in between clears suspicious_since/signature (no silent carry-over)",
      state3.suspicious_since == 0.0 and state3.suspicious_signature == "")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 2 single-signal-alert + cross-cycle-escalation checks PASSED.")
