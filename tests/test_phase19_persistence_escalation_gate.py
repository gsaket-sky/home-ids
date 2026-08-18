"""
Standalone runtime test for Phase 19 (persistence-escalation must not bypass the
severity gate). Not part of the pytest suite -- run directly:
`python3 test_phase19_persistence_escalation_gate.py`.

Background: the severity gate (Phase 17/24e1d07) trusts decision_state alone to decide
whether Pi-hole containment may fire -- only HIGH/CRITICAL may block. But
decision["state"] can become HIGH two different ways: (a) decision_engine.py's own
hypothesis scoring found >=2 genuinely independent corroborating sources, or (b) the
Phase 2 cross-cycle escalation block (pipeline.py, predates the severity gate) promoted
a single uncorroborated SUSPICIOUS signal to HIGH purely because it kept recurring on the
same device+signature for >= suspicious_escalation_seconds, with no new evidence. Before
this fix, both looked identical to the severity gate -- a domain that simply got queried
repeatedly (e.g. a legitimate vendor domain never added to the allowlist) could silently
earn itself an auto-block after 10 minutes, exactly the "block only after genuine
corroboration" guarantee the gate exists to provide, defeated through a different door.

Standing up a full EnginePipeline to exercise this end-to-end is out of scope for a fast
standalone check (see test_phase2_escalation.py's own note on this) -- this test (1)
mirrors the exact containment_decision_state computation faithfully, and (2) asserts
byte-for-byte that pipeline.py's source still contains it, so a future edit either keeps
this test honest or fails it immediately.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import re

from core.decision_engine import DecisionState

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src = f.read()

check("escalation block tags escalated-to-HIGH decisions with escalated_via_persistence",
      'decision["escalated_via_persistence"] = True' in pipeline_src)

check("the mitigate() call site downgrades containment_decision_state back to SUSPICIOUS "
      "for persistence-escalated decisions (source-level guard against regression)",
      re.search(
          r'containment_decision_state\s*=\s*decision\.get\("state",\s*"SUSPICIOUS"\)\s*\n\s*'
          r'if decision\.get\("escalated_via_persistence"\):\s*\n\s*'
          r'containment_decision_state\s*=\s*DecisionState\.SUSPICIOUS',
          pipeline_src
      ) is not None)

check("mitigate() itself is called with containment_decision_state, not decision.get(...) directly "
      "(guards against the fix being reverted by re-inlining the old expression)",
      re.search(r'decision_state=containment_decision_state', pipeline_src) is not None)


def compute_containment_decision_state(decision: dict) -> str:
    """Faithful mirror of core/pipeline.py's containment_decision_state computation."""
    containment_decision_state = decision.get("state", "SUSPICIOUS")
    if decision.get("escalated_via_persistence"):
        containment_decision_state = DecisionState.SUSPICIOUS
    return containment_decision_state


# Genuinely corroborated HIGH (decision_engine.py's own >=2-independent-sources scoring,
# no escalation flag) -- must still be allowed to authorize containment.
genuine_high = {"state": DecisionState.HIGH, "threat_confidence": 0.85}
check("genuinely corroborated HIGH (no escalation flag) still authorizes containment",
      compute_containment_decision_state(genuine_high) == DecisionState.HIGH,
      f"got {compute_containment_decision_state(genuine_high)}")

# Persistence-escalated HIGH (the bug this test guards) -- must be downgraded, never reach
# the severity gate as HIGH.
escalated_high = {"state": DecisionState.HIGH, "threat_confidence": 0.75, "escalated_via_persistence": True}
check("THE CORE FIX: persistence-escalated HIGH is downgraded to SUSPICIOUS for containment "
      "purposes, closing the silent severity-gate bypass",
      compute_containment_decision_state(escalated_high) == DecisionState.SUSPICIOUS,
      f"got {compute_containment_decision_state(escalated_high)}")

# CRITICAL (hard-stops, tier-5 reputation, geofencing) is never touched by the escalation
# block at all -- confirm it's unaffected regardless.
critical = {"state": DecisionState.CRITICAL, "threat_confidence": 0.99}
check("CRITICAL (never escalation-derived) is unaffected and still authorizes containment",
      compute_containment_decision_state(critical) == DecisionState.CRITICAL,
      f"got {compute_containment_decision_state(critical)}")

# Plain SUSPICIOUS (never escalated) -- was already correctly withheld by the severity
# gate before this fix; confirm this fix didn't change that.
plain_suspicious = {"state": DecisionState.SUSPICIOUS, "threat_confidence": 0.40}
check("plain (never-escalated) SUSPICIOUS is unchanged -- still withheld from containment",
      compute_containment_decision_state(plain_suspicious) == DecisionState.SUSPICIOUS,
      f"got {compute_containment_decision_state(plain_suspicious)}")


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 19 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 19 persistence-escalation severity-gate checks PASSED.")
    sys.exit(0)
