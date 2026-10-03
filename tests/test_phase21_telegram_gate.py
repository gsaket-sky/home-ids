"""
Standalone runtime test for Phase 21 (Telegram alert-volume reduction). Not part of the
pytest suite -- run directly: `python3 test_phase21_telegram_gate.py`.

Background: per explicit operator direction ("no alert for suspicion... reduce alerts
in telegram as it is too many"), a Telegram notification now requires the SAME
genuinely-corroborated HIGH/CRITICAL bar that already authorizes a Pi-hole block
(containment_decision_state -- already downgraded from a persistence-escalated HIGH
back to SUSPICIOUS by the Phase 19 fix, see test_phase19). A SUSPICIOUS/monitor-only
decision still writes to alerts.json (unconditional), still trains CL-AFPE, still shows
in Grafana -- it just no longer pages the operator. This does NOT touch mitigate() or
the router/tarpit escalation paths, which have their own independent risk_score/
lateral_threat gates unrelated to Telegram.

Mirrors test_phase19's approach: source-level guards (this test fails immediately if a
future edit removes the gate) plus a pure-function mirror of the actual gating decision.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import re

from argus_scenarios import DecisionState

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src = f.read()

check("telegram_worthy is computed from containment_decision_state, not fp_verdict alone",
      'telegram_worthy = containment_decision_state in (DecisionState.HIGH, DecisionState.CRITICAL)' in pipeline_src)

check("the alert_msg-build/send block requires BOTH not-suppressed AND telegram_worthy "
      "(source-level guard against regression to the old, looser gate)",
      'if not fp_verdict["suppress"] and telegram_worthy:' in pipeline_src)

check("alerts held below the Telegram threshold are still logged (observability), not silently dropped",
      re.search(
          r'elif not fp_verdict\["suppress"\]:\s*\n\s*LOGGER\.info\(\s*\n\s*'
          r'"Alert for %s held below Telegram threshold',
          pipeline_src
      ) is not None)

check("the unconditional alerts.json write (alert_writer.write) precedes the Telegram gate, "
      "so SUSPICIOUS-tier events still train CL-AFPE regardless of Telegram outcome",
      pipeline_src.find("self.alert_writer.write(alert_payload)") < pipeline_src.find('telegram_worthy ='))

check("mitigate() itself is NOT wrapped in the new telegram_worthy condition -- router/tarpit "
      "escalation (its own independent risk_score/lateral_threat gates) must be unaffected",
      pipeline_src.find("self.ips_mitigator.mitigate(") < pipeline_src.find('telegram_worthy ='))


def is_telegram_worthy(containment_decision_state: str, suppressed: bool) -> bool:
    """Mirrors core/pipeline.py's new Telegram-send gate exactly."""
    telegram_worthy = containment_decision_state in (DecisionState.HIGH, DecisionState.CRITICAL)
    return (not suppressed) and telegram_worthy


check("HIGH, not suppressed -> Telegram fires (matches the same bar that authorizes a Pi-hole block)",
      is_telegram_worthy(DecisionState.HIGH, False) is True)

check("CRITICAL, not suppressed -> Telegram fires",
      is_telegram_worthy(DecisionState.CRITICAL, False) is True)

check("THE CORE FIX: SUSPICIOUS, not suppressed -> Telegram withheld "
      "(this is exactly the case Phase 2 used to alert on -- explicitly reversed by this fix)",
      is_telegram_worthy(DecisionState.SUSPICIOUS, False) is False)

check("ANOMALOUS, not suppressed -> Telegram withheld",
      is_telegram_worthy("ANOMALOUS", False) is False)

check("HIGH but CL-AFPE suppressed as a false positive -> Telegram withheld "
      "(suppression still wins regardless of decision state)",
      is_telegram_worthy(DecisionState.HIGH, True) is False)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 21 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 21 Telegram-gating checks PASSED.")
    sys.exit(0)
