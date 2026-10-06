"""
The CL-AFPE verdict labels, and how to read one from an alert of any age.

Until 2026-10-06 one label, CONFIRMED_THREAT, covered three different outcomes: an independent hard stop (a real
confirmation), a hard stop caused only by the local confirmed-intel store (another device's earlier confirmation, not
a new one), and the Stage-3 "low false-positive probability, publish at full severity" result. On .94, 373 of 408
alerts in the first 11 h after a deploy carried it while the decision engine itself said "SUSPICIOUS / monitor".
Everything that treats the label as ground truth (the backtest's "later confirmed malicious" checks, the console's
"Confirmed threats" tile, the confirmed-threat metric) counted those too. Now each outcome has its own label:

  FALSE_POSITIVE      suppressed (trust cache or Stage 2/3).
  UNCERTAIN           published at the softer severity.
  LIKELY_REAL         Stage 3: low false-positive probability, published at full severity. Not a confirmation.
  PREVIOUSLY_FLAGGED  a hard stop whose only trigger is the local confirmed-intel match: never suppressed, but not a
                      new confirmation (the same rule _is_independent_confirmation() applies to renewing the entry).
  CONFIRMED_THREAT    a hard stop with at least one independent trigger (decision-engine CRITICAL, threat-intel IOC,
                      lateral movement, malicious JA3/JA4, decoy host, AbuseIPDB, exfiltration burst).

Alerts written before the split carry CONFIRMED_THREAT at stage STAGE_3_COMBINED; canonical_verdict() reads those as
LIKELY_REAL. An old Stage-1 alert cannot be told apart (its triggers were not stored) and stays CONFIRMED_THREAT.
"""
from typing import Any, Optional

FALSE_POSITIVE = "FALSE_POSITIVE"
UNCERTAIN = "UNCERTAIN"
LIKELY_REAL = "LIKELY_REAL"
PREVIOUSLY_FLAGGED = "PREVIOUSLY_FLAGGED"
CONFIRMED_THREAT = "CONFIRMED_THREAT"

# Published at full severity (what CONFIRMED_THREAT meant to the publishing path before the split).
FULL_SEVERITY_VERDICTS = frozenset({CONFIRMED_THREAT, PREVIOUSLY_FLAGGED, LIKELY_REAL})


def canonical_verdict(fp_verdict: Any) -> Optional[str]:
    """The verdict of an alert's `fp_verdict` dict in today's labels (None when absent)."""
    if not isinstance(fp_verdict, dict):
        return None
    verdict = fp_verdict.get("verdict")
    if verdict == CONFIRMED_THREAT and fp_verdict.get("stage") == "STAGE_3_COMBINED":
        return LIKELY_REAL
    return verdict


def is_confirmed_threat(fp_verdict: Any) -> bool:
    """True only for an independently confirmed threat."""
    return canonical_verdict(fp_verdict) == CONFIRMED_THREAT
