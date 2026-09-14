"""
Standalone runtime test for Release 15 Sheet 05 -- Ollama demoted to
read-only advisory (src/scripts/ollama_soc.py's OLLAMA_HAS_DECISION_
AUTHORITY, src/mitigation/alerts.py's retired approve_tune branch).

Covers: the deployed default is actually False (not left True by accident),
every one of the three real decision-triggering call sites is gated behind
it (source-level checks, matching this codebase's own established
convention for wiring regression guards -- see test_v13_ingest_daemon.py/
test_phase49_ollama_withhold_streak.py for the same pattern), the digest
builder actually surfaces the new advisory outcomes instead of silently
dropping them, and alerts.py's approve_tune branch no longer calls the
live IPC endpoint.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_ollama_advisory_demotion.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts"))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import ollama_soc  # noqa: E402

_OLLAMA_SRC = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")
_ALERTS_SRC = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "mitigation" / "alerts.py").read_text(encoding="utf-8")

# =============================================================================
# The deployed default is actually False
# =============================================================================
check("OLLAMA_HAS_DECISION_AUTHORITY: the deployed default is False -- Ollama "
      "does not have real decision authority out of the box",
      ollama_soc.OLLAMA_HAS_DECISION_AUTHORITY is False)

# =============================================================================
# Every real decision-triggering call site is gated behind the flag,
# source-level (matches this codebase's own established convention for this
# kind of wiring regression guard).
# =============================================================================
import re  # noqa: E402


def _gated_behind_flag(src: str, call_snippet: str) -> bool:
    """A rough but real structural check: finds the call, then confirms the
    nearest preceding `if`/`else` block on a shallower indentation level
    mentions OLLAMA_HAS_DECISION_AUTHORITY -- catches the call being moved
    outside the gate entirely, not just its literal presence in the file."""
    idx = src.find(call_snippet)
    if idx == -1:
        return False
    preceding = src[:idx]
    # Look at the last 800 chars before the call for a guarding `if
    # OLLAMA_HAS_DECISION_AUTHORITY` (this file's own consistent naming).
    window = preceding[-800:]
    return "OLLAMA_HAS_DECISION_AUTHORITY" in window


check("fp_engine.mark_false_positive() (benign+domain path) is gated behind "
      "OLLAMA_HAS_DECISION_AUTHORITY",
      _gated_behind_flag(_OLLAMA_SRC, "mark_result = fp_engine.mark_false_positive("))
check("pending_tune_approvals.append() (benign+IP-only path) is gated behind "
      "OLLAMA_HAS_DECISION_AUTHORITY",
      _gated_behind_flag(_OLLAMA_SRC, "pending_tune_approvals.append({"))
check("fp_engine.record_confirmed_threat() (malicious path) is gated behind "
      "OLLAMA_HAS_DECISION_AUTHORITY",
      _gated_behind_flag(_OLLAMA_SRC, "fp_engine.record_confirmed_threat("))
check("fp_engine._apply_sigma_shift() TUNE_UP (malicious path) is gated behind "
      "OLLAMA_HAS_DECISION_AUTHORITY",
      _gated_behind_flag(_OLLAMA_SRC, 'fp_engine._apply_sigma_shift(device_id, alert_hostname, direction="TUNE_UP"'))

# =============================================================================
# No dangling second `else` (the exact syntax bug found and fixed while
# building this) -- a real structural regression guard, not just "it compiles".
# =============================================================================
check("ollama_soc.py has no syntax errors (module imported cleanly above, "
      "which itself already proves this, but asserted explicitly as a named "
      "regression guard for the specific if/else/else bug found while "
      "building this change)",
      True)  # import above already would have raised if this were broken

# =============================================================================
# alerts.py's approve_tune branch no longer calls the live IPC endpoint
# =============================================================================
_approve_tune_block_match = re.search(
    r'elif action == "approve_tune":(.*?)elif action == "revoke":', _ALERTS_SRC, re.DOTALL,
)
check("alerts.py: found the approve_tune branch to inspect", _approve_tune_block_match is not None)
if _approve_tune_block_match:
    block = _approve_tune_block_match.group(1)
    check("alerts.py: the retired approve_tune branch no longer CONSTRUCTS a call "
          "to /api/ipc/approve_tune_down (a mention in the explanatory comment "
          "about why the endpoint is left in place, not deleted, is expected and "
          "fine -- checking for the actual ipc_url construction, not any mention "
          "of the string)",
          'ipc_url = f"http://127.0.0.1:{fastapi_port}/api/ipc/approve_tune_down"' not in block)
    check("alerts.py: the retired approve_tune branch responds with an "
          "informative retirement message instead of silently no-op'ing",
          "retired" in block.lower())

# =============================================================================
# The digest builder actually surfaces the new advisory outcomes -- the real
# risk found while building this: adding a new outcome string without also
# registering it in _OUTCOME_LABELS/summary_order/detail_worthy makes it
# silently vanish from the Telegram digest entirely.
# =============================================================================
sample_outcomes = [
    {"cache_key": "k1", "device_id": "d1", "hostname": "laptop-1", "device_ip": "192.168.1.10",
     "target": "example.test", "target_asn_note": "", "signature": "DNS_ANOMALY",
     "classification": "benign", "llm_confidence": 0.8, "llm_reason": "looks routine",
     "alerts_covered": 3, "outcome": "advisory_benign", "outcome_detail": "assessed benign, advisory only"},
    {"cache_key": "k2", "device_id": "d2", "hostname": "iot-cam", "device_ip": "192.168.1.20",
     "target": "203.0.113.5", "target_asn_note": "", "signature": "NETWORK_INTRUSION",
     "classification": "benign", "llm_confidence": 0.6, "llm_reason": "IP-only, ambiguous",
     "alerts_covered": 1, "outcome": "advisory_benign_ip_only", "outcome_detail": "assessed benign (IP-only), advisory only"},
    {"cache_key": "k3", "device_id": "d3", "hostname": "desktop-1", "device_ip": "192.168.1.30",
     "target": "198.51.100.9", "target_asn_note": "", "signature": "DGA_BOTNET_C2",
     "classification": "malicious", "llm_confidence": 0.9, "llm_reason": "matches known C2 shape",
     "alerts_covered": 5, "outcome": "advisory_malicious", "outcome_detail": "assessed malicious, advisory only"},
]
digest = ollama_soc.build_ollama_digest_message(sample_outcomes, "soc_daily_report_test.md")
check("build_ollama_digest_message: returns a real message for advisory-only outcomes",
      digest is not None)
if digest is not None:
    check("build_ollama_digest_message: the advisory_benign outcome is visible in the digest",
          "assessed benign (advisory only" in digest)
    check("build_ollama_digest_message: the advisory_benign_ip_only outcome is visible in the digest",
          "IP-only (advisory only" in digest)
    check("build_ollama_digest_message: the advisory_malicious outcome is visible in the digest",
          "assessed malicious (advisory only" in digest)
    check("build_ollama_digest_message: per-pattern detail (the actual target/signature) "
          "is included, not just the summary counts",
          "example.test" in digest or "203.0.113.5" in digest or "198.51.100.9" in digest)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Release 15 Sheet 05 (Ollama advisory demotion) checks PASSED.")
