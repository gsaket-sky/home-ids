"""
Standalone runtime test for Phase 47: shadow-mode's honeypot hard-stop (Gap 3,
Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md) didn't respect safe_ips. Not part of
the pytest suite -- run directly: `python3 tests/test_phase47_shadow_honeypot_safe_ips.py`.

Context (2026-09-01): a live shadow-mode Telegram digest showed 51 divergences in one
session, every single one the same shape -- home-router (the router, at whichever of
its several IPv6/IPv4 identifiers happened to be active that cycle) diverging live
BENIGN -> shadow CRITICAL / "Internal Honeypot Accessed".

Root cause: pipeline.py's LIVE evidence-creation gate for honeypot_access
(~line 1033) is `if features.get("zeek_honeypot_hits", 0) > 0 and not is_safe:` --
deliberately exempting safe_ips devices (the router is explicitly safe_ips-listed),
since "never treated as suspicious... even if flagged elsewhere" was extended to cover
this one hard-stop specifically (see that line's own comment history) once it was
confirmed the router legitimately touches the honeypot sometimes and mitigate()
already no-ops for is_safe devices regardless, so the only effect of NOT exempting it
was a misleading CRITICAL alert with no real containment behind it.

decision_engine.py's SHADOW computation (Gap 3) deliberately reads the SAME raw
feature (features["zeek_honeypot_hits"]) directly instead of checking EvidenceStore
presence, specifically to dodge a DIFFERENT bug (stale evidence re-firing the same
verdict for up to 600s after the real hit). In copying the raw-feature read, it copied
half of pipeline.py's condition but not the other half -- "and not is_safe" was never
carried over, because is_safe was never even passed into evaluate() at all. Every
single safe_ips device touching the honeypot for a benign reason therefore diverged
shadow CRITICAL, live BENIGN, forever -- not a one-off, a structural gap that would
have fired this way for as long as shadow mode has existed.

Sections:
  A. THE BUG (reproduced): is_safe=True, feature present -> shadow still fired CRITICAL
     before this fix (documented via the OLD condition, not re-run against old code)
  B. THE FIX: is_safe=True, same feature -> shadow no longer fires the honeypot
     hard-stop
  C. REGRESSION GUARD: is_safe=False, same feature -> shadow still correctly fires
     CRITICAL / "Internal Honeypot Accessed" (a genuinely non-exempt device touching
     the honeypot must still show up in shadow diagnostics)
  D. REGRESSION GUARD: is_safe defaults to False when omitted (every existing caller
     that hasn't been updated -- tests, regression_tester.py -- is unaffected)
  E. REGRESSION GUARD: the LIVE verdict (state/explanation, not shadow_*) was never
     wrong in the first place and stays BENIGN throughout -- this bug only ever
     affected the shadow diagnostic, never a real alert
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

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


from core.decision_engine import DecisionEngine
from intelligence.reputation.classifier import ReputationVector

de = DecisionEngine()

# A safe_ips device (the router) with a fresh honeypot hit in its raw features, but --
# because pipeline.py's own evidence-creation gate excludes safe_ips devices -- no
# honeypot_access Evidence was ever added to ev_store. This is exactly the real
# home-router shape: ev_store empty of honeypot evidence, features showing the hit.
empty_ev_store = []
rep = ReputationVector(domain="", tier=3)
honeypot_features = {"zeek_honeypot_hits": 1}


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: THE FIX -- a safe_ips device no longer trips the shadow honeypot hard-stop
# ═══════════════════════════════════════════════════════════════════════════════════
result_safe = de.evaluate(empty_ev_store, rep, features=honeypot_features, is_safe=True)
check("THE FIX: a safe_ips device with zeek_honeypot_hits>0 does NOT get shadow "
      "CRITICAL / 'Internal Honeypot Accessed' -- this is the exact home-router shape "
      "that produced 51 divergences in one live session",
      not (result_safe["shadow_state"] == "CRITICAL"
           and result_safe["shadow_explanation"] == "Internal Honeypot Accessed"),
      f"got shadow_state={result_safe['shadow_state']!r}, "
      f"shadow_explanation={result_safe['shadow_explanation']!r}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: REGRESSION GUARD -- a genuinely non-exempt device still trips it
# ═══════════════════════════════════════════════════════════════════════════════════
result_unsafe = de.evaluate(empty_ev_store, rep, features=honeypot_features, is_safe=False)
check("REGRESSION GUARD: a device that is NOT safe_ips-exempt, same raw honeypot hit, "
      "still correctly fires shadow CRITICAL / 'Internal Honeypot Accessed' -- the fix "
      "narrows the exemption, it doesn't disable the Gap-3 check itself",
      result_unsafe["shadow_state"] == "CRITICAL"
      and result_unsafe["shadow_explanation"] == "Internal Honeypot Accessed",
      f"got shadow_state={result_unsafe['shadow_state']!r}, "
      f"shadow_explanation={result_unsafe['shadow_explanation']!r}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: REGRESSION GUARD -- is_safe defaults to False (every existing, un-updated
# caller -- tests, regression_tester.py, shadow_backtest.py -- keeps working exactly
# as before this fix)
# ═══════════════════════════════════════════════════════════════════════════════════
result_default = de.evaluate(empty_ev_store, rep, features=honeypot_features)
check("REGRESSION GUARD: omitting is_safe entirely (every existing caller that hasn't "
      "been updated) defaults to False -- behavior for those callers is byte-identical "
      "to before this fix",
      result_default["shadow_state"] == result_unsafe["shadow_state"]
      and result_default["shadow_explanation"] == result_unsafe["shadow_explanation"],
      f"got {result_default['shadow_state']!r}/{result_default['shadow_explanation']!r} "
      f"vs {result_unsafe['shadow_state']!r}/{result_unsafe['shadow_explanation']!r}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: PHASE 64 UPDATE -- Gap 3's honeypot freshness check flipped LIVE (was
# shadow-only when this test was first written; see decision_engine.py's own comment).
# The live verdict now DOES react to fresh_honeypot the same way shadow_state always
# did -- this section used to assert the live verdict was untouched (true only while
# the check was shadow-only); it now asserts the live verdict correctly MATCHES
# shadow_state in both the exempted and non-exempted case, which is the actual point of
# flipping this live: a genuinely non-exempt device's fresh honeypot hit must now
# produce a REAL alert, not just a shadow-log diagnostic line nobody but an operator
# reading state/shadow_decisions.jsonl would ever see.
# ═══════════════════════════════════════════════════════════════════════════════════
check("THE FLIP (Phase 64): a safe_ips device's fresh honeypot hit still does NOT "
      "produce a live CRITICAL verdict -- the is_safe exemption applies identically to "
      "the now-live check as it always did to the shadow one",
      result_safe["state"] == "BENIGN",
      f"got live state={result_safe['state']!r} (is_safe=True)")
check("THE FLIP (Phase 64): a genuinely non-exempt device's fresh honeypot hit NOW "
      "produces a real live CRITICAL verdict, matching shadow_state -- before this "
      "flip this scenario silently stayed BENIGN live while shadow correctly said "
      "CRITICAL, i.e. exactly the home-router-shaped bug this whole file exists to "
      "cover was, until now, only ever caught in the diagnostic column, never live",
      result_unsafe["state"] == "CRITICAL" and result_unsafe["state"] == result_unsafe["shadow_state"],
      f"got live state={result_unsafe['state']!r} vs shadow_state={result_unsafe['shadow_state']!r} "
      f"(is_safe=False)")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 47 shadow-honeypot/safe_ips checks PASSED.")
