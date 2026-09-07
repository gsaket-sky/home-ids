"""
Standalone runtime test for Phase 47: the honeypot hard-stop's is_safe exemption
(originally Gap 3 shadow-mode, Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md; flipped
LIVE at Phase 64). Not part of the pytest suite -- run directly:
`python3 tests/test_phase47_shadow_honeypot_safe_ips.py`.

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

decision_engine.py's original SHADOW computation (Gap 3) deliberately read the SAME
raw feature (features["zeek_honeypot_hits"]) directly instead of checking
EvidenceStore presence, specifically to dodge a DIFFERENT bug (stale evidence
re-firing the same verdict for up to 600s after the real hit). In copying the
raw-feature read, it copied half of pipeline.py's condition but not the other half --
"and not is_safe" was never carried over, because is_safe was never even passed into
evaluate() at all. Every single safe_ips device touching the honeypot for a benign
reason therefore diverged shadow CRITICAL, live BENIGN, forever.

Phase 64 flipped this check LIVE (features["zeek_honeypot_hits"] + is_safe now drive
the real `state`/`explanation` directly). REMOVED (2026-09-07, Workstream 1 of
V13_FULL_ARCHITECTURE_SHIFT_PLAN.md): the shadow computation itself (shadow_state/
shadow_changed) was deleted from decision_engine.py once v13 became the live default
engine, leaving v-current's evaluate() with no live path left to ever flip a shadow
finding into. This file now asserts directly against the LIVE state/explanation the
fix actually produces -- the same guarantee, with no shadow_* fields left to check
against.

Sections:
  B. THE FIX: is_safe=True, feature present -> does NOT produce a live CRITICAL
     honeypot verdict
  C. REGRESSION GUARD: is_safe=False, same feature -> still correctly fires live
     CRITICAL / "Internal Honeypot Accessed" (the fix narrows the exemption, it
     doesn't disable the check itself)
  D. REGRESSION GUARD: is_safe defaults to False when omitted (every existing caller
     that hasn't been updated -- tests, regression_tester.py -- is unaffected)
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
# Section B: THE FIX -- a safe_ips device does not trip the live honeypot hard-stop
# ═══════════════════════════════════════════════════════════════════════════════════
result_safe = de.evaluate(empty_ev_store, rep, features=honeypot_features, is_safe=True)
check("THE FIX: a safe_ips device with zeek_honeypot_hits>0 does NOT get live "
      "CRITICAL / 'Internal Honeypot Accessed' -- this is the exact home-router shape "
      "that produced 51 divergences in one live session before this fix",
      result_safe["state"] == "BENIGN",
      f"got state={result_safe['state']!r}, explanation={result_safe['explanation']!r}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: REGRESSION GUARD -- a genuinely non-exempt device still trips it
# ═══════════════════════════════════════════════════════════════════════════════════
result_unsafe = de.evaluate(empty_ev_store, rep, features=honeypot_features, is_safe=False)
check("REGRESSION GUARD: a device that is NOT safe_ips-exempt, same raw honeypot hit, "
      "still correctly fires live CRITICAL / 'Internal Honeypot Accessed' -- the fix "
      "narrows the exemption, it doesn't disable the Gap-3 check itself",
      result_unsafe["state"] == "CRITICAL"
      and result_unsafe["explanation"] == "Internal Honeypot Accessed",
      f"got state={result_unsafe['state']!r}, explanation={result_unsafe['explanation']!r}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: REGRESSION GUARD -- is_safe defaults to False (every existing, un-updated
# caller -- tests, regression_tester.py, shadow_backtest.py -- keeps working exactly
# as before this fix)
# ═══════════════════════════════════════════════════════════════════════════════════
result_default = de.evaluate(empty_ev_store, rep, features=honeypot_features)
check("REGRESSION GUARD: omitting is_safe entirely (every existing caller that hasn't "
      "been updated) defaults to False -- behavior for those callers is byte-identical "
      "to before this fix",
      result_default["state"] == result_unsafe["state"]
      and result_default["explanation"] == result_unsafe["explanation"],
      f"got {result_default['state']!r}/{result_default['explanation']!r} "
      f"vs {result_unsafe['state']!r}/{result_unsafe['explanation']!r}")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 47 honeypot/safe_ips checks PASSED.")
