"""
Standalone runtime test for Phase 49: ollama_soc.py's multi-device withhold guard had
no exit condition -- a pattern that withheld once withheld forever. Not part of the
pytest suite -- run directly: `python3 tests/test_phase49_ollama_withhold_streak.py`.

Context (2026-09-01): a live operator report asked "is Ollama ever completing all the
alerts or is it just piling up." A live audit of state/ollama_analysis_cache.json found
165 distinct patterns sitting in withheld_history, some withheld 15-18 times over 4.6
days straight, 100% NETWORK_INTRUSION (this network's single most common signature, so
spread>=3 is essentially always true for it) and 100% still classified benign at high
confidence every single time -- because the guard re-checks spread>=threshold every run
forever, with nothing that ever lets a pattern resolve on its own.

A second, more fundamental bug was found investigating the fix: the normal (non-guarded)
benign+suppress immunize branch was a SILENT NO-OP whenever the alert's target had no
resolved domain (an IP-only NETWORK_INTRUSION target -- the majority shape of what was
piling up). The outer `if target_domain:` gate meant neither immunize NOR skip ever ran,
so action_taken never got set -- meaning an IP-only pattern could never resolve even on
a first-time, low-spread pass that never touched the multi-device guard at all.

Sections:
  A. should_still_withhold() -- the extracted pure decision function -- across the
     guard-satisfied/streak-fresh, guard-satisfied/streak-exhausted, and
     guard-not-satisfied cases
  B. REGRESSION GUARD: spread just at/above the guard threshold with a fresh streak
     still withholds (the original Phase-21D fix -- a real DGA-style cross-device
     campaign must still be caught)
  C. Source-level checks: the real main() wiring in ollama_soc.py actually calls
     should_still_withhold() (not a reimplemented copy that could drift), the
     IP-only-target branch is no longer a silent no-op, and the streak_note wiring
     exists so an auto-resolved action is logged distinctly from an immediate one
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


from ollama_soc import should_still_withhold, DEFAULT_MULTI_DEVICE_SUPPRESS_GUARD, DEFAULT_MULTI_DEVICE_WITHHOLD_AUTO_RESOLVE_AFTER

GUARD = DEFAULT_MULTI_DEVICE_SUPPRESS_GUARD          # 3
AUTO_RESOLVE = DEFAULT_MULTI_DEVICE_WITHHOLD_AUTO_RESOLVE_AFTER  # 10


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: should_still_withhold() across its three real states
# ═══════════════════════════════════════════════════════════════════════════════════
check("guard satisfied (spread >= threshold), fresh streak (0 prior withholds) -> "
      "still withholds",
      should_still_withhold(14, GUARD, 0, AUTO_RESOLVE) is True)
check("THE CORE FIX: guard satisfied, streak exhausted (existing count == threshold) "
      "-> no longer withholds -- this is the exact live shape (spread=14, withheld "
      "15-18x over 4.6 days) that was piling up forever before this fix",
      should_still_withhold(14, GUARD, AUTO_RESOLVE, AUTO_RESOLVE) is False)
check("streak exhausted even further past the threshold (e.g. 18 prior withholds, "
      "matching the live report's worst case) -> still resolves, not stuck again",
      should_still_withhold(14, GUARD, 18, AUTO_RESOLVE) is False)
check("guard NOT satisfied (spread below threshold) -> never withholds regardless of "
      "streak state (nothing to resolve -- this case takes the normal same-day path)",
      should_still_withhold(2, GUARD, 0, AUTO_RESOLVE) is False)
check("guard not satisfied even with a long-running streak -> still False (spread, "
      "not streak, is the primary gate)",
      should_still_withhold(1, GUARD, 5, AUTO_RESOLVE) is False)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: REGRESSION GUARD -- the ORIGINAL Phase-21D DGA-campaign catch is untouched
# ═══════════════════════════════════════════════════════════════════════════════════
check("REGRESSION GUARD: spread exactly at the guard threshold, brand-new pattern "
      "(this run's own first check, count=0) still withholds -- the original "
      "cross-device-campaign catch this guard exists for is not weakened",
      should_still_withhold(GUARD, GUARD, 0, AUTO_RESOLVE) is True)
check("REGRESSION GUARD: one below the auto-resolve threshold still withholds -- the "
      "streak must be FULLY exhausted, not just close",
      should_still_withhold(14, GUARD, AUTO_RESOLVE - 1, AUTO_RESOLVE) is True)
check("REGRESSION GUARD: default constants match the documented live-audit values "
      "(guard=3, auto-resolve after 10)",
      GUARD == 3 and AUTO_RESOLVE == 10, f"got guard={GUARD}, auto_resolve={AUTO_RESOLVE}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: source-level checks against the real ollama_soc.py wiring
# ═══════════════════════════════════════════════════════════════════════════════════
_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")

check("REGRESSION GUARD: main()'s withhold condition actually calls "
      "should_still_withhold() -- not a reimplemented copy of the spread>=guard check "
      "that could silently drift from the tested function",
      _src.count("should_still_withhold(") >= 3,  # def + streak_exhausted calc + the if-condition
      f"expected at least 3 occurrences (definition + 2 call sites), found {_src.count('should_still_withhold(')}")

check("THE CORE FIX (IP-only no-op): the benign/suppress branch's no-domain path no "
      "longer does nothing -- it now calls _apply_sigma_shift with a TUNE_DOWN "
      "direction and marks action_taken, so an IP-only target (the majority shape of "
      "what was piling up) can actually resolve",
      # PHASE 57: cache writes now go through pcache_key (evidence fingerprint +
      # validator-schema version), not the bare grouping key -- see
      # test_phase57_evidence_fingerprint.py for that change's own coverage.
      'direction="TUNE_DOWN"' in _src and 'cache[pcache_key]["action_taken"] = True' in _src)

check("REGRESSION GUARD: the no-domain fallback is still gated behind the SAME "
      "benign+suppress+not-already-actioned condition as the domain path (an `else:` "
      "off the same `if target_domain and target_domain != \"unknown\":` check), not "
      "a new unconditional branch that could fire for malicious/invalid verdicts too",
      'else:\n                # BUGFIX (2026-09-01, live report' in _src)

check("streak_note (the 'auto-resolved after N consistent withholds' wording) is wired "
      "into both the domain-immunize and no-domain fallback outcome_detail strings, "
      "not just one of them",
      _src.count("streak_note") >= 4,  # assignment + domain path (report+outcome_detail) + no-domain path (report+outcome_detail)
      f"expected at least 4 occurrences, found {_src.count('streak_note')}")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 49 ollama-withhold-streak checks PASSED.")
