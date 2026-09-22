"""
Standalone runtime test for Phase 58b (Gap 6 item 2, remainder): DeterministicValidator
now requires SOME deterministic corroboration before trusting a "benign" verdict --
either the destination is already-trusted/known infrastructure (reputation tier in
(0,1,2)) or this specific device has personally, repeatedly used this exact port/ASN/
domain before without incident (fp_engine's learned baseline_familiarity). Mirrors
DeviceProfileBenignHypothesis's own requirement (hypotheses/engine.py:
is_trusted_destination OR is_familiar_destination) at the ai_soc.py validator layer,
closing the same gap Phase 58's attack-shaped-evidence check closed for a different
failure mode: an LLM's free-text re-review of an already-published alert previously had
NO independent deterministic check requiring its "benign" story to actually be
supported by trust/familiarity, only structural checks on the LLM's own self-reported
lists (Phase 51) and the original decision_path (Phase 50).

Plumbing: fp_engine.py gains a module-level FAMILIARITY_TRUST_BAR (0.6), hoisted from
what used to be DeviceProfileBenignHypothesis's own private class attribute -- same
single-source-of-truth treatment Phase 58 already gave ATTACK_SHAPED_EVIDENCE_TYPES.

v16 NOTE: this file originally also covered (Section B) intelligence/ai_soc.py's own
DeterministicValidator directly, and (part of Section C) scripts/ollama_soc.py's
hee_rep_tier-stripping/baseline_familiarity-threading wiring and ai_soc.py's own
VALIDATOR_SCHEMA_VERSION bump. All three files were retired in the v16 cleanup; the
equivalent behavior on the surviving validator (argus/llm_review/validator.py) is
covered by tests/test_argus_llm_review_validator.py ("a 'benign' verdict is rejected
for an unclassified destination with no learned familiarity..." / "...IS allowed once
familiarity clears the bar" / "...allowed for an already-trusted-tier destination").
Only Section A and the pipeline.py/hypotheses-engine.py halves of Section C remain.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase58b_validator_destination_baseline.py`

Sections:
  A. FAMILIARITY_TRUST_BAR -- single source of truth, same value in both
     hypotheses/engine.py and fp_engine.py
  C. Source-level wiring -- pipeline.py persists hee_rep_tier from the same
     rep_vector decision_engine.evaluate() used; hypotheses/engine.py imports the
     shared FAMILIARITY_TRUST_BAR constant rather than a separately-defined literal
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


from intelligence.fp_engine import FAMILIARITY_TRUST_BAR
from intelligence.hypotheses.engine import DeviceProfileBenignHypothesis


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: single source of truth
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: FAMILIARITY_TRUST_BAR single source of truth ---")

check("DeviceProfileBenignHypothesis's class attribute equals the shared "
      "module-level constant from fp_engine.py",
      DeviceProfileBenignHypothesis._FAMILIARITY_TRUST_BAR == FAMILIARITY_TRUST_BAR)

check("value is the documented 0.6 (3 of 5 observations)",
      FAMILIARITY_TRUST_BAR == 0.6)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: source-level wiring
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section C: source-level wiring ---")

_pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")
check("pipeline.py persists hee_rep_tier from rep_vector.tier (the same reputation "
      "vector already computed for decision_engine.evaluate() this cycle)",
      '"hee_rep_tier": rep_vector.tier' in _pipeline_src)

_engine_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "intelligence" / "hypotheses" / "engine.py").read_text(encoding="utf-8")
check("hypotheses/engine.py also imports the shared constant rather than keeping its "
      "own separately-defined 0.6 literal",
      "from intelligence.fp_engine import FAMILIARITY_TRUST_BAR" in _engine_src
      and "_FAMILIARITY_TRUST_BAR = FAMILIARITY_TRUST_BAR" in _engine_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 58b destination/baseline-familiarity validator checks PASSED.")
