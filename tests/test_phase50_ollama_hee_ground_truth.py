"""
Standalone runtime test for Phase 50's surviving half: pipeline.py's alert_payload
persisting the hee_* fields (hee_hypotheses/hee_independent_sources/hee_decision_path/
hee_evidence_families) from the real decision/active_evidence values each cycle.

Original motivation (Phase 50, 2026-08-xx): scripts/ollama_soc.py's batch SOC review
never consulted the deterministic HypothesisEngine/DecisionEngine at all -- it
reconstructed a single ad-hoc `Evidence(type="reputation")` item from raw ti/vt/abuse
risk features and let an LLM's free-text paragraph be graded by a 2-rule
DeterministicValidator with no concept of evidence families or independent-source
corroboration. The fix made pipeline.py persist the SAME hypothesis-competition result
it already computes onto the published ids_alert payload, for any Layer-3 reviewer to
read back as ground truth.

v16 NOTE: this file originally also covered (Sections A/B) intelligence/ai_soc.py's
own DeterministicValidator ground-truth rejection and scripts/ollama_soc.py's wiring
that read these hee_* fields back. Both files were retired in the v16 cleanup; the
equivalent ground-truth rejection on the surviving validator
(argus/llm_review/validator.py, which reads the hee_* concept via its own
build_ground_truth()) is covered by tests/test_argus_llm_review_validator.py. The
hee_* fields themselves are NOT ollama_soc.py-specific -- they're also read by the
console/humanize.py and other alert-display consumers -- so Section C (pipeline.py's
own persistence of them) remains below regardless of which Layer-3 reviewer reads them.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase50_ollama_hee_ground_truth.py`

Sections:
  C. Source-level checks: pipeline.py's alert_payload actually persists all four hee_*
     fields from the real `decision`/`active_evidence` values, not hardcoded stand-ins
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


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: source-level checks against the real pipeline.py wiring
# ═══════════════════════════════════════════════════════════════════════════════════
_pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")

check("alert_payload persists hee_hypotheses FROM the real `decision` dict decision_engine.py "
      "returned this cycle (not a hardcoded stand-in)",
      '"hee_hypotheses": decision.get("hypotheses", {})' in _pipeline_src)
check("alert_payload persists hee_independent_sources FROM the real `decision` dict",
      '"hee_independent_sources": decision.get("independent_sources", 0)' in _pipeline_src)
check("alert_payload persists hee_decision_path FROM the real `decision` dict",
      '"hee_decision_path": decision.get("decision_path", "")' in _pipeline_src)
check("alert_payload persists hee_evidence_families derived FROM the real active_evidence "
      "list this cycle actually used to reach its verdict (not a static/empty list)",
      "ev.independence_group for ev in active_evidence if ev.independence_group" in _pipeline_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 50 ollama-HEE-ground-truth checks PASSED.")
