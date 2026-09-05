"""
Standalone runtime test for Phase 65 (HEE_ROADMAP.md item 1, structured
required/supporting/contradicting checklist per hypothesis): every Hypothesis subclass
already computes `required_satisfied`/`strong_score`/`contradicting_score` internally
(each `evaluate()` call resets then sets these on `self`) but never exposed them past
the bare numeric score used for hypothesis competition -- an operator (or a future
debugging session) had no direct, at-a-glance answer to "why did this hypothesis
fire/not fire" without reading `evaluate()`'s own source.

The fix: `HypothesisEngine.evaluate_all()` (hypotheses/engine.py) now attaches a
`checklist` dict to its `"attack"` result, read off the winning hypothesis instance
right after the scoring loop (instance state is never shared between hypothesis
objects, so this is the exact live state that hypothesis's own `evaluate()` call
computed, not a lossy reconstruction). `pipeline.py` needed NO changes -- it already
copies the whole `hee_hypotheses` dict onto `alert_payload` verbatim (Gap 4's existing
"no transformation" persistence pattern), so the new key rides along automatically.
`ollama_soc.py` gained `_hypothesis_checklist_line()`, rendered into the `.md` report
right next to the existing "Evidence relevance" line.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase65_hypothesis_checklist.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.hypotheses.evidence import Evidence
from intelligence.hypotheses.engine import HypothesisEngine
from intelligence.reputation.classifier import ReputationVector

hyp = HypothesisEngine()


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: the checklist reflects the winning hypothesis's OWN live computation
# ═══════════════════════════════════════════════════════════════════════════════════
dga_ev = [
    Evidence(type="dns_dga_burst", source="threat_signals", timestamp=time.time(), device="dev_a",
             value=20.0, confidence=0.9, independence_group="dns_behavior"),
    Evidence(type="dns_rate", source="pihole", timestamp=time.time(), device="dev_a",
             value=150.0, confidence=0.9, independence_group="dns_behavior"),
]
result_a = hyp.evaluate_all(dga_ev, ReputationVector(domain="", tier=3))
checklist_a = result_a["attack"]["checklist"]
check("winning hypothesis is DGA_BOTNET_C2 for this evidence shape",
      result_a["attack"]["name"] == "DGA_BOTNET_C2", f"got {result_a['attack']['name']}")
check("checklist is present (not None) for a real winning hypothesis",
      checklist_a is not None, f"got {result_a['attack']}")
check("required_satisfied is True (dns_dga_burst evidence present, DGAHypothesis's own "
      "required check)",
      checklist_a is not None and checklist_a["required_satisfied"] is True, f"got {checklist_a}")
check("strong_score reflects the dns_rate>100 corroboration DGAHypothesis.evaluate() "
      "itself adds",
      checklist_a is not None and checklist_a["strong_score"] == 1.0, f"got {checklist_a}")
check("contradicting_score is 0 (tier=3, neutral, no contradiction)",
      checklist_a is not None and checklist_a["contradicting_score"] == 0.0, f"got {checklist_a}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: a tier-1/2 (trusted/known-infra) reputation context DOES populate
# contradicting_score, matching DGAHypothesis.evaluate()'s own logic
# ═══════════════════════════════════════════════════════════════════════════════════
result_b = hyp.evaluate_all(dga_ev, ReputationVector(domain="", tier=1))
checklist_b = result_b["attack"]["checklist"]
check("contradicting_score reflects a trusted-tier reputation context (tier=1)",
      checklist_b is not None and checklist_b["contradicting_score"] == 1.0, f"got {checklist_b}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: no winning attack hypothesis -> checklist is None, not a crash or a
# misleading all-zero dict
# ═══════════════════════════════════════════════════════════════════════════════════
result_c = hyp.evaluate_all([], ReputationVector(domain="", tier=3))
check("REGRESSION GUARD: an empty ev_store (no attack hypothesis wins, DIRECT_IOC_HIT "
      "fallback) leaves checklist as None -- there's no Hypothesis instance to read "
      "from, and None-means-skip is this codebase's own established contract",
      result_c["attack"]["checklist"] is None, f"got {result_c['attack']}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: ollama_soc.py's _hypothesis_checklist_line() renders correctly and
# degrades to None for pre-Phase-65 alerts / no winning hypothesis
# ═══════════════════════════════════════════════════════════════════════════════════
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts"))
from ollama_soc import _hypothesis_checklist_line

rep_with_checklist = {
    "hee_hypotheses": {
        "attack": {
            "name": "DGA_BOTNET_C2", "score": 4.0,
            "checklist": {"required_satisfied": True, "strong_score": 1.0, "contradicting_score": 0.0},
        },
    },
}
line = _hypothesis_checklist_line(rep_with_checklist)
check("renders a non-None line for a real checklist",
      line is not None, f"got {line!r}")
check("the rendered line names the hypothesis",
      line is not None and "DGA_BOTNET_C2" in line, f"got {line!r}")
check("the rendered line says the required evidence was satisfied",
      line is not None and "required evidence satisfied" in line, f"got {line!r}")
check("the rendered line includes the strong-corroboration score",
      line is not None and "strong-corroboration score=1.0" in line, f"got {line!r}")

rep_not_satisfied = {
    "hee_hypotheses": {"attack": {"name": "X", "checklist": {
        "required_satisfied": False, "strong_score": 0.0, "contradicting_score": 0.0,
    }}},
}
line_not_satisfied = _hypothesis_checklist_line(rep_not_satisfied)
check("renders 'NOT satisfied' when required_satisfied is False",
      line_not_satisfied is not None and "NOT satisfied" in line_not_satisfied,
      f"got {line_not_satisfied!r}")

check("REGRESSION GUARD: a pre-Phase-65 alert (hee_hypotheses present, no 'checklist' "
      "key at all) degrades to None, not a crash",
      _hypothesis_checklist_line({"hee_hypotheses": {"attack": {"name": "X", "score": 3.0}}}) is None)
check("REGRESSION GUARD: an alert with no hee_hypotheses key at all (pre-Phase-50) "
      "degrades to None",
      _hypothesis_checklist_line({}) is None)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 65 hypothesis-checklist checks PASSED.")
