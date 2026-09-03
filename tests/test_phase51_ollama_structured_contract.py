"""
Standalone runtime test for Phase 51: ollama_soc.py's LLM response schema used to be
one free-text paragraph -- {classification, confidence, reason, recommended_action} --
with nothing forcing the model to name a specific hypothesis or list what it's actually
basing a "benign" verdict on. A model could (and, per the live SOC digest that started
this whole thread, routinely did) write "TI=0/VT=0/AbuseIPDB=0 -> low likelihood of
malicious" as its entire justification -- the ABSENCE of a bad signal, not evidence of a
good one -- and nothing rejected it.

The fix: the schema now asks for `hypothesis` (a specific named explanation, in this
system's own hypotheses/engine.py vocabulary where it fits), `supporting_evidence[]`,
`contradicting_evidence[]`, and `missing_evidence[]` -- the same required/supporting/
contradicting shape every Hypothesis subclass already reasons with internally.
ai_soc.py's DeterministicValidator now rejects a "benign" verdict outright if
supporting_evidence is empty (an assertion, not a finding), and rejects one that lists
its own contradicting_evidence but still recommends suppressing the alert anyway
(self-contradictory). `classification` itself is UNCHANGED (still benign|malicious) --
every branch in ollama_soc.py's main() already keys on those two exact strings; see
Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's Gap 4 entry for why a 3-way enum
rename was deliberately out of scope for this phase.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase51_ollama_structured_contract.py`

Sections:
  A. DeterministicValidator -- supporting_evidence requirement (empty/missing rejected,
     present accepted) and the contradicting_evidence + recommended_action=="suppress"
     self-consistency rejection (only fires for suppress, not for e.g. "none")
  B. Source-level checks: the real system_prompt actually asks for all 5 new fields,
     cache write/cache-hit reconstruction actually carry them (not silently dropped on
     a cache round-trip), and the report actually surfaces hypothesis + evidence lists
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


from intelligence.ai_soc import DeterministicValidator

validator = DeterministicValidator()

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: DeterministicValidator -- structured-contract requirements
# ═══════════════════════════════════════════════════════════════════════════════════

check("a 'benign' verdict with NO supporting_evidence key at all is REJECTED",
      validator.validate({
          "classification": "benign", "reason": "routine chatter", "recommended_action": "suppress",
      }, []) is False)

check("a 'benign' verdict with an EMPTY supporting_evidence list is REJECTED",
      validator.validate({
          "classification": "benign", "reason": "routine chatter", "recommended_action": "suppress",
          "supporting_evidence": [],
      }, []) is False)

check("a 'benign' verdict whose supporting_evidence is only blank/whitespace strings is "
      "REJECTED (not just 'the key is present')",
      validator.validate({
          "classification": "benign", "reason": "routine chatter", "recommended_action": "suppress",
          "supporting_evidence": ["   ", ""],
      }, []) is False)

check("a 'benign' verdict WITH real supporting_evidence is ACCEPTED (all else equal)",
      validator.validate({
          "classification": "benign", "reason": "routine chatter", "recommended_action": "suppress",
          "supporting_evidence": ["destination is this device's known recurring vendor endpoint"],
      }, []) is True)

check("a 'malicious' verdict is UNAFFECTED by the supporting_evidence requirement -- "
      "this check only applies to classification=='benign'",
      validator.validate({
          "classification": "malicious", "reason": "beaconing to known C2", "recommended_action": "block",
      }, []) is True)

check("a 'benign' verdict that lists its OWN contradicting_evidence but still "
      "recommends 'suppress' is REJECTED (self-contradictory)",
      validator.validate({
          "classification": "benign", "reason": "probably telemetry", "recommended_action": "suppress",
          "supporting_evidence": ["looks like vendor telemetry"],
          "contradicting_evidence": ["destination has no prior history with this device"],
      }, []) is False)

check("REGRESSION GUARD: contradicting_evidence present but recommended_action != "
      "'suppress' (e.g. 'none') is NOT rejected by the self-consistency check -- a model "
      "that's honestly uncertain and recommends no action is not being inconsistent",
      validator.validate({
          "classification": "benign", "reason": "uncertain", "recommended_action": "none",
          "supporting_evidence": ["some indication of routine chatter"],
          "contradicting_evidence": ["destination has no prior history with this device"],
      }, []) is True)

check("REGRESSION GUARD: an empty contradicting_evidence list does not trip the "
      "self-consistency check even with recommended_action=='suppress'",
      validator.validate({
          "classification": "benign", "reason": "routine chatter", "recommended_action": "suppress",
          "supporting_evidence": ["matches known pattern"],
          "contradicting_evidence": [],
      }, []) is True)

check("REGRESSION GUARD: the pre-existing hard IOC>=4.0 veto is checked BEFORE the new "
      "supporting_evidence requirement -- both independently reject, order doesn't "
      "matter for the outcome, but confirms the new check didn't replace the old one",
      validator.validate({
          "classification": "benign", "reason": "probably fine", "recommended_action": "suppress",
          "supporting_evidence": ["looks routine"],
      }, [__import__("intelligence.hypotheses.evidence", fromlist=["Evidence"]).Evidence(
          type="reputation", source="ti", timestamp=0, device="d", value=4.5,
          independence_group="reputation")]) is False)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: source-level checks against the real ollama_soc.py wiring
# ═══════════════════════════════════════════════════════════════════════════════════
_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")

check("system_prompt actually asks the model for all 5 new structured-contract fields "
      "(hypothesis, supporting_evidence, contradicting_evidence, missing_evidence, "
      "ttl_seconds), not just the original 4",
      all(f'\\"{f}\\"' in _soc_src for f in (
          "hypothesis", "supporting_evidence", "contradicting_evidence",
          "missing_evidence", "ttl_seconds",
      )))

check("system_prompt explicitly tells the model absence of a TI/VT/AbuseIPDB hit is "
      "NOT supporting evidence on its own -- the exact failure mode from the live SOC "
      "digest that prompted this whole fix",
      "NOT supporting evidence for benign" in _soc_src or "is NOT supporting evidence" in _soc_src)

check("the fresh-query cache write persists all 5 new fields (not silently dropped "
      "before the next run's cache-hit reads them back)",
      all(f'"{f}":' in _soc_src.split('cache[key] = {', 1)[1].split('\n\n', 1)[0]
          for f in ("hypothesis", "supporting_evidence", "contradicting_evidence",
                     "missing_evidence", "ttl_seconds")))

check("the cache-HIT branch reconstructs response_json with all 5 new fields from the "
      "cache entry (a cache round-trip doesn't silently lose the structured contract)",
      all(f'"{f}": cached.get("{f}"' in _soc_src for f in (
          "hypothesis", "supporting_evidence", "contradicting_evidence", "missing_evidence",
      )) and '"ttl_seconds": cached.get("ttl_seconds")' in _soc_src)

check("the .md report surfaces the LLM's own named hypothesis, not just the bare "
      "benign/malicious classification",
      "llm_hypothesis" in _soc_src and "hypothesis: `" in _soc_src)

check("the .md report surfaces supporting/contradicting/missing evidence when present",
      "Supporting evidence" in _soc_src and "Contradicting evidence" in _soc_src
      and "Missing evidence" in _soc_src)

check("REGRESSION GUARD: classification itself is UNCHANGED (still benign|malicious) -- "
      "main()'s existing branches (immunize/confirmed_threat) still key on those exact "
      "lowercase strings, confirming this phase deliberately did not rename the enum",
      "response_json.get('classification') == 'benign'" in _soc_src
      and "response_json.get('classification') == 'malicious'" in _soc_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 51 ollama-structured-contract checks PASSED.")
