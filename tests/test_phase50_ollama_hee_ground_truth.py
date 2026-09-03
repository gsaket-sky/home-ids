"""
Standalone runtime test for Phase 50: ollama_soc.py's batch SOC review never consulted
the deterministic HypothesisEngine/DecisionEngine at all -- it reconstructed a single
ad-hoc `Evidence(type="reputation")` item from raw ti/vt/abuse risk features and let an
LLM's free-text paragraph be graded by a 2-rule DeterministicValidator (bare IOC>=4.0
veto, and a "telemetry"-substring veto) with no concept of evidence families or
independent-source corroboration. That's why a live SOC digest showed reasoning like
"TI=0, VT=0, AbuseIPDB=0 -> low likelihood of malicious activity" reaching an autonomous
immunize action, even though decision_engine.py already treats unconfirmed reputation as
NEUTRAL (tier 3), not benign, and already requires >=2 independent evidence families
before it will call anything HIGH -- that correct logic just never reached this path.

The fix: pipeline.py now persists the SAME hypothesis-competition result
(decision["hypotheses"]/["independent_sources"]/["decision_path"]) it already computes
onto the published ids_alert payload (hee_hypotheses/hee_independent_sources/
hee_decision_path/hee_evidence_families). ollama_soc.py reads it back, strips it from
what the LLM actually sees (verdict-shaped, same reasoning as risk/signature/factors
already being stripped), and DeterministicValidator.validate() now rejects an LLM
"benign" verdict outright when this alert's ORIGINAL deterministic verdict already
corroborated an attack hypothesis across >=2 independent families (or a hard-stop /
confirmed-IOC path) -- the actual "AI proposes, deterministic code disposes" gate.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase50_ollama_hee_ground_truth.py`

Sections:
  A. DeterministicValidator.validate() -- ground_truth rejection for every
     _STRONG_ATTACK_DECISION_PATHS value, acceptance for weak/neutral paths, and
     backward compatibility (ground_truth=None / absent behaves exactly as before)
  B. Source-level checks: ollama_soc.py actually strips the new hee_* fields before the
     LLM prompt, actually threads ground_truth into the real validate() call (not a
     second, drifting copy), and the report surfaces the original finding
  C. Source-level checks: pipeline.py's alert_payload actually persists all four hee_*
     fields from the real `decision`/`active_evidence` values, not hardcoded stand-ins
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


from intelligence.ai_soc import DeterministicValidator, _STRONG_ATTACK_DECISION_PATHS

validator = DeterministicValidator()

BENIGN_REC = {
    "classification": "benign", "reason": "routine device chatter",
    "recommended_action": "suppress",
    # PHASE 51 (structured evidence contract, added after this file): a non-empty
    # supporting_evidence is now a separate, unconditional requirement for any "benign"
    # verdict -- see test_phase51_ollama_structured_contract.py for THAT check in
    # isolation. Included here so this file keeps testing ONLY the Phase 50 ground_truth
    # gate in isolation, unaffected by the later Phase 51 requirement.
    "supporting_evidence": ["destination matches this device's known recurring pattern"],
}

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: DeterministicValidator ground-truth rejection
# ═══════════════════════════════════════════════════════════════════════════════════

check("REGRESSION GUARD: the four decision_path values this fix targets are exactly "
      "the ones decision_engine.py actually returns for a corroborated attack "
      "conclusion (hard_stop / tier5_confirmed / tier5_corroborated / hypothesis_high)",
      _STRONG_ATTACK_DECISION_PATHS == frozenset({
          "hard_stop", "tier5_confirmed", "tier5_corroborated", "hypothesis_high"
      }),
      f"got {_STRONG_ATTACK_DECISION_PATHS}")

for path in sorted(_STRONG_ATTACK_DECISION_PATHS):
    gt = {
        "hypotheses": {"attack": {"name": "NETWORK_INTRUSION", "score": 4.0},
                        "benign": {"name": "UNKNOWN_BENIGN", "score": 0.0}},
        "independent_sources": 2,
        "decision_path": path,
    }
    check(f"benign+suppress verdict is REJECTED when this alert's original verdict "
          f"was decision_path='{path}' (a corroborated attack finding)",
          validator.validate(dict(BENIGN_REC), [], original_risk=8.0, ground_truth=gt) is False)

for path in ("benign", "tier4_unconfirmed", "hypothesis_suspicious", "ml_anomaly", ""):
    gt = {
        "hypotheses": {"attack": {"name": "NETWORK_INTRUSION", "score": 2.0},
                        "benign": {"name": "LOCAL_DEVICE_DISCOVERY", "score": 2.5}},
        "independent_sources": 1,
        "decision_path": path,
    }
    check(f"benign+suppress verdict is ACCEPTED when this alert's original verdict was "
          f"the weak/neutral decision_path='{path or '(empty)'}' -- ground-truth check "
          f"must not reject every benign verdict indiscriminately",
          validator.validate(dict(BENIGN_REC), [], original_risk=1.0, ground_truth=gt) is True)

check("BACKWARD COMPAT: ground_truth=None (the default -- every pre-Phase-50 caller, "
      "and every alert published before this existed) behaves exactly as before -- "
      "a benign verdict with no bad-reputation/IOC evidence still passes",
      validator.validate(dict(BENIGN_REC), []) is True)

check("BACKWARD COMPAT: an EMPTY ground_truth dict (alert published before hee_* "
      "fields existed, ollama_soc.py's .get(..., {}) defaults) behaves the same as "
      "ground_truth=None -- decision_path='' is not in the strong-path set",
      validator.validate(dict(BENIGN_REC), [], ground_truth={
          "hypotheses": {}, "independent_sources": 0, "decision_path": "",
      }) is True)

check("REGRESSION GUARD: the pre-existing hard IOC>=4.0 veto still fires independently "
      "of ground_truth (a genuinely poisoned Evidence list rejects benign even with a "
      "weak/absent ground_truth)",
      validator.validate(dict(BENIGN_REC), [__import__("intelligence.hypotheses.evidence",
          fromlist=["Evidence"]).Evidence(type="reputation", source="ti", timestamp=0,
          device="d", value=4.5, independence_group="reputation")]) is False)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: source-level checks against the real ollama_soc.py wiring
# ═══════════════════════════════════════════════════════════════════════════════════
_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")

check("the 4 new hee_* fields are stripped from what the LLM prompt actually sees "
      "(_VERDICT_SHAPED_FIELDS) -- same treatment as risk/signature/factors, since "
      "they encode this system's OWN prior verdict, not a raw observation",
      all(f'"{f}"' in _soc_src.split("_VERDICT_SHAPED_FIELDS = frozenset({", 1)[1].split("})", 1)[0]
          for f in ("hee_hypotheses", "hee_independent_sources", "hee_decision_path", "hee_evidence_families")))

check("main() actually threads ground_truth= into the real validator.validate() call "
      "(not a second, drifting reimplementation)",
      "validator.validate(response_json, ev_store, original_risk=risk, ground_truth=ground_truth)" in _soc_src)

check("ground_truth is built FROM the representative alert's own hee_* fields (reads "
      "back what pipeline.py persisted), not hardcoded/invented locally",
      'representative.get("hee_hypotheses"' in _soc_src
      and 'representative.get("hee_independent_sources"' in _soc_src
      and 'representative.get("hee_decision_path"' in _soc_src)

check("the .md report surfaces the original HEE finding by name (attack/benign "
      "hypothesis names + family count), not just a bare validator pass/fail line",
      "Original HEE finding" in _soc_src and "independent evidence famil" in _soc_src)

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
