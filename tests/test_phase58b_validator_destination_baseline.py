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

Three plumbing pieces, each reusing EXISTING infrastructure rather than inventing a
parallel one:
  1. pipeline.py's alert_payload gains hee_rep_tier -- the SAME rep_vector already
     computed for and consumed by decision_engine.evaluate() this cycle, not a
     separately re-derived ReputationClassifier.classify() call that could disagree
     with what the live pipeline actually used.
  2. fp_engine.py gains a module-level FAMILIARITY_TRUST_BAR (0.6), hoisted from what
     used to be DeviceProfileBenignHypothesis's own private class attribute -- same
     single-source-of-truth treatment Phase 58 already gave
     ATTACK_SHAPED_EVIDENCE_TYPES.
  3. ollama_soc.py computes baseline_familiarity via fp_engine's EXISTING
     get_baseline_familiarity() (already populated every cycle by the live pipeline's
     record_device_baseline_observation()) and threads both it and hee_rep_tier into
     DeterministicValidator.validate().

VALIDATOR_SCHEMA_VERSION bumped 3 -> 4 (ai_soc.py).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase58b_validator_destination_baseline.py`

Sections:
  A. FAMILIARITY_TRUST_BAR -- single source of truth, same value in both
     hypotheses/engine.py and ai_soc.py/fp_engine.py
  B. DeterministicValidator.validate() -- rejects benign for an unclassified/
     unreputable destination with no learned familiarity; accepts when EITHER
     condition holds; backward-compatible when rep_tier is absent
  C. Source-level wiring -- pipeline.py persists hee_rep_tier from the same
     rep_vector decision_engine.evaluate() used; ollama_soc.py computes
     baseline_familiarity via fp_engine.get_baseline_familiarity() and threads both
     into validate(); VALIDATOR_SCHEMA_VERSION bumped
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


from intelligence.fp_engine import FAMILIARITY_TRUST_BAR
from intelligence.hypotheses.engine import DeviceProfileBenignHypothesis
from intelligence.ai_soc import DeterministicValidator, VALIDATOR_SCHEMA_VERSION


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
# Section B: DeterministicValidator.validate()
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section B: DeterministicValidator.validate() ---")

validator = DeterministicValidator()

_benign_rec = {
    "classification": "benign", "reason": "smart tv telemetry",
    "supporting_evidence": ["low query rate", "no suspicious domains"],
    "contradicting_evidence": [], "recommended_action": "suppress",
}

check("REJECTS 'benign' for an unclassified/unreputable destination (tier 4) with "
      "zero learned familiarity -- no deterministic corroboration at all, just the "
      "LLM's own device-type story",
      validator.validate(
          _benign_rec, [], ground_truth={"decision_path": "", "rep_tier": 4},
          baseline_familiarity=0.0,
      ) is False)

check("ACCEPTS 'benign' when the destination IS trusted/known infrastructure "
      "(tier 1), even with zero familiarity -- trust alone is sufficient corroboration",
      validator.validate(
          _benign_rec, [], ground_truth={"decision_path": "", "rep_tier": 1},
          baseline_familiarity=0.0,
      ) is True)

check("ACCEPTS 'benign' when the destination is untrusted (tier 4) BUT this device "
      "has real learned familiarity with it (>= FAMILIARITY_TRUST_BAR) -- familiarity "
      "alone is sufficient corroboration, matching DeviceProfileBenignHypothesis's own "
      "is_trusted_destination OR is_familiar_destination logic",
      validator.validate(
          _benign_rec, [], ground_truth={"decision_path": "", "rep_tier": 4},
          baseline_familiarity=0.8,
      ) is True)

check("REJECTS right at the boundary -- familiarity just under the bar, untrusted tier",
      validator.validate(
          _benign_rec, [], ground_truth={"decision_path": "", "rep_tier": 3},
          baseline_familiarity=0.59,
      ) is False)

check("ACCEPTS right at the boundary -- familiarity exactly at the bar",
      validator.validate(
          _benign_rec, [], ground_truth={"decision_path": "", "rep_tier": 3},
          baseline_familiarity=0.6,
      ) is True)

check("BACKWARD COMPATIBLE: rep_tier absent entirely (pre-Phase-58b alert) degrades "
      "to a no-op for this specific check -- doesn't reject solely because the field "
      "is missing, even with zero familiarity and no baseline_familiarity threaded in",
      validator.validate(
          _benign_rec, [], ground_truth={"decision_path": ""},
      ) is True)

check("BACKWARD COMPATIBLE: ground_truth=None entirely still works",
      validator.validate(_benign_rec, [], ground_truth=None) is True)

check("does NOT affect 'malicious' classifications",
      validator.validate(
          {"classification": "malicious", "reason": "confirmed", "recommended_action": "block"},
          [], ground_truth={"decision_path": "", "rep_tier": 4}, baseline_familiarity=0.0,
      ) is True)

check("REGRESSION: Phase 58's attack-shaped-evidence check still fires independently "
      "of this new check (both are real gates, not one replacing the other) -- trusted "
      "tier alone doesn't rescue a verdict against genuine attack-shaped evidence",
      validator.validate(
          _benign_rec, [],
          ground_truth={"decision_path": "", "rep_tier": 1, "evidence_types": ["arp_sweep"]},
          baseline_familiarity=1.0,
      ) is False)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: source-level wiring
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section C: source-level wiring ---")

_pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")
check("pipeline.py persists hee_rep_tier from rep_vector.tier (the same reputation "
      "vector already computed for decision_engine.evaluate() this cycle)",
      '"hee_rep_tier": rep_vector.tier' in _pipeline_src)

_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")
check("ollama_soc.py strips hee_rep_tier from the LLM prompt (_VERDICT_SHAPED_FIELDS)",
      '"hee_rep_tier"' in _soc_src.split("_VERDICT_SHAPED_FIELDS = frozenset({", 1)[1].split("})", 1)[0])

check("ollama_soc.py threads hee_rep_tier into ground_truth as 'rep_tier'",
      '"rep_tier": representative.get("hee_rep_tier")' in _soc_src)

check("ollama_soc.py computes baseline_familiarity via fp_engine's EXISTING "
      "get_baseline_familiarity() -- not a second, parallel familiarity mechanism",
      "fp_engine.get_baseline_familiarity(" in _soc_src)

check("baseline_familiarity is actually threaded into the validate() call",
      "baseline_familiarity=baseline_familiarity" in _soc_src)

_ai_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "intelligence" / "ai_soc.py").read_text(encoding="utf-8")
# PHASE 63: >=4 rather than ==4, same reasoning as Phase 58's own version check --
# a later phase (63) legitimately bumps it further -- see
# test_phase63_hypothesis_independence.py for that one's own coverage.
check("VALIDATOR_SCHEMA_VERSION was bumped again for this change",
      VALIDATOR_SCHEMA_VERSION >= 4)

check("FAMILIARITY_TRUST_BAR is imported from fp_engine.py, not redefined locally",
      "from intelligence.fp_engine import FAMILIARITY_TRUST_BAR" in _ai_soc_src)

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
