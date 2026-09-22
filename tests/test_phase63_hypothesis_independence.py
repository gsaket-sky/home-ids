"""
Standalone runtime test for Phase 63 (Gap 6 items 3 & 4/5 follow-up, third-party HEE
review): closes the two structurally-incomplete items found while auditing Gap 6 a
second time --

  (3) Evidence relevance scoping only covered 2 of 9 attack hypotheses
      (DNSTunnelingHypothesis, NetworkIntrusionHypothesis). The other 7 (DGA,
      Exfiltration, Beaconing, DNS-Tunneling-V2, ConnectionAbuse, DNSEvasion,
      Suricata) got no relevance breakdown in the Ollama prompt/report at all.
      hypotheses/engine.py now declares RELEVANT_EVIDENCE_TYPES for all 9 classes and
      HYPOTHESIS_RELEVANT_EVIDENCE_TYPES registers all 13 name variants (including
      ConnectionAbuseHypothesis's 3 dynamic names and DNSEvasionHypothesis's 3).

  (4) Nothing forced the LLM to independently clear every plausible hypothesis before
      concluding benign -- the deterministic engine already does this correctly
      (HypothesisEngine.evaluate_all() scores every attack hypothesis independently
      and takes the max), but the LLM prompt asked for exactly one `hypothesis` name,
      so it could generalize "this evidence weakens hypothesis A" into "therefore
      benign overall" without checking B/C/D.

v16 NOTE: this file originally also covered (Sections B/C/D) scripts/ollama_soc.py's
_candidate_alternate_hypotheses()/_apply_confidence_calibration() and intelligence/
ai_soc.py's DeterministicValidator candidate-hypotheses check -- all three retired in
the v16 cleanup (ollama_soc.py, ai_soc.py, and confidence_calibration.py). The
surviving argus/llm_review/validator.py has equivalent candidate_hypotheses
computation and validator rejection logic, covered by
tests/test_argus_llm_review_validator.py ("build_ground_truth computes
candidate_hypotheses..." / "a 'benign' verdict is rejected when it doesn't address
every candidate hypothesis..."). Only Section A (still-live hypotheses/engine.py
registry) remains below.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase63_hypothesis_independence.py`

Sections:
  A. hypotheses/engine.py -- RELEVANT_EVIDENCE_TYPES declared for all 9 attack
     hypothesis classes; registry has all 13 name entries; alias groups share the
     SAME frozenset object (identity, not just equality)
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


from intelligence.hypotheses.engine import (
    HYPOTHESIS_RELEVANT_EVIDENCE_TYPES, DNSTunnelingHypothesis, NetworkIntrusionHypothesis,
    DGAHypothesis, ExfiltrationHypothesis, BeaconingHypothesis, DNSTunnelingV2Hypothesis,
    ConnectionAbuseHypothesis, DNSEvasionHypothesis, SuricataSignatureHypothesis,
)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: hypotheses/engine.py registry, all 9 classes
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: RELEVANT_EVIDENCE_TYPES coverage, all 9 attack hypotheses ---")

_ALL_ATTACK_CLASSES = [
    DNSTunnelingHypothesis, NetworkIntrusionHypothesis, DGAHypothesis, ExfiltrationHypothesis,
    BeaconingHypothesis, DNSTunnelingV2Hypothesis, ConnectionAbuseHypothesis,
    DNSEvasionHypothesis, SuricataSignatureHypothesis,
]
check("all 9 attack hypothesis classes declare a non-empty RELEVANT_EVIDENCE_TYPES "
      "(none silently left on the base class's empty default)",
      all(cls.RELEVANT_EVIDENCE_TYPES for cls in _ALL_ATTACK_CLASSES))

check("registry has all 14 name entries (9 classes, 5 of which have 1 extra alias "
      "each: NetworkIntrusion x2, ConnectionAbuse x3, DNSEvasion x3, "
      "the rest x1 -- 2+3+3+1+1+1+1+1+1 = 14)",
      len(HYPOTHESIS_RELEVANT_EVIDENCE_TYPES) == 14)

_expected_names = {
    "DNS_TUNNELING", "NETWORK_INTRUSION", "LATERAL_MOVEMENT", "DGA_BOTNET_C2",
    "DATA_EXFILTRATION", "C2_BEACONING", "DNS_COVERT_TUNNELING", "CONNECTION_ABUSE",
    "PORT_SCAN", "INTERNAL_RECONNAISSANCE", "DNS_POLICY_BYPASS", "DNS_EVASION",
    "DNS_ATTRIBUTION_GAP", "SIGNATURE_MATCHED_THREAT",
}
check("registry keys match the expected full name set exactly",
      set(HYPOTHESIS_RELEVANT_EVIDENCE_TYPES.keys()) == _expected_names)

check("ConnectionAbuseHypothesis's 3 dynamic names all point at the SAME frozenset "
      "object (identity, not just equal value) -- _candidate_alternate_hypotheses() "
      "dedup relies on this",
      HYPOTHESIS_RELEVANT_EVIDENCE_TYPES["CONNECTION_ABUSE"]
      is HYPOTHESIS_RELEVANT_EVIDENCE_TYPES["PORT_SCAN"]
      is HYPOTHESIS_RELEVANT_EVIDENCE_TYPES["INTERNAL_RECONNAISSANCE"])

check("DNSEvasionHypothesis's 3 dynamic names all point at the SAME frozenset object",
      HYPOTHESIS_RELEVANT_EVIDENCE_TYPES["DNS_POLICY_BYPASS"]
      is HYPOTHESIS_RELEVANT_EVIDENCE_TYPES["DNS_EVASION"]
      is HYPOTHESIS_RELEVANT_EVIDENCE_TYPES["DNS_ATTRIBUTION_GAP"])

check("DNSEvasionHypothesis's set is deliberately just the required trigger type "
      "(its own corroboration is 'any OTHER evidence type present', not a fixed set "
      "-- see its own class docstring for why listing that here would be dishonest)",
      DNSEvasionHypothesis.RELEVANT_EVIDENCE_TYPES == frozenset({"dns_evasion_anomaly"}))

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 63 hypothesis-independence checks PASSED.")
