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
      benign overall" without checking B/C/D. ollama_soc.py gains
      _candidate_alternate_hypotheses() (every OTHER named hypothesis whose
      RELEVANT_EVIDENCE_TYPES overlaps this alert's own hee_evidence_types, deduped by
      underlying class), threaded into the prompt, the response schema
      (`hypotheses_ruled_out`), and ground_truth. ai_soc.py's DeterministicValidator
      rejects a "benign" verdict that doesn't address every candidate.
      VALIDATOR_SCHEMA_VERSION bumped 4 -> 5.

  (5, partial) Confidence conflation was previously a data-collection scaffold only
      (Phase 60a) -- ConfidenceCalibrator.get_calibrated() wasn't consulted by any
      decision. Rather than deferring the wiring work until a human notices real data
      exists, ollama_soc.py now consumes it directly at the one hook point the LLM's
      confidence already had zero influence over anything else: the immunization TTL
      (fp_engine.mark_false_positive()'s ttl_seconds). _apply_confidence_calibration()
      is a no-op (returns raw_ttl unchanged) until a bucket crosses
      MIN_SAMPLES_FOR_CALIBRATION real observations -- self-activating, no further
      code change required once that happens. Explicitly NOT wired into the
      persistent Ollama-response/fingerprint cache TTL (Phase 57, a different
      concept), the DeterministicValidator PASS/FAIL gate, or the malicious track
      (deliberately slower to accumulate real volume by design).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase63_hypothesis_independence.py`

Sections:
  A. hypotheses/engine.py -- RELEVANT_EVIDENCE_TYPES declared for all 9 attack
     hypothesis classes; registry has all 13 name entries; alias groups share the
     SAME frozenset object (identity, not just equality)
  B. ollama_soc.py's _candidate_alternate_hypotheses() -- overlap surfaces a real
     candidate; no overlap returns []; an uncovered hypothesis returns None; alias
     dedup (a ConnectionAbuseHypothesis-named alert overlapping only its own evidence
     types lists no candidates, not near-duplicates of its own 3 names)
  C. ai_soc.py's DeterministicValidator.validate() -- rejects a "benign" verdict with
     unaddressed candidate_hypotheses; accepts one whose hypotheses_ruled_out covers
     them; empty/absent candidate_hypotheses is a no-op (backward compatible)
  D. ollama_soc.py's _apply_confidence_calibration() -- calibrated=None is the
     "not activated yet" branch (raw_ttl unchanged, exercised until real data exists);
     raw_ttl=None stays None regardless of calibration; a calibrated value above/below
     raw confidence extends/shortens TTL by the expected clamped factor
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


from intelligence.hypotheses.engine import (
    HYPOTHESIS_RELEVANT_EVIDENCE_TYPES, DNSTunnelingHypothesis, NetworkIntrusionHypothesis,
    DGAHypothesis, ExfiltrationHypothesis, BeaconingHypothesis, DNSTunnelingV2Hypothesis,
    ConnectionAbuseHypothesis, DNSEvasionHypothesis, SuricataSignatureHypothesis,
)
from intelligence.ai_soc import DeterministicValidator, VALIDATOR_SCHEMA_VERSION
from ollama_soc import _candidate_alternate_hypotheses, _apply_confidence_calibration


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


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: _candidate_alternate_hypotheses()
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section B: _candidate_alternate_hypotheses() ---")

# THE LIVE-SHAPED CASE: alert published as NETWORK_INTRUSION (lateral scan), but the
# persisted evidence ALSO includes a DGA burst -- a second hypothesis with real
# evidence-driven reason to be considered, structurally invisible to the old prompt.
_overlap_payload = {
    "signature": "NETWORK_INTRUSION",
    "hee_evidence_types": ["zeek_lateral_scan", "dns_dga_burst"],
}
check("an alert whose evidence overlaps a second hypothesis surfaces it as a candidate",
      _candidate_alternate_hypotheses(_overlap_payload) == ["DGA_BOTNET_C2"])

_no_overlap_payload = {
    "signature": "NETWORK_INTRUSION",
    "hee_evidence_types": ["zeek_lateral_scan"],
}
check("an alert with no overlapping evidence in any other hypothesis returns an empty "
      "list -- a real, meaningful 'checked, nothing else applies' answer",
      _candidate_alternate_hypotheses(_no_overlap_payload) == [])

_uncovered_payload = {"signature": "ADVERTISING_BURST", "hee_evidence_types": ["ad_burst_rate"]}
check("returns None (not []) for an alert published under a hypothesis not yet in "
      "the registry -- distinct from 'covered, no candidates'",
      _candidate_alternate_hypotheses(_uncovered_payload) is None)

check("returns None when hee_evidence_types is missing entirely",
      _candidate_alternate_hypotheses({"signature": "NETWORK_INTRUSION"}) is None)

_self_only_payload = {
    "signature": "PORT_SCAN",  # one of ConnectionAbuseHypothesis's 3 dynamic names
    "hee_evidence_types": ["zeek_conn_abuse", "arp_sweep"],
}
check("alias dedup: a PORT_SCAN alert overlapping only its OWN class's evidence types "
      "(zeek_conn_abuse, arp_sweep -- also relevant to CONNECTION_ABUSE/"
      "INTERNAL_RECONNAISSANCE, same underlying class) lists no candidates, not 2 "
      "near-duplicate names for itself",
      _candidate_alternate_hypotheses(_self_only_payload) == [])

_multi_candidate_payload = {
    "signature": "DNS_TUNNELING",
    "hee_evidence_types": ["dns_rate", "dns_entropy", "dns_tunnel_v2", "zeek_beaconing"],
}
# dns_rate also overlaps DGA_BOTNET_C2's own strong-corroboration type; zeek_beaconing
# overlaps both DATA_EXFILTRATION and C2_BEACONING's own relevant sets; dns_tunnel_v2
# overlaps DNS_COVERT_TUNNELING -- 4 genuinely distinct classes, not 2.
check("multiple genuinely distinct overlapping hypotheses are all surfaced, sorted",
      _candidate_alternate_hypotheses(_multi_candidate_payload)
      == ["C2_BEACONING", "DATA_EXFILTRATION", "DGA_BOTNET_C2", "DNS_COVERT_TUNNELING"])


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: DeterministicValidator.validate()
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section C: DeterministicValidator.validate() ---")

check("VALIDATOR_SCHEMA_VERSION bumped to 5", VALIDATOR_SCHEMA_VERSION == 5)

validator = DeterministicValidator()

_base_rec = {
    "classification": "benign", "reason": "device profile telemetry",
    "supporting_evidence": ["known infrastructure", "low volume"],
    "contradicting_evidence": [], "recommended_action": "suppress",
}
# rep_tier=1 (trusted) so the Phase 58b destination/baseline check doesn't itself
# reject first -- isolates the new Phase 63 check.
_trusted_ground_truth = {"decision_path": "", "rep_tier": 1, "evidence_types": []}

check("REJECTS 'benign' when candidate_hypotheses has an entry hypotheses_ruled_out "
      "never addresses",
      validator.validate(
          _base_rec, [],
          ground_truth={**_trusted_ground_truth, "candidate_hypotheses": ["DGA_BOTNET_C2"]},
          baseline_familiarity=0.0,
      ) is False)

_rec_with_ruled_out = {
    **_base_rec,
    "hypotheses_ruled_out": ["DGA_BOTNET_C2: no dns_dga_burst pattern beyond a single burst"],
}
check("ACCEPTS 'benign' when hypotheses_ruled_out addresses every candidate "
      "(case-insensitive substring match)",
      validator.validate(
          _rec_with_ruled_out, [],
          ground_truth={**_trusted_ground_truth, "candidate_hypotheses": ["DGA_BOTNET_C2"]},
          baseline_familiarity=0.0,
      ) is True)

check("REJECTS when hypotheses_ruled_out addresses SOME but not ALL candidates",
      validator.validate(
          _rec_with_ruled_out, [],
          ground_truth={
              **_trusted_ground_truth,
              "candidate_hypotheses": ["DGA_BOTNET_C2", "C2_BEACONING"],
          },
          baseline_familiarity=0.0,
      ) is False)

check("empty candidate_hypotheses is a no-op -- ACCEPTS same as before Phase 63",
      validator.validate(
          _base_rec, [],
          ground_truth={**_trusted_ground_truth, "candidate_hypotheses": []},
          baseline_familiarity=0.0,
      ) is True)

check("absent candidate_hypotheses key (pre-Phase-63 ground_truth) is a no-op -- "
      "backward compatible",
      validator.validate(
          _base_rec, [], ground_truth=_trusted_ground_truth, baseline_familiarity=0.0,
      ) is True)

check("absent ground_truth entirely is a no-op -- backward compatible",
      validator.validate(_base_rec, [], baseline_familiarity=0.0) is True)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: _apply_confidence_calibration()
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section D: _apply_confidence_calibration() ---")

check("calibrated=None (bucket still short of MIN_SAMPLES_FOR_CALIBRATION) returns "
      "raw_ttl UNCHANGED -- the 'not activated yet' branch, exercised until real data "
      "exists",
      _apply_confidence_calibration(86400, 0.9, None) == 86400)

check("raw_ttl=None stays None regardless of calibration -- nothing to adjust, "
      "mark_false_positive() already has its own 14-day fallback for this case",
      _apply_confidence_calibration(None, 0.9, 0.5) is None)

check("calibrated confidence ABOVE raw confidence extends TTL (factor > 1, clamped "
      "<= 1.5)",
      _apply_confidence_calibration(86400, 0.5, 0.9) == 86400 * 1.5)

check("calibrated confidence BELOW raw confidence shortens TTL (factor < 1, clamped "
      ">= 0.4)",
      _apply_confidence_calibration(86400, 0.9, 0.1) == 86400 * 0.4)

check("calibrated approximately equal to raw confidence leaves TTL approximately "
      "unchanged (factor ~= 1.0, no clamping)",
      abs(_apply_confidence_calibration(86400, 0.8, 0.8) - 86400) < 1.0)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 63 hypothesis-independence checks PASSED.")
