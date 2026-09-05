"""
Standalone runtime test for v13's DeterministicValidator (src/v13/llm_review/validator.py,
Phase 5 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: every rejection rule ported from ai_soc.py (confirmed-IOC veto, telemetry-
claim veto, strong-decision-path override block, attack-shaped-evidence check,
destination-ownership/baseline-familiarity check, hypothesis-independence check,
empty-supporting-evidence check, self-contradiction check, circular-reasoning
check), build_ground_truth()'s assembly from a real v13 DecisionEngine result, and
candidate_alternate_hypotheses()'s dedup-by-identity behavior.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_llm_review_validator.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from v13.llm_review.validator import (  # noqa: E402
    DeterministicValidator, build_ground_truth, candidate_alternate_hypotheses,
)
from v13.hypotheses.engine import DeviceProfileBenignHypothesis  # noqa: E402

NOW = 1_000_000.0


def ev(evidence_type, value=1.0, family="general", dest=NO_DESTINATION):
    return Evidence(device_id="dev1", destination_id=dest, evidence_type=evidence_type,
                      independence_family=family, timestamp=NOW, source="s", value=value)


validator = DeterministicValidator()

# --- confirmed-IOC veto ---
check("a 'benign' verdict is rejected outright when a real IOC (reputation>=4.0) is present",
      not validator.validate({"classification": "benign", "reason": "x"},
                               [ev("reputation", value=4.5, family="reputation")]))

# --- telemetry-claim veto ---
check("a 'telemetry' claim is rejected when reputation is already bad (>=3.0)",
      not validator.validate({"classification": "benign", "reason": "just telemetry"},
                               [ev("reputation", value=3.5, family="reputation")]))
check("a 'telemetry' claim is NOT rejected on this basis when reputation is genuinely low",
      validator.validate({"classification": "benign", "reason": "just telemetry",
                            "supporting_evidence": ["low dns rate"]},
                           [ev("reputation", value=0.0, family="reputation")]))

# --- strong-decision-path override block ---
check("a 'benign' verdict is rejected when the alert's own decision already reached a strong attack path",
      not validator.validate(
          {"classification": "benign", "reason": "x", "supporting_evidence": ["y"]},
          [], ground_truth={"decision_path": "hard_stop"},
      ))
check("a 'benign' verdict is NOT blocked by this rule for a weak/suspicious decision path",
      validator.validate(
          {"classification": "benign", "reason": "x", "supporting_evidence": ["y"]},
          [], ground_truth={"decision_path": "hypothesis_suspicious"},
      ))

# --- attack-shaped-evidence structural check ---
check("a 'benign' verdict is rejected when genuine attack-shaped evidence is present, "
      "regardless of device-type reasoning",
      not validator.validate(
          {"classification": "benign", "reason": "smart tv telemetry", "supporting_evidence": ["x"]},
          [], ground_truth={"evidence_types": ["malicious_ja3"]},
      ))

# --- destination-ownership / baseline-familiarity check ---
check("a 'benign' verdict is rejected for an unclassified destination with no learned familiarity",
      not validator.validate(
          {"classification": "benign", "reason": "x", "supporting_evidence": ["y"]},
          [], ground_truth={"rep_tier": 3}, baseline_familiarity=0.0,
      ))
check("a 'benign' verdict IS allowed for an unclassified destination when familiarity clears the bar",
      validator.validate(
          {"classification": "benign", "reason": "x", "supporting_evidence": ["y"]},
          [], ground_truth={"rep_tier": 3}, baseline_familiarity=0.8,
      ))
check("a 'benign' verdict is allowed for an already-trusted-tier destination even with zero familiarity",
      validator.validate(
          {"classification": "benign", "reason": "x", "supporting_evidence": ["y"]},
          [], ground_truth={"rep_tier": 1}, baseline_familiarity=0.0,
      ))

# --- hypothesis-independence check ---
check("a 'benign' verdict is rejected when it doesn't address every candidate hypothesis",
      not validator.validate(
          {"classification": "benign", "reason": "x", "supporting_evidence": ["y"],
           "hypotheses_ruled_out": ["DGA_BOTNET_C2: no dga score"]},
          [], ground_truth={"candidate_hypotheses": ["DGA_BOTNET_C2", "C2_BEACONING"]},
      ))
check("a 'benign' verdict IS allowed once every candidate hypothesis is addressed",
      validator.validate(
          {"classification": "benign", "reason": "x", "supporting_evidence": ["y"],
           "hypotheses_ruled_out": ["DGA_BOTNET_C2: no dga score", "C2_BEACONING: no beaconing pattern"]},
          [], ground_truth={"candidate_hypotheses": ["DGA_BOTNET_C2", "C2_BEACONING"]},
      ))

# --- empty-supporting-evidence check ---
check("a 'benign' verdict with an empty supporting_evidence list is rejected as an assertion, not a finding",
      not validator.validate({"classification": "benign", "reason": "x", "supporting_evidence": []}, []))
check("a 'benign' verdict with only whitespace/blank supporting_evidence entries is also rejected",
      not validator.validate({"classification": "benign", "reason": "x", "supporting_evidence": ["  ", ""]}, []))

# --- self-contradiction check ---
check("a verdict that lists its own contradicting_evidence but still recommends suppress is rejected",
      not validator.validate(
          {"classification": "benign", "reason": "x", "supporting_evidence": ["y"],
           "contradicting_evidence": ["some counter-signal"], "recommended_action": "suppress"},
          [],
      ))
check("the same contradicting_evidence is fine if the action ISN'T suppress",
      validator.validate(
          {"classification": "benign", "reason": "x", "supporting_evidence": ["y"],
           "contradicting_evidence": ["some counter-signal"], "recommended_action": "none"},
          [],
      ))

# --- circular-reasoning-on-malicious check ---
check("a 'malicious' verdict citing the exact original risk score it was never shown is rejected",
      not validator.validate(
          {"classification": "malicious", "reason": "risk score of 9.5 confirms this"},
          [], original_risk=9.5,
      ))
check("a 'malicious' verdict with independently-derived reasoning is accepted",
      validator.validate(
          {"classification": "malicious", "reason": "real ja3 fingerprint match to known malware"},
          [], original_risk=9.5,
      ))

# --- a clean 'benign' verdict with everything satisfied passes ---
check("a fully well-formed 'benign' verdict with real corroboration passes cleanly",
      validator.validate(
          {"classification": "benign", "reason": "trusted infra telemetry",
           "supporting_evidence": ["low query rate", "known vendor domain"],
           "contradicting_evidence": [], "recommended_action": "suppress"},
          [], ground_truth={"decision_path": "benign", "rep_tier": 1, "evidence_types": []},
      ))

# --- build_ground_truth() assembly ---
decision_result = {
    "decision_path": "hypothesis_high",
    "hypotheses": {"attack": {"name": "NETWORK_INTRUSION", "score": 4.0}, "benign": {"name": "UNKNOWN_BENIGN", "score": 0.0}},
    "independent_sources": 2,
}
evidence_list = [ev("zeek_lateral_scan"), ev("dns_dga_burst")]
gt = build_ground_truth(decision_result, evidence_list, rep_tier=3)
check("build_ground_truth carries decision_path through unchanged", gt["decision_path"] == "hypothesis_high")
check("build_ground_truth carries independent_sources through unchanged", gt["independent_sources"] == 2)
check("build_ground_truth captures the present evidence types",
      set(gt["evidence_types"]) == {"zeek_lateral_scan", "dns_dga_burst"})
check("build_ground_truth carries rep_tier through", gt["rep_tier"] == 3)
check("build_ground_truth computes candidate_hypotheses (DGA_BOTNET_C2 overlaps via dns_dga_burst, "
      "NETWORK_INTRUSION itself is excluded as the winner)",
      "DGA_BOTNET_C2" in gt["candidate_hypotheses"] and "NETWORK_INTRUSION" not in gt["candidate_hypotheses"])

# --- candidate_alternate_hypotheses: dedup by identity, not just name ---
candidates_lateral = candidate_alternate_hypotheses("LATERAL_MOVEMENT", {"zeek_lateral_scan"})
check("LATERAL_MOVEMENT (a dynamic alias of NetworkIntrusionHypothesis) correctly excludes "
      "its OWN underlying class from candidates even under its alternate name",
      "NETWORK_INTRUSION" not in candidates_lateral and "LATERAL_MOVEMENT" not in candidates_lateral)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 LLM-review validator checks PASSED.")
