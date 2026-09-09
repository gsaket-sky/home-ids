"""
Standalone runtime test for Phase 58 (Gap 6 item 2): DeterministicValidator now
rejects a "benign" verdict outright when the alert's own deterministic evaluation
found genuinely attack-shaped evidence -- independent of whether the original
decision_path had already escalated to one of _STRONG_ATTACK_DECISION_PATHS.

Root cause (Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's Gap 6): the deterministic
engine already refuses to let a device-type label rescue a "benign" hypothesis against
attack-shaped evidence -- hypotheses/engine.py's DeviceProfileBenignHypothesis checks
`has_competing_attack_evidence` against _ATTACK_SHAPED_EVIDENCE_TYPES before it will
even fire. But that guard only ever applied at the LIVE alert-scoring pass. Confirmed
live, not hypothetical: both example_smarttv_fritz_box immunizations in the
2026-09-03 SOC report justified suppressing NETWORK_INTRUSION using DNS-hygiene
language (query rate, unique domains, entropy) -- evidence types
NetworkIntrusionHypothesis.evaluate() never actually reads. The LLM's free-text
re-review of an already-published alert had no independent check against the raw
evidence at all, only against the ORIGINAL decision_path reaching a strong bar --
a pattern that hadn't yet escalated that far could still be talked into "benign,
suppress" by a device-type explanation that never engaged with the actual trigger.

The fix, in three parts:
  1. hypotheses/evidence.py gains a module-level ATTACK_SHAPED_EVIDENCE_TYPES,
     hoisted from what used to be DeviceProfileBenignHypothesis's own private class
     attribute -- single source of truth for both consumers now.
  2. pipeline.py's alert_payload gains `hee_evidence_types` (the real Evidence.type
     names present, not just their coarser independence_group families -- family
     granularity is too coarse, e.g. "dns_dga_burst" and the ambiguous
     "dns_rate"/"dns_entropy" all share the same "dns_behavior" family).
  3. ai_soc.py's DeterministicValidator.validate() rejects "benign" outright if
     ground_truth["evidence_types"] intersects ATTACK_SHAPED_EVIDENCE_TYPES --
     structural, not content-judging which evidence the model's own reasoning cites.

VALIDATOR_SCHEMA_VERSION bumped 2 -> 3 (ai_soc.py) -- the first actual use of Phase
57's versioning mechanism, so every already-cached "benign" verdict computed before
this change becomes unreachable via the persistent cache immediately.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase58_validator_attack_shaped_evidence.py`

Sections:
  A. ATTACK_SHAPED_EVIDENCE_TYPES -- single source of truth, same object identity
     in both hypotheses/engine.py and ai_soc.py
  B. DeterministicValidator.validate() -- rejects benign when attack-shaped evidence
     is present regardless of decision_path; still accepts benign when only
     ambiguous dns_behavior-family evidence (dns_rate/dns_entropy) is present;
     backward-compatible when evidence_types is absent entirely (pre-Phase-58 alert)
  C. Source-level wiring -- pipeline.py persists hee_evidence_types from the same
     active_evidence list as hee_evidence_families; ollama_soc.py strips it from the
     LLM prompt and threads it into ground_truth; VALIDATOR_SCHEMA_VERSION bumped
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


from intelligence.hypotheses.evidence import ATTACK_SHAPED_EVIDENCE_TYPES
from intelligence.hypotheses.engine import DeviceProfileBenignHypothesis
from intelligence.ai_soc import DeterministicValidator, VALIDATOR_SCHEMA_VERSION


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: single source of truth
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: ATTACK_SHAPED_EVIDENCE_TYPES single source of truth ---")

check("DeviceProfileBenignHypothesis's class attribute IS the shared module-level "
      "constant (same object, not a re-declared duplicate that could drift)",
      DeviceProfileBenignHypothesis._ATTACK_SHAPED_EVIDENCE_TYPES is ATTACK_SHAPED_EVIDENCE_TYPES)

check("the set is non-trivial and includes the exact types the live incident involved "
      "(arp_sweep, zeek_lateral_scan) plus zeek_notice_medium/malicious_ja3/ja4 -- "
      "zeek_notice fragmented into 4 evidence_type values by tier (2026-09-09), "
      "weak deliberately excluded (routine capture noise, not attack-shaped)",
      {"arp_sweep", "zeek_lateral_scan", "zeek_notice_medium", "malicious_ja3", "malicious_ja4"}
      <= ATTACK_SHAPED_EVIDENCE_TYPES)
check("REGRESSION GUARD: zeek_notice_weak is deliberately NOT attack-shaped -- a "
      "single TCP-capture-artifact notice type alone fired 68,575 times on .94's "
      "real network, and shouldn't veto an otherwise-legitimate benign verdict",
      "zeek_notice_weak" not in ATTACK_SHAPED_EVIDENCE_TYPES)

check("deliberately excludes the ambiguous dns_behavior-family signals (dns_rate/"
      "dns_entropy/dns_unique_ratio aren't Evidence `type` values that exist anyway, "
      "but confirm the set doesn't accidentally include them under some alias)",
      not ({"dns_rate", "dns_entropy", "dns_unique_ratio"} & ATTACK_SHAPED_EVIDENCE_TYPES))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: DeterministicValidator.validate()
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section B: DeterministicValidator.validate() ---")

validator = DeterministicValidator()

_benign_rec_full = {
    "classification": "benign", "reason": "smart tv telemetry",
    "supporting_evidence": ["low query rate", "no suspicious domains"],
    "contradicting_evidence": [], "recommended_action": "suppress",
}

check("REJECTS 'benign' when evidence_types includes an attack-shaped type "
      "(arp_sweep) -- the exact Fire-TV/Echo-Show scenario this phase closes, even "
      "though decision_path is only 'hypothesis_suspicious' (well below "
      "_STRONG_ATTACK_DECISION_PATHS' bar, so the pre-existing check wouldn't catch it)",
      validator.validate(
          _benign_rec_full, [],
          ground_truth={"decision_path": "hypothesis_suspicious", "evidence_types": ["arp_sweep"]},
      ) is False)

check("REJECTS 'benign' when the ORIGINAL decision_path was empty/absent (e.g. a "
      "single not-yet-corroborated MAC flip) but evidence_types still shows the "
      "attack-shaped signal directly",
      validator.validate(
          _benign_rec_full, [],
          ground_truth={"decision_path": "", "evidence_types": ["arp_spoof_pending"]},
      ) is False)

check("ACCEPTS 'benign' when evidence_types is present but contains only non-attack-"
      "shaped types (e.g. a bare 'reputation' entry, already covered by the "
      "separate IOC>=4.0 check elsewhere)",
      validator.validate(
          _benign_rec_full, [],
          ground_truth={"decision_path": "", "evidence_types": ["reputation"]},
      ) is True)

check("BACKWARD COMPATIBLE: an alert published before Phase 58 (ground_truth has no "
      "'evidence_types' key at all) degrades to a no-op for this specific check -- "
      "doesn't crash, doesn't reject solely because the field is missing",
      validator.validate(
          _benign_rec_full, [],
          ground_truth={"decision_path": ""},
      ) is True)

check("BACKWARD COMPATIBLE: ground_truth=None entirely (pre-Phase-50 caller/tests) "
      "still works, still accepts a well-formed benign verdict",
      validator.validate(_benign_rec_full, [], ground_truth=None) is True)

check("does NOT affect 'malicious' classifications at all (this check is gated "
      "the same way every other benign-only check in validate() already is)",
      validator.validate(
          {"classification": "malicious", "reason": "confirmed", "recommended_action": "block"},
          [], ground_truth={"decision_path": "", "evidence_types": ["arp_sweep"]},
      ) is True)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: source-level wiring
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section C: source-level wiring ---")

_pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")
# NOTE: found stale during unrelated work (2026-09-09) -- pipeline.py's own
# "hee_evidence_types" field was extended to UNION with decision.get("evidence_types",
# []) (the v13-synthetic-type gap fix, same session, unrelated to Phase 58) after this
# check was first written; the underlying INTENT (still reads from the SAME
# active_evidence list, not a separately-fetched one) is unchanged, just the exact
# source text this check was verifying verbatim.
check("pipeline.py persists hee_evidence_types from the SAME active_evidence list "
      "hee_evidence_families already reads (not a separately-fetched, potentially "
      "stale list)",
      '{ev.type for ev in active_evidence} | set(decision.get("evidence_types", []))' in _pipeline_src)

_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")
check("ollama_soc.py strips hee_evidence_types from the LLM prompt "
      "(_VERDICT_SHAPED_FIELDS)",
      '"hee_evidence_types"' in _soc_src.split("_VERDICT_SHAPED_FIELDS = frozenset({", 1)[1].split("})", 1)[0])

check("ollama_soc.py threads hee_evidence_types into ground_truth as 'evidence_types'",
      '"evidence_types": representative.get("hee_evidence_types", [])' in _soc_src)

_ai_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "intelligence" / "ai_soc.py").read_text(encoding="utf-8")
check("VALIDATOR_SCHEMA_VERSION was actually bumped for this change (not left at "
      "Phase 57's value 2 -- a validator logic change with no version bump would defeat "
      "the entire point of Phase 57's cache-key versioning). >=3 rather than ==3 since "
      "a later phase (58b) legitimately bumps it further -- see "
      "test_phase58b_validator_destination_baseline.py for that one's own coverage.",
      VALIDATOR_SCHEMA_VERSION >= 3)

check("ATTACK_SHAPED_EVIDENCE_TYPES is imported from hypotheses/evidence.py, not "
      "redefined locally in ai_soc.py",
      "from intelligence.hypotheses.evidence import Evidence, ATTACK_SHAPED_EVIDENCE_TYPES" in _ai_soc_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 58 attack-shaped-evidence-validator checks PASSED.")
