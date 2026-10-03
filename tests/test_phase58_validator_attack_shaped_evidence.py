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

The fix:
  1. hypotheses/evidence.py gains a module-level ATTACK_SHAPED_EVIDENCE_TYPES,
     hoisted from what used to be DeviceProfileBenignHypothesis's own private class
     attribute -- single source of truth for both consumers now.
  2. pipeline.py's alert_payload gains `hee_evidence_types` (the real Evidence.type
     names present, not just their coarser independence_group families -- family
     granularity is too coarse, e.g. "dns_dga_burst" and the ambiguous
     "dns_rate"/"dns_entropy" all share the same "dns_behavior" family).
  3. The DeterministicValidator's validate() rejects "benign" outright if
     ground_truth["evidence_types"] intersects ATTACK_SHAPED_EVIDENCE_TYPES --
     structural, not content-judging which evidence the model's own reasoning cites.

v16 NOTE: this file originally also covered (Section B) `intelligence/ai_soc.py`'s
own DeterministicValidator directly, and (part of Section C) its VALIDATOR_SCHEMA_VERSION
bump and scripts/ollama_soc.py's prompt-stripping/ground_truth-threading wiring. Both
files were retired in the v16 cleanup; the equivalent behavior on the surviving
validator (argus/llm_review/validator.py) is covered by
tests/test_argus_llm_review_validator.py ("a 'benign' verdict is rejected when genuine
attack-shaped evidence is present..."). Only Section A (still-live hypotheses code)
and the pipeline.py half of Section C remain below.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase58_validator_attack_shaped_evidence.py`

Sections:
  A. ATTACK_SHAPED_EVIDENCE_TYPES -- single source of truth in hypotheses/engine.py
  C. Source-level wiring -- pipeline.py persists hee_evidence_types from the same
     active_evidence list as hee_evidence_families
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


from argus.hypotheses.engine import DeviceProfileBenignHypothesis
ATTACK_SHAPED_EVIDENCE_TYPES = DeviceProfileBenignHypothesis.ATTACK_SHAPED_EVIDENCE_TYPES


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: single source of truth
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: ATTACK_SHAPED_EVIDENCE_TYPES single source of truth ---")

_validator_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "argus" / "llm_review" / "validator.py").read_text(encoding="utf-8")
check("the AI advisor's validator reads the SAME set the benign device-profile hypothesis uses "
      "(one definition, no re-declared duplicate that could drift)",
      "DeviceProfileBenignHypothesis.ATTACK_SHAPED_EVIDENCE_TYPES" in _validator_src)

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

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 58 attack-shaped-evidence-validator checks PASSED.")
