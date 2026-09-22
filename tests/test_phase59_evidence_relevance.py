"""
Standalone runtime test for Phase 59 (Gap 6 item 3, evidence relevance -- SUPPORTS/
CONTRADICTS/NEUTRAL/IRRELEVANT from the third-party HEE review).

Rescoped after Phase 58 shipped (see Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's
Gap 6 entry): Phase 58's attack-shaped-evidence validator check already closes the
DANGEROUS version of this gap structurally (a "benign" verdict against real
attack-shaped evidence is rejected outright, regardless of what the LLM cites). What's
left is explanation QUALITY, not a safety gate: giving the model (and the human
report reader) an explicit, deterministic breakdown of which of THIS alert's own
evidence types are actually relevant to the hypothesis in question, so reasoning like
"query rate is low, therefore NETWORK_INTRUSION is unlikely" has a structural nudge
away from it -- query rate was never relevant to NETWORK_INTRUSION in the first place
(confirmed live: both example_smarttv_fritz_box immunizations in the 2026-09-03 SOC
report cited exactly this irrelevant evidence).

Deliberately NOT a validator-side rejection rule -- matching a free-text
supporting_evidence string against an evidence TYPE name would need fragile
string-matching heuristics (the LLM writes "low query rate (1.4)", not literally
"dns_rate"), the same anti-pattern Phase 51's own comment already rejected for a
different check ("does not attempt to content-judge each item... a much more fragile
string-matching heuristic for marginal extra benefit"). Instead: the breakdown is
computed deterministically and handed to the model as explicit context BEFORE it
reasons, and shown in the human-readable report -- scaffolding, not a new rejection
gate.

hypotheses/engine.py gains a per-Hypothesis RELEVANT_EVIDENCE_TYPES class attribute
(declared for DNSTunnelingHypothesis and NetworkIntrusionHypothesis so far -- the two
hypotheses this session's live incident actually involved; most hypotheses inherit the
base class's empty default and are simply not covered by the breakdown yet, not an
error) and a module-level HYPOTHESIS_RELEVANT_EVIDENCE_TYPES registry keyed by
hypothesis name (including NetworkIntrusionHypothesis's LATERAL_MOVEMENT alt-name).

v16 NOTE: this file originally also covered (Sections B/C) scripts/ollama_soc.py's own
_evidence_relevance_breakdown() and its prompt/report wiring. That script was retired
in the v16 cleanup. The registry this file's surviving Section A tests is NOT
legacy-only, though -- argus/llm_review/validator.py imports the same
HYPOTHESIS_RELEVANT_EVIDENCE_TYPES concept (its own copy, in argus/hypotheses/engine.py)
for the surviving LLM-review validator, so this registry's design stays live and worth
testing regardless of ollama_soc.py's retirement.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase59_evidence_relevance.py`

Sections:
  A. hypotheses/engine.py -- RELEVANT_EVIDENCE_TYPES per class, registry contents,
     LATERAL_MOVEMENT alias points at the same set as NETWORK_INTRUSION
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
    AdvertisingBurstHypothesis,
)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: hypotheses/engine.py
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: hypotheses/engine.py registry ---")

check("DNSTunnelingHypothesis declares exactly its own required/strong evidence types",
      DNSTunnelingHypothesis.RELEVANT_EVIDENCE_TYPES == frozenset({"dns_rate", "dns_entropy", "dns_unique_ratio"}))

check("NetworkIntrusionHypothesis declares exactly its own required evidence types "
      "(union of live + shadow variants) -- zeek_notice fragmented into 4 evidence_type "
      "values by tier (utils.py's ZEEK_NOTICE_EVIDENCE_TYPES) as of 2026-09-09",
      NetworkIntrusionHypothesis.RELEVANT_EVIDENCE_TYPES == frozenset({
          "zeek_lateral_scan", "malicious_ja3", "malicious_ja4", "arp_spoof_pending",
          "zeek_notice_weak", "zeek_notice_medium", "zeek_notice_strong", "zeek_notice_highly_deterministic",
      }))

check("a hypothesis that hasn't declared an override (AdvertisingBurstHypothesis) "
      "inherits the base class's empty default -- not covered, not an error",
      AdvertisingBurstHypothesis.RELEVANT_EVIDENCE_TYPES == frozenset())

check("registry contains NETWORK_INTRUSION and DNS_TUNNELING",
      "NETWORK_INTRUSION" in HYPOTHESIS_RELEVANT_EVIDENCE_TYPES
      and "DNS_TUNNELING" in HYPOTHESIS_RELEVANT_EVIDENCE_TYPES)

check("LATERAL_MOVEMENT (NetworkIntrusionHypothesis's dynamic alt-name) points at the "
      "SAME set as NETWORK_INTRUSION -- a lateral-movement-named alert is still "
      "fundamentally a NetworkIntrusionHypothesis finding",
      HYPOTHESIS_RELEVANT_EVIDENCE_TYPES["LATERAL_MOVEMENT"]
      == HYPOTHESIS_RELEVANT_EVIDENCE_TYPES["NETWORK_INTRUSION"])

check("uncovered hypotheses (e.g. ADVERTISING_BURST) are simply absent from the "
      "registry, not present with an empty set (callers must distinguish "
      "'not covered' from 'covered, nothing relevant')",
      "ADVERTISING_BURST" not in HYPOTHESIS_RELEVANT_EVIDENCE_TYPES)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 59 evidence-relevance checks PASSED.")
