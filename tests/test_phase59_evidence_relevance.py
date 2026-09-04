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
ollama_soc.py's _evidence_relevance_breakdown() classifies hee_evidence_types (Phase
58) against that registry into present_relevant/absent_relevant/present_irrelevant,
appends it to the Ollama prompt as an explicitly-labeled, non-verdict-shaped section,
and renders it in the .md report next to the existing "Original HEE finding" line.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase59_evidence_relevance.py`

Sections:
  A. hypotheses/engine.py -- RELEVANT_EVIDENCE_TYPES per class, registry contents,
     LATERAL_MOVEMENT alias points at the same set as NETWORK_INTRUSION
  B. ollama_soc.py's _evidence_relevance_breakdown() -- correct classification,
     None for an uncovered hypothesis, None when hee_evidence_types is absent/empty
     (pre-Phase-58 alert), "reputation" excluded from present_irrelevant (handled by
     a separate check elsewhere, not evidence this breakdown should flag)
  C. Source-level wiring -- prompt_text gains the relevance section only when
     non-None; report_lines gains the "Evidence relevance" line; the injected prompt
     text is explicitly labeled as non-verdict scaffolding, not silently blended into
     the raw Alert Payload JSON
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
    AdvertisingBurstHypothesis,
)
from ollama_soc import _evidence_relevance_breakdown


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: hypotheses/engine.py
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: hypotheses/engine.py registry ---")

check("DNSTunnelingHypothesis declares exactly its own required/strong evidence types",
      DNSTunnelingHypothesis.RELEVANT_EVIDENCE_TYPES == frozenset({"dns_rate", "dns_entropy", "dns_unique_ratio"}))

check("NetworkIntrusionHypothesis declares exactly its own required evidence types "
      "(union of live + shadow variants)",
      NetworkIntrusionHypothesis.RELEVANT_EVIDENCE_TYPES == frozenset({
          "zeek_lateral_scan", "malicious_ja3", "malicious_ja4", "zeek_notice", "arp_spoof_pending",
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


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: _evidence_relevance_breakdown()
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section B: _evidence_relevance_breakdown() ---")

# THE LIVE INCIDENT, reproduced: NETWORK_INTRUSION alert, but the persisted evidence
# types are dns-hygiene-shaped (irrelevant) plus a genuine arp_spoof_pending signal.
_live_incident_payload = {
    "signature": "NETWORK_INTRUSION (persisted 1543s)",
    "hee_evidence_types": ["arp_spoof_pending", "dns_rate"],
}
bd = _evidence_relevance_breakdown(_live_incident_payload)

check("signature_base strips the persistence suffix before hypothesis lookup",
      bd is not None and bd["hypothesis"] == "NETWORK_INTRUSION")

check("arp_spoof_pending (present, relevant to NETWORK_INTRUSION) lands in "
      "present_relevant",
      bd["present_relevant"] == ["arp_spoof_pending"])

check("zeek_lateral_scan/malicious_ja3/ja4/zeek_notice (relevant but not present on "
      "THIS alert) land in absent_relevant",
      set(bd["absent_relevant"]) == {"zeek_lateral_scan", "malicious_ja3", "malicious_ja4", "zeek_notice"})

check("dns_rate (present on the alert, but NOT relevant to NETWORK_INTRUSION -- the "
      "exact live failure mode) lands in present_irrelevant",
      bd["present_irrelevant"] == ["dns_rate"])

_reputation_payload = {
    "signature": "NETWORK_INTRUSION",
    "hee_evidence_types": ["reputation", "arp_spoof_pending"],
}
bd_rep = _evidence_relevance_breakdown(_reputation_payload)
check("'reputation' is excluded from present_irrelevant -- it's handled by a separate "
      "IOC>=4.0 check elsewhere (ai_soc.py), not something this breakdown should flag "
      "as a relevance problem",
      "reputation" not in bd_rep["present_irrelevant"])

_uncovered_payload = {"signature": "ADVERTISING_BURST", "hee_evidence_types": ["ad_burst_rate"]}
check("returns None for a hypothesis not yet covered by the registry",
      _evidence_relevance_breakdown(_uncovered_payload) is None)

_no_types_payload = {"signature": "NETWORK_INTRUSION", "hee_evidence_types": []}
check("returns None when hee_evidence_types is empty/absent (pre-Phase-58 alert) -- "
      "even for an otherwise-covered hypothesis",
      _evidence_relevance_breakdown(_no_types_payload) is None)

check("returns None when hee_evidence_types is missing entirely",
      _evidence_relevance_breakdown({"signature": "NETWORK_INTRUSION"}) is None)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: source-level wiring
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section C: source-level wiring ---")

_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")

check("prompt_text is extended with the relevance section only inside `if relevance:`"
      " -- a None breakdown leaves the prompt byte-identical to before this phase",
      "relevance = _evidence_relevance_breakdown(representative)" in _soc_src
      and "if relevance:" in _soc_src
      and "prompt_text += (" in _soc_src)

check("the injected prompt text explicitly labels itself as reasoning scaffolding, "
      "not silently blended into the raw Alert Payload JSON above it",
      "Evidence relevance for hypothesis" in _soc_src)

check("the .md report renders an 'Evidence relevance' line next to the existing "
      "'Original HEE finding' line",
      "**Evidence relevance (" in _soc_src)

check("HYPOTHESIS_RELEVANT_EVIDENCE_TYPES is imported from hypotheses/engine.py, not "
      "redefined locally in ollama_soc.py",
      "from intelligence.hypotheses.engine import HYPOTHESIS_RELEVANT_EVIDENCE_TYPES" in _soc_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 59 evidence-relevance checks PASSED.")
