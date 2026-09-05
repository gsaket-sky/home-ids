"""
Standalone runtime test for Phase 66 (HEE_ROADMAP.md item 2, full 4-way
SUPPORTS/CONTRADICTS/NEUTRAL/IRRELEVANT evidence taxonomy): the third-party review's
suggested vocabulary classifies evidence against a hypothesis as one of 4 values; the
existing `_evidence_relevance_breakdown()` (Phase 59) only had 3
(present_relevant/absent_relevant/present_irrelevant), with the review's own reasoning
for not doing a full restructuring being that CONTRADICTS' role was already covered
elsewhere (the LLM's own `contradicting_evidence` list) -- redundant to duplicate, and
unavailable at prompt-build time anyway (LLM hasn't run yet).

The fix: `_evidence_relevance_taxonomy()` (ollama_soc.py) is an ADDITIVE reframing of
the existing 3-way data -- SUPPORTS=present_relevant, IRRELEVANT=present_irrelevant,
NEUTRAL=absent_relevant (an unmet expectation, not a counter-signal) -- plus a REAL 4th
signal for CONTRADICTS sourced from `hee_hypotheses.attack.checklist.contradicting_score`
(Phase 65 item 1, same session): the winning hypothesis's own live-computed
counter-evidence signal (e.g. a trusted-reputation-tier contradiction), genuinely
available pre-LLM. `_evidence_relevance_breakdown()` itself, its prompt-injection call
site, and its own regression suite (test_phase59) are all untouched -- this is a new,
separate function and report line, not a replacement.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase66_evidence_taxonomy_4way.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from ollama_soc import _evidence_relevance_taxonomy, _evidence_relevance_breakdown

# NetworkIntrusionHypothesis.RELEVANT_EVIDENCE_TYPES = {zeek_lateral_scan, malicious_ja3,
# malicious_ja4, zeek_notice, arp_spoof_pending} -- same fixture shape test_phase59 uses.
_base_payload = {
    "signature": "NETWORK_INTRUSION (persisted 1543s)",
    "hee_evidence_types": ["arp_spoof_pending", "dns_rate"],
}


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: SUPPORTS/NEUTRAL/IRRELEVANT correctly mirror the existing 3-way data
# ═══════════════════════════════════════════════════════════════════════════════════
tax_a = _evidence_relevance_taxonomy(_base_payload)
check("returns a real dict for a covered hypothesis with real evidence types",
      tax_a is not None, f"got {tax_a}")
check("SUPPORTS == present_relevant (arp_spoof_pending is both present and relevant)",
      tax_a is not None and tax_a["supports"] == ["arp_spoof_pending"], f"got {tax_a}")
check("IRRELEVANT == present_irrelevant (dns_rate is present but not relevant to "
      "NETWORK_INTRUSION)",
      tax_a is not None and tax_a["irrelevant"] == ["dns_rate"], f"got {tax_a}")
check("NEUTRAL == absent_relevant (the other 4 relevant types, simply not observed)",
      tax_a is not None and sorted(tax_a["neutral"]) == sorted(
          ["zeek_lateral_scan", "malicious_ja3", "malicious_ja4", "zeek_notice"]
      ), f"got {tax_a}")
check("hypothesis name matches the signature base (persistence suffix stripped)",
      tax_a is not None and tax_a["hypothesis"] == "NETWORK_INTRUSION", f"got {tax_a}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: CONTRADICTS is a REAL signal from Phase 65's checklist, not fabricated
# ═══════════════════════════════════════════════════════════════════════════════════
check("CONTRADICTS is False when there's no hee_hypotheses/checklist at all (a "
      "pre-Phase-65 alert) -- fails closed, not an error",
      _evidence_relevance_taxonomy(_base_payload)["contradicts"] is False)

payload_with_contradiction = dict(_base_payload)
payload_with_contradiction["hee_hypotheses"] = {
    "attack": {"name": "NETWORK_INTRUSION", "checklist": {
        "required_satisfied": True, "strong_score": 1.0, "contradicting_score": 1.0,
    }},
}
tax_contradicted = _evidence_relevance_taxonomy(payload_with_contradiction)
check("CONTRADICTS is True when the winning hypothesis's own checklist registered "
      "real contradicting_score (e.g. a trusted-reputation-tier context)",
      tax_contradicted is not None and tax_contradicted["contradicts"] is True,
      f"got {tax_contradicted}")

payload_no_contradiction = dict(_base_payload)
payload_no_contradiction["hee_hypotheses"] = {
    "attack": {"name": "NETWORK_INTRUSION", "checklist": {
        "required_satisfied": True, "strong_score": 1.0, "contradicting_score": 0.0,
    }},
}
tax_clean = _evidence_relevance_taxonomy(payload_no_contradiction)
check("CONTRADICTS is False when the checklist's contradicting_score is exactly 0",
      tax_clean is not None and tax_clean["contradicts"] is False, f"got {tax_clean}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: None-degradation matches _evidence_relevance_breakdown() exactly (same
# underlying data, same coverage) -- an uncovered hypothesis or no evidence types
# ═══════════════════════════════════════════════════════════════════════════════════
uncovered = {"signature": "ADVERTISING_BURST", "hee_evidence_types": ["ad_burst_rate"]}
check("REGRESSION GUARD: returns None for an uncovered hypothesis, matching "
      "_evidence_relevance_breakdown()'s own None for the same payload",
      _evidence_relevance_taxonomy(uncovered) is None
      and _evidence_relevance_breakdown(uncovered) is None)

no_types = {"signature": "NETWORK_INTRUSION", "hee_evidence_types": []}
check("REGRESSION GUARD: returns None when hee_evidence_types is empty (pre-Phase-58 "
      "alert)",
      _evidence_relevance_taxonomy(no_types) is None)

check("REGRESSION GUARD: returns None when hee_evidence_types is missing entirely",
      _evidence_relevance_taxonomy({"signature": "NETWORK_INTRUSION"}) is None)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: existing 3-way breakdown is completely untouched -- additive, not a
# replacement (the roadmap's own explicit scoping decision)
# ═══════════════════════════════════════════════════════════════════════════════════
base_result = _evidence_relevance_breakdown(_base_payload)
check("REGRESSION GUARD: _evidence_relevance_breakdown() (Phase 59, existing) is "
      "byte-identical in shape to before this phase -- 3 keys, no 'contradicts'/"
      "'supports'/'neutral' renaming leaking into the old function",
      base_result is not None
      and set(base_result.keys()) == {"hypothesis", "present_relevant", "absent_relevant", "present_irrelevant"},
      f"got {base_result}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 66 4-way evidence-taxonomy checks PASSED.")
