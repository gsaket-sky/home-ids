"""
Standalone runtime test for Phase 28 (Telegram alert redesign). Not part of the
pytest suite -- run directly: `python3 test_phase28_alert_redesign.py`.

Background: explicit operator feedback -- the alert "mixes stuff and does not flow
logically, not possible to understand what is causing the alert... it should be clear
what is definitely true and what is guess/estimation/confidence and categorized in
right logic." The message previously concatenated output from five independent
subsystems (evidence store, decision engine, CL-AFPE Stage1/2/3, reasoning trail) in
the order they happened to run, with three different confidence-like numbers scattered
through it and no visual hierarchy. This redesign leads with verdict+recommendation,
separates FACTS from WHY (evidence, in plain language, not raw per-signal magnitudes),
and reduces the message to exactly two confidence numbers, shown side by side with an
explicit "these are different questions" label -- approved via a rendered Telegram-bubble
mockup before implementation (see the artifact from this session).

Covers:
  A. _describe_evidence() -- plain-language translation, real mapped types, unmapped
     fallback, domain-suffix behavior.
  B. pipeline.py source-guards: the new structure exists, AND the old confusing
     structure it replaced is genuinely gone (regression guard against silently
     reverting to the old format).
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


from core.pipeline import _describe_evidence, _EVIDENCE_PLAIN_LANGUAGE
from intelligence.hypotheses.evidence import Evidence
import time


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: _describe_evidence()
# ═══════════════════════════════════════════════════════════════════════════════════
ev_tunnel = Evidence(type="dns_tunnel_v2", source="threat_signals", timestamp=time.time(),
                      device="dev1", value=340.0, confidence=0.9)
desc = _describe_evidence(ev_tunnel)
check("a mapped evidence type produces its plain-language sentence, not the raw type string",
      desc == _EVIDENCE_PLAIN_LANGUAGE["dns_tunnel_v2"], f"got {desc!r}")
check("the plain-language description contains NO raw numeric magnitude "
      "(the exact confusion this redesign removes)",
      "340" not in desc and "340.0" not in desc, f"got {desc!r}")

ev_with_domain = Evidence(type="arp_sweep", source="threat_signals", timestamp=time.time(),
                           device="dev1", value=12.0, confidence=0.8, domain="192.168.1.1")
desc_dom = _describe_evidence(ev_with_domain)
check("when the evidence carries a domain/IP, it's appended to the description",
      "192.168.1.1" in desc_dom, f"got {desc_dom!r}")

ev_unmapped = Evidence(type="some_brand_new_detector_type", source="x", timestamp=time.time(),
                        device="dev1", value=1.0, confidence=0.5)
desc_unmapped = _describe_evidence(ev_unmapped)
check("an UNMAPPED evidence type degrades gracefully (de-snaked, capitalized), never KeyErrors",
      desc_unmapped == "Some brand new detector type", f"got {desc_unmapped!r}")

# Every evidence type actually emitted anywhere in the detectors has a real mapping --
# not just a fallback -- so the WHY section never shows a raw de-snaked identifier for
# a signal this codebase actually produces day to day.
_REAL_EVIDENCE_TYPES = {
    "dns_rate", "dns_entropy", "dns_unique_ratio", "dns_evasion_anomaly", "dns_dga_burst",
    "dns_tunnel_v2", "zeek_exfiltration", "zeek_beaconing", "zeek_conn_abuse", "zeek_long_conn",
    "arp_sweep", "zeek_notice", "arp_spoofing", "ml_anomaly", "honeypot_access",
    "zeek_lateral_scan", "reputation", "geofencing_violation", "domain", "ip", "mixed",
}
missing = _REAL_EVIDENCE_TYPES - set(_EVIDENCE_PLAIN_LANGUAGE.keys())
check("every real evidence type emitted anywhere in the codebase has a genuine plain-language mapping",
      not missing, f"missing mappings for: {missing}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: pipeline.py source-guards
# ═══════════════════════════════════════════════════════════════════════════════════
with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src = f.read()

# B1: new structure present
check("the new header format leads with THREAT + hostname (not the old '[ALERT] hostname' form)",
      'f"🚨 *THREAT — {hostname}* ({client_ip})\\n\\n"' in pipeline_src)
check("a severity badge (HIGH/CRITICAL) appears right after the header, before any evidence",
      'severity_badge = "🔴 CRITICAL" if decision_state_for_rec == DecisionState.CRITICAL else "🟠 HIGH"' in pipeline_src)
check("the recommendation is computed and placed in the message BEFORE the evidence/confidence "
      "sections (verdict-first, not buried at the end)",
      pipeline_src.index('f"{recommendation}\\n"') < pipeline_src.index('*WHY*'))
check("a WHAT HAPPENED (facts) section exists, separate from WHY (evidence/inference)",
      "*WHAT HAPPENED*" in pipeline_src and "*WHY*" in pipeline_src)
check("WHY uses the plain-language _describe_evidence() helper, not a raw f'{ev.type} ({ev.value})' dump",
      "why_lines = [_describe_evidence(ev) for ev in" in pipeline_src)
check("exactly one CONFIDENCE section exists, framing both numbers as different questions",
      "*CONFIDENCE*" in pipeline_src and "not directly comparable" in pipeline_src)
check("the attack-confidence line cites the real independent-source count that authorized "
      "containment, not a bare percentage with no context",
      "independent signal(s) agree" in pipeline_src)

# B2: regression guards -- the old confusing structure is genuinely GONE, not just
# supplemented. These are the exact strings a silent revert would reintroduce.
check("REGRESSION GUARD: the old raw 'CAUSE / EVIDENCE' per-signal-magnitude dump is gone",
      "CAUSE / EVIDENCE" not in pipeline_src)
check("REGRESSION GUARD: the old raw reasoning_trail dump section is gone",
      "REASONING (Decision Engine)" not in pipeline_src)
check("REGRESSION GUARD: the old raw fp_verdict reasons dump section is gone",
      "FALSE-POSITIVE CHECK" not in pipeline_src)
check("REGRESSION GUARD: the old separately-placed 'CL-AFPE benign-context estimate' line "
      "(a THIRD confidence-like number) is gone -- CL-AFPE's number now lives inside the "
      "single CONFIDENCE table instead",
      "CL-AFPE benign-context estimate" not in pipeline_src)
check("REGRESSION GUARD: the old 4-branch rec_badge (which included two SUSPICIOUS/low-confidence "
      "branches that can never be reached from inside the telegram_worthy gate) is gone",
      'rec_badge = "🟢 *Recommendation:* Likely False Positive' not in pipeline_src)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 28 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 28 alert-redesign checks PASSED.")
    sys.exit(0)
