"""
Standalone runtime test for Phase 28/37 (Telegram alert redesign). Not part of the
pytest suite -- run directly: `python3 test_phase28_alert_redesign.py`.

Background: Phase 28 fixed the alert mixing five subsystems' raw output in
run-order with no visual hierarchy, but its CONFIDENCE section still showed two
raw, differently-scaled percentages ("Is this the attack? -> 89%" / "Could this
be a FP? -> 12%") side by side, explicitly labeled "not directly comparable" --
leaving the operator to reconcile them under a live incident, with no statement
of what (if anything) already happened or what's expected of them if they do
nothing. Phase 37 (this revision) replaces that with: (1) a top status block
computed from the same containment_status/fp_verdict data -- what's already
done, what the operator's move is, what happens if they do nothing -- and (2) a
single reconciled CONFIDENCE verdict (_build_confidence_line) instead of two
uncomparable numbers.

Covers:
  A. _describe_evidence() -- plain-language translation, real mapped types, unmapped
     fallback, domain-suffix behavior.
  B. _build_status_lines() / _build_confidence_line() -- the reconciliation helpers.
  C. pipeline.py source-guards: the new structure exists, AND the old confusing
     structures (both pre-Phase-28 and the Phase-28 two-number CONFIDENCE table)
     are genuinely gone (regression guard against silently reverting).
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


from core.pipeline import _describe_evidence, _EVIDENCE_PLAIN_LANGUAGE, _build_status_lines, _build_confidence_line
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
# Section B: _build_status_lines() / _build_confidence_line() -- the reconciliation
# helpers that replaced the two-raw-numbers CONFIDENCE table and the separately-worded
# severity_badge/action_summary/recommendation trio.
# ═══════════════════════════════════════════════════════════════════════════════════
emoji, done, move, idle = _build_status_lines("auto-blocked", mixed_signal=False)
check("a contained device (not mixed-signal) tells the operator no action is required",
      "nothing required" in move, f"got {move!r}")
# BUGFIX (live audit, follow-up session): "auto-blocked" (Pi-hole domain block) used
# to share the exact same "device auto-blocked from the network"/"the block stays in
# place" wording as router isolation and Layer-2 tarpit -- both of which really do
# cut a device off, unlike a single domain block. Confirmed live: this contradicted
# the SAME alert's own "WHAT HAPPENED" section, which correctly said "DOMAIN
# BLOCKED." Now scoped, accurate wording -- "stays blocked" (the domain), explicitly
# NOT "the device."
check("a contained device's 'if you do nothing' line says the (domain) block stays "
      "in place",
      "stays blocked" in idle, f"got {idle!r}")
check("THE FIX: the domain-block case explicitly clarifies the DEVICE itself is not "
      "blocked, unlike router-isolation/tarpit -- previously worded identically to "
      "those two, which really do cut a device off",
      "device itself is not blocked" in done.lower(), f"got {done!r}")

emoji_m, done_m, move_m, idle_m = _build_status_lines("auto-blocked", mixed_signal=True)
check("a contained device with a MIXED confidence signal tells the operator to review, "
      "not 'nothing required' -- the false-positive tension must actually change the "
      "operator-facing instruction, not just appear buried in a confidence number",
      "review" in move_m.lower() and "nothing required" not in move_m, f"got {move_m!r}")

emoji_w, done_w, move_w, idle_w = _build_status_lines("awaiting approval", mixed_signal=False)
check("an awaiting-approval device's 'if you do nothing' line says it stays unblocked",
      "unblocked" in idle_w, f"got {idle_w!r}")

emoji_o, done_o, move_o, idle_o = _build_status_lines("monitoring only", mixed_signal=False)
check("a monitoring-only device's status says nothing was blocked",
      "not blocked" in done_o, f"got {done_o!r}")
check("a monitoring-only device's 'if you do nothing' line warns the alert will repeat",
      "repeat" in idle_o, f"got {idle_o!r}")

hard_stop_verdict = {"stage": "STAGE1_HARD_STOP", "verdict": "CONFIRMED_MALICIOUS"}
label_hs, line_hs, mixed_hs = _build_confidence_line(90, hard_stop_verdict, 0, None)
check("a HARD_STOP verdict is shown as a direct match, not a probabilistic estimate "
      "(same guarantee the old code had, just folded into the single line)",
      "not a probabilistic estimate" in line_hs and not mixed_hs, f"got {line_hs!r}")

benign_leaning_verdict = {"stage": "STAGE3_ML_SCORED", "verdict": "SUSPICIOUS"}
label_mix, line_mix, mixed_mix = _build_confidence_line(85, benign_leaning_verdict, 78, None)
check("when the false-positive check leans benign (>=50%) despite HIGH/CRITICAL, the "
      "reconciled verdict is labeled Mixed and flags mixed_signal=True, not silently "
      "averaged away",
      label_mix == "Mixed" and mixed_mix is True, f"got label={label_mix!r} mixed={mixed_mix!r}")
check("an uncalibrated Mixed-confidence line says so explicitly",
      "uncalibrated estimate" in line_mix, f"got {line_mix!r}")

confident_verdict = {"stage": "STAGE3_ML_SCORED", "verdict": "CONFIRMED"}
label_hi, line_hi, mixed_hi = _build_confidence_line(89, confident_verdict, 12, 12)
check("a low false-positive-risk verdict is labeled High, not Mixed, and reads as "
      "reconciled agreement rather than two bare percentages",
      label_hi == "High" and mixed_hi is False, f"got label={label_hi!r}")
check("a calibrated score does NOT show the 'uncalibrated estimate' caveat",
      "uncalibrated estimate" not in line_hi, f"got {line_hi!r}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: pipeline.py source-guards
# ═══════════════════════════════════════════════════════════════════════════════════
with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src = f.read()

# C1: new structure present
check("the new header format leads with THREAT + hostname (not the old '[ALERT] hostname' form)",
      'f"🚨 *THREAT — {hostname}* ({client_ip})\\n\\n"' in pipeline_src)
check("a severity badge (HIGH/CRITICAL) appears right after the header, before any evidence",
      'severity_badge = "🔴 CRITICAL" if decision_state_for_rec == DecisionState.CRITICAL else "🟠 HIGH"' in pipeline_src)
check("the top status block (already done / your move / if you do nothing) is computed "
      "and placed BEFORE the evidence/confidence sections (status-first, not buried at "
      "the end)",
      pipeline_src.index('*If you do nothing:*') < pipeline_src.index('*WHY*'))
check("a WHAT HAPPENED (facts) section exists, separate from WHY (evidence/inference)",
      "*WHAT HAPPENED*" in pipeline_src and "*WHY*" in pipeline_src)
check("WHY uses the plain-language _describe_evidence() helper, not a raw f'{ev.type} ({ev.value})' dump",
      "why_lines = [_describe_evidence(ev) for ev in" in pipeline_src)
check("exactly one CONFIDENCE line exists, built from the reconciled _build_confidence_line() "
      "helper rather than two separately-placed raw percentages",
      "*CONFIDENCE:* {confidence_line}" in pipeline_src)
check("the WHY header cites the real independent-source count that authorized containment, "
      "not a bare percentage with no context",
      # VERSION 12 (G7/G8, HEE coverage audit): "signal" -> "evidence family" -- the
      # count itself was always a family count (one entry per independence_group);
      # only the word was wrong. See pipeline.py's own comment at this exact line.
      "independent evidence famil" in pipeline_src and "strongest first)_" in pipeline_src)

# C2: regression guards -- the old confusing structures are genuinely GONE, not just
# supplemented. These are the exact strings a silent revert would reintroduce.
check("REGRESSION GUARD: the old raw 'CAUSE / EVIDENCE' per-signal-magnitude dump is gone",
      "CAUSE / EVIDENCE" not in pipeline_src)
check("REGRESSION GUARD: the old raw reasoning_trail dump section is gone",
      "REASONING (Decision Engine)" not in pipeline_src)
check("REGRESSION GUARD: the old raw fp_verdict reasons dump section is gone",
      "FALSE-POSITIVE CHECK" not in pipeline_src)
check("REGRESSION GUARD: the old separately-placed 'CL-AFPE benign-context estimate' line "
      "(a THIRD confidence-like number) is gone",
      "CL-AFPE benign-context estimate" not in pipeline_src)
check("REGRESSION GUARD: the old 4-branch rec_badge (which included two SUSPICIOUS/low-confidence "
      "branches that can never be reached from inside the telegram_worthy gate) is gone",
      'rec_badge = "🟢 *Recommendation:* Likely False Positive' not in pipeline_src)
check("REGRESSION GUARD (Phase 37): the Phase-28 two-raw-numbers CONFIDENCE table -- 'is "
      "this the attack?' / 'could this be a FP?' shown side by side and explicitly "
      "labeled not directly comparable -- is gone, replaced by the reconciled single-line "
      "verdict",
      "not directly comparable" not in pipeline_src and "Is this really the attack pattern?" not in pipeline_src)
check("REGRESSION GUARD (Phase 37): the old jargon-leaking FP line ('CL-AFPE verdict: ...', "
      "'bypassed FP scoring') is gone from the user-facing message",
      "Could this still be a false positive?" not in pipeline_src)
check("REGRESSION GUARD (Phase 37): the old separately-worded 'recommendation' string "
      "('Possibly a false positive despite reaching...' / 'Investigate. N independent "
      "signal(s) corroborated...') is gone, folded into the reconciled status block instead",
      "Possibly a false positive despite reaching" not in pipeline_src
      and "corroborated before containment fired" not in pipeline_src)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 28 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 28 alert-redesign checks PASSED.")
    sys.exit(0)
