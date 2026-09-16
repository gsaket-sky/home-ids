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


from core.pipeline import (
    _describe_evidence, _EVIDENCE_PLAIN_LANGUAGE, _build_status_lines, _build_confidence_line,
    _is_signature_based_hard_stop, _canonical_evidence_family, _route_evidence_into_buckets,
    _enforce_evidence_families_invariant,
)
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
    "arp_sweep", "arp_spoofing", "ml_anomaly", "honeypot_access",
    "zeek_lateral_scan", "reputation", "geofencing_violation", "domain", "ip", "mixed",
    # "zeek_notice" fragmented into 4 evidence_type values by tier (utils.py's
    # ZEEK_NOTICE_EVIDENCE_TYPES, explicit user request, 2026-09-09).
    "zeek_notice_weak", "zeek_notice_medium", "zeek_notice_strong", "zeek_notice_highly_deterministic",
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
# Section B2 (2026-09-15, live alert audit -- iPhone/d7cb300865b3 DATA_EXFILTRATION,
# real fired alert): every HARD_STOP verdict showed "Very High -- matched a known-bad
# signature directly (not a probabilistic estimate)" regardless of WHICH Stage-1 check
# actually fired -- but two of the real checks (lateral movement, exfiltration burst)
# are purely statistical/behavioral, not a signature match of any kind. Confirmed live:
# this alert's real reason was "Exfiltration Payload Burst (outbound_bytes_z=122.99...)"
# and the destination turned out to be the user's own VPN -- misleading wording on a
# genuinely ambiguous case.
# ═══════════════════════════════════════════════════════════════════════════════════
check("_is_signature_based_hard_stop: a ThreatIntel IOC reason is genuinely signature-based",
      _is_signature_based_hard_stop(["ThreatIntel IOC match (ti_risk=3.50) – domain on global malware blacklist"]))
check("_is_signature_based_hard_stop: a malicious JA3/JA4 fingerprint reason is genuinely signature-based",
      _is_signature_based_hard_stop(["Malicious TLS fingerprint (JA3=1, JA4+=0 hits)"]))
check("_is_signature_based_hard_stop: an exfiltration-burst-ONLY reason is NOT signature-based "
      "-- the real iPhone alert's own exact shape",
      not _is_signature_based_hard_stop(["Exfiltration Payload Burst (outbound_bytes_z=122.99, bytes=4531926)"]))
check("_is_signature_based_hard_stop: a lateral-movement-ONLY reason is NOT signature-based",
      not _is_signature_based_hard_stop(["Internal lateral movement / port scan (3 connection(s) across 2 distinct target(s))"]))
check("_is_signature_based_hard_stop: a MIX of a statistical reason and a genuine signature "
      "reason is still reported as signature-based -- something concrete DID match",
      _is_signature_based_hard_stop([
          "Exfiltration Payload Burst (outbound_bytes_z=8.0, bytes=3000000)",
          "AbuseIPDB blacklisted destination IP (risk=5.0)",
      ]))
check("_is_signature_based_hard_stop: an empty/missing reasons list defaults to True "
      "(the prior, safe behavior) rather than guessing with nothing to classify",
      _is_signature_based_hard_stop([]) and _is_signature_based_hard_stop(None))

exfil_only_verdict = {"stage": "STAGE_1_HARD_STOP",
                       "reasons": ["Exfiltration Payload Burst (outbound_bytes_z=122.99, bytes=4531926)"]}
label_ex, line_ex, mixed_ex = _build_confidence_line(85, exfil_only_verdict, 0, None)
check("_build_confidence_line: a purely statistical hard-stop does NOT claim a signature "
      "match -- the real bug this closes (note: the honest wording below deliberately "
      "still says 'not a known-bad signature match' as a disclaimer, so this checks for "
      "absence of the old CLAIM text specifically, not the substring 'known-bad signature')",
      "matched a known-bad signature directly" not in line_ex, f"got {line_ex!r}")
check("...and says so honestly instead (statistical/behavioral, not a signature)",
      "statistical" in line_ex.lower() and "not a known-bad signature" in line_ex, f"got {line_ex!r}")
check("...while still reading as a strong, confident verdict (this IS a real hard-stop, "
      "just not a signature one) -- label stays Very High", label_ex == "Very High")

ti_verdict = {"stage": "STAGE_1_HARD_STOP",
              "reasons": ["ThreatIntel IOC match (ti_risk=3.50) – domain on global malware blacklist"]}
label_ti, line_ti, mixed_ti = _build_confidence_line(90, ti_verdict, 0, None)
check("_build_confidence_line: a genuine signature-based hard-stop keeps the original "
      "'matched a known-bad signature directly' wording, unchanged",
      "matched a known-bad signature directly" in line_ti, f"got {line_ti!r}")

check("REGRESSION GUARD: the pre-existing hard_stop_verdict fixture above (no 'reasons' "
      "key at all) still gets the original wording, not the new statistical one -- "
      "missing reasons defaults safely, doesn't silently flip behavior",
      "matched a known-bad signature directly" in line_hs, f"got {line_hs!r}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B3 (2026-09-15, same live alert audit): grouped_evidence's WHY-block family
# dedup. The real iPhone alert showed "4 independent evidence families" for what
# hee_independent_sources correctly recorded as 2 -- dns_evasion_anomaly and
# zeek_exfiltration each got counted TWICE, once under v1's own OLDER family name
# (from whichever detector created the live active_evidence item) and once under
# Argus's newer INDEPENDENCE_FAMILY_MAP name (from the decision["attack_evidence"]
# bridge) -- two different dict keys for the identical real evidence.
# ═══════════════════════════════════════════════════════════════════════════════════
check("_canonical_evidence_family: dns_evasion_anomaly resolves to Argus's canonical "
      "'dns_behavior', not v1's older 'blindspot_audit' independence_group -- the "
      "exact real-alert mismatch this closes",
      _canonical_evidence_family("dns_evasion_anomaly", "blindspot_audit") == "dns_behavior")
check("_canonical_evidence_family: zeek_exfiltration resolves to Argus's canonical "
      "'data_transfer_pattern', not v1's older 'zeek_network' independence_group",
      _canonical_evidence_family("zeek_exfiltration", "zeek_network") == "data_transfer_pattern")
check("_canonical_evidence_family: an evidence type NOT covered by Argus's map falls "
      "back to the raw independence_group unchanged (e.g. a v1-only evidence type)",
      _canonical_evidence_family("some_v1_only_evidence_type", "raw_v1_family") == "raw_v1_family")

_gb, _cb = {}, {}
_ev_legacy = Evidence(type="dns_evasion_anomaly", source="dns_evasion", timestamp=time.time(),
                       device="dev1", value=0.6, confidence=0.9, independence_group="blindspot_audit")
_fam_legacy = _canonical_evidence_family(_ev_legacy.type, _ev_legacy.independence_group)
_route_evidence_into_buckets(_ev_legacy, _fam_legacy, _gb, _cb)
_ev_bridged = Evidence(type="dns_evasion_anomaly", source="argus_live_engine", timestamp=time.time(),
                        device="dev1", value=0.9, confidence=1.0, independence_group="dns_behavior")
_fam_bridged = _canonical_evidence_family(_ev_bridged.type, _ev_bridged.independence_group)
_route_evidence_into_buckets(_ev_bridged, _fam_bridged, _gb, _cb)
check("end-to-end: the SAME real evidence type reaching grouped_evidence through BOTH "
      "source loops (a live active_evidence item with the OLDER v1 family, and a "
      "bridged decision.attack_evidence item with Argus's canonical family) collapses "
      "into exactly ONE dict entry, not two -- fam_count = len(grouped_evidence) is "
      "now correct", len(_gb) == 1, f"got {len(_gb)} entries: {list(_gb.keys())}")
check("...and keeps the HIGHER-value entry between the two (0.9 from the bridged item, "
      "not 0.6 from the legacy one) -- matches the pre-existing 'keep the higher "
      "value' rule, now applied consistently across both loops",
      _gb["dns_behavior"].value == 0.9)

_gb2, _cb2 = {}, {}
_ev_local = Evidence(type="local_device_discovery", source="lan", timestamp=time.time(),
                      device="dev1", value=1.0, confidence=1.0, independence_group="local_context")
_route_evidence_into_buckets(_ev_local, _canonical_evidence_family(_ev_local.type, _ev_local.independence_group),
                              _gb2, _cb2)
check("_route_evidence_into_buckets: a NON_ATTACK_FAMILIES member (local_context) is "
      "routed to context_evidence, never grouped_evidence -- never inflates the "
      "independent-source count, matches decision_engine.py's own exclusion",
      len(_gb2) == 0 and len(_cb2) == 1)

_gb3, _cb3 = {}, {}
_route_evidence_into_buckets(Evidence(type="x", source="s", timestamp=time.time(), device="d",
                                        value=1.0, confidence=1.0, independence_group="peer_cohort_deviation"),
                              "peer_cohort_deviation", _gb3, _cb3)
check("_route_evidence_into_buckets: peer_cohort_deviation (a DIFFERENT NON_ATTACK_FAMILIES "
      "member than local_context, previously only excluded by the OTHER loop's own "
      "separate hand-picked check) is ALSO correctly routed to context, not grouped -- "
      "proves the two loops' context-routing can no longer disagree",
      len(_gb3) == 0 and len(_cb3) == 1)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B4 (2026-09-16, real live alert -- FireTV/a4544eb6d2ca COORDINATED_TARGETING,
# user-flagged): destination-linkage for the WHY-block DISPLAY, not just decision/
# engine.py's own SCORING. The real alert showed 3 "independent evidence families":
# cross_device_correlation (dest 192.168.77.41, genuinely the incident's own
# destination), dns_behavior (dest 62.245.131.134, an unrelated German IP, confidence
# 0.0), and network_behavior -- but network_behavior's DISPLAYED item was a weak,
# unrelated-destination Zeek notice (45.57.41.1, Netflix, confidence 0.4) even though a
# stronger, genuinely destination-matching item existed in the SAME family (an actual
# SSL::Invalid_Server_Cert notice fired on a connection to 192.168.77.41 itself,
# confidence 0.65) -- it just carried the same flat value=1.0 as the wrong one, so the
# old value-only tie-break couldn't tell them apart. decision/engine.py's own Gap-64
# filter already excluded the unrelated items from independent_sources; this closes the
# matching gap in what gets DISPLAYED.
# ═══════════════════════════════════════════════════════════════════════════════════
_hyp_dest = frozenset({"192.168.77.41"})
_gb4, _cb4 = {}, {}
_ev_ctc = Evidence(type="coordinated_targeting", source="argus_live_engine", timestamp=time.time(),
                    device="dev1", value=3.0, confidence=1.0, independence_group="cross_device_correlation",
                    domain="192.168.77.41")
_route_evidence_into_buckets(_ev_ctc, "cross_device_correlation", _gb4, _cb4, _hyp_dest)
_ev_dns_unrelated = Evidence(type="dns_evasion_anomaly", source="dns_evasion", timestamp=time.time(),
                              device="dev1", value=2.0, confidence=0.0, independence_group="dns_behavior",
                              domain="62.245.131.134")
_route_evidence_into_buckets(_ev_dns_unrelated, "dns_behavior", _gb4, _cb4, _hyp_dest)
check("_route_evidence_into_buckets: a dns_behavior item about a destination that "
      "doesn't match the winning hypothesis's own verified destination is demoted to "
      "context, never grouped -- the exact real bug (Germany IP shown as one of the "
      "'independent evidence families' when decision/engine.py's own Gap-64 filter "
      "had already excluded it from scoring for the identical reason)",
      "dns_behavior" not in _gb4 and "dns_behavior" in _cb4)

_ev_zeek_weak_wrong_dest = Evidence(type="zeek_notice_weak", source="zeek", timestamp=time.time() - 60,
                                     device="dev1", value=1.0, confidence=0.4, independence_group="network_behavior",
                                     domain="45.57.41.1", provenance="detector:zeek:notice:weird:window_recision")
_route_evidence_into_buckets(_ev_zeek_weak_wrong_dest, "network_behavior", _gb4, _cb4, _hyp_dest)
_ev_zeek_medium_right_dest = Evidence(type="zeek_notice_medium", source="zeek", timestamp=time.time(),
                                       device="dev1", value=1.0, confidence=0.65, independence_group="network_behavior",
                                       domain="192.168.77.41", provenance="detector:zeek:notice:SSL::Invalid_Server_Cert")
_route_evidence_into_buckets(_ev_zeek_medium_right_dest, "network_behavior", _gb4, _cb4, _hyp_dest)
check("THE REAL FIX: within the SAME family (network_behavior), the destination-matching "
      "zeek_notice_medium (SSL::Invalid_Server_Cert on 192.168.77.41 itself) wins the "
      "decisive slot over the unrelated-destination zeek_notice_weak (Netflix, "
      "45.57.41.1) -- even though the old code would have kept whichever inserted "
      "first, since both share the same flat value=1.0",
      _gb4.get("network_behavior") is _ev_zeek_medium_right_dest,
      f"got {_gb4.get('network_behavior')!r}")
check("...and the unrelated Netflix item lands in context_evidence instead of being "
      "silently dropped -- still shown for completeness, just never decisive",
      _cb4.get("network_behavior") is _ev_zeek_weak_wrong_dest)
check("net result for this exact real alert shape: fam_count = len(grouped_evidence) "
      "is 2 (cross_device_correlation + network_behavior), matching what "
      "independent_sources actually was for this incident -- not the 3 the live alert's "
      "Telegram text showed", len(_gb4) == 2, f"got {len(_gb4)}: {sorted(_gb4.keys())}")

_gb5, _cb5 = {}, {}
_route_evidence_into_buckets(
    Evidence(type="dns_evasion_anomaly", source="dns_evasion", timestamp=time.time(), device="d",
              value=2.0, confidence=0.0, independence_group="dns_behavior", domain="62.245.131.134"),
    "dns_behavior", _gb5, _cb5, frozenset())
check("_route_evidence_into_buckets: an EMPTY hyp_destination_ids (no destination anchor "
      "for this decision at all) never demotes anything on destination grounds -- "
      "mirrors decision/engine.py's own 'no anchor -> no filtering' Gap-64 rule",
      "dns_behavior" in _gb5)

_gb6, _cb6 = {}, {}
_route_evidence_into_buckets(
    Evidence(type="ml_anomaly", source="ml", timestamp=time.time(), device="d",
              value=1.0, confidence=0.5, independence_group="ml_anomaly", domain=None),
    "ml_anomaly", _gb6, _cb6, _hyp_dest)
check("_route_evidence_into_buckets: an evidence item with NO destination at all "
      "(domain=None) is unaffected by hyp_destination_ids -- only carries the "
      "pre-existing NON_ATTACK_FAMILIES routing (ml_anomaly), same as before this fix",
      "ml_anomaly" not in _gb6 and "ml_anomaly" in _cb6)

# --- _enforce_evidence_families_invariant() (2026-09-16, same fix): the general
# backstop for every OTHER way a family could end up decisive here without actually
# counting toward independent_sources in decision/engine.py -- not just the
# destination-mismatch case _route_evidence_into_buckets() already covers above.
# E.g. a family that's decisive in grouped_evidence purely because active_evidence's
# own freshness/attack-shaped filtering diverged from decision/engine.py's (per-type
# TTLs via score_evidence(), _is_attack_shaped()) -- decision["evidence_families"] is
# the single ground truth, so anything grouped_evidence has that it doesn't gets
# demoted, regardless of WHY the two disagreed.
_gb7 = {"network_behavior": Evidence(type="zeek_notice_medium", source="zeek", timestamp=time.time(),
                                       device="d", value=1.0, confidence=0.65, domain="192.168.77.41"),
        "dns_behavior": Evidence(type="dns_evasion_anomaly", source="dns_evasion", timestamp=time.time(),
                                   device="d", value=2.0, confidence=0.0, domain="192.168.77.41")}
_cb7 = {}
_enforce_evidence_families_invariant(_gb7, _cb7, {"evidence_families": ["network_behavior"]})
check("_enforce_evidence_families_invariant: a family present in grouped_evidence "
      "but absent from decision['evidence_families'] (the actual scoring ground "
      "truth) is demoted to context -- covers every divergence source, not just "
      "the destination-mismatch one _route_evidence_into_buckets() already filters",
      "dns_behavior" not in _gb7 and "network_behavior" in _gb7 and "dns_behavior" in _cb7)

_gb8, _cb8 = {"network_behavior": Evidence(type="x", source="s", timestamp=time.time(), device="d", value=1.0)}, {}
_enforce_evidence_families_invariant(_gb8, _cb8, {})
check("_enforce_evidence_families_invariant: a decision dict with NO 'evidence_families' "
      "key at all (v-current, which never populates it) degrades to a no-op -- exactly "
      "today's unfiltered behavior, not a wrongly-empty allowlist",
      "network_behavior" in _gb8 and _cb8 == {})

_gb9, _cb9 = {"network_behavior": Evidence(type="x", source="s", timestamp=time.time(), device="d", value=1.0)}, {}
_enforce_evidence_families_invariant(_gb9, _cb9, {"evidence_families": []})
check("_enforce_evidence_families_invariant: a genuinely EMPTY evidence_families "
      "(0 independent sources) correctly demotes everything -- the key's PRESENCE, "
      "not truthiness, is what gates enforcement",
      _gb9 == {} and "network_behavior" in _cb9)


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
      "why_lines = [_describe_evidence(ev, self.geoip_engine) for ev in" in pipeline_src)
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
