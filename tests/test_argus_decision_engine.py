"""
Standalone runtime test for v13's DecisionEngine (src/v13/decision/engine.py,
Phase 1/3 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: the pluggable hard-stop registry (honeypot's is_safe exemption, arp_spoof/
geofence/confirmed_exploit freshness-by-default -- a deliberate departure from
v-current's current live behavior), geofence corroboration split, tier-5's three-way
split (verified_ioc/corroborated/uncorroborated), tier-4, hypothesis-driven
HIGH/SUSPICIOUS, ml_anomaly fallback, plain benign fallback, the Gap-64
domain-linkage reputation-stripping redesign, and registry pluggability itself
(the actual structural point of this rewrite).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_decision_engine.py`
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


from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from argus.decision.engine import DecisionEngine, DecisionState, HardStopRule  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402

NOW = 1_000_000.0


def ev(evidence_type, value=1.0, timestamp=NOW, family=None, dest=NO_DESTINATION, confidence=1.0, provenance=""):
    from argus.hypotheses.independence import family_for
    return Evidence(device_id="dev1", destination_id=dest, evidence_type=evidence_type,
                      independence_family=family or family_for(evidence_type) or "general",
                      timestamp=timestamp, source="s", value=value, confidence=confidence,
                      provenance=provenance)


def rep(tier, **kwargs):
    return ReputationVector(domain="x.com", tier=tier, **kwargs)


engine = DecisionEngine()

# --- honeypot hard-stop: features-driven, is_safe exemption ---
r = engine.evaluate([], rep(3), features={"zeek_honeypot_hits": 1}, is_safe=False, now=NOW)
check("honeypot hard-stop fires CRITICAL/block from features, with no evidence needed at all",
      r["state"] == DecisionState.CRITICAL and r["decision_path"] == "hard_stop"
      and r["explanation"] == "Internal Honeypot Accessed")

r_safe = engine.evaluate([], rep(3), features={"zeek_honeypot_hits": 1}, is_safe=True, now=NOW)
check("honeypot hard-stop is exempted entirely for is_safe devices",
      r_safe["state"] != DecisionState.CRITICAL or r_safe["explanation"] != "Internal Honeypot Accessed")

r_stale_features = engine.evaluate([], rep(3), features={"zeek_honeypot_hits": 0}, is_safe=False, now=NOW)
check("honeypot hard-stop does not fire when the raw feature itself is 0",
      r_stale_features["decision_path"] != "hard_stop" or r_stale_features["explanation"] != "Internal Honeypot Accessed")

# --- arp_spoof hard-stop: freshness-aware BY DEFAULT (v13's deliberate departure) ---
r_fresh_arp = engine.evaluate([ev("arp_spoofing", timestamp=NOW - 10)], rep(3), now=NOW)
check("a FRESH arp_spoofing hit hard-stops CRITICAL/block",
      r_fresh_arp["state"] == DecisionState.CRITICAL and r_fresh_arp["decision_path"] == "hard_stop")

r_stale_arp = engine.evaluate([ev("arp_spoofing", timestamp=NOW - 500)], rep(3), now=NOW)
check("a STALE arp_spoofing hit (past the 120s freshness window) does NOT hard-stop "
      "-- v13's deliberate freshness-by-default departure from v-current's current live behavior",
      r_stale_arp["state"] != DecisionState.CRITICAL or r_stale_arp["decision_path"] != "hard_stop")

# --- geofence: corroboration split ---
r_geo_corroborated = engine.evaluate(
    [ev("geofencing_violation", timestamp=NOW - 5, dest="bad.example.com"),
     ev("malicious_ja3", timestamp=NOW - 5, dest="bad.example.com")],
    rep(3), now=NOW,
)
check("a fresh geofence hit WITH independent corroboration (and attack>benign) reaches full CRITICAL hard-stop",
      r_geo_corroborated["state"] == DecisionState.CRITICAL
      and r_geo_corroborated["explanation"] == "Geofencing Policy Violation")

r_geo_alone = engine.evaluate([ev("geofencing_violation", timestamp=NOW - 5)], rep(3), now=NOW)
check("a fresh geofence hit ALONE (no corroboration) demotes to HIGH with the Uncorroborated suffix",
      r_geo_alone["state"] == DecisionState.HIGH
      and r_geo_alone["explanation"] == "Geofencing Policy Violation (Uncorroborated)"
      and r_geo_alone["decision_path"] == "geofence_uncorroborated")

# --- confirmed_exploit: confidence threshold ---
# UPDATED 2026-09-12 (own_families bugfix, caught by
# tests/test_real_world_alert_regression.py's own Suricata scenario -- no real
# fired alert of this shape existed to catch it live): this used to assert a
# LONE high-confidence Suricata match reaches CRITICAL directly -- but that was
# the exact bug the 2026-09-10 "requires_corroboration" policy change was
# supposed to prevent (user's explicit choice: alert-only, always, a second
# independent signal required to escalate). It silently didn't, because
# suricata_signature_match's own family ("signature_match") isn't globally
# excluded from attack_evidence the way geofencing_violation's is -- so the
# lone match satisfied its own >=1-independent-source bar by counting itself.
# Now split into the two real scenarios: alone -> uncorroborated HIGH;
# corroborated -> CRITICAL hard-stop, matching HardStopRule.own_families.
r_exploit_high_conf_alone = engine.evaluate(
    [ev("suricata_signature_match", timestamp=NOW - 5, confidence=0.95)], rep(3), now=NOW,
)
check("a high-confidence (>=0.9) Suricata match ALONE is HIGH/uncorroborated, not "
      "autonomous CRITICAL -- the confidence bar alone was never meant to bypass "
      "the corroboration requirement",
      r_exploit_high_conf_alone["state"] == DecisionState.HIGH
      and r_exploit_high_conf_alone["decision_path"] == "suricata_uncorroborated")

r_exploit_high_conf_corroborated = engine.evaluate(
    [ev("suricata_signature_match", timestamp=NOW - 5, confidence=0.95, dest="evil.example"),
     ev("zeek_lateral_scan", timestamp=NOW - 5, dest="evil.example")],
    rep(3), now=NOW,
)
check("a high-confidence (>=0.9) Suricata match WITH genuine corroboration (a "
      "second independent family, same destination) hard-stops CRITICAL",
      r_exploit_high_conf_corroborated["state"] == DecisionState.CRITICAL
      and r_exploit_high_conf_corroborated["explanation"] == "Confirmed Exploit/Malware Signature (Suricata)")

r_exploit_low_conf = engine.evaluate(
    [ev("suricata_signature_match", timestamp=NOW - 5, confidence=0.5)], rep(3), now=NOW,
)
check("a LOW-confidence (<0.9) Suricata match does NOT hard-stop -- it's just real evidence "
      "for SuricataSignatureHypothesis instead",
      r_exploit_low_conf["decision_path"] != "hard_stop")

# --- tier-5: three-way split ---
r_verified = engine.evaluate([], rep(5, verified_ioc=True), now=NOW)
check("tier-5 + verified_ioc=True -> Confirmed Malicious IOC, CRITICAL",
      r_verified["decision_path"] == "tier5_confirmed" and r_verified["state"] == DecisionState.CRITICAL)

r_corroborated = engine.evaluate(
    [ev("malicious_ja3", timestamp=NOW - 5), ev("dns_dga_burst", timestamp=NOW - 5)],
    rep(5, verified_ioc=False), now=NOW,
)
check("tier-5, not verified, but corroborated by 2 independent families (tls_fingerprint "
      "+ network_behavior) + attack>benign -> Corroborated Reputation Signal, CRITICAL",
      r_corroborated["decision_path"] == "tier5_corroborated" and r_corroborated["state"] == DecisionState.CRITICAL)

# TIGHTENED (third-party architecture review, 2026-09-09): tier 5 without
# verified_ioc used to reach CRITICAL from just ONE independent family -- a bare
# crowd-sourced AbuseIPDB score, not a curated feed match, could reach auto-block
# from a single weak corroborating hint. CRITICAL should never require LESS
# corroboration than HIGH; now requires the same >=2-family bar.
r_single_family_tier5 = engine.evaluate(
    [ev("zeek_notice_medium", timestamp=NOW - 5)],
    rep(5, verified_ioc=False), now=NOW,
)
check("REGRESSION GUARD: tier-5, not verified, only ONE independent family (network_behavior "
      "alone) no longer reaches CRITICAL -- demotes to SUSPICIOUS instead",
      r_single_family_tier5["decision_path"] == "tier5_uncorroborated"
      and r_single_family_tier5["state"] == DecisionState.SUSPICIOUS,
      f"got {r_single_family_tier5['decision_path']}/{r_single_family_tier5['state']}")

r_uncorroborated5 = engine.evaluate([], rep(5, verified_ioc=False), now=NOW)
check("tier-5, not verified, no corroboration -> demotes to SUSPICIOUS, not CRITICAL",
      r_uncorroborated5["decision_path"] == "tier5_uncorroborated"
      and r_uncorroborated5["state"] == DecisionState.SUSPICIOUS)

# --- hypothesis-driven HIGH vs SUSPICIOUS ---
# A lateral scan alone hard-escalates the HYPOTHESIS's own score to 4.0 (confirmed in
# test_argus_hypotheses_engine.py), but the DECISION ENGINE's own independent-sources
# gate for HIGH is a SEPARATE requirement (>=2 families) -- a single evidence item
# from one family never satisfies it alone, matching v-current's own two-tier design
# (a hypothesis hard-escalating its own score doesn't bypass the engine's
# corroboration bar). Genuine two-family corroboration is needed to actually reach HIGH.
r_high_single_source = engine.evaluate([ev("zeek_lateral_scan", value=1)], rep(3), now=NOW)
check("a lateral scan ALONE (one family only) hard-escalates the hypothesis's own score to "
      "4.0, but still only counts as ONE independent source, so it stays at SUSPICIOUS, not HIGH "
      "-- the decision engine's corroboration gate is separate from the hypothesis's own score",
      r_high_single_source["decision_path"] == "hypothesis_suspicious"
      and r_high_single_source["state"] == DecisionState.SUSPICIOUS)

r_high = engine.evaluate(
    [ev("zeek_lateral_scan", value=1), ev("dns_dga_burst", value=1)], rep(3), now=NOW,
)
check("a lateral-scan-driven attack hypothesis WITH genuine two-family corroboration "
      "(network_behavior + tls_fingerprint) reaches HIGH via the hypothesis_high path",
      r_high["decision_path"] == "hypothesis_high" and r_high["state"] == DecisionState.HIGH)

r_suspicious = engine.evaluate([ev("zeek_notice_medium", value=1)], rep(3), now=NOW)
check("a weaker, single-source attack hypothesis (score 2.0) stays at SUSPICIOUS, not HIGH",
      r_suspicious["decision_path"] == "hypothesis_suspicious" and r_suspicious["state"] == DecisionState.SUSPICIOUS)

# --- tier-4 ---
r_tier4 = engine.evaluate([], rep(4, ti_risk=2.0), now=NOW)
check("tier-4 with a real elevated TI/VT/AbuseIPDB score -> Elevated Reputation Signal (Unconfirmed), SUSPICIOUS",
      r_tier4["decision_path"] == "tier4_unconfirmed" and r_tier4["state"] == DecisionState.SUSPICIOUS)

r_tier4_weak = engine.evaluate([], rep(4, ti_risk=0.5), now=NOW)
check("tier-4 with only a weak score (<1.5) does NOT trigger the tier4_unconfirmed branch",
      r_tier4_weak["decision_path"] != "tier4_unconfirmed")

# --- ml_anomaly fallback ---
r_ml = engine.evaluate([ev("ml_anomaly", value=0.95)], rep(3), now=NOW)
check("a strong ML anomaly with nothing else -> ANOMALOUS/log, the lowest real-signal fallback",
      r_ml["decision_path"] == "ml_anomaly" and r_ml["state"] == DecisionState.ANOMALOUS)

# --- plain benign fallback ---
r_benign = engine.evaluate([], rep(0), now=NOW)
check("no evidence, trusted-tier destination -> plain BENIGN/suppress",
      r_benign["state"] == DecisionState.BENIGN and r_benign["decision_path"] == "benign")

# --- Gap-64 domain-linkage reputation-stripping redesign ---
# A DGA finding on domain A, corroborated by a reputation hit on the SAME domain A,
# should count as genuine linkage and reach a higher tier.
same_domain = engine.evaluate(
    [ev("dns_dga_burst", value=1, dest="evil-a.example.com"),
     ev("dns_rate", value=150, dest="evil-a.example.com"),
     ev("reputation", value=4.0, dest="evil-a.example.com")],
    rep(3), now=NOW,
)
different_domain = engine.evaluate(
    [ev("dns_dga_burst", value=1, dest="evil-a.example.com"),
     ev("dns_rate", value=150, dest="evil-a.example.com"),
     ev("reputation", value=4.0, dest="totally-unrelated.example.com")],
    rep(3), now=NOW,
)
check("a reputation hit on the SAME domain as the winning attack hypothesis's own evidence "
      "counts as genuine corroboration (num_independent_sources includes it)",
      same_domain["independent_sources"] >= different_domain["independent_sources"],
      f"same={same_domain['independent_sources']} different={different_domain['independent_sources']}")
check("a reputation hit on an AFFIRMATIVELY DIFFERENT domain is stripped from corroboration "
      "-- the actual Gap-64 fix -- so the different-domain case has strictly fewer independent sources",
      different_domain["independent_sources"] < same_domain["independent_sources"])

no_domain_either_side = engine.evaluate(
    [ev("dns_dga_burst", value=1), ev("dns_rate", value=150), ev("reputation", value=4.0)],
    rep(3), now=NOW,
)
check("when NEITHER side carries domain info (the existing golden-case ambiguity), the "
      "reputation hit is left alone, not stripped -- matches v-current's own documented "
      "'don't touch the ambiguous case' rule exactly",
      no_domain_either_side["independent_sources"] == same_domain["independent_sources"])

# --- local_device_discovery is excluded from attack corroboration counting ---
with_local_only = engine.evaluate(
    [ev("dns_dga_burst", value=1), ev("local_device_discovery", value=1)], rep(3), now=NOW,
)
without_local = engine.evaluate([ev("dns_dga_burst", value=1)], rep(3), now=NOW)
check("local_device_discovery evidence never inflates the independent-attack-source count "
      "(mirrors v-current's ATTACK_EVIDENCE_FAMILIES exclusion exactly)",
      with_local_only["independent_sources"] == without_local["independent_sources"])

# --- geofencing_violation (family "policy") is excluded from attack corroboration
# counting too (BUGFIX, external architecture review, 2026-09-09) -- a policy fact
# about a destination must not be able to silently supply the SECOND independent
# source for an unrelated, weaker attack hypothesis. NOT the same question as the
# geofence hard-stop's own corroboration check (that one requires attack_score>
# benign_score too, which a bare geofencing_violation alone never satisfies since no
# hypothesis reads that evidence type -- see the existing geofence INVARIANT tests
# above, unaffected by this change).
with_geofence_only = engine.evaluate(
    [ev("zeek_lateral_scan", value=1), ev("geofencing_violation", value=1)], rep(3), now=NOW,
)
without_geofence = engine.evaluate([ev("zeek_lateral_scan", value=1)], rep(3), now=NOW)
check("REGRESSION GUARD: geofencing_violation evidence never inflates the "
      "independent-attack-source count for an UNRELATED attack hypothesis -- a "
      "destination-policy fact is not real behavioral corroboration",
      with_geofence_only["independent_sources"] == without_geofence["independent_sources"],
      f"got with={with_geofence_only['independent_sources']} without={without_geofence['independent_sources']}")
check("REGRESSION GUARD: that same unrelated attack hypothesis (single family, malicious_ja3 "
      "alone) still stays SUSPICIOUS, not HIGH, even with a co-occurring geofencing_violation",
      with_geofence_only["state"] != DecisionState.HIGH,
      f"got state={with_geofence_only['state']}")

# --- registry pluggability: the actual structural point of this rewrite ---
custom_rule = HardStopRule(
    name="custom_test_rule", explanation="Custom Test Hard-Stop", confidence=1.0,
    decision_path="hard_stop",
    check=lambda ev_store, features, is_safe, now: any(e.evidence_type == "custom_marker" for e in ev_store),
)
custom_engine = DecisionEngine(hard_stop_registry=[custom_rule])
r_custom = custom_engine.evaluate([ev("custom_marker")], rep(3), now=NOW)
check("a completely custom hard-stop rule, swapped in via the registry with zero code changes "
      "to evaluate() itself, fires correctly -- the actual point of the pluggable-registry redesign",
      r_custom["state"] == DecisionState.CRITICAL and r_custom["explanation"] == "Custom Test Hard-Stop")

r_custom_no_default = custom_engine.evaluate([ev("arp_spoofing", timestamp=NOW - 5)], rep(3), now=NOW)
check("a custom registry that omits arp_spoof entirely means arp_spoofing evidence no longer "
      "hard-stops at all -- confirms the registry is genuinely swappable, not just additive",
      r_custom_no_default["decision_path"] != "hard_stop")

# --- winning_evidence (BUGFIX, live audit 2026-09-09): pipeline.py's alert-building
# step needs the REAL evidence that satisfied the winning hypothesis (destination +
# features), not just the hypotheses dict/reasoning_trail strings it already had --
# see pipeline.py's own COORDINATED_TARGETING/PEER_COHORT_DEVIATION attribution
# branches (src/core/pipeline.py) for the consuming side that motivated this.
# UPDATED 2026-09-11 (destination-linkage generalization, see the attack_evidence
# checks below): zeek_notice_medium's destination changed from
# "unrelated-destination.example" to "evil-dga.example" (the DGA evidence's own
# destination) -- the ORIGINAL version of this test asserted that a different
# hypothesis's evidence about a genuinely UNRELATED destination should still
# count as independent corroboration, which is exactly the bug a real
# PEER_COHORT_DEVIATION alert exposed live (three evidence items about three
# unrelated destinations all counted as "independent sources" for a verdict
# about none of them). This scenario's actual point -- a different hypothesis's
# own evidence type still counting toward attack_evidence/independent_sources,
# just excluded from winning_evidence -- only holds when that evidence is
# genuinely ABOUT the same real-world destination the winning evidence is.
r_we = engine.evaluate(
    [ev("dns_dga_burst", value=1.0, confidence=0.95, dest="evil-dga.example"),
     ev("dns_rate", value=150.0, confidence=1.0, dest=NO_DESTINATION),
     ev("zeek_notice_medium", value=1.0, dest="evil-dga.example")],
    rep(3), now=NOW,
)
check("winning_evidence is populated for an attack-hypothesis-driven verdict",
      len(r_we["winning_evidence"]) > 0, f"got {r_we['winning_evidence']}")
check("winning_evidence is scoped to the WINNING hypothesis's own RELEVANT_EVIDENCE_TYPES -- "
      "the unrelated zeek_notice_medium evidence (a different hypothesis's own evidence type) is excluded",
      all(w["evidence_type"] in ("dns_dga_burst", "dns_rate") for w in r_we["winning_evidence"])
      and not any(w["evidence_type"] == "zeek_notice_medium" for w in r_we["winning_evidence"]),
      f"got {r_we['winning_evidence']}")
check("winning_evidence carries the real destination_id for the evidence that has one",
      any(w["destination_id"] == "evil-dga.example" for w in r_we["winning_evidence"]),
      f"got {r_we['winning_evidence']}")

r_we_benign = engine.evaluate([], rep(3), now=NOW)
check("winning_evidence is empty (not crashing) when no attack hypothesis wins at all",
      r_we_benign["winning_evidence"] == [])

# --- REGRESSION GUARD (found live, checking a real sent Telegram alert -- this exact
# scenario silently never worked from the day it was written): winning_evidence must
# include the winning hypothesis's OWN evidence even when that evidence's family is in
# NON_ATTACK_FAMILIES (peer_deviation's own family, peer_cohort_deviation, is excluded
# from CORROBORATION counting -- a different question from whether it should be
# DISPLAYABLE as the winning hypothesis's own reasoning). Without this, pipeline.py's
# "Talked to N distinct destinations vs peer average" behavioral-stat line can never
# fire for a PEER_COHORT_DEVIATION alert, silently falling back to a meaningless
# "Contacted `unknown`" line instead -- confirmed live, every real PEER_COHORT_
# DEVIATION alert this session ever showed exactly that fallback.
peer_dev_ev = Evidence(
    device_id="dev1", destination_id=NO_DESTINATION, evidence_type="peer_deviation",
    independence_family="peer_cohort_deviation", timestamp=NOW, source="s",
    value=42.0, confidence=0.6,
    features={"device_type": "smart_plug", "my_count": 42, "peer_avg": 8.5, "peer_count": 4},
)
r_peer = engine.evaluate([peer_dev_ev], rep(3), now=NOW)
check("REGRESSION GUARD: winning_evidence is NOT empty when PEER_COHORT_DEVIATION wins "
      "-- peer_deviation's own family (peer_cohort_deviation) is excluded from "
      "attack_evidence/corroboration-counting, but must still be displayable",
      len(r_peer["winning_evidence"]) > 0, f"got {r_peer}")
check("REGRESSION GUARD: winning_evidence's peer_deviation entry carries the real "
      "my_count/peer_avg/peer_count/device_type features pipeline.py's behavioral-stat "
      "line needs -- not just present, but with the actual usable data",
      any(w.get("evidence_type") == "peer_deviation"
          and (w.get("features") or {}).get("my_count") == 42
          and (w.get("features") or {}).get("peer_avg") == 8.5
          for w in r_peer["winning_evidence"]),
      f"got {r_peer['winning_evidence']}")

# --- attack_evidence (BUGFIX, live audit 2026-09-09, REAL production alerts): a live
# PEER_COHORT_DEVIATION HIGH alert's PERSISTED hee_evidence_families/
# hee_independent_sources were already correct (4/4, evidence_families fix above) but
# the ACTUAL SENT TELEGRAM TEXT still showed only 1 -- sometimes 0 -- families, because
# pipeline.py's WHY-block bridge only used winning_evidence (scoped to the WINNING
# hypothesis's own RELEVANT_EVIDENCE_TYPES -- for PEER_COHORT_DEVIATION, just
# peer_deviation, missing the 3 OTHER real corroborating families). Unlike
# winning_evidence, attack_evidence must include EVERY family independent_sources
# counts against, not just the winning hypothesis's own slice -- reusing the SAME r_we
# scenario above: zeek_notice_medium (network_behavior) is a DIFFERENT hypothesis's own
# evidence type (NetworkIntrusionHypothesis, not DGA_BOTNET_C2 which won here), excluded
# from winning_evidence but MUST be present in attack_evidence since it's a real,
# counted corroborating source (independent_sources==2, dns_behavior+network_behavior)
# -- ABOUT THE SAME real-world destination as the winning evidence (see r_we's own
# updated comment above; a genuinely unrelated destination is covered separately below).
check("attack_evidence includes EVERY corroborating family, not just the winning "
      "hypothesis's own slice -- zeek_notice_medium (a DIFFERENT hypothesis's evidence type) "
      "must be present even though winning_evidence correctly excludes it",
      any(w["evidence_type"] == "zeek_notice_medium" for w in r_we["attack_evidence"]),
      f"got {r_we['attack_evidence']}")
check("attack_evidence's length matches independent_sources's own family count exactly "
      "(one entry per distinct independence_family among {dns_dga_burst/dns_rate -> "
      "dns_behavior, zeek_notice_medium -> network_behavior})",
      len({w['independence_family'] for w in r_we["attack_evidence"]}) == r_we["independent_sources"] == 2,
      f"got attack_evidence={r_we['attack_evidence']} independent_sources={r_we['independent_sources']}")
check("each attack_evidence entry carries its own independence_family directly -- "
      "pipeline.py's WHY-block bridge needs no separate type-to-family mapping",
      all("independence_family" in w and w["independence_family"] for w in r_we["attack_evidence"]))

r_ae_benign = engine.evaluate([], rep(3), now=NOW)
check("attack_evidence is an empty list (not crashing) when there's no evidence at all",
      r_ae_benign["attack_evidence"] == [])

# BUGFIX regression (live audit, 2026-09-09): attack_evidence's serialized dict used
# to drop provenance entirely -- a zeek_notice item reaching pipeline.py's WHY-block
# through THIS bridge (real corroborating evidence, not the winning hypothesis's own
# slice) lost the real Notice::Type + weak/medium/strong/highly_deterministic tier
# subtag zeek_network.py encodes there, showing the generic "Zeek policy notice fired
# for this connection" instead -- confirmed live, the SAME evidence shape showed the
# real note type correctly via winning_evidence/active_evidence but not via this path.
# UPDATED 2026-09-11: destination matches the DGA evidence's own (same reasoning
# as r_we above) -- this test is about provenance preservation, not destination
# matching, so the destination just needs to clear the (separately tested)
# destination-linkage bar, not be the thing under test here.
r_ae_prov = engine.evaluate(
    [ev("dns_dga_burst", value=1.0, confidence=0.95, dest="evil-dga.example"),
     ev("zeek_notice_medium", value=1.0, dest="evil-dga.example",
        provenance="detector:zeek:notice:SSL::Invalid_Server_Cert")],
    rep(3), now=NOW,
)
check("REGRESSION GUARD: attack_evidence's zeek_notice_medium entry carries the real "
      "provenance (note type -- the tier itself now lives in evidence_type, not "
      "dropped at serialization",
      any(w["evidence_type"] == "zeek_notice_medium"
          and w.get("provenance") == "detector:zeek:notice:SSL::Invalid_Server_Cert"
          for w in r_ae_prov["attack_evidence"]),
      f"got {r_ae_prov['attack_evidence']}")

# --- destination-linkage generalization (BUGFIX, 2026-09-11, user-identified from a
# real Telegram alert): the ORIGINAL Gap-64 fix only ever checked reputation-family
# evidence, and only ran at all when the winning hypothesis's own evidence carried a
# destination. Same r_we scenario as above, but zeek_notice_medium now points at a
# genuinely DIFFERENT destination than the winning dns_dga_burst evidence -- must be
# excluded from attack_evidence/independent_sources, not just reputation-family items.
r_unrelated_dest = engine.evaluate(
    [ev("dns_dga_burst", value=1.0, confidence=0.95, dest="evil-dga.example"),
     ev("dns_rate", value=150.0, confidence=1.0, dest=NO_DESTINATION),
     ev("zeek_notice_medium", value=1.0, dest="totally-unrelated-domain.example")],
    rep(3), now=NOW,
)
check("a non-reputation-family item (zeek_notice_medium/network_behavior) pointing at a "
      "genuinely UNRELATED destination is now excluded from attack_evidence too -- the "
      "original Gap-64 fix only ever checked reputation-family items for this",
      not any(w["evidence_type"] == "zeek_notice_medium" for w in r_unrelated_dest["attack_evidence"]),
      f"got {r_unrelated_dest['attack_evidence']}")
check("independent_sources correctly drops to 1 (dns_behavior alone) once the "
      "unrelated-destination network_behavior item is excluded",
      r_unrelated_dest["independent_sources"] == 1,
      f"got {r_unrelated_dest['independent_sources']}")

# --- destination-less winning hypothesis (BUGFIX, 2026-09-11, user-identified from a
# real live PEER_COHORT_DEVIATION alert: 3 evidence items about 3 unrelated
# destinations -- Telegram's IP, Google's IP, a Datacamp IP -- all counted as
# "independent evidence families" for a verdict about none of them). peer_deviation's
# own evidence is ALWAYS destination_id=NO_DESTINATION by construction (it's a pure
# aggregate/volume statistic, not about any one destination) -- hyp_destinations is
# therefore always empty for a PEER_COHORT_DEVIATION-winning cycle, which used to mean
# the whole domain-linkage check silently never engaged at all, letting ANY other
# family's evidence -- about whatever destination it happened to be about -- count
# unfiltered. Fixed: no destination anchor at all now means no destination-carrying
# evidence counts, not "everything counts."
r_peer_unrelated = engine.evaluate(
    [peer_dev_ev,
     ev("dns_evasion_anomaly", value=1.0, dest="telegram-ip.example"),
     ev("zeek_notice_medium", value=1.0, dest="google-ip.example"),
     ev("reputation", value=4.0, dest="datacamp-ip.example")],
    rep(3), now=NOW,
)
check("REAL-WORLD REGRESSION GUARD: a PEER_COHORT_DEVIATION verdict no longer counts "
      "unrelated-destination evidence from other families toward attack_evidence -- "
      "matches the exact live alert shape (3 unrelated destinations, 0 of them actually "
      "explaining the peer-deviation finding) that exposed this bug",
      len(r_peer_unrelated["attack_evidence"]) == 0,
      f"got {r_peer_unrelated['attack_evidence']}")
check("REAL-WORLD REGRESSION GUARD: independent_sources for that same alert drops to 0 "
      "(peer_deviation's own family, peer_cohort_deviation, is itself in "
      "NON_ATTACK_FAMILIES and was never counted) -- previously reported 3",
      r_peer_unrelated["independent_sources"] == 0,
      f"got {r_peer_unrelated['independent_sources']}")

# --- weak-tier zeek_notice exclusion (BUGFIX, 2026-09-11, user-identified: "should
# weak zeek notices count in HEE?"): NetworkIntrusionHypothesis's own scoring already
# treats a weak-tier notice as worth exactly zero (_zeek_notice_weight(), utils.py's
# ZEEK_NOTICE_TIER_SCORE_WEIGHT["weak"]=0.0 -- a TCP-capture/protocol-edge-case
# artifact, not attacker behavior), but attack_evidence/independent_sources never
# checked this, so a notice contributing NOTHING to attack_score could still pad the
# independent-source count.
r_weak_notice = engine.evaluate(
    [ev("malicious_ja3", value=1.0, dest="c2.example"),
     ev("zeek_notice_weak", value=1.0, dest="c2.example")],
    rep(3), now=NOW,
)
check("a weak-tier zeek_notice does NOT count toward attack_evidence/independent_sources "
      "even when it points at the SAME destination as the winning evidence -- it "
      "contributes zero to the hypothesis's own score (NetworkIntrusionHypothesis's "
      "_zeek_notice_weight()), so it must not count as corroboration either",
      not any(w["evidence_type"] == "zeek_notice_weak" for w in r_weak_notice["attack_evidence"])
      and r_weak_notice["independent_sources"] == 1,
      f"got attack_evidence={r_weak_notice['attack_evidence']} independent_sources={r_weak_notice['independent_sources']}")

r_medium_notice = engine.evaluate(
    [ev("malicious_ja3", value=1.0, dest="c2.example"),
     ev("zeek_notice_medium", value=1.0, dest="c2.example")],
    rep(3), now=NOW,
)
check("REGRESSION GUARD: a MEDIUM-tier zeek_notice on the same destination still counts "
      "normally (only weak is excluded) -- confirms this is a tier-specific fix, not a "
      "blanket zeek_notice exclusion",
      any(w["evidence_type"] == "zeek_notice_medium" for w in r_medium_notice["attack_evidence"])
      and r_medium_notice["independent_sources"] == 1,  # B6: JA3 + notice are both Zeek-derived = one source
      f"got attack_evidence={r_medium_notice['attack_evidence']} independent_sources={r_medium_notice['independent_sources']}")

# BUGFIX regression (live audit, 2026-09-10): the bare "zeek_notice" evidence_type
# (pre-fragmentation, still valid within the 24h graph window right after the
# 2026-09-09 deploy) used to fall through to UNKNOWN_FAMILY ("unregistered")
# instead of its real family "network_behavior" -- confirmed live: a real alert
# counted an old bare zeek_notice row as a SEPARATE "unregistered" independent
# source from a different (correctly-tiered) zeek_notice item in the SAME alert
# that's actually the same underlying vantage point, inflating independent_sources
# with a phantom extra family.
# UPDATED 2026-09-11: destination changed from "unrelated-destination.example" to
# NO_DESTINATION -- neither piece of evidence here belongs to any hypothesis that
# ends up winning (dns_rate is ADVERTISING_BURST's own, a benign hypothesis; bare
# "zeek_notice" isn't in NetworkIntrusionHypothesis's own RELEVANT_EVIDENCE_TYPES
# -- only the 4 tiered variants are), so no attack hypothesis wins and
# hyp_destinations has nothing to anchor against either way (this test is about
# family-collapsing/UNKNOWN_FAMILY fallback correctness, not destination
# matching -- matches this scenario's own "same underlying vantage point"
# framing, a network-level observation, not about one specific destination).
r_old_zn = engine.evaluate(
    [ev("dns_rate", value=150.0, confidence=1.0, dest=NO_DESTINATION),
     ev("zeek_notice", value=1.0, dest=NO_DESTINATION)],
    rep(3), now=NOW,
)
check("REGRESSION GUARD: bare 'zeek_notice' (old, pre-fragmentation evidence_type) "
      "still resolves to its real family 'network_behavior', not the "
      "'unregistered' UNKNOWN_FAMILY fallback",
      any(w["evidence_type"] == "zeek_notice" and w["independence_family"] == "network_behavior"
          for w in r_old_zn["attack_evidence"]),
      f"got {r_old_zn['attack_evidence']}")
check("REGRESSION GUARD: that same bare 'zeek_notice' item does NOT create a "
      "phantom extra independence family alongside a real network_behavior hit "
      "-- both collapse into the SAME family, not two",
      r_old_zn["evidence_families"] == ["dns_behavior", "network_behavior"],
      f"got {r_old_zn['evidence_families']}")

# --- evidence_families/evidence_types (BUGFIX, live audit 2026-09-09, third-party
# ChatGPT review of real production alerts): pipeline.py's persisted
# hee_evidence_families/hee_evidence_types were ALWAYS recomputed independently from
# active_evidence (pipeline.py's own v1 evidence store), which structurally never
# contains v13-only synthetic evidence -- confirmed live, 34 of 121 real alerts in a
# 24h sample showed hee_evidence_families=[] (empty) while hee_independent_sources
# correctly showed 2-4, every one COORDINATED_TARGETING/PEER_COHORT_DEVIATION. These
# two fields are the ground truth independent_sources itself counts against -- must
# never be empty when independent_sources > 0.
r_ef = engine.evaluate(
    [ev("dns_dga_burst", value=1.0, confidence=0.95, dest="evil-dga.example"),
     ev("reputation", value=4.0, dest="evil-dga.example")],
    rep(3), now=NOW,
)
check("REGRESSION GUARD: evidence_families is never empty when independent_sources > 0 "
      "-- the exact 'HIGH with 0 evidence families' inconsistency flagged externally "
      "against real production alerts, and evidence_families's count always matches "
      "independent_sources exactly (same underlying set)",
      len(r_ef["evidence_families"]) == r_ef["independent_sources"] and r_ef["independent_sources"] > 0,
      f"got evidence_families={r_ef['evidence_families']} independent_sources={r_ef['independent_sources']}")

r_ef_empty = engine.evaluate([], rep(3), now=NOW)
check("evidence_families/evidence_types are empty lists (not crashing) when there's no evidence at all",
      r_ef_empty["evidence_families"] == [] and r_ef_empty["evidence_types"] == []
      and r_ef_empty["independent_sources"] == 0)

# --- hypothesis_destination_ids (2026-09-16, live alert audit -- FireTV/a4544eb6d2ca
# COORDINATED_TARGETING, user-flagged): exposes the SAME hyp_destinations this function
# already computes for its own Gap-64 destination-linkage filtering above, so
# pipeline.py's WHY-block construction can apply the identical check to what it
# DISPLAYS -- previously only the SCORING path (attack_evidence/independent_sources)
# had this; the display path (pipeline.py's active_evidence loop) had no way to know
# which destination(s) the winning hypothesis actually verified.
check("hypothesis_destination_ids carries the SAME anchor evidence_families was "
      "filtered against -- the real evil-dga.example destination from r_ef above",
      r_ef["hypothesis_destination_ids"] == ["evil-dga.example"],
      f"got {r_ef['hypothesis_destination_ids']}")
check("hypothesis_destination_ids is an empty list (not crashing, not None) when "
      "there's no winning attack hypothesis to anchor against at all",
      r_ef_empty["hypothesis_destination_ids"] == [])

# --- INVARIANT BATTERY (third-party architecture review, item #11: "enforce
# HIGH/CRITICAL invariants in code") -- rather than trusting the branch logic by
# convention, assert the two central rules directly against a battery of varied
# scenarios: HIGH always requires >=2 independent families, and CRITICAL never
# comes from a path weaker than that (either a genuine deterministic hard-stop, a
# curated-feed verified_ioc, or a tier5_corroborated path itself now gated on
# >=2 families). If a future change weakens either bar, one of these fails. ---
_DETERMINISTIC_CRITICAL_PATHS = {"hard_stop", "tier5_confirmed"}

_invariant_scenarios = [
    ("empty evidence, tier 3", [], rep(3)),
    ("single dns_behavior family only", [ev("dns_dga_burst", value=1, confidence=0.95)], rep(3)),
    ("single network_behavior family only", [ev("zeek_notice_medium")], rep(3)),
    ("two genuinely different families", [ev("malicious_ja3"), ev("zeek_notice_medium")], rep(3)),
    ("three genuinely different families",
     [ev("malicious_ja3"), ev("zeek_notice_medium"), ev("reputation", value=5.0)], rep(3)),
    ("tier 5 unverified, single family", [ev("zeek_notice_medium")], rep(5, verified_ioc=False)),
    ("tier 5 unverified, two families", [ev("malicious_ja3"), ev("zeek_notice_medium")], rep(5, verified_ioc=False)),
    ("tier 5 verified_ioc, no evidence", [], rep(5, verified_ioc=True)),
    ("fresh honeypot feature, no evidence", [], rep(3)),
    ("fresh arp_spoofing hard-stop", [ev("arp_spoofing", timestamp=NOW - 5)], rep(3)),
    ("stale arp_spoofing (past freshness)", [ev("arp_spoofing", timestamp=NOW - 500)], rep(3)),
    ("geofence alone, no corroboration",
     [ev("geofencing_violation", timestamp=NOW - 5)], rep(3)),
    ("geofence + one corroborating family",
     [ev("geofencing_violation", timestamp=NOW - 5, dest="bad.example.com"),
      ev("malicious_ja3", timestamp=NOW - 5, dest="bad.example.com")], rep(3)),
    # ADDED 2026-09-12: closes the exact gap that let a lone Suricata match
    # self-satisfy its own requires_corroboration bar (own_families bugfix) --
    # this scenario would have caught it generically, the same way "geofence
    # alone" above already guards geofence's own corroboration requirement.
    ("suricata alone, no corroboration (>=0.9 confidence)",
     [ev("suricata_signature_match", timestamp=NOW - 5, confidence=0.95)], rep(3)),
    ("suricata + one corroborating family",
     [ev("suricata_signature_match", timestamp=NOW - 5, confidence=0.95, dest="bad.example.com"),
      ev("zeek_lateral_scan", timestamp=NOW - 5, dest="bad.example.com")], rep(3)),
    ("local_device_discovery only (non-attack family)", [ev("local_device_discovery", value=1)], rep(3)),
    ("trusted tier (1) with otherwise-strong evidence",
     [ev("malicious_ja3"), ev("zeek_notice_medium")], rep(1)),
]

for label, evidence, rep_vec in _invariant_scenarios:
    r = engine.evaluate(evidence, rep_vec, features={"zeek_honeypot_hits": 1} if label.startswith("fresh honeypot") else None, now=NOW)
    if r["state"] == DecisionState.HIGH:
        # geofence_uncorroborated/suricata_uncorroborated are legitimate exceptions:
        # both are a downgrade FROM a deterministic hard-stop fact (a confirmed
        # GeoIP blocklist match / a curated-ruleset signature match), not an
        # escalation via the hypothesis-driven corroboration path -- a real,
        # already-verified fact standing alone is not the "unusual is not
        # malicious" gap this invariant otherwise guards against. UPDATED
        # 2026-09-12: added suricata_uncorroborated alongside geofence_uncorroborated
        # -- both HardStopRule.requires_corroboration paths share this shape.
        is_deterministic_downgrade = r["decision_path"] in ("geofence_uncorroborated", "suricata_uncorroborated")
        check(f"INVARIANT [{label}]: HIGH implies independent_sources >= 2, OR a "
              "deterministic hard-stop fact downgraded rather than escalated",
              r["independent_sources"] >= 2 or is_deterministic_downgrade,
              f"got independent_sources={r['independent_sources']} decision_path={r['decision_path']}")
    if r["state"] == DecisionState.CRITICAL:
        is_deterministic_path = r["decision_path"] in _DETERMINISTIC_CRITICAL_PATHS
        is_corroborated_reputation = r["decision_path"] == "tier5_corroborated" and r["independent_sources"] >= 2
        check(f"INVARIANT [{label}]: CRITICAL only via a deterministic hard-stop/verified_ioc, "
              "or tier5_corroborated with independent_sources >= 2",
              is_deterministic_path or is_corroborated_reputation,
              f"got decision_path={r['decision_path']} independent_sources={r['independent_sources']}")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 DecisionEngine checks PASSED.")
