"""
Standalone runtime test for Phase 38 (VERSION 11): comprehensive end-to-end scenario
coverage. Not part of the pytest suite -- run directly:
`python3 tests/test_phase38_comprehensive_scenarios.py`.

Unlike the phase-numbered unit tests elsewhere (each pinned to one specific bugfix),
this file builds realistic, full-cycle MOCKUP scenarios -- real device categories,
real evidence shapes, real reputation contexts -- and runs them through the actual
production classes end-to-end (DecisionEngine -> HypothesisEngine -> individual
Hypothesis subclasses, ReputationClassifier, ThreatSignalDetector, dns_evasion.py,
suricata_scan.py). Nothing here is mocked except raw input data; every assertion is
against the real decision the live system would make for that scenario.

Organized as one section per scenario family, each independently readable:
  A. Benign device telemetry (smart TV / IoT trusted infra)
  B. Benign per-device learned baseline (familiar destination, untrusted tier)
  C. Benign VPN app (no DNS history, real VPN ASN)
  D. Attack: DGA botnet C2
  E. Attack: DNS covert tunneling (real encoded labels + fanout, non-CDN)
  F. Attack: DNS_EVASION / DNS_ATTRIBUTION_GAP / DNS_POLICY_BYPASS naming split
  G. Attack: lateral movement / connection abuse corroboration
  H. Attack: Suricata signature match (hard-stop vs. evidence-only)
  I. Attack: hard-stop conditions (honeypot, ARP spoof, geofence, confirmed exploit)
  J. Reputation tiers (confirmed IOC vs. weak/unconfirmed signal)
  K. Corroboration requirements (single source stays SUSPICIOUS, not HIGH)
  L. Kill-chain phase labeling (SUSPECTED_ prefix)
  M. Payload size classifier (no protocol guessing)
"""
import sys
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.decision_engine import DecisionEngine, DecisionState
from core.pipeline import classify_payload_size
from intelligence.hypotheses.evidence import Evidence, EvidenceStore
from intelligence.reputation.classifier import ReputationClassifier, ReputationVector
from intelligence.detectors.threat_signals import ThreatSignalDetector
from intelligence.detectors.dns_evasion import DeviceBurstAudit, audit_device
from intelligence.detectors.suricata_scan import suricata_alerts_to_evidence
from extractors.dns_features import FeatureExtractor

de = DecisionEngine()
rc = ReputationClassifier()
tsd = ThreatSignalDetector()


def fresh_store(evidence_list, device="dev"):
    s = EvidenceStore()
    for e in evidence_list:
        s.add(e)
    return s.get_for_device(device)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: Benign device telemetry (smart TV / IoT trusted infra)
# ═══════════════════════════════════════════════════════════════════════════════════
# Constructed directly (not via rc.classify()) -- tier assignment by domain string
# match is ReputationClassifier's own concern, already covered elsewhere (Section J
# below, test_phase0_fixes.py); this section is specifically about what
# DeviceProfileBenignHypothesis/decision_engine DO with a tier-2 context, so the
# tier is given directly rather than needing a domain that happens to match.
rep_trusted = ReputationVector(domain="device-metrics-us.amazon.com", tier=2, asn_owner="Amazon.com, Inc.")
tv_evidence = fresh_store([
    Evidence(type="dns_rate", source="pihole", timestamp=time.time(), device="dev", value=35.0,
             confidence=0.8, independence_group="dns_behavior"),
])
decision_tv = de.evaluate(tv_evidence, rep_trusted, device_type="smart_tv")
check("a smart TV's routine high-volume DNS traffic to a known-infrastructure (tier 2) "
      "destination resolves BENIGN with a named explanation, not a generic fallback",
      decision_tv["state"] == "BENIGN" and decision_tv["explanation"] == "DEVICE_PROFILE_TELEMETRY",
      f"got {decision_tv['state']}/{decision_tv['explanation']}")

laptop_decision = de.evaluate(tv_evidence, rep_trusted, device_type="laptop")
check("REGRESSION GUARD: the SAME evidence on a laptop (not an expected-high-volume "
      "category) falls through to the generic UNKNOWN_BENIGN, not DEVICE_PROFILE_TELEMETRY",
      laptop_decision["explanation"] == "UNKNOWN_BENIGN", f"got {laptop_decision['explanation']}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: Benign per-device learned baseline (VERSION 11) -- a destination this
# device has personally talked to repeatedly, even without a global trust tier.
# ═══════════════════════════════════════════════════════════════════════════════════
rep_unclassified = rc.classify("some-iot-vendor-api.example", vt_score=0.0, ti_score=0.0, abuse_score=0.0, asn_owner="Unknown")
familiar_evidence = fresh_store([
    Evidence(type="dns_rate", source="pihole", timestamp=time.time(), device="dev", value=25.0,
             confidence=0.8, independence_group="dns_behavior"),
])
decision_no_familiarity = de.evaluate(familiar_evidence, rep_unclassified, device_type="iot", baseline_familiarity=0.0)
check("an unclassified (tier 3) destination with ZERO learned familiarity does NOT "
      "get DEVICE_PROFILE_TELEMETRY -- familiarity has to actually be earned",
      decision_no_familiarity["explanation"] != "DEVICE_PROFILE_TELEMETRY", f"got {decision_no_familiarity['explanation']}")

decision_with_familiarity = de.evaluate(familiar_evidence, rep_unclassified, device_type="iot", baseline_familiarity=0.8)
check("THE NEW FEATURE: the SAME unclassified destination, once this device has a "
      "high learned familiarity with it (repeated benign history), DOES resolve "
      "DEVICE_PROFILE_TELEMETRY -- a per-device learned pattern, not a global tier",
      decision_with_familiarity["state"] == "BENIGN" and decision_with_familiarity["explanation"] == "DEVICE_PROFILE_TELEMETRY",
      f"got {decision_with_familiarity['state']}/{decision_with_familiarity['explanation']}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: Benign VPN app (real captured traffic, zero DNS history, real VPN ASN)
# ═══════════════════════════════════════════════════════════════════════════════════
class _FakeASN:
    def __init__(self, org):
        self.autonomous_system_organization = org


class _FakeGeoIPVpn:
    def lookup_asn(self, ip):
        return _FakeASN("NordVPN S.A.")

    def reverse_dns(self, ip):
        return None


vpn_audit = DeviceBurstAudit(dest_ips={"185.1.2.3"}, queried_domains=set())
vpn_evidence = audit_device("dev_iphone", vpn_audit, geoip_engine=_FakeGeoIPVpn())
check("a legitimate VPN app's tunnel endpoint (real ASN-recognized VPN provider, zero "
      "DNS history) produces NO dns_evasion_anomaly evidence at all -- the exact "
      "iPhone/NordVPN false-positive case this detector was built around",
      vpn_evidence == [])


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: Attack -- DGA botnet C2
# ═══════════════════════════════════════════════════════════════════════════════════
dga_features = {
    "suspicious_domains": 18, "entropy_avg": 3.9,
    "suspicious_domain_examples": ["qwertyuiopasdfghjklzxcvbnm382.attacker-c2.ru"],
    "dns_rate": 40.0,
}
dga_evidence_list = tsd.detect("dev_dga", dga_features, top_domain="qwertyuiopasdfghjklzxcvbnm382.attacker-c2.ru")
dga_store = fresh_store(dga_evidence_list, "dev_dga")
rep_unknown_ru = rc.classify("qwertyuiopasdfghjklzxcvbnm382.attacker-c2.ru", vt_score=0.0, ti_score=0.0, abuse_score=0.0, asn_owner="Unknown Hosting LLC")
decision_dga = de.evaluate(dga_store, rep_unknown_ru)
check("a genuine DGA-shaped domain burst (18 suspicious domains, high entropy, "
      "non-telemetry, unrecognized hosting) is flagged DGA_BOTNET_C2",
      decision_dga["explanation"] == "DGA_BOTNET_C2" and decision_dga["hypotheses"]["attack"]["score"] > 0,
      f"got {decision_dga}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: Attack -- DNS covert tunneling (real encoded labels + fanout, non-CDN)
# ═══════════════════════════════════════════════════════════════════════════════════
tunnel_features = {
    "max_label_length": 61,
    "max_label_domain": "9f82ab7c3e1d5a90bcf2e14d.attacker-tunnel.net",
    "dns_tunneling_domains": 4,
    "dns_tunneling_domain_examples": ["9f82ab7c3e1d5a90bcf2e14d.attacker-tunnel.net"],
    "subdomain_fanout_count": 12,
    "subdomain_fanout_domain": "attacker-tunnel.net",
    "fanout_label_entropy": 4.1,
}
tunnel_evidence_list = tsd.detect("dev_tunnel", tunnel_features, top_domain="attacker-tunnel.net")
tunnel_store = fresh_store(tunnel_evidence_list, "dev_tunnel")
rep_unknown_tunnel = rc.classify("attacker-tunnel.net", vt_score=0.0, ti_score=0.0, abuse_score=0.0, asn_owner="Unknown")
decision_tunnel = de.evaluate(tunnel_store, rep_unknown_tunnel)
check("real encoded-label + high-entropy-fanout evidence on a non-CDN, unrecognized "
      "domain is flagged DNS_COVERT_TUNNELING",
      decision_tunnel["explanation"] == "DNS_COVERT_TUNNELING", f"got {decision_tunnel}")

# Same shape, but on a recognized CDN/telemetry domain -- must NOT fire.
cdn_tunnel_features = dict(tunnel_features)
cdn_tunnel_features["max_label_domain"] = "9f82ab7c3e1d5a90bcf2e14d.us-east-1.cloudfront.net"
cdn_tunnel_features["dns_tunneling_domain_examples"] = ["9f82ab7c3e1d5a90bcf2e14d.us-east-1.cloudfront.net"]
cdn_tunnel_features["subdomain_fanout_domain"] = "cloudfront.net"
cdn_tunnel_evidence_list = tsd.detect("dev_cdn", cdn_tunnel_features, top_domain="somewhere-else.com")
check("REGRESSION GUARD: the identical shape on recognized CDN infrastructure "
      "(cloudfront.net) produces NO dns_tunnel_v2 evidence",
      not any(e.type == "dns_tunnel_v2" for e in cdn_tunnel_evidence_list),
      f"got {cdn_tunnel_evidence_list}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: Attack -- DNS_EVASION / DNS_ATTRIBUTION_GAP / DNS_POLICY_BYPASS naming
# ═══════════════════════════════════════════════════════════════════════════════════
class _FakeGeoIPUnknown:
    def lookup_asn(self, ip):
        return None

    def reverse_dns(self, ip):
        return None


# F1: genuinely zero DNS footprint -> strong DNS_EVASION
no_dns_audit = DeviceBurstAudit(dest_ips={"66.66.66.66"}, queried_domains=set())
no_dns_ev = audit_device("dev_no_dns", no_dns_audit, geoip_engine=_FakeGeoIPUnknown())
check("a device with real traffic and ZERO DNS history produces dns_evasion_anomaly "
      "tagged for the strong DNS_EVASION name",
      len(no_dns_ev) == 1 and "no_dns_history" in no_dns_ev[0].provenance, f"got {no_dns_ev}")

# F2: otherwise-normal DNS history, one connection outlives its window -> weaker gap
partial_gap_audit = DeviceBurstAudit(dest_ips={"66.66.66.67"}, queried_domains={"normal-site.com"})
partial_gap_ev = audit_device("dev_partial", partial_gap_audit, geoip_engine=_FakeGeoIPUnknown())
check("a device with SOME normal DNS history and one unexplained connection is "
      "tagged for the weaker DNS_ATTRIBUTION_GAP name",
      len(partial_gap_ev) == 1 and "partial_attribution_gap" in partial_gap_ev[0].provenance,
      f"got {partial_gap_ev}")

# F3: direct port-53 bypass -> DNS_POLICY_BYPASS
policy_bypass_audit = DeviceBurstAudit(dest_ips={"66.66.66.68"}, queried_domains={"normal-site.com"},
                                        dest_ports={"66.66.66.68": 53})
policy_bypass_ev = audit_device("dev_bypass", policy_bypass_audit, geoip_engine=_FakeGeoIPUnknown())
check("a direct UDP/53 connection to a non-Pi-hole, non-public-resolver IP is tagged "
      "for the most specific name, DNS_POLICY_BYPASS",
      len(policy_bypass_ev) == 1 and "policy_bypass" in policy_bypass_ev[0].provenance,
      f"got {policy_bypass_ev}")

# End-to-end: verify the hypothesis actually picks the right name for each.
from intelligence.hypotheses.engine import DNSEvasionHypothesis
hyp_f = DNSEvasionHypothesis()
neutral_rep_f = ReputationVector(domain="", tier=3)
hyp_f.evaluate(no_dns_ev, neutral_rep_f)
check("END-TO-END: no_dns_history evidence -> DNSEvasionHypothesis.name == DNS_EVASION",
      hyp_f.name == "DNS_EVASION", f"got {hyp_f.name}")
hyp_f.evaluate(partial_gap_ev, neutral_rep_f)
check("END-TO-END: partial_attribution_gap evidence -> DNSEvasionHypothesis.name == DNS_ATTRIBUTION_GAP",
      hyp_f.name == "DNS_ATTRIBUTION_GAP", f"got {hyp_f.name}")
hyp_f.evaluate(policy_bypass_ev, neutral_rep_f)
check("END-TO-END: policy_bypass evidence -> DNSEvasionHypothesis.name == DNS_POLICY_BYPASS",
      hyp_f.name == "DNS_POLICY_BYPASS", f"got {hyp_f.name}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section G: Attack -- lateral movement / connection abuse corroboration
# ═══════════════════════════════════════════════════════════════════════════════════
lateral_evidence = fresh_store([
    Evidence(type="zeek_lateral_scan", source="zeek", timestamp=time.time(), device="dev_scan",
             value=5.0, confidence=0.9, independence_group="zeek_network"),
    Evidence(type="arp_sweep", source="threat_signals", timestamp=time.time(), device="dev_scan",
             value=12.0, confidence=0.7, independence_group="lan_recon"),
], "dev_scan")
rep_neutral_scan = ReputationVector(domain="", tier=3)
decision_scan = de.evaluate(lateral_evidence, rep_neutral_scan)
check("a genuine multi-target lateral scan CORROBORATED by an ARP host-discovery "
      "sweep (2 independent evidence families) reaches HIGH",
      decision_scan["state"] == "HIGH", f"got {decision_scan}")

single_source_scan = fresh_store([
    Evidence(type="zeek_lateral_scan", source="zeek", timestamp=time.time(), device="dev_scan2",
             value=5.0, confidence=0.9, independence_group="zeek_network"),
], "dev_scan2")
decision_single_scan = de.evaluate(single_source_scan, rep_neutral_scan)
check("REGRESSION GUARD: the SAME lateral-scan evidence with only ONE independent "
      "source stays SUSPICIOUS (monitor), not HIGH (block-worthy) -- corroboration "
      "still required",
      decision_single_scan["state"] == "SUSPICIOUS", f"got {decision_single_scan}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section H: Attack -- Suricata signature match (hard-stop vs. evidence-only)
# ═══════════════════════════════════════════════════════════════════════════════════
high_sev_alerts = [{"src_ip": "192.168.1.60", "dest_ip": "203.0.113.99",
                     "alert": {"signature": "ET MALWARE Win32/Generic C2", "signature_id": 5001,
                               "category": "A Network Trojan was detected", "severity": 1}}]
high_sev_ev = suricata_alerts_to_evidence(high_sev_alerts, {"192.168.1.60": "dev_malware"}, time.time())
decision_malware = de.evaluate(high_sev_ev["dev_malware"], ReputationVector(domain="", tier=3))
check("a real severity=1 Suricata signature match is a CRITICAL hard-stop end-to-end",
      decision_malware["state"] == "CRITICAL" and decision_malware["explanation"] == "Confirmed Exploit/Malware Signature (Suricata)",
      f"got {decision_malware}")

low_sev_alerts = [{"src_ip": "192.168.1.61", "dest_ip": "203.0.113.98",
                    "alert": {"signature": "ET INFO Generic Suspicious", "signature_id": 5002,
                              "category": "Misc", "severity": 3}}]
low_sev_ev = suricata_alerts_to_evidence(low_sev_alerts, {"192.168.1.61": "dev_weak_sig"}, time.time())
decision_weak_sig = de.evaluate(low_sev_ev["dev_weak_sig"], ReputationVector(domain="", tier=3))
check("REGRESSION GUARD: a low-severity Suricata match is real evidence (SUSPICIOUS) "
      "but does NOT hard-stop on its own",
      decision_weak_sig["state"] == "SUSPICIOUS" and decision_weak_sig["state"] != "CRITICAL",
      f"got {decision_weak_sig}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section I: Attack -- other hard-stop conditions
# ═══════════════════════════════════════════════════════════════════════════════════
honeypot_ev = fresh_store([Evidence(type="honeypot_access", source="zeek", timestamp=time.time(),
                                     device="dev_hp", value=1.0, confidence=1.0, independence_group="honeypot")], "dev_hp")
check("honeypot access is a CRITICAL hard-stop",
      de.evaluate(honeypot_ev, ReputationVector(domain="", tier=3))["state"] == "CRITICAL")

arp_ev = fresh_store([Evidence(type="arp_spoofing", source="zeek", timestamp=time.time(),
                                device="dev_arp", value=10.0, confidence=1.0, independence_group="zeek_network")], "dev_arp")
check("verified ARP spoofing (real MAC-flip evidence) is a CRITICAL hard-stop",
      de.evaluate(arp_ev, ReputationVector(domain="", tier=3))["state"] == "CRITICAL")

geofence_ev = fresh_store([Evidence(type="geofencing_violation", source="geoip", timestamp=time.time(),
                                     device="dev_geo", value=1.0, confidence=1.0, independence_group="reputation")], "dev_geo")
check("a geofencing policy violation is a CRITICAL hard-stop",
      de.evaluate(geofence_ev, ReputationVector(domain="", tier=3))["state"] == "CRITICAL")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section J: Reputation tiers -- confirmed IOC vs. weak/unconfirmed signal
# ═══════════════════════════════════════════════════════════════════════════════════
rep_confirmed_ioc = rc.classify("actually-malicious-c2.example", vt_score=0.0, ti_score=3.5, abuse_score=0.0, asn_owner="Unknown")
decision_confirmed = de.evaluate([], rep_confirmed_ioc)
check("a genuine ThreatIntel IOC match (ti_score=3.5, above the 2.0 confirmed bar) "
      "reaches CRITICAL / Confirmed Malicious IOC even with zero behavioral evidence",
      decision_confirmed["state"] == "CRITICAL" and decision_confirmed["explanation"] == "Confirmed Malicious IOC",
      f"got {decision_confirmed}")

rep_weak_telegram_shape = rc.classify("149.154.166.110", vt_score=0.0, ti_score=0.0, abuse_score=3.78, asn_owner="Some Hosting Provider LLC")
decision_weak = de.evaluate([], rep_weak_telegram_shape)
check("GOLDEN CASE: a weak AbuseIPDB-only signal (3.78, below the 4.0 confirmed bar) "
      "on an unclassified IP stays SUSPICIOUS/monitor, never auto-blocks",
      decision_weak["state"] == "SUSPICIOUS" and decision_weak["explanation"] == "Elevated Reputation Signal (Unconfirmed)",
      f"got {decision_weak}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section K: Corroboration requirements -- attack_score alone isn't enough for HIGH
# ═══════════════════════════════════════════════════════════════════════════════════
single_dga_only = fresh_store([
    Evidence(type="dns_dga_burst", source="threat_signals", timestamp=time.time(), device="dev_solo",
             value=20.0, confidence=0.9, independence_group="dns_behavior"),
], "dev_solo")
decision_solo = de.evaluate(single_dga_only, ReputationVector(domain="", tier=3))
check("a strong single-source DGA signal (no corroborating family) stays SUSPICIOUS, "
      "matching every other hypothesis's 2-independent-source bar for HIGH",
      decision_solo["state"] == "SUSPICIOUS", f"got {decision_solo}")

corroborated_dga = fresh_store([
    Evidence(type="dns_dga_burst", source="threat_signals", timestamp=time.time(), device="dev_corrob",
             value=20.0, confidence=0.9, independence_group="dns_behavior"),
    Evidence(type="reputation", source="threat_intel", timestamp=time.time(), device="dev_corrob",
             value=1.5, confidence=0.8, independence_group="reputation"),
], "dev_corrob")
decision_corroborated = de.evaluate(corroborated_dga, ReputationVector(domain="", tier=4))
check("the SAME DGA signal, corroborated by an independent reputation-family hit, "
      "can reach HIGH",
      decision_corroborated["state"] == "HIGH", f"got {decision_corroborated}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section L: Kill-chain phase labeling (VERSION 11, review #22) -- SUSPECTED_ prefix
# ═══════════════════════════════════════════════════════════════════════════════════
fx = FeatureExtractor()
normal_phase = fx._determine_killchain_phase(None, {})
check("a quiet feature set stays NORMAL (no hedging needed for the non-alarming case)",
      normal_phase == "NORMAL", f"got {normal_phase}")

exfil_phase = fx._determine_killchain_phase(None, {"outbound_bytes_z": 0.0, "zeek_outbound_bytes": 60_000_000})
check("a large-outbound-burst feature set returns SUSPECTED_EXFIL, not the bare, "
      "confirmed-sounding EXFIL",
      exfil_phase == "SUSPECTED_EXFIL", f"got {exfil_phase}")

recon_phase = fx._determine_killchain_phase(None, {"nxdomain_ratio": 0.5})
check("a high-NXDOMAIN feature set returns SUSPECTED_RECON",
      recon_phase == "SUSPECTED_RECON", f"got {recon_phase}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section M: Payload size classifier (VERSION 11, review #23) -- no protocol guessing
# ═══════════════════════════════════════════════════════════════════════════════════
check("classify_payload_size(46) no longer claims a protocol ('Standard DNS/Control "
      "Packet') for an arbitrary small TCP/ICMP/whatever packet",
      "DNS" not in classify_payload_size(46) and "Control Packet" not in classify_payload_size(46),
      f"got {classify_payload_size(46)!r}")
check("classify_payload_size(500) no longer claims 'API Metadata'",
      "API" not in classify_payload_size(500) and "Metadata" not in classify_payload_size(500),
      f"got {classify_payload_size(500)!r}")
check("classify_payload_size still describes SIZE correctly (46 bytes)",
      classify_payload_size(46) == "46 B", f"got {classify_payload_size(46)!r}")
check("classify_payload_size still describes SIZE correctly (2.5 MB range)",
      "MB" in classify_payload_size(3_000_000), f"got {classify_payload_size(3_000_000)!r}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 38 comprehensive end-to-end scenario checks PASSED.")
