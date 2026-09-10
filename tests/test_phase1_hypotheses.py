"""
Standalone runtime test for Phase 1 (port scoring.py's signal categories into the live
hypothesis engine). Not part of the pytest suite — run directly:
`python3 test_phase1_hypotheses.py`. Exercises the real ThreatSignalDetector ->
EvidenceStore -> HypothesisEngine -> DecisionEngine chain end-to-end, no mocks.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.detectors.threat_signals import ThreatSignalDetector
from intelligence.hypotheses.evidence import EvidenceStore
from intelligence.hypotheses.engine import HypothesisEngine
from intelligence.reputation.classifier import ReputationClassifier
from core.decision_engine import DecisionEngine, DecisionState

detector = ThreatSignalDetector()
rc = ReputationClassifier()


def run_hypothesis(features, top_domain=None, domain_for_tier="randomdomain12345.biz"):
    """Runs a fresh detect() -> EvidenceStore -> HypothesisEngine cycle in isolation."""
    store = EvidenceStore()
    ev = detector.detect("dev_x", features, top_domain=top_domain)
    for e in ev:
        store.add(e)
    active = store.get_for_device("dev_x")
    rep = rc.classify(domain_for_tier)
    hyp = HypothesisEngine()
    result = hyp.evaluate_all(active, rep)
    return ev, active, result, rep


# ── Test 1: DGA burst detector -> DGAHypothesis ─────────────────────────────────────
dga_features = {"suspicious_domains": 20.0, "entropy_avg": 4.0, "dga_score": 0.0}
ev, active, result, rep = run_hypothesis(dga_features)
check("ThreatSignalDetector emits dns_dga_burst evidence for an absolute burst (sd>=15)",
      any(e.type == "dns_dga_burst" for e in ev), f"evidence types={[e.type for e in ev]}")
check("DGAHypothesis becomes the winning attack hypothesis for a DGA burst",
      result["attack"]["name"] == "DGA_BOTNET_C2", f"got={result['attack']}")
check("DGA burst reaches at least SUSPICIOUS-equivalent score (>=2.0)",
      result["attack"]["score"] >= 2.0)

# BUGFIX regression guard: dns_dga_burst used to be a pure device-wide aggregate with
# NO domain attached at all -- found via a production alerts.json audit showing the
# same displayed "target" domain with wildly different max_label_length across
# consecutive alerts, and the same domain family spread across 6+ unrelated devices
# with zero threat-intel corroboration (both symptoms of this exact attribution gap).
# dns_features.py's compute() now collects real examples from the SAME per-domain loop
# that counts them, mirroring the already-fixed dns_tunneling_domain_examples pattern.
dga_features_no_examples = {"suspicious_domains": 20.0, "entropy_avg": 4.0, "dga_score": 0.0}
ev_no_examples, _, _, _ = run_hypothesis(dga_features_no_examples)
dga_ev_no_examples = [e for e in ev_no_examples if e.type == "dns_dga_burst"]
check("without suspicious_domain_examples present (the pre-fix shape), evidence.domain "
      "stays None rather than crashing -- backward compatible with any caller that "
      "hasn't been updated yet",
      bool(dga_ev_no_examples) and dga_ev_no_examples[0].domain is None)

dga_features_with_examples = {
    "suspicious_domains": 20.0, "entropy_avg": 4.0, "dga_score": 0.0,
    "suspicious_domain_examples": ["xkqz289dfj10dj-224.ru", "xkqz289dfj10dj-393.ru"],
}
ev_with_examples, _, _, _ = run_hypothesis(dga_features_with_examples)
dga_ev_with_examples = [e for e in ev_with_examples if e.type == "dns_dga_burst"]
check("THE CORE FIX: dns_dga_burst evidence now carries a real example domain from "
      "the per-domain loop that actually found it, not None",
      bool(dga_ev_with_examples) and dga_ev_with_examples[0].domain == "xkqz289dfj10dj-224.ru",
      f"got domain={dga_ev_with_examples[0].domain if dga_ev_with_examples else 'NO EVIDENCE'}")

# Confirm it actually reaches DecisionEngine and produces an alertable state
de = DecisionEngine()
decision = de.evaluate(active, rep)
check("DGA burst evidence reaches DecisionEngine and is NOT silently dropped "
      "(this is the core Phase 1 bug: scoring.py computed this but it never reached here)",
      decision["state"] != DecisionState.BENIGN, f"got state={decision['state']}")


# ── Test 2: Exfiltration byte burst -> ExfiltrationHypothesis ──────────────────────
exfil_features = {"outbound_bytes_z": 6.0, "zeek_outbound_bytes": 3_000_000.0}
ev, active, result, rep = run_hypothesis(exfil_features, top_domain="randomupload.example")
check("ThreatSignalDetector emits zeek_exfiltration evidence for a massive outbound burst",
      any(e.type == "zeek_exfiltration" for e in ev))
check("ExfiltrationHypothesis becomes the winning attack hypothesis",
      result["attack"]["name"] == "DATA_EXFILTRATION", f"got={result['attack']}")

# Vendor-cloud-API dampening: the SAME Z-score/bytes profile against a curated vendor
# domain (coinbase.com — in _VENDOR_CLOUD_API_DOMAINS but NOT telemetry-classified) must
# still produce zeek_exfiltration evidence, just at a DAMPENED confidence, not zero.
# BUGFIX (2026-09-10, AUDIT_V14_REVIEW_RESPONSE.md §2.4): this used to be a hard
# `not is_vendor_cloud_api` gate on the "massive burst" branch itself -- for THIS exact
# scenario the vendor case still produced evidence, but only by accident, via `elif`
# fallthrough into the separate "elevated" branch a few lines below (which independently
# dampens to 0.35) -- a vendor case that ALSO failed that second branch's own gate (e.g.
# high absolute volume but a lower z-score) got zero evidence with no fallback left.
# Dampening is now applied directly at the massive-burst tier itself (0.5, not 0.35 --
# deliberately higher than the elevated tier's own dampened value, since the underlying
# signal here is more extreme: z>5 vs z>3.5), so every tier dampens consistently instead
# of only working via incidental fallthrough.
exfil_probe = {"outbound_bytes_z": 6.0, "zeek_outbound_bytes": 3_000_000.0}
ev_nonvendor = detector.detect("dev_x", exfil_probe, top_domain="random-exfil-drop.io")
ev_vendor = detector.detect("dev_x", exfil_probe, top_domain="coinbase.com")
nonvendor_conf = next((e.confidence for e in ev_nonvendor if e.type == "zeek_exfiltration"), None)
vendor_conf = next((e.confidence for e in ev_vendor if e.type == "zeek_exfiltration"), None)
check("non-vendor domain with a massive outbound burst gets full-confidence (0.9) exfiltration evidence",
      nonvendor_conf == 0.9, f"got confidence={nonvendor_conf}")
check("curated vendor-cloud-API domain with the IDENTICAL burst profile is dampened to low "
      "confidence (0.5), not excluded outright and not full-confidence",
      vendor_conf == 0.5, f"got confidence={vendor_conf}")

# BUGFIX (v13 full-architecture plan, Phase 9): zeek_exfiltration's add() calls never
# passed domain= before, unlike dns_tunnel_v2's own add() calls a few lines above in
# the same file -- last_dest_ip is already computed and already used for this same
# evidence's own _is_local_dest() gate, so this is a real destination the Evidence
# item can now carry at the source, not a new computation.
exfil_features_with_dest = {"outbound_bytes_z": 6.0, "zeek_outbound_bytes": 3_000_000.0,
                              "last_dest_ip": "93.184.216.34"}
ev_exfil_dest = detector.detect("dev_exfil_dest", exfil_features_with_dest, top_domain="random-exfil-drop.io")
exfil_ev = next((e for e in ev_exfil_dest if e.type == "zeek_exfiltration"), None)
check("a zeek_exfiltration Evidence item now carries the real destination in .domain "
      "(previously always None, forcing v13's own live_engine.py fallback_context "
      "workaround to fire for every single instance of this evidence type)",
      exfil_ev is not None and exfil_ev.domain == "93.184.216.34")


# ── Test 3: C2 beaconing -> BeaconingHypothesis ─────────────────────────────────────
beacon_features = {"beaconing_c2_1h": 5.0}
ev, active, result, rep = run_hypothesis(beacon_features)
check("ThreatSignalDetector emits zeek_beaconing evidence for low-and-slow C2 periodicity",
      any(e.type == "zeek_beaconing" for e in ev))
check("BeaconingHypothesis becomes the winning attack hypothesis",
      result["attack"]["name"] == "C2_BEACONING", f"got={result['attack']}")

# Same Phase 9 bugfix as zeek_exfiltration above, for zeek_beaconing's own three add()
# call sites.
beacon_features_with_dest = {"beaconing_c2_1h": 5.0, "last_dest_ip": "104.16.132.229"}
ev_beacon_dest = detector.detect("dev_beacon_dest", beacon_features_with_dest)
beacon_ev = next((e for e in ev_beacon_dest if e.type == "zeek_beaconing"), None)
check("a zeek_beaconing Evidence item now carries the real destination in .domain",
      beacon_ev is not None and beacon_ev.domain == "104.16.132.229")


# ── Test 4: DNS covert tunneling (TXT/NULL abuse) -> DNSTunnelingV2Hypothesis ───────
tunnel_features = {"dns_txt_null_ratio": 0.5, "suspicious_tld_ratio": 0.5}
ev, active, result, rep = run_hypothesis(tunnel_features)
check("ThreatSignalDetector emits dns_tunnel_v2 evidence for TXT/NULL + suspicious-TLD abuse",
      sum(1 for e in ev if e.type == "dns_tunnel_v2") >= 2,
      f"evidence={[(e.type, e.provenance) for e in ev]}")
check("DNSTunnelingV2Hypothesis becomes the winning attack hypothesis",
      result["attack"]["name"] == "DNS_COVERT_TUNNELING", f"got={result['attack']}")
check("two distinct tunneling signal categories push DNSTunnelingV2Hypothesis to PROBABLE (3.0)+",
      result["attack"]["score"] >= 3.0, f"score={result['attack']['score']}")


# ── Regression: live production false positive (2026-08-17) ───────────────────────
# api.eu-west-1.aiv-delivery.net (Amazon Prime Video's CDN delivery domain) tripped
# DNS_COVERT_TUNNELING and got auto-blocked in production — Amazon Prime Video edge
# nodes issue long hash/session-token subdomains that look identical to the
# "encoded/long labels" tunneling signal. Root cause: utils.py's CDN/telemetry
# allowlists had "aiv-cdn.net" (Amazon Instant Video's OTHER CDN domain) but not
# "aiv-delivery.net" (this one) — a curated-list gap, not a detector bug. Fixed by
# adding "aiv-delivery.net" alongside "aiv-cdn.net" in utils.py's
# _CDN_PARENT_ALLOWLIST and _SYSTEM_SAFE_BASE_DOMAINS. This locks that fix in.
#
# UPDATED (later phase): threat_signals.py's CDN exemption now checks the evidence's
# OWN domain (max_label_domain/tunnel_domain_examples), not top_domain -- top_domain
# used to double as "the domain this evidence is about" by convention alone, which is
# exactly the bug a later phase fixed for the opposite case (a SAFE evidence domain
# escaping exemption because top_domain was something unrelated). max_label_domain is
# added here to match what dns_features.py's real get_features() always populates
# whenever max_label_length is set (they're written together in the same loop) --
# this test previously relied on top_domain standing in for it, which only worked by
# coincidence before that fix.
aiv_features = {"max_label_length": 62.0, "dns_tunneling_domains": 3.0,
                "max_label_domain": "api.eu-west-1.aiv-delivery.net"}
ev_aiv = detector.detect("dev_x", aiv_features, top_domain="api.eu-west-1.aiv-delivery.net")
check("REGRESSION: Amazon Prime Video's aiv-delivery.net CDN no longer trips "
      "DNS_COVERT_TUNNELING on long/encoded edge-node subdomains",
      len(ev_aiv) == 0, f"got evidence={[(e.type, e.provenance) for e in ev_aiv]}")


# ── Test 5: TCP connection abuse / port scan -> ConnectionAbuseHypothesis ──────────
scan_features = {"zeek_s0_rej_count": 40.0, "zeek_s0_rej_unique_ips": 20.0}
ev, active, result, rep = run_hypothesis(scan_features)
check("ThreatSignalDetector emits zeek_conn_abuse evidence for a port-scan pattern",
      any(e.type == "zeek_conn_abuse" for e in ev))
# VERSION 12 (G7, HEE coverage audit): ConnectionAbuseHypothesis is still the winning
# CLASS -- only its dynamic self.name changed. A zeek_conn_abuse-only finding (no
# arp_sweep/zeek_long_conn alongside it, exactly this scenario) now gets the more
# specific "PORT_SCAN" name instead of the old generic "CONNECTION_ABUSE" (which is
# now reserved for zeek_long_conn-only or multi-category corroborated findings -- see
# hypotheses/engine.py's ConnectionAbuseHypothesis docstring).
check("ConnectionAbuseHypothesis becomes the winning attack hypothesis, named PORT_SCAN "
      "for this single-category (scan-only) evidence shape",
      result["attack"]["name"] == "PORT_SCAN", f"got={result['attack']}")


# ── Test 6: telemetry-domain dampening suppresses the classifier-score DGA branch ──
# apple.com traffic is treated as telemetry-safe by utils.is_telemetry_domain in most
# builds of this codebase's allowlist; use a domain explicitly configured as telemetry-safe
# via the module's own is_telemetry_domain to keep this test resilient to allowlist changes.
#
# UPDATED (later phase): the domain-EXAMPLE-driven branches (suspicious_domains >= 15
# or >= 5-with-entropy, i.e. what dga_features above exercises) no longer use this
# device-wide top_domain-based gate at all -- suspicious_domains itself now excludes
# telemetry domains at the source (dns_features.py's suspicious_dga() call site), so a
# real suspicious_domains=20 count can no longer legitimately consist of telemetry
# domains in the first place. Re-using dga_features (sd=20) with a telemetry
# top_domain here would now be a self-contradictory scenario (that count could never
# arise from telemetry-only domains post-fix) rather than a real regression -- fixed by
# testing the ONE branch that still has no per-domain source protection and therefore
# still needs (and still has) the device-wide gate: the pure classifier-score path.
from utils import is_telemetry_domain
telemetry_probe_domain = "push.apple.com"
classifier_only_features = {"suspicious_domains": 0.0, "entropy_avg": 0.0, "dga_score": 0.75}
if is_telemetry_domain(telemetry_probe_domain):
    ev_telemetry = detector.detect("dev_x", classifier_only_features, top_domain=telemetry_probe_domain)
    check(f"DGA classifier-score evidence is dampened (suppressed) for known-telemetry domain '{telemetry_probe_domain}'",
          not any(e.type == "dns_dga_burst" for e in ev_telemetry))
    ev_non_telemetry = detector.detect("dev_x", classifier_only_features, top_domain="some-unrelated-domain.example")
    check("REGRESSION GUARD: the same classifier-score evidence still fires for a non-telemetry top_domain",
          any(e.type == "dns_dga_burst" for e in ev_non_telemetry))
else:
    print(f"[SKIP] telemetry dampening check — '{telemetry_probe_domain}' not classified as telemetry in this build")


# ── Test 7: no signals present -> no evidence emitted (quiet baseline) ─────────────
quiet_features = {"suspicious_domains": 0.0, "entropy_avg": 0.0, "outbound_bytes_z": 0.0,
                   "zeek_outbound_bytes": 0.0, "beaconing_c2_1h": 0.0, "zeek_s0_rej_count": 0.0,
                   "zeek_max_duration": 0.0}
ev_quiet = detector.detect("dev_x", quiet_features)
check("a fully quiet feature set emits zero evidence (no false signal generation)",
      len(ev_quiet) == 0, f"got {len(ev_quiet)} evidence items: {[e.type for e in ev_quiet]}")


# ── Test 8: all 9 attack hypotheses (2 pre-existing + 5 Phase 1 ports + Phase 21C2's
# DNS_EVASION + VERSION 11's SuricataSignatureHypothesis) are registered ────────────
# NOTE: DNS_EVASION is DNSEvasionHypothesis's DEFAULT name -- VERSION 11 (P1) made
# that hypothesis pick DNS_ATTRIBUTION_GAP dynamically per-evaluation for the weaker
# uncorroborated sub-case (see hypotheses/engine.py), but the class's constructed
# .name (read here, before any .evaluate() call) is still DNS_EVASION -- this set
# membership check is unaffected by that change.
hyp = HypothesisEngine()
names = {h.name for h in hyp.attack_hypotheses}
expected = {"DNS_TUNNELING", "NETWORK_INTRUSION", "DGA_BOTNET_C2", "DATA_EXFILTRATION",
            "C2_BEACONING", "DNS_COVERT_TUNNELING", "CONNECTION_ABUSE", "DNS_EVASION",
            "SIGNATURE_MATCHED_THREAT"}
check("all 9 attack hypotheses (2 pre-existing + 5 Phase 1 ports + Phase 21C2's DNS_EVASION "
      "+ VERSION 11's Suricata signature hypothesis) are registered in HypothesisEngine",
      names == expected, f"got={names}")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 1 hypothesis-engine checks PASSED.")
