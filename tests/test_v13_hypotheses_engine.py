"""
Standalone runtime test for v13's HypothesisEngine (src/v13/hypotheses/engine.py,
Phase 1/3 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: the freshness/TTL mechanism (matches EvidenceStore.get_for_device() exactly
-- 600s default, 86400s for the reputation family, linear decay, stale evidence
dropped), each hypothesis's required/strong/contradicting logic against known
score thresholds, the three dynamic-naming hypotheses (NetworkIntrusion,
ConnectionAbuse, DNSEvasion), DeviceProfileBenignHypothesis's competing-attack-
evidence guard, and HypothesisEngine.evaluate_all()'s winner-selection.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_hypotheses_engine.py`
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


from v13.evidence.model import Evidence  # noqa: E402
from v13.hypotheses.engine import (  # noqa: E402
    HypothesisEngine, DNSTunnelingHypothesis, NetworkIntrusionHypothesis,
    ConnectionAbuseHypothesis, DNSEvasionHypothesis, DeviceProfileBenignHypothesis,
    DGAHypothesis, compute_freshness, score_evidence,
)
from intelligence.reputation.classifier import ReputationVector  # noqa: E402

NOW = 1_000_000.0


def ev(evidence_type, value, timestamp=NOW, family="general", provenance="", confidence=1.0):
    return Evidence(device_id="dev1", destination_id="x.com", evidence_type=evidence_type,
                      independence_family=family, timestamp=timestamp, source="s",
                      value=value, confidence=confidence, provenance=provenance)


def rep(tier, domain="x.com"):
    return ReputationVector(domain=domain, tier=tier)


# --- freshness/TTL mechanism ---
fresh = compute_freshness(ev("x", 1.0, timestamp=NOW - 60), now=NOW)
check("evidence well within the 600s default TTL gets a high freshness value",
      fresh is not None and fresh > 0.8, f"got {fresh}")

stale = compute_freshness(ev("x", 1.0, timestamp=NOW - 700), now=NOW)
check("evidence past the 600s default TTL is dropped (freshness=None)", stale is None)

rep_fresh = compute_freshness(ev("reputation", 1.0, timestamp=NOW - 3600, family="reputation"), now=NOW)
check("reputation-family evidence uses the 86400s TTL, not 600s -- still fresh at 1hr old",
      rep_fresh is not None and rep_fresh > 0.9, f"got {rep_fresh}")

rep_stale = compute_freshness(ev("reputation", 1.0, timestamp=NOW - 90000, family="reputation"), now=NOW)
check("reputation-family evidence IS eventually dropped past its own 86400s TTL", rep_stale is None)

scored = score_evidence([ev("x", 1.0, timestamp=NOW - 60), ev("x", 1.0, timestamp=NOW - 700)], now=NOW)
check("score_evidence() silently drops stale items rather than including them at freshness=0",
      len(scored) == 1)

# --- DNSTunnelingHypothesis: required both signals, strong bumps to Probable ---
h = DNSTunnelingHypothesis()
score = h.evaluate(score_evidence([ev("dns_rate", 150), ev("dns_entropy", 4.5)], now=NOW), rep(3))
check("DNSTunnelingHypothesis requires BOTH high rate AND high entropy",
      h.required_satisfied and score == 2.0)

score_strong = h.evaluate(
    score_evidence([ev("dns_rate", 150), ev("dns_entropy", 4.5), ev("dns_unique_ratio", 0.9)], now=NOW),
    rep(0),  # tier 0 (local/internal): strong signal but NOT in (3,4), isolates the Probable bump from the separate High bump
)
check("DNSTunnelingHypothesis reaches Probable (3.0) with the strong signal present", score_strong == 3.0)

score_strong_high_tier = h.evaluate(
    score_evidence([ev("dns_rate", 150), ev("dns_entropy", 4.5), ev("dns_unique_ratio", 0.9)], now=NOW),
    rep(3),  # tier 3 (unclassified): same strong signal, but tier in (3,4) additionally triggers the High bump
)
check("DNSTunnelingHypothesis reaches High (4.0) when the strong signal is ALSO on an unclassified-tier destination",
      score_strong_high_tier == 4.0)

score_only_rate = h.evaluate(score_evidence([ev("dns_rate", 150)], now=NOW), rep(3))
check("DNSTunnelingHypothesis does NOT fire on rate alone (required_satisfied is False)",
      not h.required_satisfied and score_only_rate == 0.0)

# --- NetworkIntrusionHypothesis: dynamic naming ---
h = NetworkIntrusionHypothesis()
score_lateral = h.evaluate(score_evidence([ev("zeek_lateral_scan", 1)], now=NOW), rep(3))
check("a lateral scan alone renames the hypothesis to LATERAL_MOVEMENT",
      h.name == "LATERAL_MOVEMENT")
check("a lateral scan alone hard-escalates to HIGH (4.0) when uncontradicted", score_lateral == 4.0)

h2 = NetworkIntrusionHypothesis()
score_notice_only = h2.evaluate(score_evidence([ev("zeek_notice", 1)], now=NOW), rep(3))
check("zeek_notice alone (no lateral scan) keeps the base NETWORK_INTRUSION name",
      h2.name == "NETWORK_INTRUSION")
check("zeek_notice alone (no other corroboration) stays at Suspicious (2.0), "
      "not treated as strong on its own", score_notice_only == 2.0)

h3 = NetworkIntrusionHypothesis()
score_ja3_plus_notice = h3.evaluate(
    score_evidence([ev("malicious_ja3", 1), ev("zeek_notice", 1)], now=NOW), rep(4),
)
check("a real JA3 match plus a corroborating notice gets partial strong credit (0.5) "
      "and reaches Probable, matching the Gap-2 fix's exact intent (notice can corroborate "
      "but never single-handedly equal a real fingerprint match)",
      h3.strong_score == 0.5 and score_ja3_plus_notice == 3.0)

# --- ConnectionAbuseHypothesis: 3-way dynamic naming ---
h = ConnectionAbuseHypothesis()
h.evaluate(score_evidence([ev("arp_sweep", 1)], now=NOW), rep(3))
check("ARP sweep alone names the hypothesis INTERNAL_RECONNAISSANCE", h.name == "INTERNAL_RECONNAISSANCE")

h2 = ConnectionAbuseHypothesis()
h2.evaluate(score_evidence([ev("zeek_conn_abuse", 1)], now=NOW), rep(3))
check("a port-scan signal alone names the hypothesis PORT_SCAN", h2.name == "PORT_SCAN")

h3 = ConnectionAbuseHypothesis()
score_multi = h3.evaluate(
    score_evidence([ev("arp_sweep", 1), ev("zeek_conn_abuse", 1)], now=NOW), rep(3),
)
check("TWO distinct categories together keep the general CONNECTION_ABUSE name "
      "(broader multi-stage story), not either specific name", h3.name == "CONNECTION_ABUSE")
check("two distinct corroborating categories reach the strong/High tier", score_multi == 4.0)

# --- DNSEvasionHypothesis: 3-way naming via provenance subtag ---
h = DNSEvasionHypothesis()
h.evaluate(score_evidence([ev("dns_evasion_anomaly", 1, provenance="detector:dns_evasion:policy_bypass:note")], now=NOW), rep(3))
check("a 'policy_bypass' subtag names the hypothesis DNS_POLICY_BYPASS", h.name == "DNS_POLICY_BYPASS")

h2 = DNSEvasionHypothesis()
h2.evaluate(score_evidence([ev("dns_evasion_anomaly", 1, provenance="detector:dns_evasion:no_dns_history:note")], now=NOW), rep(3))
check("a 'no_dns_history' subtag names the hypothesis DNS_EVASION", h2.name == "DNS_EVASION")

h3 = DNSEvasionHypothesis()
h3.evaluate(score_evidence([ev("dns_evasion_anomaly", 1, provenance="detector:dns_evasion:partial_gap:note")], now=NOW), rep(3))
check("an unrecognized/weaker subtag falls back to the least-alarming DNS_ATTRIBUTION_GAP name",
      h3.name == "DNS_ATTRIBUTION_GAP")

# --- DGAHypothesis (effective_weight-driven thresholds) ---
h = DGAHypothesis()
score_weak = h.evaluate(score_evidence([ev("dns_dga_burst", 1, confidence=0.5)], now=NOW), rep(3))
check("a weak (low-confidence, hence low effective_weight) DGA hit stays at base Suspicious",
      score_weak == 2.0)

score_strong = h.evaluate(
    score_evidence([ev("dns_dga_burst", 1, confidence=0.95), ev("dns_rate", 150)], now=NOW), rep(4),
)
check("a high-confidence DGA hit plus rate corroboration on an unclassified-tier domain reaches HIGH",
      score_strong == 4.0)

# --- DeviceProfileBenignHypothesis: competing-attack-evidence guard ---
h = DeviceProfileBenignHypothesis()
score_benign = h.evaluate(
    score_evidence([ev("dns_rate", 30)], now=NOW), rep(1), device_type="smart_tv",
)
check("an expected-category device with routine elevated DNS activity against a trusted "
      "destination scores as benign telemetry", h.required_satisfied and score_benign == 3.0)

h2 = DeviceProfileBenignHypothesis()
score_blocked = h2.evaluate(
    score_evidence([ev("dns_rate", 30), ev("malicious_ja3", 1)], now=NOW),
    rep(1), device_type="smart_tv",
)
check("genuine attack-shaped evidence (malicious_ja3) present at all BLOCKS the benign "
      "verdict outright, even on an expected-category device against a trusted destination "
      "-- the exact guard this hypothesis exists to enforce",
      not h2.required_satisfied and score_blocked == 0.0)

h3 = DeviceProfileBenignHypothesis()
score_wrong_category = h3.evaluate(
    score_evidence([ev("dns_rate", 30)], now=NOW), rep(1), device_type="laptop",
)
check("a device category NOT in the expected-high-volume set does not get this benign pass",
      score_wrong_category == 0.0)

# --- HypothesisEngine.evaluate_all(): winner selection ---
engine = HypothesisEngine()
result = engine.evaluate_all(
    [ev("zeek_lateral_scan", 1)], rep(3), device_type="unknown", now=NOW,
)
check("evaluate_all() surfaces the winning attack hypothesis's dynamic name (LATERAL_MOVEMENT)",
      result["attack"]["name"] == "LATERAL_MOVEMENT")
check("evaluate_all() attaches a non-None checklist for a real attack winner",
      result["attack"]["checklist"] is not None
      and result["attack"]["checklist"]["required_satisfied"] is True)

result_benign = engine.evaluate_all([ev("dns_rate", 30)], rep(1), device_type="smart_tv", now=NOW)
check("evaluate_all() surfaces the winning benign hypothesis when no attack evidence exists",
      result_benign["benign"]["name"] == "DEVICE_PROFILE_TELEMETRY")
check("evaluate_all() falls back to DIRECT_IOC_HIT when no attack hypothesis fires at all",
      result_benign["attack"]["name"] == "DIRECT_IOC_HIT" and result_benign["attack"]["checklist"] is None)

result_empty = engine.evaluate_all([], rep(3))
check("evaluate_all() with zero evidence falls back to UNKNOWN_BENIGN / DIRECT_IOC_HIT cleanly, no crash",
      result_empty["benign"]["name"] == "UNKNOWN_BENIGN" and result_empty["attack"]["name"] == "DIRECT_IOC_HIT")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 HypothesisEngine checks PASSED.")
