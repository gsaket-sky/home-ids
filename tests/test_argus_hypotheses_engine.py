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
`.venv/Scripts/python.exe tests/test_argus_hypotheses_engine.py`
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
from argus.hypotheses.engine import (  # noqa: E402
    HypothesisEngine, DNSTunnelingHypothesis, NetworkIntrusionHypothesis,
    ConnectionAbuseHypothesis, DNSEvasionHypothesis, DeviceProfileBenignHypothesis,
    DGAHypothesis, ExfiltrationHypothesis, BeaconingHypothesis, DNSTunnelingV2Hypothesis,
    CoordinatedTargetingHypothesis, PeerDeviationHypothesis, AdvertisingBurstHypothesis,
    compute_freshness, score_evidence,
)
from intelligence.reputation.classifier import ReputationVector  # noqa: E402

NOW = 1_000_000.0


def ev(evidence_type, value, timestamp=NOW, family="general", provenance="", confidence=1.0):
    return Evidence(device_id="dev1", destination_id="x.com", evidence_type=evidence_type,
                      independence_family=family, timestamp=timestamp, source="s",
                      value=value, confidence=confidence, provenance=provenance)


def rep(tier, domain="x.com"):
    return ReputationVector(domain=domain, tier=tier)


def ev_at(evidence_type, value, destination_id, timestamp=NOW, family="general", provenance=""):
    """Like ev() above but with an explicit destination_id -- ev() hardcodes "x.com"
    (matching rep()'s own default domain), so every check using ev()/rep() together
    only ever exercises the SAME-destination path. Needed to exercise the mismatch/
    ambiguous paths of _effective_rep_tier() (BUGFIX, live audit 2026-09-09) below."""
    return Evidence(device_id="dev1", destination_id=destination_id, evidence_type=evidence_type,
                      independence_family=family, timestamp=timestamp, source="s",
                      value=value, confidence=1.0, provenance=provenance)


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
    # BUGFIX (2026-09-15, gap 2 of the "3 automated-learning gaps" audit): this used
    # to pass rep(0) here on the mistaken assumption tier 0 was neutral/non-
    # contradicting -- it never actually was BY DESIGN (tier 0's own docstring
    # always said "external reputation doesn't apply," the same dampening role as
    # tier 1/2), it just happened to behave that way because of the very bug gap 2
    # fixed (tier 0 was excluded from every `eff_tier in (1, 2)` check). Now that
    # tier 0 correctly dampens like every other hypothesis, rep(3) (genuinely
    # unclassified/neutral) is the correct fixture for "strong signal, no rep-tier
    # interference" -- matches the tier-3 fixture already used two checks below for
    # the identical isolate-from-tier-4 purpose.
    rep(3),  # tier 3 (unclassified): strong signal but not tier 4, isolates the Probable bump from the separate High bump
)
check("DNSTunnelingHypothesis reaches Probable (3.0) with the strong signal present", score_strong == 3.0)

# TIGHTENED (third-party architecture review, 2026-09-09): tier 3 (unclassified,
# no external signal at all) used to also qualify for the High bump alongside
# tier 4 -- "we know nothing about this destination" isn't evidence of anything,
# so it no longer helps a hypothesis reach its own ceiling ("unusual is not
# malicious"). Only tier 4 (at least one real, if weak, external reputation
# signal) now qualifies.
score_strong_unclassified_tier = h.evaluate(
    score_evidence([ev("dns_rate", 150), ev("dns_entropy", 4.5), ev("dns_unique_ratio", 0.9)], now=NOW),
    rep(3),  # tier 3 (unclassified): strong signal alone is no longer enough for the High bump
)
check("DNSTunnelingHypothesis does NOT reach High (4.0) on an unclassified (tier 3) "
      "destination -- being unclassified isn't evidence of anything",
      score_strong_unclassified_tier == 3.0, f"got {score_strong_unclassified_tier}")

score_strong_weak_signal_tier = h.evaluate(
    score_evidence([ev("dns_rate", 150), ev("dns_entropy", 4.5), ev("dns_unique_ratio", 0.9)], now=NOW),
    rep(4),  # tier 4: at least one real (if weak) external reputation signal present
)
check("DNSTunnelingHypothesis reaches High (4.0) when the strong signal is paired with "
      "a real (if weak) external reputation signal (tier 4)",
      score_strong_weak_signal_tier == 4.0)

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
score_notice_only = h2.evaluate(score_evidence([ev("zeek_notice_medium", 1)], now=NOW), rep(3))
check("zeek_notice_medium alone (no lateral scan) keeps the base NETWORK_INTRUSION name",
      h2.name == "NETWORK_INTRUSION")
check("zeek_notice_medium alone (no other corroboration) stays at Suspicious (2.0), "
      "not treated as strong on its own", score_notice_only == 2.0)

h3 = NetworkIntrusionHypothesis()
score_ja3_plus_notice = h3.evaluate(
    score_evidence([ev("malicious_ja3", 1), ev("zeek_notice_medium", 1)], now=NOW), rep(4),
)
check("a real JA3 match plus a corroborating medium-tier notice gets partial strong "
      "credit (0.5 * 0.5 medium-tier weight = 0.25) and still reaches Probable, "
      "matching the Gap-2 fix's exact intent (notice can corroborate but never "
      "single-handedly equal a real fingerprint match)",
      h3.strong_score == 0.25 and score_ja3_plus_notice == 3.0)

# --- NetworkIntrusionHypothesis: zeek_notice tier weighting (live audit, 2026-09-09;
# tier fragmented into evidence_type itself, explicit user request, same day) ---
h3w = NetworkIntrusionHypothesis()
score_ja3_plus_weak_notice = h3w.evaluate(
    score_evidence([ev("malicious_ja3", 1), ev("zeek_notice_weak", 1)], now=NOW), rep(4),
)
check("REGRESSION GUARD: a WEAK-tier notice (e.g. weird:data_before_established, a "
      "TCP-capture artifact) contributes ZERO strong credit even alongside a real "
      "JA3 match -- routine protocol/capture noise is not corroboration",
      h3w.strong_score == 0.0 and score_ja3_plus_weak_notice == 2.0)

h3s = NetworkIntrusionHypothesis()
score_ja3_plus_strong_notice = h3s.evaluate(
    score_evidence([ev("malicious_ja3", 1), ev("zeek_notice_strong", 1)], now=NOW), rep(4),
)
check("a STRONG-tier notice (e.g. Scan::Address_Scan) alongside a real JA3 match "
      "gets more strong credit (0.5 * 0.75 = 0.375) than a medium-tier one, but "
      "still short of a second fully-independent strong signal (1.0)",
      h3s.strong_score == 0.375 and score_ja3_plus_strong_notice == 3.0)

h3hd = NetworkIntrusionHypothesis()
score_notice_only_highly_det = h3hd.evaluate(
    score_evidence([ev("zeek_notice_highly_deterministic", 1)], now=NOW), rep(4),
)
check("a HIGHLY_DETERMINISTIC-tier notice (e.g. a real Intel::Notice hit) ALONE, "
      "with no other strong signal this cycle, still earns real corroborating "
      "weight (0.75) and can reach High (4.0) given a real (tier 4) reputation "
      "signal too -- unlike a lone medium/weak notice, which stays at the base floor",
      h3hd.strong_score == 0.75 and score_notice_only_highly_det == 4.0)

h3hd2 = NetworkIntrusionHypothesis()
score_notice_only_medium = h3hd2.evaluate(
    score_evidence([ev("zeek_notice_medium", 1)], now=NOW), rep(4),
)
check("REGRESSION GUARD: a lone MEDIUM-tier notice (e.g. SSL::Invalid_Server_Cert), "
      "with no other strong signal, stays at the base floor (2.0) -- only "
      "highly_deterministic clears the bar to corroborate on its own",
      score_notice_only_medium == 2.0)

h3old = NetworkIntrusionHypothesis()
score_old_format_notice = h3old.evaluate(
    score_evidence([ev("malicious_ja3", 1), ev("zeek_notice", 1)], now=NOW), rep(4),
)
check("REGRESSION GUARD: pre-fragmentation evidence (bare 'zeek_notice', no tier "
      "suffix at all -- still valid within the 24h graph window right after this "
      "deploy) safely degrades to zero weight, same as weak -- never crashes, never "
      "silently over-trusted",
      h3old.strong_score == 0.0 and score_old_format_notice == 2.0)

# --- ConnectionAbuseHypothesis: 3-way dynamic naming ---
h = ConnectionAbuseHypothesis()
h.evaluate(score_evidence([ev("arp_sweep", 1)], now=NOW), rep(3))
check("ARP sweep alone names the hypothesis INTERNAL_RECONNAISSANCE", h.name == "INTERNAL_RECONNAISSANCE")

h2 = ConnectionAbuseHypothesis()
h2.evaluate(score_evidence([ev("zeek_conn_abuse", 1)], now=NOW), rep(3))
check("a port-scan signal alone names the hypothesis PORT_SCAN", h2.name == "PORT_SCAN")

h3 = ConnectionAbuseHypothesis()
score_multi_high_conf = h3.evaluate(
    score_evidence([ev("arp_sweep", 1), ev("zeek_conn_abuse", 1)], now=NOW), rep(3),
)
check("TWO distinct categories together keep the general CONNECTION_ABUSE name "
      "(broader multi-stage story), not either specific name", h3.name == "CONNECTION_ABUSE")
check("two distinct categories at high confidence (effective_weight>=0.85) reach the "
      "High tier -- via genuine WITHIN-category intensity, not mere co-occurrence",
      score_multi_high_conf == 4.0)

# REWORKED (third-party architecture review, 2026-09-09): an ARP sweep (internal
# recon) and an abnormally-long connection (often just a legitimate large
# transfer/stream) are conceptually unrelated behaviors from different sensors --
# co-occurring used to grant this hypothesis its own 4.0 ceiling regardless of how
# weak either signal was on its own, double-counting the SAME cross-family
# diversity the decision engine's own num_independent_sources already rewards.
h4 = ConnectionAbuseHypothesis()
score_multi_low_conf = h4.evaluate(
    score_evidence([ev("arp_sweep", 1, confidence=0.7), ev("zeek_long_conn", 1, confidence=0.7)], now=NOW), rep(3),
)
check("REGRESSION GUARD: two distinct categories at MODERATE confidence "
      "(effective_weight 0.7, clears best>=0.6 but not best>=0.85) reach only the "
      "Probable tier now, not High -- mere category co-occurrence no longer "
      "manufactures the ceiling score", score_multi_low_conf == 3.0, f"got {score_multi_low_conf}")

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

# CAPPED (third-party architecture review, 2026-09-09): DNS_ATTRIBUTION_GAP is an
# acknowledged ambiguity, not a confirmed evasion pattern -- it must never climb
# the same ladder as the two confirmed names above, even with high-confidence
# and/or corroborating evidence.
h4 = DNSEvasionHypothesis()
score_gap_high_conf = h4.evaluate(
    score_evidence([
        ev("dns_evasion_anomaly", 1, confidence=0.95, provenance="detector:dns_evasion:partial_gap:note"),
        ev("zeek_notice_medium", 1),  # unrelated corroborating evidence -- would trigger the strong_score bump
    ], now=NOW), rep(3),
)
check("REGRESSION GUARD: DNS_ATTRIBUTION_GAP stays capped at the base floor (2.0) "
      "even with high confidence AND corroborating evidence present -- an "
      "acknowledged ambiguity can't independently escalate",
      score_gap_high_conf == 2.0, f"got {score_gap_high_conf}")

h5 = DNSEvasionHypothesis()
score_policy_bypass_high_conf = h5.evaluate(
    score_evidence([
        ev("dns_evasion_anomaly", 1, confidence=0.95, provenance="detector:dns_evasion:policy_bypass:note"),
        ev("zeek_notice_medium", 1),
    ], now=NOW), rep(3),
)
check("REGRESSION GUARD: a genuinely CONFIRMED evasion pattern (policy_bypass) "
      "under the identical evidence shape still reaches High (4.0) -- the cap "
      "targets the ambiguous case specifically, not the whole hypothesis",
      score_policy_bypass_high_conf == 4.0, f"got {score_policy_bypass_high_conf}")

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

# BUGFIX regression (live audit, 2026-09-09): a WEAK-tier zeek_notice (routine
# TCP-capture/protocol-edge-case noise, not attacker behavior) must NOT veto an
# otherwise-legitimate benign verdict -- confirmed live that this safety valve used
# to fire on ANY zeek_notice regardless of tier, and a single weak notice type alone
# (weird:data_before_established) fired 68,575 times on .94's real network, making
# this benign path nearly unreachable in practice.
h2w = DeviceProfileBenignHypothesis()
score_weak_notice_ok = h2w.evaluate(
    score_evidence([ev("dns_rate", 30), ev("zeek_notice_weak", 1)], now=NOW),
    rep(1), device_type="smart_tv",
)
check("REGRESSION GUARD: a WEAK-tier zeek_notice does NOT block the benign verdict "
      "-- routine capture/protocol noise is not competing attack evidence",
      h2w.required_satisfied and score_weak_notice_ok > 0.0)

h2m = DeviceProfileBenignHypothesis()
score_medium_notice_blocked = h2m.evaluate(
    score_evidence([ev("dns_rate", 30), ev("zeek_notice_medium", 1)], now=NOW),
    rep(1), device_type="smart_tv",
)
check("a MEDIUM-tier-or-above zeek_notice (e.g. SSL::Invalid_Server_Cert) still "
      "blocks the benign verdict, same as every other genuinely attack-shaped type",
      not h2m.required_satisfied and score_medium_notice_blocked == 0.0)

h3 = DeviceProfileBenignHypothesis()
score_wrong_category = h3.evaluate(
    score_evidence([ev("dns_rate", 30)], now=NOW), rep(1), device_type="laptop",
)
check("a device category NOT in the expected-high-volume set does not get this benign pass",
      score_wrong_category == 0.0)

# --- REMOVED (third-party architecture review, 2026-09-09): first_contact used to
# bump strong_score in Exfiltration/Beaconing/DNSTunnelingV2Hypothesis -- "never
# talked to this destination before" is real context, but novelty alone isn't
# corroboration ("unusual is not malicious"). These are now REGRESSION GUARDS
# proving first_contact no longer moves any of the three hypotheses' own score,
# replacing the old tests that asserted the removed behavior. ---
h = ExfiltrationHypothesis()
score_moderate_alone = h.evaluate(
    score_evidence([ev("zeek_exfiltration", 1, confidence=0.7)], now=NOW), rep(3),
)
check("a moderate-confidence exfiltration hit alone (effective_weight 0.7) reaches "
      "SUSPICIOUS via the best>=0.6 gate", score_moderate_alone == 3.0)

h = ExfiltrationHypothesis()
score_weak_plus_first_contact = h.evaluate(
    score_evidence([ev("zeek_exfiltration", 1, confidence=0.4), ev("first_contact", 1.0)], now=NOW), rep(3),
)
check("REGRESSION GUARD: a WEAK exfiltration hit (effective_weight 0.4, below the "
      "best>=0.6 gate) does NOT reach SUSPICIOUS just because first_contact is also "
      "present -- novelty alone is no longer corroboration",
      score_weak_plus_first_contact == 2.0, f"got {score_weak_plus_first_contact}")

h = ExfiltrationHypothesis()
score_weak_alone = h.evaluate(
    score_evidence([ev("zeek_exfiltration", 1, confidence=0.4)], now=NOW), rep(3),
)
check("that same weak hit WITHOUT first_contact also stays at the base floor (2.0) "
      "-- identical to the first_contact case now, confirming first_contact is inert",
      score_weak_alone == 2.0)

# confidence=0.5 (below the 0.85 best-effective_weight gate) isolates the
# strong_score-only SUSPICIOUS path from the separate best>=0.85 HIGH path below.
h = BeaconingHypothesis()
score_beacon_plain = h.evaluate(score_evidence([ev("zeek_beaconing", 1, confidence=0.5)], now=NOW), rep(3))
h2 = BeaconingHypothesis()
score_beacon_first_contact = h2.evaluate(
    score_evidence([ev("zeek_beaconing", 1, confidence=0.5), ev("first_contact", 1.0)], now=NOW), rep(3),
)
check("BeaconingHypothesis: a beacon hit alone (below the best>=0.85 HIGH gate, no "
      "other corroboration) stays at the base floor", score_beacon_plain == 2.0)
check("REGRESSION GUARD: adding first_contact does NOT raise that same beacon hit "
      "-- novelty alone is no longer corroboration",
      score_beacon_first_contact == score_beacon_plain == 2.0, f"got {score_beacon_first_contact}")

h = DNSTunnelingV2Hypothesis()
score_tunnel_plain = h.evaluate(
    score_evidence([ev("dns_tunnel_v2", 1, confidence=0.5,
                        provenance="detector:threat_signals:dns_tunnel_v2:sub1:note")], now=NOW),
    rep(3),
)
h2 = DNSTunnelingV2Hypothesis()
score_tunnel_first_contact = h2.evaluate(
    score_evidence([
        ev("dns_tunnel_v2", 1, confidence=0.5, provenance="detector:threat_signals:dns_tunnel_v2:sub1:note"),
        ev("first_contact", 1.0),
    ], now=NOW), rep(3),
)
check("DNSTunnelingV2Hypothesis: a single-signal tunnel hit alone stays at the base floor",
      score_tunnel_plain == 2.0)
check("REGRESSION GUARD: adding first_contact does NOT raise that same tunnel hit "
      "-- novelty alone is no longer corroboration",
      score_tunnel_first_contact == score_tunnel_plain == 2.0, f"got {score_tunnel_first_contact}")

# --- Phase 1a: CoordinatedTargetingHypothesis -- a genuinely new capability, no v1 equivalent ---
h = CoordinatedTargetingHypothesis()
score_no_evidence = h.evaluate(score_evidence([ev("dns_rate", 10)], now=NOW), rep(3))
check("CoordinatedTargetingHypothesis requires its own coordinated_targeting evidence "
      "-- unrelated evidence types never satisfy it", score_no_evidence == 0.0 and not h.required_satisfied)

h = CoordinatedTargetingHypothesis()
score_two_devices = h.evaluate(
    score_evidence([ev("coordinated_targeting", 2.0)], now=NOW), rep(3),
)
check("2 total devices (this one + 1 other) satisfies the hypothesis and reaches "
      "SUSPICIOUS (3.0) via the best-effective_weight gate, but NOT HIGH -- the "
      ">=3-devices strong_score bump correctly hasn't fired yet at only 2",
      h.required_satisfied and score_two_devices == 3.0)

h = CoordinatedTargetingHypothesis()
score_many_devices_confident = h.evaluate(
    score_evidence([ev("coordinated_targeting", 5.0, confidence=0.95)], now=NOW), rep(3),
)
check("3+ total devices with high confidence reaches HIGH (4.0) -- the strong_score "
      "bump for >=3 devices plus a high effective_weight",
      score_many_devices_confident == 4.0)

h = CoordinatedTargetingHypothesis()
score_contradicted = h.evaluate(
    score_evidence([ev("coordinated_targeting", 5.0, confidence=0.95)], now=NOW), rep(1),  # trusted destination
)
check("a trusted-tier destination (tier 1) contradicts even a many-device coordinated "
      "hit, same contradicting-evidence pattern every other hypothesis uses",
      score_contradicted == 2.0)

# GAP 2 FIX (2026-09-15, "3 automated-learning gaps" audit): tier 0
# ("local/internal, external reputation doesn't apply") used to be silently
# excluded from this contradicting-evidence check (only (1,2) were checked,
# despite tier 0's own docstring already promising the same dampening) --
# this is the real-world shape of the actual bug: a household's own smart-TV
# devices doing ordinary mDNS discovery of each other, which ReputationClassifier
# now correctly assigns tier 0 to (see that module's own 2026-09-15 fix).
h = CoordinatedTargetingHypothesis()
score_contradicted_tier0 = h.evaluate(
    score_evidence([ev("coordinated_targeting", 5.0, confidence=0.95)], now=NOW), rep(0),  # local/internal destination
)
check("a local/internal-tier destination (tier 0) NOW ALSO contradicts a many-device "
      "coordinated hit, matching tier 1/2's existing dampening -- the actual fix for "
      "the real Fire TV / Echo Show COORDINATED_TARGETING false positives found "
      "2026-09-15 (ordinary mDNS discovery between a household's own devices)",
      score_contradicted_tier0 == 2.0)

engine_ct = HypothesisEngine()
result_ct = engine_ct.evaluate_all([ev("coordinated_targeting", 3.0)], rep(3), now=NOW)
check("HypothesisEngine.evaluate_all() surfaces COORDINATED_TARGETING as the winning "
      "attack hypothesis when it's the only evidence present",
      result_ct["attack"]["name"] == "COORDINATED_TARGETING")

# --- Release 14, N4: CoordinatedTargetingHypothesis widened to fingerprint_campaign/
# dga_seed_campaign -- same scoring logic, generalized evidence-type filter ---
h = CoordinatedTargetingHypothesis()
score_fingerprint = h.evaluate(score_evidence([ev("fingerprint_campaign", 2.0)], now=NOW), rep(3))
check("N4: fingerprint_campaign alone satisfies CoordinatedTargetingHypothesis and "
      "scores identically to coordinated_targeting at the same device count/confidence "
      "-- the SAME underlying signal, just a different shared identifier",
      h.required_satisfied and score_fingerprint == 3.0)

h = CoordinatedTargetingHypothesis()
score_dga = h.evaluate(
    score_evidence([ev("dga_seed_campaign", 5.0, confidence=0.95)], now=NOW), rep(3),
)
check("N4: dga_seed_campaign with 3+ devices and high confidence also reaches HIGH "
      "(4.0), the same strong_score bump path as coordinated_targeting",
      score_dga == 4.0)

h = CoordinatedTargetingHypothesis()
score_mixed = h.evaluate(
    score_evidence([ev("coordinated_targeting", 2.0), ev("fingerprint_campaign", 2.0)], now=NOW), rep(3),
)
check("N4: coordinated_targeting and fingerprint_campaign co-occurring both count "
      "as hits (best-effective_weight/total_devices take the max across all three "
      "evidence types, not just one)",
      h.required_satisfied and score_mixed >= 3.0)

# --- Release 14, N2: PeerDeviationHypothesis -- a genuinely new, deliberately capped signal ---
h2 = PeerDeviationHypothesis()
score_no_dev = h2.evaluate(score_evidence([ev("dns_rate", 10)], now=NOW), rep(3))
check("N2: PeerDeviationHypothesis requires its own peer_deviation evidence -- "
      "unrelated evidence types never satisfy it",
      score_no_dev == 0.0 and not h2.required_satisfied)

h2 = PeerDeviationHypothesis()
score_alone = h2.evaluate(score_evidence([ev("peer_deviation", 15.0, confidence=0.6)], now=NOW), rep(3))
check("N2: CONTEXT ONLY (2026-10-03) -- peer_deviation on its own scores 0 and creates no alert",
      score_alone == 0.0 and not h2.required_satisfied)

# with attack-shaped evidence on the same device it still contributes
_PEER_WITH = lambda conf=0.6, v=15.0: [ev("peer_deviation", v, confidence=conf), ev("zeek_conn_abuse", 1.0)]
h2 = PeerDeviationHypothesis()
score_dev = h2.evaluate(score_evidence(_PEER_WITH(), now=NOW), rep(3))
check("N2: peer_deviation alongside attack-shaped evidence reaches SUSPICIOUS (3.0)",
      h2.required_satisfied and score_dev == 3.0)

h2 = PeerDeviationHypothesis()
score_dev_contradicted = h2.evaluate(
    score_evidence(_PEER_WITH(), now=NOW), rep(1),  # trusted destination
)
check("N2: a trusted-tier context contradicts peer_deviation, same "
      "contradicting-evidence pattern every other hypothesis uses",
      score_dev_contradicted == 2.0)

check("N2: PeerDeviationHypothesis is capped at SUSPICIOUS (3.0) even with a "
      "very high effective_weight -- deliberately never reaches HIGH on its own, "
      "unlike an established signal such as coordinated_targeting",
      PeerDeviationHypothesis().evaluate(
          score_evidence(_PEER_WITH(conf=1.0, v=50.0), now=NOW), rep(3),
      ) == 3.0)

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

# --- BUGFIX (live audit, 2026-09-09): Hypothesis._effective_rep_tier() -- generalizes
# a214a2f's single-hypothesis (CoordinatedTargetingHypothesis) per-destination
# reputation fix to all 11 attack hypotheses, both the trust-suppression (tier in
# (1,2)) and escalation (tier==4 / tier in (3,4)/(3,4,5)) directions. Every check
# above this point uses ev()'s hardcoded "x.com" destination alongside rep()'s
# matching default domain -- exercises only the "rep_vector IS about my destination"
# path. These use ev_at() to construct evidence at an explicit, different
# destination, directly exercising the mismatch/match/ambiguous paths.

# Suppression direction (DGAHypothesis, tier in (1,2)):
dga_hits = [
    ev_at("dns_dga_burst", 1.0, "evil-dga-domain.ru"),
    ev_at("dns_rate", 150.0, NO_DESTINATION),
]
dga = DGAHypothesis()
dga_mismatched = dga.evaluate(score_evidence(dga_hits, now=NOW), rep(1, domain="totally-unrelated-cdn.com"))
check("REGRESSION GUARD: a rep_vector describing an UNRELATED destination no longer wrongly "
      "suppresses a real DGA hit via a trusted (tier 1) verdict about something else",
      dga_mismatched >= 3.0 and dga.contradicting_score == 0, f"got score={dga_mismatched}")

dga_matched = dga.evaluate(score_evidence(dga_hits, now=NOW), rep(1, domain="evil-dga-domain.ru"))
check("a rep_vector that DOES describe this hypothesis's own destination still suppresses it normally",
      dga_matched == 2.0 and dga.contradicting_score == 1.0, f"got score={dga_matched}")

dga_ambiguous = dga.evaluate(score_evidence(dga_hits, now=NOW), rep(1, domain=""))
check("a rep_vector with NO domain info at all (ambiguous) still applies its tier unchanged -- "
      "matches decision_engine.py's own Gap-64 'never touch the ambiguous case' rule",
      dga_ambiguous == 2.0 and dga.contradicting_score == 1.0, f"got score={dga_ambiguous}")

# Escalation direction (DNSTunnelingHypothesis, the one hypothesis whose escalation
# check requires tier==4 exactly, not a wider (3,4,5)-style range that already treats
# "unclassified" as escalation-eligible regardless of this fix -- see this session's
# own analysis for why that range is a separate, pre-existing design choice this fix
# deliberately doesn't also change).
dns_tunnel_hits = [
    ev_at("dns_rate", 150.0, "sketchy-domain.example"),
    ev_at("dns_entropy", 4.5, "sketchy-domain.example"),
    ev_at("dns_unique_ratio", 0.9, "sketchy-domain.example"),
]
dnst = DNSTunnelingHypothesis()
dnst_mismatched = dnst.evaluate(score_evidence(dns_tunnel_hits, now=NOW), rep(4, domain="totally-different-domain.example"))
check("REGRESSION GUARD: an unrelated tier-4 rep_vector no longer wrongly escalates a DNS-tunneling "
      "finding it has nothing to do with (falls back to neutral/unclassified, not tier 4)",
      dnst_mismatched == 3.0, f"got score={dnst_mismatched}")

dnst_matched = dnst.evaluate(score_evidence(dns_tunnel_hits, now=NOW), rep(4, domain="sketchy-domain.example"))
check("a tier-4 rep_vector that DOES describe this hypothesis's own destination still escalates it normally",
      dnst_matched == 4.0, f"got score={dnst_matched}")

# PeerDeviationHypothesis's own evidence is device-level by design (destination_id=
# NO_DESTINATION, live_engine.py's _inject_peer_deviation_evidence()) -- confirms the
# generalized fix is a correct NO-OP here, not an accidental behavior change to the
# one hypothesis that deliberately has no destination to compare against.
pd_hits = [ev_at("peer_deviation", 0.9, NO_DESTINATION), ev_at("zeek_conn_abuse", 1.0, NO_DESTINATION)]
pd = PeerDeviationHypothesis()
pd_score = pd.evaluate(score_evidence(pd_hits, now=NOW), rep(1, domain="some-unrelated-domain.example"))
check("PeerDeviationHypothesis (destination-less evidence by design) is unaffected by the "
      "generalized fix -- an unrelated-domain rep_vector still applies its tier unchanged, the "
      "same ambiguous-case behavior it had before this fix",
      pd_score == 2.0 and pd.contradicting_score == 1.0, f"got score={pd_score}")

# --- BUGFIX (live audit, 2026-09-09): the 2 benign hypotheses whose REQUIRED gate reads
# rep_vector.tier (AdvertisingBurstHypothesis/DeviceProfileBenignHypothesis) now also
# route through _effective_rep_tier(). In production this is a no-op today (dns_rate
# never carries a destination), but these tests use ev_at() to simulate the gap being
# closed later (the same way zeek_exfiltration/zeek_beaconing's identical gap already
# was, via live_engine.py's _NEEDS_LAST_DEST_IP_FALLBACK) -- proving the safety net is
# actually wired correctly, not just declared.
ab = AdvertisingBurstHypothesis()
ab_hits = [ev_at("dns_rate", 60.0, "some-cdn.example")]
ab_matched = ab.evaluate(score_evidence(ab_hits, now=NOW), rep(2, domain="some-cdn.example"))
check("AdvertisingBurstHypothesis fires normally when rep_vector DOES describe its own destination",
      ab_matched > 0.0, f"got score={ab_matched}")
ab_mismatched = ab.evaluate(score_evidence(ab_hits, now=NOW), rep(2, domain="totally-different.example"))
check("REGRESSION GUARD: AdvertisingBurstHypothesis does NOT fire on an unrelated tier-2 "
      "rep_vector -- a benign verdict must not be approved based on a destination this "
      "evidence has nothing to do with",
      ab_mismatched == 0.0, f"got score={ab_mismatched}")

dpb = DeviceProfileBenignHypothesis()
dpb_hits = [ev_at("dns_rate", 30.0, "some-cdn.example")]
dpb_matched = dpb.evaluate(score_evidence(dpb_hits, now=NOW), rep(1, domain="some-cdn.example"), device_type="smart_tv")
check("DeviceProfileBenignHypothesis fires normally when rep_vector DOES describe its own destination",
      dpb_matched > 0.0, f"got score={dpb_matched}")
dpb_mismatched = dpb.evaluate(score_evidence(dpb_hits, now=NOW), rep(1, domain="unrelated.example"), device_type="smart_tv")
check("REGRESSION GUARD: DeviceProfileBenignHypothesis does NOT fire on an unrelated "
      "trusted-tier rep_vector alone (no baseline_familiarity here either) -- same "
      "wrong-destination-approves-benign-verdict risk closed",
      dpb_mismatched == 0.0, f"got score={dpb_mismatched}")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 HypothesisEngine checks PASSED.")
