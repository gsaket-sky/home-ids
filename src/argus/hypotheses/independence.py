"""
v13 INDEPENDENCE_FAMILY_MAP (Phase 3 groundwork, built early in Phase 1 since it's
the plan's own "core design correction" -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

THE CATEGORY ERROR THIS FILE EXISTS TO AVOID REPEATING (Phase 64's postmortem,
DECISION_LOGIC_DEPENDENCY_MAP.md:48, confirmed via direct research this session):
a first v-current attempt at per-hypothesis independence scoping was built and
reverted because it filtered `attack_evidence` using `HYPOTHESIS_RELEVANT_EVIDENCE_TYPES`
-- but that registry answers "what does this hypothesis's own evaluate() read,"
NOT "what independence families can legitimately corroborate it." Those are
different questions. This file answers ONLY the second one, and is never consulted
for the first (v13's own relevance registry, when built, stays a fully separate
file/map -- this one must never grow a "what a hypothesis reads" field).

WHAT A FAMILY MEANS: evidence types that share the same underlying sensor/vantage
point. Two evidence items from the SAME family are correlated observations of one
underlying phenomenon (e.g. three different DNS-query-shape metrics all describe
the same DNS stream) -- seeing several of them together is not the same strength of
signal as seeing evidence from two genuinely different vantage points (e.g. a DNS
signal AND a separate TLS-fingerprint signal). Independent-source counting (Phase 3's
decision engine) should count DISTINCT FAMILIES represented, not raw evidence-item
count.

HONEST STATUS: these specific groupings are a first-draft judgment call made this
session, grounded in this project's own detector documentation -- NOT yet validated
against real divergence data the way this project validates everything else (Gap
1/2/3's own evidentiary bar). Treat this mapping itself as a hypothesis to test
during the parallel run, not a settled fact just because it's now code.

KNOWN DISCREPANCY FROM v-CURRENT (found during Phase 3 decision-engine porting,
confirmed via direct read of hypotheses/evidence.py's EVIDENCE_FAMILIES, not
guessed -- flagged rather than silently carried forward): v-current groups
malicious_ja3/ja4, zeek_notice, zeek_lateral_scan, zeek_exfiltration,
zeek_beaconing, zeek_conn_abuse, and zeek_long_conn ALL into one family
("zeek_network") -- so a JA3 match plus an exfiltration signal count as ONE
independent source there, not two. This file deliberately splits them into three
families (tls_fingerprint, network_behavior, data_transfer_pattern) on the
reasoning that TLS fingerprinting and traffic-volume analysis are genuinely
different vantage points from flow-level notices. v-current's own grouping is
ALSO a one-time judgment call, not something empirically validated at this
granularity either -- so this isn't "v13 fixing a known-wrong v1 value," it's two
independent judgment calls that happen to disagree, and the parallel run's
divergence data is exactly what should settle which one predicts real outcomes
better. Similarly, v-current's "dns_behavior" family also includes dns_tunnel_v2
and dns_evasion_anomaly (which v-current itself further splits into separate
"dns_tunnel_v2" and "blindspot_audit" families) -- this file's simpler
"dns_behavior" bucket for all four DNS-related types is a real simplification
relative to v-current's own three-way DNS split, not an oversight.
"""
from typing import Dict, FrozenSet, Iterable

# Evidence.evidence_type -> independence family name.
INDEPENDENCE_FAMILY_MAP: Dict[str, str] = {
    # DNS query-pattern analysis -- all derived from the same DNS query stream.
    "dns_entropy": "dns_behavior",
    "dns_tunnel_v2": "dns_behavior",
    "dns_dga_burst": "dns_behavior",
    "dns_evasion_anomaly": "dns_behavior",
    # DNSBehaviorDetector's other two evidence types (intelligence/detectors/
    # dns_behavior.py) -- v-current itself groups all three (rate/entropy/
    # unique_ratio) under one independence_group="dns_behavior", so mapping
    # these here too matches v-current's own grouping choice for this
    # detector specifically, consistent with dns_entropy above.
    "dns_rate": "dns_behavior",
    "dns_unique_ratio": "dns_behavior",

    # TLS handshake fingerprinting -- same underlying sensor (ClientHello).
    "malicious_ja3": "tls_fingerprint",
    "malicious_ja4": "tls_fingerprint",

    # General Zeek flow-level behavioral notices. BUGFIX (explicit user request,
    # 2026-09-09): "zeek_notice" fragmented into 4 evidence_type values by tier
    # (utils.py's ZEEK_NOTICE_EVIDENCE_TYPES) -- all 4 still share this SAME family,
    # this split is about evidence_type-level scoring granularity, not about which
    # vantage point they come from (still the same Zeek notice/weird stream).
    "zeek_notice_weak": "network_behavior",
    "zeek_notice_medium": "network_behavior",
    "zeek_notice_strong": "network_behavior",
    "zeek_notice_highly_deterministic": "network_behavior",
    # BUGFIX (live audit, 2026-09-10): the bare "zeek_notice" key was dropped
    # entirely when the 4 tiered entries above were added -- but evidence rows
    # created BEFORE that deploy (still valid within the 24h graph window) still
    # carry the OLD flat evidence_type, and family_for() re-derives family FRESH
    # at evaluate() time, not from a stored value. Without this entry, old
    # zeek_notice evidence fell through to UNKNOWN_FAMILY ("unregistered")
    # instead of its real family -- confirmed live: a real alert counted an old
    # zeek_notice row as a SEPARATE "unregistered" independent source, distinct
    # from a different (correctly-tiered) zeek_notice item in the SAME alert
    # that's actually the same underlying vantage point. Kept alongside the 4
    # tiered entries (not instead of) purely for this backward-compat window --
    # self-resolving as old evidence ages out, but must not silently
    # miscount corroboration in the meantime.
    "zeek_notice": "network_behavior",
    "zeek_lateral_scan": "network_behavior",
    "zeek_conn_abuse": "network_behavior",
    "zeek_long_conn": "network_behavior",

    # Traffic volume/timing analysis -- a distinct vantage point from flow-level
    # notices above, even though both come from Zeek.
    "zeek_exfiltration": "data_transfer_pattern",
    "zeek_beaconing": "data_transfer_pattern",

    # ARP-layer signals -- same underlying sensor (local ARP traffic/table).
    "arp_sweep": "network_recon",
    "arp_spoof_pending": "network_recon",
    "arp_spoofing": "network_recon",

    # External threat-intel lookups -- genuinely independent of any on-network
    # behavioral sensor above.
    "reputation": "reputation",

    # A device actually contacting a honeypot -- a distinct, very strong signal
    # that shouldn't be diluted into a general behavioral family.
    "honeypot_access": "direct_observation",

    # Geographic/policy fact about a destination -- not first-hand behavioral
    # evidence about what the device DID, a distinct category from all of the above.
    "geofencing_violation": "policy",

    # A confirmed exploit/malware signature match -- its own distinct vantage point
    # (a curated Suricata ruleset), not behavioral inference like everything above.
    "suricata_signature_match": "signature_match",

    # Statistical anomaly detection -- a distinct vantage point (an ML model's own
    # output), not the same as any specific behavioral sensor above.
    #
    # REVERSED (third-party architecture review, 2026-09-09): decision/engine.py's
    # own ml_anomaly branch already never sets HIGH/CRITICAL directly (only
    # ANOMALOUS/log). But before this change, this family still counted toward
    # OTHER hypotheses' independent-source total -- an unvalidated model output
    # could silently be the "second source" that promotes an unrelated hypothesis
    # to HIGH, the same indirect-promotion shape already found and fixed for
    # peer_deviation above. Now in NON_ATTACK_FAMILIES: an ML anomaly can still
    # produce its own ANOMALOUS verdict, it just can't corroborate anything else.
    "ml_anomaly": "ml_anomaly",

    # BENIGN-CONTEXT ONLY, deliberately excluded from attack corroboration counting
    # by decision/engine.py (mirrors v-current's own ATTACK_EVIDENCE_FAMILIES =
    # EVIDENCE_FAMILIES - {"local_context"}, hypotheses/evidence.py:71) -- real UPnP/
    # SSDP local-device-discovery traffic must never count toward "N independent
    # attack sources," the same way it can't in v-current.
    "local_device_discovery": "local_context",

    # v13 full-architecture plan, Phase 1a -- new capabilities the graph makes
    # possible, not ported from v-current (no v1 equivalent exists). A genuinely
    # distinct vantage point: "another device's own independent behavior," not a
    # sensor reading on THIS device at all -- counts toward independent-source
    # corroboration like any other family (2+ devices independently hitting the
    # same destination is real corroborating signal, not a context modifier).
    "coordinated_targeting": "cross_device_correlation",

    # Release 14, N4: same family as coordinated_targeting above -- "another
    # device independently corroborating this" is the same vantage point
    # regardless of whether the shared signal is a destination, a JA3/JA4
    # fingerprint, or a DGA generation shape.
    "fingerprint_campaign": "cross_device_correlation",
    "dga_seed_campaign": "cross_device_correlation",

    # Release 14, N2 -- a genuinely distinct vantage point from cross_device_
    # correlation above: THIS device's own behavior diverging from its peer
    # cohort's norm, not another device corroborating a shared observation.
    #
    # REVERSED (third-party architecture review + live audit, 2026-09-09): this
    # family used to count toward independent-source corroboration, on the
    # reasoning that PeerDeviationHypothesis's own 3.0 cap meant it could never
    # reach HIGH alone. That reasoning held for "alone" but not for "combined with
    # one other weak signal from any family" -- confirmed live, twice: a device
    # pooled into a fake device_type cohort reached HIGH from peer_deviation +
    # stale reputation evidence alone (zero real corroboration), and a normally-
    # active laptop (112 real distinct destinations/week) reached HIGH purely
    # because its "laptop" peer cohort was 5 near-dormant devices (0,0,0,0,1
    # destinations) -- a statistically fragile comparison, not real corroboration
    # of anything. Now in NON_ATTACK_FAMILIES: PeerDeviationHypothesis still fires
    # and still caps at SUSPICIOUS on its own, it just can no longer be the thing
    # that pushes an unrelated hypothesis over the HIGH bar.
    "peer_deviation": "peer_cohort_deviation",

    # Also Phase 1a: "this destination has never been contacted before" is a fact
    # ABOUT an existing observation (novelty), not itself an independent behavioral
    # signal the way a genuinely separate sensor is -- deliberately placed in
    # NON_ATTACK_FAMILIES below, the same treatment local_device_discovery gets,
    # so it can inform specific hypotheses' scoring without inflating "N
    # independent sources" on its own.
    "first_contact": "novelty_context",

    # Release 15, closed-loop autotuning architecture (v13/baseline/bayesian.py,
    # v13/baseline/engine.py). A statistical outlier is context, never proof --
    # same posture as ml_anomaly above, for the same reason (an unvalidated
    # model output must never silently be the second source that promotes an
    # unrelated hypothesis to HIGH).
    "baseline_deviation": "baseline_deviation",

    # A detected BOCPD regime change (a firmware/OS update reshaping a device's
    # traffic) is informational only -- never itself evidence of anything
    # attack-shaped. It only ever gates how much weight a device's own
    # new-regime data gets (baseline/engine.py's probation logic), never
    # corroborates a hypothesis.
    "regime_change": "regime_change",

    # Markov sequence-surprise, all axes (activity-state, destination-tier,
    # beaconing-interval). CORROBORATION DESIGN DECISION (see this file's own
    # docstring conventions): permanently non-attack-family, with NO exception
    # for whatever raw evidence happened to trigger the activity-state label
    # this cycle. This is the actual fix for a self-corroboration-through-
    # derivation risk found during a red-team pass (the Markov signal is
    # partly DERIVED from evidence that already has its own family, e.g.
    # peer_deviation -- the risk was a derived signal getting a fresh family
    # and pairing with its own raw input to fake a second independent
    # source). family_for() is looked up centrally by evidence_type alone
    # (confirmed via direct read of decision/engine.py's own corroboration-
    # counting, which re-derives family_for(e.evidence_type) rather than
    # trusting whatever independence_family is stored on the Evidence
    # instance) -- so a permanent, unconditional NON_ATTACK_FAMILIES
    # membership closes this structurally, with no per-instance override
    # needed or possible. The sequence classifier is itself an attack surface
    # (an adversary could try to shape event order to look like an
    # improbable escalation without real corroborating evidence), so it must
    # never open a new path to inflate severity on its own -- it still acts
    # as a severity/urgency multiplier on a verdict already corroborated some
    # other way, just never a corroborating SOURCE itself.
    "markov_activity_surprise": "sequence_dynamics",
    "markov_destination_surprise": "sequence_dynamics",
    "markov_beaconing_surprise": "sequence_dynamics",
}

# Mirrors v-current's ATTACK_EVIDENCE_FAMILIES exclusion exactly -- decision/engine.py
# excludes evidence in this family from independent-source counting toward an ATTACK
# verdict (it's legitimate evidence for the LocalDeviceDiscoveryHypothesis benign
# side, never for corroborating an attack). "novelty_context" (Phase 1a) gets the
# same treatment for the same structural reason -- see its own comment above.
# "peer_cohort_deviation" and "ml_anomaly" (third-party review + live audit,
# 2026-09-09) joined this set for the same reason: both are real signals worth a
# hypothesis's own verdict, but too cheap/unvalidated to count as one of the two
# independent SOURCES the whole HIGH bar rests on -- see each family's own comment
# above for the live incidents that found this.
#
# "policy" (external architecture review, 2026-09-09) joins for the identical
# reason: geofencing_violation is "a policy fact about a destination, not
# first-hand behavioral evidence about what the device DID" (its own comment
# above) -- the exact same cheapness argument already applied to peer_cohort_
# deviation/ml_anomaly, just not extended here until this review named it
# explicitly. The geofence hard-stop's OWN corroboration check (decision/
# engine.py's requires_corroboration, num_independent_sources>=1) is unaffected:
# it never depended on geofencing_violation counting itself (no hypothesis reads
# that evidence type at all, so attack_score stays 0 without a REAL attack
# hypothesis also firing -- confirmed against both existing geofence test
# scenarios before this change shipped). What this closes is geofencing being
# able to silently supply the SECOND independent source for an unrelated, weaker
# attack hypothesis via the normal (non-hard-stop) num_independent_sources>=2
# path -- a real destination-policy fact corroborating a behaviorally-unrelated
# finding is exactly the "unusual is not malicious" gap this whole family exists
# to close everywhere else.
NON_ATTACK_FAMILIES = frozenset({
    "local_context", "novelty_context", "peer_cohort_deviation", "ml_anomaly", "policy",
    # Release 15: see each new family's own comment above for why.
    "baseline_deviation", "regime_change", "sequence_dynamics",
})

UNKNOWN_FAMILY = "unregistered"  # visible fallback, see count_independent_families()'s own docstring


def family_for(evidence_type: str) -> str:
    return INDEPENDENCE_FAMILY_MAP.get(evidence_type, UNKNOWN_FAMILY)


def count_independent_families(evidence_types: Iterable[str]) -> int:
    """The actual corroboration-counting logic this whole file exists to support:
    counts DISTINCT families represented, not raw evidence-item count. An unknown
    evidence_type maps to UNKNOWN_FAMILY, which still counts as its own family
    (visible/inspectable, not silently dropped) -- but every unknown type collapses
    into the SAME single family, so five different not-yet-registered types don't
    inflate the count as five independent sources."""
    families: FrozenSet[str] = frozenset(family_for(t) for t in evidence_types)
    return len(families)
