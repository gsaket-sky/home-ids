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

    # General Zeek flow-level behavioral notices.
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
    # Counts toward independent-source corroboration like any other real
    # attack-shaped signal (never added to NON_ATTACK_FAMILIES) -- but
    # PeerDeviationHypothesis itself is deliberately capped low, so this signal
    # alone still can't reach HIGH without a second, different family
    # corroborating it (the decision engine's own >=2-independent-source gate).
    "peer_deviation": "peer_cohort_deviation",

    # Also Phase 1a: "this destination has never been contacted before" is a fact
    # ABOUT an existing observation (novelty), not itself an independent behavioral
    # signal the way a genuinely separate sensor is -- deliberately placed in
    # NON_ATTACK_FAMILIES below, the same treatment local_device_discovery gets,
    # so it can inform specific hypotheses' scoring without inflating "N
    # independent sources" on its own.
    "first_contact": "novelty_context",
}

# Mirrors v-current's ATTACK_EVIDENCE_FAMILIES exclusion exactly -- decision/engine.py
# excludes evidence in this family from independent-source counting toward an ATTACK
# verdict (it's legitimate evidence for the LocalDeviceDiscoveryHypothesis benign
# side, never for corroborating an attack). "novelty_context" (Phase 1a) gets the
# same treatment for the same structural reason -- see its own comment above.
NON_ATTACK_FAMILIES = frozenset({"local_context", "novelty_context"})

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
