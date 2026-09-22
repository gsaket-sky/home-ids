"""
humanize.py -- plain-English labels/descriptions for the raw identifiers this engine
produces internally (Evidence.type strings, attack/benign hypothesis names), so the
console can show something a non-engineer operator can read instead of a code
identifier. Server-side only, deliberately: API responses embed the resolved label
right on the JSON object (e.g. graph_api.py's evidence nodes gain `type_label`/
`type_description`) so console.html just renders whatever the server sends -- no
client-side copy of this dictionary to drift out of sync with it.

Source of truth for wording: Documentation/ALERT_CATEGORIZATION_CATALOG.md, which
already documents every hypothesis name's real trigger condition against production
data. Kept consistent with that file's language rather than re-invented here; if that
catalog's wording for something changes, mirror it here too.

Every Evidence.type string actually constructed anywhere in this codebase is listed
below (found by grepping every `Evidence(type=...)`/`evidence_type=...` call site, not
guessed). Anything NOT in the dict still renders correctly via label_evidence_type()'s
fallback -- a title-cased version of the raw string -- so a future new evidence type
never shows as a dead/missing label, just an un-glossed (but still readable) one until
this dict is updated for it.
"""
from typing import Optional, Tuple

EVIDENCE_TYPE_LABELS = {
    "arp_spoofing": ("ARP spoofing (MAC flip)", "A device's IP address suddenly answered from a different MAC address twice within 10 minutes -- the classic signature of an on-LAN man-in-the-middle attempt."),
    "arp_spoof_pending": ("Possible ARP spoofing (single flip)", "A device's IP briefly answered from a different MAC address once -- could be a DHCP lease change; only escalates to a confirmed finding on a second flip."),
    "ml_anomaly": ("ML behavioral anomaly", "This device's traffic pattern scored as unusual by the anomaly-detection model, relative to its own learned baseline."),
    "honeypot_access": ("Internal honeypot accessed", "This device contacted an internal decoy host that has no legitimate reason to ever be contacted -- a strong compromise indicator."),
    "zeek_lateral_scan": ("Internal lateral movement / port scan", "This device made rapid connection attempts to many internal hosts or ports -- the pattern Zeek's own connection logs use to flag scanning."),
    "geofencing_violation": ("Geofencing policy violation", "This device contacted a destination in a country your geofencing_countries policy blocks outright."),
    "local_device_discovery": ("Local device discovery", "Routine LAN discovery traffic (ARP/mDNS-style) -- almost always benign, logged as evidence rather than treated as a threat."),
    "reputation": ("Threat-intelligence reputation signal", "The destination's reputation score from VirusTotal/AbuseIPDB/OTX threat-intel feeds."),
    "dns_rate": ("Elevated DNS query rate", "This device is issuing DNS queries faster than its own learned baseline."),
    "dns_entropy": ("High DNS name entropy", "Queried domain names look more random than typical human/application traffic -- a DGA/tunneling indicator."),
    "dns_unique_ratio": ("High ratio of unique domains", "A high fraction of this device's DNS queries are for domains never seen before -- consistent with domain-generation-algorithm (DGA) traffic."),
    "dns_evasion_anomaly": ("DNS evasion pattern", "Query pattern consistent with evading DNS-based blocking (e.g. NXDOMAIN bursts, suspicious TLD concentration)."),
    "suricata_signature_match": ("Suricata signature match", "A real Suricata IDS rule fired against captured traffic for this device -- see the Suricata tab for which rule, when available."),
    # BUGFIX (explicit user request, 2026-09-09): "zeek_notice" fragmented into 4
    # evidence_type values by tier (utils.py's ZEEK_NOTICE_EVIDENCE_TYPES) -- same
    # base description, the label itself names the tier so an operator can tell a
    # routine capture artifact apart from a real attack-technique notice at a glance.
    "zeek_notice_weak": ("Zeek protocol notice (weak)", "Zeek's own protocol analyzers flagged something about this connection -- classified weak (routine TCP-framing/capture-timing artifact, not attacker behavior)."),
    "zeek_notice_medium": ("Zeek protocol notice (medium)", "Zeek's own protocol analyzers flagged something about this connection -- classified medium (touches real payload/protocol content, e.g. an invalid TLS cert)."),
    "zeek_notice_strong": ("Zeek protocol notice (strong)", "Zeek's own protocol analyzers flagged something about this connection -- classified strong (a well-documented attack-technique notice type, e.g. port scanning)."),
    "zeek_notice_highly_deterministic": ("Zeek protocol notice (highly deterministic)", "Zeek's own protocol analyzers flagged something about this connection -- classified highly deterministic (a curated threat-intel/signature match, not a probabilistic heuristic)."),
    "coordinated_targeting": ("Coordinated targeting", "Multiple devices on this network contacted the same suspicious destination in a short window -- suggests a coordinated campaign rather than one device acting alone."),
    "first_contact": ("First-ever contact with this destination", "This device has never been observed contacting this destination before now."),
    "fingerprint_campaign": ("TLS fingerprint campaign match", "This connection's JA3/JA4 TLS fingerprint matches a fingerprint seen across a wider malicious campaign."),
    "dga_seed_campaign": ("DGA seed-domain campaign", "This device's queried domains match a known domain-generation-algorithm seed pattern."),
    "peer_deviation": ("Deviates from peer devices", "This device's behavior differs significantly from other devices of the same type on this network."),
}

HYPOTHESIS_LABELS = {
    "DNS_TUNNELING": ("DNS tunneling", "Traffic pattern consistent with smuggling data through DNS queries/responses rather than normal name resolution."),
    "DNS_COVERT_TUNNELING": ("Covert DNS tunneling", "A stealthier DNS-tunneling pattern -- lower volume/more evasive than straightforward DNS_TUNNELING."),
    "NETWORK_INTRUSION": ("Network intrusion pattern", "Behavior consistent with a network intrusion attempt -- the single largest category system-wide, mostly single-source/lower-confidence findings."),
    "DGA_BOTNET_C2": ("DGA / botnet command-and-control", "Domain-generation-algorithm traffic consistent with a botnet reaching out to its command-and-control infrastructure."),
    "C2_BEACONING": ("Command-and-control beaconing", "Regular, low-jitter periodic connections to the same destination -- the signature of malware checking in with a C2 server."),
    "DATA_EXFILTRATION": ("Data exfiltration", "Outbound data volume/pattern consistent with data being extracted from this device."),
    "CONNECTION_ABUSE": ("Connection abuse", "Excessive or abusive connection behavior (e.g. rejected-connection floods) from this device."),
    "DNS_EVASION": ("DNS-based evasion", "Traffic pattern consistent with evading DNS-based blocking or filtering."),
    "DNS_ATTRIBUTION_GAP": ("DNS attribution gap", "DNS behavior that can't be cleanly attributed to a known-benign cause, without rising to a confirmed evasion finding."),
    "DNS_POLICY_BYPASS": ("DNS policy bypass", "Traffic consistent with bypassing this network's own DNS policy (e.g. hardcoded resolvers, DoH bypass)."),
    "SIGNATURE_MATCHED_THREAT": ("Suricata signature-matched threat", "A real Suricata IDS rule match against this device's captured traffic."),
    "ADVERTISING_BURST": ("Advertising/tracking burst", "A short burst of ad/tracking-network requests -- routine app behavior, not a threat."),
    "LOCAL_DEVICE_DISCOVERY": ("Local device discovery", "Routine LAN discovery traffic -- benign."),
    "DEVICE_PROFILE_TELEMETRY": ("Device telemetry", "Routine telemetry/check-in traffic typical of this device's own profile -- benign."),
    "UNKNOWN_BENIGN": ("No concerning pattern found", "Nothing about this evidence matched any attack hypothesis -- treated as benign by default, not because it was actively cleared."),
    "DIRECT_IOC_HIT": ("Matched a known-benign indicator", "Matched an entry the system already has confirmed as benign."),
    # Found missing (2026-09-22, plain-English alert rewrite): these 5 real
    # hypothesis names (argus/hypotheses/engine.py's own super().__init__()/
    # _NAME_* calls) had no entry here at all -- PEER_COHORT_DEVIATION and
    # COORDINATED_TARGETING both fire routinely in production, confirmed
    # against .94's real alert_events, so this wasn't a hypothetical gap.
    "PEER_COHORT_DEVIATION": ("Unusual compared to similar devices", "This device's behavior (e.g. how many different destinations it talks to) differs noticeably from other devices of the same type on this network."),
    "COORDINATED_TARGETING": ("Coordinated targeting", "Multiple devices on this network independently contacted the same suspicious destination in a short window -- suggests a coordinated campaign rather than one device acting alone."),
    "LATERAL_MOVEMENT": ("Internal lateral movement", "This device made rapid connection attempts to many other devices or ports on your own network -- the pattern of something trying to spread internally, not just talk to the outside internet."),
    "PORT_SCAN": ("Port scanning", "This device probed many different ports on one or more targets in quick succession -- the classic pattern of searching for an open door, not normal application traffic."),
    "INTERNAL_RECONNAISSANCE": ("Internal network scanning", "This device probed multiple other devices or services on your own network in a pattern consistent with mapping out what's there, not routine use."),
}


def label_evidence_type(evidence_type: str) -> Tuple[str, str]:
    """Returns (label, description) for an Evidence.type string. Falls back to a
    title-cased version of the raw type (never a blank/missing label) for any type not
    yet in EVIDENCE_TYPE_LABELS."""
    entry = EVIDENCE_TYPE_LABELS.get(evidence_type)
    if entry:
        return entry
    return evidence_type.replace("_", " ").title(), ""


def label_hypothesis(name: Optional[str]) -> Tuple[str, str]:
    """Same contract as label_evidence_type(), for attack/benign hypothesis names
    (intelligence/hypotheses/engine.py). Returns ("", "") for a falsy/missing name so
    callers can omit the field entirely rather than show a nonsense label."""
    if not name:
        return "", ""
    entry = HYPOTHESIS_LABELS.get(name)
    if entry:
        return entry
    return name.replace("_", " ").title(), ""
