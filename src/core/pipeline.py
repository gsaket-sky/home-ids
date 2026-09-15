"""
pipeline.py – Core Engine Execution Loop & Component Orchestrator.

RECENT ARCHITECTURAL FIXES:
- FIXED (MEMORY LEAK / GHOST RISK): Added rigorous time-based pruning for `state.rolling.domains` 
  and `state.rolling.events` inside the main execution loop. Prevents extreme risk scores from 
  permanently locking due to historical domains failing to age out.
- ADDED (LOGGING): Debug events tracked at pipeline start, loop cycle, scoring, and metrics export.
- FIXED (ML MIGRATION SYNC): Passed `self.ml_registry` directly into identity processing 
  so machine learning models are flawlessly synchronized whenever statistical baselines 
  are migrated to a new identity anchor.
"""

import ipaddress
import json
import logging
import math
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
from prometheus_client import start_http_server

from utils import sanitize_hostname, is_telemetry_domain, _is_cdn_or_cloud_domain, entropy as compute_entropy, etld1, register_safe_cdn_base_domains, is_local_or_multicast_destination, ZEEK_NOTICE_TIER_SCORE_WEIGHT, ZEEK_NOTICE_EVIDENCE_TYPES
from config import resolve_home_subnets
from core.state import BoundedSet
from core.state_guard import StateManager
from core.identity import DeviceIdentityManager
from core.heartbeat import HEARTBEATS
from core.metrics_sync import MetricsExporter
from extractors.dns_features import FeatureExtractor, PiHoleCollector
from extractors.zeek_features import ZeekCollector, ZeekFeatureExtractor
from extractors.fritzbox_capture import ReactiveCaptureDispatcher, cleanup_stale_scratch_files  # PHASE 21D
from intelligence.hypotheses.evidence import EvidenceStore, Evidence
from intelligence.reputation.classifier import ReputationClassifier
from intelligence.detectors.dns_behavior import DNSBehaviorDetector
from intelligence.detectors.zeek_network import ZeekNetworkDetector
from intelligence.detectors.threat_signals import ThreatSignalDetector  # PHASE 1
from core.decision_engine import DecisionEngine, DecisionState
from core.incident_tracker import IncidentTracker  # VERSION 10 (incident aggregation)
from incident_key import incident_key as _incident_key
from mitigation.alerts import AlertManager, AlertJSONWriter
from mitigation.ips import IPSMitigator
from intelligence.threat_intel import ThreatIntel, AbuseIPDB, VirusTotalClient
from intelligence.geoip import GeoIPEngine
from intelligence.ml_engine import MLRegistry
from intelligence.fp_engine import AutonomousFPEngine  # CL-AFPE: Closed-Loop Autonomous FP Engine
from argus.ops import live_engine as v13_live_engine  # v13 fast cutover -- see V13_ARCHITECTURE_DEPENDENCY_MAP.md
from argus.identity.live_manager import LiveIdentityManager  # v13 full-architecture plan, Phase 3
from argus.config.trust_anchors import load_trust_anchors_from_config, load_hardware_profile  # v13 full-architecture plan, Phase 3
from merge_fragmented_devices import find_fragmented_groups, pick_canonical  # device-identity fragmentation fix, in-process reconciliation worker


def _ip_family(ip: str) -> str:
    """v13 full-architecture plan, Phase 3: a real display gap found by direct
    investigation, not guessed -- alert payloads carry whatever raw address was
    active THIS cycle (client_ip) with no address-family label at all. Confirmed
    live this session: a real alert for the router showed a bare `fe80::...` link-
    local literal in `device.ip` with nothing explaining why "the router" suddenly
    displays an IPv6 address that cycle (this is the gateway's own MAC-based
    cross-address-family unification, identity.py:186-195, working as designed --
    just with zero indication of that in the alert itself). Never raises -- an
    unparseable ip string (shouldn't happen, but this must never break alert
    delivery) falls back to "unknown"."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if parsed.version == 4:
        return "ipv4"
    if parsed.is_link_local:
        return "ipv6-link-local"
    return "ipv6-global"

from metrics import alerts_total, ti_ioc_hits_total, ips_pihole_status, ips_router_status, ips_tarpit_status, integration_status_metric, honeypot_probes_total, ti_engine_ready_status, decision_path_total, persistence_escalation_total

# PHASE 1 (device-sensitivity source): infra device types are only trusted as "verified"
# (and therefore have certain behavioral evidence dampened) when device_type came from an
# operator-configured override — see core/identity.py's apply_device_type() and
# core/state.py's device_type_is_override field.
_INFRA_DEVICE_TYPES = frozenset({"dns_server", "router", "gateway"})
# Evidence types stripped for verified infrastructure — same rationale as the existing
# is_safe noisy_types stripping just below it: an operator-confirmed DNS server/router
# naturally produces DNS/connection volume that would misfire these detectors, but
# reputation/honeypot/lateral-movement/malicious-TLS evidence is NEVER stripped, so a
# genuinely compromised router still alerts.
_INFRA_NOISY_TYPES = {"dns_dga_burst", "dns_tunnel_v2", "zeek_beaconing", "zeek_conn_abuse", "zeek_long_conn",
                       "arp_sweep",  # BUGFIX: same gap as the is_safe noisy_types set above -- a router
                       # ARPing its own LAN is routine gateway behavior, not recon, for an
                       # operator-confirmed infra device either.
                       # BUGFIX (live audit): dns_evasion_anomaly (Phase 21C2, added well after
                       # this set was first written) was missing here too -- an operator-
                       # confirmed DNS server/resolver doing its own recursive resolution
                       # (querying root/TLD/authoritative servers directly, never through
                       # another Pi-hole) is EXACTLY what dns_evasion.py's policy_bypass check
                       # flags as "direct port-53/853 query to a non-Pi-hole resolver".
                       # Confirmed live: a real Pi-hole/unbound box generated 1,000+
                       # DNS_POLICY_BYPASS alerts over a week purely from its own normal
                       # upstream resolution traffic.
                       "dns_evasion_anomaly"}

LOGGER = logging.getLogger("home_ids.pipeline")

# Real DNS status classifications aligned with dns_features.py
BLOCKED_STATUSES = {1, 4, 5, 6, 7, 8, 10}
NXDOMAIN_STATUSES = {3, 12, 13}


# Reviewer suggestion, implemented: URI substrings characteristic of local media/UPnP
# device-discovery protocols (SSDP, DIAL app-launch) -- confirmed against real traffic
# in a live alert (dd.xml, ssdp/device-desc.xml, apps/com.spotify.Spotify.TVv2). Kept
# narrow and specific to well-known discovery-protocol conventions, not a broad "any
# local HTTP request is benign" rule -- a genuinely malicious local pivot would not
# typically request these exact, standardized discovery-protocol paths.
_LOCAL_DEVICE_DISCOVERY_URI_PATTERNS = (
    "/dd.xml", "/ssdp/", "/description.xml", "/apps/",  # UPnP/DIAL device + app discovery
)


def _count_local_device_discovery_requests(zeek_fx, client_ip: str) -> int:
    """Counts this device's recent HTTP requests that look like local media/UPnP
    device-discovery traffic (SSDP/DIAL) to another device on the SAME home network --
    see _LOCAL_DEVICE_DISCOVERY_URI_PATTERNS. Reuses the exact same zeek_fx.
    get_http_reqs() data source pipeline.py's own alert-display code (recent_http_reqs)
    already reads; this just also reads it at evidence-gathering time, not only at
    alert-build time, so decision_engine.py's benign-hypothesis track can weigh it."""
    if not zeek_fx or not client_ip:
        return 0
    count = 0
    for entry in zeek_fx.get_http_reqs(client_ip):
        host, _, uri = entry.partition("/")
        uri = "/" + uri
        host_ip = host.split(":", 1)[0]
        if not zeek_fx.is_home_ip(host_ip):
            continue
        if any(pat in uri for pat in _LOCAL_DEVICE_DISCOVERY_URI_PATTERNS):
            count += 1
    return count


# VERSION 11 (P2, review #23): this used to append a PROTOCOL guess to every size
# bucket ("Standard DNS/Control Packet" for anything <128B, regardless of whether it
# was actually DNS) -- purely a byte-count heuristic with no basis in the actual
# protocol. classify_service(port, proto) a few lines below already does correct
# port/protocol-based service naming from data this SAME alert payload already
# carries (dest_proto/dominant_protocol, sourced from Zeek's real connection
# parsing) -- the two were sitting side-by-side in the same alert with the size
# classifier's guess contradicting the real value next to it (confirmed live: a
# TCP:8883 MQTT connection under 128B displayed as "Standard DNS/Control Packet").
# This now describes size only, which is all it ever had grounds to claim.
def classify_payload_size(bytes_count: int) -> str:
    if bytes_count == 0: return "0 B"
    elif bytes_count < 128: return f"{bytes_count} B"
    elif bytes_count < 1024: return f"{bytes_count} B"
    elif bytes_count < 1024 * 1024: return f"{bytes_count / 1024.0:.1f} KB"
    elif bytes_count < 1024 * 1024 * 1024: return f"{bytes_count / (1024.0 * 1024.0):.2f} MB"
    else: return f"{bytes_count / (1024.0 * 1024.0 * 1024.0):.2f} GB"


def classify_service(port: int, proto: str = "TCP") -> str:
    known_ports = {
        53: "DNS", 80: "HTTP", 443: "HTTPS", 137: "NetBIOS Name", 138: "NetBIOS Datagram", 139: "NetBIOS Session",
        445: "SMB", 22: "SSH", 3389: "RDP", 1900: "SSDP / UPnP", 5353: "mDNS", 8080: "HTTP Alternate",
        8443: "HTTPS Alternate", 123: "NTP", 67: "DHCP Server", 68: "DHCP Client", 1883: "MQTT", 853: "DoT",
    }
    return known_ports.get(port, "Control / ICMP Ping" if port == 0 else f"{proto.upper()} Service")


# PHASE 21-ALERT-REDESIGN: plain-language descriptions for the Telegram "WHY" section --
# the raw evidence dump this replaces ("`dns_tunnel_v2` (340.0)") forced an operator to
# already know what each detector's internal magnitude means and what scale it's on, and
# a live-data audit found operators (and Ollama's own LLM analysis) reading it as if it
# were on the same 0-100 scale as the headline confidence percentage -- it never was. One
# sentence per evidence type, no numbers, so there's nothing left to misread as a
# probability. An unmapped type still degrades gracefully (de-snaked type name), never KeyErrors.
_EVIDENCE_PLAIN_LANGUAGE = {
    "dns_rate": "Unusually high DNS query rate for this device's own baseline",
    "dns_entropy": "High-entropy, random-looking domain names queried",
    "dns_unique_ratio": "Querying an unusually high number of distinct domains",
    "dns_evasion_anomaly": "Real network traffic with no matching DNS lookup history",
    "dns_dga_burst": "Burst of DGA-shaped (algorithm-generated) domain names",
    "dns_tunnel_v2": "DNS tunneling signature (encoded or unusually long subdomain labels)",
    "zeek_exfiltration": "Large outbound data transfer -- possible exfiltration",
    "zeek_beaconing": "Regular, beacon-like connection interval -- possible C2 check-in",
    "zeek_conn_abuse": "Abnormal connection pattern (many short-lived or rejected connections)",
    "zeek_long_conn": "Unusually long-lived connection",
    "arp_sweep": "ARP-swept many distinct hosts on the LAN (host-discovery behavior)",
    # BUGFIX (explicit user request, 2026-09-09): "zeek_notice" fragmented into 4
    # evidence_type values by tier (utils.py's ZEEK_NOTICE_EVIDENCE_TYPES) -- same
    # base text for all 4, since the actual distinguishing detail (note type + tier)
    # is appended by _describe_evidence()'s own notice_suffix, not this base text.
    "zeek_notice_weak": "Zeek policy notice fired for this connection",
    "zeek_notice_medium": "Zeek policy notice fired for this connection",
    "zeek_notice_strong": "Zeek policy notice fired for this connection",
    "zeek_notice_highly_deterministic": "Zeek policy notice fired for this connection",
    # BUGFIX (live audit, 2026-09-10): the bare "zeek_notice" key was dropped
    # when the 4 tiered entries above were added -- but evidence rows created
    # BEFORE that deploy still carry the old flat evidence_type (still valid
    # within the 24h graph window). Without this entry the base text fell
    # through to the ugly generic fallback ("Zeek notice") instead of this
    # sentence -- confirmed live in a real alert. Same backward-compat window
    # as INDEPENDENCE_FAMILY_MAP's own matching fix.
    "zeek_notice": "Zeek policy notice fired for this connection",
    "arp_spoofing": "Layer-2 ARP spoofing detected (this device's MAC address changed)",
    "arp_spoof_pending": "Possible ARP spoofing -- MAC change detected, not yet confirmed",
    "ml_anomaly": "Flagged as statistically anomalous by the ML baseline model",
    "honeypot_access": "Connected to the internal honeypot decoy server",
    "zeek_lateral_scan": "Internal port scanning / lateral movement across the LAN",
    "local_device_discovery": "Local network device-discovery traffic (e.g. UPnP/SSDP)",
    "reputation": "Destination has a poor external reputation score",
    "geofencing_violation": "Connection to a blocklisted country",
    "suricata_signature_match": "Matched a known attack/exploit signature (Suricata)",
    "malicious_ja3": "Malicious TLS client fingerprint (JA3)",
    "malicious_ja4": "Malicious TLS client fingerprint (JA4+)",
    "domain": "Destination domain matches a known-malicious reputation list",
    "ip": "Destination IP matches a known-malicious reputation list",
    "mixed": "Mixed reputation signal on this connection",
    # BUGFIX (live audit, 2026-09-09): these 4 are v13-only synthetic evidence
    # (v13/ops/live_engine.py, coordinated_targeting/peer_deviation's own docstrings)
    # that never existed in _EVIDENCE_PLAIN_LANGUAGE because they never existed in
    # active_evidence at all -- see the WHY-block synthetic-evidence bridging below.
    "coordinated_targeting": "Same destination independently reached by multiple other devices",
    "fingerprint_campaign": "Same TLS client fingerprint (JA3/JA4) shared with other devices",
    "dga_seed_campaign": "Same DGA-shaped domain-generation pattern shared with other devices",
    "peer_deviation": "Distinct-destination count far above this device's own peer cohort average",
}

# VERSION 12 (G8-for-live-alerts, HEE coverage audit): human-readable labels for
# evidence.py's EVIDENCE_FAMILIES (independence_group values) -- the WHY block below
# groups evidence by FAMILY (one entry per independence_group, the strongest in each),
# exactly the "3 DNS features != 3 independent signals" distinction this whole HEE
# review is about, but the header text still said "N independent signal(s)" -- correct
# on the COUNT (it always was a family count, not a raw-item count) but using the wrong
# WORD, which is exactly the ambiguity a third-party review flagged in ollama_soc.py's
# reporting (see Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's Gap 4, Phase 50) and
# that fix never reached this file's own, separate WHY-block text. An unmapped family
# still degrades gracefully (de-snaked title-cased group name), never KeyErrors --
# same fallback shape as _EVIDENCE_PLAIN_LANGUAGE above.
_EVIDENCE_FAMILY_LABELS = {
    "dns_behavior": "DNS Behavior",
    "dns_tunnel_v2": "DNS Tunneling",
    "zeek_network": "Network (Zeek)",
    "lan_recon": "Internal Discovery",
    "blindspot_audit": "DNS Blind-Spot Audit",
    "honeypot": "Honeypot",
    "ml_anomaly": "ML Anomaly",
    "local_context": "Local Context",
    "reputation": "Reputation",
    "suricata": "Signature Match",
    # BUGFIX (live audit, 2026-09-09): v13's own finer independence-family split
    # (hypotheses/independence.py) names these two families -- see
    # _EVIDENCE_PLAIN_LANGUAGE's matching new entries above for why they were never
    # reachable here before.
    "cross_device_correlation": "Cross-Device Correlation",
    "peer_cohort_deviation": "Peer-Cohort Deviation",
    # BUGFIX (live audit, 2026-09-09): v13's INDEPENDENCE_FAMILY_MAP names zeek_notice's
    # own family "network_behavior" (hypotheses/independence.py), a DIFFERENT string
    # than v1's "zeek_network" independence_group above -- a zeek_notice item reaching
    # the WHY-block via decision["attack_evidence"] (the corroborating-evidence bridge,
    # not the primary active_evidence loop) carries the v13 name directly and fell
    # through to the generic de-snake-cased fallback ("Network Behavior") instead of
    # this dict's own "Network (Zeek)" label -- confirmed live, the exact same
    # evidence shape showed two different family labels depending on which bridge
    # reached it.
    "network_behavior": "Network (Zeek)",
}

# BUGFIX (live audit, 2026-09-09): the 4 v13-only synthetic evidence types
# (v13/ops/live_engine.py's _inject_graph_derived_evidence()/
# _inject_peer_deviation_evidence()) mapped to v13's own independence-family name
# (hypotheses/independence.py's INDEPENDENCE_FAMILY_MAP) -- used to bridge
# decision["winning_evidence"] entries into the WHY-block grouping loop below, since
# these never exist in active_evidence (pipeline.py's own v1 evidence store) at all.
_V13_SYNTHETIC_EVIDENCE_FAMILY = {
    "coordinated_targeting": "cross_device_correlation",
    "fingerprint_campaign": "cross_device_correlation",
    "dga_seed_campaign": "cross_device_correlation",
    "peer_deviation": "peer_cohort_deviation",
}


def _describe_evidence(ev, geoip_engine=None) -> str:
    """One human-readable sentence for ONE piece of evidence -- see
    _EVIDENCE_PLAIN_LANGUAGE's module comment for why this replaced showing the raw
    per-signal magnitude directly. Appends the specific domain/IP this evidence came
    from when the detector attached one (Evidence.domain) -- this is the domain THIS
    evidence actually fired on, which is not guaranteed to be the alert's own "Target"
    line (that's the most-notable domain in the window, picked independently of which
    evidence fired -- a live-data audit found these can differ within one alert).

    BUGFIX (explicit user request, 2026-09-09): a bare IP here told a human reader
    nothing about what it actually was -- the "WHAT HAPPENED" section's own
    "Contacted" line already solved this exact problem for its own target
    (_build_geo_note(), added 2026-08-27 after a real WireGuard-to-Bharti-Airtel
    alert was unreadable without it), but the per-evidence WHY-block bullets never
    got the same treatment. geoip_engine is optional (defaults to None, e.g. for
    every existing test call site) -- _build_geo_note() itself already no-ops
    cleanly on None or a real domain name, so this never changes behavior for a
    caller that doesn't have a GeoIPEngine handy."""
    text = _EVIDENCE_PLAIN_LANGUAGE.get(ev.type, ev.type.replace("_", " ").capitalize())
    ev_domain = getattr(ev, "domain", None)
    geo_note = _build_geo_note(geoip_engine, ev_domain) if ev_domain else ""
    domain_suffix = f" — `{ev_domain}`{geo_note}" if ev_domain else ""
    # BUGFIX (reviewer suggestion, implemented): zeek_notice previously gave no way to
    # tell a genuinely alarming notice type apart from a routine one -- provenance now
    # carries the real note type (see zeek_network.py), surfaced here the same way
    # domain_suffix already surfaces per-evidence detail for other types.
    # BUGFIX (explicit user request, 2026-09-09): evidence_type is now
    # "zeek_notice_{tier}" (utils.py's ZEEK_NOTICE_EVIDENCE_TYPES) instead of a flat
    # "zeek_notice" with the tier hidden in a provenance subtag -- the tier comes
    # straight from ev.type now, provenance only needs to carry the note type
    # ("detector:zeek:notice:{note_type}", split(":", 3)[3]). The tier itself is
    # shown too, not just the raw note type -- "Zeek policy notice fired --
    # weird:data_before_established" told a human nothing about whether that
    # specific notice was actually worth their attention or routine capture noise;
    # "(weak)" vs. "(highly deterministic)" does.
    notice_suffix = ""
    if ev.type in ZEEK_NOTICE_EVIDENCE_TYPES and getattr(ev, "provenance", ""):
        tier = ev.type[len("zeek_notice_"):]
        parts = ev.provenance.split(":", 3)
        note_type = parts[3] if len(parts) == 4 else ""
        if note_type and note_type != "unknown":
            notice_suffix = f" — `{note_type}` _({tier.replace('_', ' ')})_"
    elif ev.type == "zeek_notice" and getattr(ev, "provenance", ""):
        # BACKWARD COMPAT: evidence written before this fragmentation deploy still
        # carries the old flat "zeek_notice" evidence_type -- still valid within the
        # 24h graph window, self-resolving as it ages out. Its provenance may be in
        # EITHER the tier-in-provenance format (detector:zeek:notice:{tier}:
        # {note_type}, from the same-day tiering fix that preceded this
        # fragmentation) or the original untiered format (detector:zeek:notice:
        # {note_type}) -- try the 5-segment tiered form first so evidence from
        # earlier today still shows its tier, falling back to the 4-segment
        # untiered form so older evidence still shows a note type rather than
        # going silent.
        parts5 = ev.provenance.split(":", 4)
        if len(parts5) == 5 and parts5[3] in ZEEK_NOTICE_TIER_SCORE_WEIGHT and parts5[4] and parts5[4] != "unknown":
            notice_suffix = f" — `{parts5[4]}` _({parts5[3].replace('_', ' ')})_"
        else:
            parts4 = ev.provenance.split(":", 3)
            if len(parts4) == 4 and parts4[3] and parts4[3] != "unknown":
                notice_suffix = f" — `{parts4[3]}`"
    return f"{text}{domain_suffix}{notice_suffix}"


# ALERT REDESIGN: the previous Telegram alert exposed two raw, differently-scaled
# percentages ("Is this the attack? -> 89%" / "Could this be a FP? -> 12%") and left
# it to the operator to reconcile them under a live incident, with no statement of
# what (if anything) already happened or what happens if they do nothing. These two
# helpers compute that reconciliation once, in plain language, instead of leaving it
# to the reader -- see the alert_msg assembly below for how they're used.
def _build_status_lines(action_summary: str, mixed_signal: bool) -> tuple:
    """Returns (already_done_emoji, already_done_text, your_move_text, if_nothing_text)
    for the alert's top status block, keyed off the same action_summary already
    derived from containment_status. `mixed_signal` (true confidence conflicts with
    the false-positive check) softens an "already blocked, nothing to do" line into
    a "please double-check" line without changing what action was actually taken.

    BUGFIX (live audit): "auto-blocked" (Pi-hole domain block) previously shared the
    exact same "device auto-blocked from the network"/"the block stays in place"
    wording as router isolation and Layer-2 tarpit -- both of which really do cut a
    device off. A single domain being Pi-hole-blocked does not; the device keeps
    full network/internet access otherwise. Confirmed live: this contradicted the
    SAME alert's own "WHAT HAPPENED" section three lines down, which correctly said
    "DOMAIN BLOCKED." Each containment type now gets its own accurate, plain-language
    description of what actually happened and what staying idle actually means --
    not a shared template that overstates the mildest case to match the severity of
    the other two.
    """
    contained_text = {
        "tarpitted (Layer-2)": (
            "this device's network traffic is being intercepted and slowed to a crawl "
            "at the network level (a \"tarpit\") -- it can't reliably reach anything "
            "until released.",
            "the tarpit stays active until you release it.",
        ),
        "router isolated": (
            "this device has been cut off from the internet at your router -- it can "
            "still reach other devices on your home network, but not the outside world, "
            "until released.",
            "the device stays cut off from the internet until you release it.",
        ),
        "auto-blocked": (
            "one specific domain this device was trying to reach has been blocked via "
            "Pi-hole -- the DEVICE ITSELF is not blocked; everything else it does still "
            "works normally.",
            "just that one domain stays blocked until you release it -- nothing else "
            "about this device is affected.",
        ),
    }
    if action_summary in contained_text:
        already_done_text, if_nothing_text = contained_text[action_summary]
        your_move = (
            "review below -- there's a real chance this is a false positive. Release if it looks wrong."
            if mixed_signal else
            'nothing required -- tap "Release" only if you\'re sure this is a false positive.'
        )
        return "✅", already_done_text, your_move, if_nothing_text

    if action_summary == "awaiting approval":
        # BUGFIX (2026-09-01, button/description audit): only an "Approve Hardware
        # Isolation" button is ever attached in this state (see the inline_keyboard
        # assembly below -- Release was deliberately removed from here on 2026-08-29,
        # since nothing is contained yet so there's nothing to release). This text
        # said "approve or release using the buttons below" regardless -- stale,
        # predates and was missed by that same fix. Corrected to match the one
        # button that's actually there.
        return (
            "⏳", "nothing yet -- action is queued, waiting for your approval via the buttons below.",
            "tap Approve below if you want this isolated -- otherwise do nothing, it stays unblocked.",
            "the device stays on the network, unblocked, until you approve isolation.",
        )

    # BUGFIX (2026-09-01, button/description audit): "review below and decide
    # manually" implied unspecified options without saying what they are. The only
    # button ever attached in this state ("monitoring only") is Mark False Positive
    # (added unconditionally whenever the target is known -- see the inline_keyboard
    # assembly below); there is no isolation button to "decide" between. Named the
    # one real action instead of leaving it vague.
    return (
        "⚠️", "nothing -- traffic is being monitored only, not blocked.",
        "no isolation action available at this severity -- tap \"Mark False Positive\" below if this looks wrong, otherwise no action needed.",
        "the device stays on the network; this alert repeats if the behavior continues.",
    )


def _build_confidence_line(threat_conf_pct: int, fp_verdict: Dict[str, Any], fp_pct: int, fp_calibrated_pct: Optional[int]) -> tuple:
    """Returns (confidence_label, confidence_line_text, mixed_signal_bool). Folds the
    two previously-separate raw percentages into one synthesized verdict -- the
    system already computes which side "wins" (that's what gates HIGH/CRITICAL and
    the >=0.75 false-positive-lean check below), so it should say so rather than
    handing the reader two uncomparable numbers.
    """
    fp_stage = str(fp_verdict.get("stage", ""))
    if "HARD_STOP" in fp_stage:
        return "Very High", "Very High -- matched a known-bad signature directly _(not a probabilistic estimate)_", False

    fp_risk_pct = fp_calibrated_pct if fp_calibrated_pct is not None else fp_pct
    calib_suffix = "" if fp_calibrated_pct is not None else " _(uncalibrated estimate)_"

    if fp_risk_pct >= 50:
        label = "Mixed"
        detail = (f"attack pattern matches ({threat_conf_pct}%), but our false-positive check leans "
                  f"benign ({fp_risk_pct}% chance this is a false positive) -- worth a manual look")
    elif fp_risk_pct >= 25:
        label = "Moderate"
        detail = (f"attack pattern matches ({threat_conf_pct}%); some chance this is benign "
                  f"({fp_risk_pct}%) -- quick review recommended")
    else:
        label = "High"
        detail = (f"attack pattern strongly matches ({threat_conf_pct}%), and our false-positive check "
                  f"disagrees only weakly ({fp_risk_pct}% chance this is benign)")

    return label, f"{label} -- {detail}{calib_suffix}", fp_risk_pct >= 50


def _build_geo_note(geoip_engine: Any, ip: str) -> str:
    """Returns a formatted ' _(Org, Country)_' geo/ASN annotation for a raw IP, or ''
    if unavailable. Extracted from the WHAT HAPPENED section's existing inline geo-note
    logic (same lookup_asn()/lookup() calls, same format) so the autonomous-action
    revoke prompt can show the same "who/where is this" context without duplicating it
    -- both are pure local mmdb reads (lookup_asn is @lru_cache'd), cheap enough to call
    on every alert."""
    if not ip or ip == "unknown" or not geoip_engine:
        return ""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ""
    asn_res = geoip_engine.lookup_asn(ip)
    city_res = geoip_engine.lookup(ip)
    geo_org = getattr(asn_res, "autonomous_system_organization", None) if asn_res else None
    geo_country = getattr(getattr(city_res, "country", None), "name", None) if city_res else None
    geo_parts = [p for p in (geo_org, geo_country) if p]
    return f" _({', '.join(geo_parts)})_" if geo_parts else ""


class EnginePipeline:
    def __init__(
        self, config, state_manager: StateManager = None, ti_engine: ThreatIntel = None, 
        ml_registry: MLRegistry = None, geoip_engine: GeoIPEngine = None, 
        ips_mitigator: IPSMitigator = None, pihole_collector: PiHoleCollector = None, 
        shared_alert_writer: AlertJSONWriter = None,
    ):
        self.config = config
        self.running = False

        LOGGER.debug("Activating configuration file live-watcher daemon.")
        if hasattr(self.config, "start_watcher"):
            self.config.start_watcher(interval=10.0)

        state_path = self.config.get("state_path", "state/ids_state.json")
        state_dir = Path(state_path).parent
        state_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir = state_dir  # PHASE 18: sync_relay_metrics() needs this every cycle

        # v13 full-architecture plan, Phase 1: point the live graph store at THIS box's
        # own state dir (matching every other state file's location) rather than the
        # module's bare relative default -- avoids depending on soc.service's CWD
        # happening to already be the right directory. Moved here (before
        # self.identity_manager below) specifically so Phase 3's LiveIdentityManager
        # can call v13_live_engine.get_graph_store() and get the CORRECTLY-configured
        # singleton, not one lazily initialized against the wrong default path.
        # v13 full-architecture plan, Phase 10b: hardware_profile-driven SQLite
        # cache_size tuning for the live graph store singleton (GraphStore's own
        # PRAGMA cache_size, see graph/store.py's _HARDWARE_PROFILE_CACHE_SIZE_KB).
        v13_live_engine.configure(str(state_dir / "v13_graph.db"),
                                    hardware_profile=load_hardware_profile(self.config))

        # v13 full-architecture plan, device-state unification: mirrors each
        # device's COLD fields (hostname/device_type/confirmed_threat_count/etc.,
        # see DeviceState.to_graph_metadata()) into the graph on every
        # flush_to_disk() -- the hot fields (baselines/rolling) never leave this
        # process. Same already-configured graph store singleton every other v13
        # write path this cycle reuses, not a second connection.
        self.state_manager = state_manager or StateManager(
            state_path=state_path, max_devices=int(self.config.get("max_device_states", 5000)),
            graph_store=v13_live_engine.get_graph_store(),
        )
        if state_manager is None:
            self.state_manager.load_from_disk(alpha=float(self.config.get("baseline_alpha", 0.05)))

        # v13 full-architecture plan, Phase 3: config.get("engine", "argus") == "argus"
        # (the default) swaps in LiveIdentityManager -- a real DeviceIdentityManager
        # SUBCLASS (Fritz!Box polling, process_dns_identities/process_zeek_identities,
        # apply_device_type, orphan-merge cleanup all inherited UNCHANGED; only
        # resolve_device_id() itself is overridden) generalizing the single hardcoded
        # gateway_ip to config.yaml's network.trust_anchors (Phase 2's loader) plus
        # real MAC-randomization detection. Same rollback flag as the decision engine
        # (A13) -- "v_current" uses the real, unmodified DeviceIdentityManager exactly
        # as before Phase 3 existed.
        if self.config.get("engine", "argus") == "argus":
            trust_anchors = load_trust_anchors_from_config(self.config)
            self.identity_manager = LiveIdentityManager(
                self.state_manager, self.config, v13_live_engine.get_graph_store(), trust_anchors,
            )
        else:
            self.identity_manager = DeviceIdentityManager(self.state_manager, self.config)

        self.ti_engine = ti_engine
        self.ml_registry = ml_registry
        if self.ml_registry: self.ml_registry.load_models()
        
        self.geoip_engine = geoip_engine or GeoIPEngine(db_path=self.config.get("geoip_db", str(state_dir / "GeoLite2-City.mmdb")), asn_db_path=self.config.get("geoip_asn_db", ""))

        cache_dir = state_dir / "ti_cache"
        abuse_key = self.config.get("abuseipdb_api_key", "")
        self.abuseipdb = AbuseIPDB(api_key=abuse_key, cache_dir=cache_dir, refresh_interval=int(self.config.get("ti_refresh_interval", 3600)))
        self.abuseipdb.start_refresh_thread()
        if abuse_key:
            LOGGER.info("AbuseIPDB integration activated successfully.")
            integration_status_metric.labels("abuseipdb").set(1)
        else:
            integration_status_metric.labels("abuseipdb").set(0)
            
        vt_key = self.config.get("virustotal_api_key", "")
        self.virustotal = VirusTotalClient(api_key=vt_key, cache_dir=cache_dir)
        if vt_key:
            LOGGER.info("VirusTotal integration activated successfully.")
            integration_status_metric.labels("virustotal").set(1)
        else:
            integration_status_metric.labels("virustotal").set(0)
            
        if self.ti_engine and self.ti_engine.otx_api_key:
            LOGGER.info("AlienVault OTX integration activated successfully.")
            integration_status_metric.labels("otx").set(1)
        else:
            integration_status_metric.labels("otx").set(0)

        self.dns_extractor = FeatureExtractor()
        safe_ips = set(self.config.get("safe_ips", []))
        safe_patterns = set(self.config.get("safe_host_patterns", []))

        honeypot_ips = set(self.config.get("honeypot_ips", []))
        if bool(self.config.get("ips_enabled", True)) and not honeypot_ips and bool(self.config.get("ips_router_enabled", False)):
            LOGGER.warning("⚠️ IPS router isolation is enabled but no honeypot IPs are configured. Router isolation will remain inert until honeypot_ips is populated.")
        # PHASE 21D: the two wired devices (NAS/server) already have full Zeek flow
        # visibility today -- a new source IP contacting one of them for the first
        # time is worth a reactive-capture burst. Empty by default (opt-in, since it
        # names specific real device IPs).
        wired_probe_ips = set(self.config.get("reactive_capture_wired_probe_ips", []))
        self.zeek_fx = ZeekFeatureExtractor(
            home_subnets=resolve_home_subnets(self.config),  # PHASE 0 FIX: multi-subnet support
            ti_engine=self.ti_engine, geoip_engine=self.geoip_engine,
            safe_ips=safe_ips, honeypot_ips=honeypot_ips, safe_patterns=safe_patterns,
            wired_probe_ips=wired_probe_ips,
            lateral_ports=set(self.config.get("lateral_movement_ports", [22, 445, 3389, 5900, 23])),
        )

        self.zeek_collector = ZeekCollector(log_dir=self.config.get("zeek_log_dir", "/opt/zeek/logs/current"), poll_interval=float(self.config.get("poll_interval", 2.0)), state_dir=state_dir)
        self.pihole_collector = pihole_collector or PiHoleCollector(db_path=self.config.get("pihole_db", "/etc/pihole/pihole-FTL.db"), lookback_seconds=int(self.config.get("startup_lookback_seconds", 300)), excluded_ips=safe_ips, excluded_patterns=safe_patterns)

        self.evidence_store = EvidenceStore()
        # VERSION 10 (incident aggregation): config-driven so an operator can tune
        # notification density without a code change, same pattern as
        # suspicious_escalation_seconds. See incident_tracker.py for the full rationale.
        self.incident_tracker = IncidentTracker(
            grouping_window_seconds=float(self.config.get("incident_grouping_window_seconds", 1800.0)),
            update_min_interval_seconds=float(self.config.get("incident_update_min_interval_seconds", 900.0)),
        )
        self.rep_classifier = ReputationClassifier()
        self.dns_detector = DNSBehaviorDetector()
        self.zeek_detector = ZeekNetworkDetector()
        self.threat_signal_detector = ThreatSignalDetector()  # PHASE 1
        self.decision_engine = DecisionEngine()
        self.alert_writer = shared_alert_writer or AlertJSONWriter(path=self.config.get("alert_json_path", str(state_dir / "alerts.json")), max_bytes=int(self.config.get("alert_json_max_bytes", 1073741824)))
        self.alert_manager = AlertManager(
            token=self.config.get("telegram_token", ""), 
            chat_id=self.config.get("telegram_chat_id", ""), 
            enabled=bool(self.config.get("telegram_enabled", False))
        )

        if self.config.get("telegram_token") and bool(self.config.get("telegram_enabled", False)):
            interactive = "ENABLED" if self.config.get("interactive_blocking_enabled", False) else "DISABLED"
            LOGGER.info(f"Telegram integration activated (Interactive Blocking: {interactive}).")
            integration_status_metric.labels("telegram").set(1)
        else:
            integration_status_metric.labels("telegram").set(0)
        
        # v13 full-architecture plan, IPS containment unification: the graph store
        # singleton is already configured above (v13_live_engine.configure()) --
        # reused here, not a second connection, matching LiveIdentityManager's own
        # v13_live_engine.get_graph_store() call site. Passed unconditionally
        # (not gated on config.get("engine")) since the containment audit mirror
        # is a useful record regardless of which decision engine is live -- it's
        # optional/best-effort at IPSMitigator's own call sites either way.
        self.ips_mitigator = ips_mitigator or IPSMitigator(
            config=self.config, state_manager=self.state_manager, stream_writer=self.alert_writer,
            graph_store=v13_live_engine.get_graph_store(),
        )
        self.ips_mitigator.state_manager = self.state_manager
        
        self.metrics_exporter = MetricsExporter()

        # PHASE 21D: shared hourly-budget gate for every reactive-capture trigger below
        # (new device, ARP-sweep, DNS-suspicion, HIGH/CRITICAL, periodic spot-check) --
        # one instance so the budget is genuinely shared, not per-trigger-type. See
        # ReactiveCaptureDispatcher's docstring in extractors/fritzbox_capture.py.
        self.reactive_capture = ReactiveCaptureDispatcher()
        # Seeded to "now", not 0 -- avoids firing a spot-check burst immediately on
        # every process restart; the first one fires after a full interval has
        # elapsed, same as a cron-scheduled job would behave.
        self._last_reactive_spotcheck_ts = time.time()

        # -----------------------------------------------------------------------
        # Closed-Loop Autonomous FP Engine (CL-AFPE)
        # Instantiated here so it boots its background ML loader threads immediately.
        # The engine runs in the same process but offloads model inference to daemon
        # threads so the pipeline timing is unaffected during cold-start warm-up.
        # -----------------------------------------------------------------------
        LOGGER.info("🤖 Booting Autonomous False-Positive Elimination Engine (CL-AFPE)...")
        self.fp_engine = AutonomousFPEngine(
            config=self.config,
            state_dir=str(state_dir),
            state_manager=self.state_manager,
        )
        if self.ti_engine:
            self.ti_engine.fp_engine = self.fp_engine

        self._last_flush = time.time()
        self._last_prune = time.time()

        def _on_config_reload(changed_keys):
            LOGGER.info("Dynamic configuration change detected: %s", changed_keys)
            if "safe_ips" in changed_keys:
                new_safe = set(self.config.get("safe_ips", []))
                self.pihole_collector.excluded_ips = new_safe
                self.zeek_fx.safe_ips = new_safe
            if "safe_host_patterns" in changed_keys:
                new_patterns = {str(p).lower().strip() for p in self.config.get("safe_host_patterns", []) if str(p).strip()}
                self.pihole_collector.excluded_patterns = new_patterns
                self.zeek_fx.safe_patterns = new_patterns
            if "telegram_enabled" in changed_keys:
                self.alert_manager.enabled = bool(self.config.get("telegram_enabled", False))
            if "home_subnet" in changed_keys or "home_subnets" in changed_keys:
                self.zeek_fx.set_home_subnets(resolve_home_subnets(self.config))  # PHASE 0 FIX
            if "honeypot_ips" in changed_keys:
                self.zeek_fx.honeypot_ips = set(self.config.get("honeypot_ips", []))
            if "zeek_log_dir" in changed_keys:
                self.zeek_collector.update_log_dir(self.config.get("zeek_log_dir", "/opt/zeek/logs/current"))
            if "safe_cdn_base_domains" in changed_keys:
                register_safe_cdn_base_domains(self.config.get("safe_cdn_base_domains", []))

        if hasattr(self.config, "set_notify"):
            self.config.set_notify(_on_config_reload)

        # Initial population at boot -- the reload hook above only fires on a LATER
        # change, not the config this process already started with.
        register_safe_cdn_base_domains(self.config.get("safe_cdn_base_domains", []))

        # Device-identity fragmentation fix (continuation session): background
        # reconciliation worker, matching IPSMitigator's own established
        # background-worker pattern (_router_reconcile_worker, ips.py) exactly --
        # daemon thread, started here (after every collaborator it needs --
        # state_manager/ml_registry/fp_engine/identity_manager/ips_mitigator/
        # evidence_store/metrics_exporter -- already exists on self).
        #
        # Deliberately NOT a scheduled_jobs.scheduler entry (the pattern
        # live_prune.py/live_decision_archive.py/cl_afpe_flip_monitor.py use):
        # that mechanism spawns each job as a SEPARATE SUBPROCESS
        # (scripts/scheduler.py's own subprocess.Popen calls) against
        # state/ids_state.json on disk. soc.service runs continuously with its
        # OWN in-memory StateManager._states, flushing to disk every ~60s
        # (flush_to_disk()) -- an external process's merge would be silently
        # overwritten by the live process's own next flush within a minute.
        # .ipc_sync_signal's existing live-reconciliation path (see below in
        # _step()) only ever pulls IPS state back into memory, never the
        # devices dict -- it does not cover this case either. This worker runs
        # IN this process instead, mutating self.state_manager directly under
        # its own lock, so there is no split-brain window at all.
        LOGGER.info("Starting Device-Identity Reconciliation Worker Thread...")
        threading.Thread(target=self._identity_reconcile_worker, daemon=True, name="identity_reconcile_worker").start()

    def _identity_reconcile_worker(self) -> None:
        """Periodically finds and merges device-identity fragmentation (the same
        union-find over shared known-IP / shared MAC / shared non-generic hostname
        / DHCP+JA4 fingerprint corroboration that src/merge_fragmented_devices.py's
        offline CLI tool already uses -- find_fragmented_groups()/pick_canonical()
        imported directly, one shared implementation for both callers) against the
        LIVE self.state_manager, not an on-disk snapshot.

        Runs one pass IMMEDIATELY at boot (same reasoning as IPSMitigator's own
        boot-time reconcile fix -- ips.py:100-113 -- "so a restart converges to
        real state right away"), then sleeps identity_reconcile_interval_seconds
        (config, default 600.0) and repeats. A first-pass judgment call, not
        empirically tuned, same honesty framing this project's own
        INDEPENDENCE_FAMILY_MAP already uses for a similar not-yet-validated
        number -- between _router_reconcile_worker's 300s status-check cadence and
        something much slower, since a merge is more consequential than a status
        poll.

        Per merge: reuses merge_into_canonical() (state_guard.py) -- the SAME
        primitive the real-time _merge_orphan_if_fragmented() path already uses --
        then drains the EXACT SAME consume-once cleanup side channels
        (_last_migrated_isolation_target/_last_orphan_merge_cleanup) via
        self.identity_manager's own _release_stale_isolation_if_merged()/
        _cleanup_merged_orphan(), rather than reimplementing that cleanup a second
        time. This closes a real gap the offline script itself flags: it has no
        live ml_registry/fp_engine/ips_mitigator/evidence_store/metrics_exporter
        to pass through, so orphan ML model files and stale isolation/metric state
        are left behind; this worker has all of them as real, live self.*
        references.

        Every failure mode is best-effort/non-fatal -- this must never crash the
        pipeline's own main loop, which runs in a separate thread untouched by
        anything here."""
        interval = float(self.config.get("identity_reconcile_interval_seconds", 600.0))
        if interval <= 0:
            interval = 600.0
        first_pass = True
        while True:
            if not first_pass:
                time.sleep(interval)
            first_pass = False
            try:
                self._identity_reconcile_pass()
                HEARTBEATS.beat("identity_reconcile_worker", health_state="healthy")
            except Exception as exc:
                LOGGER.error("Identity reconcile worker pass failed (non-fatal, will retry next interval): %s",
                             exc, exc_info=True)
                HEARTBEATS.beat("identity_reconcile_worker", health_state="degraded")

    def _identity_reconcile_pass(self) -> int:
        """One reconciliation pass -- factored out of _identity_reconcile_worker()'s
        own sleep-loop so it's directly callable/testable without an infinite loop
        (e.g. to assert on a specific merge's cleanup side effects) and so a boot-time
        immediate pass and the periodic one share exactly one implementation. Returns
        the number of device_ids actually merged this pass."""
        groups = find_fragmented_groups(self.state_manager)
        merged_count = 0
        for group in groups:
            canonical = pick_canonical(group)
            for orphan in group:
                if orphan["device_id"] == canonical["device_id"]:
                    continue
                if self.state_manager.merge_into_canonical(
                    orphan["device_id"], canonical["device_id"],
                    ml_registry=self.ml_registry, fp_engine=self.fp_engine,
                ):
                    merged_count += 1
                    try:
                        self.identity_manager._release_stale_isolation_if_merged(self.ips_mitigator)
                        self.identity_manager._cleanup_merged_orphan(self.evidence_store, self.metrics_exporter)
                    except Exception as exc:
                        LOGGER.warning(
                            "Identity reconcile: cleanup after merging %s -> %s failed "
                            "(the merge itself already succeeded): %s",
                            orphan["device_id"], canonical["device_id"], exc,
                        )
                    try:
                        v13_live_engine.get_graph_store().merge_device(orphan["device_id"], canonical["device_id"])
                    except Exception as exc:
                        LOGGER.debug(
                            "Identity reconcile: graph-side merge mirror failed for %s -> %s "
                            "(the real v1 merge already succeeded, unaffected): %s",
                            orphan["device_id"], canonical["device_id"], exc,
                        )
        if merged_count:
            LOGGER.warning(
                "🔗 [IDENTITY RECONCILE] Merged %d fragmented device_id(s) into %d "
                "canonical identit(y/ies).", merged_count, len(groups),
            )
            if self.config.get("telegram_enabled", False):
                self.alert_manager.send(
                    f"🔗 *Identity reconciliation*: merged {merged_count} fragmented "
                    f"device(s) into {len(groups)} canonical identit(y/ies)."
                )
        return merged_count

    def run(self) -> None:
        metrics_port = int(self.config.get("metrics_port", 9105))
        try:
            start_http_server(metrics_port)
            LOGGER.info("📊 Prometheus metrics server running on port %d", metrics_port)
        except Exception as exc:
            LOGGER.error("Failed to start Prometheus server on port %d: %s", metrics_port, exc)

        if self.config.get("telegram_enabled", False):
            self.alert_manager.send("🚀 *Home IDS Network Security Engine Online*")

        self.running = True
        LOGGER.info("🟢 Pipeline loop active. Ingesting network telemetry...")

        while self.running:
            start_time = time.time()
            try:
                self._step(now=start_time, window_seconds=int(self.config.get("window_seconds", 300)), alert_threshold=float(self.config.get("alert_threshold", 6.0)))
            except Exception as exc:
                LOGGER.error("Unhandled error during pipeline step execution: %s", exc, exc_info=True)
            elapsed = time.time() - start_time
            # BUGFIX (health manager, CONSERVATION-tier degradation): under sustained
            # resource pressure, HealthManager sets this attribute (never touches
            # poll_interval itself, so the normal-path behavior above is unchanged) to
            # slow the loop down and ease CPU/allocation pressure until pressure clears.
            poll_interval = max(float(self.config.get("poll_interval", 2.0)), float(getattr(self, "_health_pressure_poll_floor", None) or 0.0))
            time.sleep(max(0.05, poll_interval - elapsed))

    def _step(self, now: float, window_seconds: int, alert_threshold: float) -> None:
        LOGGER.debug("Starting pipeline processing step at %f", now)
        # BUGFIX (health manager): lets HealthManager (a separate daemon thread in
        # this same process, started from main.py) detect a hung/stuck main loop --
        # a step that stops calling _step() entirely (deadlock, an infinite loop in
        # a detector) would otherwise be invisible until something else noticed.
        HEARTBEATS.beat("pipeline_main_loop", queue_depth=self.alert_manager.q.qsize() if self.alert_manager else None)
        ips_pihole_status.set(1.0 if self.config.get("ips_pihole_enabled", True) else 0.0)
        ips_router_status.set(1.0 if self.config.get("ips_router_enabled", False) else 0.0)
        ips_tarpit_status.set(1.0 if self.config.get("ips_tarpit_enabled", True) else 0.0)
        ti_engine_ready_status.set(1.0 if (self.ti_engine and self.ti_engine.is_ready()) else 0.0)  # PHASE 5 FIX

        # PHASE 21D trigger: periodic spot-check, deliberately kept IN-PROCESS rather
        # than a separate scheduled subprocess script (unlike retro_hunter.py/
        # ollama_soc.py) -- capture_and_ingest() reprocesses each burst into an
        # isolated scratch directory, not the live zeek_log_dir ZeekCollector tails, so
        # the ONLY way a burst's findings reach the live pipeline's detection state is
        # by ingesting into this SAME self.zeek_fx instance. A separate subprocess
        # would need its own throwaway ZeekFeatureExtractor, and its findings would
        # never reach live detection at all -- silently defeating the entire point of
        # this phase's design (see fritzbox_capture.py's module docstring). Not gated
        # by a device-specific condition, so it's a plain elapsed-time check, not part
        # of the per-device loop below.
        if bool(self.config.get("reactive_capture_spotcheck_enabled", True)):
            interval = float(self.config.get("reactive_capture_spotcheck_interval_seconds", 1800.0))
            if now - self._last_reactive_spotcheck_ts >= interval:
                self._last_reactive_spotcheck_ts = now
                self.reactive_capture.try_dispatch(
                        self.config, self.zeek_fx, trigger_reason="spotcheck",
                        state_manager=self.state_manager, evidence_store=self.evidence_store,
                        geoip_engine=self.geoip_engine, ti_engine=self.ti_engine, fp_engine=self.fp_engine,
                    )
                # Disk-safety sweep, piggybacked on this same interval rather than a
                # separate timer -- catches any raw pcap/Zeek scratch directory
                # orphaned by a process crash mid-burst (capture_and_ingest()'s own
                # try/finally handles the normal case; this is the defense-in-depth
                # backstop for the abnormal one).
                try:
                    scratch_dir = Path(self.config.get("reactive_capture_scratch_dir", "state/reactive_capture"))
                    cleanup_stale_scratch_files(scratch_dir)
                except Exception as exc:
                    LOGGER.warning("Reactive-capture stale-file sweep failed (non-fatal): %s", exc)

        dns_rows = self.pihole_collector.poll()
        zeek_events = self.zeek_collector.poll()

        LOGGER.debug("Polled %d DNS rows, %d Zeek events", len(dns_rows), len(zeek_events))

        for ze_event in zeek_events:
            self.zeek_fx.ingest(ze_event)

        # PHASE 21D trigger: a new, previously-unseen source IP contacted one of the
        # configured wired-probe devices this cycle -- fire one burst per cycle that has
        # any new source at all, not one per new source (a single burst captures the
        # whole radio regardless of count, same reasoning as every other trigger here).
        if bool(self.config.get("reactive_capture_wired_probe_trigger_enabled", True)):
            new_probe_sources = self.zeek_fx.pop_new_wired_probe_sources()
            if new_probe_sources:
                LOGGER.info("🔌 New source(s) contacting a wired-probe device this cycle: %s "
                            "-- dispatching a reactive capture.", new_probe_sources)
                self.reactive_capture.try_dispatch(
                        self.config, self.zeek_fx, trigger_reason="wired_probe",
                        state_manager=self.state_manager, evidence_store=self.evidence_store,
                        geoip_engine=self.geoip_engine, ti_engine=self.ti_engine, fp_engine=self.fp_engine,
                    )

        active_ids_dns = self.identity_manager.process_dns_identities(
            dns_rows, self.zeek_fx, self.ml_registry, ips_mitigator=self.ips_mitigator,
            fp_engine=self.fp_engine, evidence_store=self.evidence_store, metrics_exporter=self.metrics_exporter)
        active_ids_zeek = self.identity_manager.process_zeek_identities(
            zeek_events, self.zeek_fx, self.ml_registry, ips_mitigator=self.ips_mitigator,
            fp_engine=self.fp_engine, evidence_store=self.evidence_store, metrics_exporter=self.metrics_exporter)
        all_active_ids = set(active_ids_dns + active_ids_zeek)
        LOGGER.debug("Identity mapping complete: %d active devices tracking", len(all_active_ids))

        for row in dns_rows:
            client_ip = str(row.get("client_ip", "")).strip()
            domain = str(row.get("domain", "")).strip()
            ts = float(row.get("timestamp", now))

            raw_hostname = str(row.get("hostname", "unknown")).strip()
            hostname = sanitize_hostname(raw_hostname) or "unknown"
            if hostname == "unknown" and self.zeek_fx:
                zh = self.zeek_fx.get_hostname(client_ip)
                if zh and zh != "unknown": hostname = sanitize_hostname(zh) or "unknown"

            mac_addr = self.zeek_fx.get_mac(client_ip)
            dev_id = self.identity_manager.resolve_device_id(client_ip, mac_addr, hostname)

            if not self.state_manager.has_device(dev_id):
                # PHASE 21D: pass real fingerprints so get_or_create()'s MAC-rotation
                # re-identification actually has something to compare against -- before
                # this, this call site always cold-started directly (fingerprints were
                # never supplied here), so the ambiguous-candidate trigger below could
                # never fire regardless of what state_guard.py itself supported.
                dhcp_fp = self.zeek_fx.get_dhcp_fingerprint(client_ip) if self.zeek_fx else None
                ja4s = self.zeek_fx.get_ja4_set(client_ip) if self.zeek_fx else None
                self.state_manager.get_or_create(
                    dev_id, client_ip, hostname, float(self.config.get("baseline_alpha", 0.05)),
                    dhcp_fingerprint=dhcp_fp, ja4_set=ja4s,
                )
                # PHASE 21D trigger: a brand-new device cold-starting fires one capture
                # burst to establish a baseline JA4/connection fingerprint for it
                # immediately, rather than waiting for it to look suspicious first.
                if bool(self.config.get("reactive_capture_new_device_trigger_enabled", True)):
                    self.reactive_capture.try_dispatch(
                        self.config, self.zeek_fx, trigger_reason="new_device",
                        state_manager=self.state_manager, evidence_store=self.evidence_store,
                        geoip_engine=self.geoip_engine, ti_engine=self.ti_engine, fp_engine=self.fp_engine,
                    )

                # PHASE 21D trigger: get_or_create() just found a MAC-rotation candidate
                # too weak to auto-merge on -- genuinely ambiguous, not "no match". Fresh
                # JA4/DHCP data from this burst can resolve it on a FUTURE cold-start of
                # the same physical device instead of it staying stuck below the merge
                # bar indefinitely (this cycle's own dev_id already exists now either way).
                if bool(self.config.get("reactive_capture_reid_ambiguous_trigger_enabled", True)):
                    ambiguous = self.state_manager.pop_last_reidentify_ambiguous()
                    if ambiguous:
                        LOGGER.info("🔎 Ambiguous re-identification candidate (new=%s, candidate=%s, "
                                    "confidence=%.2f) -- dispatching a reactive capture to try to resolve it.",
                                    ambiguous["new_device_id"], ambiguous["candidate_id"], ambiguous["confidence"])
                        self.reactive_capture.try_dispatch(
                        self.config, self.zeek_fx, trigger_reason="ambiguous_reidentify",
                        state_manager=self.state_manager, evidence_store=self.evidence_store,
                        geoip_engine=self.geoip_engine, ti_engine=self.ti_engine, fp_engine=self.fp_engine,
                    )

            with self.state_manager.lock_device(dev_id) as state:
                status_code = int(row.get("status", 0))
                qtype = row.get("reply_type", 0)
                state.rolling.events.append((ts, domain, status_code))
                state.rolling.long_events.append((ts, domain, status_code, qtype))
                state.rolling.dns_qtypes[qtype] += 1
                if status_code in BLOCKED_STATUSES:
                    state.rolling.blocked += 1
                if status_code in NXDOMAIN_STATUSES:
                    state.rolling.nxdomain += 1
                state.rolling.domains[domain] += 1
                state.rolling.domain_timestamps[domain].append(ts)

        safe_ips = set(self.config.get("safe_ips", []))
        safe_patterns = {str(p).lower().strip() for p in self.config.get("safe_host_patterns", []) if str(p).strip()}

        for dev_id in self.state_manager.get_all_device_ids():
            # ─── PHASE 1: Snapshot state data (short lock window) ───────────────────
            mitigation_pending = None
            with self.state_manager.lock_device(dev_id) as state:
                client_ip = state.client_ip
                hostname = state.hostname
                mac_addr = getattr(state, "mac_address", "unknown")
                device_type = getattr(state, "device_type", "unknown")
                # PHASE 6 (cross-address-family correlation): snapshot every address this
                # device is known to answer to (e.g. both its IPv4 and IPv6 addresses once
                # MAC-correlation has unified them under one device_id), so the Zeek feature
                # aggregation below sums/merges activity across ALL of them instead of only
                # whichever address happened to be "most recently active" (client_ip). Falls
                # back to the single client_ip if known_ips is empty (shouldn't happen post
                # Phase 6, but keeps this resilient to states loaded from an older snapshot).
                known_ips_snapshot = state.known_ips.to_list() if getattr(state, "known_ips", None) else []
                if not known_ips_snapshot:
                    known_ips_snapshot = [client_ip] if client_ip else []
                # BUGFIX: found via a live state-folder audit -- checking only the single
                # current client_ip against safe_ips missed a device entirely once its
                # snapshot happened to be one of its OTHER known addresses that cycle.
                # Confirmed live: this network's own Fritzbox (dev_id 3028d18cbd7c,
                # safe_ips lists only its IPv4 "192.168.1.1") still generated a
                # CONNECTION_ABUSE alert at risk=8.5 in a cycle where client_ip was its
                # IPv6 link-local address (fe80::52e6:36ff:fe6a:5428) instead -- same
                # physical device, same known_ips set, just a different snapshot of
                # which address was "most recently active." known_ips_snapshot already
                # exists for exactly this reason (see the PHASE 6 comment above); the
                # same reasoning applies here, not just to Zeek feature aggregation.
                is_safe = (
                    client_ip in safe_ips
                    or any(ip in safe_ips for ip in known_ips_snapshot)
                    or (bool(hostname) and any(pat in hostname.lower() for pat in safe_patterns if pat))
                )

                # AUDIT FIX #4: Prune rolling.domains to the current window using domain_timestamps.
                # This prevents the Counter from growing unboundedly across the device's lifetime.
                if hasattr(state, "rolling"):
                    cutoff = now - window_seconds
                    stale_domains = [
                        dom for dom, ts_deque in list(state.rolling.domain_timestamps.items())
                        if ts_deque and ts_deque[-1] < cutoff
                    ]
                    for dom in stale_domains:
                        state.rolling.domains.pop(dom, None)
                        del state.rolling.domain_timestamps[dom]

                    if len(state.rolling.domain_timestamps) > 10000:
                        for dom in list(state.rolling.domain_timestamps.keys())[:2000]:
                            state.rolling.domains.pop(dom, None)
                            state.rolling.domain_timestamps.pop(dom, None)

                    # Re-derive blocked/nxdomain counts from the bounded events deque
                    # so they stay accurate as old events age out.
                    state.rolling.blocked = sum(1 for _, _, sc in state.rolling.events if sc in BLOCKED_STATUSES)
                    state.rolling.nxdomain = sum(1 for _, _, sc in state.rolling.events if sc in NXDOMAIN_STATUSES)

                current_hour = int(time.strftime("%H", time.localtime(now)))
                current_minute = int(time.strftime("%M", time.localtime(now)))

                if hasattr(state, "seen_domains") and len(state.seen_domains) > 5000:
                    LOGGER.debug("Device %s exceeded domain capacity limit. Truncating history.", dev_id)
                    state.seen_domains = BoundedSet(max_size=10000, initial=list(state.seen_domains)[-5000:])

                # Snapshot baselines for Z-score computation (used outside lock)
                _rate_bl    = state.rate_baseline
                _ent_bl     = state.entropy_baseline
                _uniq_bl    = state.unique_baseline
                _nx_bl      = state.nxdomain_baseline
                _bl_bl      = state.blocked_baseline
                _dga_bl     = state.dga_baseline
                _ob_bl      = state.outbound_bytes_baseline
                _last_alert_confidence = getattr(state, "last_alert_confidence", 0.0)
                _last_alert_time = getattr(state, "last_alert_time", 0.0)
                _last_alert_sig  = getattr(state, "last_alert_signature", "")
                _last_bl_update  = getattr(state, "last_baseline_update", 0.0)
                # Snapshot rolling domain keys for TI lookups (avoids holding lock during I/O).
                # BUGFIX (live audit, 2026-09-09): same multicast/broadcast exclusion as
                # _select_target_domain()'s own fix just below -- this separate snapshot feeds
                # its own TI-lookup loop a few hundred lines down (`for domain in
                # _rolling_domain_keys: ... reputation_target = domain`), which can
                # independently attribute reputation_target to a raw multicast IP key exactly
                # the same way _select_target_domain() could before its fix.
                _rolling_domain_keys = [
                    d for d in state.rolling.domains.keys() if not is_local_or_multicast_destination(d)
                ] if hasattr(state, "rolling") else []
                _killchain_hist = list(getattr(state, "killchain_history", []))

            # ─── PHASE 2: Pre-fetch Zeek data outside the lock ──────────────────────
            # Zeek feature fetching is a pure dict read (no lock needed for zeek_fx).
            # The full DNS feature compute still happens inside the Phase 4 lock below
            # since it needs live state (rolling window, EWMA baselines).
            # PHASE 6: aggregate across every known address of this device, not just the
            # single currently-active client_ip — see known_ips_snapshot comment above.
            _zeek_features = {**self.zeek_fx.get_features(known_ips_snapshot), **self.zeek_fx.get_last_connection_meta(client_ip)}

            # ─── PHASE 3: Compute localized features (re-acquire lock) ──────────────
            mitigation_pending = None
            with self.state_manager.lock_device(dev_id) as state:
                features = {**self.dns_extractor.compute(state, now, window_seconds), **_zeek_features}
                features["sigma_shift"] = self.fp_engine.get_sigma_shift(dev_id)
                features["current_hour"] = current_hour
                features["current_minute"] = current_minute
                # AUDIT FIX #15: Inject honeypot IPs from config so scoring engine doesn't hardcode them
                _honeypot_ips = self.config.get("honeypot_ips", [])
                features["_config_honeypot_ips"] = ", ".join(_honeypot_ips) if _honeypot_ips else "configured decoy IPs"

                def calc_z(val: float, baseline_obj) -> float:
                    mean, var, init, n = baseline_obj.get_stats_interpolated(current_hour, current_minute) if hasattr(baseline_obj, "get_stats_interpolated") else baseline_obj.get_stats(current_hour)
                    if not init or n < 10: return 0.0
                    return max(0.0, (val - mean) / math.sqrt(max(var, 1e-4)))

                features["query_rate_z"]       = calc_z(features.get("query_rate", 0.0), state.rate_baseline)
                features["entropy_z"]           = calc_z(features.get("entropy_avg", 0.0), state.entropy_baseline)
                features["entropy_avg_z"]       = features["entropy_z"]
                features["unique_domains_z"]    = calc_z(features.get("unique_domains", 0.0), state.unique_baseline)
                features["nxdomain_ratio_z"]    = calc_z(features.get("nxdomain_ratio", 0.0), state.nxdomain_baseline)
                features["blocked_ratio_z"]     = calc_z(features.get("blocked_ratio", 0.0), state.blocked_baseline)
                features["suspicious_domains_z"]= calc_z(features.get("suspicious_domains", 0.0), state.dga_baseline)
                features["outbound_bytes_z"]    = calc_z(features.get("zeek_outbound_bytes", 0.0), state.outbound_bytes_baseline)

                target_malicious_domain = self._select_target_domain(state, self.ti_engine)
                top_domain = target_malicious_domain
                dest_ip = features.get("last_dest_ip", "unknown")
                if not dest_ip or dest_ip == "unknown":
                    if top_domain and top_domain != "unknown":
                        # BUGFIX (dead-code audit): prefer Zeek's own wire-observed DNS
                        # resolution (get_wire_ip() -- real answer this device's own query
                        # actually got, tracked in _process_dns() but never read by anyone
                        # before this) over a fresh live gethostbyname() lookup. The live
                        # lookup can resolve to a DIFFERENT IP than the one this device
                        # actually contacted (DGA/fast-flux/CDN domains rotate), costs a
                        # real outbound DNS query generated by the IDS itself on every
                        # cycle a WiFi-blind device alerts, and can stall up to 0.5s. The
                        # wire-observed value is an instant local dict lookup and reflects
                        # what genuinely happened. Falls back to the live lookup only when
                        # Zeek never actually saw this domain's resolution on the wire.
                        wire_ip = self.zeek_fx.get_wire_ip(top_domain) if self.zeek_fx else None
                        if wire_ip:
                            dest_ip = wire_ip
                        else:
                            try:
                                import socket
                                from concurrent.futures import ThreadPoolExecutor, TimeoutError
                                # Use a temporary thread to enforce a 0.5s timeout on gethostbyname
                                # without breaking global socket timeouts for other threads.
                                with ThreadPoolExecutor(max_workers=1) as executor:
                                    future = executor.submit(socket.gethostbyname, top_domain)
                                    dest_ip = future.result(timeout=0.5)
                            except Exception:
                                dest_ip = "unknown"
                    else:
                        dest_ip = "unknown"

            # BUGFIX (external architecture review, 2026-09-09, "Invariant 8" --
            # destination==MULTICAST must never independently create a reputation
            # threat): every dest_ip-gated reputation lookup below (TI/AbuseIPDB/VT)
            # used to gate on a bare `dest_ip and dest_ip != "unknown"` check with no
            # multicast/broadcast/link-local exclusion -- unlike every OTHER IP-touching path in
            # this codebase (GraphStore.get_devices_targeting(),
            # get_distinct_destination_count(), fp_engine.py's confirmed-intel guard,
            # all already excluded this exact traffic shape, see 1ff6c97/graph/
            # store.py's own docstring). A multicast dest_ip (mDNS 224.0.0.251/ff02::fb,
            # SSDP 239.255.255.250, etc. -- extremely common, this device's OWN cycle
            # destination, not a bystander) could still be enqueued against paid
            # AbuseIPDB/VT quota and, in the theoretical case a feed ever returned
            # garbage data for one, become `reputation_target` itself. No live
            # incident confirmed this fired in practice (a real TI/VT/AbuseIPDB feed
            # essentially never has data for a non-routable multicast address), but
            # nothing here actually prevented it structurally -- closing the gap
            # rather than relying on external feeds happening to stay silent.
            _dest_ip_is_real_host = bool(dest_ip) and dest_ip != "unknown" and not is_local_or_multicast_destination(dest_ip)

            # ─── PHASE 4: Expensive I/O outside the lock ────────────────────────────
            # BUGFIX: found via a live third-party review of a real CRITICAL/"Confirmed
            # Malicious IOC" alert (c.pki.goog, Google's own certificate-revocation
            # infrastructure), verified against this exact code -- ti_risk/abuse_risk/
            # vt_risk are each a MAX across this device's several recent domains and its
            # single dest_ip, with NO tracking of WHICH domain/IP actually produced that
            # max. rep_classifier.classify(top_domain, ti_score=ti_risk, ...) then blames
            # top_domain (a SEPARATE, "_select_target_domain()-picked most notable domain
            # in the window" value) for a risk score that may have come from a completely
            # different domain this same device also happened to query -- confirmed
            # plausible here: a real device on this network had a history of contacting
            # genuinely malicious DGA domains in the same rolling window. reputation_target now tracks the
            # SPECIFIC domain/IP that earned the highest risk score, so the classifier
            # (and the alert built from its verdict) blame the actual source of the risk,
            # not an unrelated bystander domain. When no risk was ever found at all,
            # nothing needs attribution and top_domain remains a harmless, neutral choice.
            reputation_target = top_domain
            ti_risk, ti_match = 0.0, 0
            if self.ti_engine:
                for domain in _rolling_domain_keys:
                    ti_res = self.ti_engine.lookup_domain(domain)
                    if ti_res:
                        cur_risk = float(ti_res.get("confidence", 0.8)) * 4.0
                        if cur_risk > ti_risk:
                            ti_risk = cur_risk
                            reputation_target = domain
                        ti_match = 1
                        ti_ioc_hits_total.labels(source="threat_intel", ioc_type="domain").inc()
                if _dest_ip_is_real_host:
                    ip_ti_res = self.ti_engine.lookup_ip(dest_ip)
                    if ip_ti_res:
                        cur_ip_risk = float(ip_ti_res.get("confidence", 0.8) * 4.0)
                        if cur_ip_risk > ti_risk:
                            ti_risk = cur_ip_risk
                            reputation_target = dest_ip
                        ti_match = 1
                        ti_ioc_hits_total.labels(source="threat_intel", ioc_type="ip").inc()

            features["ti_risk"] = ti_risk
            features["ti_match"] = ti_match
            # BUGFIX: fp_engine.py Stage-2 and train_fp_classifier.py both read
            # features["tranco_rank"] for Feature 0 of the 11-dim LightGBM vector, but
            # nothing ever wrote it -- permanently 0 for every alert since this feature
            # was introduced. threat_intel.py's Tranco loader already downloads the
            # full ranked 1M-row list every 24h (only the domain half was ever kept);
            # get_tranco_rank() now exposes the rank half too. Same top_domain used for
            # the reputation classifier just below, for consistency.
            features["tranco_rank"] = self.ti_engine.get_tranco_rank(top_domain) if self.ti_engine and top_domain else 0
            # Running best-so-far for reputation_target's attribution, carried across the
            # ti_risk/abuse_risk/vt_risk blocks (see the BUGFIX comment above ti_risk).
            _best_risk_seen = ti_risk

            abuse_risk = 0.0
            honeypots = self.config.get("honeypot_ips", [])
            
            if _dest_ip_is_real_host:
                if dest_ip in honeypots:
                    # Target is a honeypot; external client_ip is inherently malicious. Skip API quota waste.
                    abuse_risk = 4.0
                    honeypot_probes_total.labels(dest_port=features.get("last_dest_port", 0), protocol=features.get("dominant_protocol", "TCP")).inc()
                else:
                    self.abuseipdb.enqueue_ip(dest_ip)
                    if self.abuseipdb.lookup(dest_ip):
                        abuse_risk = 4.0
                        ti_ioc_hits_total.labels(source="abuseipdb", ioc_type="ip").inc()
                    else:
                        live_risk = self.abuseipdb.get_live_risk(dest_ip)
                        if live_risk > 0:
                            abuse_risk = live_risk
                            ti_ioc_hits_total.labels(source="abuseipdb", ioc_type="ip").inc()
                # abuse_risk is always dest_ip-sourced when nonzero -- no ambiguity to track.
                if abuse_risk > _best_risk_seen:
                    _best_risk_seen = abuse_risk
                    reputation_target = dest_ip

            features["abuseipdb_risk"] = abuse_risk

            vt_risk = 0.0
            if dest_ip in honeypots:
                # Target is a honeypot; external client_ip is inherently malicious. Skip API quota waste.
                vt_risk = 4.0
                if vt_risk > _best_risk_seen:
                    _best_risk_seen = vt_risk
                    reputation_target = dest_ip
            else:
                if _dest_ip_is_real_host:
                    self.virustotal.enqueue_ip(dest_ip)
                if top_domain:
                    self.virustotal.enqueue_domain(top_domain)
                vt_ip_risk = self.virustotal.risk_contribution("ip", dest_ip) if dest_ip else 0.0
                vt_domain_risk = self.virustotal.risk_contribution("domain", top_domain) if top_domain else 0.0
                if vt_ip_risk >= vt_domain_risk:
                    vt_risk = vt_ip_risk
                    vt_risk_source = dest_ip
                else:
                    vt_risk = vt_domain_risk
                    vt_risk_source = top_domain
                if vt_risk > 0:
                    ti_ioc_hits_total.labels(source="virustotal", ioc_type="mixed").inc()
                    if vt_risk > _best_risk_seen:
                        _best_risk_seen = vt_risk
                        reputation_target = vt_risk_source
            features["vt_risk"] = vt_risk

            # ─── PHASE 5: ML scoring + risk computation (re-acquire lock) ──────────
            # --- Version 7 Integration ---
            # 1. Check for Layer-2 ARP Spoofing
            # BUGFIX: found via a live state-folder audit -- this is a CRITICAL/block
            # hard-stop (decision_engine.py's has_arp_spoof branch, threat_confidence=1.0,
            # zero corroboration required) that was never gated on is_safe/safe_ips at
            # all, unlike every other behavioral noise source. Confirmed live: this
            # network's own mesh Wi-Fi repeaters (192.168.1.2/.3, both explicitly in
            # safe_ips, both "repeaters" per the operator) kept reaching this hard-stop
            # even after the earlier known-oscillation fix (zeek_features.py's
            # _bind_mac()) -- a repeater relaying many different client devices'
            # traffic naturally presents new-to-this-IP MACs on an ongoing basis, which
            # that fix can't distinguish from a genuine hijack. `client_ip` here is
            # this exact device's own address -- if the operator has explicitly listed
            # it as safe_ips ("NEVER treated as suspicious... even if flagged
            # elsewhere" per its own config.yaml docstring), honor that promise for
            # this hard-stop too, same as the noisy_types exclusion above already does
            # for behavioral evidence. Honeypot/geofencing/reputation hard-stops are
            # untouched -- this is scoped to the MAC-flip heuristic specifically, which
            # is the one demonstrated to have this exact false-positive shape.
            if hasattr(self.zeek_fx, "layer2_spoofs") and client_ip in self.zeek_fx.layer2_spoofs:
                spoof_info = self.zeek_fx.layer2_spoofs[client_ip]
                if is_safe:
                    LOGGER.info(
                        f"ARP/NDP MAC flip on {client_ip} ({spoof_info['old']} -> {spoof_info['new']}) "
                        f"NOT escalated to a hard-stop -- this IP is explicitly listed in safe_ips."
                    )
                else:
                    LOGGER.critical(f"Adding HARD-STOP evidence for ARP Spoofing on {client_ip}")
                    # BUGFIX (live audit): domain=client_ip so this alert's destination_ip
                    # attributes to what's ACTUALLY being spoofed (this device's own
                    # identity), not the generic "last connection" fallback -- confirmed
                    # live, 191 historical alerts showing hostname=unknown + an unrelated
                    # DNS-query/broadcast destination_ip on this exact signature.
                    self.evidence_store.add(Evidence(type="arp_spoofing", source="zeek", timestamp=now, device=dev_id, value=10.0, confidence=1.0, provenance=f"MAC flip: {spoof_info['old']} -> {spoof_info['new']}", domain=client_ip))
                del self.zeek_fx.layer2_spoofs[client_ip]

            # BUGFIX (live audit): a single genuinely-new MAC flip (weaker than the 2nd-
            # flip hard-stop above) -- corroboration-required evidence, same is_safe
            # dampening as the hard-stop for consistency (a mesh repeater's single flip
            # shouldn't count here either), feeding NetworkIntrusionHypothesis instead
            # of bypassing hypothesis competition.
            if hasattr(self.zeek_fx, "pending_spoof_evidence") and client_ip in self.zeek_fx.pending_spoof_evidence:
                pending_info = self.zeek_fx.pending_spoof_evidence.pop(client_ip)
                if not is_safe:
                    self.evidence_store.add(Evidence(
                        type="arp_spoof_pending", source="zeek", timestamp=now, device=dev_id,
                        value=1.0, confidence=0.5, independence_group="zeek_network",
                        provenance=f"MAC flip (1st, uncorroborated): {pending_info['old']} -> {pending_info['new']}",
                        domain=client_ip,
                    ))

            mitigation_pending = None
            with self.state_manager.lock_device(dev_id) as state:
                ml_score = 0.0
                if self.ml_registry:
                    ml_score = self.ml_registry.score(dev_id, features)

                # --- Version 7 Integration ---
                # 1. Run Detectors
                dns_ev = self.dns_detector.detect(dev_id, features)
                for ev in dns_ev: self.evidence_store.add(ev)
                
                # PHASE 6: merge JA3/JA4/notice alerts across every known address of this device.
                zeek_ev = self.zeek_detector.detect(dev_id, self.zeek_fx.get_alerts(known_ips_snapshot))
                for ev in zeek_ev: self.evidence_store.add(ev)

                # PHASE 1: DGA/exfiltration/beaconing/tunneling-v2/connection-abuse — the
                # scoring.py-derived categories that previously had no path into the live
                # evidence/hypothesis pipeline at all (scoring.py itself is dead code).
                # PHASE 21D2: a device with its OWN raised threshold (operator/LLM
                # corrected a past ARP-sweep false positive via mark_false_positive())
                # uses that instead of the global default -- self-healing takes effect
                # immediately, not just as a contribution to next week's retrain.
                global_arp_sweep_threshold = float(self.config.get("arp_sweep_unique_targets_threshold", 8))
                arp_sweep_threshold = int(
                    self.fp_engine.get_device_arp_sweep_threshold(dev_id, default=global_arp_sweep_threshold)
                    if self.fp_engine else global_arp_sweep_threshold
                )
                # BUGFIX (live audit): same self-healing shape as arp_sweep_threshold just
                # above, now also covering zeek_conn_abuse's unique-IP requirement and
                # zeek_long_conn's duration requirement -- previously hardcoded, so a
                # correction to either had nowhere to actually take effect.
                conn_abuse_unique_ip_threshold = int(
                    self.fp_engine.get_device_conn_abuse_unique_ip_threshold(dev_id, default=5.0)
                    if self.fp_engine else 5.0
                )
                long_conn_duration_threshold = float(
                    self.fp_engine.get_device_long_conn_duration_threshold(dev_id, default=14400.0)
                    if self.fp_engine else 14400.0
                )
                threat_signal_ev = self.threat_signal_detector.detect(
                    dev_id, features, top_domain=top_domain, arp_sweep_threshold=arp_sweep_threshold,
                    conn_abuse_unique_ip_threshold=conn_abuse_unique_ip_threshold,
                    long_conn_duration_threshold=long_conn_duration_threshold,
                    ti_engine=self.ti_engine,
                )
                for ev in threat_signal_ev: self.evidence_store.add(ev)

                # PHASE 21D trigger: an ARP host-discovery sweep is exactly the kind of
                # LAN-recon precursor a capture burst should confirm with real traffic,
                # not just DNS-shape evidence.
                if bool(self.config.get("reactive_capture_arp_sweep_trigger_enabled", True)) \
                        and any(ev.type == "arp_sweep" for ev in threat_signal_ev):
                    self.reactive_capture.try_dispatch(
                        self.config, self.zeek_fx, trigger_reason="arp_sweep",
                        state_manager=self.state_manager, evidence_store=self.evidence_store,
                        geoip_engine=self.geoip_engine, ti_engine=self.ti_engine, fp_engine=self.fp_engine,
                    )

                if ml_score > 0.90:
                    self.evidence_store.add(Evidence(type="ml_anomaly", source="ml_engine", timestamp=now, device=dev_id, value=ml_score, confidence=ml_score, independence_group="ml_anomaly", provenance="detector:ml"))
                
                # GAP 3 FIX B (2026-08-27, explicit product decision, not a bug fix): a
                # live investigation found home-router (the router, safe_ips-listed)
                # genuinely, repeatedly touching the honeypot's IP -- most likely its own
                # "Home Network"/UPnP/mDNS device-mapping feature treating the honeypot's
                # macvlan address as a normal known host, not an attack. safe_ips already
                # means "never treated as suspicious... even if flagged elsewhere" for
                # every OTHER signal (reputation, behavioral evidence) -- this was the one
                # exception, and it wasn't containing anything anyway: mitigate() already
                # no-ops entirely for is_safe devices (see ips.py's "LATCHED CONTAINMENT
                # PROTECTION" comment), so the only effect of NOT exempting it was a
                # misleading CRITICAL "Internal Honeypot Accessed" alert with no real
                # containment behind it. A genuinely compromised safe_ips device would
                # still show up via every other detection path (reputation, behavioral
                # hypotheses, DNS anomalies) -- this narrows one specific hard-stop, not
                # the device's overall exposure.
                if features.get("zeek_honeypot_hits", 0) > 0 and not is_safe:
                    # BUGFIX (live alert audit): the same attribution gap already fixed for
                    # CONNECTION_ABUSE/DGA_BOTNET_C2/NETWORK_INTRUSION/ARP-spoofing below --
                    # this evidence previously carried no .domain at all, so a CRITICAL
                    # "Internal Honeypot Accessed" alert's "Contacted" line fell back to
                    # whatever this device connected to most recently (confirmed live:
                    # mDNS multicast addresses and unrelated DNS hostnames), even though the
                    # evidence text says "Connected to the internal honeypot decoy server."
                    # get_last_honeypot_ip() (zeek_features.py) now tracks which honeypot_ips
                    # entry was actually hit -- attach it here, consumed by the
                    # "Internal Honeypot Accessed" branch below.
                    honeypot_hit_ip = self.zeek_fx.get_last_honeypot_ip(known_ips_snapshot) if self.zeek_fx else None
                    self.evidence_store.add(Evidence(type="honeypot_access", source="zeek", timestamp=now, device=dev_id, value=features["zeek_honeypot_hits"], confidence=1.0, independence_group="honeypot", provenance="detector:honeypot", domain=honeypot_hit_ip))
                
                # BUGFIX: found via a third-party review of a real tarpit alert, verified
                # against production data -- this fed NetworkIntrusionHypothesis's own
                # "Hard escalate for lateral scans (very rarely benign on a home network)"
                # branch (hypotheses/engine.py), which force-escalates to HIGH whenever
                # this evidence's value > 0 -- the SAME raw-connection-count gap already
                # fixed at fp_engine.py's Stage-1 hard-stop and this file's lateral_threat
                # (tarpit authorization), just missed here. A single legitimate SMB/SSH/
                # RDP connection to one internal device is not "very rarely benign" --
                # it's routine. Same distinct-target threshold as those two fixes.
                lateral_unique_targets = int(features.get("zeek_lateral_unique_targets", 0) or 0)
                lateral_evidence_threshold = int(self.config.get("lateral_movement_unique_targets_threshold", 2))
                if features.get("zeek_lateral_moves", 0) > 0 and lateral_unique_targets >= lateral_evidence_threshold:
                    lateral_target_examples = features.get("zeek_lateral_target_examples", []) or []
                    lateral_evidence_target = lateral_target_examples[0] if lateral_target_examples else None
                    self.evidence_store.add(Evidence(type="zeek_lateral_scan", source="zeek", timestamp=now, device=dev_id, value=features["zeek_lateral_moves"], confidence=0.9, independence_group="zeek_network", provenance="detector:zeek:lateral_scan", domain=lateral_evidence_target))

                # BUGFIX (reviewer suggestion, implemented): a device's own real-time
                # HTTP/SSDP/DIAL requests to OTHER local devices for media-discovery
                # purposes (Spotify Connect app discovery, Chromecast/UPnP device
                # descriptors) were only ever surfaced as alert-display context
                # (recent_http_reqs, computed after scoring already finished) -- never as
                # an actual benign signal decision_engine.py's hypothesis competition could
                # weigh. A device browsing for Spotify/Chromecast targets on its own LAN is
                # not "more suspicious network activity"; it's exactly why HEE has a benign
                # hypothesis track (see AdvertisingBurstHypothesis) rather than only ever
                # scoring attack likelihood. Deliberately checked using the SAME zeek_fx.
                # get_http_reqs() data source pipeline.py's own alert-display code already
                # reads, just gathered here (evidence time) instead of only at
                # alert-build time.
                local_discovery_hits = _count_local_device_discovery_requests(self.zeek_fx, client_ip)
                if local_discovery_hits > 0:
                    self.evidence_store.add(Evidence(
                        type="local_device_discovery", source="zeek", timestamp=now, device=dev_id,
                        value=float(local_discovery_hits), confidence=0.7,
                        independence_group="local_context",
                        provenance="detector:zeek:local_device_discovery",
                    ))
                
                # BUGFIX (external architecture review, 2026-09-09, real production
                # alert): confirmed live -- a HIGH PEER_COHORT_DEVIATION alert cited
                # "poor external reputation score" for 35.186.224.24, a Google LLC-owned
                # IP (is_cloud_cdn_provider_org() already recognizes "google llc" --
                # confirmed, not a missing-keyword problem). Same false-positive shape
                # as the c.pki.goog/Netflix incidents already fixed elsewhere (a214a2f,
                # COORDINATED_TARGETING's own evidence-creation site specifically) but
                # never extended to reputation evidence itself, or to classify()'s own
                # asn_owner. Two separate, pre-existing gaps, same root fix: below,
                # asn_owner was computed for dest_ip (this cycle's real connection --
                # correct for the baseline-familiarity/CL-AFPE uses further down, kept
                # unchanged), NOT reputation_target -- the two can legitimately differ
                # (the whole point of the reputation-target-attribution fix a few lines
                # below), so classify()'s own tier-2 trusted-infra check was being asked
                # about the wrong destination's ownership. A separate, cheap local ASN
                # lookup (same GeoLite2 db self.geoip_engine already has open, no
                # network call) scoped to reputation_target specifically -- IP-only (a
                # domain's own trust is already handled by classify()'s explicit
                # TIER_0/1/2 domain-suffix lists, a separate, pre-existing mechanism) --
                # computed once, reused both to gate the reputation Evidence itself
                # (skip creating it entirely for known-trusted infra, matching a214a2f's
                # own exemption) and passed to classify() below so rep_vector.tier
                # itself correctly reflects tier 2 for the SAME destination reputation_
                # target actually names, not dest_ip's unrelated ownership.
                reputation_target_asn_owner = "Unknown"
                if reputation_target and reputation_target != "unknown" and self.geoip_engine:
                    try:
                        ipaddress.ip_address(reputation_target)
                    except (ValueError, TypeError):
                        pass
                    else:
                        try:
                            rt_asn_info = self.geoip_engine.lookup_asn(reputation_target)
                            if rt_asn_info and getattr(rt_asn_info, "autonomous_system_organization", None):
                                reputation_target_asn_owner = rt_asn_info.autonomous_system_organization
                        except Exception:
                            pass
                # BUGFIX (found live, same day, after this fix's first deploy):
                # is_cloud_cdn_provider_org() alone missed 149.154.167.41 (Telegram's
                # own infrastructure, AS62041) -- self.rep_classifier already has its
                # OWN separate, narrower trust list for exactly this (_SAFE_ASN_OWNER_
                # KEYWORDS, just "telegram", the 149.154.166.110 incident's own fix,
                # see classifier.py's own comments) that classify() below already
                # combines with is_cloud_cdn_provider_org() internally -- but this gate
                # was calling is_cloud_cdn_provider_org() directly instead of asking
                # the classifier for its own combined answer, so it silently missed
                # Telegram even though classify() itself would have correctly called
                # tier 2. is_known_safe_asn_owner() (classifier.py, this same pass) is
                # the exact same check classify() uses internally -- asking THAT
                # instead means this gate and classify()'s own tier-2 assignment can
                # never drift apart like this again.
                reputation_target_is_trusted_infra = self.rep_classifier.is_known_safe_asn_owner(reputation_target_asn_owner)

                reputation_value = max(ti_risk, abuse_risk, vt_risk)
                if (ti_match or abuse_risk > 0.0 or vt_risk > 0.0) and not reputation_target_is_trusted_infra:
                    # PHASE 64 (reputation independence-scoping redesign): domain=
                    # was never populated here before -- reputation_target (set above,
                    # :841-926) is already the specific domain/IP that actually produced
                    # this max TI/VT/AbuseIPDB score (the same causal-attribution fix
                    # documented in this file's own reputation-target-selection comments),
                    # so attaching it here is just exposing an already-correct value on
                    # the Evidence item, not a new computation. Lets decision_engine.py
                    # tell "this reputation hit is about the SAME destination the winning
                    # attack hypothesis's own evidence points at" apart from "some
                    # unrelated domain elsewhere in this device's rolling window also has
                    # a nonzero reputation score" -- see decision_engine.py's own comment
                    # for how this is consumed.
                    self.evidence_store.add(Evidence(
                        type="reputation",
                        source="threat_intel",
                        timestamp=now,
                        device=dev_id,
                        value=reputation_value,
                        confidence=0.95 if reputation_value >= 4.0 else 0.8,
                        independence_group="reputation",
                        provenance="detector:reputation",
                        domain=reputation_target if reputation_target and reputation_target != "unknown" else None,
                    ))
                
                # 2. Get Reputation
                # PHASE 8 FIX: ReputationVector.asn_owner existed as a dataclass field but
                # was never populated anywhere — the classifier had zero notion of IP
                # ownership, which is exactly the context missing from the
                # 149.154.166.110/Telegram false-positive-block case (an IP's owner is
                # cheap to look up — self.geoip_engine already does this every cycle for
                # geofencing a few lines below — and is now surfaced in the alert's
                # reasoning trail so a human can see "this is Telegram infrastructure"
                # instead of the system silently having no way to know).
                asn_owner = "Unknown"
                if self.geoip_engine and _dest_ip_is_real_host:
                    try:
                        asn_info = self.geoip_engine.lookup_asn(dest_ip)
                        if asn_info and getattr(asn_info, "autonomous_system_organization", None):
                            asn_owner = asn_info.autonomous_system_organization
                    except Exception:
                        pass
                # BUGFIX: classify reputation_target (the domain/IP that actually earned
                # ti_risk/abuse_risk/vt_risk), not top_domain -- see the BUGFIX comment
                # above the ti_risk computation for the full incident (a genuinely
                # innocent domain, Google's own c.pki.goog certificate-revocation
                # endpoint, reached CRITICAL/"Confirmed Malicious IOC" purely because it
                # happened to be _select_target_domain()'s "most notable domain in the
                # window" pick while a DIFFERENT domain this same device also queried is
                # what actually earned the risk score).
                #
                # BUGFIX (same pass, above): asn_owner (dest_ip-scoped) is deliberately
                # NOT used here anymore -- reputation_target_asn_owner (reputation_
                # target-scoped, computed above) is passed instead, so this tier
                # classification is asked about the SAME destination it's actually
                # classifying, not dest_ip's unrelated ownership.
                rep_vector = self.rep_classifier.classify(reputation_target, vt_score=vt_risk, afpe_score=0.0, ti_score=ti_risk, abuse_score=abuse_risk, asn_owner=reputation_target_asn_owner)
                
                # 3. Decision Engine
                active_evidence = self.evidence_store.get_for_device(dev_id)
                
                if is_safe:
                    # Hybrid Approach: Exclude ML and DNS behavioral anomalies for infrastructure,
                    # but retain Threat Intel and Honeypot evidence to alert on real threats.
                    # BUGFIX: found via a live state-folder audit -- "lan_recon" (arp_sweep
                    # evidence, added in Phase 21B, well after this noisy_types set was
                    # written) was missing here. A router/gateway ARPs its entire LAN as
                    # routine DHCP/ARP-table/mesh-sync behavior -- confirmed live: this
                    # network's own Fritzbox (192.168.1.1, explicitly in safe_ips)
                    # generated repeated CONNECTION_ABUSE alerts against its own mesh
                    # repeaters (.2/.3, also in safe_ips) purely from zeek_arp_sweep_count=14,
                    # the single most predictable false-positive case for this detector and
                    # exactly the class of behavioral noise this exclusion already exists to
                    # dampen for infrastructure devices.
                    # BUGFIX (live audit): dns_evasion_anomaly (Phase 21C2, added well after
                    # this set was first written) was missing here too, for the exact same
                    # reason as _INFRA_NOISY_TYPES below -- a safe_ips/safe_host_patterns
                    # device doing its own DNS-resolver traffic (e.g. Pi-hole/unbound's own
                    # recursive resolution to upstream root/TLD/authoritative servers) is not
                    # "policy bypass," it's that device's normal job.
                    noisy_types = {"ml_anomaly", "dns_rate", "dns_entropy", "dns_unique_ratio", "zeek_network", "lan_recon", "dns_evasion_anomaly"}
                    active_evidence = [ev for ev in active_evidence if ev.type not in noisy_types and ev.independence_group not in noisy_types]

                # PHASE 1 FIX (device-sensitivity source): only dampen the new Phase-1
                # behavioral evidence for devices whose infra classification came from an
                # OPERATOR override (device_type_overrides), never from a self-reported
                # hostname — closes the retracted-finding gap ("a device can't talk its
                # way into infra-tier sensitivity by naming itself 'my-router'") in the
                # one place it now actually matters, since these are the first hypotheses
                # that use a sensitivity concept at all. Reputation/honeypot/lateral/TLS
                # evidence is never touched here, same as the is_safe block above.
                is_verified_infra = (
                    getattr(state, "device_type", "unknown") in _INFRA_DEVICE_TYPES
                    and getattr(state, "device_type_is_override", False)
                )
                if is_verified_infra:
                    active_evidence = [ev for ev in active_evidence if ev.type not in _INFRA_NOISY_TYPES]

                # VERSION 11 (P1 follow-up, review #9/#10): this device's own LEARNED
                # familiarity with the current cycle's destination -- read BEFORE
                # decision_engine.evaluate() so DeviceProfileBenignHypothesis can use it
                # as an alternate trust signal alongside global reputation tier. The
                # WRITE side (recording this cycle into the baseline) happens further
                # below, gated on this cycle's own verdict -- see that comment for why.
                baseline_familiarity = 0.0
                if self.fp_engine:
                    baseline_familiarity = self.fp_engine.get_baseline_familiarity(
                        dev_id,
                        dest_port=features.get("last_dest_port"),
                        asn_owner=asn_owner if asn_owner != "Unknown" else None,
                        domain_base=etld1(top_domain) if top_domain else None,
                    )

                # VERSION 10 (#9/#10 per-device benign profiles): state.device_type feeds
                # DeviceProfileBenignHypothesis so routine vendor-telemetry traffic from a
                # smart TV/IoT/NAS/router-category device gets a named benign explanation
                # instead of falling through to the generic UNKNOWN_BENIGN catch-all.
                # BUGFIX (2026-09-01, shadow-divergence flood): is_safe now threaded
                # through so the shadow honeypot check (decision_engine.py's
                # fresh_honeypot) can mirror the SAME "and not is_safe" exemption this
                # evidence's own creation gate uses a few hundred lines below (~line
                # 1033) -- without it, a safe_ips device (the router) touching the
                # honeypot for a benign reason diverged CRITICAL in shadow on every
                # single cycle it happened, live BENIGN, with nothing wrong.
                # V13 FAST CUTOVER (Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md, the
                # entry recording this cutover): v13's EvidenceGraph-based
                # hypothesis/decision engine is now the LIVE decision path, not a shadow
                # comparison -- superseding A10's earlier per-mechanism shadow-flip
                # machinery (that whole apparatus checked ONE mechanism at a time before
                # flipping; this replaces the entire engine at once, per an explicit,
                # deliberate risk-tolerance change: this box is being used as a real-
                # traffic testbed for IDS_PRODUCT, not run as a critical home-security
                # system right now). `engine: "v_current"` in config.yaml is the instant
                # rollback switch (config edit + restart, no redeploy) if anything looks
                # wrong -- kept from the superseded plan since it costs nothing.
                #
                # Cleanup (2026-09-07, Workstream 1 of V13_FULL_ARCHITECTURE_SHIFT_PLAN.md):
                # Gap 1/2/3's OWN shadow experiment (shadow_changed/_log_shadow_divergence,
                # DECISION_LOGIC_DEPENDENCY_MAP.md) used to be computed INSIDE
                # core/decision_engine.py's evaluate() and logged here on divergence -- since
                # v-current stopped being the primary engine it had already stopped producing
                # new state/shadow_decisions.jsonl entries under the live default, so both the
                # computation and this call site were removed outright rather than kept as
                # permanently-dead code with no live path left to ever flip into (see the
                # dependency map's A13 entry for the full cutover record; git history has the
                # removed code if it's ever needed for reference).
                if self.config.get("engine", "argus") == "argus":
                    decision = v13_live_engine.evaluate(
                        active_evidence, rep_vector, getattr(state, "device_type", ""), baseline_familiarity,
                        features=features, is_safe=is_safe,
                        fallback_evaluate=self.decision_engine.evaluate,
                        device_id=dev_id, now=now, geoip_engine=self.geoip_engine,
                    )
                else:
                    decision = self.decision_engine.evaluate(
                        active_evidence, rep_vector, getattr(state, "device_type", ""), baseline_familiarity,
                        features=features, is_safe=is_safe,
                    )

                # VERSION 11 (P1, review #9/#10): per-device learned behavioral baseline.
                # Deliberately gated on the HEE's OWN verdict for THIS cycle being
                # BENIGN/ANOMALOUS -- never records a port/ASN/domain the system itself
                # currently considers SUSPICIOUS or worse. Without this gate, a device
                # beaconing to a C2 host every cycle would "launder" itself into a
                # trusted baseline through sheer repetition, which would be exactly
                # backwards for a self-healing mechanism. fp_engine persists this
                # per-device, fully autonomously, no human step -- see
                # AutonomousFPEngine.record_device_baseline_observation()'s docstring.
                if self.fp_engine and decision["state"] in (DecisionState.BENIGN, DecisionState.ANOMALOUS):
                    self.fp_engine.record_device_baseline_observation(
                        dev_id,
                        dest_port=features.get("last_dest_port"),
                        asn_owner=asn_owner if asn_owner != "Unknown" else None,
                        domain_base=etld1(top_domain) if top_domain else None,
                    )

                risk = decision["threat_confidence"] * 10.0 # Map to old 0-10 scale temporarily for metrics
                factors = [{"name": decision["explanation"], "score": risk}]
                
                LOGGER.debug("HEE Decision for %s: %s (Confidence: %.2f)", hostname, decision["state"], decision["threat_confidence"])
                
                is_poisoned = state.is_poisoned(risk)

                # H2 FIX: Only train on non-poisoned (benign) observations.
                if self.ml_registry and dev_id in all_active_ids and not is_poisoned:
                    self.ml_registry.learn(dev_id, features)

                if hasattr(state, "rolling") and hasattr(state.rolling, "domains"):
                    for d in state.rolling.domains.keys():
                        state.seen_domains.add(d)

                # PHASE 6: union destination IPs contacted from every known address of this device.
                dest_ips = self.zeek_fx.get_dest_ips(known_ips_snapshot)
                # BUGFIX (external architecture review, 2026-09-09): dest_ips (just
                # computed above) is THIS cycle's real network-traffic destinations --
                # exactly what PeerDeviationHypothesis's own peer-cohort baseline
                # needs and never had access to before (GraphStore.
                # get_distinct_destination_count()'s own BUGFIX comment has the full
                # incident: it used to read the `evidence` table, a detector-biased
                # proxy, not real traffic). Reuses this cycle's already-computed
                # dest_ips rather than a second Zeek query -- best-effort, never
                # blocks the real decision (record_device_traffic()'s own contract).
                v13_live_engine.record_device_traffic(dev_id, dest_ips, now=now)
                if self.geoip_engine and dest_ips:
                    for d_ip in dest_ips:
                        should_export = (d_ip not in state.geo_exported_ips) or (risk >= alert_threshold)
                        if should_export:
                            state.geo_exported_ips.add(d_ip)
                            geo_info = self.geoip_engine.lookup(d_ip)
                            asn_info = self.geoip_engine.lookup_asn(d_ip)
                            country_code = None
                            if geo_info:
                                if isinstance(geo_info, dict): country_code = geo_info.get("country")
                                elif hasattr(geo_info, "country") and geo_info.country: country_code = getattr(geo_info.country, "iso_code", None)
                            
                            if country_code:
                                # Feature 3: Geofencing Policy Enforcement
                                if self.config.get("geofencing_enabled", False):
                                    if country_code in self.config.get("geofencing_countries", []) and d_ip in self.config.get("geofencing_exempt_ips", []):
                                        LOGGER.info(f"Geofence match on {d_ip} ({country_code}) for {dev_id} -- exempted via geofencing_exempt_ips, not escalating.")
                                    elif country_code in self.config.get("geofencing_countries", []):
                                        LOGGER.warning(f"🚫 GEOFENCE VIOLATION: {dev_id} connected to {d_ip} ({country_code})")
                                        # BUGFIX (2026-08-27, categorization consistency audit): this
                                        # evidence carried no .domain at all -- the same attribution gap
                                        # already fixed for honeypot_access/arp_spoofing/zeek_lateral_scan/
                                        # CONNECTION_ABUSE/DGA_BOTNET_C2, just never extended here. Confirmed
                                        # live: a "Geofencing Policy Violation" CRITICAL alert's "Contacted"
                                        # line showed 192.168.1.1 (the router's own private LAN IP -- not
                                        # even something GeoIP can resolve a country for) instead of the real
                                        # foreign IP that actually triggered the block, because with no
                                        # .domain to consume, the display fell back to whatever this device
                                        # connected to most recently. domain=d_ip here, consumed by the
                                        # "Geofencing Policy Violation" branch below, same pattern as every
                                        # other hard-stop evidence type.
                                        active_evidence.append(Evidence(type="geofencing_violation", source="geoip", timestamp=now, device=dev_id, value=10.0, confidence=1.0, provenance=f"Blocklisted Country: {country_code}", domain=d_ip))
                                        # Force re-evaluate decision (V13 FAST CUTOVER: same engine
                                        # selection as the main call site above, kept consistent).
                                        # Deliberately NOT passed device_id/now here (Phase 1, v13
                                        # full-architecture plan): v13's evidence/ingest.py assigns
                                        # a FRESH evidence_id on every convert() call, no dedup by
                                        # content -- since `active_evidence` here is the SAME list
                                        # already converted+written once by the main call site above
                                        # (plus one new geofencing_violation item), passing device_id
                                        # would re-insert every one of those items again as genuine
                                        # duplicate graph rows. This second, rare re-evaluation path
                                        # stays graph-uninvolved until that's worth solving properly.
                                        if self.config.get("engine", "argus") == "argus":
                                            decision = v13_live_engine.evaluate(
                                                active_evidence, rep_vector, getattr(state, "device_type", ""),
                                                fallback_evaluate=self.decision_engine.evaluate,
                                            )
                                        else:
                                            decision = self.decision_engine.evaluate(active_evidence, rep_vector, getattr(state, "device_type", ""))
                                        risk = decision["threat_confidence"] * 10.0
                                        factors = [{"name": decision["explanation"], "score": risk}]
                                
                                self.metrics_exporter.export_geoip_telemetry(geo_info, asn_info, risk=risk, features=features, alert_threshold=alert_threshold)

                if not is_poisoned:
                    self.state_manager.update_baselines(state, features, now, window_seconds, current_risk=risk)

                # PHASE 18: after the geofencing loop above (which can re-evaluate `decision`
                # per contacted IP), this is the FINAL decision for the cycle -- the same one
                # everything downstream (baselines already updated above, alert-building,
                # fp_engine.evaluate()) treats as authoritative. One increment per cycle, not
                # per re-evaluation, using decision_path from whichever branch actually won.
                try:
                    decision_path_total.labels(device=dev_id, hostname=hostname, path=decision.get("decision_path", "benign")).inc()
                except Exception:
                    pass

                # PHASE 21D trigger: widened to ANY non-benign decision_path (not just
                # SUSPICIOUS+) -- per explicit operator direction ("more trigger rather
                # than conservative"), since one burst captures the whole radio and a
                # shared hourly budget (not per-source cooldowns) is what actually
                # controls capture cost, not how eagerly any one source fires.
                if bool(self.config.get("reactive_capture_dns_trigger_enabled", True)) \
                        and decision.get("decision_path", "benign") != "benign":
                    self.reactive_capture.try_dispatch(
                        self.config, self.zeek_fx, trigger_reason="dns_suspicion",
                        state_manager=self.state_manager, evidence_store=self.evidence_store,
                        geoip_engine=self.geoip_engine, ti_engine=self.ti_engine, fp_engine=self.fp_engine,
                    )

                primary_sig = factors[0]["name"] if factors else "Threshold Exceeded"

                # ═══════════════════════════════════════════════════════════════════
                # PHASE 2: cross-cycle escalation. Widening the alert gate below to fire
                # on SUSPICIOUS too gives "alert immediately on a single strong signal."
                # This gives the other half: a SUSPICIOUS state with the SAME primary
                # signature persisting continuously (not just repeating once and going
                # quiet) escalates to HIGH after `suspicious_escalation_seconds` (default
                # 10 min) — increasingly confident the longer it persists, not just a
                # one-shot low-confidence alert every time it recurs.
                # ═══════════════════════════════════════════════════════════════════
                if decision["state"] == DecisionState.SUSPICIOUS:
                    if getattr(state, "suspicious_signature", "") == primary_sig and getattr(state, "suspicious_since", 0.0) > 0:
                        persisted_for = now - state.suspicious_since
                        escalation_threshold = float(self.config.get("suspicious_escalation_seconds", 600.0))
                        if persisted_for >= escalation_threshold:
                            LOGGER.warning(
                                "⬆️ [ESCALATION] %s: SUSPICIOUS signature '%s' persisted %.0fs (>= %.0fs) → escalating to HIGH",
                                hostname, primary_sig, persisted_for, escalation_threshold
                            )
                            decision = dict(decision)
                            decision["state"] = DecisionState.HIGH
                            # PHASE 19 FIX: this escalation predates the severity gate (24e1d07) --
                            # at the time it was written, EVERY non-suppressed alert triggered
                            # mitigate() regardless of state, so mutating decision["state"] here had
                            # no bearing on containment, only on alert visibility/urgency. Once the
                            # severity gate started trusting decision["state"] alone to authorize a
                            # Pi-hole block, this became a silent bypass: a single uncorroborated
                            # signal that simply keeps recurring on the same device+signature (no
                            # NEW independent evidence, just time) could escalate to HIGH and pass
                            # the gate -- exactly the "block only after genuine corroboration"
                            # guarantee the gate exists to provide. Tagging it here lets the
                            # mitigate() call site downstream tell "genuinely corroborated HIGH"
                            # (decision_engine.py's own >=2-independent-sources scoring) apart from
                            # "escalated via persistence alone" -- only the former may contain.
                            # Alert visibility/urgency (this whole block's original purpose) is
                            # untouched: confidence, explanation text, and Telegram severity still
                            # reflect the escalation exactly as before.
                            decision["escalated_via_persistence"] = True
                            # PHASE 30: primary_sig here is still the pre-"(persisted Ns)"
                            # value (the suffix is appended on the next line) -- exactly the
                            # stable underlying signature this counter should be keyed by.
                            persistence_escalation_total.labels(
                                device=str(state.device_id), hostname=str(hostname), signature=str(primary_sig)
                            ).inc()
                            decision["explanation"] = f"{decision['explanation']} (persisted {int(persisted_for)}s)"
                            # BUGFIX (live audit): 0.75 put a persistence-escalated alert's
                            # confidence in the SAME range as decision_engine.py's genuine
                            # 2-independent-source HIGH (0.85) -- indistinguishable in the
                            # number itself, only in a text suffix a human/LLM/downstream
                            # model reader might not weight properly. This is honestly a
                            # weaker claim: the SAME single uncorroborated signal simply kept
                            # recurring, not new evidence. 0.55 keeps it visibly below every
                            # genuine-HIGH path (hypothesis_high=0.85, tier5=0.99,
                            # hard_stop=0.98-1.0) while still above a bare SUSPICIOUS (0.40),
                            # reflecting "worth escalated attention" without overclaiming
                            # "corroborated."
                            decision["threat_confidence"] = max(decision["threat_confidence"], 0.55)
                            risk = decision["threat_confidence"] * 10.0
                            factors = [{"name": decision["explanation"], "score": risk}]
                            primary_sig = factors[0]["name"]
                    else:
                        state.suspicious_signature = primary_sig
                        state.suspicious_since = now
                else:
                    state.suspicious_signature = ""
                    state.suspicious_since = 0.0

                # BUGFIX (found via a 1.5h live alert audit): persistence-escalation
                # (just above) can append " (persisted Ns)" onto primary_sig, and N keeps
                # growing every cycle -- so a raw primary_sig comparison against a
                # previously-stored raw signature almost never matches once a signature
                # has escalated, even though the UNDERLYING signature hasn't changed at
                # all. This fed the repeat-suppression gate below a false "signature
                # changed" signal every cycle, defeating its normal 300s cadence and
                # spamming an alert roughly every 60s+ for as long as the persistence
                # held -- confirmed live via a real "DNS_EVASION (persisted Ns)" alert
                # storm. primary_sig_base strips the suffix so cadence/attribution both
                # key off the stable underlying signature. Split on " (persisted " (not a
                # bare space) since "Confirmed Malicious IOC" has internal spaces of its
                # own.
                primary_sig_base = primary_sig.split(" (persisted ", 1)[0]

                risk_delta = abs(risk - getattr(state, "last_alert_confidence", 0.0))
                time_elapsed = now - getattr(state, "last_alert_time", 0.0)

                # PHASE 2 FIX: alert on any single strong signal, not just HIGH/CRITICAL.
                # SUSPICIOUS was previously capped at confidence 0.40 and NEVER alerted —
                # per your explicit direction (detection over fewer alerts), a single
                # strong signal now reaches the operator instead of going silent until a
                # second independent source corroborates it.
                if decision["state"] in (DecisionState.HIGH, DecisionState.CRITICAL, DecisionState.SUSPICIOUS):
                    if time_elapsed > 300 or (time_elapsed > 60 and (risk_delta >= 1.0 or primary_sig_base != getattr(state, "last_alert_signature_base", ""))):
                        LOGGER.warning("Alert Triggered for %s! Risk: %.2f, Signature: %s", hostname, risk, primary_sig)
                        state.last_alert_time = now
                        state.last_alert_confidence = risk
                        state.last_alert_signature = primary_sig
                        state.last_alert_signature_base = primary_sig_base

                        outbound_bytes = features.get("zeek_outbound_bytes", 0)
                        data_classification = classify_payload_size(outbound_bytes)
                        dest_port = features.get("last_dest_port", 0)
                        dest_proto = features.get("dominant_protocol", "UNKNOWN")
                        service_name = classify_service(dest_port, dest_proto)

                        dns_seq_lines = []
                        if hasattr(state, "rolling") and hasattr(state.rolling, "events"):
                            for ev_ts, ev_dom, ev_status in list(state.rolling.events)[-20:]:
                                status_tag = "🔴 BLOCKED" if ev_status in BLOCKED_STATUSES else "🟡 NXDOMAIN" if ev_status in NXDOMAIN_STATUSES else "🟢 ALLOWED"
                                dns_seq_lines.append(f"  {time.strftime('%H:%M:%S', time.localtime(ev_ts))} | {status_tag} | {ev_dom}")

                        dns_seq_str = "\n".join(dns_seq_lines) if dns_seq_lines else "  No recent DNS events"

                        # PHASE 21D2 FIX: `dest_ip` above is generically "this device's
                        # most recent real connection" (features["last_dest_ip"]),
                        # tracked independently of which detector actually fired -- fine
                        # for a normal DNS-driven alert (the decision engine selects the
                        # triggering domain/IP together via _select_target_domain()), but
                        # DNS_EVASION has no domain and can flag SEVERAL unexplained IPs
                        # at once, so "most recent connection" isn't necessarily one of
                        # them. Without this, mark_false_positive()'s IP-immunization
                        # routing (fp_engine.py) could immunize the wrong IP on a
                        # DNS_EVASION correction -- the actual unexplained one stays
                        # unaddressed and can keep re-firing. dns_evasion.py attaches one
                        # representative unexplained IP onto its Evidence.domain field
                        # specifically so this alert-building step can prefer it here.
                        # BUGFIX: every domain-attribution branch below was written
                        # against the clean, un-suffixed signature name -- primary_sig_base
                        # (computed earlier, stripping any " (persisted Ns)" suffix from
                        # the cross-cycle escalation step) is used here instead of raw
                        # primary_sig so persisted alerts get the same correct attribution
                        # as fresh ones. See primary_sig_base's own comment above for the
                        # full incident writeup.
                        # VERSION 11: DNS_ATTRIBUTION_GAP is DNSEvasionHypothesis's other
                        # possible name (see hypotheses/engine.py) -- same evidence type,
                        # same "no domain, dest_ip is the real target" shape, just a
                        # weaker/more honestly-named sub-case, so it needs the identical
                        # attribution handling as DNS_EVASION in every branch below.
                        alert_dest_ip = dest_ip
                        if primary_sig_base in ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS"):
                            for ev in active_evidence:
                                if ev.type == "dns_evasion_anomaly" and ev.domain:
                                    alert_dest_ip = ev.domain
                                    break

                        # BUGFIX (found via production alerts.json audit): same class of bug as
                        # the DNS_EVASION fix above. target_malicious_domain comes ONLY from
                        # _select_target_domain()'s "most notable domain in the whole window"
                        # scan -- independent of which evidence/hypothesis actually fired. For
                        # DNS_COVERT_TUNNELING (DNSTunnelingV2Hypothesis, keyed on dns_tunnel_v2
                        # evidence), this produced alerts whose displayed queried_domain had NO
                        # causal relationship to the actual tunneling finding -- confirmed in
                        # production data showing benign domains (init.push.apple.com,
                        # time.g.aaplimg.com, an AWS device-hash subdomain) displayed as the
                        # "target" of a tunneling alert that couldn't possibly have fired on
                        # them (they're all in the CDN/telemetry allowlist). threat_signals.py
                        # already attaches the REAL triggering domain onto dns_tunnel_v2
                        # evidence's own .domain field (see its own comment on this exact
                        # transparency gap) -- this was simply never consumed here.
                        alert_target_domain = target_malicious_domain
                        if primary_sig_base == "DNS_COVERT_TUNNELING":
                            for ev in active_evidence:
                                if ev.type == "dns_tunnel_v2" and ev.domain:
                                    alert_target_domain = ev.domain
                                    break
                        # BUGFIX: same gap, DGA_BOTNET_C2/dns_dga_burst instead of
                        # DNS_COVERT_TUNNELING/dns_tunnel_v2 -- dns_dga_burst was a pure
                        # device-wide aggregate (count of recent domains that looked
                        # DGA-like) with no domain attached at all until threat_signals.py
                        # started collecting real examples from the same per-domain loop
                        # that counts them. Confirmed in production: the SAME displayed
                        # domain showing wildly different max_label_length across
                        # consecutive alerts, and the SAME domain family spread across 6+
                        # unrelated devices with zero threat-intel corroboration -- both
                        # symptoms of this exact attribution gap, not necessarily evidence
                        # of a real coordinated threat across those devices.
                        elif primary_sig_base == "DGA_BOTNET_C2":
                            for ev in active_evidence:
                                if ev.type == "dns_dga_burst" and ev.domain:
                                    alert_target_domain = ev.domain
                                    break
                        # BUGFIX: found via a live alert audit -- unlike the two branches
                        # above (which replace the fallback with a REAL evidence-linked
                        # domain), DNS_EVASION structurally has no domain at all by design
                        # (that's the whole signature: real traffic, no DNS explanation) --
                        # yet alert_target_domain had no branch for it either, so it stayed
                        # as target_malicious_domain, a coincidentally-queried, causally-
                        # unrelated domain the device happened to also look up. This
                        # polluted network_context["queried_domain"] (used by
                        # train_fp_classifier.py's f1_entropy feature, among other
                        # consumers) with a real-looking but meaningless domain for every
                        # DNS_EVASION alert -- confirmed live, alongside the earlier
                        # target_display fix which only patched the Telegram TEXT, not this
                        # underlying field. alert_dest_ip (computed just above) already
                        # correctly carries the real flagged IP into destination_ip -- this
                        # just stops a second, unrelated domain from also being attached
                        # where none exists.
                        elif primary_sig_base in ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS"):
                            alert_target_domain = "unknown"
                        # BUGFIX: found via a live third-party review of a real CRITICAL
                        # alert -- decision_engine.py's tier-5 reputation escalation
                        # ("Confirmed Malicious IOC", rep.tier==5) is a SEPARATE verdict
                        # path from the hypothesis competition above; it never got a
                        # branch here either, so it stayed on target_malicious_domain
                        # too. reputation_target (computed alongside ti_risk/abuse_risk/
                        # vt_risk above) is the domain/IP that actually earned the tier-5
                        # classification -- use it here for the same reason the branches
                        # above use their own evidence-linked domain, so the alert
                        # displays/records/immunizes the real source of the risk, not an
                        # unrelated bystander domain. reputation_target may be an IP
                        # (abuse_risk and part of vt_risk are IP-only signals) rather
                        # than a domain, so route it to whichever field actually fits.
                        elif primary_sig_base == "Confirmed Malicious IOC":
                            try:
                                ipaddress.ip_address(reputation_target)
                                alert_dest_ip = reputation_target
                                alert_target_domain = "unknown"
                            except (ValueError, TypeError):
                                alert_target_domain = reputation_target or "unknown"
                        # BUGFIX (live audit): same attribution gap as the branches above,
                        # for the signature types that had NO branch at all until now --
                        # confirmed live, 3,179 alerts across 18 devices where these four
                        # signatures displayed some OTHER device's DNS resolver or a
                        # broadcast address as "destination_ip", purely because dest_ip
                        # defaulted to "whatever this device connected to most recently,"
                        # with zero relation to which evidence actually fired. Each of
                        # these evidence types now carries a real .domain (zeek_features.py/
                        # threat_signals.py/zeek_network.py changes, this same session) --
                        # this just consumes it, same pattern as every branch above.
                        # VERSION 12 (G7): PORT_SCAN/INTERNAL_RECONNAISSANCE are
                        # ConnectionAbuseHypothesis's own dynamic names for a single-category
                        # zeek_conn_abuse-only / arp_sweep-only finding (hypotheses/engine.py) --
                        # same evidence types, same attribution logic applies regardless of
                        # which of the three names this cycle's finding actually got.
                        elif primary_sig_base in ("CONNECTION_ABUSE", "PORT_SCAN", "INTERNAL_RECONNAISSANCE"):
                            # BUGFIX (live audit, follow-up): zeek_conn_abuse's domain is a
                            # genuinely singular target (one specific rejected connection);
                            # arp_sweep's is only ONE of potentially hundreds of swept IPs,
                            # picked somewhat arbitrarily -- prefer the more specific one
                            # when both fired, instead of "whichever happens to iterate
                            # first in active_evidence" (evidence-store insertion order,
                            # not meaningfulness).
                            conn_abuse_ev_domain = None
                            arp_sweep_ev_domain = None
                            for ev in active_evidence:
                                if ev.type == "zeek_conn_abuse" and ev.domain and not conn_abuse_ev_domain:
                                    conn_abuse_ev_domain = ev.domain
                                elif ev.type == "arp_sweep" and ev.domain and not arp_sweep_ev_domain:
                                    arp_sweep_ev_domain = ev.domain
                            chosen = conn_abuse_ev_domain or arp_sweep_ev_domain
                            if chosen:
                                alert_dest_ip = chosen
                                alert_target_domain = "unknown"
                        # VERSION 12 (G7): LATERAL_MOVEMENT is NetworkIntrusionHypothesis's own
                        # dynamic name whenever zeek_lateral_scan drove the finding
                        # (hypotheses/engine.py) -- same evidence types, same attribution logic.
                        elif primary_sig_base in ("NETWORK_INTRUSION", "LATERAL_MOVEMENT"):
                            # BUGFIX (explicit user request, 2026-09-09): "zeek_notice"
                            # fragmented into 4 evidence_type values by tier -- ev.type ==
                            # "zeek_notice" (bare) also still matched for evidence written
                            # before this deploy, still valid within the 24h graph window.
                            for ev in active_evidence:
                                if (ev.type in ("zeek_lateral_scan", "malicious_ja3", "malicious_ja4", "zeek_notice")
                                        or ev.type in ZEEK_NOTICE_EVIDENCE_TYPES) and ev.domain:
                                    alert_dest_ip = ev.domain
                                    alert_target_domain = "unknown"
                                    break
                        # BUGFIX (live audit, 2026-09-09): COORDINATED_TARGETING/
                        # PEER_COHORT_DEVIATION had no branch here at all -- their
                        # evidence (coordinated_targeting/peer_deviation) is v13-only,
                        # synthesized inside decision_engine.evaluate() from graph
                        # queries and never written into pipeline.py's own
                        # active_evidence store, so both signatures silently fell
                        # through to the generic dest_ip fallback ("whatever this
                        # device connected to most recently"). Confirmed live: the two
                        # highest-volume signatures (~57% of unsuppressed HIGH alerts
                        # in a 7h sample) were displayed as "Contacted 224.0.0.22" /
                        # "Contacted ff02::1" / "Contacted unknown" -- multicast/
                        # broadcast noise the multicast-exclusion fix (1ff6c97)
                        # already correctly keeps OUT of the actual scoring, just
                        # never made it into the display. decision.get("winning_evidence")
                        # (decision/engine.py, this same session) carries the real
                        # v13-only evidence that satisfied the winning hypothesis.
                        # coordinated_targeting DOES have a real destination_id (the
                        # destination multiple devices targeted); peer_deviation is
                        # device-level by design (destination_id=NO_DESTINATION,
                        # live_engine.py) -- explicitly "unknown" here rather than a
                        # misleading fallback, same treatment as the DNS_EVASION
                        # "no domain by design" branch above.
                        elif primary_sig_base == "COORDINATED_TARGETING":
                            alert_target_domain = "unknown"
                            for we in decision.get("winning_evidence", []):
                                dest = we.get("destination_id")
                                if we.get("evidence_type") == "coordinated_targeting" and dest and dest != "(none)":
                                    alert_dest_ip = dest
                                    break
                        elif primary_sig_base == "PEER_COHORT_DEVIATION":
                            alert_dest_ip = "unknown"
                            alert_target_domain = "unknown"
                        # BUGFIX (live audit, 2026-09-09, same pass as COORDINATED_TARGETING/
                        # PEER_COHORT_DEVIATION above): a broader check across every
                        # HYPOTHESIS_RELEVANT_EVIDENCE_TYPES name found 4 more signatures
                        # falling through to the same generic dest_ip fallback with no branch
                        # of their own -- DNS_TUNNELING, DATA_EXFILTRATION, C2_BEACONING,
                        # SIGNATURE_MATCHED_THREAT (plus decision_engine.py's own hard-stop
                        # name for the same underlying evidence, "Confirmed Exploit/Malware
                        # Signature (Suricata)"). DNS_TUNNELING's own evidence
                        # (dns_rate/dns_entropy/dns_unique_ratio, detectors/dns_behavior.py)
                        # never sets .domain at all -- a genuine device-wide DNS-rate
                        # aggregate, no single destination to name, same "destination-less by
                        # design" shape as PEER_COHORT_DEVIATION above.
                        elif primary_sig_base == "DNS_TUNNELING":
                            alert_dest_ip = "unknown"
                            alert_target_domain = "unknown"
                        # DATA_EXFILTRATION/C2_BEACONING's own evidence (zeek_exfiltration/
                        # zeek_beaconing, detectors/threat_signals.py) has the SAME known gap
                        # v13/ops/live_engine.py's own _NEEDS_LAST_DEST_IP_FALLBACK already
                        # documents and patches (a last-known-dest-IP fallback, applied when
                        # v13 converts this cycle's v1 evidence to its own model) -- so
                        # decision.get("winning_evidence") already carries a usable
                        # destination_id for these two, the same field COORDINATED_TARGETING
                        # above reads, no new plumbing needed.
                        elif primary_sig_base == "DATA_EXFILTRATION":
                            alert_target_domain = "unknown"
                            for we in decision.get("winning_evidence", []):
                                dest = we.get("destination_id")
                                if we.get("evidence_type") == "zeek_exfiltration" and dest and dest != "(none)" and dest != "unknown":
                                    alert_dest_ip = dest
                                    break
                        elif primary_sig_base == "C2_BEACONING":
                            alert_target_domain = "unknown"
                            for we in decision.get("winning_evidence", []):
                                dest = we.get("destination_id")
                                if we.get("evidence_type") == "zeek_beaconing" and dest and dest != "(none)" and dest != "unknown":
                                    alert_dest_ip = dest
                                    break
                        # SIGNATURE_MATCHED_THREAT (SuricataSignatureHypothesis, a
                        # corroborating-evidence-tier Suricata match) and "Confirmed Exploit/
                        # Malware Signature (Suricata)" (decision_engine.py's own hard-stop
                        # name for a high-confidence Suricata match) are two different verdict
                        # PATHS over the exact same suricata_signature_match evidence
                        # (detectors/suricata_scan.py), which already sets a real .domain
                        # (target_ip) directly on the v1 evidence -- same simple pattern as
                        # the NETWORK_INTRUSION/ARP-spoofing/honeypot branches above, no
                        # winning_evidence needed.
                        elif primary_sig_base in ("SIGNATURE_MATCHED_THREAT", "Confirmed Exploit/Malware Signature (Suricata)"):
                            for ev in active_evidence:
                                if ev.type == "suricata_signature_match" and ev.domain:
                                    alert_dest_ip = ev.domain
                                    alert_target_domain = "unknown"
                                    break
                        elif primary_sig_base == "Layer-2 ARP Spoofing Detected":
                            for ev in active_evidence:
                                if ev.type == "arp_spoofing" and ev.domain:
                                    alert_dest_ip = ev.domain
                                    alert_target_domain = "unknown"
                                    break
                        elif primary_sig_base == "Internal Honeypot Accessed":
                            for ev in active_evidence:
                                if ev.type == "honeypot_access" and ev.domain:
                                    alert_dest_ip = ev.domain
                                    alert_target_domain = "unknown"
                                    break
                        # VERSION 12 (G6): "(Uncorroborated)" is decision_engine.py's own
                        # suffix for the demoted HIGH case (geography alone, no behavioral
                        # corroboration) -- same evidence type/attribution applies either way.
                        elif primary_sig_base in ("Geofencing Policy Violation", "Geofencing Policy Violation (Uncorroborated)"):
                            for ev in active_evidence:
                                if ev.type == "geofencing_violation" and ev.domain:
                                    alert_dest_ip = ev.domain
                                    alert_target_domain = "unknown"
                                    break

                        # VERSION 10 (incident aggregation): computed here, once, using the
                        # already-corrected alert_dest_ip/alert_target_domain (not the raw
                        # dest_ip/target_malicious_domain fallbacks) so the incident key is
                        # keyed on the SAME evidence-linked target every domain-attribution
                        # fix above already worked to get right -- an incorrect target here
                        # would silently re-fragment incident grouping the same way the
                        # persistence-suffix bug once fragmented alert attribution.
                        incident_id = _incident_key(dev_id, alert_dest_ip, alert_target_domain, primary_sig_base)

                        alert_payload = {
                            "type": "ids_alert",
                            "timestamp": now,
                            "device": {
                                "id": dev_id, "ip": client_ip, "hostname": hostname, "type": state.device_type,
                                # v13 full-architecture plan, Phase 3: closes a real operator-confusion
                                # gap -- see _ip_family()'s own docstring above for the real incident
                                # that prompted this. other_known_ips lets an operator immediately see
                                # this device's OTHER addresses (e.g. its IPv4 alongside an IPv6-only
                                # alert) instead of needing to cross-reference dev_id manually.
                                "ip_family": _ip_family(client_ip),
                                "other_known_ips": sorted(
                                    ip for ip in getattr(state, "known_ips", set()) if ip and ip != client_ip
                                ),
                            },
                            "network_context": {
                                "destination_ip": alert_dest_ip, "destination_port": dest_port, "service_name": service_name,
                                "data_type": dest_proto, "payload_size_bytes": outbound_bytes, "payload_classification": data_classification,
                                "queried_domain": alert_target_domain,
                            },
                            "risk": risk,
                            "signature": primary_sig,
                            "factors": factors,
                            "features": features,
                            "schema": "home_ids_alerts_v3",
                            "evidence_verification_required": decision.get("evidence_verification_required", False),
                            "hypothesis_weight": decision.get("hypothesis_weight", 0.0),
                            "reasoning_trail": decision.get("reasoning_trail", []),
                            "incident_id": incident_id,
                            # PHASE 50 (ollama_soc.py HEE ground-truth wiring): persists the
                            # SAME attack-vs-benign hypothesis competition decision_engine.py just
                            # computed for this alert -- previously only reachable in-memory via the
                            # `decision` dict, discarded once this cycle ended. Closes the "Known
                            # limitation" this doc's own dependency map already flagged (reasoning_trail
                            # retains the rendered strings but not the raw name/score/family-count
                            # triple a downstream consumer can actually grade against). ollama_soc.py's
                            # batch SOC review reads this back the next time this exact alert pattern
                            # comes up for LLM review, so a same-day "benign, suppress" LLM verdict can
                            # be rejected outright when the deterministic engine already corroborated an
                            # attack hypothesis across >=2 independent evidence families for THIS alert
                            # -- instead of the LLM's free-text paragraph being the only thing deciding
                            # whether to auto-suppress. See ai_soc.py's DeterministicValidator.validate()
                            # `ground_truth` param and ollama_soc.py's _VERDICT_SHAPED_FIELDS (these are
                            # stripped back out before the evidence-only prompt reaches the LLM -- they
                            # encode this system's own prior verdict, not a raw observation).
                            "hee_hypotheses": decision.get("hypotheses", {}),
                            "hee_independent_sources": decision.get("independent_sources", 0),
                            "hee_decision_path": decision.get("decision_path", ""),
                            # BUGFIX (live audit, 2026-09-09, third-party ChatGPT review):
                            # these were ALWAYS computed from active_evidence alone --
                            # pipeline.py's own v1 evidence store, which structurally never
                            # contains v13-only synthetic evidence (coordinated_targeting/
                            # peer_deviation/fingerprint_campaign/dga_seed_campaign -- see
                            # decision/engine.py's own comment on its "evidence_families"/
                            # "evidence_types" return fields, the actual ground truth
                            # hee_independent_sources counts against). Confirmed live: 34 of
                            # 121 alerts in a 24h sample showed hee_evidence_families=[] while
                            # hee_independent_sources correctly showed 2-4 -- every one a
                            # COORDINATED_TARGETING/PEER_COHORT_DEVIATION verdict, exactly the
                            # "HIGH with 0 evidence families" inconsistency flagged externally.
                            # Unioned (not replaced) with decision's own values so v-current
                            # (whose decision dict lacks these keys, .get(...,[]) degrades to
                            # today's behavior unchanged) and any evidence type not read by
                            # decision_engine.py's attack_evidence (e.g. local_context/
                            # novelty_context families, deliberately excluded there) are never
                            # lost -- purely additive, can only ADD what was missing.
                            "hee_evidence_families": sorted({
                                ev.independence_group for ev in active_evidence if ev.independence_group
                            } | set(decision.get("evidence_families", []))),
                            # PHASE 58: the actual Evidence.type names present (not just
                            # their coarser independence_group families) -- needed because
                            # family granularity is too coarse for ai_soc.py's attack-shaped-
                            # evidence check: e.g. "dns_dga_burst" and the ambiguous
                            # "dns_rate"/"dns_entropy" all share the SAME "dns_behavior"
                            # family, but only the former is attack-shaped (see
                            # hypotheses/evidence.py's ATTACK_SHAPED_EVIDENCE_TYPES). Reuses
                            # the SAME active_evidence list already in scope here, same
                            # treatment as hee_evidence_families right above -- same union
                            # reasoning for the v13-synthetic-type gap.
                            "hee_evidence_types": sorted(
                                {ev.type for ev in active_evidence} | set(decision.get("evidence_types", []))
                            ),
                            # Console Suricata surfacing (this session): suricata_scan.py's
                            # suricata_alerts_to_evidence() already builds a rich provenance
                            # string ("detector:suricata:{signature_id}:{category}:{signature}")
                            # on each Evidence object, but nothing downstream ever persisted
                            # that detail onto the alert record -- confirmed directly against
                            # .94's live state/alerts.json: 0 of 25 historical
                            # SIGNATURE_MATCHED_THREAT alerts have a signature name anywhere in
                            # the file, only the hypothesis label. Additive field, parses that
                            # same provenance string back out for suricata-type evidence in the
                            # SAME active_evidence list already in scope here (no new evidence
                            # lookup). Historical alerts predating this change simply have an
                            # empty list here -- the console shows an honest "not recorded for
                            # this alert" fallback rather than guessing.
                            "suricata_matches": [
                                {"signature_id": parts[2], "category": parts[3], "signature": parts[4]}
                                for ev in active_evidence if ev.type == "suricata_signature_match"
                                for parts in [ev.provenance.split(":", 4)] if len(parts) == 5
                            ],
                            # PHASE 58b (destination-ownership/baseline-familiarity
                            # validator precondition): this cycle's own reputation tier
                            # for the destination -- rep_vector is already computed above
                            # (feeds decision_engine.evaluate() itself), reused verbatim
                            # rather than ai_soc.py/ollama_soc.py re-deriving a
                            # ReputationClassifier.classify() call independently, which
                            # could disagree with what the live pipeline actually used if
                            # TI feeds changed between publish time and LLM review time.
                            "hee_rep_tier": rep_vector.tier,
                            # BUGFIX (live audit): previously only lived on the in-memory
                            # `decision` dict (read once for the mitigation gate at the
                            # severity-gate check below) and was never persisted onto the
                            # alert record itself -- train_fp_classifier.py had no way to
                            # tell a persistence-escalated alert (same single uncorroborated
                            # signal recurring, confidence capped at 0.55, no NEW evidence)
                            # apart from a genuine 2-independent-source HIGH when reading
                            # alerts.json back for training.
                            "escalated_via_persistence": bool(decision.get("escalated_via_persistence", False)),
                        }

                        # =============================================================
                        # AUTONOMOUS FALSE-POSITIVE GATE (CL-AFPE)
                        # Before publishing this alert or executing hardware IPS containment,
                        # the 3-stage FP engine evaluates whether this is a real threat.
                        # =============================================================
                        # VERSION 11 (P0 fix): pass the HEE's own already-computed verdict
                        # through so fp_engine's Stage-1 hard-stop can recognize a
                        # decision_engine.py hard-stop (honeypot/ARP-spoof/geofence/tier-5
                        # IOC) directly instead of independently re-deriving the same
                        # signal from raw features with its own, separately-drifting
                        # thresholds -- see fp_engine.evaluate()'s docstring.
                        # V13 FULL-ARCHITECTURE PLAN, WORKSTREAM 2: cl_afpe_engine mirrors
                        # the top-level `engine:` switch's exact shape -- default
                        # "v_current" keeps AutonomousFPEngine as the real suppression
                        # decision (with v13's ClAfpeEngine still shadow-computed
                        # alongside for comparison, below); "argus" (set automatically by
                        # cl_afpe_flip_monitor.py once its own bar clears, see that file's
                        # docstring) makes ClAfpeEngine's verdict the real one instead --
                        # a whole-engine swap, not a per-mechanism flag, matching this
                        # project's own precedent for the main decision engine (A13).
                        if self.config.get("cl_afpe_engine", "v_current") == "argus":
                            fp_verdict = v13_live_engine.evaluate_cl_afpe_live(
                                alert_payload=alert_payload,
                                features=features,
                                risk_score=risk,
                                ti_engine=self.ti_engine,
                                decision=decision,
                                asn_owner=asn_owner if asn_owner != "Unknown" else "",
                                fallback_evaluate=self.fp_engine.evaluate,
                                now=now,
                            )
                        else:
                            fp_verdict = self.fp_engine.evaluate(
                                alert_payload=alert_payload,
                                features=features,
                                risk_score=risk,
                                ti_engine=self.ti_engine,
                                decision=decision,
                                asn_owner=asn_owner if asn_owner != "Unknown" else "",
                            )

                            # V13 FULL-ARCHITECTURE PLAN, PHASE 6E: CL-AFPE shadow-mode
                            # comparison, compute-only -- never affects fp_verdict above
                            # or anything derived from it. Only runs while v1 is still
                            # the real decision-maker -- once cl_afpe_engine="argus" above,
                            # there's no more real v1 verdict left to diff against (same
                            # reasoning that froze decision_engine.py's own shadow
                            # experiment once the main engine flipped, A13), and calling
                            # fp_engine.evaluate() here anyway would keep writing to its
                            # now-unread flat files for no purpose. Best-effort: never
                            # raises (caught internally), so a shadow failure can never
                            # affect the real alert this cycle publishes.
                            v13_live_engine.evaluate_cl_afpe_shadow(
                                alert_payload=alert_payload,
                                features=features,
                                decision=decision,
                                asn_owner=asn_owner if asn_owner != "Unknown" else "",
                                fp_verdict_v1=fp_verdict,
                                now=now,
                            )

                        # PHASE 12: persist CL-AFPE's own combined confidence into the alert
                        # record. Previously this number existed only in memory for the
                        # duration of this evaluation — alerts.json never carried it, so
                        # there was no way to later ask "how well-calibrated is the
                        # suppress/uncertain threshold against what actually turned out to
                        # be a confirmed FP or a confirmed threat?" This is the data
                        # scripts/train_fp_classifier.py's threshold-calibration pass reads.
                        alert_payload["fp_verdict"] = {
                            "verdict": fp_verdict.get("verdict"),
                            "confidence": fp_verdict.get("confidence"),
                            # VERSION 11 (P2 follow-up): None whenever no reliable
                            # calibration is loaded -- see fp_engine.py's _apply_calibration().
                            "calibrated_confidence": fp_verdict.get("calibrated_confidence"),
                            "stage": fp_verdict.get("stage"),
                        }

                        # Tightly coupled ML learning & Anti-Poisoning:
                        if self.ml_registry:
                            if fp_verdict["verdict"] == "FALSE_POSITIVE":
                                self.ml_registry.learn_normal(dev_id, features)
                            elif fp_verdict["verdict"] == "CONFIRMED_THREAT":
                                self.ml_registry.reject_threat(dev_id, features)

                        # BUGFIX: containment_decision_state was previously only assigned
                        # inside the `else:` branch below (fp_verdict["suppress"] is False) --
                        # but the telegram_worthy computation (using containment_decision_state)
                        # further below runs unconditionally after this if/else, regardless of which
                        # branch executed. Every autonomously-suppressed alert (the `if` branch
                        # here) crashed with UnboundLocalError. Harmless default here: every
                        # downstream use of telegram_worthy is itself gated on
                        # `not fp_verdict["suppress"]`, so this value is never actually acted on
                        # when suppressed -- the else branch's own PHASE 19 logic still computes
                        # the real value whenever it matters.
                        containment_decision_state = decision.get("state", "SUSPICIOUS")
                        if fp_verdict["suppress"]:
                            LOGGER.info(
                                "✅ [PIPELINE] Alert for %s autonomously suppressed as FALSE POSITIVE "
                                "(confidence=%.3f, stage=%s). Skipping Telegram & Hardware Isolation.",
                                hostname, fp_verdict["confidence"], fp_verdict["stage"]
                            )
                            # Flag it so downstream readers know it was suppressed
                            alert_payload["suppressed"] = True

                            # ═══════════════════════════════════════════════════════
                            # PHASE 3 (closed-loop autonomous actions): the action already
                            # executed (the domain is immunized, this and future alerts
                            # for it are suppressed) — this does NOT block on approval.
                            # It posts a non-blocking, one-tap-revoke notification so a
                            # human can catch a bad auto-suppression without having been
                            # in the loop for the action itself. Only fires on a genuinely
                            # NEW immunization (fp_engine already dedupes repeat hits).
                            # ═══════════════════════════════════════════════════════
                            action_info = fp_verdict.get("action")

                            # PHASE 14 FIX: this is the PRIMARY, highest-volume autonomous
                            # suppression path (every CL-AFPE Stage 2/3 auto-suppress runs
                            # through here) — until now it immunized the domain (stopping
                            # FUTURE alerts) but never checked whether an EARLIER cycle had
                            # already blocked it in Pi-hole before CL-AFPE learned the
                            # pattern was safe. A domain immunized today could stay blocked
                            # in Pi-hole indefinitely, silently breaking the device that
                            # depends on it, with nothing left to ever un-block it. Per
                            # explicit direction: block only what's absolutely necessary.
                            # Checks LOCAL state first (cheap, no network call) rather than
                            # calling unblock_domain() unconditionally — it always fires a
                            # real Pi-hole DELETE and always returns True regardless of
                            # whether the domain was actually blocked, so an unconditional
                            # call would both waste API traffic on every immunization and
                            # make an inaccurate "released" log claim. Only on a genuinely
                            # NEW immunization, matching the same dedup fp_engine already
                            # applies before offering a revoke.
                            if action_info and action_info.get("type") == "immunize_domain" and self.ips_mitigator:
                                target_domain_imm = action_info["target"]
                                # PHASE 16 FIX: was an exact-match check against target_domain_imm
                                # itself (the base domain) -- but Pi-hole blocks are keyed by the
                                # specific queried FQDN, which is almost always a SUBDOMAIN of the
                                # base domain, not the base domain literally. That exact match
                                # essentially never fired in practice. unblock_by_base_domain()
                                # sweeps every blocked entry under this base domain instead.
                                released = self.ips_mitigator.unblock_by_base_domain(target_domain_imm)
                                if released:
                                    LOGGER.info(
                                        "🔓 [PIPELINE] '%s' was immunized as a false positive — "
                                        "released %d existing Pi-hole block(s): %s",
                                        target_domain_imm, len(released), ", ".join(released)
                                    )

                            if action_info and bool(self.config.get("fp_revoke_notifications_enabled", True)):
                                action_id = uuid.uuid4().hex[:10]
                                ttl_seconds = float(self.config.get("fp_revoke_action_ttl_seconds", 86400.0))
                                self.state_manager.record_action(
                                    action_id=action_id, action_type=action_info["type"],
                                    target=action_info["target"], device_id=dev_id, hostname=hostname,
                                    ttl_seconds=ttl_seconds,
                                )
                                revoke_hours = max(1, int(ttl_seconds / 3600))

                                # BUGFIX (live alert audit): this message used to show only
                                # hostname (dead-ended on "unknown" for devices with no
                                # resolved hostname, with no IP fallback even though client_ip
                                # was sitting right there) and a bare confidence number with
                                # zero explanation of what alert/evidence led here or why the
                                # FP engine landed on that number. Everything below was already
                                # computed by fp_engine.evaluate() a few lines earlier -- see
                                # fp_verdict["reasons"]'s own comment ("Exposed as a real key
                                # here so pipeline.py can show it") -- it just was never read.
                                identity = f"*{hostname}*"
                                if client_ip and client_ip != "unknown":
                                    identity += f" ({client_ip})"

                                net_ctx = alert_payload.get("network_context", {})
                                orig_dest_ip = net_ctx.get("destination_ip", "unknown")
                                origin_line = ""
                                if orig_dest_ip and orig_dest_ip != "unknown":
                                    dest_geo_note = _build_geo_note(self.geoip_engine, orig_dest_ip)
                                    origin_line = (
                                        f"\nIt was originally flagged by: {alert_payload.get('signature', 'unknown')} "
                                        f"(risk {alert_payload.get('risk', 0.0):.1f}) — contacted `{orig_dest_ip}`"
                                        f"{dest_geo_note}:{net_ctx.get('destination_port', '')} "
                                        f"({net_ctx.get('service_name', 'unknown')})"
                                    )

                                revoke_msg = (
                                    f"🔔 *Auto-action:* immunized `{action_info['target']}` for {identity}\n"
                                    f"This stopped future alerts for this domain because our false-positive "
                                    f"check was {fp_verdict.get('confidence', 0.0) * 100:.0f}% confident it's "
                                    f"benign.{origin_line}\n"
                                    f"If this was actually a real threat, tap Revoke within {revoke_hours}h."
                                )
                                reasons_list = fp_verdict.get("reasons") or []
                                if reasons_list:
                                    calib = fp_verdict.get("calibrated_confidence")
                                    calib_line = (
                                        f"- Calibrated confidence: {calib:.2f}" if calib is not None
                                        else "- Calibrated confidence: not available"
                                    )
                                    revoke_msg += (
                                        "\n\n🔧 *Technical detail (optional)*\n"
                                        + "\n".join(f"- {r}" for r in reasons_list)
                                        + f"\n{calib_line}"
                                    )
                                self.alert_manager.send(
                                    revoke_msg,
                                    reply_markup={"inline_keyboard": [[
                                        {"text": "↩️ Revoke (this was a real threat)", "callback_data": f"revoke:{action_id}"}
                                    ]]}
                                )
                        else:
                            # Real threat or low-confidence alert -> execute IPS containment & publish Telegram
                            containment_status = "🔓 UNBLOCKED / ACTIVE (Monitoring Only)"
                            # BUGFIX: found via a live third-party review of a real tarpit alert --
                            # this authorizes Layer-2 tarpit containment (bypassing the normal
                            # risk>=9.0 floor entirely), but zeek_lateral_moves is a raw connection
                            # COUNT, so a single ordinary SMB/SSH/RDP connection to one internal
                            # device satisfied `> 0` identically to a genuine multi-target scan --
                            # confirmed live: zeek_lateral_moves=1 alone triggered tarpit. Same fix
                            # as fp_engine.py's Stage-1 Check 2 -- require a genuine distinct-target
                            # count, not just "at least one connection happened."
                            lateral_targets_count = int(features.get("zeek_lateral_unique_targets", 0) or 0)
                            lateral_threshold = int(self.config.get("lateral_movement_unique_targets_threshold", 2))
                            lateral_threat = (
                                (features.get("zeek_lateral_moves", 0) > 0 and lateral_targets_count >= lateral_threshold)
                                or features.get("zeek_honeypot_hits", 0) > 0
                            )
                            # PHASE 19 FIX: decision["state"] alone can no longer be trusted here --
                            # it reads HIGH both when decision_engine.py itself found >=2 genuinely
                            # independent corroborating sources, AND when the escalation block above
                            # promoted a single persisting-but-uncorroborated SUSPICIOUS signal to
                            # HIGH purely because it kept recurring. Only the former should ever be
                            # allowed to authorize containment -- persistence of one weak signal is
                            # not the same as a second independent one. Alert text/Telegram severity
                            # still shows the escalated HIGH exactly as before; only the value fed to
                            # the severity gate is downgraded back to SUSPICIOUS for this case.
                            containment_decision_state = decision.get("state", "SUSPICIOUS")
                            if decision.get("escalated_via_persistence"):
                                containment_decision_state = DecisionState.SUSPICIOUS
                            if self.ips_mitigator:
                                # BUGFIX: use alert_target_domain (the evidence-corrected domain,
                                # see its own comment above), not the raw target_malicious_domain
                                # fallback -- otherwise containment could block/track a benign
                                # "most frequent domain" instead of the domain actually implicated
                                # by the evidence that authorized this containment decision.
                                self.ips_mitigator.mitigate(
                                    st=state,
                                    target_domain=alert_target_domain,
                                    risk_score=risk,
                                    lateral_threat=lateral_threat,
                                    is_safe=is_safe,
                                    ti_engine=self.ti_engine,
                                    reason=primary_sig,
                                    fp_verdict=fp_verdict,
                                    decision_state=containment_decision_state
                                )
                                containment_status = self.ips_mitigator.get_containment_status(
                                    client_ip=client_ip,
                                    mac_addr=getattr(state, "mac_address", "unknown"),
                                    domain=alert_target_domain,
                                    dev_id=dev_id
                                )
                                # V13 FULL-ARCHITECTURE PLAN, PHASE 7 (presentation-layer drift
                                # guard): get_containment_status() above (ips.py's own 3-dict
                                # scan) stays the AUTHORITATIVE, synchronous source for the alert
                                # text -- it's the real, zero-latency truth; the graph's
                                # containment_actions mirror (Phase 3) is a best-effort, eventually-
                                # consistent AUDIT COPY, so replacing the authoritative check with
                                # the graph one would be a real reliability regression, not an
                                # improvement. What's actually worth catching: the two
                                # DISAGREEING at all would mean either the mirror silently failed
                                # (ips.py's real state is right, the graph write from
                                # mitigate()->_mirror_containment() a moment ago didn't land) or a
                                # deeper bug -- best-effort, log-only, never affects containment_status.
                                if "UNBLOCKED" not in containment_status:
                                    try:
                                        graph_active = v13_live_engine.get_graph_store().get_active_containment_for_device(dev_id)
                                        if not graph_active:
                                            LOGGER.warning(
                                                "Containment drift: ips.py reports '%s' active for %s but the graph "
                                                "mirror shows nothing active -- a containment_actions write may have "
                                                "silently failed this cycle.", containment_status, hostname,
                                            )
                                    except Exception as exc:
                                        LOGGER.debug("Containment drift check failed (non-fatal): %s", exc)

                            # PHASE 10 FIX: this used to rewrite ANY "UNBLOCKED" containment
                            # status to "WAITING FOR APPROVAL" purely because
                            # interactive_blocking_enabled was on — with no check on whether
                            # mitigate() actually had anything pending. mitigate()'s own
                            # interactive-mode branches (ips.py:344,362) are only even
                            # reachable when risk_score >= 8.5 (router) or lateral_threat is
                            # true — below that, mitigate() does nothing and "UNBLOCKED" is
                            # just the correct, final status, not a placeholder. A SUSPICIOUS/
                            # monitor alert at risk=4.5 was getting relabeled "Action Required"
                            # with live approval buttons even though nothing was ever
                            # queued — a real, user-facing contradiction (SUSPICIOUS/monitor
                            # decision, WAITING FOR APPROVAL response). 8.5 is the lower of
                            # mitigate()'s two thresholds (router 8.5, tarpit 9.0), so it's the
                            # correct floor for "could plausibly have something pending".
                            # BUGFIX (2026-08-27): this rewrite fired regardless of `is_safe`,
                            # but mitigate() (ips.py) returns immediately -- queuing nothing at
                            # all -- for ANY is_safe device, unconditionally, before it ever
                            # reaches its own interactive-mode branches. A CRITICAL alert on a
                            # safe_ips device (e.g. the router touching the honeypot) was
                            # telling the operator "action is queued, waiting for your
                            # approval" and "tap Release" for containment that was never
                            # queued and never will be -- tapping Approve there would either
                            # no-op or attempt to isolate the device the config explicitly
                            # promises to never touch. See also Gap 3 Fix B just above, which
                            # stops the honeypot hard-stop from firing on safe_ips devices at
                            # all going forward; this fix covers every OTHER hard-stop/HIGH
                            # path that could still reach this same contradiction.
                            if (
                                bool(self.config.get("interactive_blocking_enabled", False))
                                and "UNBLOCKED" in containment_status
                                and (risk >= 8.5 or lateral_threat)
                                and not is_safe
                            ):
                                containment_status = "⏳ WAITING FOR APPROVAL (Action Required via Inline Buttons below)"

                        self.alert_writer.write(alert_payload)
                        alerts_total.labels(client_ip, getattr(state, "hostname", "unknown"), getattr(state, "device_type", "unknown")).inc()

                        # PHASE 21 FIX (Telegram volume reduction, explicit operator direction:
                        # "no alert for suspicion"): a Telegram notification now requires the SAME
                        # genuinely-corroborated HIGH/CRITICAL bar that already authorizes a Pi-hole
                        # block (containment_decision_state, computed above at the mitigate() call
                        # site -- already downgraded from a persistence-escalated HIGH back to
                        # SUSPICIOUS, see the PHASE 19 comment above). A SUSPICIOUS/monitor-only
                        # decision still writes to alerts.json (line above, unconditional), still
                        # trains CL-AFPE, still shows in Grafana -- it just no longer pages the
                        # operator. This does not touch mitigate() or the router/tarpit escalation
                        # paths above, which already have their own independent risk_score/
                        # lateral_threat gates unrelated to Telegram.
                        telegram_worthy = containment_decision_state in (DecisionState.HIGH, DecisionState.CRITICAL)

                        # PHASE 21D trigger: even though a HIGH/CRITICAL decision already
                        # alerts/blocks via the paths above, also firing a capture burst
                        # gives full radio-wide context for that specific incident window,
                        # not just the flagged device's own (WiFi-blind, absent this) view.
                        # Gated on the same not-suppressed condition as the Telegram send
                        # below -- CL-AFPE already decided this specific decision was a
                        # false positive, so there's no real incident window to capture.
                        if bool(self.config.get("reactive_capture_high_severity_trigger_enabled", True)) \
                                and telegram_worthy and not fp_verdict["suppress"]:
                            self.reactive_capture.try_dispatch(
                        self.config, self.zeek_fx, trigger_reason="high_severity",
                        state_manager=self.state_manager, evidence_store=self.evidence_store,
                        geoip_engine=self.geoip_engine, ti_engine=self.ti_engine, fp_engine=self.fp_engine,
                    )

                        # PHASE 21D3: second feed point for the local confirmed-intel store
                        # (fp_engine.py's Stage-1 CONFIRMED_THREAT is the first) -- a HIGH/
                        # CRITICAL decision here can come from 2+ independent hypothesis
                        # evidence sources WITHOUT any single Stage-1 hard-stop signal ever
                        # firing (e.g. DGA + reputation combined), so this is genuinely a
                        # second, non-redundant confirmation path, not a duplicate of the one
                        # inside fp_engine.py. Same not-suppressed gate as the trigger above.
                        if telegram_worthy and not fp_verdict["suppress"] and self.fp_engine:
                            # BUGFIX: alert_target_domain, not target_malicious_domain -- see its
                            # own comment above. Feeding the local confirmed-intel store (which a
                            # DIFFERENT device's future connection can hard-stop against) the
                            # wrong domain would teach the network to remember the wrong thing.
                            # FURTHER BUGFIX (found via a live state-folder audit): alert_target_domain
                            # is only ever evidence-linked for the two signatures explicitly handled
                            # above (DNS_COVERT_TUNNELING/DGA_BOTNET_C2) -- for every other signature
                            # reaching HIGH/CRITICAL (e.g. CONNECTION_ABUSE via arp_sweep + a second
                            # corroborating source, with no domain involved in the actual evidence at
                            # all), alert_target_domain still equals target_malicious_domain, the
                            # generic "most notable domain in the window" fallback -- confirmed live:
                            # sharepoint.com/coinbase.com/alibaba.com/aws.dev/nflximg.com/
                            # vscode-cdn.net/claudeusercontent.com/epson.biz all got poisoned as
                            # "confirmed malicious" this exact way. Only pass a domain here when it
                            # was actually overridden by real evidence above, never the raw fallback.
                            domain_is_evidence_linked = alert_target_domain != target_malicious_domain
                            self.fp_engine.record_confirmed_threat(
                                dev_id,
                                etld1(alert_target_domain) if domain_is_evidence_linked else None,
                                dest_ip, reason="HIGH_CRITICAL_DECISION",
                                signature=primary_sig,
                                asn_owner=asn_owner if asn_owner != "Unknown" else "",
                            )

                        # VERSION 10 (incident aggregation): the same device+target+signature
                        # combination could previously generate a full Telegram alert every
                        # time this cadence gate cleared (as often as every 60s once a
                        # signature escalated) even though it's the SAME ongoing incident, not
                        # a new one. should_notify() always records the occurrence (so
                        # occurrence_count/incident age stay accurate regardless), but only
                        # asks for a Telegram send on: the first occurrence, a genuine severity
                        # escalation (SUSPICIOUS->HIGH->CRITICAL), or a periodic "still
                        # ongoing" update no more often than incident_update_min_interval_seconds.
                        # alerts.json (written unconditionally above, before this gate) and
                        # mitigate()/containment (their own independent gates above) are both
                        # completely unaffected -- this only ever suppresses the redundant
                        # Telegram push for a repeat of the exact same incident.
                        incident_notify = self.incident_tracker.should_notify(incident_id, containment_decision_state, now)
                        if not incident_notify.should_notify:
                            LOGGER.info(
                                "Telegram suppressed for %s: occurrence #%d of ongoing incident '%s' (age %.0fs)",
                                hostname, incident_notify.occurrence_count, incident_id, incident_notify.incident_age_seconds,
                            )

                        # V13 FULL-ARCHITECTURE PLAN, ALERT/DECISION UNIFICATION (Phase 2+4):
                        # enrich this cycle's graph decision row (already written by
                        # v13_live_engine.evaluate()'s own _write_graph() call, earlier this
                        # cycle) with the SAME alert_payload/fp_verdict already written to
                        # alerts.json above, plus IncidentTracker's own notify decision for
                        # this occurrence -- makes decisions.raw_payload_json a real superset
                        # of alert_payload without changing alerts.json's write path at all
                        # (AlertJSONWriter.write() above is completely untouched -- zero
                        # regression risk to train_fp_classifier.py/LLM review, which read its
                        # existing flat JSONL shape). IncidentTracker's own hot-path code and
                        # behavior are also completely unchanged -- only the FACT that a notify
                        # decision was made gets recorded, for audit, reusing this one call
                        # rather than adding a second graph write. Best-effort: a failure here
                        # must never affect the alert already decided/written above.
                        graph_decision_id = decision.get("_graph_decision_id")
                        if graph_decision_id:
                            try:
                                v13_live_engine.get_graph_store().update_decision_payload(
                                    graph_decision_id,
                                    {
                                        "alert_payload": alert_payload,
                                        "fp_verdict": fp_verdict,
                                        "incident": {
                                            "key": incident_id,
                                            "should_notify": incident_notify.should_notify,
                                            "occurrence_count": incident_notify.occurrence_count,
                                            "is_escalation": incident_notify.is_escalation,
                                            "incident_age_seconds": incident_notify.incident_age_seconds,
                                        },
                                    },
                                )
                            except Exception as exc:
                                LOGGER.warning(
                                    "Failed to enrich graph decision %r with alert_payload/fp_verdict/incident "
                                    "for %s -- alerts.json/Telegram are already decided and unaffected: %s",
                                    graph_decision_id, hostname, exc,
                                )

                        if fp_verdict["suppress"] and telegram_worthy:
                            # PHASE 64: the reset below (PHASE 6's own comment: "leaving stale
                            # counters ... would let it immediately re-trigger from leftover state
                            # on its next cycle") only ever ran inside the alert-send branch --
                            # never when CL-AFPE genuinely suppressed a HIGH/CRITICAL decision as a
                            # false positive. RollingWindow.domains/domain_timestamps/dns_qtypes
                            # (state.py) are unbounded Counters/deques (unlike events/long_events,
                            # which self-prune via deque maxlen) -- with no reset, a device whose
                            # HIGH/CRITICAL verdicts keep getting correctly suppressed accumulates
                            # them indefinitely, staling the dns_behavior features computed from
                            # them for as long as suppression continues. Deliberately scoped to
                            # `telegram_worthy` (HIGH/CRITICAL) only, not SUSPICIOUS and not the
                            # `incident_notify.should_notify==False` withheld-repeat case just above
                            # -- both of those are still analytically ongoing (persistence-escalation
                            # depends on the SAME primary_sig recurring across cycles, which itself
                            # depends on state.rolling continuing to accumulate), so resetting there
                            # would erase state an active incident still needs. Only a suppressed
                            # HIGH/CRITICAL cycle -- CL-AFPE positively concluding this specific
                            # story is a false positive -- gets its window cleared.
                            self.zeek_fx.reset_client(known_ips_snapshot)
                            state.rolling.reset()

                        if not fp_verdict["suppress"] and telegram_worthy and incident_notify.should_notify:

                                # Extract Application / Process Name & Scanned Ports
                                app_name = self.zeek_fx.get_app_context(client_ip) if self.zeek_fx else "Network Socket"
                                scanned_ports = self.zeek_fx.get_scanned_ports(client_ip) if self.zeek_fx else []
                                # BUGFIX (dead-code audit): get_http_reqs() (host+URI pairs from
                                # this device's real HTTP traffic, tracked in _process_http() the
                                # whole time) was never read by anything -- only its sibling
                                # _http_uas (User-Agent strings, via get_app_context() above) ever
                                # reached an alert. Capped at 5 so a chatty device doesn't blow up
                                # the message.
                                recent_http_reqs = sorted(self.zeek_fx.get_http_reqs(client_ip))[:5] if self.zeek_fx else []

                                # Filter DNS sequence to show only threat-contributing / suspicious queries
                                threat_dns_lines = []
                                # BUGFIX (2026-08-27, third-party review): a known-vendor/telemetry
                                # domain that happened to get Pi-hole-blocked (e.g. an ad/tracker
                                # blocklist entry for teams.events.data.microsoft.com or
                                # wpad.fritz.box) previously fell through into threat_dns_lines with a
                                # 🔴 tag under a header literally called "Threat-Filtered DNS
                                # Sequence" -- reading as if it were relevant to the threat, when a
                                # domain being on an ad/tracker blocklist says nothing about THIS
                                # alert. Routed to its own section instead of either omitting it
                                # entirely or presenting it as threat evidence.
                                benign_blocked_lines = []
                                omitted_count = 0
                                if hasattr(state, "rolling") and hasattr(state.rolling, "events"):
                                    for ev_ts, ev_dom, ev_status in list(state.rolling.events)[-25:]:
                                        # Omit harmless background noise and known safe domains
                                        safe_domains = set(self.config.get("safe_domains", []))
                                        is_trusted = (
                                            is_telemetry_domain(ev_dom) or 
                                            (ev_dom in safe_domains) or 
                                            (self.ti_engine and self.ti_engine.is_allowlisted(ev_dom))
                                        )
                                        if is_trusted and ev_status not in BLOCKED_STATUSES:
                                            omitted_count += 1
                                            continue

                                        status_tag = "🔴 BLOCKED" if ev_status in BLOCKED_STATUSES else "🟡 NXDOMAIN" if ev_status in NXDOMAIN_STATUSES else "🟢 ALLOWED"
                                        line = f"  {time.strftime('%H:%M:%S', time.localtime(ev_ts))} | {status_tag} | {ev_dom}"
                                        if is_trusted and ev_status in BLOCKED_STATUSES:
                                            benign_blocked_lines.append(line)
                                        else:
                                            threat_dns_lines.append(line)

                                threat_dns_str = "\n".join(threat_dns_lines[:10]) if threat_dns_lines else "  No suspicious DNS queries detected"
                                if omitted_count > 0:
                                    threat_dns_header = f"🕒 *Threat-Filtered DNS Sequence (Omitted {omitted_count} harmless queries):*"
                                else:
                                    threat_dns_header = "🕒 *Threat-Filtered DNS Sequence:*"
                                benign_blocked_str = "\n".join(benign_blocked_lines[:10]) if benign_blocked_lines else ""

                                # calibrated_confidence is None whenever no reliable calibration is
                                # loaded (train_fp_classifier.py hasn't run with enough held-out data
                                # yet) -- _build_confidence_line() below appends an explicit
                                # "(uncalibrated estimate)" caveat in that case rather than silently
                                # implying precision that isn't there.
                                fp_pct = int(fp_verdict.get("confidence", 0.0) * 100)
                                fp_calibrated = fp_verdict.get("calibrated_confidence")
                                fp_calibrated_pct = int(fp_calibrated * 100) if fp_calibrated is not None else None

                                # PHASE 21-ALERT-REDESIGN: this whole block only runs inside
                                # `if not fp_verdict["suppress"] and telegram_worthy:` (Phase A's
                                # gate), so decision_state_for_rec here is ALWAYS HIGH or CRITICAL
                                # -- the old 4-branch badge below this comment used to also handle
                                # SUSPICIOUS/low-confidence cases that literally cannot reach this
                                # code anymore since that gate landed. Two real cases remain: CL-AFPE
                                # leans benign (>=0.75) despite the corroborated evidence still
                                # reaching HIGH/CRITICAL -- genuinely worth flagging as tension, not
                                # papering over -- or the normal case, where N independent evidence
                                # groups corroborated before containment authorized. See
                                # get_device_suppress_threshold()/mitigate() for why the SAME
                                # decision_state -- not fp_verdict alone -- is what actually
                                # authorizes containment (PHASE 15's original point, preserved here).
                                decision_state_for_rec = decision.get("state", DecisionState.SUSPICIOUS)
                                severity_badge = "🔴 CRITICAL" if decision_state_for_rec == DecisionState.CRITICAL else "🟠 HIGH"

                                # PHASE 8 FIX (still true): decision["explanation"] (== primary_sig) is
                                # what actually decided the state, not the hypothesis engine's raw best
                                # guess (which falls back to a generic label whenever no attack
                                # hypothesis's own evidence matched) -- keeping this the single source
                                # for the headline name prevents the alert from naming two different
                                # "causes" in two different places.
                                threat_name = decision.get("explanation", primary_sig)
                                threat_conf_pct = int(decision.get('threat_confidence', 0) * 100)

                                # PHASE 6: clear counters for every known address of this device — leaving
                                # stale counters on the non-current address family would let it immediately
                                # re-trigger from leftover state on its next cycle.
                                self.zeek_fx.reset_client(known_ips_snapshot)
                                state.rolling.reset()
                                state.last_alert_time = now

                                # One entry per INDEPENDENT evidence group (the strongest signal in
                                # each), not one per raw evidence item -- this is also the exact
                                # corroboration count the decision engine itself required to reach
                                # HIGH/CRITICAL, so citing len(grouped_evidence) in the recommendation
                                # below is the real number that authorized containment, not a guess.
                                # BUGFIX (2026-08-27, third-party review): this used to bucket EVERY
                                # independence_group present, including "local_context" (e.g.
                                # LOCAL_DEVICE_DISCOVERY) -- which evidence.py's own
                                # ATTACK_EVIDENCE_FAMILIES registry already explicitly excludes from
                                # ever counting toward an attack verdict's corroboration. The WHY
                                # block was showing it side-by-side with genuinely decisive evidence
                                # as if it carried equal weight, and len(grouped_evidence) (the
                                # "N independent signal(s)" count) was inflated by evidence that
                                # structurally cannot have authorized the verdict. Split into
                                # decisive (counts toward the verdict) vs. context (shown for
                                # completeness, never decisive) -- same distinction the decision
                                # engine itself already enforces, just finally reflected in the alert.
                                grouped_evidence = {}
                                context_evidence = {}
                                for ev in active_evidence:
                                    bucket = context_evidence if ev.independence_group == "local_context" else grouped_evidence
                                    if ev.independence_group not in bucket or ev.value > bucket[ev.independence_group].value:
                                        bucket[ev.independence_group] = ev
                                # BUGFIX (live audit, 2026-09-09, real production alerts --
                                # confirmed via a live PEER_COHORT_DEVIATION HIGH alert whose
                                # PERSISTED hee_evidence_families/hee_independent_sources were
                                # already correct [4/4, this session's own evidence_families
                                # fix] but whose ACTUAL SENT TELEGRAM TEXT still showed only 1
                                # -- sometimes 0 -- families): active_evidence is a SHORT-TTL
                                # (~600s, EvidenceStore.get_for_device()) local snapshot, but
                                # independence_families/num_independent_sources (decision/
                                # engine.py) draws on v13's graph-window query, up to 86400s/
                                # 24h (live_engine.py's _query_graph_window()). Corroborating
                                # evidence older than ~10 minutes is still genuinely valid for
                                # THIS decision but has already aged out of active_evidence --
                                # no amount of fixing THIS loop's active_evidence handling can
                                # surface evidence active_evidence never had. An EARLIER version
                                # of this fix only bridged decision["winning_evidence"]
                                # (correct for destination attribution, but scoped to just the
                                # WINNING hypothesis's own RELEVANT_EVIDENCE_TYPES -- e.g. only
                                # `peer_deviation` for PEER_COHORT_DEVIATION, missing the OTHER
                                # 3 real corroborating families that actually justified HIGH).
                                # decision["attack_evidence"] (decision/engine.py, this same
                                # pass) is the fix: the FULL post-domain-stripping set
                                # independent_sources itself counts against, not just the
                                # winning hypothesis's own slice -- bridged into synthetic v1
                                # Evidence objects so _describe_evidence() and the grouping/
                                # sorting logic below need no special-casing, same pattern as
                                # before, just fed from the complete list instead of a narrow
                                # one. Naturally de-duplicates against active_evidence's own
                                # real items via the SAME "keep the higher .value per family"
                                # rule the loop above already uses -- a family present in both
                                # just keeps whichever value is higher, never double-counted
                                # (grouped_evidence is keyed by family, one entry each).
                                for we in decision.get("attack_evidence", []):
                                    fam = we.get("independence_family") or _V13_SYNTHETIC_EVIDENCE_FAMILY.get(we.get("evidence_type"))
                                    if not fam:
                                        continue
                                    dest = we.get("destination_id")
                                    synth_ev = Evidence(
                                        type=we["evidence_type"], source="v13_live_engine", timestamp=now,
                                        device=dev_id, value=float(we.get("value") or 1.0),
                                        confidence=float(we.get("confidence") or 1.0),
                                        independence_group=fam,
                                        # BUGFIX (live audit, 2026-09-09): provenance was never
                                        # carried through this bridge -- see decision/engine.py's
                                        # matching full_attack_evidence fix for the full incident.
                                        # Needed for _describe_evidence()'s zeek_notice note-type/
                                        # tier suffix to work when a notice reaches the WHY-block
                                        # through THIS bridge rather than active_evidence directly.
                                        provenance=we.get("provenance") or "",
                                        domain=dest if dest and dest != "(none)" else None,
                                    )
                                    # BUGFIX (same pass): peer_cohort_deviation is in v13's
                                    # own NON_ATTACK_FAMILIES (hypotheses/independence.py,
                                    # "too cheap/unvalidated to count as one of the two
                                    # independent SOURCES the whole HIGH bar rests on" --
                                    # third-party review, same reasoning already applied to
                                    # local_context above) -- decision["evidence_families"]
                                    # (this same session's own fix, just above) correctly
                                    # never includes it (attack_evidence is already filtered
                                    # to exclude NON_ATTACK_FAMILIES, decision/engine.py).
                                    # Routing it into grouped_evidence here would inflate
                                    # fam_count PAST hee_independent_sources, creating a NEW
                                    # families-vs-sources mismatch in the opposite direction
                                    # from the one this whole fix exists to close.
                                    # context_evidence (shown, never counted) is the correct
                                    # bucket, same as local_context. In practice this branch
                                    # is now dead code (attack_evidence never contains a
                                    # NON_ATTACK_FAMILIES member), kept as an explicit
                                    # defense-in-depth guard rather than trusting that
                                    # invariant silently.
                                    bucket = context_evidence if fam == "peer_cohort_deviation" else grouped_evidence
                                    if fam not in bucket or synth_ev.value > bucket[fam].value:
                                        bucket[fam] = synth_ev
                                why_lines = [_describe_evidence(ev, self.geoip_engine) for ev in
                                             sorted(grouped_evidence.values(), key=lambda e: e.value, reverse=True)]
                                # VERSION 12: family labels, aligned to why_lines by construction --
                                # both sort the SAME dict by the SAME key function (stable sort, ties
                                # preserve dict insertion order identically in both), so
                                # zip(why_families, why_lines) below pairs each label with its own
                                # description. Kept as a second pass (not folded into why_lines
                                # itself) so the existing `why_lines = [_describe_evidence(ev,
                                # self.geoip_engine) for ev in ...]` line -- what
                                # tests/test_phase20_alert_quality.py and
                                # tests/test_phase28_alert_redesign.py both check for verbatim
                                # (updated 2026-09-09 for the geoip_engine param) -- stays intact.
                                why_families = [fam for fam, ev in
                                                 sorted(grouped_evidence.items(), key=lambda kv: kv[1].value, reverse=True)]
                                context_lines = [_describe_evidence(ev, self.geoip_engine) for ev in
                                                  sorted(context_evidence.values(), key=lambda e: e.value, reverse=True)]
                                active_evidence.clear()

                                # BUGFIX: found via a live alert audit -- alert_target_domain never got a
                                # DNS_EVASION branch the way DNS_COVERT_TUNNELING/DGA_BOTNET_C2 do above,
                                # so it stayed as the generic target_malicious_domain fallback (a
                                # coincidentally-queried domain, no causal link) for that signature --
                                # DNS_EVASION structurally has no domain by design, so alert_target_domain
                                # is NEVER meaningfully correct for it. alert_dest_ip (computed just above,
                                # already correctly attributed to the flagged unexplained IP) was sitting
                                # right there unused for display. Confirmed live: a DNS_EVASION alert's
                                # "Contacted" line showed a domain like "device-metrics-us.amazon.com" the
                                # device happened to also query, while the real evidence -- and the actual
                                # IP that got immunized on a correction -- was a completely different IP
                                # buried in the WHY section. The non-DNS_EVASION fallback also now uses
                                # alert_dest_ip instead of the raw dest_ip, for the same reason
                                # alert_dest_ip exists at all: it's the one already-corrected IP variable.
                                target_display = (
                                    alert_dest_ip if primary_sig_base in ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS") and alert_dest_ip and alert_dest_ip != "unknown"
                                    else alert_target_domain if alert_target_domain and alert_target_domain != "unknown"
                                    else (alert_dest_ip if alert_dest_ip and alert_dest_ip != "unknown" else "unknown")
                                )

                                # BUGFIX: found via a live alert audit -- this only recognized "BLOCKED"
                                # and "WAITING FOR APPROVAL" as substrings of containment_status, but
                                # ips.py's get_containment_status() can also return "🔒 TARPITTED
                                # (Layer-2 ARP/NDP)" or "🔒 ROUTER ISOLATED (Fritz!Box WAN)" -- neither
                                # contains the literal word "BLOCKED", so a genuinely tarpitted device
                                # (Layer 2 fires on risk>=9.0 OR lateral movement, independent of the
                                # decision engine's own HIGH-vs-CRITICAL state) had its headline read
                                # "monitoring only" directly above an "Action taken: TARPITTED" line a
                                # few lines further down in the SAME message -- confirmed live on a
                                # real example_pc_fritz_box alert. Same bug class as the 8.0
                                # "WAITING FOR APPROVAL contradiction" fix; this is the other half of
                                # the SAME containment_status value that fix never got extended to.
                                # SECOND BUGFIX, caught by this fix's own regression test: a bare
                                # "BLOCKED" substring check also matches "UNBLOCKED" (get_containment_
                                # status()'s genuine not-blocked-at-all case, "🔓 ACTIVE / UNBLOCKED
                                # (Monitoring Only)") -- "BLOCKED" IS a substring of "UNBLOCKED", so a
                                # fully clean device was mislabeled "auto-blocked" in the headline,
                                # pre-existing and unrelated to the tarpit gap above. Checking for the
                                # specific "DOMAIN BLOCKED" badge text instead of the bare word fixes
                                # both directions at once. Order matters here (most-severe-first) since
                                # a device could theoretically match more than one badge in a future
                                # containment_status format change.
                                action_summary = ("tarpitted (Layer-2)" if "TARPITTED" in containment_status
                                                   else "router isolated" if "ROUTER ISOLATED" in containment_status
                                                   else "auto-blocked" if "DOMAIN BLOCKED" in containment_status
                                                   else "awaiting approval" if "WAITING FOR APPROVAL" in containment_status
                                                   else "monitoring only")

                                # See _build_confidence_line/_build_status_lines module docstrings:
                                # these replace the old two-raw-percentages CONFIDENCE block and the
                                # separately-worded severity_badge/action_summary/recommendation trio
                                # with one reconciled verdict and one status block that says what
                                # already happened, what's expected of the operator, and what happens
                                # if they do nothing -- computed once here instead of left for the
                                # reader to piece together from three different lines.
                                confidence_label, confidence_line, mixed_signal = _build_confidence_line(
                                    threat_conf_pct, fp_verdict, fp_pct, fp_calibrated_pct
                                )
                                status_emoji, status_done, status_move, status_if_idle = _build_status_lines(
                                    action_summary, mixed_signal
                                )

                                alert_msg = (
                                    f"🚨 *THREAT — {hostname}* ({client_ip})\n\n"
                                    f"{severity_badge}  *{threat_name}*\n\n"
                                    f"{status_emoji} *Already done:* {status_done}\n"
                                    f"👉 *Your move:* {status_move}\n"
                                    f"⏱ *If you do nothing:* {status_if_idle}\n"
                                )
                                # VERSION 10 (incident aggregation): occurrence_count > 1 means
                                # this Telegram send is a periodic "still ongoing" update or a
                                # severity escalation for an incident already notified once --
                                # say so explicitly, since without this an operator who already
                                # saw the first alert has no way to tell "still the same thing"
                                # apart from "something new just started".
                                if incident_notify.occurrence_count > 1:
                                    incident_age_min = incident_notify.incident_age_seconds / 60.0
                                    update_kind = "escalated" if incident_notify.is_escalation else "still ongoing"
                                    alert_msg += (
                                        f"🔁 _Incident update — {update_kind}: {incident_notify.occurrence_count} "
                                        f"occurrences over {incident_age_min:.0f}m_\n"
                                    )
                                # BUGFIX (2026-08-27, explicit request): a raw destination IP told
                                # the operator nothing about what it actually was -- a WireGuard
                                # connection to 106.201.214.127 read as an unexplained anomaly until
                                # manually looked up and found to be Bharti Airtel (India mobile
                                # carrier), immediately reframing the whole alert. GeoIP ASN/city
                                # lookups are local mmdb reads (lookup_asn is @lru_cache'd in
                                # geoip.py) -- cheap enough to do on every alert, unlike the rate-
                                # limited AbuseIPDB/VT calls elsewhere in this file. Only applies
                                # when target_display is a raw IP; a domain already carries its own
                                # meaning and isn't touched.
                                target_geo_note = ""
                                try:
                                    ipaddress.ip_address(target_display)
                                    is_ip_target_display = True
                                except ValueError:
                                    is_ip_target_display = False
                                if is_ip_target_display and self.geoip_engine:
                                    asn_res = self.geoip_engine.lookup_asn(target_display)
                                    city_res = self.geoip_engine.lookup(target_display)
                                    geo_org = getattr(asn_res, "autonomous_system_organization", None) if asn_res else None
                                    geo_country = getattr(getattr(city_res, "country", None), "name", None) if city_res else None
                                    geo_parts = [p for p in (geo_org, geo_country) if p]
                                    if geo_parts:
                                        target_geo_note = f" _({', '.join(geo_parts)})_"

                                alert_msg += (
                                    f"\n━━━━━━━━━━━━━━━━━━━━\n"
                                    f"📍 *WHAT HAPPENED* _(facts)_\n"
                                )
                                # BUGFIX (live audit, 2026-09-09): PEER_COHORT_DEVIATION's
                                # evidence is device-level by design (destination_id=
                                # NO_DESTINATION, live_engine.py's
                                # _inject_peer_deviation_evidence() -- "distinct
                                # destination count" is a behavioral statistic about the
                                # device, not any single connection), so target_display
                                # was always "unknown" for this signature and "Contacted
                                # `unknown` (... / Port ...)" told the operator literally
                                # nothing about what actually triggered the alert. The
                                # real numbers (my_count/peer_avg/peer_count/device_type)
                                # already exist on the evidence's own .features
                                # (winning_evidence, decision/engine.py) -- show those
                                # instead of a fabricated "Contacted" line.
                                peer_stat_shown = False
                                if primary_sig_base == "PEER_COHORT_DEVIATION":
                                    for we in decision.get("winning_evidence", []):
                                        if we.get("evidence_type") != "peer_deviation":
                                            continue
                                        pf = we.get("features") or {}
                                        if "my_count" in pf and "peer_avg" in pf:
                                            alert_msg += (
                                                f"- Talked to `{pf['my_count']}` distinct destinations recently "
                                                f"vs. a `{pf.get('device_type', 'peer')}` cohort average of "
                                                f"`{pf['peer_avg']}` (across {pf.get('peer_count', '?')} peer(s))\n"
                                            )
                                            peer_stat_shown = True
                                        break
                                if not peer_stat_shown:
                                    alert_msg += f"- Contacted `{target_display}`{target_geo_note} ({service_name} / Port {dest_port})\n"
                                # BUGFIX (live alert audit): get_app_context()'s generic fallback
                                # (no HTTP User-Agent seen) is literally f"{proto} Port {port}" --
                                # e.g. "Application: TCP Port 55443" directly under "Contacted ...
                                # Port 55443" -- restating the exact same port with zero added
                                # information, confirmed live on several alerts. Only show the line
                                # when it says something the Contacted line doesn't already.
                                if app_name and not app_name.endswith(f"Port {dest_port}"):
                                    alert_msg += f"- Application: `{app_name}`\n"
                                if scanned_ports:
                                    # BUGFIX (reviewer suggestion, implemented): this used to show
                                    # only the port list ("445 (SMB)"), reading like a confirmed
                                    # multi-target scan regardless of whether it was one connection
                                    # or many -- confirmed live: a single-connection alert displayed
                                    # identically to a genuine scan. Now shows the distinct-target
                                    # count and raw connection count alongside the ports, the same
                                    # numbers that now actually gate containment (see
                                    # zeek_lateral_unique_targets).
                                    lateral_targets_display = int(features.get("zeek_lateral_unique_targets", 0) or 0)
                                    lateral_conns_display = int(features.get("zeek_lateral_moves", 0) or 0)
                                    # BUGFIX (2026-08-27, third-party review): counts were already shown
                                    # (the fix above this comment), but the label itself still said
                                    # "Lateral Scans" even when zeek_lateral_unique_targets was below the
                                    # SAME threshold (lateral_movement_unique_targets_threshold) that
                                    # gates whether this evidence is even allowed to exist / authorize
                                    # containment (see fp_engine.py Stage-1 Check 2 and this file's own
                                    # lateral_threat gate) -- a single SMB/SSH/RDP connection to one
                                    # internal device (e.g. browsing a NAS share) isn't a scan, and
                                    # calling it one here contradicted the decision the system actually
                                    # made. One shared threshold for display and containment now, so
                                    # they can't disagree.
                                    lateral_scan_threshold = int(self.config.get("lateral_movement_unique_targets_threshold", 2))
                                    if lateral_targets_display >= lateral_scan_threshold:
                                        alert_msg += (
                                            f"- Lateral Scans: `{', '.join(scanned_ports)}` "
                                            f"({lateral_conns_display} connection(s) across {lateral_targets_display} distinct target(s))\n"
                                        )
                                    else:
                                        alert_msg += (
                                            f"- Connection: `{', '.join(scanned_ports)}` "
                                            f"({lateral_conns_display} connection(s), {lateral_targets_display} target(s) -- below lateral-scan threshold)\n"
                                        )
                                if recent_http_reqs:
                                    alert_msg += f"- Recent HTTP requests: `{', '.join(recent_http_reqs)}`\n"
                                # BUGFIX (live alert audit): state.killchain_history is a
                                # per-cycle rolling window -- it appends the current phase EVERY
                                # cycle, not just on a transition (see dns_features.py's own
                                # comment on this) -- so "not all NORMAL" let a device that's
                                # simply been sitting in the SAME phase for 5 straight cycles
                                # through, and joining 5 identical entries with " -> " arrows
                                # visually implies movement that never happened. Confirmed live:
                                # "SUSPECTED_RECON -> SUSPECTED_RECON -> SUSPECTED_RECON ->
                                # SUSPECTED_RECON -> SUSPECTED_RECON" on a device that hadn't
                                # actually progressed anywhere. Collapsing consecutive repeats
                                # turns the raw per-cycle log into a genuine transition sequence
                                # -- only shown when that sequence actually has more than one
                                # distinct phase in it.
                                killchain_transitions = [
                                    p for i, p in enumerate(_killchain_hist)
                                    if i == 0 or p != _killchain_hist[i - 1]
                                ]
                                if len(killchain_transitions) > 1:
                                    alert_msg += f"- Kill-chain trajectory: `{' → '.join(killchain_transitions)}`\n"
                                alert_msg += f"- Action taken: `{containment_status}`\n"

                                # VERSION 12: "family" not "signal" -- len(grouped_evidence) was
                                # always a family count (one entry per independence_group, see the
                                # BUGFIX comment above this block), the word was just wrong. Each
                                # entry now names its family explicitly (✓ *Family* / └─ description),
                                # matching evidence.py's own EVIDENCE_FAMILIES vocabulary -- the
                                # concrete "3 DNS features != 3 independent signals" distinction this
                                # whole HEE review exists to make legible, now reflected here too, not
                                # just in ollama_soc.py's report (Phase 50).
                                fam_count = len(grouped_evidence)
                                alert_msg += (
                                    f"\n🧠 *WHY* _({fam_count} independent evidence famil"
                                    f"{'y' if fam_count == 1 else 'ies'}, strongest first)_\n"
                                )
                                for fam, line in zip(why_families, why_lines):
                                    fam_label = _EVIDENCE_FAMILY_LABELS.get(fam, fam.replace("_", " ").title())
                                    alert_msg += f"✓ *{fam_label}*\n   └─ {line}\n"

                                if context_lines:
                                    alert_msg += "\n📎 *Also observed* _(context -- did not independently trigger this)_\n"
                                    for line in context_lines:
                                        alert_msg += f"- {line}\n"

                                alert_msg += (
                                    f"\n━━━━━━━━━━━━━━━━━━━━\n"
                                    f"📊 *CONFIDENCE:* {confidence_line}\n"
                                )

                                has_threat_dns = bool(threat_dns_str) and "No suspicious" not in threat_dns_str
                                if has_threat_dns or benign_blocked_str:
                                    alert_msg += (
                                        f"\n━━━━━━━━━━━━━━━━━━━━\n"
                                        f"🔧 *Technical detail* _(optional)_\n"
                                    )
                                    if has_threat_dns:
                                        alert_msg += f"{threat_dns_header}\n{threat_dns_str}\n"
                                    if benign_blocked_str:
                                        alert_msg += (
                                            f"\n🔕 *Blocked by ad/tracker policy* "
                                            f"_(known vendor domain, not threat-related)_\n{benign_blocked_str}\n"
                                        )


                                reply_markup = None
                                inline_keyboard = []
                                # PHASE 10 FIX (extended — live-alert audit): the old condition
                                # here (risk>=8.5 or lateral_threat) was computed completely
                                # independently of containment_status/action_summary, so it could
                                # (and did, confirmed live) attach an "Approve Hardware Isolation"
                                # button to a device that was ALREADY tarpitted/router-isolated
                                # from an earlier incident — misleading regardless of what the
                                # "Already done" text said. Buttons now key off action_summary,
                                # the SAME authoritative value the status-text lines above already
                                # use: already contained -> Release only (nothing left to
                                # approve); genuinely pending -> Approve only; nothing queued
                                # ("monitoring only") -> no hardware buttons at all, matching that
                                # text exactly.
                                # BUGFIX (2026-08-29, user catch): "awaiting approval" used to also
                                # get a "Release Device" button alongside Approve -- but
                                # action_summary=="awaiting approval" is ITSELF derived from
                                # containment_status containing "WAITING FOR APPROVAL" specifically
                                # in the branch where none of TARPITTED/ROUTER ISOLATED/DOMAIN
                                # BLOCKED matched (see action_summary's own assignment above) --
                                # i.e. this state, by construction, always means "not currently
                                # contained." Release's callback (unblock:{client_ip}) always calls
                                # the same hardware-release IPC either way, so it was guaranteed to
                                # no-op here every single time ("nothing to release" was itself
                                # confirmed correct, just confusingly worded -- see the alerts.py
                                # message-text fix). This is the same "only show a button when it
                                # would actually do something" principle the fix above this comment
                                # already established for the other two states -- the third state
                                # just never got the same treatment.
                                #
                                # BUGFIX (2026-09-01, button/description audit): Release was wrongly
                                # wrapped in the SAME `interactive_blocking_enabled` gate as Approve.
                                # That flag controls whether a NEW containment action needs approval
                                # before it happens (ips.py: "Interactive HITL Mode" vs "Autonomous
                                # Auto-Block") -- it says nothing about whether an ALREADY-contained
                                # device can be released. With the flag False (the config's own
                                # default when unset), the mitigator still autonomously
                                # tarpits/isolates/blocks devices -- but the Release button for
                                # exactly those alerts was being suppressed by this same gate, even
                                # though _build_status_lines' text for those three states explicitly
                                # says "tap Release". Release now shows purely off containment state,
                                # matching the text unconditionally. Approve keeps no separate gate
                                # either -- it doesn't need one: action_summary=="awaiting approval"
                                # can only ever be set when interactive_blocking_enabled is True in
                                # the first place (see the containment_status rewrite above,
                                # ~line 1841), so gating it a second time here was always redundant.
                                if action_summary in ("tarpitted (Layer-2)", "router isolated", "auto-blocked"):
                                    inline_keyboard.append([
                                        {"text": "🔓 Release Device", "callback_data": f"unblock:{client_ip}"}
                                    ])
                                elif action_summary == "awaiting approval":
                                    inline_keyboard.append([
                                        {"text": "🔒 Approve Hardware Isolation", "callback_data": f"block:{client_ip}"}
                                    ])

                                # PHASE 6 (operator-driven self-healing, closed loop): record a
                                # "published_alert" action-ledger entry for EVERY published alert,
                                # not just autonomous actions, carrying the full alert_payload in
                                # `extra` so a later "Mark False Positive" tap can retrieve it without
                                # re-deriving features. Deliberately NOT gated on
                                # interactive_blocking_enabled — marking a false positive is operator
                                # feedback for the FP-reduction training loop, not a hardware
                                # containment decision, so it should be available whether or not
                                # hardware isolation buttons are enabled.
                                if target_display and target_display != "unknown":
                                    publish_action_id = uuid.uuid4().hex[:10]
                                    feedback_ttl = float(self.config.get("fp_operator_feedback_ttl_seconds", 30 * 86400.0))
                                    self.state_manager.record_action(
                                        action_id=publish_action_id, action_type="published_alert",
                                        target=target_display, device_id=dev_id, hostname=hostname,
                                        ttl_seconds=feedback_ttl, extra={"alert_payload": alert_payload},
                                    )
                                    inline_keyboard.append([
                                        {"text": "🛡️ Mark False Positive", "callback_data": f"immunize:{publish_action_id}"}
                                    ])

                                if inline_keyboard:
                                    reply_markup = {"inline_keyboard": inline_keyboard}

                                self.alert_manager.send(alert_msg, raw_payload=alert_payload, reply_markup=reply_markup)

                        # BUGFIX: this elif was previously mis-indented to attach to the OUTER
                        # `if decision["state"] in (...)` (16-indent) instead of the inner
                        # `if not fp_verdict["suppress"] and telegram_worthy:` above it (24-indent)
                        # it was actually meant to pair with. At 16-indent it only ran when
                        # decision["state"] was NOT in (HIGH, CRITICAL, SUSPICIOUS) at all -- i.e.
                        # almost every cycle for almost every device -- a branch where fp_verdict
                        # is never computed, crashing every _step() call in production with
                        # UnboundLocalError. Attaching it here means it correctly fires only when
                        # we're actually inside the elevated-decision-state branch, fp_verdict was
                        # computed, CL-AFPE didn't suppress it, but the decision wasn't
                        # telegram_worthy (SUSPICIOUS, not HIGH/CRITICAL) -- exactly what the log
                        # message below describes.
                        elif not fp_verdict["suppress"]:
                            LOGGER.info(
                                "Alert for %s held below Telegram threshold (state=%s, risk=%.2f) — "
                                "logged to alerts.json and CL-AFPE, not sent to Telegram.",
                                hostname, containment_decision_state, risk
                            )

                elif getattr(state, "last_alert_confidence", 0.0) >= alert_threshold and risk <= (alert_threshold - 1.0):
                    LOGGER.debug("Device %s risk subsided below threshold.", hostname)
                    state.last_alert_confidence = 0.0

                # Hardware IPS containment is handled exclusively inside the alert gate above
                # (lines ~404-414), which is already gated on risk >= alert_threshold.
                # Calling mitigate() unconditionally here for every device every 2s cycle was
                # generating 30+ unnecessary Pi-hole API lookups per minute at 30 devices.

                rate_mean, _, _, _ = state.rate_baseline.get_stats(current_hour)
                threshold_limit = rate_mean + (float(self.config.get("threshold_std_dev", 3.0)) * math.sqrt(max(state.rate_baseline.var[current_hour], 1e-4)))

                self.metrics_exporter.export_device_telemetry(
                    state=state, features=features, risk_score=risk, ml_score=ml_score, ti_risk=ti_risk,
                    ti_match=ti_match, abuse_risk=abuse_risk, vt_risk=vt_risk, is_safe=is_safe,
                    is_poisoned=is_poisoned, current_threshold_limit=threshold_limit, decision=decision,
                    fp_engine=self.fp_engine,
                )

                for dst_ip, dst_port in self.zeek_fx.pop_new_lateral_events(client_ip):
                    self.metrics_exporter.record_lateral_target(dev_id, hostname, client_ip, dst_ip, dst_port)
                    
            # --- END DEVICE EVALUATION LOOP ---

        self.zeek_fx.prune(now, window_seconds)
        
        self.metrics_exporter.export_pipeline_health(
            zeek_online=self.zeek_collector.available, zeek_events_count=len(zeek_events),
            collector_lag=max(0.0, time.time() - now), events_processed=len(dns_rows),
            alert_queue_size=self.alert_manager.q.qsize(), ml_model_loaded=self.ml_registry.global_warmed_up if self.ml_registry else False
        )
        # Real-time Prometheus gauge cleanup for Grafana dashboard sync
        self.metrics_exporter.garbage_collect_ips_metrics(self.state_manager.get_ips_state())
        # PHASE 18: syncs autotune/Ollama/job-health gauges from the small JSON files
        # those separate cron processes write -- cheap every cycle, each file is only
        # actually re-parsed when its own mtime changes (see sync_relay_metrics()).
        self.metrics_exporter.sync_relay_metrics(str(self.state_dir))
        
        if now - self._last_prune > 3600.0:
            pruned_list = self.state_manager.prune_stale_devices(now)
            for e_dev_id, e_hostname, e_dev_type in pruned_list:
                self.metrics_exporter.remove_device_metric_labels(e_dev_id, e_hostname, e_dev_type)
                if hasattr(self, 'evidence_store'): self.evidence_store.clear_device(e_dev_id)
                # BUGFIX (device-identity fragmentation audit): device_fp_profiles.json had
                # NO cleanup on ordinary eviction either -- a pruned device's learned FP
                # calibration stayed in that file forever with nothing to remove it. Closes
                # the same gap the merge path's discard_device_profile() closes, here for
                # the age-out eviction path instead of the retroactive-merge path.
                if hasattr(self, 'fp_engine') and self.fp_engine: self.fp_engine.discard_device_profile(e_dev_id, reason="prune")
            self.state_manager.prune_expired_actions(now)  # PHASE 3: drop expired revoke-ledger entries
            self._last_prune = now

        # IPC Split-Brain Reconciliation: detect if the Uvicorn IPC endpoints wrote
        # a sentinel file after modifying state from the separate process. If so, pull
        # the updated IPS state (tarpit_targets, router_isolated_devices, blocked_domains) back into live memory
        # before the periodic flush so the latest operator action is not overwritten.
        _sentinel = self.state_manager.state_path.parent / ".ipc_sync_signal"
        if _sentinel.exists():
            try:
                _sentinel.unlink()
                self.state_manager.reconcile_ips_from_disk()
                if self.ips_mitigator:
                    # Sync the live IPSMitigator's in-memory tarpit/router dicts from the reconciled state
                    ips_state = self.state_manager.get_ips_state()
                    with self.ips_mitigator._lock:
                        self.ips_mitigator._tarpit_active_targets = ips_state.get("tarpit_targets", {})
                        self.ips_mitigator._router_isolated_devices = ips_state.get("router_isolated_devices", {})
                        self.ips_mitigator._operator_released_devices = ips_state.get("operator_released_devices", {})
                    LOGGER.info("✅ [IPC SYNC] IPSMitigator in-memory state reconciled after Telegram release.")
            except Exception as _ipc_exc:
                LOGGER.warning("IPC sentinel reconciliation failed: %s", _ipc_exc)

        if now - self._last_flush > 60.0:
            LOGGER.debug("Triggering periodic state/model flush to disk.")
            self.state_manager.flush_to_disk()
            if self.ml_registry: self.ml_registry.save_models()
            self._last_flush = now

        LOGGER.debug("Pipeline step finished.")


    def stop(self) -> None:
        LOGGER.info("Stopping Engine Pipeline...")
        self.running = False
        if hasattr(self, "state_manager"): self.state_manager.flush_to_disk()
        if hasattr(self, "ml_registry") and self.ml_registry: self.ml_registry.save_models()
        if hasattr(self, "alert_manager"): self.alert_manager.stop()

    def _select_target_domain(self, state, ti_engine) -> str:
        """
        Selects the primary target domain for alert reporting and FP evaluation.
        Prioritizes:
        1. ThreatIntel IOC match
        2. Suspicious / High-Entropy / Non-Allowlisted domain in current window
        3. Fallback: Most frequent domain (top_domain)
        """
        if not hasattr(state, "rolling") or not hasattr(state.rolling, "domains") or not state.rolling.domains:
            return "unknown"

        # BUGFIX (live audit, 2026-09-09): state.rolling.domains's keys are not always
        # real DNS names -- a raw destination IP lands here as a fallback "domain" when
        # there's no PTR/DNS name for it, and a multicast/broadcast LAN protocol address
        # (SSDP 239.255.255.250 chief among them) can be by far the most FREQUENT such
        # key on a real home network, since group discovery traffic is chatty. None of
        # the 3 priority tiers below filtered these out, so a multicast address could
        # become top_domain -> reputation_target (pipeline.py's own "which destination
        # actually earned this risk score" attribution, a few hundred lines below this
        # function) with nothing structurally preventing it -- confirmed live: 239.
        # 255.255.250 had accumulated 782 "reputation" evidence rows on .94's graph,
        # continuously, over 2.5 days, directly feeding PEER_COHORT_DEVIATION's WHY-block
        # ("Destination has a poor external reputation score -- 239.255.255.250" on a
        # real alert). is_local_or_multicast_destination() already exists and is used
        # pervasively elsewhere for exactly this filtering; it safely passes real domain
        # names through unaffected (only parses as an IP, never matches a hostname).
        domains_dict = {
            dom: cnt for dom, cnt in state.rolling.domains.items()
            if not is_local_or_multicast_destination(dom)
        }
        if not domains_dict:
            return "unknown"

        # Priority 1: ThreatIntel IOC match
        if ti_engine:
            best_ti_domain = None
            max_ti_score = 0.0
            for dom in domains_dict.keys():
                res = ti_engine.lookup_domain(dom)
                if res:
                    score = float(res.get("confidence", 0.8))
                    if score > max_ti_score:
                        max_ti_score = score
                        best_ti_domain = dom
            if best_ti_domain:
                return best_ti_domain

        # Priority 2: Highest-risk non-allowlisted suspicious domain
        best_susp_domain = None
        max_susp_score = 0.0


        for dom in domains_dict.keys():
            if not dom or dom == "unknown":
                continue
            if is_telemetry_domain(dom) or (ti_engine and ti_engine.is_allowlisted(dom)):
                continue

            first_label = dom.split(".")[0] if dom else ""
            label_len = len(first_label)
            ent = compute_entropy(first_label)

            score = 0.0
            if label_len > 30:
                score += (label_len - 30) * 0.25
            if ent > 3.2:
                score += (ent - 3.2) * 2.0
            if not _is_cdn_or_cloud_domain(dom):
                score += 1.0

            if score > max_susp_score:
                max_susp_score = score
                best_susp_domain = dom

        if best_susp_domain and max_susp_score >= 1.0:
            return best_susp_domain

        # Priority 3: Fallback to most frequent domain
        return max(domains_dict, key=domains_dict.get, default="unknown")