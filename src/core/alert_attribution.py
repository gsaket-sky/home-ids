"""
What an alert is about: its destination address, its domain and, for scan-shaped findings, the set of hosts it
touched -- taken ONLY from the evidence that fired for the alert's signature (CLAUDE.md pre-flight 1).

History (2026-10-12, new_issues items 3/4 and the 7 wrong Pi-hole blocks): pipeline.py started every alert from two
window-wide guesses -- `_select_target_domain()`'s "most notable domain in the window" and `features["last_dest_ip"]`
(this device's most recent connection) -- and only some signatures overrode them. Every signature or evidence shape
without an override kept the guess: an internal ARP sweep "about" a website, a resolver or broadcast address as the
destination, and the guessed domain reaching containment and the confirmed-intel store. Here there is no guess: a
signature with no evidence-linked target says "unknown" (device-level), and the caller derives the destination port
and every downstream write from this result.

Network-agnostic: nothing here names a vendor, address or interface; values are routed by their shape (an address
parses as one, anything else is a name).
"""
import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional

from utils import ZEEK_NOTICE_EVIDENCE_TYPES

UNKNOWN = "unknown"

DNS_EVASION_NAMES = ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS")
REPUTATION_VERDICTS = (
    "Confirmed Malicious IOC",
    "Corroborated Reputation Signal",
    "Elevated Reputation Signal (Unconfirmed, Tier 5 Score)",
    "Elevated Reputation Signal (Unconfirmed)",
)
SCAN_NAMES = ("CONNECTION_ABUSE", "PORT_SCAN", "INTERNAL_RECONNAISSANCE")
INTRUSION_NAMES = ("NETWORK_INTRUSION", "LATERAL_MOVEMENT")

# signature -> the evidence types whose `domain` names what the alert is about (an address or a name).
_FROM_EVIDENCE = {
    **{n: ("dns_evasion_anomaly",) for n in DNS_EVASION_NAMES},
    "DNS_COVERT_TUNNELING": ("dns_tunnel_v2",),
    "DGA_BOTNET_C2": ("dns_dga_burst",),
    # dns_rate / dns_unique_ratio are device-wide aggregates; only dns_entropy names the domain that raised the average.
    "DNS_TUNNELING": ("dns_entropy",),
    "SIGNATURE_MATCHED_THREAT": ("suricata_signature_match",),
    "Confirmed Exploit/Malware Signature (Suricata)": ("suricata_signature_match",),
    "Confirmed Exploit/Malware Signature (Suricata, Uncorroborated)": ("suricata_signature_match",),
    "Layer-2 ARP Spoofing Detected": ("arp_spoofing",),
    "Internal Honeypot Accessed": ("honeypot_access",),
    "Geofencing Policy Violation": ("geofencing_violation",),
    "Geofencing Policy Violation (Uncorroborated)": ("geofencing_violation",),
}

# signature -> the argus-only evidence type (decision["winning_evidence"]) whose destination_id is the target. These
# types never reach pipeline.py's own evidence store (they are synthesized from graph queries or converted there).
_FROM_WINNING_EVIDENCE = {
    "COORDINATED_TARGETING": "coordinated_targeting",
    "DATA_EXFILTRATION": "zeek_exfiltration",
    "C2_BEACONING": "zeek_beaconing",
}

# Scan-shaped evidence: one finding touches a set of hosts. Order = preference when several fired (a rejected
# connection names a host the device really tried to reach; a swept address only one it asked about).
_SCAN_EVIDENCE = ("zeek_lateral_scan", "zeek_conn_abuse", "arp_sweep")
_SCAN_KIND = {"zeek_lateral_scan": "lateral_targets", "zeek_conn_abuse": "rejected_connections",
              "arp_sweep": "swept_hosts"}

# B2: how strongly each network evidence type points at "its" destination, used to pick the destination an
# intrusion alert shows when several flows contributed. Unlisted types rank 2.0 (same as a medium notice).
NETWORK_EVIDENCE_STRENGTH = {
    "zeek_lateral_scan": 4.0, "zeek_notice_highly_deterministic": 3.5, "malicious_ja3": 3.0,
    "malicious_ja4": 3.0, "zeek_notice_strong": 2.5, "zeek_notice_medium": 2.0, "zeek_notice": 2.0,
    "zeek_notice_weak": 1.0,
}
_INTRUSION_TYPES = frozenset({"zeek_lateral_scan", "malicious_ja3", "malicious_ja4", "zeek_notice"}) \
    | frozenset(ZEEK_NOTICE_EVIDENCE_TYPES)


@dataclass
class AlertTarget:
    dest_ip: str = UNKNOWN
    domain: str = UNKNOWN
    # {"kind": "swept_hosts" | "rejected_connections" | "lateral_targets", "count": int, "examples": [...]}
    target_set: Optional[dict] = None
    # the evidence type the target came from ("" = none: a device-level alert)
    source: str = ""
    examples: List[str] = field(default_factory=list)

    @property
    def evidence_linked(self) -> bool:
        return bool(self.source)


def _usable(value) -> bool:
    return bool(value) and str(value) not in (UNKNOWN, "(none)", "-")


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).split("%", 1)[0])
        return True
    except ValueError:
        return False


def _place(target: AlertTarget, value: str, source: str, wire_ip_of: Optional[Callable[[str], Optional[str]]]):
    """Routes `value` by its shape: an address is the destination; a name is the domain, and its destination is the
    address this device's own query for it got on the wire (when observed) -- never an unrelated connection."""
    value = str(value)
    target.source = source
    if _is_address(value):
        target.dest_ip = value
        return
    target.domain = value
    wire_ip = wire_ip_of(value) if wire_ip_of else None
    if _usable(wire_ip):
        target.dest_ip = str(wire_ip)


def _first_with_domain(evidence: Iterable, types) -> Optional[object]:
    for ev in evidence:
        if getattr(ev, "type", None) in types and _usable(getattr(ev, "domain", None)):
            return ev
    return None


def attribute_alert_target(signature_base: str, active_evidence: Iterable, winning_evidence: Iterable = (),
                           reputation_target: Optional[str] = None,
                           wire_ip_of: Optional[Callable[[str], Optional[str]]] = None) -> AlertTarget:
    """The alert's target for `signature_base` (the signature without its " (persisted Ns)" suffix).

    active_evidence: this cycle's detector evidence (intelligence.hypotheses.evidence.Evidence).
    winning_evidence: decision["winning_evidence"] (dicts with evidence_type / destination_id).
    reputation_target: the domain or address the reputation computation scored (reputation verdicts only).
    wire_ip_of: domain -> the address this device's own query for it resolved to, as observed (optional).
    """
    evidence = list(active_evidence or ())
    target = AlertTarget()

    if signature_base in _FROM_EVIDENCE:
        ev = _first_with_domain(evidence, _FROM_EVIDENCE[signature_base])
        if ev is not None:
            _place(target, ev.domain, ev.type, wire_ip_of)
    elif signature_base in REPUTATION_VERDICTS:
        if _usable(reputation_target):
            _place(target, reputation_target, "reputation", wire_ip_of)
    elif signature_base in _FROM_WINNING_EVIDENCE:
        wanted = _FROM_WINNING_EVIDENCE[signature_base]
        for we in winning_evidence or ():
            if we.get("evidence_type") == wanted and _usable(we.get("destination_id")):
                _place(target, we["destination_id"], wanted, wire_ip_of)
                break
    elif signature_base in SCAN_NAMES:
        _attribute_scan(target, evidence)
    elif signature_base in INTRUSION_NAMES:
        best_rank, best = None, None
        for ev in evidence:
            if getattr(ev, "type", None) not in _INTRUSION_TYPES or not _usable(getattr(ev, "domain", None)):
                continue
            rank = (NETWORK_EVIDENCE_STRENGTH.get(ev.type, 2.0), float(getattr(ev, "confidence", 0.0) or 0.0),
                    float(getattr(ev, "timestamp", 0.0) or 0.0))
            if best_rank is None or rank > best_rank:
                best_rank, best = rank, ev
        if best is not None and best.type == "zeek_lateral_scan":
            _attribute_scan(target, [best])
        elif best is not None:
            _place(target, best.domain, best.type, wire_ip_of)
    # Every other signature (PEER_COHORT_DEVIATION, "Threshold Exceeded", a new hypothesis without a rule here) is
    # device-level: no destination is named rather than a guessed one.
    return target


def _attribute_scan(target: AlertTarget, evidence: List) -> None:
    """A scan names its set: count + examples. The destination stays unknown unless the set has exactly one host --
    picking one member of a sweep as "the" destination is the guess this module exists to remove."""
    for etype in _SCAN_EVIDENCE:
        ev = next((e for e in evidence if getattr(e, "type", None) == etype), None)
        if ev is None:
            continue
        examples = [str(x) for x in (getattr(ev, "targets", ()) or ()) if _usable(x)]
        if not examples and _usable(getattr(ev, "domain", None)):
            examples = [str(ev.domain)]
        count = int(getattr(ev, "target_count", 0) or 0) or len(examples)
        if not count:
            continue
        target.source = etype
        target.examples = examples
        target.target_set = {"kind": _SCAN_KIND[etype], "count": count, "examples": examples}
        if count == 1 and examples and _is_address(examples[0]):
            target.dest_ip = examples[0]
        return


def describe_target_set(target_set: Optional[dict]) -> str:
    """'12 hosts (e.g. a, b, c)' for display; '' when there is no set."""
    if not target_set or not target_set.get("count"):
        return ""
    count = int(target_set["count"])
    examples = list(target_set.get("examples") or ())[:3]
    text = f"{count} host{'s' if count != 1 else ''}"
    return f"{text} (e.g. {', '.join(examples)})" if examples else text
