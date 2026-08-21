"""
dns_evasion.py - Blind-spot audit (Phase 21C2).

Every other detector in this codebase reasons over DNS-query SHAPE (entropy, rate,
subdomain fanout, tunneling signatures) or over Zeek connection-level features for
devices Zeek actually has flow visibility into. Neither approach can see the specific
gap this module targets: a device that is genuinely active on the network -- real
captured connections, real bytes -- with little or no DNS query history explaining
where that traffic went. That's exactly the "already-infected device avoiding DNS
queries" scenario, and it is structurally invisible to DNS-only detection by
definition, regardless of how good the DNS-shape detectors get.

A reactive Fritzbox capture burst (Phase C) is what makes this checkable at all: it
gives a rare window of REAL destination-IP ground truth for a WiFi device, not just
what it claims to have looked up via DNS. This module's audit_burst()/audit_device()
compare that ground truth against the device's own recent DNS history and flag what's
left unexplained.

False-positive guard, directly modeled on a real case found this session: a legitimate
VPN app (NordVPN, on an iPhone) produces exactly this signature -- real traffic, no
matching DNS history for the tunnel endpoint itself -- with zero malicious intent.
Without recognizing known VPN infrastructure, this detector would flag every VPN user
on the network. See utils.is_vpn_provider_org() for how that's handled (ASN
organization-name matching, not a brittle IP/CIDR list).

Deliberately evidence-based, not a Stage-1 hard-stop (see fp_engine.py): finding an
unexplained connection proves a detection GAP existed, not that the device is
compromised. It needs to reach the same 2-independent-source bar as every other
hypothesis before it can influence containment or a Telegram alert -- see
DNSEvasionHypothesis in hypotheses/engine.py and Phase A's Telegram-gating change.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set

from utils import etld1, _is_cdn_or_cloud_domain, is_vpn_provider_org
from intelligence.hypotheses.evidence import Evidence


@dataclass
class DeviceBurstAudit:
    """Ground-truth input for one device's blind-spot audit.

    dest_ips: real destinations the device actually talked to during the capture
        burst (e.g. from ZeekFeatureExtractor.get_dest_ips() after Phase C's
        capture_and_ingest() reprocesses a burst).
    queried_domains: distinct domains the device resolved via Pi-hole in the same
        window (e.g. from DeviceState.rolling.domain_timestamps, filtered to the
        burst's [window_start, window_end]). Assembling/filtering this is the
        caller's job -- kept out of this module so it stays testable without a full
        StateManager.
    """
    dest_ips: Set[str] = field(default_factory=set)
    queried_domains: Set[str] = field(default_factory=set)


def _reverse_dns_explains(ip: str, queried_domains: Set[str], geoip_engine) -> bool:
    """True if this IP's reverse-DNS hostname shares an eTLD+1 base domain with
    something the device actually queried, or is itself known CDN/cloud
    infrastructure. Deliberately a base-domain match, not a domain->IP forward-resolve
    comparison -- CDNs commonly rotate/load-balance across many IPs for one domain, so
    an exact IP-set comparison would false-positive on completely ordinary CDN
    traffic."""
    if not geoip_engine:
        return False
    host = geoip_engine.reverse_dns(ip)
    if not host:
        return False
    if _is_cdn_or_cloud_domain(host):
        return True
    host_base = etld1(host)
    if not host_base:
        return False
    queried_bases = {etld1(d) for d in queried_domains}
    return host_base in queried_bases


def _vpn_explains(ip: str, geoip_engine) -> bool:
    """True if this IP's GeoIP ASN organization matches a recognized commercial VPN
    provider (see utils.is_vpn_provider_org's docstring for why this is name-based,
    not a CIDR list)."""
    if not geoip_engine:
        return False
    asn = geoip_engine.lookup_asn(ip)
    if not asn:
        return False
    return is_vpn_provider_org(asn.autonomous_system_organization or "")


def audit_device(device_id: str, audit: DeviceBurstAudit, geoip_engine=None,
                  ti_engine=None) -> List[Evidence]:
    """Audits one device's burst data for real connections its own DNS history can't
    explain. Returns zero or one Evidence -- one dns_evasion_anomaly summarizing the
    whole device's gap, not one per unexplained IP (a dozen near-identical evidence
    entries aren't more informative than one with the right numbers in its note)."""
    if not audit.dest_ips:
        return []

    unexplained: List[str] = []
    reputation_hits: List[str] = []

    for ip in audit.dest_ips:
        if _reverse_dns_explains(ip, audit.queried_domains, geoip_engine):
            continue
        if _vpn_explains(ip, geoip_engine):
            continue
        unexplained.append(ip)
        if ti_engine is not None:
            try:
                if ti_engine.lookup_ip(ip):
                    reputation_hits.append(ip)
            except Exception:
                pass

    if not unexplained:
        return []

    total = len(audit.dest_ips)
    unexplained_ratio = len(unexplained) / total
    has_reputation_hit = bool(reputation_hits)
    # A device with mostly-normal DNS history and a couple of stray unexplained
    # connections is a much weaker signal than one with real traffic and essentially
    # NO DNS footprint at all to explain any of it -- scale confidence accordingly
    # rather than treating "1 unexplained IP" the same regardless of context.
    no_dns_at_all = not audit.queried_domains
    confidence = min(1.0, 0.3
                      + 0.4 * unexplained_ratio
                      + (0.2 if no_dns_at_all else 0.0)
                      + (0.3 if has_reputation_hit else 0.0))

    note = (f"{len(unexplained)}/{total} real connection(s) from this device's captured "
            f"burst traffic have no matching DNS query history and don't resolve to "
            f"known CDN/VPN infrastructure")
    if reputation_hits:
        note += f"; {len(reputation_hits)} already carry threat-intel reputation data"
    if no_dns_at_all:
        note += " (device has NO DNS history at all in this window)"

    # One representative unexplained IP, so downstream alert-building
    # (pipeline.py's DNS_EVASION-signature branch) can put the ACTUAL flagged
    # destination in network_context.destination_ip instead of falling back to
    # whatever this device's most recent unrelated connection happened to be --
    # otherwise an operator/LLM correction on this alert could immunize the wrong
    # IP entirely. Prefer a reputation-hit IP when one exists (the most actionable
    # one, worth surfacing specifically); otherwise pick deterministically (sorted)
    # so the same audit input always yields the same evidence. When there's more
    # than one unexplained IP, this still only carries ONE forward -- a real
    # narrowing, not a complete list; a persisting alert on the same device after a
    # correction is expected if multiple distinct unexplained IPs are involved.
    representative_ip = sorted(reputation_hits)[0] if reputation_hits else sorted(unexplained)[0]

    return [Evidence(
        type="dns_evasion_anomaly",
        source="dns_evasion",
        timestamp=0.0,  # audit_burst() overwrites this with the real capture timestamp
        device=device_id,
        value=float(len(unexplained)),
        confidence=confidence,
        independence_group="blindspot_audit",
        provenance="detector:dns_evasion",
        domain=representative_ip,
    )]


def audit_burst(devices: Dict[str, DeviceBurstAudit], capture_ts: float,
                 geoip_engine=None, ti_engine=None) -> Dict[str, List[Evidence]]:
    """Runs audit_device() for every device present in a completed capture burst --
    the actual point of a burst covering the whole radio, not a side effect: a burst
    triggered by one device's suspicion still gets every OTHER device present in it
    audited for its own, independent blind-spot gap, for free. Returns
    {device_id: [Evidence]} for only the devices that produced a real finding."""
    out: Dict[str, List[Evidence]] = {}
    for device_id, audit in devices.items():
        evidence = audit_device(device_id, audit, geoip_engine=geoip_engine, ti_engine=ti_engine)
        if not evidence:
            continue
        for e in evidence:
            e.timestamp = capture_ts
        out[device_id] = evidence
    return out
