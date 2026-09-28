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
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from utils import etld1, _is_cdn_or_cloud_domain, is_vpn_provider_org, is_cloud_cdn_provider_org, KNOWN_PUBLIC_DNS_RESOLVERS
from intelligence.hypotheses.evidence import Evidence
from metrics import dns_evasion_reverse_dns_timeout_outcomes_total

# P1 FIX (third-party review, 2026-09-28): a reverse-DNS timeout used to be counted
# (as "inconclusive") and the IP was then simply dropped -- gone, with no trace,
# forever, even though "timed out under load" says nothing about whether the
# connection is actually innocuous. This in-process dict is the retry queue: ip ->
# consecutive timeout count. Deliberately keyed by ip alone, shared across every
# device's audit -- reverse-DNS/ASN status is a property of the destination IP
# itself, not of which device asked, so a timeout recorded auditing one device's
# burst correctly counts toward the SAME ip's retry budget in another device's
# burst too. No separate retry scheduler needed: dest_ips already comes from real,
# ongoing connections, so an IP a device is still actually talking to naturally
# reappears in its next capture burst and gets re-checked fresh then, same shape as
# every other reactive-capture-driven re-evaluation in this module.  Cleared on a
# conclusive answer (explained either way); after _MAX_REVERIFICATION_ATTEMPTS
# consecutive timeouts with no conclusive answer, the ip is escalated into real
# unexplained evidence instead of being silently dropped forever -- same
# "attempts, then commit to an outcome" shape as mitigation/ips.py's own
# _retry_queue/_dead_letter, at in-process scale (a module-lifetime dict, not a new
# persisted file -- no new state file for what's fundamentally ephemeral, same as
# live_engine.py's own _last_risk_score).
_PENDING_REVERIFICATION: Dict[str, int] = {}
_MAX_REVERIFICATION_ATTEMPTS = 3


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
    dest_ports: VERSION 11 (P1, review #3/#4 follow-up) -- {dest_ip: last-seen
        destination port}, from ZeekFeatureExtractor.get_dest_ports(). Optional
        (defaults empty) -- an IP absent here just means "port unknown," not an
        error; audit_device() only uses this to distinguish a direct UDP/53 (or
        DoT/853) bypass from a generic unexplained connection, never as a required
        input.
    doh_bypass_ips: destination IPs whose TLS SNI matched a known DoH provider
        hostname (DOH_SNIS in zeek_features.py), from
        ZeekFeatureExtractor.get_doh_bypass_ips() -- real SNI-verified DoH, not a
        port+IP heuristic (that approach was tried and reverted, see
        audit_device()'s own note on the KNOWN_PUBLIC_DNS_RESOLVERS:443 attempt).
        Optional (defaults empty).
    """
    dest_ips: Set[str] = field(default_factory=set)
    queried_domains: Set[str] = field(default_factory=set)
    dest_ports: Dict[str, int] = field(default_factory=dict)
    doh_bypass_ips: Set[str] = field(default_factory=set)


def _is_private_lan_ip(ip: str) -> bool:
    """True for any RFC1918/link-local/loopback/multicast address -- i.e. traffic that
    never needed DNS to begin with, because it never left the local network.

    BUGFIX (production false-positive): the only two "explained" checks below
    (reverse-DNS-matches-a-query, VPN-ASN-match) are both structurally incapable of
    ever passing for a private IP -- a home LAN has no public PTR record for
    192.168.x.x, and a private address has no public ASN to match against a VPN
    provider. That meant ANY intra-LAN connection (a device talking to the IDS
    server itself, to a NAS, to another local device -- none of which need or use
    DNS to find each other) was guaranteed to be flagged as "unexplained," no matter
    how legitimate. Confirmed in production: a device repeatedly flagged for
    connecting to 192.168.1.94 -- the IDS server's own LAN IP -- re-firing
    DNS_EVASION roughly every minute for 15+ minutes straight. This detector's whole
    premise is real INTERNET traffic bypassing DNS to avoid detection; intra-LAN
    traffic was never DNS-bound in the first place, so it isn't evidence of anything."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# BUGFIX (production false-positive, found via a live audit): a device's own DNS QUERY
# traffic to a well-known public resolver (e.g. a Chromecast querying 8.8.8.8 directly
# instead of through Pi-hole) was guaranteed to be flagged as "unexplained" -- the
# connection itself IS how domain resolution happens, so by definition no domain lookup
# can ever explain it (a chicken-and-egg self-reference the other two "explained"
# checks structurally can't resolve: reverse-DNS of a resolver IP won't match anything
# the device queried, and a resolver operator is not a VPN provider). Deliberately a
# short, stable, name-brand list -- these IPs are as close to universally-recognized
# internet infrastructure as exists, unlike a general "trust this cloud provider" list
# that would create a real blind spot for C2 hosted on the same infrastructure.
# Moved to utils.py (KNOWN_PUBLIC_DNS_RESOLVERS) so fp_engine.py's confirmed-intel
# write/read guards can share the exact same list -- see that constant's docstring.
_KNOWN_PUBLIC_DNS_RESOLVERS = KNOWN_PUBLIC_DNS_RESOLVERS


def _is_known_dns_resolver(ip: str) -> bool:
    return ip in _KNOWN_PUBLIC_DNS_RESOLVERS


def _asn_explains(ip: str, geoip_engine) -> bool:
    """True if this IP's GeoIP ASN organization matches a recognized commercial VPN
    provider OR a major cloud/CDN operator (utils.is_vpn_provider_org() /
    is_cloud_cdn_provider_org() -- both name-based against MaxMind's ASN org field, not
    a CIDR list, so this refreshes automatically with MaxMind's own DB updates and
    needs no per-domain maintenance). A single local lookup_asn() call (now @lru_cache'd
    -- geoip.py) covers both checks. Deliberately checked BEFORE _reverse_dns_explains()
    below: this is a fast, reliable, purely local DB read with no timeout risk, so
    resolving it first means an IP it already explains never needs the slower,
    load-sensitive reverse-DNS network round-trip at all."""
    if not geoip_engine:
        return False
    asn = geoip_engine.lookup_asn(ip)
    if not asn:
        return False
    org = asn.autonomous_system_organization or ""
    return is_vpn_provider_org(org) or is_cloud_cdn_provider_org(org)


def _reverse_dns_explains(ip: str, queried_domains: Set[str], geoip_engine, ti_engine=None) -> Optional[bool]:
    """True if this IP's reverse-DNS hostname shares an eTLD+1 base domain with
    something the device actually queried, is itself known CDN/cloud infrastructure, or
    is allowlisted (ti_engine.is_allowlisted() -- live Tranco popularity feed + the
    persisted CL-AFPE self-healing trust cache, so a domain corrected once via "Mark
    False Positive" or the autonomous path stops needing a manual code patch here).
    Deliberately a base-domain match, not a domain->IP forward-resolve comparison --
    CDNs commonly rotate/load-balance across many IPs for one domain, so an exact
    IP-set comparison would false-positive on completely ordinary CDN traffic.

    BUGFIX (live audit, self-diagnosed in geoip.py's own prior comment but never
    fixed): returns None (not False) when the reverse-DNS lookup TIMED OUT under load,
    distinct from a lookup that cleanly confirmed there's no PTR record. A timeout is
    inconclusive, not evidence of anything -- the caller must not count it as
    "unexplained." Confirmed live: a reactive-capture burst's reverse-DNS sweep across
    every unexplained IP in one pass could saturate the lookup pool, and several
    genuinely-innocent devices got flagged purely from queueing behind each other,
    not from anything about their own traffic."""
    if not geoip_engine:
        return False
    host, timed_out = geoip_engine.reverse_dns_status(ip)
    if timed_out:
        return None
    if not host:
        return False
    if _is_cdn_or_cloud_domain(host):
        return True
    if ti_engine and ti_engine.is_allowlisted(host):
        return True
    host_base = etld1(host)
    if not host_base:
        return False
    queried_bases = {etld1(d) for d in queried_domains}
    return host_base in queried_bases


def audit_device(device_id: str, audit: DeviceBurstAudit, geoip_engine=None,
                  ti_engine=None, fp_engine=None) -> List[Evidence]:
    """Audits one device's burst data for real connections its own DNS history can't
    explain. Returns zero or one Evidence -- one dns_evasion_anomaly summarizing the
    whole device's gap, not one per unexplained IP (a dozen near-identical evidence
    entries aren't more informative than one with the right numbers in its note).

    fp_engine (VERSION 11, P1, review #9/#10): optional. When supplied, damps
    confidence by this device's own LEARNED familiarity with each unexplained IP's
    ASN owner (AutonomousFPEngine.get_baseline_familiarity(), fp_engine.py) -- an ASN
    this device has legitimately talked to many times before, without ever reaching
    CONFIRMED_THREAT, is real self-healing counter-evidence, continuous rather than a
    hard include/exclude list. Same spirit as the VPN/CDN exemptions above, just
    softer and per-device rather than global."""
    if not audit.dest_ips:
        return []

    unexplained: List[str] = []
    reputation_hits: List[str] = []
    familiarity_scores: List[float] = []
    # VERSION 11 (P1, review #3/#4 follow-up): a direct connection on port 53/853 to
    # an IP that isn't a recognized public resolver (_is_known_dns_resolver already
    # excludes the well-known ones, e.g. 8.8.8.8) is a materially more specific
    # finding than a generic unexplained connection -- it's not just "no DNS history
    # explains this," it's "this connection IS a DNS query, made directly instead of
    # through Pi-hole." Note: a LOCAL resolver bypass (LAN IP) is already excluded
    # entirely by _is_private_lan_ip() above, before ever reaching this loop -- so
    # by construction, anything landing here on port 53/853 is an external resolver.
    policy_bypass_ips: List[str] = []
    doh_bypass_hits: List[str] = []

    inconclusive_timeouts = 0
    exhausted_reverifications = 0
    for ip in audit.dest_ips:
        if _is_private_lan_ip(ip):
            continue
        # TRIED (P1, third-party audit, 2026-09-16) and REVERTED: a DoH analogue of
        # the port-53/853 policy-bypass check below, treating a port-443 connection
        # to a KNOWN_PUBLIC_DNS_RESOLVERS IP as evasion. Reverted after
        # test_phase23_fritzbox_capture.py's own "clean device" fixture (a
        # connection to 1.1.1.1:443 that reverse-DNS genuinely explains, via
        # _reverse_dns_explains() below) failed against it -- Cloudflare/Google
        # etc. are NOT single-purpose DNS infrastructure on port 443 the way they
        # are on 53/853; 1.1.1.1 alone fronts unrelated CDN/proxy traffic, so this
        # would have flagged ordinary HTTPS to those providers as "DNS policy
        # bypass" alongside genuine DoH.
        #
        # FIXED (2026-09-18): the port+IP heuristic above was the wrong signal, but
        # TLS SNI telemetry to actually distinguish a DoH handshake from ordinary
        # HTTPS to the same IP already existed -- just uncollected here.
        # zeek_features.py's _process_ssl() already reads the real TLS ClientHello
        # SNI and matches it against DOH_SNIS (genuine DoH-provider hostnames like
        # "dns.google"), exposed via get_doh_bypass_ips() -> DeviceBurstAudit.
        # doh_bypass_ips. An SNI match is proof of an actual DoH handshake, so it's
        # checked BEFORE (not after) _is_known_dns_resolver()/_asn_explains()/
        # _reverse_dns_explains() below and bypasses all three deliberately: those
        # exist to explain away an IP that MIGHT be innocuous (a device's own DNS
        # history covers it, or it belongs to a CDN/cloud ASN it legitimately talks
        # to for other reasons) -- irrelevant once SNI has already proven this
        # SPECIFIC connection was a DoH handshake. 1.1.1.1/8.8.8.8 etc. are both
        # "known resolvers" (would otherwise short-circuit below) AND the exact IPs
        # real DoH providers answer on, so gating this after those checks would
        # have silently exempted the primary real-world case.
        is_doh = ip in audit.doh_bypass_ips
        if not is_doh:
            if _is_known_dns_resolver(ip):
                continue
            # BUGFIX (live audit): _asn_explains() (fast, local, no timeout risk) now
            # runs BEFORE _reverse_dns_explains() (slow, network, timeout-prone under
            # load) -- any IP the ASN check already explains never pays the
            # reverse-DNS round-trip at all, directly shrinking exposure to the exact
            # load-driven timeout cascade geoip.py's own comment describes.
            if _asn_explains(ip, geoip_engine):
                continue
            explained = _reverse_dns_explains(ip, audit.queried_domains, geoip_engine, ti_engine)
            if explained is None:
                # Inconclusive (reverse-DNS timed out under load) -- not evidence of
                # anything on its own, so it must not be counted as "unexplained"
                # immediately. Unlike the old behavior, it's not dropped either:
                # queued in _PENDING_REVERIFICATION for a fresh check next time this
                # IP shows up in a burst, up to _MAX_REVERIFICATION_ATTEMPTS times.
                attempts = _PENDING_REVERIFICATION.get(ip, 0) + 1
                if attempts < _MAX_REVERIFICATION_ATTEMPTS:
                    _PENDING_REVERIFICATION[ip] = attempts
                    inconclusive_timeouts += 1
                    dns_evasion_reverse_dns_timeout_outcomes_total.labels(outcome="enqueued").inc()
                    continue
                # Retry budget exhausted: a timeout that keeps recurring across
                # multiple bursts is no longer distinguishable from "genuinely
                # can't be explained" -- it must not keep vanishing every cycle.
                # Falls through to the same unexplained-connection handling below
                # as any other unexplained IP (is_doh is always False here).
                _PENDING_REVERIFICATION.pop(ip, None)
                dns_evasion_reverse_dns_timeout_outcomes_total.labels(outcome="exhausted").inc()
                exhausted_reverifications += 1
            else:
                if _PENDING_REVERIFICATION.pop(ip, None) is not None:
                    # A later attempt got a conclusive answer for an IP that had
                    # previously timed out -- the retry mechanism doing its job.
                    dns_evasion_reverse_dns_timeout_outcomes_total.labels(outcome="resolved").inc()
                if explained:
                    continue
        unexplained.append(ip)
        if is_doh:
            policy_bypass_ips.append(ip)
            doh_bypass_hits.append(ip)
        elif audit.dest_ports.get(ip) in (53, 853):
            policy_bypass_ips.append(ip)
        if ti_engine is not None:
            try:
                if ti_engine.lookup_ip(ip):
                    reputation_hits.append(ip)
            except Exception:
                pass
        if fp_engine is not None:
            owner = None
            if geoip_engine:
                try:
                    asn = geoip_engine.lookup_asn(ip)
                    owner = asn.autonomous_system_organization if asn else None
                except Exception:
                    owner = None
            try:
                familiarity_scores.append(fp_engine.get_baseline_familiarity(device_id, asn_owner=owner))
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
    has_policy_bypass = bool(policy_bypass_ips)
    confidence = min(1.0, 0.3
                      + 0.4 * unexplained_ratio
                      + (0.2 if no_dns_at_all else 0.0)
                      + (0.3 if has_reputation_hit else 0.0)
                      # VERSION 11: a direct port-53/853 bypass is intentional-resolver-
                      # avoidance evidence, not just an attribution gap -- worth a
                      # confidence bump on its own, independent of no_dns_at_all/
                      # reputation (a device can have otherwise-normal DNS history AND
                      # still make one direct bypass connection).
                      + (0.2 if has_policy_bypass else 0.0))
    # VERSION 11: dampen by this device's own learned baseline familiarity with the
    # unexplained IPs' ASN owners (see fp_engine parameter docstring above).
    avg_familiarity = sum(familiarity_scores) / len(familiarity_scores) if familiarity_scores else 0.0
    confidence = max(0.0, confidence - 0.5 * avg_familiarity)

    note = (f"{len(unexplained)}/{total} real connection(s) from this device's captured "
            f"burst traffic have no matching DNS query history and don't resolve to "
            f"known CDN/VPN infrastructure")
    if reputation_hits:
        note += f"; {len(reputation_hits)} already carry threat-intel reputation data"
    if no_dns_at_all:
        note += " (device has NO DNS history at all in this window)"
    non_doh_policy_bypass = len(policy_bypass_ips) - len(doh_bypass_hits)
    if non_doh_policy_bypass:
        note += f"; {non_doh_policy_bypass} connection(s) are direct port-53/853 queries to a non-Pi-hole resolver"
    if doh_bypass_hits:
        note += f"; {len(doh_bypass_hits)} connection(s) are DNS-over-HTTPS to a known DoH provider (SNI-verified)"
    if inconclusive_timeouts:
        note += (f"; {inconclusive_timeouts} additional connection(s) queued for delayed "
                 f"re-verification -- reverse-DNS timed out under load, inconclusive rather "
                 f"than counted as unexplained this cycle")
    if exhausted_reverifications:
        note += (f"; {exhausted_reverifications} of the {len(unexplained)} counted above "
                 f"never got a conclusive reverse-DNS answer after {_MAX_REVERIFICATION_ATTEMPTS} "
                 f"attempts across separate bursts and were escalated to unexplained rather "
                 f"than dropped")

    # VERSION 11 (P1, review #3/#4): a stable subtag distinguishing WHY this is
    # unexplained, matching threat_signals.py's provenance subtag convention.
    # Precedence: a direct DNS-port bypass is the most specific, most actionable
    # finding (intentional resolver avoidance, not just an attribution gap) --
    # checked first even if the device also happens to have zero DNS history
    # otherwise. A device with genuinely zero DNS footprint at all is the next-
    # strongest finding ("this device isn't using DNS to look things up"); a device
    # that mostly has normal DNS history but has a handful of connections outliving
    # their DNS lookup's observation window (e.g. a long-lived MQTT/IoT session
    # resolved before this capture burst started) is the weakest, most ambiguous
    # case. Collapsing all three into the same "DNS_EVASION" name was flagged by a
    # third-party review as misleading for the weaker cases.
    # hypotheses/engine.py's DNSEvasionHypothesis reads this tag to name the
    # hypothesis accordingly; detection power/thresholds are unchanged either way.
    if has_policy_bypass:
        gap_subtag = "policy_bypass"
    elif no_dns_at_all:
        gap_subtag = "no_dns_history"
    else:
        gap_subtag = "partial_attribution_gap"

    # One representative unexplained IP, so downstream alert-building
    # (pipeline.py's DNS_EVASION-signature branch) can put the ACTUAL flagged
    # destination in network_context.destination_ip instead of falling back to
    # whatever this device's most recent unrelated connection happened to be --
    # otherwise an operator/LLM correction on this alert could immunize the wrong
    # IP entirely. Prefer a policy-bypass IP (the most specific finding), then a
    # reputation-hit IP, then pick deterministically (sorted) so the same audit
    # input always yields the same evidence. When there's more than one unexplained
    # IP, this still only carries ONE forward -- a real narrowing, not a complete
    # list; a persisting alert on the same device after a correction is expected if
    # multiple distinct unexplained IPs are involved.
    if policy_bypass_ips:
        representative_ip = sorted(policy_bypass_ips)[0]
    elif reputation_hits:
        representative_ip = sorted(reputation_hits)[0]
    else:
        representative_ip = sorted(unexplained)[0]

    return [Evidence(
        type="dns_evasion_anomaly",
        source="dns_evasion",
        timestamp=0.0,  # audit_burst() overwrites this with the real capture timestamp
        device=device_id,
        value=float(len(unexplained)),
        confidence=confidence,
        independence_group="blindspot_audit",
        provenance=f"detector:dns_evasion:{gap_subtag}:{note}",
        domain=representative_ip,
    )]


def audit_burst(devices: Dict[str, DeviceBurstAudit], capture_ts: float,
                 geoip_engine=None, ti_engine=None, fp_engine=None) -> Dict[str, List[Evidence]]:
    """Runs audit_device() for every device present in a completed capture burst --
    the actual point of a burst covering the whole radio, not a side effect: a burst
    triggered by one device's suspicion still gets every OTHER device present in it
    audited for its own, independent blind-spot gap, for free. Returns
    {device_id: [Evidence]} for only the devices that produced a real finding."""
    out: Dict[str, List[Evidence]] = {}
    for device_id, audit in devices.items():
        evidence = audit_device(device_id, audit, geoip_engine=geoip_engine, ti_engine=ti_engine, fp_engine=fp_engine)
        if not evidence:
            continue
        for e in evidence:
            e.timestamp = capture_ts
        out[device_id] = evidence
    return out
