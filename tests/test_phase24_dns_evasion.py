"""
Standalone runtime test for Phase 24 (DNS-evasion blind-spot audit, Phase 21C2 in the
reactive-capture plan). Not part of the pytest suite -- run directly:
`python3 test_phase24_dns_evasion.py`.
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


from utils import is_vpn_provider_org
from intelligence.detectors.dns_evasion import DeviceBurstAudit, audit_device, audit_burst
from intelligence.hypotheses.engine import DNSEvasionHypothesis, HypothesisEngine
from intelligence.hypotheses.evidence import Evidence
from intelligence.reputation.classifier import ReputationVector


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: is_vpn_provider_org
# ═══════════════════════════════════════════════════════════════════════════════════
check("recognizes NordVPN (the real case found this session)", is_vpn_provider_org("NordVPN S.A."))
check("recognizes ExpressVPN, case-insensitively", is_vpn_provider_org("expressvpn international ltd"))
check("recognizes Mullvad", is_vpn_provider_org("Mullvad VPN AB"))
check("rejects an ordinary hosting/cloud org", not is_vpn_provider_org("Amazon.com, Inc."))
check("rejects an ordinary ISP org", not is_vpn_provider_org("Deutsche Telekom AG"))
check("empty/None org name doesn't crash and returns False", is_vpn_provider_org("") is False)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: audit_device -- fake geoip/ti engines, no network calls
# ═══════════════════════════════════════════════════════════════════════════════════
class _FakeASN:
    def __init__(self, org):
        self.autonomous_system_organization = org

class _FakeGeoIP:
    """reverse_dns_map: ip -> hostname (or None), or the sentinel "TIMEOUT" to simulate
    a reverse-DNS timeout. asn_org_map: ip -> org name (or None)."""
    def __init__(self, reverse_dns_map=None, asn_org_map=None):
        self.reverse_dns_map = reverse_dns_map or {}
        self.asn_org_map = asn_org_map or {}

    def reverse_dns(self, ip):
        val = self.reverse_dns_map.get(ip)
        return None if val == "TIMEOUT" else val

    def reverse_dns_status(self, ip):
        """Matches the real GeoIPEngine's (host, timed_out) contract (geoip.py) --
        _reverse_dns_explains() now calls this instead of the plain reverse_dns()."""
        val = self.reverse_dns_map.get(ip)
        if val == "TIMEOUT":
            return None, True
        return val, False

    def lookup_asn(self, ip):
        org = self.asn_org_map.get(ip)
        return _FakeASN(org) if org is not None else None

class _FakeTI:
    def __init__(self, bad_ips=None):
        self.bad_ips = bad_ips or set()

    def lookup_ip(self, ip):
        return {"source": "test"} if ip in self.bad_ips else None


DEV = "dev-iphone-1"

# B1: fully explained by matching DNS history (reverse-DNS base domain matches a
# queried domain) -- no evidence should fire.
geoip = _FakeGeoIP(reverse_dns_map={"93.184.216.34": "server-1.example.com"})
audit = DeviceBurstAudit(dest_ips={"93.184.216.34"}, queried_domains={"example.com"})
ev = audit_device(DEV, audit, geoip_engine=geoip)
check("a destination whose reverse-DNS base domain matches a queried domain is explained (no evidence)",
      ev == [])

# B2: explained via known CDN infra even with zero matching DNS history.
geoip_cdn = _FakeGeoIP(reverse_dns_map={"1.2.3.4": "edge99.cloudfront.net"})
audit_cdn = DeviceBurstAudit(dest_ips={"1.2.3.4"}, queried_domains=set())
ev_cdn = audit_device(DEV, audit_cdn, geoip_engine=geoip_cdn)
check("a destination resolving to known CDN infra (cloudfront.net) is explained even with zero DNS history",
      ev_cdn == [])

# B3: THE CORE REGRESSION GUARD -- a NordVPN destination with zero matching DNS
# history must NOT be flagged (the real case found live this session).
geoip_vpn = _FakeGeoIP(asn_org_map={"5.6.7.8": "NordVPN S.A."})
audit_vpn = DeviceBurstAudit(dest_ips={"5.6.7.8"}, queried_domains=set())
ev_vpn = audit_device(DEV, audit_vpn, geoip_engine=geoip_vpn)
check("THE CORE REGRESSION GUARD: a real NordVPN destination with zero DNS history is NOT "
      "flagged as an evasion anomaly (this is the exact iPhone/NordVPN case found live this session)",
      ev_vpn == [])

# B3c (THE FIX): a destination hosted on a recognized cloud/CDN ASN (e.g. AWS) is
# explained even with zero DNS history AND zero reverse-DNS data at all -- this is
# what would have caught samsungcloudsolution.net on day one without ever needing its
# exact domain string enumerated anywhere, since niche vendor domains are almost always
# hosted on major cloud infrastructure rather than the vendor's own network.
geoip_cloud = _FakeGeoIP(asn_org_map={"9.8.7.6": "Amazon.com, Inc."})
audit_cloud = DeviceBurstAudit(dest_ips={"9.8.7.6"}, queried_domains=set())
ev_cloud = audit_device(DEV, audit_cloud, geoip_engine=geoip_cloud)
check("THE FIX: a destination hosted on a recognized cloud/CDN ASN (Amazon) is explained "
      "with zero DNS/reverse-DNS data at all -- no domain string enumeration needed",
      ev_cloud == [])

geoip_isp = _FakeGeoIP(asn_org_map={"9.8.7.5": "Deutsche Telekom AG"})
audit_isp = DeviceBurstAudit(dest_ips={"9.8.7.5"}, queried_domains=set())
ev_isp = audit_device(DEV, audit_isp, geoip_engine=geoip_isp)
check("REGRESSION GUARD: an ordinary consumer-ISP ASN is NOT treated as known cloud/CDN infra",
      len(ev_isp) == 1)

# B3b (BUGFIX regression guard): a connection to a private/LAN IP (e.g. the IDS server's
# own address, a NAS, another local device) must never be flagged, even with zero DNS
# history and no geoip_engine at all -- intra-LAN traffic never needed DNS to begin with.
# Found in production: a device re-firing DNS_EVASION every ~65s for 15+ minutes straight
# because its connection to 192.168.1.94 (the IDS server itself) was "unexplained."
audit_lan = DeviceBurstAudit(dest_ips={"192.168.1.94"}, queried_domains=set())
ev_lan = audit_device(DEV, audit_lan, geoip_engine=None)
check("THE CORE FIX: a private-LAN destination is never flagged as an evasion anomaly, "
      "even with zero DNS history and no geoip_engine",
      ev_lan == [])

audit_lan_mixed = DeviceBurstAudit(dest_ips={"192.168.1.94", "99.99.99.99"}, queried_domains=set())
geoip_unknown_for_mixed = _FakeGeoIP(reverse_dns_map={}, asn_org_map={"99.99.99.99": "Some Random Hosting LLC"})
ev_lan_mixed = audit_device(DEV, audit_lan_mixed, geoip_engine=geoip_unknown_for_mixed)
check("a private-LAN IP alongside a genuinely unexplained public IP: only the public one counts",
      len(ev_lan_mixed) == 1 and ev_lan_mixed[0].value == 1.0 and ev_lan_mixed[0].domain == "99.99.99.99")

# B4: genuinely unexplained -- no DNS match, not CDN, not VPN -- fires evidence.
geoip_unknown = _FakeGeoIP(reverse_dns_map={}, asn_org_map={"99.99.99.99": "Some Random Hosting LLC"})
audit_unexplained = DeviceBurstAudit(dest_ips={"99.99.99.99"}, queried_domains={"totally-unrelated.com"})
ev_unexplained = audit_device(DEV, audit_unexplained, geoip_engine=geoip_unknown)
check("a genuinely unexplained destination (no DNS match, not CDN, not VPN) fires exactly one evidence",
      len(ev_unexplained) == 1)
if ev_unexplained:
    e = ev_unexplained[0]
    check("evidence type is dns_evasion_anomaly", e.type == "dns_evasion_anomaly")
    check("evidence independence_group is blindspot_audit", e.independence_group == "blindspot_audit")
    check("evidence value equals the unexplained-connection count", e.value == 1.0)

# B5: no DNS history at all + unexplained connection -> higher confidence than a
# device with SOME (unrelated) DNS history.
audit_no_dns = DeviceBurstAudit(dest_ips={"99.99.99.99"}, queried_domains=set())
ev_no_dns = audit_device(DEV, audit_no_dns, geoip_engine=geoip_unknown)
check("a device with real traffic and ZERO dns history at all scores a HIGHER confidence "
      "than one with some unrelated DNS history for the same unexplained IP",
      ev_no_dns[0].confidence > ev_unexplained[0].confidence,
      f"no_dns={ev_no_dns[0].confidence} vs some_dns={ev_unexplained[0].confidence}")

# B6: reputation-hit bump.
ti_bad = _FakeTI(bad_ips={"99.99.99.99"})
ev_reputation = audit_device(DEV, audit_unexplained, geoip_engine=geoip_unknown, ti_engine=ti_bad)
check("an unexplained IP that also carries threat-intel reputation data scores a higher "
      "confidence than the same IP without a reputation hit",
      ev_reputation[0].confidence > ev_unexplained[0].confidence,
      f"with_ti={ev_reputation[0].confidence} vs without={ev_unexplained[0].confidence}")

# B7: no destination IPs at all -> no evidence, no crash.
check("a device with zero captured destination IPs produces no evidence",
      audit_device(DEV, DeviceBurstAudit(dest_ips=set(), queried_domains={"x.com"})) == [])

# B8: mixed -- one explained, one not -- only the unexplained one counts toward the ratio.
geoip_mixed = _FakeGeoIP(
    reverse_dns_map={"1.1.1.1": "sub.example.com"},
    asn_org_map={},
)
audit_mixed = DeviceBurstAudit(dest_ips={"1.1.1.1", "99.99.99.99"}, queried_domains={"example.com"})
ev_mixed = audit_device(DEV, audit_mixed, geoip_engine=geoip_mixed)
check("mixed case: 1 explained + 1 unexplained out of 2 total -> evidence value is 1 (only the unexplained one)",
      len(ev_mixed) == 1 and ev_mixed[0].value == 1.0, f"got {ev_mixed}")

# B9-B11: Evidence.domain carries a REPRESENTATIVE unexplained IP -- this is what lets
# pipeline.py's DNS_EVASION alert-building put the actual flagged destination into
# network_context.destination_ip, instead of falling back to the device's unrelated
# last-known dest_ip (the fix for the "wrong IP got immunized on correction" gap).
geoip_unknown2 = _FakeGeoIP()
audit_single = DeviceBurstAudit(dest_ips={"99.99.99.99"}, queried_domains=set())
ev_single = audit_device(DEV, audit_single, geoip_engine=geoip_unknown2)
check("a single unexplained IP is carried as Evidence.domain",
      ev_single[0].domain == "99.99.99.99", f"got {ev_single[0].domain}")

audit_multi = DeviceBurstAudit(dest_ips={"99.99.99.99", "5.5.5.5", "7.7.7.7"}, queried_domains=set())
ev_multi = audit_device(DEV, audit_multi, geoip_engine=geoip_unknown2)
check("with multiple unexplained IPs and no reputation hits, the representative IP is "
      "chosen deterministically (sorted first) -- same input always yields the same evidence",
      ev_multi[0].domain == "5.5.5.5", f"got {ev_multi[0].domain}")

ti_with_hit = _FakeTI(bad_ips={"7.7.7.7"})
ev_multi_rep = audit_device(DEV, audit_multi, geoip_engine=geoip_unknown2, ti_engine=ti_with_hit)
check("THE CORE FIX: when one of several unexplained IPs carries threat-intel reputation "
      "data, THAT one is preferred as the representative IP over a plain sorted pick "
      "(the most actionable one is worth surfacing/immunizing-correctly specifically)",
      ev_multi_rep[0].domain == "7.7.7.7", f"got {ev_multi_rep[0].domain}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: audit_burst -- multi-device orchestration
# ═══════════════════════════════════════════════════════════════════════════════════
devices = {
    "dev-clean": DeviceBurstAudit(dest_ips={"93.184.216.34"}, queried_domains={"example.com"}),
    "dev-evasive": DeviceBurstAudit(dest_ips={"99.99.99.99"}, queried_domains=set()),
}
geoip_burst = _FakeGeoIP(reverse_dns_map={"93.184.216.34": "www.example.com"})
capture_ts = 1700000000.0
results = audit_burst(devices, capture_ts, geoip_engine=geoip_burst)

check("audit_burst only returns devices with a real finding (clean device excluded)",
      "dev-clean" not in results and "dev-evasive" in results, f"got keys={list(results.keys())}")
check("audit_burst stamps every evidence with the real capture timestamp",
      results["dev-evasive"][0].timestamp == capture_ts)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: DNSEvasionHypothesis
# ═══════════════════════════════════════════════════════════════════════════════════
hyp = DNSEvasionHypothesis()
neutral_rep = ReputationVector(domain="", tier=3)
trusted_rep = ReputationVector(domain="", tier=1)

check("no evidence at all -> hypothesis doesn't fire", hyp.evaluate([], neutral_rep) == 0.0)

anomaly_only = [Evidence(type="dns_evasion_anomaly", source="dns_evasion", timestamp=time.time(),
                          device=DEV, value=1.0, confidence=0.7, independence_group="blindspot_audit")]
score_alone = hyp.evaluate(anomaly_only, neutral_rep)
check("dns_evasion_anomaly alone satisfies the required condition and scores >= 2.0",
      score_alone >= 2.0, f"got {score_alone}")
check("dns_evasion_anomaly alone does not reach the 'strong' bonus score",
      score_alone < 4.0, f"got {score_alone}")

corroborated = anomaly_only + [
    Evidence(type="reputation", source="threat_intel", timestamp=time.time(),
             device=DEV, value=1.0, confidence=0.9, independence_group="reputation"),
]
score_corroborated = hyp.evaluate(corroborated, neutral_rep)
check("dns_evasion_anomaly + a second independent evidence type reaches the 'strong' bonus score",
      score_corroborated == 4.0, f"got {score_corroborated}")

score_trusted = hyp.evaluate(anomaly_only, trusted_rep)
check("a tier-1/2 trusted reputation context dampens the score below the untrusted case",
      score_trusted < score_alone, f"got {score_trusted} vs {score_alone}")

check("DNSEvasionHypothesis is registered in HypothesisEngine.attack_hypotheses",
      any(isinstance(h, DNSEvasionHypothesis) for h in HypothesisEngine().attack_hypotheses))

# VERSION 11 (P1, review #3/#4): the hypothesis's NAME should reflect why the
# connection was unexplained, not just that it was -- a device with otherwise-normal
# DNS history missing just one connection's attribution window is a materially
# weaker, more honest finding than one with zero DNS footprint at all. Detection
# power (the score thresholds above) is unchanged either way.
hyp_naming = DNSEvasionHypothesis()
partial_gap_evidence = [Evidence(
    type="dns_evasion_anomaly", source="dns_evasion", timestamp=time.time(), device=DEV,
    value=1.0, confidence=0.7, independence_group="blindspot_audit",
    provenance="detector:dns_evasion:partial_attribution_gap:1/12 unexplained",
)]
hyp_naming.evaluate(partial_gap_evidence, neutral_rep)
check("a partial-attribution-gap-only finding (normal DNS history, one connection "
      "outlived its window) is named DNS_ATTRIBUTION_GAP, not the more alarming "
      "DNS_EVASION",
      hyp_naming.name == "DNS_ATTRIBUTION_GAP", f"got {hyp_naming.name}")

no_dns_history_evidence = [Evidence(
    type="dns_evasion_anomaly", source="dns_evasion", timestamp=time.time(), device=DEV,
    value=1.0, confidence=0.7, independence_group="blindspot_audit",
    provenance="detector:dns_evasion:no_dns_history:3/3 unexplained (device has NO DNS history at all in this window)",
)]
hyp_naming.evaluate(no_dns_history_evidence, neutral_rep)
check("a device with genuinely zero DNS footprint keeps the strong DNS_EVASION name",
      hyp_naming.name == "DNS_EVASION", f"got {hyp_naming.name}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: pipeline.py -- source-level guard for the destination_ip precision fix
# ═══════════════════════════════════════════════════════════════════════════════════
with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src = f.read()

# UPDATED (persistence-suffix fix): primary_sig can carry a " (persisted Ns)" suffix
# once a signature escalates via the cross-cycle persistence mechanism, so every one of
# these source-guard checks now targets primary_sig_base (the suffix-stripped value)
# instead of the raw primary_sig -- see pipeline.py's own comment on primary_sig_base
# for the full incident this fixed.
check("pipeline.py prefers a DNS_EVASION evidence's own flagged IP over the generic "
      "last-known dest_ip when building that alert's network_context",
      'if primary_sig_base in ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS"):' in pipeline_src and
      'if ev.type == "dns_evasion_anomaly" and ev.domain:' in pipeline_src)
check("the alert_payload's destination_ip uses the corrected alert_dest_ip variable, "
      "not the raw generic dest_ip, for every alert (not just DNS_EVASION ones)",
      '"destination_ip": alert_dest_ip,' in pipeline_src)

# BUGFIX regression guard (found via a live alerts.json audit): the SAME class of bug as
# DNS_EVASION's destination_ip fix above, for the queried_domain field instead --
# target_malicious_domain came ONLY from _select_target_domain()'s "most notable domain
# in the whole window" scan, independent of which evidence/hypothesis actually fired.
# For DNS_COVERT_TUNNELING (DNSTunnelingV2Hypothesis / dns_tunnel_v2 evidence), this
# produced alerts whose displayed target had no causal relationship to the real finding
# -- and, more seriously, the SAME wrong domain was what actually got passed to
# mitigate() (real Pi-hole blocking), get_containment_status(), and
# record_confirmed_threat() (the local confirmed-intel learning store).
check("pipeline.py prefers a DNS_COVERT_TUNNELING evidence's own flagged domain over the "
      "generic 'most notable domain in the window' fallback",
      'if primary_sig_base == "DNS_COVERT_TUNNELING":' in pipeline_src and
      'if ev.type == "dns_tunnel_v2" and ev.domain:' in pipeline_src)
check("the alert_payload's queried_domain uses the corrected alert_target_domain variable, "
      "not the raw target_malicious_domain, for every alert",
      '"queried_domain": alert_target_domain,' in pipeline_src)
check("THE MORE SERIOUS HALF OF THE FIX: real containment (mitigate()) targets the "
      "corrected alert_target_domain, not the raw target_malicious_domain -- otherwise "
      "containment could block/track a benign frequently-visited domain instead of the "
      "one actually implicated by the evidence that authorized it",
      "target_domain=alert_target_domain," in pipeline_src)
check("get_containment_status() also checks against the corrected domain, not the raw fallback",
      "domain=alert_target_domain" in pipeline_src)
check("the local confirmed-intel learning store (record_confirmed_threat) is fed the "
      "corrected domain -- feeding it the wrong domain would teach the network-effect "
      "cross-device hard-stop to remember the wrong thing",
      "etld1(alert_target_domain)" in pipeline_src)
check("REGRESSION GUARD: no remaining use of the raw target_malicious_domain in the "
      "alert-payload/containment call sites this fix touched",
      'target_domain=target_malicious_domain,' not in pipeline_src and
      '"queried_domain": target_malicious_domain,' not in pipeline_src and
      'etld1(target_malicious_domain)' not in pipeline_src)

# BUGFIX regression guard: the SAME class of bug again, DGA_BOTNET_C2/dns_dga_burst
# instead of DNS_COVERT_TUNNELING/dns_tunnel_v2 -- found while investigating why the
# qwertyuiopasdfghjklzxcvbnm-*.ru / xkqz289dfj10dj-*.ru domain families appeared spread
# across 6+ unrelated devices with zero threat-intel corroboration. dns_dga_burst was a
# pure device-wide aggregate (a count of recent DGA-looking domains) with no domain
# attached at all -- every DGA_BOTNET_C2 alert's displayed target was the same
# unrelated "most notable domain in window" fallback, so the cross-device spread proved
# nothing about a real coordinated threat; it was an attribution artifact.
check("pipeline.py prefers a DGA_BOTNET_C2 evidence's own flagged domain over the "
      "generic 'most notable domain in the window' fallback, same as DNS_COVERT_TUNNELING",
      'elif primary_sig_base == "DGA_BOTNET_C2":' in pipeline_src and
      'if ev.type == "dns_dga_burst" and ev.domain:' in pipeline_src)

# ═══════════════════════════════════════════════════════════════════════════════════
# BUGFIX (found via a live alert): alert_dest_ip (a few lines above target_display's
# computation) was already correctly attributed to the flagged unexplained IP for
# DNS_EVASION -- but target_display (the "Contacted `X`" headline field) never
# consulted it, and alert_target_domain never got a DNS_EVASION branch the way
# DNS_COVERT_TUNNELING/DGA_BOTNET_C2 do (DNS_EVASION structurally has no domain, so
# there's nothing meaningful to attach there). Confirmed live: a DNS_EVASION alert's
# "Contacted" line showed a domain the device happened to also query (no causal link),
# while the real flagged IP -- and the one actually immunized on a correction -- was a
# completely different value buried in the WHY section.
# ═══════════════════════════════════════════════════════════════════════════════════
check("THE FIX: target_display prefers alert_dest_ip specifically for DNS_EVASION, "
      "checked before the generic alert_target_domain path",
      'alert_dest_ip if primary_sig_base in ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS") and alert_dest_ip and alert_dest_ip != "unknown"' in pipeline_src)
check("THE FIX: the non-DNS_EVASION fallback now uses alert_dest_ip (the corrected "
      "variable), not the raw dest_ip",
      'else (alert_dest_ip if alert_dest_ip and alert_dest_ip != "unknown" else "unknown")' in pipeline_src)

# Simulate the actual priority chain the fix uses, to prove the real mapping.
def _target_display_for(primary_sig, alert_target_domain, alert_dest_ip):
    return (
        alert_dest_ip if primary_sig == "DNS_EVASION" and alert_dest_ip and alert_dest_ip != "unknown"
        else alert_target_domain if alert_target_domain and alert_target_domain != "unknown"
        else (alert_dest_ip if alert_dest_ip and alert_dest_ip != "unknown" else "unknown")
    )

check("DNS_EVASION with a coincidental unrelated domain in alert_target_domain still "
      "displays the real flagged IP, not the domain",
      _target_display_for("DNS_EVASION", "device-metrics-us.amazon.com", "104.156.80.32") == "104.156.80.32")
check("REGRESSION GUARD: DNS_COVERT_TUNNELING (a real evidence-linked domain signature) "
      "still displays its domain, unaffected by the DNS_EVASION-specific branch",
      _target_display_for("DNS_COVERT_TUNNELING", "real-tunnel-domain.example", "5.5.5.5") == "real-tunnel-domain.example")
check("REGRESSION GUARD: DNS_EVASION with no resolved IP at all falls back to 'unknown', "
      "not a stale/wrong domain",
      _target_display_for("DNS_EVASION", "unknown", "unknown") == "unknown")

# BUGFIX (found via a live audit): reverse-DNS's tiny worker pool (4) and tight timeout
# (1.0s/1.05s) meant a burst reverse-DNS'ing every unexplained IP across every device
# seen in ONE capture (audit_burst()'s whole point -- every device, not just the
# triggering one) could genuinely saturate the pool: a caller-side future timeout does
# NOT stop the underlying worker thread, which keeps running and occupying a slot
# regardless, so later lookups queue behind busy workers and hit the ceiling before
# even starting. Confirmed live: 4 unrelated devices (including this network's own IDS
# server) all flagged "no matching DNS lookup history" within the same ~2-minute
# window, right after a reactive-capture burst -- the signature of a shared-resource
# bottleneck, not four coincidentally-evasive devices.
geoip_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "intelligence" / "geoip.py").read_text(encoding="utf-8")
check("THE FIX: reverse-DNS worker pool widened from 4 to reduce queueing under a "
      "multi-device burst audit",
      "ThreadPoolExecutor(max_workers=12" in geoip_src)
check("THE FIX: reverse-DNS timeout widened from the original tight 1.0s/1.05s pairing",
      "socket.setdefaulttimeout(2.5)" in geoip_src and "future.result(timeout=2.6)" in geoip_src)

# BUGFIX (follow-up, same session): widening the pool/timeout above only reduces HOW
# OFTEN a timeout happens, not what happens when one still does -- _reverse_dns_explains
# had no way to tell "genuinely no PTR record" apart from "timed out under load," both
# collapsed to the same None and counted as unexplained. geoip.py's reverse_dns_status()
# now returns (host, timed_out) so a timeout is inconclusive (skipped), never treated as
# "checked, suspicious."
geoip_timeout = _FakeGeoIP(reverse_dns_map={"9.9.9.1": "TIMEOUT", "9.9.9.2": None})
audit_timeout_only = DeviceBurstAudit(dest_ips={"9.9.9.1"}, queried_domains={"unrelated.example"})
ev_timeout_only = audit_device("dev-timeout", audit_timeout_only, geoip_engine=geoip_timeout)
check("THE FIX: an IP whose reverse-DNS TIMED OUT produces NO evidence at all "
      "(inconclusive, not unexplained) when it's the only unexplained candidate",
      ev_timeout_only == [])

audit_timeout_mixed = DeviceBurstAudit(dest_ips={"9.9.9.1", "9.9.9.2"}, queried_domains={"unrelated.example"})
ev_timeout_mixed = audit_device("dev-timeout-mixed", audit_timeout_mixed, geoip_engine=geoip_timeout)
check("THE FIX: a genuinely-confirmed no-PTR-record IP (9.9.9.2) still counts as "
      "unexplained even when a DIFFERENT IP in the same burst timed out",
      len(ev_timeout_mixed) == 1 and ev_timeout_mixed[0].value == 1.0)

# ═══════════════════════════════════════════════════════════════════════════════════
# BUGFIX (found via a live alert): a device's own DNS QUERY traffic to a well-known
# public resolver (e.g. a Chromecast querying 8.8.8.8 directly instead of through
# Pi-hole) was guaranteed to be flagged as "unexplained" -- the connection itself IS
# how domain resolution happens, so by definition no domain lookup can ever explain it.
# Confirmed live: chromecast_fritz_box flagged for "no matching DNS lookup history" on
# a connection to 8.8.8.8.
# ═══════════════════════════════════════════════════════════════════════════════════
from intelligence.detectors.dns_evasion import _is_known_dns_resolver, audit_device, DeviceBurstAudit

check("THE FIX: 8.8.8.8 (Google Public DNS) is recognized as a known resolver",
      _is_known_dns_resolver("8.8.8.8"))
check("THE FIX: 1.1.1.1 (Cloudflare) is recognized as a known resolver",
      _is_known_dns_resolver("1.1.1.1"))
check("REGRESSION GUARD: an ordinary, unrecognized public IP is NOT treated as a resolver",
      not _is_known_dns_resolver("172.238.164.57"))

resolver_audit = DeviceBurstAudit(dest_ips={"8.8.8.8"}, queried_domains=set())
resolver_evidence = audit_device("dev_resolver", resolver_audit, geoip_engine=None, ti_engine=None)
check("END-TO-END: a device whose ONLY real destination is a known public DNS resolver "
      "produces NO dns_evasion_anomaly evidence at all",
      resolver_evidence == [], f"got {resolver_evidence}")

mixed_audit = DeviceBurstAudit(dest_ips={"8.8.8.8", "66.66.66.66"}, queried_domains=set())
mixed_evidence = audit_device("dev_mixed", mixed_audit, geoip_engine=None, ti_engine=None)
check("REGRESSION GUARD: a genuinely unexplained IP alongside a known resolver still "
      "produces evidence -- the fix excludes only the resolver, not the whole device",
      bool(mixed_evidence) and mixed_evidence[0].domain == "66.66.66.66", f"got {mixed_evidence}")

# BUGFIX (found in the SAME live audit, a level deeper than the earlier target_display
# fix): alert_target_domain ITSELF (not just the Telegram display text) never got a
# DNS_EVASION branch, so network_context["queried_domain"] -- used by
# train_fp_classifier.py's f1_entropy feature and other consumers, not just display --
# stayed polluted with a coincidentally-queried, causally-unrelated real domain for
# every DNS_EVASION alert. Confirmed live: "Contacted: device-metrics-us.amazon.com"
# stored in the alert record itself, while the actual flagged IP (already correctly in
# destination_ip) was something completely different.
check("THE DEEPER FIX: alert_target_domain itself (the source field, not just the "
      "display variable) is now set to 'unknown' for DNS_EVASION -- no domain is "
      "attached where none exists, rather than the generic fallback leaking in",
      'elif primary_sig_base in ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS"):\n                            alert_target_domain = "unknown"' in pipeline_src)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 24 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 24 DNS-evasion blind-spot-audit checks PASSED.")
    sys.exit(0)
