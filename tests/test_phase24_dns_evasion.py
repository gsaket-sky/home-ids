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
    """reverse_dns_map: ip -> hostname (or None). asn_org_map: ip -> org name (or None)."""
    def __init__(self, reverse_dns_map=None, asn_org_map=None):
        self.reverse_dns_map = reverse_dns_map or {}
        self.asn_org_map = asn_org_map or {}

    def reverse_dns(self, ip):
        return self.reverse_dns_map.get(ip)

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

# B4: genuinely unexplained -- no DNS match, not CDN, not VPN -- fires evidence.
geoip_unknown = _FakeGeoIP(reverse_dns_map={}, asn_org_map={"9.9.9.9": "Some Random Hosting LLC"})
audit_unexplained = DeviceBurstAudit(dest_ips={"9.9.9.9"}, queried_domains={"totally-unrelated.com"})
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
audit_no_dns = DeviceBurstAudit(dest_ips={"9.9.9.9"}, queried_domains=set())
ev_no_dns = audit_device(DEV, audit_no_dns, geoip_engine=geoip_unknown)
check("a device with real traffic and ZERO dns history at all scores a HIGHER confidence "
      "than one with some unrelated DNS history for the same unexplained IP",
      ev_no_dns[0].confidence > ev_unexplained[0].confidence,
      f"no_dns={ev_no_dns[0].confidence} vs some_dns={ev_unexplained[0].confidence}")

# B6: reputation-hit bump.
ti_bad = _FakeTI(bad_ips={"9.9.9.9"})
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
audit_mixed = DeviceBurstAudit(dest_ips={"1.1.1.1", "9.9.9.9"}, queried_domains={"example.com"})
ev_mixed = audit_device(DEV, audit_mixed, geoip_engine=geoip_mixed)
check("mixed case: 1 explained + 1 unexplained out of 2 total -> evidence value is 1 (only the unexplained one)",
      len(ev_mixed) == 1 and ev_mixed[0].value == 1.0, f"got {ev_mixed}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: audit_burst -- multi-device orchestration
# ═══════════════════════════════════════════════════════════════════════════════════
devices = {
    "dev-clean": DeviceBurstAudit(dest_ips={"93.184.216.34"}, queried_domains={"example.com"}),
    "dev-evasive": DeviceBurstAudit(dest_ips={"9.9.9.9"}, queried_domains=set()),
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


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 24 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 24 DNS-evasion blind-spot-audit checks PASSED.")
    sys.exit(0)
