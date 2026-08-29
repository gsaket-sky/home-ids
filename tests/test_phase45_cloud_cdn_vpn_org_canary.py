"""
Standalone runtime test for Phase 45: a canary regression sweep for
is_cloud_cdn_provider_org()/is_vpn_provider_org() (utils.py), the hardcoded org-name
keyword lists fp_engine.py's confirmed-intel write guard relies on.

Context (2026-08-29): investigated why this codebase uses hardcoded org-name-substring
keywords instead of ASN NUMBERS or an external authoritative CDN list. Checked real
data against the actual GeoLite2-ASN.mmdb: Akamai alone shows at least three different
org-name strings across its ASNs ("Akamai Technologies, Inc.", "Akamai International
B.V.", "Akamai Connected Cloud"), and Alibaba shows three more -- yet the single
substring keyword ("akamai"/"alibaba") already catches all of them. Switching to
ASN-number matching would NOT reduce the maintenance burden (each major provider owns
dozens of ASNs across regions/subsidiaries/acquisitions -- an ASN-number list would
need to be LARGER than today's ~30 keyword strings for equivalent coverage). The
actual failure mode that let "apple"/"facebook" go missing for months (see the
2026-08-29 BUGFIX in utils.py) wasn't a string-variant-matching problem -- it was a
plain missing keyword with ZERO test coverage. This file is that coverage: every IP
below was independently verified against the real production GeoLite2-ASN.mmdb before
being hardcoded here (not guessed) -- two earlier guesses for this exact test (a
different Vultr IP, a Leaseweb IP) turned out to resolve to unexpected org strings and
were corrected before landing, which is exactly the discipline this test exists to
enforce going forward.

Not part of the pytest suite -- run directly:
`python3 tests/test_phase45_cloud_cdn_vpn_org_canary.py`.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from utils import is_cloud_cdn_provider_org, is_vpn_provider_org
from intelligence.geoip import GeoIPEngine

_MODELS_DIR = _PathForSysPath(__file__).resolve().parent.parent / "models"
_CITY_DB = str(_MODELS_DIR / "GeoLite2-City.mmdb")
_ASN_DB = str(_MODELS_DIR / "GeoLite2-ASN.mmdb")

geo = GeoIPEngine(db_path=_CITY_DB, asn_db_path=_ASN_DB)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: cloud/CDN canary sweep -- every (provider, ip) pair independently
# verified against the real GeoLite2-ASN.mmdb before being hardcoded here.
# ═══════════════════════════════════════════════════════════════════════════════════
CLOUD_CDN_CANARIES = [
    ("Apple", "17.57.146.55"),
    ("Facebook/Meta", "157.240.223.61"),
    ("Google", "8.8.8.8"),
    ("Microsoft", "20.190.159.23"),
    ("Cloudflare", "104.16.85.20"),
    ("Akamai", "172.238.164.57"),
    ("Alibaba", "8.209.113.73"),
    ("Amazon/AWS", "52.94.236.248"),
    ("Netflix", "45.57.41.1"),
    ("DigitalOcean", "138.68.201.49"),
    ("Hetzner", "116.203.244.102"),
    ("OVH", "144.217.75.98"),
    ("Oracle", "132.145.106.0"),
    ("Tencent", "129.226.128.17"),
    ("Fastly", "151.101.194.49"),
    ("IBM Cloud", "169.55.79.145"),
    ("Vultr", "45.32.0.1"),
    ("Leaseweb", "178.162.128.1"),
    ("Scaleway", "51.15.0.1"),
    ("Contabo", "5.189.148.1"),
]

for name, ip in CLOUD_CDN_CANARIES:
    asn_res = geo.lookup_asn(ip)
    org = getattr(asn_res, "autonomous_system_organization", None) if asn_res else None
    if org is None:
        check(f"CANARY: {name} ({ip}) -- ASN lookup returned a result", False,
              "GeoLite2-ASN.mmdb has no entry for this IP (database may need updating, "
              "or the IP has been reassigned since this test was written)")
        continue
    check(f"CANARY: {name} ({ip}, real ASN org={org!r}) is recognized as a cloud/CDN provider",
          is_cloud_cdn_provider_org(org), f"is_cloud_cdn_provider_org({org!r}) returned False")

check("REGRESSION GUARD: an ordinary residential/unrelated hosting org is NOT swept "
      "in by the canary list above",
      not is_cloud_cdn_provider_org("Definitely Evil Hosting LLC"))
check("REGRESSION GUARD: empty/None org_name returns False, not a crash",
      is_cloud_cdn_provider_org("") is False and is_cloud_cdn_provider_org(None) is False)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: VPN-provider keyword sweep -- unlike cloud/CDN providers, commercial VPN
# services usually rent infrastructure from generic hosting resellers rather than
# operating their own named ASN (verified live: real exit-node IPs for NordVPN and
# Mullvad both resolved to generic reseller ASNs -- "Datacamp Limited" and "31173
# Services AB" -- neither containing the VPN brand name at all). So this section tests
# is_vpn_provider_org()'s own keyword-matching logic directly against crafted strings
# built from its own keyword list, rather than against live IPs that may not reliably
# carry a brand-identifiable org name in the first place -- a live-IP canary here would
# test ASN-reseller-naming luck, not this function's actual logic.
# ═══════════════════════════════════════════════════════════════════════════════════
VPN_ORG_STRING_CANARIES = [
    "NordVPN S.A.", "ExpressVPN International Ltd", "Mullvad VPN AB",
    "Surfshark Ltd.", "Proton VPN AG", "Private Internet Access, Inc.",
    "CyberGhost S.A.", "Windscribe Limited",
]
for org in VPN_ORG_STRING_CANARIES:
    check(f"is_vpn_provider_org({org!r}) recognizes its own listed keyword",
          is_vpn_provider_org(org))

check("REGRESSION GUARD: is_vpn_provider_org() does not flag an ordinary cloud "
      "provider as a VPN service",
      not is_vpn_provider_org("Google LLC"))
check("REGRESSION GUARD: empty/None org_name returns False, not a crash",
      is_vpn_provider_org("") is False and is_vpn_provider_org(None) is False)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 45 cloud/CDN/VPN org canary checks PASSED.")
