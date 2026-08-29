"""
Standalone runtime test for Phase 42: Gap 1 (rep.verified_ioc tier-5 split) flipped
live in decision_engine.py, plus the related cloud/CDN-org confirmed-intel write guard
gap found in the same investigation. Not part of the pytest suite -- run directly:
`python3 tests/test_phase42_tier5_verified_ioc_split.py`.

Context (2026-08-29): a live production alert for family_pc_fritz_box vs. 35.186.224.24
(Google LLC) reached CRITICAL / "Confirmed Malicious IOC" / 0.99 confidence three times
in one night from a bare AbuseIPDB=4.0 score alone (VT=0.0, TI=0.0, i.e.
rep.verified_ioc=False), with the benign hypothesis (LOCAL_DEVICE_DISCOVERY, 2.5)
actually outscoring the attack hypothesis (NETWORK_INTRUSION, 2.0) and zero other
corroborating evidence. This was already a known gap under evaluation in shadow mode
(shadow_backtest.py: verified_ioc was True for ZERO of 80 historical "Confirmed
Malicious IOC" alerts) -- this live recurrence is what triggered flipping it into the
real decision path. Same investigation found _CLOUD_CDN_ORG_KEYWORDS (utils.py) was
missing "apple"/"facebook" despite the confirmed-intel write guard's own docstring
already claiming Apple was covered -- confirmed live via retro_hunter's cross-reference
digest showing Apple Push (17.57.146.55/.59) and Facebook CDN (157.240.223.61) IPs
poisoned as "confirmed malicious," cascading sensitivity-tightening to every other
device sharing that infrastructure.

Sections:
  A. is_cloud_cdn_provider_org() now recognizes Apple/Facebook/Meta
  B. _is_ip_protected_from_confirmed_intel() / record_confirmed_threat() end-to-end:
     an Apple-owned IP is refused, an unrelated hosting IP is still recorded
  C. decision_engine.py's tier==5 three-way split: verified_ioc / corroborated / not
  D. Regression guard: duck-typed rep objects without .verified_ioc don't crash
     (live path and the pre-existing shadow path)
  E. Real-world pin: the exact family_pc_fritz_box/35.186.224.24 shape now lands at
     SUSPICIOUS, not CRITICAL
"""
import sys
import tempfile
import time
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


from core.decision_engine import DecisionEngine
from intelligence.hypotheses.evidence import Evidence, EvidenceStore
from intelligence.reputation.classifier import ReputationClassifier, ReputationVector
from intelligence.fp_engine import AutonomousFPEngine
from utils import is_cloud_cdn_provider_org

de = DecisionEngine()
rc = ReputationClassifier()


def fresh_store(evidence_list, device="dev"):
    s = EvidenceStore()
    for e in evidence_list:
        s.add(e)
    return s.get_for_device(device)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: is_cloud_cdn_provider_org() now recognizes Apple/Facebook/Meta
# ═══════════════════════════════════════════════════════════════════════════════════
check("is_cloud_cdn_provider_org('Apple Inc.') is now True (was the gap)",
      is_cloud_cdn_provider_org("Apple Inc."))
check("is_cloud_cdn_provider_org('Facebook, Inc.') is now True (was the gap)",
      is_cloud_cdn_provider_org("Facebook, Inc."))
check("is_cloud_cdn_provider_org('Meta Platforms, Inc.') is now True",
      is_cloud_cdn_provider_org("Meta Platforms, Inc."))
check("REGRESSION GUARD: pre-existing orgs (Google LLC, AWS) still recognized",
      is_cloud_cdn_provider_org("Google LLC") and is_cloud_cdn_provider_org("Amazon Technologies Inc."))
check("REGRESSION GUARD: an unrelated hosting provider is NOT swept in by the new keywords",
      not is_cloud_cdn_provider_org("Definitely Evil Hosting LLC"))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: _is_ip_protected_from_confirmed_intel() / record_confirmed_threat()
# end-to-end -- an Apple-owned IP is refused, an unrelated one is still recorded
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    apple_protected = fp._is_ip_protected_from_confirmed_intel("17.57.146.55", asn_owner="Apple Inc.")
    check("_is_ip_protected_from_confirmed_intel('17.57.146.55', asn_owner='Apple Inc.') is now True",
          apple_protected)

    facebook_protected = fp._is_ip_protected_from_confirmed_intel("157.240.223.61", asn_owner="Facebook, Inc.")
    check("_is_ip_protected_from_confirmed_intel('157.240.223.61', asn_owner='Facebook, Inc.') is now True",
          facebook_protected)

    fp.record_confirmed_threat("dev_apple_test", None, "17.57.146.55", reason="TEST",
                                asn_owner="Apple Inc.")
    apple_hit = fp.local_intel.check("ip", "17.57.146.55")
    check("record_confirmed_threat() REFUSES to write an Apple-owned IP into local_intel",
          apple_hit is None, f"got {apple_hit}")

    # NOTE: not an RFC 5737 documentation range (203.0.113.0/24 etc.) -- Python's own
    # ipaddress module classifies those as is_private=True, which would trip this guard
    # for an unrelated reason and defeat the point of this regression check.
    fp.record_confirmed_threat("dev_evil_test", None, "45.33.32.156", reason="TEST",
                                asn_owner="Definitely Evil Hosting LLC")
    evil_hit = fp.local_intel.check("ip", "45.33.32.156")
    check("REGRESSION GUARD: an unrelated hosting-provider IP is still recorded normally",
          evil_hit is not None, f"got {evil_hit}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: decision_engine.py's tier==5 three-way split
# ═══════════════════════════════════════════════════════════════════════════════════
rep_genuine_ioc = rc.classify("actually-malicious-c2.example", vt_score=0.0, ti_score=3.5,
                               abuse_score=0.0, asn_owner="Unknown")
decision_genuine = de.evaluate([], rep_genuine_ioc)
check("verified_ioc=True (genuine ThreatIntel feed match) still reaches CRITICAL / "
      "'Confirmed Malicious IOC', unaffected by the split",
      decision_genuine["state"] == "CRITICAL" and decision_genuine["explanation"] == "Confirmed Malicious IOC",
      f"got {decision_genuine}")

rep_bare_abuse = rc.classify("203.0.113.201", vt_score=0.0, ti_score=0.0, abuse_score=4.0,
                              asn_owner="Some Hosting LLC")
check("SANITY: this reputation shape is tier=5 with verified_ioc=False (the exact gap shape)",
      rep_bare_abuse.tier == 5 and rep_bare_abuse.verified_ioc is False,
      f"got tier={rep_bare_abuse.tier} verified_ioc={rep_bare_abuse.verified_ioc}")

decision_uncorroborated = de.evaluate([], rep_bare_abuse)
check("verified_ioc=False with ZERO corroborating evidence now lands at SUSPICIOUS / "
      "'Elevated Reputation Signal (Unconfirmed, Tier 5 Score)', not an auto-block",
      decision_uncorroborated["state"] == "SUSPICIOUS"
      and decision_uncorroborated["explanation"] == "Elevated Reputation Signal (Unconfirmed, Tier 5 Score)",
      f"got {decision_uncorroborated}")

lateral_scan_evidence = fresh_store([
    Evidence(type="zeek_lateral_scan", source="zeek", timestamp=time.time(), device="dev_corrob5",
             value=5.0, confidence=0.9, independence_group="zeek_network"),
], "dev_corrob5")
decision_corroborated = de.evaluate(lateral_scan_evidence, rep_bare_abuse)
check("verified_ioc=False but corroborated by real behavioral evidence (attack_score > "
      "benign_score, >=1 independent source) reaches CRITICAL / 'Corroborated Reputation "
      "Signal' -- a real signal, just not a genuine curated IOC match",
      decision_corroborated["state"] == "CRITICAL"
      and decision_corroborated["explanation"] == "Corroborated Reputation Signal",
      f"got {decision_corroborated}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: duck-typed rep objects without .verified_ioc don't crash
# ═══════════════════════════════════════════════════════════════════════════════════
class MockRep:
    """Mirrors regression_tester.py's MockRep -- only sets .tier, same as every other
    duck-typed test double already tolerated via getattr() elsewhere in this file."""
    def __init__(self, tier=1):
        self.tier = tier
        self.confidence = 1.0


mock_store = fresh_store([
    Evidence(type="reputation_tier", source="mock", timestamp=time.time(), device="dev_mock5",
             value=4.0, confidence=1.0, provenance="mock_ioc"),
], "dev_mock5")
try:
    decision_mock = de.evaluate(mock_store, MockRep(tier=5))
    mock_crashed = False
except AttributeError as exc:
    decision_mock = None
    mock_crashed = True
    mock_exc = exc
check("a duck-typed rep object with no .verified_ioc attribute at all does NOT crash "
      "evaluate() (live path's getattr fallback)",
      not mock_crashed, f"raised {mock_exc if mock_crashed else ''}")
if not mock_crashed:
    check("...and resolves to SUSPICIOUS (missing verified_ioc treated as False, not "
          "an error) since there's no corroborating evidence here",
          decision_mock["state"] == "SUSPICIOUS", f"got {decision_mock}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: real-world pin -- the exact family_pc_fritz_box/35.186.224.24 shape
# ═══════════════════════════════════════════════════════════════════════════════════
rep_family_pc_shape = rc.classify("unknown", vt_score=0.0, ti_score=0.0, abuse_score=4.0,
                                asn_owner="Google LLC")
decision_family_pc = de.evaluate([], rep_family_pc_shape)
check("PRODUCTION PIN: the exact family_pc_fritz_box/35.186.224.24 alert shape "
      "(AbuseIPDB=4.0, VT=0.0, TI=0.0, Google LLC, no corroborating Zeek/ARP/honeypot "
      "evidence) now lands at SUSPICIOUS/monitor instead of CRITICAL/block",
      decision_family_pc["state"] == "SUSPICIOUS", f"got {decision_family_pc}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 42 tier5/verified_ioc split checks PASSED.")
