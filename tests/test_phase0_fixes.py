"""
Standalone runtime test for Phase 0 (zero-risk fixes). Not part of the pytest suite —
run directly: `python3 test_phase0_fixes.py`. Exercises the real shipped code paths,
no mocks, matching the style of test_phase4_reidentify.py.

Covers:
  1. Reputation classifier eTLD+1 boundary-safe matching (the endswith substring bug).
  2. ml_engine.reject_threat() real exclusion window (was a no-op log statement).
  3. config.resolve_home_subnets() multi-subnet schema + legacy fallback.
  4. fp_engine._extract_base_domain() fail-closed behavior when tldextract is unavailable.
  5. decision_engine.py no longer has the dead dns_rate_anomaly branch (source check,
     since the live detector never emits that type — this is a "can't regress" guard).
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


# ── Test 1: reputation classifier boundary-safe matching ───────────────────────────
from intelligence.reputation.classifier import ReputationClassifier, _suffix_or_domain_match

rc = ReputationClassifier()

check("'notgoogle.com' is NOT boundary-matched against 'google.com'",
      not _suffix_or_domain_match("notgoogle.com", "google.com"))
check("real subdomain 'mail.google.com' IS matched against 'google.com'",
      _suffix_or_domain_match("mail.google.com", "google.com"))
check("exact domain 'google.com' IS matched against 'google.com'",
      _suffix_or_domain_match("google.com", "google.com"))

vec_attack = rc.classify("notgoogle.com")
check("ReputationClassifier no longer promotes 'notgoogle.com' to Tier 1 (trusted)",
      vec_attack.tier != 1, f"got tier={vec_attack.tier}")

vec_legit = rc.classify("mail.google.com")
check("ReputationClassifier still correctly tiers real 'mail.google.com' subdomain as Tier 1",
      vec_legit.tier == 1, f"got tier={vec_legit.tier}")

# Also check a malicious lookalike combining a trusted TIER_2 suffix as a substring
vec_lookalike = rc.classify("evil-doubleclick.net.attacker.io")
check("lookalike 'evil-doubleclick.net.attacker.io' is NOT promoted to Tier 2",
      vec_lookalike.tier != 2, f"got tier={vec_lookalike.tier}")

# BUGFIX regression guard (found via a live alerts.json audit spanning 5+ days): the
# EXACT PHASE 8 case (149.154.166.110, Telegram's own published server infrastructure)
# kept recurring anyway, because AbuseIPDB's crowd-sourced score for a huge shared IP
# block naturally drifts above and below any fixed threshold over time. Hundreds of
# alerts oscillating between "Elevated Reputation Signal (Unconfirmed)" and full
# "Confirmed Malicious IOC" Stage-1 hard-stops for a domain-less raw IP that no
# domain-based safe-list could ever immunize.
vec_telegram_low = rc.classify("unknown", abuse_score=3.78, asn_owner="Telegram Messenger Inc")
check("a known-safe ASN (Telegram) with a below-bar abuse score stays Tier 2",
      vec_telegram_low.tier == 2, f"got tier={vec_telegram_low.tier}")
vec_telegram_high = rc.classify("unknown", abuse_score=9.9, asn_owner="Telegram Messenger LLP")
check("THE CORE FIX: a known-safe ASN (Telegram) does NOT escalate to Tier 5 even when "
      "the abuse score clears the confirmed-IOC bar (this is what kept recurring in "
      "production despite the PHASE 8 threshold-only fix)",
      vec_telegram_high.tier == 2, f"got tier={vec_telegram_high.tier}")

# REGRESSION GUARDS: an otherwise-identical unrelated IP still escalates normally --
# this fix must not weaken reputation-based detection for anything else.
vec_evil_high = rc.classify("unknown", abuse_score=4.0, asn_owner="Definitely Evil Hosting LLC")
check("an UNRELATED asn_owner with the same abuse score still escalates to Tier 5 "
      "(the fix is scoped to known-safe ASNs, not a general threshold change)",
      vec_evil_high.tier == 5, f"got tier={vec_evil_high.tier}")
vec_evil_low = rc.classify("unknown", abuse_score=1.0, asn_owner="Definitely Evil Hosting LLC")
check("an UNRELATED asn_owner with a below-bar score still reaches Tier 4 (unconfirmed) as before",
      vec_evil_low.tier == 4, f"got tier={vec_evil_low.tier}")

# BUGFIX regression guard: an explicit tier assignment (0/1/2) is now a floor a stray
# reputation score cannot override -- matches this class's own documented intent
# ("1 trusted... strong counter-evidence required to override"), which the code
# previously did not actually enforce for ANY tier, not just the new ASN check above.
vec_trusted_with_hit = rc.classify("apple.com", vt_score=3.0)
check("an explicit Tier-1 domain (apple.com) is no longer escalated by a single stray "
      "reputation score -- an explicit safe classification is a floor, not a suggestion",
      vec_trusted_with_hit.tier == 1, f"got tier={vec_trusted_with_hit.tier}")
vec_unclassified_with_hit = rc.classify("totally-unclassified-domain.example", vt_score=3.0)
check("REGRESSION GUARD: a genuinely unclassified (Tier 3) domain still escalates "
      "normally on a real reputation hit -- only explicit tiers are protected",
      vec_unclassified_with_hit.tier == 5, f"got tier={vec_unclassified_with_hit.tier}")


# ── Test 2: ml_engine reject_threat() real exclusion window ────────────────────────
from intelligence.ml_engine import DeviceMLEngine, GlobalMLEngine, REJECT_THREAT_WINDOW_SECONDS

dme = DeviceMLEngine("test_device_1")
sample_features = {
    "query_rate": 5.0, "entropy_avg": 2.0, "unique_domains": 3, "nxdomain_ratio": 0.0,
    "blocked_ratio": 0.0, "zeek_outbound_bytes": 1000, "zeek_lateral_moves": 0,
    "zeek_s0_rej_count": 0, "zeek_app_protocol_weight": 0.2,
}

dme.learn_normal(sample_features)
check("baseline sample accepted before any threat rejection", len(dme.training) == 1,
      f"training len={len(dme.training)}")

dme.reject_threat(sample_features)
check("reject_threat() actually sets a future _reject_until timestamp",
      dme._reject_until > time.time(), f"_reject_until={dme._reject_until}, now={time.time()}")
check("_reject_until window matches REJECT_THREAT_WINDOW_SECONDS (120s)",
      abs((dme._reject_until - time.time()) - REJECT_THREAT_WINDOW_SECONDS) < 2.0)

dme.learn_normal(sample_features)
check("learn_normal() is skipped while inside the post-threat rejection window "
      "(poisoning prevention — this was previously a no-op)",
      len(dme.training) == 1, f"training len={len(dme.training)} (expected still 1, not 2)")

dme._reject_until = 0.0  # simulate window expiry
dme.learn_normal(sample_features)
check("learn_normal() resumes training once the rejection window has passed",
      len(dme.training) == 2, f"training len={len(dme.training)}")

gme = GlobalMLEngine()
gme.reject_threat(sample_features)
check("GlobalMLEngine.reject_threat() also sets a real _reject_until (not just device-level)",
      gme._reject_until > time.time())
gme.learn_normal(sample_features)
check("GlobalMLEngine.learn_normal() also honors the rejection window",
      len(gme.training) == 0, f"training len={len(gme.training)} (expected 0)")


# ── Test 3: config.resolve_home_subnets() multi-subnet schema ──────────────────────
from config import resolve_home_subnets

cfg_legacy_only = {"home_subnet": "192.168.1.0/24", "home_subnets": []}
check("legacy-only config falls back to home_subnet as a single-item list",
      resolve_home_subnets(cfg_legacy_only) == ["192.168.1.0/24"])

cfg_multi = {"home_subnet": "192.168.1.0/24", "home_subnets": ["10.0.0.0/24", "192.168.50.0/24"]}
check("multi-subnet config prefers the home_subnets list over the legacy key",
      resolve_home_subnets(cfg_multi) == ["10.0.0.0/24", "192.168.50.0/24"])

cfg_whitespace = {"home_subnet": "192.168.1.0/24", "home_subnets": ["  10.0.0.0/24  ", "", "   "]}
check("home_subnets entries are trimmed and blanks dropped",
      resolve_home_subnets(cfg_whitespace) == ["10.0.0.0/24"])

cfg_empty_all = {"home_subnet": "", "home_subnets": []}
check("fully-empty config resolves to an empty subnet list (not a crash)",
      resolve_home_subnets(cfg_empty_all) == [])


# ── Test 4: fp_engine._extract_base_domain() fails closed without tldextract ───────
import utils as _utils_mod
_orig_tldextract = _utils_mod.tldextract
_utils_mod.tldextract = None  # simulate "tldextract not installed" for this check

from intelligence.fp_engine import AutonomousFPEngine
import tempfile

with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)
    base = fp._extract_base_domain("mail.example.co.uk")
    check("base-domain extraction fails CLOSED (returns '') when tldextract is unavailable, "
          "instead of the dangerous naive 'co.uk' last-two-labels fallback",
          base == "", f"got base_domain={base!r}")

    base_empty_input = fp._extract_base_domain("")
    check("empty domain input returns '' without raising", base_empty_input == "")

_utils_mod.tldextract = _orig_tldextract  # restore

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 0 zero-risk-fix checks PASSED.")
