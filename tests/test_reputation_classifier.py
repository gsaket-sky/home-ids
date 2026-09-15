"""
Standalone runtime test for intelligence/reputation/classifier.py's ReputationClassifier,
specifically the 2026-09-15 "3 automated-learning gaps" audit fix (gap 2): tier 0
("local/internal, RFC1918 -- external reputation doesn't apply") was documented in
ReputationVector's own docstring but never actually implemented for raw private IPs --
_TIER_0 was always a set of DOMAIN-SUFFIX strings (.box/.local/fritz.box), so a raw
private IP like "192.168.1.41" never matched any of them and fell through to tier 3
(neutral) instead.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_reputation_classifier.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.reputation.classifier import ReputationClassifier  # noqa: E402

c = ReputationClassifier()

# --- gap 2: raw private/link-local/loopback IPs now correctly reach tier 0 ---
# Deliberately NOT this project's own real household subnet (192.168.77.0/24) --
# per feedback_network_agnostic_design.md, the fix is a real ipaddress-stdlib range
# check, not anything tied to one specific network, so these use clearly different
# private ranges to prove that.
check("RFC1918 Class C (192.168.x.x) reaches tier 0", c.classify("192.168.1.41").tier == 0)
check("RFC1918 Class A (10.x.x.x) reaches tier 0", c.classify("10.20.30.40").tier == 0)
check("RFC1918 Class B (172.16-31.x.x) reaches tier 0", c.classify("172.20.5.9").tier == 0)
check("link-local (169.254.x.x) reaches tier 0", c.classify("169.254.1.1").tier == 0)
check("loopback (127.x.x.x) reaches tier 0", c.classify("127.0.0.1").tier == 0)
check("IPv6 unique-local (fc00::/7, RFC1918's IPv6 equivalent) reaches tier 0",
      c.classify("fd12:3456:789a::1").tier == 0)
check("IPv6 link-local (fe80::/10) reaches tier 0", c.classify("fe80::1").tier == 0)
check("IPv6 loopback (::1) reaches tier 0", c.classify("::1").tier == 0)

# --- a genuinely public IP must NOT be swept into tier 0 by an overly broad check ---
check("an ordinary public IP does NOT reach tier 0 (no reputation signal at all -> "
      "unclassified, tier 3)", c.classify("93.184.216.34").tier == 3)

# --- non-IP domain strings are completely unaffected -- the fix only ever attempts
# ipaddress.ip_address() and falls through unchanged on a ValueError ---
check("a real trusted-tier domain (apple.com) still reaches tier 1, unaffected by the "
      "IP-range check", c.classify("apple.com").tier == 1)
check("a known infrastructure domain (cloudflare.com) still reaches tier 2, unaffected",
      c.classify("cloudflare.com").tier == 2)
check("the pre-existing domain-suffix tier-0 patterns (.local) still work exactly as "
      "before -- the new IP-range check is additive, not a replacement",
      c.classify("some-device.local").tier == 0)
check("fritz.box (the pre-existing exact-match tier-0 pattern) still works",
      c.classify("fritz.box").tier == 0)
check("an ordinary unclassified domain still reaches tier 3", c.classify("random-xyz-example.net").tier == 3)

# --- tier 0 is still a FLOOR, not overridable by a noisy reputation score -- same
# invariant the PHASE-8/tier-1/2 fix already established, now also true for tier 0 ---
r = c.classify("192.168.5.5", abuse_score=10.0, vt_score=5.0, ti_score=5.0)
check("a private IP's tier-0 classification is NOT escalatable back to tier 5 by a "
      "noisy reputation score -- 'external reputation doesn't apply' is a floor",
      r.tier == 0)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All ReputationClassifier checks PASSED.")
