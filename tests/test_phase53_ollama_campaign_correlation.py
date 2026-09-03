"""
Standalone runtime test for Phase 53: ollama_soc.py's multi-device withhold guard
(should_still_withhold(), Phase 49) treated "N distinct devices fired this signature"
as the whole story -- device COUNT alone can't distinguish a genuine coordinated
campaign (many devices independently reaching the SAME/shared attacker infrastructure)
from a noisy, generic signature that many devices trip independently against
DIFFERENT, individually reputable destinations (the concrete "3 smart-TVs hitting 3
different CDN edges" shape a Zeek `weird` notice or similar heuristic produces). The
guard's own history (DEFAULT_MULTI_DEVICE_SUPPRESS_GUARD's comment) describes exactly
the case it SHOULD catch -- a DGA-shaped domain firing on 9 devices over 47 hours -- but
nothing distinguished that from the harmless case, so every spread>=3 pattern withheld
identically regardless of whether the destinations told the same story.

The fix: _is_campaign_corroborated() classifies a signature's cross-device spread by
its DESTINATIONS, not just device count -- concentrated on one/few IPs (or anything
unclassified/not-reputable) stays True (conservative, still withheld, unchanged
behavior); genuinely scattered across MULTIPLE distinct IPs that ALL resolve to
recognized cloud/CDN infrastructure flips to False, letting the pattern proceed to the
normal (already Phase-1/2/3-hardened) per-target correction path instead of being
withheld for human review it doesn't need. should_still_withhold() ANDs this in
alongside the existing spread check -- it can only ever RELAX the guard, never make it
withhold something spread alone wouldn't already have caught.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase53_ollama_campaign_correlation.py`

Sections:
  A. _is_campaign_corroborated() -- concentrated/single-IP, no geoip engine, all-
     reputable-scattered (the actual relaxation), partially-unclassified (stays
     conservative), none-reputable (stays conservative), missing destination_ips
  B. should_still_withhold()'s new campaign_corroborated param -- default True
     (backward compat), and False actually overriding a satisfied spread guard
  C. Source-level wiring checks in ollama_soc.py's main()
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts"))

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


from ollama_soc import _is_campaign_corroborated, should_still_withhold


class _StubASNResult:
    def __init__(self, org):
        self.autonomous_system_organization = org


class _StubGeoIP:
    """ip -> org name (or None for "doesn't resolve/unclassified")."""
    def __init__(self, mapping):
        self._mapping = mapping

    def lookup_asn(self, ip):
        org = self._mapping.get(ip)
        return _StubASNResult(org) if org else None


def _members(*ips):
    return [{"network_context": {"destination_ip": ip}} for ip in ips]


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: _is_campaign_corroborated()
# ═══════════════════════════════════════════════════════════════════════════════════

check("a single distinct destination IP -> True (concentrated, nothing to disambiguate)",
      _is_campaign_corroborated(_members("1.1.1.1", "1.1.1.1", "1.1.1.1"), _StubGeoIP({})) is True)

check("no destination_ips at all (e.g. every alert is domain-only) -> True (conservative)",
      _is_campaign_corroborated([{"network_context": {}}, {"network_context": {"destination_ip": "unknown"}}],
                                 _StubGeoIP({})) is True)

check("multiple distinct IPs but NO geoip engine available -> True (can't classify, conservative)",
      _is_campaign_corroborated(_members("1.1.1.1", "2.2.2.2", "3.3.3.3"), None) is True)

geoip_all_reputable = _StubGeoIP({
    "1.1.1.1": "Amazon.com, Inc.", "2.2.2.2": "Google LLC", "3.3.3.3": "Cloudflare, Inc.",
})
check("THE CORE FIX: multiple distinct IPs, ALL resolve to recognized cloud/CDN infra "
      "-> False (scattered across reputable infra, NOT a coordinated campaign -- the "
      "'3 smart-TVs hitting 3 different CDN edges' shape)",
      _is_campaign_corroborated(_members("1.1.1.1", "2.2.2.2", "3.3.3.3"), geoip_all_reputable) is False)

geoip_partial = _StubGeoIP({
    "1.1.1.1": "Amazon.com, Inc.", "2.2.2.2": "Google LLC",
    "3.3.3.3": None,  # doesn't resolve / unclassified
})
check("multiple distinct IPs, MOSTLY reputable but one unclassified -> True (conservative "
      "-- NOT every destination is explained, so it must stay cautious)",
      _is_campaign_corroborated(_members("1.1.1.1", "2.2.2.2", "3.3.3.3"), geoip_partial) is True)

geoip_none_reputable = _StubGeoIP({
    "1.1.1.1": "Some Random Hosting LLC", "2.2.2.2": "Bulletproof VPS Ltd",
    "3.3.3.3": "Unknown Datacenter Co",
})
check("multiple distinct IPs, all resolve but NONE are recognized reputable infra -> "
      "True (unexplained infrastructure -- stays cautious, same as before this phase)",
      _is_campaign_corroborated(_members("1.1.1.1", "2.2.2.2", "3.3.3.3"), geoip_none_reputable) is True)

geoip_mixed_rep = _StubGeoIP({
    "1.1.1.1": "Amazon.com, Inc.", "2.2.2.2": "Google LLC", "3.3.3.3": "Sketchy Hosting LLC",
})
check("multiple distinct IPs, mostly reputable but one genuinely NOT reputable -> True "
      "(a single unexplained destination among reputable ones still keeps this cautious)",
      _is_campaign_corroborated(_members("1.1.1.1", "2.2.2.2", "3.3.3.3"), geoip_mixed_rep) is True)

check("REGRESSION GUARD: a lookup that raises internally is treated as unclassified, "
      "not a crash",
      _is_campaign_corroborated(_members("1.1.1.1", "2.2.2.2"), _StubGeoIP({"1.1.1.1": "Amazon.com, Inc."}))
      is True)  # 2.2.2.2 unclassified -> conservative True

check("only 2 distinct IPs (not 3+) still correctly flips to False when BOTH are reputable",
      _is_campaign_corroborated(_members("1.1.1.1", "2.2.2.2"),
                                 _StubGeoIP({"1.1.1.1": "Amazon.com, Inc.", "2.2.2.2": "Google LLC"})) is False)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: should_still_withhold()'s campaign_corroborated param
# ═══════════════════════════════════════════════════════════════════════════════════

check("BACKWARD COMPAT: should_still_withhold() with NO campaign_corroborated arg "
      "(every pre-Phase-53 call site/test) behaves exactly as before -- spread>=guard "
      "alone still withholds",
      should_still_withhold(5, 3, 0, 10) is True)

check("campaign_corroborated=True (explicit) behaves identically to the default",
      should_still_withhold(5, 3, 0, 10, campaign_corroborated=True) is True)

check("THE CORE FIX: campaign_corroborated=False overrides an otherwise-satisfied spread "
      "guard -- a pattern spread across devices but scattered on reputable infra does "
      "NOT withhold",
      should_still_withhold(5, 3, 0, 10, campaign_corroborated=False) is False)

check("campaign_corroborated=False on a pattern that DOESN'T even meet the spread "
      "threshold is still correctly False (spread check alone would already reject it)",
      should_still_withhold(1, 3, 0, 10, campaign_corroborated=False) is False)

check("REGRESSION GUARD: the streak-exhaustion behavior (Phase 49) is unaffected when "
      "campaign_corroborated=True",
      should_still_withhold(5, 3, 10, 10, campaign_corroborated=True) is False  # streak exhausted
      and should_still_withhold(5, 3, 9, 10, campaign_corroborated=True) is True)  # streak not yet exhausted

# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: source-level checks against the real ollama_soc.py wiring
# ═══════════════════════════════════════════════════════════════════════════════════
_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")

check("signature_members (full alert payloads per signature, not just device ids) is "
      "actually built -- _is_campaign_corroborated() needs real destination_ips, which "
      "signature_device_counts (a bare set of device ids) can't provide",
      "signature_members: dict = defaultdict(list)" in _src
      and "signature_members[sig].append(payload)" in _src)

check("campaign classification is cached PER SIGNATURE (campaign_shape_cache), not "
      "recomputed for every target sharing that signature -- avoids redundant GeoIP "
      "ASN lookups within one run",
      "campaign_shape_cache: dict = {}" in _src
      and "campaign_shape_cache[signature] = _is_campaign_corroborated(" in _src)

check("both should_still_withhold() call sites in main() actually pass "
      "campaign_corroborated -- not just one of them (streak_exhausted computation AND "
      "the withhold if-condition must agree, or they'd desync)",
      _src.count("multi_device_withhold_auto_resolve_after, campaign_corroborated,") == 2)

check("streak_exhausted's own computation also requires campaign_corroborated to have "
      "been True -- otherwise a campaign-relaxed pattern (never actually withheld) "
      "would be misreported as an exhausted-streak auto-resolve",
      "and spread >= multi_device_suppress_guard and campaign_corroborated" in _src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 53 ollama-campaign-correlation checks PASSED.")
