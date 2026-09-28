"""
Standalone runtime test for Phase 52: fp_engine.py's domain/IP trust cache (the Stage-1
fast path evaluate() uses to suppress recurring alerts at zero CPU cost) was keyed
purely on domain/IP, globally, with no device or hypothesis dimension at all -- an
immunization from correcting ONE attack hypothesis against a domain (e.g. a DGA false
positive) could silently suppress a completely DIFFERENT, unrelated hypothesis against
the SAME domain later (e.g. real lateral-movement evidence happening to route through
the same IP), for every device on the network, forever (well, 14 days).

The fix, scoped narrowly per explicit direction (a full rescoping would also touch
get_dynamic_trust_cache()'s pipeline.py/scoring.py consumer and utils.py's separate
detector allowlist -- 9 files total, deliberately out of scope -- see
Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's Gap 4 entry): `_trust_cache` entries
now carry `{ts, source, device_id, hypothesis, ttl_seconds}` (a dict) instead of a bare
timestamp float. `_is_trust_cached()` -- read ONLY by evaluate()'s own trust-cache-hit
check, the actual gate that decides whether an alert is suppressed -- now requires the
CURRENT alert's hypothesis to match what's recorded (always), and additionally requires
the SAME device for DEVICE_SCOPED_TRUST_HYPOTHESES specifically (DNS_EVASION/
DNS_ATTRIBUTION_GAP/DNS_POLICY_BYPASS -- hypotheses whose correction is a claim about
THAT device's own DNS usage, not the destination's general safety). Every other
hypothesis (NETWORK_INTRUSION, DGA_BOTNET_C2, generic reputation, ...) stays
domain-shared across devices, same as before this phase -- "combine both" per explicit
direction: hypothesis-gated always, device-gated only where the underlying claim is
genuinely device-specific.

A legacy bare-float entry (every entry written before this phase, and what a live
production fp_trust_cache.json actually contains today) is an unconditional
always-match wildcard -- this phase only NARROWS future hits, it never invents a
rejection the pre-Phase-52 cache wouldn't already have accepted.

ttl_seconds (optional, e.g. ollama_soc.py's LLM-supplied value from Phase 51) overrides
the global 14-day default for one entry, clamped to
[MIN_TRUST_ENTRY_TTL_SECONDS, MAX_TRUST_ENTRY_TTL_SECONDS].

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase52_scoped_trust_cache.py`

Sections:
  A. Pure helper functions (_trust_entry_ts/_trust_entry_ttl/_trust_entry_hypothesis_base)
     -- shape handling and malformed-input safety
  B. _immunize_domain() -- writes a scoped entry, TTL clamping, refresh behavior
  C. _is_trust_cached() -- hypothesis gate, device gate (only for
     DEVICE_SCOPED_TRUST_HYPOTHESES), legacy-float backward compatibility
  D. End-to-end via evaluate()'s real trust-cache-hit path
  E. mark_false_positive() -- device_id/hypothesis/ttl_seconds actually threaded through
  F. Mixed on-disk cache (old float entries alongside new dict ones) loads without
     crashing -- exactly what a live upgrade produces
  G. Source-level wiring checks
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time
import json
import tempfile

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.fp_engine import (
    AutonomousFPEngine, _trust_entry_ts, _trust_entry_ttl, _trust_entry_hypothesis_base,
    DEVICE_SCOPED_TRUST_HYPOTHESES, MIN_TRUST_ENTRY_TTL_SECONDS, MAX_TRUST_ENTRY_TTL_SECONDS,
    TRUST_CACHE_TTL_SECONDS,
)

BENIGN_FEATURES = {"ti_risk": 0.0, "zeek_lateral_moves": 0, "zeek_ja3_malicious": 0,
                    "zeek_ja4_malicious": 0, "zeek_honeypot_hits": 0, "abuseipdb_risk": 0.0,
                    "outbound_bytes_z": 0.0}

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: pure helper functions
# ═══════════════════════════════════════════════════════════════════════════════════

check("REGRESSION GUARD: the device-scoped hypothesis set is exactly the three "
      "DNS-evasion-family names that actually reach mark_false_positive() as a claim "
      "about THIS device's own DNS usage",
      DEVICE_SCOPED_TRUST_HYPOTHESES == frozenset({"DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS"}))

check("_trust_entry_ts() reads a legacy bare-float entry directly", _trust_entry_ts(1000.0) == 1000.0)
check("_trust_entry_ts() reads a dict entry's 'ts' key", _trust_entry_ts({"ts": 2000.0}) == 2000.0)
check("_trust_entry_ts() returns 0.0 (treated as already-expired) for a malformed dict, "
      "not a crash", _trust_entry_ts({"no_ts_key": True}) == 0.0)
check("_trust_entry_ts() returns 0.0 for a totally malformed value (e.g. a string), not a crash",
      _trust_entry_ts("not-a-number") == 0.0)

check("_trust_entry_ttl() falls back to the global default for a legacy bare-float entry",
      _trust_entry_ttl(500.0) == TRUST_CACHE_TTL_SECONDS)
check("_trust_entry_ttl() falls back to the global default for a dict with no ttl_seconds",
      _trust_entry_ttl({"ts": 500.0}) == TRUST_CACHE_TTL_SECONDS)
check("_trust_entry_ttl() honors a dict entry's own ttl_seconds",
      _trust_entry_ttl({"ts": 500.0, "ttl_seconds": 7200.0}) == 7200.0)
check("_trust_entry_ttl() ignores a non-positive ttl_seconds and falls back to the default "
      "(malformed data must not create a permanently-expired or infinite entry)",
      _trust_entry_ttl({"ts": 500.0, "ttl_seconds": -5.0}) == TRUST_CACHE_TTL_SECONDS)

check("_trust_entry_hypothesis_base() returns None for empty/missing input",
      _trust_entry_hypothesis_base("") is None and _trust_entry_hypothesis_base(None) is None)
check("_trust_entry_hypothesis_base() strips the persistence-escalation suffix",
      _trust_entry_hypothesis_base("DNS_EVASION (persisted 603s)") == "DNS_EVASION")
check("_trust_entry_hypothesis_base() passes an unsuffixed name through unchanged",
      _trust_entry_hypothesis_base("NETWORK_INTRUSION") == "NETWORK_INTRUSION")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: _immunize_domain() write path
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    fp._immunize_domain("scoped-example.com", "host1", source="llm_validated",
                         device_id="devA", hypothesis="DGA_BOTNET_C2", ttl_seconds=7200.0)
    entry = fp._trust_cache["scoped-example.com"]
    check("a scoped immunization writes a dict entry (not a bare float)", isinstance(entry, dict))
    check("the entry records the device_id that justified it", entry.get("device_id") == "devA")
    check("the entry records the hypothesis that justified it", entry.get("hypothesis") == "DGA_BOTNET_C2")
    check("the entry records the (in-range) ttl_seconds verbatim", entry.get("ttl_seconds") == 7200.0)

    fp._immunize_domain("clamped-low.com", "host1", device_id="devA", hypothesis="NETWORK_INTRUSION",
                         ttl_seconds=10.0)
    check("a too-small ttl_seconds is clamped UP to MIN_TRUST_ENTRY_TTL_SECONDS",
          fp._trust_cache["clamped-low.com"]["ttl_seconds"] == MIN_TRUST_ENTRY_TTL_SECONDS)

    fp._immunize_domain("clamped-high.com", "host1", device_id="devA", hypothesis="NETWORK_INTRUSION",
                         ttl_seconds=999999999.0)
    check("an absurdly-large ttl_seconds is clamped DOWN to MAX_TRUST_ENTRY_TTL_SECONDS",
          fp._trust_cache["clamped-high.com"]["ttl_seconds"] == MAX_TRUST_ENTRY_TTL_SECONDS)

    fp._immunize_domain("no-hint.com", "host1")
    check("an immunization with NO device_id/hypothesis/ttl_seconds still writes a valid "
          "(unscoped, wildcard) dict entry -- not a crash, not a bare float either",
          isinstance(fp._trust_cache["no-hint.com"], dict)
          and "device_id" not in fp._trust_cache["no-hint.com"]
          and "hypothesis" not in fp._trust_cache["no-hint.com"])

    is_new_1 = fp._immunize_domain("refresh-me.com", "host1", device_id="devA", hypothesis="DGA_BOTNET_C2")
    is_new_2 = fp._immunize_domain("refresh-me.com", "host1", device_id="devB", hypothesis="C2_BEACONING")
    check("REGRESSION GUARD: re-immunizing an existing domain still reports is_new=False "
          "(TTL refresh), even though the scope metadata changed",
          is_new_1 is True and is_new_2 is False)
    check("a refresh OVERWRITES the recorded scope with the latest call's values",
          fp._trust_cache["refresh-me.com"]["device_id"] == "devB"
          and fp._trust_cache["refresh-me.com"]["hypothesis"] == "C2_BEACONING")

    check("REGRESSION GUARD: invalid domain is still rejected outright, scoped or not",
          fp._immunize_domain("", "host1", device_id="devA", hypothesis="DGA_BOTNET_C2") is False)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: _is_trust_cached() -- the actual gate
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    # Non-device-scoped hypothesis: domain trust is SHARED across devices.
    fp._immunize_domain("shared-domain.com", "host1", device_id="devA", hypothesis="DGA_BOTNET_C2")
    check("same device, same hypothesis -> hit",
          fp._is_trust_cached("shared-domain.com", device_id="devA", hypothesis="DGA_BOTNET_C2") is True)
    check("DIFFERENT device, SAME (non-device-scoped) hypothesis -> still a hit -- domain "
          "trust for DGA_BOTNET_C2 is shared, not device-gated",
          fp._is_trust_cached("shared-domain.com", device_id="devB", hypothesis="DGA_BOTNET_C2") is True)
    check("THE CORE FIX: same device, DIFFERENT hypothesis -> MISS -- an immunization for "
          "one attack hypothesis no longer silently suppresses an unrelated one against "
          "the same domain",
          fp._is_trust_cached("shared-domain.com", device_id="devA", hypothesis="NETWORK_INTRUSION") is False)
    check("a persistence-escalated suffix on the CURRENT alert's hypothesis still matches "
          "the base name recorded at write time",
          fp._is_trust_cached("shared-domain.com", device_id="devA",
                               hypothesis="DGA_BOTNET_C2 (persisted 600s)") is True)

    # Device-scoped hypothesis: domain trust is per-device.
    fp._immunize_domain("device-scoped.com", "host1", device_id="devA", hypothesis="DNS_EVASION")
    check("device-scoped hypothesis: same device -> hit",
          fp._is_trust_cached("device-scoped.com", device_id="devA", hypothesis="DNS_EVASION") is True)
    check("THE CORE FIX (device gate): device-scoped hypothesis, DIFFERENT device -> MISS -- "
          "'this device's traffic wasn't preceded by its own DNS lookup' says nothing about "
          "a DIFFERENT device that DID properly resolve it",
          fp._is_trust_cached("device-scoped.com", device_id="devB", hypothesis="DNS_EVASION") is False)
    for h in ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS"):
        fp._immunize_domain(f"scoped-{h}.com", "host1", device_id="devA", hypothesis=h)
        check(f"{h}: different device -> MISS (device-gated)",
              fp._is_trust_cached(f"scoped-{h}.com", device_id="devB", hypothesis=h) is False)
        check(f"{h}: same device -> hit",
              fp._is_trust_cached(f"scoped-{h}.com", device_id="devA", hypothesis=h) is True)

    # Backward compatibility: a caller that doesn't pass device_id/hypothesis (or an
    # entry with none recorded) is unaffected -- this only NARROWS a hit, never widens
    # a rejection beyond what a caller actually asked to check.
    check("BACKWARD COMPAT: calling _is_trust_cached() with NO device_id/hypothesis at all "
          "(pre-Phase-52 call shape) still matches a scoped entry",
          fp._is_trust_cached("device-scoped.com") is True)
    fp._immunize_domain("no-hint2.com", "host1")
    check("BACKWARD COMPAT: an entry with no recorded hypothesis matches ANY current "
          "hypothesis (wildcard, same as an unscoped legacy entry)",
          fp._is_trust_cached("no-hint2.com", device_id="devZ", hypothesis="ANYTHING") is True)

    # Legacy bare-float entry (simulates a real pre-Phase-52 production trust cache).
    fp._trust_cache["legacy-float.com"] = time.time()
    check("BACKWARD COMPAT: a legacy bare-float entry matches regardless of the current "
          "alert's device/hypothesis -- unscoped, exactly as before this phase",
          fp._is_trust_cached("legacy-float.com", device_id="devZ", hypothesis="NETWORK_INTRUSION") is True)

    # Per-entry TTL expiry, independent of the 14-day global default.
    fp._immunize_domain("short-ttl.com", "host1", device_id="devA", hypothesis="NETWORK_INTRUSION",
                         ttl_seconds=3600.0)
    fp._trust_cache["short-ttl.com"]["ts"] = time.time() - 7200.0  # 2h old, TTL was 1h
    check("THE CORE FIX (per-entry TTL): an entry with a short ttl_seconds expires on its "
          "OWN schedule, even though the 14-day global default hasn't elapsed",
          fp._is_trust_cached("short-ttl.com", device_id="devA", hypothesis="NETWORK_INTRUSION") is False)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: end-to-end via evaluate()'s real trust-cache-hit path
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)
    fp._immunize_domain("e2e-scoped.com", "laptop", device_id="dev1", hypothesis="DNS_POLICY_BYPASS")

    alert_same_device = {
        "device": {"id": "dev1", "hostname": "laptop"},
        "network_context": {"queried_domain": "sub.e2e-scoped.com", "destination_ip": "1.2.3.4"},
        "signature": "DNS_POLICY_BYPASS",
    }
    verdict_same = fp.evaluate(alert_same_device, BENIGN_FEATURES, risk_score=6.5, ti_engine=None)
    check("end-to-end: same device + same device-scoped hypothesis -> TRUST_CACHE stage "
          "(suppressed via the fast path)",
          verdict_same["stage"] == "TRUST_CACHE", f"got {verdict_same}")

    alert_other_device = {
        "device": {"id": "dev2", "hostname": "phone"},
        "network_context": {"queried_domain": "sub.e2e-scoped.com", "destination_ip": "1.2.3.4"},
        "signature": "DNS_POLICY_BYPASS",
    }
    verdict_other = fp.evaluate(alert_other_device, BENIGN_FEATURES, risk_score=6.5, ti_engine=None)
    check("THE CORE FIX end-to-end: a DIFFERENT device hitting the SAME domain under the "
          "SAME device-scoped hypothesis does NOT get the fast-path TRUST_CACHE stage -- "
          "it falls through to a real Stage 1/2/3 evaluation instead",
          verdict_other["stage"] != "TRUST_CACHE", f"got {verdict_other}")

    alert_other_hypothesis = {
        "device": {"id": "dev1", "hostname": "laptop"},
        "network_context": {"queried_domain": "sub.e2e-scoped.com", "destination_ip": "1.2.3.4"},
        "signature": "NETWORK_INTRUSION",
    }
    verdict_diff_hyp = fp.evaluate(alert_other_hypothesis, BENIGN_FEATURES, risk_score=6.5, ti_engine=None)
    check("THE CORE FIX end-to-end: the SAME device, but a DIFFERENT (unrelated) hypothesis "
          "against the same domain, also does NOT reuse the cache",
          verdict_diff_hyp["stage"] != "TRUST_CACHE", f"got {verdict_diff_hyp}")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: mark_false_positive() actually threads device_id/hypothesis/ttl_seconds
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)
    alert_payload = {
        "device": {"id": "dev_mfp", "hostname": "nas1"},
        "network_context": {"queried_domain": "corrected.example.com", "destination_ip": "9.8.7.6"},
        "signature": "DGA_BOTNET_C2",
        "timestamp": time.time(),
    }
    result = fp.mark_false_positive(alert_payload, "nas1", "corrected.example.com",
                                     source="llm_validated", ttl_seconds=86400.0)
    entry = fp._trust_cache.get(result["base_domain"])
    check("mark_false_positive() threads device_id through to the trust-cache entry",
          isinstance(entry, dict) and entry.get("device_id") == "dev_mfp", f"entry={entry}")
    check("mark_false_positive() threads the alert's own signature through as the "
          "entry's hypothesis",
          isinstance(entry, dict) and entry.get("hypothesis") == "DGA_BOTNET_C2", f"entry={entry}")
    check("mark_false_positive() threads the LLM-supplied ttl_seconds through (in range, "
          "unclamped)",
          isinstance(entry, dict) and entry.get("ttl_seconds") == 86400.0, f"entry={entry}")

    # An operator correction (no ttl_seconds passed) must fall back to the global default,
    # not error and not leave a stale/zero TTL. Uses a domain with a DISTINCT eTLD+1 from
    # Section E's first case ("corrected.example.com" -> base domain "example.com") so the
    # two corrections don't collide on the same trust-cache key.
    alert_operator = {
        "device": {"id": "dev_op", "hostname": "desktop1"},
        "network_context": {"queried_domain": "operator-corrected.example.net", "destination_ip": "2.2.2.2"},
        "signature": "NETWORK_INTRUSION",
        "timestamp": time.time(),
    }
    op_result = fp.mark_false_positive(alert_operator, "desktop1", "operator-corrected.example.net", source="operator")
    op_entry = fp._trust_cache.get(op_result["base_domain"])
    check("REGRESSION GUARD: an operator correction (no ttl_seconds) still writes a valid "
          "entry with no explicit ttl_seconds override -- falls back to the 14-day global "
          "default via _trust_entry_ttl(), not an error",
          isinstance(op_entry, dict) and "ttl_seconds" not in op_entry, f"entry={op_entry}")
    check("REGRESSION GUARD: the operator-corrected domain is still visible via "
          "get_dynamic_trust_cache() (that consumer stays unscoped/unaffected)",
          op_result["base_domain"] in fp.get_dynamic_trust_cache())

# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: mixed on-disk cache (old float entries + new dict entries) loads cleanly
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    cache_path = _PathForSysPath(tmpdir) / "fp_trust_cache.json"
    now = time.time()
    cache_path.write_text(json.dumps({
        "legacy-domain.com": now - 3600,  # bare float, exactly a pre-Phase-52 entry
        "scoped-domain.com": {"ts": now - 3600, "device_id": "devX", "hypothesis": "DGA_BOTNET_C2",
                               "source": "llm_validated", "ttl_seconds": 86400.0},
        "expired-legacy.com": now - (15 * 24 * 3600),  # older than the 14-day default -> pruned
    }), encoding="utf-8")

    fp2 = AutonomousFPEngine(config={}, state_dir=tmpdir)
    check("THE CORE FIX (mixed load): a live upgrade's mixed float+dict trust cache loads "
          "without crashing",
          "legacy-domain.com" in fp2._trust_cache and "scoped-domain.com" in fp2._trust_cache,
          f"trust_cache keys={list(fp2._trust_cache.keys())}")
    check("a loaded legacy float entry still behaves as an unscoped wildcard",
          fp2._is_trust_cached("legacy-domain.com", device_id="anyone", hypothesis="ANYTHING") is True)
    check("a loaded scoped dict entry still enforces its recorded hypothesis on reuse",
          fp2._is_trust_cached("scoped-domain.com", device_id="devX", hypothesis="NETWORK_INTRUSION") is False)
    check("REGRESSION GUARD: an entry older than the 14-day global default is still "
          "pruned at load time (unaffected by the new per-entry TTL logic)",
          "expired-legacy.com" not in fp2._trust_cache)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section G: source-level wiring checks
# ═══════════════════════════════════════════════════════════════════════════════════
_fp_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "intelligence" / "fp_engine.py").read_text(encoding="utf-8")

check("evaluate()'s trust-cache-hit check passes device_id=/hypothesis= into "
      "_is_trust_cached() (not a bare domain-only call that could silently drift back "
      "to the pre-Phase-52 unscoped behavior)",
      _fp_src.count("_is_trust_cached(base_domain, device_id=device_id, hypothesis=alert_hypothesis)") == 1
      and _fp_src.count("_is_trust_cached(dest_ip, device_id=device_id, hypothesis=alert_hypothesis)") == 1)

check("all THREE _immunize_domain() call sites inside mark_false_positive() pass "
      "hypothesis=signature (DNS_EVASION-family branch, generic domain branch, and its "
      "IP fallback) -- not just one of them",
      _fp_src.count("hypothesis=signature,") == 3)

check("all THREE _immunize_domain() call sites inside mark_false_positive() also pass "
      "device_id=device_id and ttl_seconds=ttl_seconds",
      _fp_src.count("device_id=device_id,") >= 3 and _fp_src.count("ttl_seconds=ttl_seconds,") == 3)

# PHASE 63b's ollama_soc.py raw_ttl/adjusted_ttl -> mark_false_positive() wiring
# [RETIRED]: ollama_soc.py was deleted 2026-09-22 (commit 57c9c4a, "consolidate Layer-3
# LLM review onto live_llm_review.py"). Its successor is advisory/reporting-only by
# design and never calls mark_false_positive() at all (confirmed: no reference in
# live_llm_review.py) -- that autonomous-correction authority moved to argus/autotune/
# engine.py + argus/cl_afpe/composite_trust.py, neither of which threads an LLM-supplied
# ttl_seconds through this same path. This check has no live equivalent and was removed.

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 52 scoped-trust-cache checks PASSED.")
