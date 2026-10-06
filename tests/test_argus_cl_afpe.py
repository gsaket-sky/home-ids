"""
Standalone runtime test for v13's CL-AFPE (src/v13/cl_afpe/engine.py, Phase 4 --
Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: graph-native trust caching (immunize/is_trust_cached/get_dynamic_trust_cache/
revoke), TTL clamping and expiry, DEVICE_SCOPED_TRUST_HYPOTHESES device-scoping vs.
globally-shared trust, mark_false_positive()'s two refusal guards (device-identity,
hard-stop-signature) and default domain/IP routing, and baseline familiarity.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_cl_afpe.py`
"""
import sys
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.graph.store import GraphStore  # noqa: E402
from argus.cl_afpe.engine import ClAfpeEngine, MIN_TRUST_ENTRY_TTL_SECONDS, MAX_TRUST_ENTRY_TTL_SECONDS  # noqa: E402
from argus.cl_afpe import composite_trust as ct  # noqa: E402
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402

tmpdir = tempfile.mkdtemp(prefix="v13_clafpe_test_")
db_path = str(_PathForSysPath(tmpdir) / "test_clafpe.db")
store = GraphStore(db_path)
cl_afpe = ClAfpeEngine(store)

NOW = 1_000_000.0

# --- basic immunize / is_trust_cached / get_dynamic_trust_cache ---
is_new = cl_afpe.immunize("evil.example.com", device_id="dev1", hypothesis="NETWORK_INTRUSION", now=NOW)
check("first immunization of a destination is reported as new", is_new is True)

is_new_refresh = cl_afpe.immunize("evil.example.com", device_id="dev1", hypothesis="NETWORK_INTRUSION", now=NOW + 10)
check("re-immunizing the same destination is reported as a refresh, not new", is_new_refresh is False)

check("get_dynamic_trust_cache includes the immunized destination, globally unscoped",
      "evil.example.com" in cl_afpe.get_dynamic_trust_cache(now=NOW + 20))

check("is_trust_cached matches on the same hypothesis",
      cl_afpe.is_trust_cached("evil.example.com", hypothesis="NETWORK_INTRUSION", now=NOW + 20))
check("is_trust_cached does NOT match on a DIFFERENT hypothesis for a non-device-scoped destination",
      not cl_afpe.is_trust_cached("evil.example.com", hypothesis="DGA_BOTNET_C2", now=NOW + 20))
check("is_trust_cached returns False for a destination never immunized",
      not cl_afpe.is_trust_cached("never-seen.example.com", now=NOW))

# --- revoke ---
revoked = cl_afpe.revoke("evil.example.com")
check("revoke() removes an existing immunization and reports True", revoked is True)
check("the destination is no longer trust-cached after revoke",
      not cl_afpe.is_trust_cached("evil.example.com", hypothesis="NETWORK_INTRUSION", now=NOW + 20))
revoked_again = cl_afpe.revoke("evil.example.com")
check("revoking an already-revoked destination reports False, not an error", revoked_again is False)

# --- TTL clamping ---
cl_afpe.immunize("short-ttl.example.com", ttl_seconds=1, now=NOW)  # far below the 1hr floor
edges = store.get_edges(relation="trusts", dst_id="short-ttl.example.com")
check("a too-short requested TTL is clamped up to the 1-hour floor",
      edges[0]["metadata"]["ttl_seconds"] == MIN_TRUST_ENTRY_TTL_SECONDS)

cl_afpe.immunize("long-ttl.example.com", ttl_seconds=999_999_999, now=NOW)  # far above the 14-day ceiling
edges2 = store.get_edges(relation="trusts", dst_id="long-ttl.example.com")
check("a too-long requested TTL is clamped down to the 14-day ceiling",
      edges2[0]["metadata"]["ttl_seconds"] == MAX_TRUST_ENTRY_TTL_SECONDS)

# ttl_seconds must be >= MIN_TRUST_ENTRY_TTL_SECONDS (3600s) or it gets clamped up
# to that floor (already verified above) -- use exactly the floor value here so
# expiry can be tested within a reasonable time offset.
cl_afpe.immunize("short-lived.example.com", ttl_seconds=MIN_TRUST_ENTRY_TTL_SECONDS, now=NOW)
check("a destination immunized with the minimum custom TTL is still cached just after immunization",
      cl_afpe.is_trust_cached("short-lived.example.com", now=NOW + 50))
check("...but expires once its own custom TTL has passed",
      not cl_afpe.is_trust_cached("short-lived.example.com", now=NOW + MIN_TRUST_ENTRY_TTL_SECONDS + 10))

# --- invalid destination rejection ---
check("an empty destination is rejected outright", cl_afpe.immunize("", now=NOW) is False)
check("the NO_DESTINATION sentinel is rejected outright", cl_afpe.immunize("(none)", now=NOW) is False)
check("the literal string 'unknown' is rejected outright", cl_afpe.immunize("unknown", now=NOW) is False)

# --- DEVICE_SCOPED_TRUST_HYPOTHESES: device-specific vs globally-shared trust ---
cl_afpe.immunize("shared-dest.example.com", device_id="devA", hypothesis="NETWORK_INTRUSION", now=NOW)
check("a non-device-scoped hypothesis (NETWORK_INTRUSION) shares trust across devices",
      cl_afpe.is_trust_cached("shared-dest.example.com", device_id="devB", hypothesis="NETWORK_INTRUSION", now=NOW))

cl_afpe.immunize("device-specific.example.com", device_id="devA", hypothesis="DNS_EVASION", now=NOW)
check("a DEVICE_SCOPED_TRUST_HYPOTHESES hypothesis (DNS_EVASION) is trusted for the SAME device",
      cl_afpe.is_trust_cached("device-specific.example.com", device_id="devA", hypothesis="DNS_EVASION", now=NOW))
check("...but NOT trusted for a DIFFERENT device -- the actual point of device-scoping",
      not cl_afpe.is_trust_cached("device-specific.example.com", device_id="devB", hypothesis="DNS_EVASION", now=NOW))

# --- mark_false_positive: device-identity refusal ---
store.upsert_device("known_device", timestamp=NOW)
refused_unknown_device = cl_afpe.mark_false_positive(
    {"signature": "NETWORK_INTRUSION", "device": {"id": "phantom_device"},
     "network_context": {"queried_domain": "x.com"}},
    now=NOW,
)
check("mark_false_positive refuses a device_id that doesn't resolve to a known canonical device",
      refused_unknown_device.refused and "phantom_device" in refused_unknown_device.refused_reason)

ok_known_device = cl_afpe.mark_false_positive(
    {"signature": "NETWORK_INTRUSION", "device": {"id": "known_device"},
     "network_context": {"queried_domain": "corrected.example.com"}},
    now=NOW,
)
check("mark_false_positive proceeds normally for a known canonical device",
      not ok_known_device.refused and ok_known_device.is_new_immunization)

unknown_device_id_noop = cl_afpe.mark_false_positive(
    {"signature": "NETWORK_INTRUSION", "device": {"id": "unknown"},
     "network_context": {"queried_domain": "x2.example.com"}},
    now=NOW,
)
check("device_id=='unknown' is never refused by the identity check (nothing to validate against)",
      not unknown_device_id_noop.refused)

# --- mark_false_positive: hard-stop-signature refusal ---
for hard_stop_sig in ("Internal Honeypot Accessed", "Layer-2 ARP Spoofing Detected",
                       "Geofencing Policy Violation", "Confirmed Malicious IOC"):
    r = cl_afpe.mark_false_positive(
        {"signature": hard_stop_sig, "device": {"id": "known_device"},
         "network_context": {"queried_domain": "x.com"}},
        now=NOW,
    )
    check(f"mark_false_positive refuses the hard-stop signature '{hard_stop_sig}'",
          r.refused and hard_stop_sig in r.refused_reason)

# --- mark_false_positive: default domain vs IP routing ---
# BUGFIX (Phase 6e): immunizes the eTLD+1 BASE domain, matching v1 exactly and
# matching evaluate()'s own trust-cache lookup (see mark_false_positive()'s own
# comment on this branch for the full explanation) -- a THREE-label input
# ("sub.domain-route-example.com") would immunize as its base
# ("domain-route-example.com"), so this test uses a domain that IS its own base
# to keep the assertion a direct string match.
domain_route = cl_afpe.mark_false_positive(
    {"signature": "NETWORK_INTRUSION", "device": {"id": "known_device"},
     "network_context": {"queried_domain": "domain-route-example.com"}},
    now=NOW,
)
check("a correction with a real queried_domain immunizes that domain's eTLD+1 base",
      domain_route.immunized_destination == "domain-route-example.com")

ip_route = cl_afpe.mark_false_positive(
    {"signature": "NETWORK_INTRUSION", "device": {"id": "known_device"},
     "network_context": {"queried_domain": "unknown", "destination_ip": "203.0.113.5"}},
    now=NOW,
)
check("a correction with no usable domain falls back to immunizing the raw destination_ip "
      "-- the live-audit bugfix this module ports exactly",
      ip_route.immunized_destination == "203.0.113.5")

no_target = cl_afpe.mark_false_positive(
    {"signature": "NETWORK_INTRUSION", "device": {"id": "known_device"}, "network_context": {}},
    now=NOW,
)
check("a correction with no usable domain AND no usable IP takes no immunization action, "
      "without erroring", not no_target.refused and not no_target.is_new_immunization)

# --- baseline familiarity ---
check("an unobserved device/port combination has zero familiarity",
      cl_afpe.get_baseline_familiarity("dev_new", dest_port=443) == 0.0)

for _ in range(3):
    cl_afpe.record_baseline_observation("dev_fam", dest_port=443)
check("3 of 5 needed observations gives partial (0.6) familiarity",
      abs(cl_afpe.get_baseline_familiarity("dev_fam", dest_port=443) - 0.6) < 1e-9)

for _ in range(10):
    cl_afpe.record_baseline_observation("dev_fam", dest_port=443)
check("familiarity caps at 1.0 even with many more observations than the threshold",
      cl_afpe.get_baseline_familiarity("dev_fam", dest_port=443) == 1.0)

check("familiarity is per-identity-dimension -- an unrelated ASN owner on the same device stays at 0",
      cl_afpe.get_baseline_familiarity("dev_fam", asn_owner="SomeOtherASN") == 0.0)
check("an unknown device_id always returns 0 familiarity, never crashes", cl_afpe.get_baseline_familiarity("unknown") == 0.0)

# --- Phase 6c: sigma-shift widening ---
check("a device never corrected has zero sigma shift", cl_afpe.get_sigma_shift("sigma_dev") == 0.0)

cl_afpe._apply_sigma_shift("sigma_dev", now=NOW)  # default direction: TUNE_DOWN
check("a single TUNE_DOWN (correction) widens the shift by exactly SIGMA_WIDENING_STEP (0.25)",
      abs(cl_afpe.get_sigma_shift("sigma_dev") - 0.25) < 1e-9)

for _ in range(20):
    cl_afpe._apply_sigma_shift("sigma_dev", now=NOW)
check("repeated TUNE_DOWN widening is capped at MAX_SIGMA_SHIFT (2.0), never exceeds it",
      cl_afpe.get_sigma_shift("sigma_dev") == 2.0)

cl_afpe._apply_sigma_shift("sigma_dev", direction="TUNE_UP", now=NOW)
check("a single TUNE_UP (confirmed threat) tightens by the flat step (0.50), NOT the "
      "widening step -- the asymmetry is real, confirmed via direct read of fp_engine.py",
      abs(cl_afpe.get_sigma_shift("sigma_dev") - 1.5) < 1e-9)

for _ in range(20):
    cl_afpe._apply_sigma_shift("sigma_dev", direction="TUNE_UP", now=NOW)
check("repeated TUNE_UP tightening is floored at -1.5, never goes lower",
      cl_afpe.get_sigma_shift("sigma_dev") == -1.5)

check("an 'unknown' device_id is a no-op for _apply_sigma_shift, never raises",
      cl_afpe._apply_sigma_shift("unknown", now=NOW) is None
      and cl_afpe.get_sigma_shift("unknown") == 0.0)

# mark_false_positive applies sigma-shift unconditionally, regardless of branch --
# confirmed against BOTH the default domain-routing branch (already exercised above
# by domain_route) and the new CONNECTION_ABUSE branch (exercised below).
check("mark_false_positive's default domain-routing branch also widened this device's "
      "sigma shift as a side effect (matches v1's own 'runs regardless of which "
      "branch fired' placement)",
      cl_afpe.get_sigma_shift("known_device") > 0.0)

# --- Phase 6a: per-device threshold bumping (CONNECTION_ABUSE/PORT_SCAN/INTERNAL_RECONNAISSANCE) ---
check("a device with no correction history yet returns the caller-supplied default threshold",
      cl_afpe.get_device_arp_sweep_threshold("thresh_dev", default=8.0) == 8.0
      and cl_afpe.get_device_conn_abuse_unique_ip_threshold("thresh_dev", default=5.0) == 5.0
      and cl_afpe.get_device_long_conn_duration_threshold("thresh_dev", default=14400.0) == 14400.0)

store.upsert_device("thresh_dev", timestamp=NOW)
arp_only = cl_afpe.mark_false_positive(
    {"signature": "INTERNAL_RECONNAISSANCE", "device": {"id": "thresh_dev", "hostname": "thresh-host"},
     "network_context": {}, "features": {"zeek_arp_sweep_count": 3}},
    now=NOW,
)
check("mark_false_positive reports threshold_bumped=True for a CONNECTION_ABUSE-family signature",
      arp_only.threshold_bumped and not arp_only.refused)
check("...and does NOT also attempt domain/IP immunization (the branches are mutually "
      "exclusive -- the real v1 bugfix this port exists to preserve)",
      arp_only.immunized_destination == "" and not arp_only.is_new_immunization)
check("ONLY the arp_sweep threshold was bumped (arp_count>0, the other two conditions "
      "weren't true for this alert) -- the real v1 bugfix: bump only what actually fired",
      cl_afpe.get_device_arp_sweep_threshold("thresh_dev", default=8.0) == 12.0
      and cl_afpe.get_device_conn_abuse_unique_ip_threshold("thresh_dev", default=5.0) == 5.0
      and cl_afpe.get_device_long_conn_duration_threshold("thresh_dev", default=14400.0) == 14400.0)

store.upsert_device("thresh_dev2", timestamp=NOW)
multi_bump = cl_afpe.mark_false_positive(
    {"signature": "CONNECTION_ABUSE", "device": {"id": "thresh_dev2", "hostname": "thresh-host2"},
     "network_context": {}, "features": {
         "zeek_s0_rej_count": 30, "zeek_s0_rej_unique_ips": 10,
         "zeek_max_duration": 20000.0, "zeek_arp_sweep_count": 0,
     }},
    now=NOW,
)
check("multiple simultaneously-true conditions bump multiple thresholds in one call "
      "(conn-abuse-unique-ip AND long-conn, arp_sweep excluded since its own count was 0)",
      cl_afpe.get_device_conn_abuse_unique_ip_threshold("thresh_dev2", default=5.0) == 9.0
      and cl_afpe.get_device_long_conn_duration_threshold("thresh_dev2", default=14400.0) == 21600.0
      and cl_afpe.get_device_arp_sweep_threshold("thresh_dev2", default=8.0) == 8.0)

store.upsert_device("thresh_dev3", timestamp=NOW)
no_condition_true = cl_afpe.mark_false_positive(
    {"signature": "PORT_SCAN", "device": {"id": "thresh_dev3"},
     "network_context": {}, "features": {}},
    now=NOW,
)
check("when NONE of the three conditions hold (empty features), falls back to the old "
      "blanket behavior (bump arp_sweep anyway) rather than silently doing nothing, "
      "matching v1 exactly", no_condition_true.threshold_bumped
      and cl_afpe.get_device_arp_sweep_threshold("thresh_dev3", default=8.0) == 12.0)

store.upsert_device("thresh_dev4", timestamp=NOW)
bump_repeat = cl_afpe.mark_false_positive(
    {"signature": "INTERNAL_RECONNAISSANCE", "device": {"id": "thresh_dev4"},
     "network_context": {}, "features": {"zeek_arp_sweep_count": 1}},
    now=NOW,
)
cl_afpe.mark_false_positive(
    {"signature": "INTERNAL_RECONNAISSANCE", "device": {"id": "thresh_dev4"},
     "network_context": {}, "features": {"zeek_arp_sweep_count": 1}},
    now=NOW,
)
check("a SECOND correction for the same device/key builds on the ALREADY-BUMPED value, "
      "not the original default (12.0 -> 16.0, not 8.0 -> 12.0 again)",
      cl_afpe.get_device_arp_sweep_threshold("thresh_dev4", default=8.0) == 16.0)
check("correction_count increments across repeated corrections to the same key",
      store.get_device_metadata("thresh_dev4")["fp_profile"]["arp_sweep_unique_targets_threshold"]["correction_count"] == 2)

# --- Phase 6b: local-intel poisoning protection ---

# _is_ip_protected_from_confirmed_intel: every guard, matching the real production
# incidents fp_engine.py's own docstring documents.
cl_afpe_no_intel = ClAfpeEngine(store)  # local_intel=None -- the safe-default case
check("a known public DNS resolver (8.8.8.8) is always protected",
      cl_afpe_no_intel._is_ip_protected_from_confirmed_intel("8.8.8.8"))
check("an IP explicitly listed in safe_ips is protected",
      ClAfpeEngine(store, safe_ips={"192.168.1.94"})._is_ip_protected_from_confirmed_intel("192.168.1.94"))
check("a cloud/CDN-owned ASN is protected when asn_owner is supplied",
      cl_afpe_no_intel._is_ip_protected_from_confirmed_intel("35.186.224.24", asn_owner="Google LLC"))
check("a private LAN IP is protected", cl_afpe_no_intel._is_ip_protected_from_confirmed_intel("192.168.1.1"))
check("a multicast address (mDNS) is protected", cl_afpe_no_intel._is_ip_protected_from_confirmed_intel("224.0.0.251"))
check("an ordinary public IP with no protection reason is NOT protected",
      not cl_afpe_no_intel._is_ip_protected_from_confirmed_intel("93.184.216.34"))
check("'unknown'/empty IPs are never protected (nothing to protect)",
      not cl_afpe_no_intel._is_ip_protected_from_confirmed_intel("unknown")
      and not cl_afpe_no_intel._is_ip_protected_from_confirmed_intel(""))

# record_confirmed_threat / check_local_intel_hard_stop with NO LocalConfirmedIntel
# injected -- a safe no-op throughout, never raises.
cl_afpe_no_intel.record_confirmed_threat("dev_x", "evil-noop.example.com", "203.0.113.9", reason="test")
check("record_confirmed_threat with local_intel=None is a safe no-op",
      cl_afpe_no_intel.check_local_intel_hard_stop("evil-noop.example.com", "203.0.113.9") is None)

# record_confirmed_threat / check_local_intel_hard_stop with a REAL LocalConfirmedIntel
local_intel_dir = _PathForSysPath(tempfile.mkdtemp(prefix="v13_clafpe_local_intel_"))
real_local_intel = LocalConfirmedIntel(str(local_intel_dir))
cl_afpe_intel = ClAfpeEngine(store, local_intel=real_local_intel, safe_ips={"192.168.1.94"})

check("check_local_intel_hard_stop finds nothing before any confirmation is recorded",
      cl_afpe_intel.check_local_intel_hard_stop("evil-confirmed.example.com", "104.16.132.229") is None)

cl_afpe_intel.record_confirmed_threat("dev_a", "evil-confirmed.example.com", "104.16.132.229", reason="Stage-1 test")
domain_hit = cl_afpe_intel.check_local_intel_hard_stop("evil-confirmed.example.com", "unknown")
check("a domain confirmed by one device is found by check_local_intel_hard_stop for "
      "a DIFFERENT device querying the SAME domain -- the actual network-wide "
      "propagation point of this whole mechanism",
      domain_hit is not None and domain_hit["kind"] == "domain" and domain_hit["target"] == "evil-confirmed.example.com")

ip_hit = cl_afpe_intel.check_local_intel_hard_stop(None, "104.16.132.229")
check("the same confirmation is ALSO found via its IP independently",
      ip_hit is not None and ip_hit["kind"] == "ip" and ip_hit["target"] == "104.16.132.229")

# write-side telemetry-domain guard
cl_afpe_intel.record_confirmed_threat("dev_b", "sentry.io", "unknown", reason="mis-attributed")
check("record_confirmed_threat REFUSES to write a known-telemetry base domain as "
      "confirmed-malicious -- the real live-incident guard this ports",
      cl_afpe_intel.check_local_intel_hard_stop("sentry.io", None) is None)

# write-side protected-IP guard (safe_ips)
cl_afpe_intel.record_confirmed_threat("dev_c", None, "192.168.1.94", reason="mis-attributed")
check("record_confirmed_threat REFUSES to write a safe_ips-protected IP as "
      "confirmed-malicious",
      cl_afpe_intel.check_local_intel_hard_stop(None, "192.168.1.94") is None)

# read-side re-check: an entry that got into the store SOME OTHER WAY (bypassing
# record_confirmed_threat()'s own write guard entirely -- e.g. written directly, or
# recorded before this project's own telemetry allowlist grew to cover it) still
# doesn't get honored -- the real v1 fix: "stops being honored immediately, without
# needing to hand-edit the state file," not just "never written going forward."
real_local_intel.record("domain", "sentry.io", "dev_d", reason="pre-existing, bypassed the write guard")
check("check_local_intel_hard_stop re-applies the telemetry guard on the READ side "
      "independently of the write guard -- an entry that got in some other way "
      "still doesn't match",
      cl_afpe_intel.check_local_intel_hard_stop("sentry.io", None) is None)

# --- Phase 6e: composed evaluate() -------------------------------------------
# Uses `cl_afpe` (module-level, no local_intel/ml_scorer -- ml_scorer=None means
# Stage 2 is always the neutral 0.50 sentinel and Stage 3 always uses the static
# rule fallback, both deterministic, matching v1's own real "model not ready yet"
# behavior rather than requiring a real ONNX/FastEmbed model for this test file).
store.upsert_device("shadow_dev", timestamp=NOW)


def _alert(device_id="shadow_dev", hostname="shadow-host", signature="NETWORK_INTRUSION",
           domain="", dest_ip="", features=None):
    return {
        "signature": signature,
        "device": {"id": device_id, "hostname": hostname},
        "network_context": {"queried_domain": domain, "destination_ip": dest_ip},
        "features": features or {},
    }


def _evaluate(engine, alert_payload, decision=None, asn_owner="", now=NOW):
    # Matches fp_engine.py's real evaluate(alert_payload, features, ...) shape:
    # `features` is its OWN top-level parameter (Stage 1/2/3 all read from it),
    # separate from alert_payload["features"] (which ONLY mark_false_positive()'s
    # CONNECTION_ABUSE branch reads, via its own alert_payload.get("features", {})
    # lookup) -- both must carry the SAME dict for a realistic test.
    return engine.evaluate(alert_payload, alert_payload["features"], decision=decision,
                             asn_owner=asn_owner, now=now)


# Check 0: v13's own decision state reused as a hard-stop trigger.
v = _evaluate(cl_afpe, _alert(domain="unknown"), decision={"state": "CRITICAL", "explanation": "honeypot"})
check("evaluate() Check 0 hard-stops on v13's own decision state == CRITICAL",
      v["verdict"] == "CONFIRMED_THREAT" and v["stage"] == "STAGE_1_HARD_STOP"
      and any("HEE hard-stop verdict" in r for r in v["reasons"]))

# Check 1: ThreatIntel IOC (ti_risk > 2.0).
v = _evaluate(cl_afpe, _alert(features={"ti_risk": 3.0}))
check("evaluate() Check 1 hard-stops on ti_risk > 2.0",
      v["verdict"] == "CONFIRMED_THREAT" and any("ThreatIntel IOC" in r for r in v["reasons"]))
v = _evaluate(cl_afpe, _alert(features={"ti_risk": 1.5}))
check("...but NOT at ti_risk <= 2.0 (falls through toward Stage 2/3)",
      v["stage"] != "STAGE_1_HARD_STOP")

# Check 2: lateral movement, gated on DISTINCT targets, not raw connection count.
v = _evaluate(cl_afpe, _alert(features={"zeek_lateral_moves": 1, "zeek_lateral_unique_targets": 1}))
check("evaluate() Check 2 does NOT hard-stop on a single connection to ONE target "
      "(the real v1 bugfix: a lone SMB/SSH/RDP connection is not 'movement')",
      v["stage"] != "STAGE_1_HARD_STOP")
v = _evaluate(cl_afpe, _alert(features={"zeek_lateral_moves": 3, "zeek_lateral_unique_targets": 2}))
check("evaluate() Check 2 DOES hard-stop once the distinct-target threshold is met",
      v["verdict"] == "CONFIRMED_THREAT" and any("lateral movement" in r for r in v["reasons"]))

# Check 3: malicious JA3/JA4 TLS fingerprint.
v = _evaluate(cl_afpe, _alert(features={"zeek_ja4_malicious": 1}))
check("evaluate() Check 3 (B1): a malicious JA4+ fingerprint ALONE is not a hard stop",
      v["stage"] != "STAGE_1_HARD_STOP")
v = _evaluate(cl_afpe, _alert(features={"zeek_ja4_malicious": 1, "ti_risk": 0.5}))
check("evaluate() Check 3 hard-stops on a malicious JA4+ fingerprint corroborated by a reputation score",
      v["verdict"] == "CONFIRMED_THREAT" and any("TLS fingerprint" in r for r in v["reasons"]))

# Check 4: honeypot.
v = _evaluate(cl_afpe, _alert(features={"zeek_honeypot_hits": 1}))
check("evaluate() Check 4 hard-stops on any honeypot hit",
      v["verdict"] == "CONFIRMED_THREAT" and any("honeypot" in r for r in v["reasons"]))

# Check 5: AbuseIPDB.
v = _evaluate(cl_afpe, _alert(features={"abuseipdb_risk": 4.0}))
check("evaluate() Check 5 hard-stops at abuseipdb_risk >= 4.0",
      v["verdict"] == "CONFIRMED_THREAT" and any("AbuseIPDB" in r for r in v["reasons"]))

# Check 6: exfiltration burst -- absolute-byte floor AND telemetry/CDN exemption.
v = _evaluate(cl_afpe, _alert(domain="random-nonvendor-xyz.example.net",
                                features={"outbound_bytes_z": 9.0, "zeek_outbound_bytes": 5_000_000}))
check("evaluate() Check 6 hard-stops on a genuine exfiltration burst (real destination)",
      v["verdict"] == "CONFIRMED_THREAT" and any("Exfiltration" in r for r in v["reasons"]))
# Deliberately a signature OTHER than "sentry.io"'s later tests' default
# ("NETWORK_INTRUSION") -- this exemption check reaches Stage 2/3 (Check 6 doesn't
# hard-stop) and, at combined=0.92, DOES suppress+immunize sentry.io as a real side
# effect; a different hypothesis here means that immunization can never satisfy
# is_trust_cached()'s hypothesis-match for the dedicated Stage 2/3 tests below,
# which need to reach Stage 2/3 fresh, not short-circuit via an already-warm cache.
v = _evaluate(cl_afpe, _alert(signature="EXFIL_EXEMPTION_CHECK", domain="sentry.io",
                                features={"outbound_bytes_z": 9.0, "zeek_outbound_bytes": 5_000_000}))
check("...but the SAME burst on a known telemetry domain is exempt (real v1 bugfix "
      "this port preserves -- an AWS IoT/MQTT-shaped connection must not hard-stop "
      "purely off a z-score)",
      v["stage"] != "STAGE_1_HARD_STOP")

# --- trust-cache fast path, wired through the composed evaluate() ---
# Release 15 Sheet 03b, HARD-GATED (2026-09-15): trust-cache alone is no longer
# sufficient -- composite_trust.permits_suppression() must also independently
# agree, or evaluate() falls through to full Stage 1/2/3 instead of suppressing.
# A SEPARATE device for this pre-check specifically -- falling through now reaches
# Stage 3 and may itself call _apply_sigma_shift(TUNE_UP), which would otherwise
# mutate "shadow_dev"'s cumulative sigma-shift state out from under the later,
# pre-existing "tunes sensitivity UP" assertion below (that one depends on
# capturing sigma_before immediately prior to its own single TUNE_UP event).
store.upsert_device("shadow_dev_precheck", timestamp=NOW)
cl_afpe.immunize("trusted-vendor-example.com", device_id="shadow_dev_precheck", hypothesis="NETWORK_INTRUSION", now=NOW)
v = _evaluate(cl_afpe, _alert(device_id="shadow_dev_precheck", domain="trusted-vendor-example.com"))
check("evaluate() does NOT suppress on trust-cache alone anymore -- composite_trust "
      "hasn't corroborated this tuple yet, so it fails open to full evaluation "
      "(THE hard-gate behavior, not the pre-2026-09-15 shadow-only one)",
      v["stage"] != "TRUST_CACHE")

cl_afpe.immunize("trusted-vendor-example.com", device_id="shadow_dev", hypothesis="NETWORK_INTRUSION", now=NOW)

# Seed composite_trust with 2 DISTINCT evidence families, each past the trust floor
# (0.6, needs ceil(0.6/0.15)=4 calls at _TRUST_INCREMENT=0.15 each) for the EXACT
# tuple this alert/decision=None combination resolves to: behavior_fingerprint
# "NORMAL" (derive_activity_state([]) with no decision passed), destination_class
# "public" (no dest_ip, "trusted-vendor-example.com" isn't a known telemetry
# domain), hypothesis "NETWORK_INTRUSION" (the alert's default signature),
# regime_id 0 (this file's fixed default until Sheet 00 baseline ever runs here).
# cl_afpe_trust.hypothesis_id is a real FK against the hypotheses catalog (same
# pattern test_argus_cl_afpe_composite_trust.py already uses).
store._conn.execute("INSERT OR IGNORE INTO hypotheses (hypothesis_id, kind) VALUES (?, 'attack')",
                      ("NETWORK_INTRUSION",))
for _ in range(4):
    ct.record_corroborating_signal(store, "shadow_dev", "NORMAL", "public",
                                      "NETWORK_INTRUSION", "dns_behavior", 0, now=NOW)
    ct.record_corroborating_signal(store, "shadow_dev", "NORMAL", "public",
                                      "NETWORK_INTRUSION", "reputation", 0, now=NOW)
check("composite_trust.permits_suppression() now agrees for this exact tuple "
      "(setup check before re-testing the fast path with both gates satisfied)",
      ct.permits_suppression(store, "shadow_dev", "NORMAL", "public", "NETWORK_INTRUSION", 0, now=NOW))

v = _evaluate(cl_afpe, _alert(domain="trusted-vendor-example.com"))
check("evaluate() suppresses immediately once BOTH trust-cache AND composite_trust "
      "agree (TRUST_CACHE, no ML stages run)",
      v["verdict"] == "FALSE_POSITIVE" and v["stage"] == "TRUST_CACHE")

sigma_before = cl_afpe.get_sigma_shift("shadow_dev")
v = _evaluate(cl_afpe, _alert(domain="trusted-vendor-example.com", features={"zeek_honeypot_hits": 1}))
check("evaluate() RE-RUNS Stage 1 even on a trust-cache hit and overrides it on a "
      "genuine hard-stop signal (the non-negotiable Phase-3 fix this port preserves)",
      v["verdict"] == "CONFIRMED_THREAT" and v["stage"] == "TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP")
check("...and tunes sensitivity UP as a side effect of the override, same as a "
      "fresh (non-cached) hard-stop would",
      cl_afpe.get_sigma_shift("shadow_dev") < sigma_before)

# --- Stage 2/3 final verdict branches (no real ML model -- deterministic rule fallback) ---
v = _evaluate(cl_afpe, _alert(domain="sentry.io"))
check("evaluate() suppresses via Stage 2/3 when Stage 3's rule fallback alone clears "
      "the embed-similarity threshold for a known telemetry vendor domain",
      v["verdict"] == "FALSE_POSITIVE" and v["stage"] == "STAGE_3_COMBINED"
      and cl_afpe.is_trust_cached("sentry.io", device_id="shadow_dev", hypothesis="NETWORK_INTRUSION", now=NOW))
# shadow_dev has no learned activity (in its learning period), so the automatic correction trusts sentry.io for it
# only (tests/test_argus_trust_cache_learning_scope.py covers the scoping itself).
check("...for that device only: an automatic correction during the learning period is not network-wide trust",
      not cl_afpe.is_trust_cached("sentry.io", device_id="other_dev", hypothesis="NETWORK_INTRUSION", now=NOW)
      and "sentry.io" not in cl_afpe.get_dynamic_trust_cache(now=NOW))

v = _evaluate(cl_afpe, _alert(domain="totally-unrecognized-xyz123.example"))
check("evaluate() reaches LIKELY_REAL (published at full severity, not a confirmation) via Stage 2/3 when "
      "neither stage finds anything vendor-like (low combined confidence)",
      v["verdict"] == "LIKELY_REAL" and v["stage"] == "STAGE_3_COMBINED" and v["suppress"] is False)

# per-device suppress threshold (Phase 6e's own new getter) actually changes the
# Stage 2/3 branch outcome for the SAME evidence.
store.upsert_device("thresh_dev5", timestamp=NOW)
cl_afpe.apply_device_fp_profile(
    "thresh_dev5", "fp_combined_suppress_threshold", 0.95, baseline=0.80,
    set_by="test", reason="raise this device's own bar above the telemetry rule-fallback score", now=NOW,
)
check("get_device_suppress_threshold reflects the newly-written per-device value",
      cl_afpe.get_device_suppress_threshold("thresh_dev5") == 0.95)
# A signature distinct from the sentry.io suppression test just above -- that test
# already immunized sentry.io for hypothesis "NETWORK_INTRUSION" (not device-
# scoped) as a real side effect of its own suppression; this test needs to reach
# Stage 2/3 fresh, not short-circuit via that already-warm trust-cache entry.
v = _evaluate(cl_afpe, _alert(device_id="thresh_dev5", hostname="thresh5",
                                signature="THRESH_SUPPRESS_TEST", domain="sentry.io"))
check("...and a combined score that WOULD suppress against the global default "
      "(0.80) now correctly falls to UNCERTAIN against this device's own raised bar",
      v["verdict"] == "UNCERTAIN" and v["stage"] == "STAGE_3_COMBINED")

# CONNECTION_ABUSE signature suppressing via Stage 2/3 routes through
# mark_false_positive()'s threshold-bump branch, not domain immunization -- same
# mutual-exclusivity guarantee as Phase 6a, now proven reachable via evaluate() too.
store.upsert_device("shadow_dev2", timestamp=NOW)
v = _evaluate(cl_afpe, _alert(device_id="shadow_dev2", hostname="shadow2", signature="CONNECTION_ABUSE",
                                domain="sentry.io", features={"zeek_arp_sweep_count": 5}))
check("evaluate()'s FALSE_POSITIVE branch for a CONNECTION_ABUSE signature bumps "
      "this device's own threshold instead of immunizing the domain, and carries "
      "no 'action' (immunize_domain) payload",
      v["verdict"] == "FALSE_POSITIVE"
      and cl_afpe.get_device_arp_sweep_threshold("shadow_dev2") > 8.0
      and v.get("action") is None)

# --- local-intel Check 7, wired through the composed evaluate() end-to-end ---
real_local_intel_dir2 = _PathForSysPath(tempfile.mkdtemp(prefix="v13_clafpe_shadow_intel_"))
real_local_intel2 = LocalConfirmedIntel(str(real_local_intel_dir2))
cl_afpe_with_intel = ClAfpeEngine(store, local_intel=real_local_intel2)
store.upsert_device("shadow_confirmer", timestamp=NOW)
store.upsert_device("shadow_victim", timestamp=NOW)

# Uses a ThreatIntel IOC match (Check 1) specifically -- _is_domain_causal_hard_stop()
# only treats THAT check as causally linked to `domain` (every other check records
# dest_ip only, never the domain), same real v1 distinction Phase 6b's own tests
# already cover for the write guard in isolation -- this proves it end-to-end
# through the composed evaluate().
confirm_verdict = _evaluate(cl_afpe_with_intel, _alert(
    device_id="shadow_confirmer", hostname="confirmer", features={"ti_risk": 3.0},
    domain="evil-shadow-example.com", dest_ip="203.0.113.9"))
check("a genuine Stage-1 hard-stop with local_intel wired in records the confirmation "
      "(setup step for the cross-device propagation check below)",
      confirm_verdict["verdict"] == "CONFIRMED_THREAT")

later_verdict = _evaluate(cl_afpe_with_intel, _alert(
    device_id="shadow_victim", hostname="victim", domain="evil-shadow-example.com"), now=NOW + 5)
check("evaluate()'s Check 7 gives a DIFFERENT device an immediate hard-stop on the "
      "same confirmed-malicious domain -- the network-wide propagation point of "
      "this whole mechanism, now proven reachable through the composed evaluate()",
      later_verdict["verdict"] == "PREVIOUSLY_FLAGGED" and later_verdict["suppress"] is False
      and any("Local confirmed-threat match" in r for r in later_verdict["reasons"]))

# --- "3 automated-learning gaps" fix (2026-09-15) -----------------------------
# Gap 1: composite-trust corroboration must accumulate from ANY genuine,
# non-refused mark_false_positive() call, not just the autonomous Stage 2/3 ML
# path. Gap 3: a new, deliberately protocol-agnostic "Stage 1b" auto-
# corroboration path -- see engine.py's own 2026-09-15 comments for the full
# design rationale (feedback_network_agnostic_design.md).

# --- gap 1: operator-sourced mark_false_positive now records corroboration ---
# Mirrors pihole_api.py's real call shape exactly: no `decision` kwarg (the
# operator path never has a live one), relies entirely on the alert's own
# persisted hee_evidence_families/hee_evidence_types -- confirmed present on
# every real alert payload. 4 calls, 2 distinct families each call, to cross
# the same 0.6-per-family trust floor the pre-existing Stage 2/3 test above
# already exercises directly via ct.record_corroborating_signal() -- this
# time going through mark_false_positive(source="operator") instead, which
# is exactly the path that used to NOT feed this table at all.
store.upsert_device("op_corrob_dev", timestamp=NOW)


def _operator_alert(domain):
    return {
        "signature": "NETWORK_INTRUSION",
        "device": {"id": "op_corrob_dev", "hostname": "op-corrob-host"},
        "network_context": {"queried_domain": domain},
        "hee_evidence_families": ["dns_behavior", "reputation"],
        "hee_evidence_types": [],
    }


check("before any operator correction, composite_trust has not corroborated this tuple",
      not ct.permits_suppression(store, "op_corrob_dev", "NORMAL", "public",
                                    "NETWORK_INTRUSION", 0, now=NOW))

for _ in range(4):
    op_result = cl_afpe.mark_false_positive(_operator_alert("op-corrob-example.com"), source="operator", now=NOW)
check("a purely operator-sourced correction (no `decision` passed, matching pihole_api.py's "
      "real call shape) is NOT refused", not op_result.refused)
check("...and, after enough repeated operator corrections, composite_trust HAS now "
      "corroborated this tuple -- the actual gap 1 fix: this used to be impossible "
      "via the operator path, only the autonomous Stage 2/3 path could do it",
      ct.permits_suppression(store, "op_corrob_dev", "NORMAL", "public",
                                "NETWORK_INTRUSION", 0, now=NOW))

# --- gap 3: local-origin auto-corroboration, protocol-agnostic -----------------
# Two device pairs with DELIBERATELY DIFFERENT "shapes" (a plausible mDNS-like
# one and a totally fictional protocol/port) to prove the mechanism is
# structurally incapable of depending on protocol/port -- nothing in Stage 1b's
# own code path ever reads destination_port/service_name at all.
store._conn.execute("INSERT OR IGNORE INTO hypotheses (hypothesis_id, kind) VALUES (?, 'attack')",
                      ("LOCAL_ORIGIN_TEST",))


def _own_device_alert(device_id, dest_ip, features=None):
    return {
        "signature": "LOCAL_ORIGIN_TEST",
        "device": {"id": device_id, "hostname": device_id},
        "network_context": {"queried_domain": "", "destination_ip": dest_ip},
        "features": features or {},
    }


def _run_local_origin_sequence(label, observer_id, dest_device_id, dest_ip, features):
    store.upsert_device(observer_id, timestamp=NOW)
    store.upsert_device(dest_device_id, timestamp=NOW)
    store.update_device_metadata(dest_device_id, {"known_ips_history": {dest_ip: NOW}}, timestamp=NOW)
    decision = {"evidence_families": ["dns_behavior", "reputation"], "evidence_types": []}

    for i in range(3):
        v = _evaluate(cl_afpe, _own_device_alert(observer_id, dest_ip, features), decision=decision)
        check(f"[{label}] occurrence {i+1}/4: NOT auto-resolved yet -- a genuinely new "
              "pattern still alerts for real while corroboration is still accumulating "
              "(never on a first sighting)",
              v.get("stage") != "STAGE_1B_LOCAL_ORIGIN")

    v = _evaluate(cl_afpe, _own_device_alert(observer_id, dest_ip, features), decision=decision)
    check(f"[{label}] occurrence 4/4: NOW auto-resolves once composite_trust's "
          "distinct-family floor is genuinely crossed -- no human input anywhere "
          "in this sequence",
          v.get("verdict") == "FALSE_POSITIVE" and v.get("stage") == "STAGE_1B_LOCAL_ORIGIN"
          and v.get("suppress") is True)
    check(f"[{label}] the auto-resolution actually created a real trust-cache edge "
          "(mark_false_positive() genuinely ran, not just a synthetic verdict)",
          cl_afpe.is_trust_cached(dest_ip, device_id=observer_id, hypothesis="LOCAL_ORIGIN_TEST", now=NOW))


_run_local_origin_sequence(
    "mdns-like", "lo_dev_mdns", "lo_dest_mdns", "10.20.30.41",
    {"destination_port": 5353, "service_name": "mDNS"},
)
_run_local_origin_sequence(
    "fictional-protocol", "lo_dev_fictional", "lo_dest_fictional", "10.20.30.42",
    {"destination_port": 47823, "service_name": "totally-made-up-protocol-xyz"},
)

# --- gap 3 negative cases: must NOT auto-resolve ---
store.upsert_device("lo_dev_dirty_ti", timestamp=NOW)
store.upsert_device("lo_dest_dirty_ti", timestamp=NOW)
store.update_device_metadata("lo_dest_dirty_ti", {"known_ips_history": {"10.20.30.43": NOW}}, timestamp=NOW)
decision = {"evidence_families": ["dns_behavior", "reputation"], "evidence_types": []}
for _ in range(4):
    # ti_risk=1.0 is BELOW Stage 1's own hard-stop bar (_TI_RISK_HARD_STOP=2.0, so
    # Stage 1 itself doesn't catch it) but ABOVE Stage 1b's stricter "==0.0 clean"
    # bar -- proves Stage 1b's own redundant safety condition, not just Stage 1's.
    v = _evaluate(cl_afpe, _own_device_alert("lo_dev_dirty_ti", "10.20.30.43", {"ti_risk": 1.0}), decision=decision)
check("a destination that IS the network's own device but has a non-zero (if "
      "sub-hard-stop) threat-intel signal NEVER auto-resolves via Stage 1b, "
      "even after repeated occurrences",
      v.get("stage") != "STAGE_1B_LOCAL_ORIGIN")

store.upsert_device("lo_dev_unknown_dest", timestamp=NOW)
for _ in range(4):
    # 203.0.113.99 (TEST-NET-3, RFC 5737) is never registered as a device --
    # is_own_registered_device() must return False every time.
    v = _evaluate(cl_afpe, _own_device_alert("lo_dev_unknown_dest", "203.0.113.99"), decision=decision)
check("a destination that is NOT one of the network's own registered devices "
      "never auto-resolves via Stage 1b, regardless of how many times it recurs "
      "-- an unrecognized external host stays fully scrutinized",
      v.get("stage") != "STAGE_1B_LOCAL_ORIGIN")

store.upsert_device("lo_dev_hardstop_sig", timestamp=NOW)
store.upsert_device("lo_dest_hardstop_sig", timestamp=NOW)
store.update_device_metadata("lo_dest_hardstop_sig", {"known_ips_history": {"10.20.30.44": NOW}}, timestamp=NOW)
hardstop_alert = _own_device_alert("lo_dev_hardstop_sig", "10.20.30.44")
hardstop_alert["signature"] = "Confirmed Malicious IOC"  # a _HARD_STOP_SIGNATURES member
v = _evaluate(cl_afpe, hardstop_alert, decision=decision)
check("an alert whose SIGNATURE is a hard-stop verdict is refused by "
      "mark_false_positive()'s own guard even when Stage 1b's own own-device/clean-TI "
      "conditions are otherwise satisfied -- the safety net is shared, not "
      "reimplemented, across every autonomous source",
      v.get("stage") != "STAGE_1B_LOCAL_ORIGIN")

store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 CL-AFPE checks PASSED.")
