"""
Standalone runtime test for v13's CL-AFPE (src/v13/cl_afpe/engine.py, Phase 4 --
Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: graph-native trust caching (immunize/is_trust_cached/get_dynamic_trust_cache/
revoke), TTL clamping and expiry, DEVICE_SCOPED_TRUST_HYPOTHESES device-scoping vs.
globally-shared trust, mark_false_positive()'s two refusal guards (device-identity,
hard-stop-signature) and default domain/IP routing, and baseline familiarity.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_cl_afpe.py`
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


from v13.graph.store import GraphStore  # noqa: E402
from v13.cl_afpe.engine import ClAfpeEngine, MIN_TRUST_ENTRY_TTL_SECONDS, MAX_TRUST_ENTRY_TTL_SECONDS  # noqa: E402

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
domain_route = cl_afpe.mark_false_positive(
    {"signature": "NETWORK_INTRUSION", "device": {"id": "known_device"},
     "network_context": {"queried_domain": "domain-route.example.com"}},
    now=NOW,
)
check("a correction with a real queried_domain immunizes that domain",
      domain_route.immunized_destination == "domain-route.example.com")

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

store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 CL-AFPE checks PASSED.")
