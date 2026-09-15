"""
Standalone runtime test for src/v13/config/trust_anchors.py -- the config loader
bridging network.trust_anchors' YAML list shape into the Dict[str, TrustAnchor]
src/v13/identity/resolver.py's resolve_device_id() expects (v13 full-architecture
plan, Phase 2).

Not part of the pytest suite -- run directly:
`python3 tests/test_argus_config_trust_anchors.py`
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


from argus.config.trust_anchors import (  # noqa: E402
    load_trust_anchors, load_trust_anchors_from_config, load_hardware_profile,
    VALID_HARDWARE_PROFILES, DEFAULT_HARDWARE_PROFILE,
)
from argus.identity.resolver import TrustAnchor, resolve_device_id  # noqa: E402


# --- load_trust_anchors: the real config_v13.example.yaml shape ---

real_shape = [
    {"role": "gateway", "ip": "192.168.1.1"},
    {"role": "this_host", "ip": "192.168.1.2"},
    {"role": "nas", "ip": "192.168.1.3", "mac": "aa:bb:cc:dd:ee:ff"},
]
anchors = load_trust_anchors(real_shape)
check("A: returns a dict keyed by role, one entry per real config_v13.example.yaml-shaped item",
      set(anchors.keys()) == {"gateway", "this_host", "nas"})
check("A: each value is a real TrustAnchor with the right ip",
      anchors["gateway"].ip == "192.168.1.1" and anchors["gateway"].role == "gateway")
check("A: an entry with a mac carries it through", anchors["nas"].mac == "aa:bb:cc:dd:ee:ff")
check("A: an entry with no mac defaults to None, not a crash", anchors["gateway"].mac is None)

check("A: the returned dict is directly usable by resolve_device_id() with zero adaptation",
      resolve_device_id("192.168.1.1", trust_anchors=anchors) == resolve_device_id(
          "192.168.1.1", trust_anchors={"gateway": TrustAnchor(role="gateway", ip="192.168.1.1")}))


# --- empty / absent input: fails safe, never crashes ---

check("B: None input returns an empty dict, not an error", load_trust_anchors(None) == {})
check("B: an empty list returns an empty dict", load_trust_anchors([]) == {})


# --- malformed entries: skipped and logged, never raise ---

malformed = [
    {"role": "gateway", "ip": "192.168.1.1"},   # valid
    {"ip": "192.168.1.2"},                        # missing role
    "not-a-dict",                                  # wrong type entirely
    {"role": "", "ip": "192.168.1.3"},           # empty role string
    {"role": 123, "ip": "192.168.1.4"},          # non-string role
    {"role": "nas", "ip": 12345},                 # non-string ip
    {"role": "bad_mac", "ip": "192.168.1.5", "mac": 999},  # non-string mac
]
result = load_trust_anchors(malformed)
check("C: only the one genuinely valid entry survives -- every malformed entry is "
      "skipped, none of them raise out of load_trust_anchors()",
      set(result.keys()) == {"gateway"}, f"got {list(result.keys())}")


# --- duplicate role: first wins, doesn't silently overwrite ---

dup = [
    {"role": "gateway", "ip": "192.168.1.1"},
    {"role": "gateway", "ip": "10.0.0.1"},  # duplicate role, different ip
]
dup_result = load_trust_anchors(dup)
check("D: a duplicate role keeps the FIRST occurrence's values, not the last",
      dup_result["gateway"].ip == "192.168.1.1")


# --- load_trust_anchors_from_config: the real nested config shape ---

full_config = {
    "network": {
        "subnets": ["192.168.1.0/24"],
        "trust_anchors": [{"role": "gateway", "ip": "192.168.1.1"}],
    },
    "hardware_profile": "x86_16gb",
}
from_config = load_trust_anchors_from_config(full_config)
check("E: reads the real nested network.trust_anchors shape correctly",
      list(from_config.keys()) == ["gateway"])

check("E: a config with NO 'network' key at all returns an empty dict, not an error",
      load_trust_anchors_from_config({}) == {})
check("E: a 'network' key that isn't a mapping (e.g. a typo'd string) fails safe",
      load_trust_anchors_from_config({"network": "oops"}) == {})
check("E: a 'network' mapping with no 'trust_anchors' key returns an empty dict",
      load_trust_anchors_from_config({"network": {"subnets": []}}) == {})


# --- load_hardware_profile ---

check("F: a valid profile is returned as-is", load_hardware_profile({"hardware_profile": "pi_8gb"}) == "pi_8gb")
check("F: an absent key defaults to the known-working default",
      load_hardware_profile({}) == DEFAULT_HARDWARE_PROFILE)
check("F: an unrecognized value falls back to the default rather than propagating garbage",
      load_hardware_profile({"hardware_profile": "raspberry_pi_5_overclocked"}) == DEFAULT_HARDWARE_PROFILE)
check("F: DEFAULT_HARDWARE_PROFILE is itself always a member of VALID_HARDWARE_PROFILES "
      "(a basic self-consistency guard against a future typo in either constant)",
      DEFAULT_HARDWARE_PROFILE in VALID_HARDWARE_PROFILES)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 config/trust_anchors checks PASSED.")
