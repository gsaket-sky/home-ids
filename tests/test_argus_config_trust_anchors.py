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


import argus.config.trust_anchors as trust_anchors_module  # noqa: E402
from argus.config.trust_anchors import (  # noqa: E402
    load_trust_anchors, load_trust_anchors_from_config, load_hardware_profile,
    bootstrap_trust_anchors, VALID_HARDWARE_PROFILES, DEFAULT_HARDWARE_PROFILE,
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


# --- G (Phase 13, 2026-09-27): bootstrap_trust_anchors() -- the zero-site
# bootstrap cutover, auto-discovery + the gateway-continuity safety guard ---

_real_discover = trust_anchors_module.discover


def _mock_discover(gateway_ip=None, gateway_mac=None, this_host_ip=None, this_host_mac=None):
    anchors = []
    if gateway_ip:
        anchors.append({"role": "gateway", "ip": gateway_ip, "mac": gateway_mac})
    if this_host_ip:
        anchors.append({"role": "this_host", "ip": this_host_ip, "mac": this_host_mac})
    return lambda previous_trust_anchors=None: anchors


# G1: first-ever adoption -- nothing hand-configured, nothing to conflict with.
trust_anchors_module.discover = _mock_discover(
    gateway_ip="192.168.1.1", gateway_mac="aa:bb:cc:00:00:01",
    this_host_ip="192.168.1.50", this_host_mac="aa:bb:cc:00:00:02",
)
result_g1 = bootstrap_trust_anchors({})
check("G1: first-ever adoption -- no hand-configured trust_anchors and no legacy "
      "gateway_ip -- the discovered gateway/this_host are adopted directly",
      result_g1["gateway"].ip == "192.168.1.1" and result_g1["this_host"].ip == "192.168.1.50")

# G2: discovered gateway matches the hand-configured one exactly -- adopted (and
# picks up a fresher mac from discovery).
config_g2 = {"network": {"trust_anchors": [{"role": "gateway", "ip": "192.168.1.1"}]}}
trust_anchors_module.discover = _mock_discover(gateway_ip="192.168.1.1", gateway_mac="aa:bb:cc:00:00:99")
result_g2 = bootstrap_trust_anchors(config_g2)
check("G2: a discovered gateway matching the hand-configured ip is adopted, "
      "picking up discovery's own (fresher) mac",
      result_g2["gateway"].ip == "192.168.1.1" and result_g2["gateway"].mac == "aa:bb:cc:00:00:99")

# G3: THE SAFETY GUARD -- discovered gateway does NOT match hand-configured one --
# refused, last-known-good kept, loud warning (can't easily assert the log text
# here without a handler, but the RETURNED value is the real behavioral contract).
config_g3 = {"network": {"trust_anchors": [{"role": "gateway", "ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01"}]}}
trust_anchors_module.discover = _mock_discover(gateway_ip="10.0.0.1", gateway_mac="ff:ff:ff:ff:ff:ff")
result_g3 = bootstrap_trust_anchors(config_g3)
check("G3: THE SAFETY GUARD -- a discovered gateway ip that does NOT match the "
      "hand-configured (last-known-good) one is REFUSED -- the original ip/mac "
      "are kept, not the mismatched discovery",
      result_g3["gateway"].ip == "192.168.1.1" and result_g3["gateway"].mac == "aa:bb:cc:00:00:01")

# G4: same guard, but the ONLY prior source is the legacy gateway_ip key (no
# network.trust_anchors configured at all) -- still refuses and preserves
# continuity with the legacy value, not silently dropping gateway anchoring.
config_g4 = {"gateway_ip": "192.168.1.1"}
trust_anchors_module.discover = _mock_discover(gateway_ip="10.0.0.1")
result_g4 = bootstrap_trust_anchors(config_g4)
check("G4: with ONLY the legacy gateway_ip configured (no network.trust_anchors "
      "at all), a mismatched discovery still refuses and falls back to a "
      "gateway anchor built from the legacy ip directly",
      result_g4["gateway"].ip == "192.168.1.1")

# G5: this_host has no continuity risk -- always adopted fresh, even alongside a
# refused gateway mismatch in the SAME call.
config_g5 = {"network": {"trust_anchors": [
    {"role": "gateway", "ip": "192.168.1.1"},
    {"role": "this_host", "ip": "192.168.1.40"},
]}}
trust_anchors_module.discover = _mock_discover(
    gateway_ip="10.0.0.1",  # mismatch -- refused
    this_host_ip="192.168.1.99",  # different from hand-configured -- still adopted
)
result_g5 = bootstrap_trust_anchors(config_g5)
check("G5: this_host is always adopted fresh from discovery, independent of "
      "whether the SAME call's gateway discovery was refused",
      result_g5["this_host"].ip == "192.168.1.99" and result_g5["gateway"].ip == "192.168.1.1")

# G6: a hand-configured anchor discovery has no concept of (e.g. a manually-added
# household anchor) is preserved untouched.
config_g6 = {"network": {"trust_anchors": [
    {"role": "gateway", "ip": "192.168.1.1"},
    {"role": "nas", "ip": "192.168.1.5", "mac": "cc:cc:cc:00:00:01"},
]}}
trust_anchors_module.discover = _mock_discover(gateway_ip="192.168.1.1")
result_g6 = bootstrap_trust_anchors(config_g6)
check("G6: a hand-configured anchor with a role discover() doesn't produce (e.g. "
      "'nas') survives untouched", result_g6["nas"].ip == "192.168.1.5"
      and result_g6["nas"].mac == "cc:cc:cc:00:00:01")

# G7: discover() itself raising -- degrades to the hand-configured value unchanged.
config_g7 = {"network": {"trust_anchors": [{"role": "gateway", "ip": "192.168.1.1"}]}}


def _raising_discover(previous_trust_anchors=None):
    raise RuntimeError("simulated discovery failure")


trust_anchors_module.discover = _raising_discover
result_g7 = bootstrap_trust_anchors(config_g7)
check("G7: FAIL-SAFE -- a raising discover() degrades to the hand-configured "
      "trust_anchors unchanged, never raises out to the caller",
      result_g7["gateway"].ip == "192.168.1.1" and set(result_g7.keys()) == {"gateway"})

trust_anchors_module.discover = _real_discover


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 config/trust_anchors checks PASSED.")
