"""
Standalone runtime test for v13's identity resolver (src/v13/identity/resolver.py,
Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: the full generalized priority chain (trust-anchor exact match, learned
anchor MAC on a different IP, MAC-first binding, trackable-IP anchor, non-generic
hostname anchor, MAC fallback, raw-IP fallback), and that stable_device_id() /
is_generic_hostname() match core/identity.py's own behavior exactly (confirmed via
direct read this session, not guessed).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_identity_resolver.py`
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


from v13.identity.resolver import (  # noqa: E402
    resolve_device_id, stable_device_id, is_generic_hostname, TrustAnchor,
    is_locally_administered_mac,
)

# --- is_locally_administered_mac (Phase 3): real MAC-randomization detection ---
check("a real vendor MAC (Apple OUI, globally-unique bit) is NOT flagged as randomized",
      is_locally_administered_mac("f0:18:98:aa:bb:cc") is False)
check("a locally-administered MAC (2nd-LSB of first octet set, e.g. iOS private "
      "address randomization) IS flagged as randomized",
      is_locally_administered_mac("02:00:00:aa:bb:cc") is True)
check("the locally-administered bit check is independent of the other bits in the octet",
      is_locally_administered_mac("06:aa:bb:cc:dd:ee") is True
      and is_locally_administered_mac("0a:aa:bb:cc:dd:ee") is True)
check("a hyphen-separated MAC is parsed the same as colon-separated",
      is_locally_administered_mac("02-00-00-aa-bb-cc") is True)
check("None/empty/'unknown' all return False, never raise",
      is_locally_administered_mac(None) is False
      and is_locally_administered_mac("") is False
      and is_locally_administered_mac("unknown") is False)
check("a malformed MAC string fails safe to False, doesn't raise",
      is_locally_administered_mac("not-a-mac") is False)

# --- stable_device_id / is_generic_hostname match core/identity.py exactly ---
check("stable_device_id is deterministic", stable_device_id("192.168.1.1") == stable_device_id("192.168.1.1"))
check("stable_device_id is case/whitespace insensitive", stable_device_id("  ABC ") == stable_device_id("abc"))
check("stable_device_id of empty string is the documented sentinel", stable_device_id("") == "000000000000")
check("stable_device_id returns a 12-char hex string", len(stable_device_id("x")) == 12)

check("'android' is a generic hostname", is_generic_hostname("android"))
check("'ANDROID' is generic (case-insensitive)", is_generic_hostname("ANDROID"))
check("'unknown' is generic", is_generic_hostname("unknown"))
check("a purely numeric hostname is generic", is_generic_hostname("12345"))
check("'living-room-tv' is NOT generic", not is_generic_hostname("living-room-tv"))
check("empty/None hostname is generic", is_generic_hostname("") and is_generic_hostname(None))

anchors = {
    "gateway": TrustAnchor(role="gateway", ip="192.168.1.1", mac="aa:bb:cc:00:00:01"),
    "nas": TrustAnchor(role="nas", ip="192.168.1.3"),
}

# --- 1. exact trust-anchor IP match ---
gw_id = resolve_device_id("192.168.1.1", trust_anchors=anchors)
check("exact trust-anchor IP match resolves to a fixed anchor id", gw_id == stable_device_id("anchor:gateway"))
nas_id = resolve_device_id("192.168.1.3", trust_anchors=anchors)
check("a different anchor's exact IP resolves to ITS OWN distinct fixed id", nas_id != gw_id)

# --- 2. learned anchor MAC on a different IP (multi-homed anchor) ---
gw_other_iface = resolve_device_id(
    "fe80::1", trust_anchors=anchors, client_mac="aa:bb:cc:00:00:01",
)
check("a trust anchor's own MAC seen on a different IP still resolves to the same anchor id",
      gw_other_iface == gw_id)

learned = {"nas": "dd:ee:ff:00:00:02"}
nas_other_iface = resolve_device_id(
    "10.0.0.5", trust_anchors=anchors, client_mac="dd:ee:ff:00:00:02", learned_anchor_macs=learned,
)
check("a LEARNED anchor MAC (not the anchor's static config MAC) also resolves correctly",
      nas_other_iface == nas_id)

# --- 3. MAC-first binding ---
bindings = {"11:22:33:44:55:66": "existing_device_abc"}
mac_bound = resolve_device_id("192.168.1.99", client_mac="11:22:33:44:55:66", mac_bindings=bindings)
check("an existing MAC binding takes priority over a fresh IP-based id",
      mac_bound == "existing_device_abc")

# --- 4. trackable IP anchor ---
ip_anchor = resolve_device_id("192.168.1.50")
check("a private IP with no other signals resolves via stable_device_id(ip)",
      ip_anchor == stable_device_id("192.168.1.50"))

# --- 5. non-generic hostname anchor (only reachable when IP itself isn't trackable) ---
host_anchor = resolve_device_id("", hostname="living-room-tv")
check("a non-generic hostname anchors identity when the IP itself isn't trackable",
      host_anchor == stable_device_id("host:living-room-tv"))

generic_host_falls_through = resolve_device_id("", hostname="android", client_mac="ff:ff:ff:ff:ff:ff")
check("a GENERIC hostname does not anchor identity -- falls through to MAC fallback",
      generic_host_falls_through == stable_device_id("ff:ff:ff:ff:ff:ff"))

# --- 6. MAC fallback ---
mac_fallback = resolve_device_id("", client_mac="ff:ff:ff:ff:ff:ff")
check("MAC fallback used when IP isn't trackable and no hostname given",
      mac_fallback == stable_device_id("ff:ff:ff:ff:ff:ff"))

# --- 7. raw IP fallback (loopback is the one deliberately non-trackable case) ---
loopback_fallback = resolve_device_id("127.0.0.1")
check("loopback IP with no other signals still resolves via the final raw-IP fallback "
      "(not trackable, but not left unresolved either)",
      loopback_fallback == stable_device_id("127.0.0.1"))

# --- priority ordering sanity: anchor match beats everything else ---
priority_check = resolve_device_id(
    "192.168.1.1", trust_anchors=anchors, client_mac="zz", hostname="some-real-name",
)
check("trust-anchor exact match wins over hostname/MAC signals present on the same call",
      priority_check == gw_id)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 identity-resolver checks PASSED.")
