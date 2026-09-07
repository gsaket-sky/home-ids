"""
Standalone runtime test for Phase 44: infer_device_type()'s dead mac_vendor parameter
wired up via utils.get_mac_vendor() (offline OUI lookup, the `manuf` package), plus
its final fallback changing from "laptop" to "unknown".

Context (2026-08-29 investigation): confirmed on production state that 13 of 36
devices were typed "laptop", and 12 of those 13 (92%) actually had hostname="unknown"
-- infer_device_type() (utils.py) has always had hostname/User-Agent/mac_vendor layers
plus a hardcoded final fallback, but its only real caller (identity.py's
apply_device_type()) never passed mac_vendor at all, and the fallback was
unconditionally "laptop" rather than the "unknown" fp_engine.py's own dev_type_weights
dict already expected. Real production MACs were checked directly against the `manuf`
package this fix adds (e.g. 24:6f:28:xx:xx:xx -> "Espressif Inc.", an IoT device
currently mis-typed "laptop"; 00:11:32:xx:xx:xx -> "Synology Incorporated", a NAS).

Not part of the pytest suite -- run directly:
`python3 tests/test_phase44_mac_vendor_and_device_type.py`.
"""
import sys
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


from utils import get_mac_vendor, infer_device_type


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: get_mac_vendor() -- real production MACs, verified against the actual
# manuf database this fix adds (not fabricated -- checked live before writing this)
# ═══════════════════════════════════════════════════════════════════════════════════
espressif_mac = "24:6f:28:00:00:00"
espressif_vendor = get_mac_vendor(espressif_mac)
check("get_mac_vendor() resolves a real production Espressif (IoT) MAC",
      "espressif" in espressif_vendor.lower(), f"got {espressif_vendor!r}")

synology_mac = "00:11:32:00:00:00"
synology_vendor = get_mac_vendor(synology_mac)
check("get_mac_vendor() resolves a real production Synology (NAS) MAC",
      "synology" in synology_vendor.lower(), f"got {synology_vendor!r}")

randomized_mac = "aa:bb:cc:dd:ee:11"  # locally-administered bit set (bit 1 of octet 1)
check("get_mac_vendor() returns '' (not a crash, not a wrong guess) for a "
      "locally-administered/randomized MAC -- no registered OUI to find",
      get_mac_vendor(randomized_mac) == "")

check("get_mac_vendor('unknown') returns '' without raising",
      get_mac_vendor("unknown") == "")
check("get_mac_vendor('') returns '' without raising",
      get_mac_vendor("") == "")
check("get_mac_vendor(None) returns '' without raising",
      get_mac_vendor(None) == "")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: infer_device_type()'s new "unknown" fallback (was "laptop")
# ═══════════════════════════════════════════════════════════════════════════════════
check("BUGFIX: hostname='unknown', no mac_vendor -- no real signal anywhere, now "
      "returns 'unknown' instead of silently defaulting to 'laptop'",
      infer_device_type("unknown") == "unknown")
check("BUGFIX: empty hostname, no mac_vendor -- same fallback",
      infer_device_type("") == "unknown")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: infer_device_type()'s mac_vendor layer now actually reachable
# ═══════════════════════════════════════════════════════════════════════════════════
check("a device with no hostname signal but a real Espressif MAC now correctly "
      "types as 'iot' instead of falling through to 'unknown'/'laptop'",
      infer_device_type("unknown", mac_vendor=espressif_vendor) == "iot",
      f"got {infer_device_type('unknown', mac_vendor=espressif_vendor)!r} for vendor={espressif_vendor!r}")
check("a device with no hostname signal but a real Synology MAC now correctly "
      "types as 'nas'",
      infer_device_type("unknown", mac_vendor=synology_vendor) == "nas",
      f"got {infer_device_type('unknown', mac_vendor=synology_vendor)!r} for vendor={synology_vendor!r}")
check("REGRESSION GUARD: a randomized-MAC device with no hostname still correctly "
      "falls through to 'unknown' (mac_vendor='' provides no signal, same as before)",
      infer_device_type("unknown", mac_vendor=get_mac_vendor(randomized_mac)) == "unknown")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: REGRESSION GUARD -- hostname-keyword classification is untouched
# ═══════════════════════════════════════════════════════════════════════════════════
check("a real, resolved hostname still classifies correctly (hostname layer takes "
      "priority over mac_vendor, unaffected by this fix)",
      # BUGFIX (2026-09-07, live audit): this used "home-router" as its own example
      # here, asserting device_type=="router" -- but that's exactly the bug a later
      # fix found and closed: ".fritz.box" is a FritzBox's own default local-DNS
      # domain suffix, appended to nearly EVERY device's DHCP-reported hostname on
      # this kind of network regardless of what the device actually is, so this
      # assertion was unknowingly encoding the misclassification bug as "correct."
      # "fritzbox_router" (the box itself, not the generic domain suffix) is what
      # this test actually needs to prove hostname-layer priority.
      infer_device_type("fritzbox_router", mac_vendor=espressif_vendor) == "router",
      f"got {infer_device_type('fritzbox_router', mac_vendor=espressif_vendor)!r}")
check("REGRESSION GUARD: iphone-shaped hostname still types 'phone'",
      # "iphone" kept literally here (unlike the generic device-name examples
      # elsewhere in this repo) -- infer_device_type()'s own pattern table (utils.py)
      # keys on that exact substring, so this is testing recognized keyword-matching
      # logic, not narrating a real device on any specific network.
      infer_device_type("example_iphone_fritz_box") == "phone")
check("REGRESSION GUARD: a genuinely laptop-shaped hostname still types 'laptop' "
      "(the fix only changed the FALLBACK, not real laptop detection)",
      infer_device_type("example_pc_fritz_box") == "laptop")

# BUGFIX (2026-09-07, live audit): a device with NO recognizable vendor/type keyword
# in its own hostname, but carrying the universal ".fritz.box" local-DNS domain
# suffix every device on this kind of network gets, used to fall through the whole
# pattern table and match the generic "fritz" keyword -> misclassified as "router"
# purely from DNS-domain noise, not any real signal about the device. Confirmed
# live: an actual IoT device was showing up as device_type="router" this way.
check("BUGFIX: a device with an UNRECOGNIZED hostname but the universal "
      "_fritz_box domain suffix no longer falls through to 'router' -- the "
      "domain suffix alone is not a device-type signal",
      infer_device_type("some_unrecognized_iot_gadget_fritz_box") == "unknown",
      f"got {infer_device_type('some_unrecognized_iot_gadget_fritz_box')!r}")
check("BUGFIX: the SAME hostname shape, but naming a real FritzBox mesh repeater "
      "specifically, still correctly classifies as 'router' -- the fix narrowed "
      "the keyword to real FritzBox hardware, it didn't just delete router "
      "detection entirely",
      infer_device_type("fritzrepeater_1200_fritz_box") == "router")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: source-guard -- identity.py actually wires get_mac_vendor() in
# ═══════════════════════════════════════════════════════════════════════════════════
_identity_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "identity.py").read_text(encoding="utf-8")
check("SOURCE-GUARD: identity.py imports get_mac_vendor from utils",
      "get_mac_vendor" in _identity_src and "from utils import" in _identity_src)
check("SOURCE-GUARD: apply_device_type() actually calls get_mac_vendor() and passes "
      "the result into infer_device_type() (catches the wiring silently regressing "
      "back to dead-parameter status on a future edit)",
      "mac_vendor = get_mac_vendor(" in _identity_src
      and "infer_device_type(hostname, mac_vendor=mac_vendor)" in _identity_src)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: source-guard -- fp_engine.py's pre-existing "unknown" weight bucket this
# fix activates (read-only confirmation, not modified by this fix)
# ═══════════════════════════════════════════════════════════════════════════════════
_fp_engine_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "intelligence" / "fp_engine.py").read_text(encoding="utf-8")
check("SOURCE-GUARD: fp_engine.py's dev_type_weights dict still has its 'unknown' "
      "entry -- this fix's whole point is making it reachable, not adding it",
      '"unknown": 0.3' in _fp_engine_src)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 44 mac-vendor/device-type checks PASSED.")
