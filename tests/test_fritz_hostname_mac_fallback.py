"""
test_fritz_hostname_mac_fallback.py - hostname-resolution fix, continuation
session: DeviceIdentityManager._enrich_from_cache() previously looked up
Fritz!Box's hosts cache (_fritz_cache) by IP only. Confirmed live on .94:
Fritz!Box's /hosts webhook (fritzbox_api.py's get_dhcp_hosts(), a TR-064
DHCPv4-lease query) can never return an IPv6 address at all -- so a dual-stack
device whose CURRENT resolve event happens to pass an IPv6 address as `ip`
permanently misses the cache, even though the same device's real IPv4 address
(which WOULD match) sits right there in its own known_ips, and even though its
MAC is already correctly resolved. 9 currently-active production devices were
found in exactly this state. Fix: a second, MAC-keyed cache
(_fritz_cache_by_mac), tried as a fallback whenever the IP-keyed lookup misses.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_fritz_hostname_mac_fallback.py`
"""
import sys
import tempfile
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

FAILURES = []


def check(label: str, condition: bool) -> None:
    status = "[PASS]" if condition else "[FAIL]"
    print(f"{status} {label}")
    if not condition:
        FAILURES.append(label)


from core.state_guard import StateManager  # noqa: E402
from core.identity import DeviceIdentityManager  # noqa: E402


class _FakeConfig(dict):
    def get(self, k, default=None):
        return dict.get(self, k, default)


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(state_path=str(Path(d) / "ids_state.json"), max_devices=100)
        mgr = DeviceIdentityManager(sm, _FakeConfig())

        # Simulate the real poll result directly (bypassing the background
        # thread/HTTP call) -- Fritz!Box only ever reports the device's IPv4
        # lease, never its IPv6 addresses.
        mgr._fritz_cache = {"192.168.77.26": {"mac": "02:aa:bb:cc:dd:72", "name": "sky_lp_office"}}
        mgr._fritz_cache_by_mac = {"02:aa:bb:cc:dd:72": {"ip": "192.168.77.26", "name": "sky_lp_office"}}

        # THE BUG (reproduced): resolving via the device's IPv6 address, with its
        # real MAC already known, used to miss entirely -- IP-keyed lookup can
        # never match an IPv6 string against an IPv4-only cache.
        mac_ipv4, host_ipv4 = mgr._enrich_from_cache(
            ip="192.168.77.26", current_mac="02:aa:bb:cc:dd:72", current_hostname="unknown")
        check("baseline: the IPv4 path still resolves directly (unaffected by this fix)",
              host_ipv4 == "sky_lp_office")

        mac_ipv6, host_ipv6 = mgr._enrich_from_cache(
            ip="fe80::1cc7:5b4f:3229:f108", current_mac="02:aa:bb:cc:dd:72", current_hostname="unknown")
        check("THE FIX: the SAME device, resolved via its IPv6 address this cycle, "
              "now ALSO resolves the real hostname via the MAC fallback",
              host_ipv6 == "sky_lp_office")
        check("THE FIX: the MAC itself is preserved/unchanged by the fallback path",
              mac_ipv6 == "02:aa:bb:cc:dd:72")

        # REGRESSION GUARD: a device with NO known MAC and an IPv6-only address
        # must NOT crash, and must fall through to the existing _ip_cache behavior
        # (unaffected by this fix -- no MAC to even attempt a fallback with).
        mac_unknown, host_unknown = mgr._enrich_from_cache(
            ip="fe80::deadbeef", current_mac="unknown", current_hostname="unknown")
        check("REGRESSION GUARD: no MAC known at all -- falls through safely, stays unknown "
              "(this fix doesn't invent data that was never available)",
              host_unknown == "unknown" and mac_unknown == "unknown")

        # REGRESSION GUARD: a MAC that Fritz!Box genuinely has never seen (not in
        # either cache) must not match anything or crash.
        mac_nomatch, host_nomatch = mgr._enrich_from_cache(
            ip="fe80::abc", current_mac="aa:bb:cc:dd:ee:ff", current_hostname="unknown")
        check("REGRESSION GUARD: a real MAC with no Fritz!Box record for it stays unresolved, "
              "not a false match", host_nomatch == "unknown")

        # REGRESSION GUARD: Fritz!Box's own reported hostname of literally "unknown"
        # (a real value it can return) must not be treated as a hit.
        mgr._fritz_cache_by_mac["11:22:33:44:55:66"] = {"ip": "192.168.77.99", "name": "unknown"}
        mac_fritz_unknown, host_fritz_unknown = mgr._enrich_from_cache(
            ip="fe80::999", current_mac="11:22:33:44:55:66", current_hostname="unknown")
        check("REGRESSION GUARD: Fritz!Box itself reporting name='unknown' is not treated as a real hit",
              host_fritz_unknown == "unknown")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All Fritz!Box MAC-fallback hostname-resolution checks PASSED.")


if __name__ == "__main__":
    main()
