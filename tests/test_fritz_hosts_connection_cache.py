"""
test_fritz_hosts_connection_cache.py - Fritz!Box hosts-webhook latency fix,
continuation session: middleware/routers/fritzbox_api.py's get_dhcp_hosts()
used to construct a brand-new FritzHosts (and therefore a brand-new
FritzConnection, doing a fresh TR-064 device-description/service-discovery SOAP
handshake) on EVERY single call.

Real motivation, confirmed via direct measurement against .94's live Fritz!Box:
constructing FritzHosts() alone took 4.5s, get_hosts_info() itself another
3.5s -- ~8s total for a cold connection. core/identity.py's own background
poller (_poll_fritzbox_hosts(), every 60s) had its own CLIENT-side HTTP
timeout hardcoded to 5.0s -- shorter than that real 8s server-side round-trip
-- meaning every single poll timed out on the client side even when Fritz!Box
was responding successfully, permanently starving _fritz_cache/
_fritz_cache_by_mac of real data. This test covers the connection-caching fix
(_get_fritz_hosts()/_invalidate_fritz_hosts_cache()) that eliminates the
expensive reconnect on every call; the timeout/logging fix on the client side
is covered by direct code reading in identity.py's own comments (no live
Fritz!Box needed to unit-test a timeout constant).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_fritz_hosts_connection_cache.py`
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

FAILURES = []


def check(label: str, condition: bool) -> None:
    status = "[PASS]" if condition else "[FAIL]"
    print(f"{status} {label}")
    if not condition:
        FAILURES.append(label)


import middleware.routers.fritzbox_api as mod  # noqa: E402


def main() -> None:
    # Reset module-level cache state in case an earlier test/import touched it.
    mod._fritz_hosts_cached = None

    with patch("middleware.routers.fritzbox_api.FritzHosts") as MockFritzHosts:
        MockFritzHosts.side_effect = lambda *a, **kw: MagicMock(name=f"fritzhosts_call_{MockFritzHosts.call_count}")

        fh1 = mod._get_fritz_hosts("192.168.77.1", "user", "pass", 5.0)
        check("FritzHosts constructed on the first call", MockFritzHosts.call_count == 1)

        fh2 = mod._get_fritz_hosts("192.168.77.1", "user", "pass", 5.0)
        check("THE FIX: the SAME cached connection is reused on a second call -- "
              "no reconnect, no second expensive TR-064 handshake", MockFritzHosts.call_count == 1)
        check("both calls return the identical object", fh1 is fh2)

        mod._invalidate_fritz_hosts_cache()
        fh3 = mod._get_fritz_hosts("192.168.77.1", "user", "pass", 5.0)
        check("REGRESSION GUARD: after an explicit invalidation (e.g. a real connection "
              "failure), the NEXT call constructs a genuinely fresh connection -- "
              "self-healing, not a permanent wedge", MockFritzHosts.call_count == 2)
        check("the new instance is a real, different object from the stale cached one",
              fh3 is not fh1)

    mod._fritz_hosts_cached = None  # leave clean for any other test importing this module

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All Fritz!Box connection-caching checks PASSED.")


if __name__ == "__main__":
    main()
