"""
Standalone runtime test for mitigation/router_adapter.py -- Phase 12 of the
16-parameter autonomy-completion effort (zero-site bootstrap D: RouterAdapter
abstraction).

No real Fritz!Box/network I/O in this file -- middleware.routers.fritzbox_api's
own functions and fritzconnection.FritzConnection are monkeypatched.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_mitigation_router_adapter.py`
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


from mitigation.router_adapter import (  # noqa: E402
    get_router_adapter, FritzBoxAdapter, NoRouterAdapter, DEFAULT_ROUTER_TYPE,
)


# --- A. factory selection ---

check("A: router_type='fritzbox' selects FritzBoxAdapter",
      isinstance(get_router_adapter({"router_type": "fritzbox"}), FritzBoxAdapter))
check("A: router_type='none' selects NoRouterAdapter",
      isinstance(get_router_adapter({"router_type": "none"}), NoRouterAdapter))
check("A: no router_type key at all defaults to FritzBoxAdapter (matching every "
      "existing real deployment's hardware)",
      isinstance(get_router_adapter({}), FritzBoxAdapter)
      and DEFAULT_ROUTER_TYPE == "fritzbox")
check("A: an unrecognized router_type fails safe to NoRouterAdapter, never a "
      "silent guess at FritzBoxAdapter against hardware that may not even be one",
      isinstance(get_router_adapter({"router_type": "openwrt_not_built_yet"}), NoRouterAdapter))


# --- B. NoRouterAdapter: every method degrades safely, never raises ---

no_router = NoRouterAdapter()
check("B: capture_supported is False", no_router.capture_supported is False)
check("B: isolate() returns False (no crash)", no_router.isolate("aa:bb", "1.2.3.4", "test") is False)
check("B: unisolate() returns False (no crash)", no_router.unisolate("aa:bb", "1.2.3.4", "test") is False)
check("B: get_hosts() returns an empty list, not an error", no_router.get_hosts() == [])
check("B: get_isolation_status() returns False -- nothing was ever isolated "
      "without a router", no_router.get_isolation_status("1.2.3.4") is False)
ok, detail = no_router.health_check()
check("B: health_check() reports ok=True with an honest 'no router configured' "
      "message, not a failure -- this is the intended, working default state",
      ok is True and "no router" in detail.lower())


# --- C. FritzBoxAdapter: thin wrapper, calls the real (mocked) fritzbox_api functions ---

import middleware.routers.fritzbox_api as fritzbox_api  # noqa: E402

isolate_calls = []


def _mock_execute_fritzbox_isolation(action, mac_address, ip_address, reason):
    isolate_calls.append((action, mac_address, ip_address, reason))


_real_execute = fritzbox_api.execute_fritzbox_isolation
fritzbox_api.execute_fritzbox_isolation = _mock_execute_fritzbox_isolation

fritz = FritzBoxAdapter({"fritz_ip": "192.168.1.1", "fritz_user": "admin", "fritz_password": "secret"})
check("C: capture_supported is True", fritz.capture_supported is True)

result_isolate = fritz.isolate("aa:bb:cc:dd:ee:ff", "192.168.1.50", "test reason")
check("C: isolate() calls through to the real execute_fritzbox_isolation() with "
      "action='isolate' and the exact args given",
      isolate_calls[-1] == ("isolate", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "test reason"))
check("C: isolate() returns True once the action was queued", result_isolate is True)

result_unisolate = fritz.unisolate("aa:bb:cc:dd:ee:ff", "192.168.1.50", "risk subsided")
check("C: unisolate() calls through with action='unisolate'",
      isolate_calls[-1] == ("unisolate", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "risk subsided"))
check("C: unisolate() returns True", result_unisolate is True)

fritzbox_api.execute_fritzbox_isolation = _real_execute


# --- D. FritzBoxAdapter.get_hosts(): parses real (mocked) FritzHosts output ---

class _FakeFritzHosts:
    def get_hosts_info(self):
        return [
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:00:00:01", "name": "living-room-tv"},
            {"ip": "", "mac": "AA:BB:CC:00:00:02", "name": "no-ip-entry"},  # no ip -- must be skipped
            {"ip": "192.168.1.11", "name": "no-mac-entry"},  # mac defaults to 'unknown'
        ]


_real_get_fritz_hosts = fritzbox_api._get_fritz_hosts
_real_invalidate_cache = fritzbox_api._invalidate_fritz_hosts_cache
fritzbox_api._get_fritz_hosts = lambda *a, **kw: _FakeFritzHosts()
invalidate_calls = []
fritzbox_api._invalidate_fritz_hosts_cache = lambda: invalidate_calls.append(1)

hosts = fritz.get_hosts()
check("D: get_hosts() returns exactly the 2 entries with a real ip (skips the "
      "one with an empty ip)", len(hosts) == 2, f"got {hosts}")
check("D: mac is lowercased", hosts[0]["mac"] == "aa:bb:cc:00:00:01")
check("D: a missing mac defaults to 'unknown', not a crash", hosts[1]["mac"] == "unknown")

fritz_no_creds = FritzBoxAdapter({"fritz_ip": "192.168.1.1"})  # no fritz_password
raised = False
try:
    fritz_no_creds.get_hosts()
except RuntimeError:
    raised = True
check("D: get_hosts() raises when fritz_password isn't configured, rather than "
      "attempting a doomed connection", raised is True)

fritzbox_api._get_fritz_hosts = lambda *a, **kw: (_ for _ in ()).throw(ConnectionError("simulated"))
raised_conn = False
try:
    fritz.get_hosts()
except ConnectionError:
    raised_conn = True
check("D: a genuine connection failure propagates (the route handler decides "
      "the HTTP status), and invalidates the cached connection so the NEXT "
      "call gets a fresh one",
      raised_conn is True and len(invalidate_calls) == 1)

fritzbox_api._get_fritz_hosts = _real_get_fritz_hosts
fritzbox_api._invalidate_fritz_hosts_cache = _real_invalidate_cache


# --- E. FritzBoxAdapter.get_isolation_status() / health_check(): mocked FritzConnection ---

import fritzconnection as fritzconnection_module  # noqa: E402


class _FakeFritzConnection:
    def __init__(self, address=None, user=None, password=None, timeout=None):
        self.address = address

    def call_action(self, service, action, **kwargs):
        return {"NewDisallow": 1 if kwargs.get("NewIPv4Address") == "192.168.1.99" else 0}


_real_fritz_connection = fritzconnection_module.FritzConnection
fritzconnection_module.FritzConnection = _FakeFritzConnection

check("E: get_isolation_status() returns True for an ip the (mocked) router "
      "reports as disallowed", fritz.get_isolation_status("192.168.1.99") is True)
check("E: get_isolation_status() returns False for an ip NOT disallowed",
      fritz.get_isolation_status("192.168.1.50") is False)

ok_e, detail_e = fritz.health_check()
check("E: health_check() succeeds with real (mocked) credentials configured",
      ok_e is True and "192.168.1.1" in detail_e)

fritz_no_pass = FritzBoxAdapter({"fritz_ip": "192.168.1.1", "fritz_password": ""})
ok_e2, detail_e2 = fritz_no_pass.health_check()
check("E: health_check() fails cleanly (no exception) when fritz_password is "
      "empty, with an honest reason", ok_e2 is False and "password" in detail_e2.lower())

fritzconnection_module.FritzConnection = _real_fritz_connection


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All mitigation/router_adapter.py checks PASSED.")
