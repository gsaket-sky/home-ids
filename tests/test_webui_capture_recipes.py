"""
Standalone runtime test for the network-capture setup wizard's recipe registry
(PRODUCTIZATION_ROADMAP.md Phase 5, pulled into Phase 4's setup flow). No real
router needed -- mocks fritzbox_capture.py's login()/run_burst() to exercise
the "validate, don't just check presence" result shapes. Run directly:
`python3 test_webui_capture_recipes.py`.
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


from middleware.webui import capture_recipes
from extractors.fritzbox_capture import FritzboxCaptureError

# ── Registry shape ────────────────────────────────────────────────────────────
recipes = capture_recipes.list_recipes()
check("fritzbox recipe is registered", any(r.key == "fritzbox" for r in recipes))
check("get_recipe() finds it by key", capture_recipes.get_recipe("fritzbox") is not None)
check("get_recipe() returns None for an unknown vendor", capture_recipes.get_recipe("some_other_router") is None)
check("run_test_capture() on an unknown vendor fails cleanly, not an exception",
      capture_recipes.run_test_capture("nope", {}).ok is False)

_CFG = {"fritz_ip": "192.168.1.1", "fritz_user": "admin", "fritz_password": "pw",
        "reactive_capture_radios": ["ath0"], "reactive_capture_snaplen": 1600}


# ── Login failure surfaces cleanly, no exception escapes ────────────────────
def _boom_login(*a, **kw):
    raise FritzboxCaptureError("bad credentials")


capture_recipes.login = _boom_login
result = capture_recipes.run_test_capture("fritzbox", _CFG)
check("a login failure produces ok=False with a real detail message",
      result.ok is False and "bad credentials" in result.detail)


# ── A burst that captures real traffic reports ok=True ───────────────────────
def _ok_login(*a, **kw):
    return "fake-sid"


def _burst_with_traffic(fritz_ip, user, password, radios, burst_seconds, out_dir, snaplen=1600, connect_timeout=10.0):
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "ath0.pcap"
    # A real pcap global header (24 bytes) + enough bytes to look like >=1 packet record.
    path.write_bytes(b"\x00" * 24 + b"\x00" * 40)
    return {"ath0": path}


capture_recipes.login = _ok_login
capture_recipes.run_burst = _burst_with_traffic
result = capture_recipes.run_test_capture("fritzbox", _CFG)
check("a burst with real packet data reports ok=True", result.ok is True, result.detail)
check("packet_bytes_captured is populated on success", result.packet_bytes_captured > 0)


# ── A burst that captures NOTHING (login fine, but empty) reports ok=False ──
def _burst_empty(fritz_ip, user, password, radios, burst_seconds, out_dir, snaplen=1600, connect_timeout=10.0):
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "ath0.pcap"
    path.write_bytes(b"\x00" * 24)  # global header only -- zero packets
    return {"ath0": path}


capture_recipes.run_burst = _burst_empty
result = capture_recipes.run_test_capture("fritzbox", _CFG)
check("a burst that captured zero real packets reports ok=False, not a false positive",
      result.ok is False, result.detail)
check("the empty-burst failure message explains WHY (not just 'failed')",
      "no real packet data" in result.detail or "nothing traversed" in result.detail)


if FAILURES:
    print(f"\n{len(FAILURES)} capture-recipes check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll capture-recipes checks PASSED.")
    sys.exit(0)
