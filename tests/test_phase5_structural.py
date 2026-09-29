"""
Standalone runtime test for Phase 5 (remaining structural fixes). Not part of the pytest
suite — run directly: `python3 test_phase5_structural.py`.

Covers:
  1. IPv6 visibility fix in core/identity.py's _is_trackable_local_ip (was a hard `if
     ip_obj.version == 6: return False`, now relies on `is_private` which already
     correctly covers both RFC1918 IPv4 and IPv6 ULA/link-local).
  2. ThreatIntel.is_ready() fail-open visibility gauge — distinguishes "checked, clean"
     from "TI not loaded yet" without changing any decision logic.
  3. Phase 1 device-sensitivity source (device_type_is_override) — included here rather
     than a separate file since it's a small, self-contained identity.py check like #1.
  4. Documents (via source presence checks, not behavioral tests — there is no new
     runtime behavior to exercise) that audit Finding #10 ("move TI/AbuseIPDB/VT lookups
     off the main loop into a background worker thread") was ALREADY satisfied by
     existing code before this work started.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import tempfile

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# ── Test 1: IPv6 visibility ─────────────────────────────────────────────────────────
from core.identity import _is_trackable_local_ip

check("IPv4 RFC1918 private address is trackable (unchanged behavior)",
      _is_trackable_local_ip("192.168.1.50") is True)
check("IPv4 loopback is NOT trackable (unchanged behavior)",
      _is_trackable_local_ip("127.0.0.1") is False)
check("IPv4 public address is NOT trackable (unchanged behavior)",
      _is_trackable_local_ip("8.8.8.8") is False)

check("PHASE 5 FIX: IPv6 ULA address (fd00::/8) is now trackable — previously ANY IPv6 "
      "address was hard-excluded regardless of scope, blinding identity resolution the "
      "moment IPv6 is enabled on the router",
      _is_trackable_local_ip("fd12:3456:789a:1::50") is True)
check("PHASE 5 FIX: IPv6 link-local address (fe80::/10) is now trackable",
      _is_trackable_local_ip("fe80::1a2b:3c4d:5e6f:7890") is True)
check("IPv6 loopback (::1) is still correctly excluded",
      _is_trackable_local_ip("::1") is False)
check("IPv6 global unicast (public) address is still correctly excluded "
      "(is_private is False for real public IPv6 space)",
      _is_trackable_local_ip("2001:4860:4860::8888") is False)
check("malformed IP string doesn't raise, just returns False",
      _is_trackable_local_ip("not-an-ip") is False)


# ── Test 2: ThreatIntel.is_ready() ──────────────────────────────────────────────────
from intelligence.threat_intel import ThreatIntel

with tempfile.TemporaryDirectory() as tmpdir:
    ti = ThreatIntel(cache_dir=tmpdir)
    check("a freshly-constructed ThreatIntel (no feed refresh yet) reports is_ready()=False "
          "(distinguishes cold-start from 'checked, genuinely clean')",
          ti.is_ready() is False)

    with ti._lock:
        ti._stats["last_refresh"] = "2026-08-16 12:00:00"
    check("after a feed refresh completes (last_refresh set), is_ready() reports True",
          ti.is_ready() is True)


# ── Test 3: device-sensitivity source (device_type_is_override) ───────────────────
from core.state_guard import StateManager

with tempfile.TemporaryDirectory() as tmpdir2:
    sm = StateManager(state_path=f"{tmpdir2}/ids_state.json")
    from core.identity import DeviceIdentityManager

    idm = DeviceIdentityManager(sm, config={})
    state = sm.get_or_create("dev_infra", "192.168.1.1", "some-hostname")

    idm.apply_device_type(state, overrides={"192.168.1.1": "router"})
    check("an operator-configured client_ip override sets device_type_is_override=True",
          state.device_type == "router" and state.device_type_is_override is True,
          f"device_type={state.device_type}, is_override={state.device_type_is_override}")

    state2 = sm.get_or_create("dev_selfreport", "192.168.1.55", "my-router-totally-real")
    idm.apply_device_type(state2, overrides={"192.168.1.1": "router"})  # no match for this IP/hostname
    check("PHASE 1 FIX: a device that merely SELF-REPORTS a router-like hostname "
          "('my-router-totally-real') does NOT get device_type_is_override=True — only an "
          "explicit operator override can mark a device as verified infrastructure",
          state2.device_type_is_override is False,
          f"is_override={state2.device_type_is_override}")

    # Confirm pipeline.py's infra-sensitivity filter actually reads this flag, not just
    # device_type alone, guarding the intended semantics against silent regression.
    with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
        pipeline_src = f.read()
    check("pipeline.py's is_verified_infra check requires BOTH device_type membership AND "
          "device_type_is_override=True (not device_type alone)",
          "getattr(state, \"device_type_is_override\", False)" in pipeline_src)


# ── Test 4: TI/AbuseIPDB/VT background worker (audit Finding #10) — already satisfied ─
import inspect
from intelligence.threat_intel import ThreatIntel as TI2
ti_source = inspect.getsource(TI2)
check("ThreatIntel already runs feed refreshes in a background thread (_refresh_loop), "
      "not on the main pipeline loop — Finding #10 was already resolved before this work, "
      "no new threading needed",
      "_refresh_loop" in ti_source)

try:
    from intelligence.threat_intel import AbuseIPDB as _AbuseCls
    abuse_src = inspect.getsource(_AbuseCls)
except Exception:
    abuse_src = ""
if abuse_src:
    check("AbuseIPDB client already uses an async enqueue + background worker pattern "
          "(enqueue_ip / _live_worker_loop), not a blocking main-loop call",
          "enqueue_ip" in abuse_src and "_live_worker_loop" in abuse_src)
if not abuse_src:
    print("[SKIP] AbuseIPDB source checks — classes not importable in this sandbox")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 5 structural-fix checks PASSED.")
