"""
Standalone runtime test for the onboarding grace-period gate
(PRODUCTIZATION_ROADMAP.md Phase 4). Run directly: `python3 test_webui_onboarding_gate.py`.
"""
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.onboarding import get_onboarding_status, is_onboarding_active, activate_protection_now

_tmp = tempfile.mkdtemp()


class _Cfg(dict):
    def get(self, k, d=None):
        return super().get(k, d)


# ── Fresh install: onboarding active from first read ────────────────────────
state_dir_a = str(_PathForSysPath(_tmp) / "a")
cfg = _Cfg({"onboarding_mode_days": 14})
status = get_onboarding_status(cfg, state_dir_a)
check("fresh install starts with onboarding active", status["active"] is True)
check("fresh install reports close to the full grace period remaining",
      13.9 <= status["days_remaining"] <= 14.0)
check("state/onboarding.json is created on first read", (_PathForSysPath(state_dir_a) / "onboarding.json").exists())

# ── onboarding_mode_days = 0 disables it entirely ────────────────────────────
state_dir_b = str(_PathForSysPath(_tmp) / "b")
cfg_disabled = _Cfg({"onboarding_mode_days": 0})
check("onboarding_mode_days=0 disables onboarding", is_onboarding_active(cfg_disabled, state_dir_b) is False)

# ── Manual activation ends onboarding immediately, idempotently ─────────────
state_dir_c = str(_PathForSysPath(_tmp) / "c")
cfg_c = _Cfg({"onboarding_mode_days": 14})
check("onboarding starts active", is_onboarding_active(cfg_c, state_dir_c) is True)
activate_protection_now(state_dir_c)
check("activate_protection_now() ends onboarding", is_onboarding_active(cfg_c, state_dir_c) is False)
first_status = get_onboarding_status(cfg_c, state_dir_c)
activate_protection_now(state_dir_c)  # calling again should not reset activated_at
second_status = get_onboarding_status(cfg_c, state_dir_c)
check("activate_protection_now() is idempotent (activated_at doesn't move)",
      first_status["activated_at"] == second_status["activated_at"])

# ── mitigate()'s onboarding gate actually withholds action ──────────────────
import types
from mitigation.ips import IPSMitigator

state_dir_d = str(_PathForSysPath(_tmp) / "d")
_PathForSysPath(state_dir_d).mkdir(parents=True, exist_ok=True)


class _FakeStateManager:
    def get_ips_state(self):
        return {"retry_queue": {}, "dead_letter": {}, "tarpit_targets": {},
                "router_isolated_devices": {}, "operator_released_devices": {}}


mitigator = IPSMitigator.__new__(IPSMitigator)  # bypass __init__ (starts threads) -- unit-level only
mitigator.config = _Cfg({
    "onboarding_mode_days": 14, "state_path": f"{state_dir_d}/ids_state.json",
    "ips_pihole_enabled": True, "ips_router_enabled": True, "ips_tarpit_enabled": True,
    "ips_enabled": True, "operator_release_cooldown_seconds": 3600.0,
    "interactive_blocking_enabled": False, "safe_domains": [],
})
mitigator._tarpit_active_targets = {}
mitigator._router_isolated_devices = {}
mitigator._operator_released_devices = {}
mitigator._lock = __import__("threading").RLock()
mitigator.state_manager = _FakeStateManager()

blocked_calls = []
mitigator._block_domain = lambda **kw: blocked_calls.append(kw)

fake_device = types.SimpleNamespace(
    client_ip="192.168.1.99", hostname="test-device", device_id="dev_test", mac_address="aa:bb:cc:dd:ee:ff",
)
# risk_score kept below the router (8.5)/tarpit (9.0) thresholds deliberately -- this
# test only needs to isolate the Pi-hole path, not exercise router/tarpit's own
# StateManager persistence calls, which need a fuller fake than this test provides.
mitigator.mitigate(
    st=fake_device, target_domain="evil.example", risk_score=5.0, lateral_threat=False,
    is_safe=False, reason="test", decision_state="CRITICAL",
)
check("onboarding-active mitigate() withholds Pi-hole block", len(blocked_calls) == 0,
      f"got {len(blocked_calls)} block call(s)")

# Now end onboarding and confirm the SAME call actually blocks
activate_protection_now(state_dir_d)
mitigator.mitigate(
    st=fake_device, target_domain="evil.example", risk_score=5.0, lateral_threat=False,
    is_safe=False, reason="test", decision_state="CRITICAL",
)
check("post-onboarding mitigate() blocks normally", len(blocked_calls) == 1,
      f"got {len(blocked_calls)} block call(s)")


if FAILURES:
    print(f"\n{len(FAILURES)} onboarding-gate check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll onboarding-gate checks PASSED.")
    # os._exit(), not sys.exit(): importing mitigation.ips pulls in scapy, which in
    # this dev environment (no real libpcap provider on Windows) leaves a lingering
    # non-daemon thread that blocks a normal interpreter shutdown -- pre-existing
    # scapy/environment behavior, unrelated to anything under test here. All checks
    # above have already passed by this point.
    import os
    os._exit(0)
