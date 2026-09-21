"""
Standalone runtime test for Phase 64 (HEE_ROADMAP.md item 3, "correct device identity"):
fp_engine.py's mark_false_positive() previously had no check that the device_id it was
about to scope an immunization to still resolves to a currently-known canonical device.
An alert published hours or days earlier could name a device_id that's since been folded
into a different canonical identity by StateManager.merge_into_canonical() (the
device-identity-fragmentation fix, shipped/live-verified 2026-08-25 -- see
DEVICE_IDENTITY_LIFECYCLE.md) -- immunizing under the stale id either under-protects (the
real device keeps alerting under its new id, uncovered) or scopes trust to an identity
nothing is tracked under anymore.

The fix: AutonomousFPEngine.__init__() gained an optional `state_manager` param (None for
any caller without a live StateManager -- most standalone scripts construct a fresh
AutonomousFPEngine without one, per the codebase's own optional/defaulted/single-consumer
convention). mark_false_positive() now refuses (mirrors the existing hard-stop-signature
guard's return shape) when state_manager is available AND device_id is a real value AND
state_manager.has_device(device_id) is False.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase64_device_identity_guard.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time
import tempfile

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.fp_engine import AutonomousFPEngine


class _FakeStateManager:
    """Minimal stand-in exposing only the one public method mark_false_positive()'s
    guard actually calls -- StateManager.has_device() (core/state_guard.py:357-359,
    `return device_id in self._states`). Avoids constructing a real StateManager (which
    touches actual state-file I/O) just to exercise this one check."""
    def __init__(self, known_ids):
        self._known = set(known_ids)

    def has_device(self, device_id: str) -> bool:
        return device_id in self._known


def _alert(device_id: str, domain: str) -> dict:
    return {
        "device": {"id": device_id, "hostname": "host-" + device_id},
        "network_context": {"queried_domain": domain, "destination_ip": "5.5.5.5"},
        "signature": "DGA_BOTNET_C2",
        "timestamp": time.time(),
    }


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: no state_manager at all (default None) -- every existing caller that
# hasn't threaded one through (most standalone scripts) must be completely unaffected
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp_no_sm = AutonomousFPEngine(config={}, state_dir=tmpdir)
    result = fp_no_sm.mark_false_positive(_alert("dev_unverified", "no-sm-check.example.com"), "host")
    check("REGRESSION GUARD: state_manager=None (default) never refuses on device-identity "
          "grounds -- this check is a no-op wherever a live StateManager isn't available",
          result.get("is_new_immunization") is True and not result.get("refused"),
          f"got {result}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: THE FIX -- a device_id that does NOT resolve in the provided StateManager
# (e.g. it was merged into a different canonical id since this alert was published)
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    sm = _FakeStateManager(known_ids={"dev_still_canonical"})
    fp_stale = AutonomousFPEngine(config={}, state_dir=tmpdir, state_manager=sm)
    result_stale = fp_stale.mark_false_positive(
        _alert("dev_merged_away", "stale-device.example.com"), "host"
    )
    check("THE FIX: a device_id no longer known to StateManager is REFUSED, not silently "
          "immunized under a stale identity",
          result_stale.get("refused") is True and result_stale.get("is_new_immunization") is False,
          f"got {result_stale}")
    check("THE FIX: the refusal reason names the offending device_id",
          "dev_merged_away" in (result_stale.get("refused_reason") or ""),
          f"got {result_stale}")
    check("THE FIX: a refused immunization writes NOTHING to the trust cache for this domain",
          "stale-device.example.com" not in fp_stale.get_dynamic_trust_cache(),
          f"trust cache={fp_stale.get_dynamic_trust_cache()}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: REGRESSION GUARD -- a device_id that DOES resolve still immunizes normally
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    sm = _FakeStateManager(known_ids={"dev_still_canonical"})
    fp_valid = AutonomousFPEngine(config={}, state_dir=tmpdir, state_manager=sm)
    result_valid = fp_valid.mark_false_positive(
        _alert("dev_still_canonical", "valid-device.example.com"), "host"
    )
    check("REGRESSION GUARD: a device_id that IS currently canonical is never refused by "
          "this check -- the guard narrows a real gap, it doesn't disable immunization",
          result_valid.get("is_new_immunization") is True and not result_valid.get("refused"),
          f"got {result_valid}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: REGRESSION GUARD -- device_id=="unknown" (alert_payload's own fallback for
# a missing device.id) has nothing to validate against and must not be refused by this
# check specifically (it may still be refused/no-op for other, unrelated reasons)
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    sm = _FakeStateManager(known_ids={"dev_still_canonical"})
    fp_unknown = AutonomousFPEngine(config={}, state_dir=tmpdir, state_manager=sm)
    alert_no_device = {
        "device": {},
        "network_context": {"queried_domain": "no-device-id.example.com", "destination_ip": "6.6.6.6"},
        "signature": "DGA_BOTNET_C2",
        "timestamp": time.time(),
    }
    result_unknown = fp_unknown.mark_false_positive(alert_no_device, "host")
    check("REGRESSION GUARD: device_id=='unknown' (no device.id in alert_payload) is never "
          "refused BY THIS CHECK -- there's nothing to validate against, so it must not be "
          "the reason a legitimate correction gets blocked",
          result_unknown.get("refused_reason", "").find("device_id 'unknown'") == -1,
          f"got {result_unknown}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 64 device-identity immunization-guard checks PASSED.")
