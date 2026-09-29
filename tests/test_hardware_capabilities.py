"""
Standalone runtime test for the shared hardware-capability-detection layer
(PRODUCTIZATION_ROADMAP.md Phase 0). Not part of a pytest suite -- run
directly: `python3 test_hardware_capabilities.py`.

Runs on whatever platform dev/CI happens to be on (this project's own dev
venv is Windows) -- every check here is about the module's degrade-gracefully
CONTRACT (never raise, return a well-formed CapabilityResult, correctly diff
transitions), not about actually validating real Pi hardware, which needs a
live device.
"""
import json
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.hardware_capabilities import (
    CapabilityRegistry,
    CapabilityResult,
    candidate_capture_interfaces,
    check_llm_eligible,
    detect_total_ram_gb,
    validate_mirror_traffic,
)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: presence checks never raise, even on a platform with no /sys/class/net
# ═══════════════════════════════════════════════════════════════════════════════════
ifaces = candidate_capture_interfaces()
check("candidate_capture_interfaces() returns a list without raising",
      isinstance(ifaces, list))
check("candidate_capture_interfaces() excludes loopback",
      "lo" not in ifaces)
check("candidate_capture_interfaces() excludes virtual/container interfaces",
      "docker0" not in ifaces)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: validate_mirror_traffic degrades cleanly on a bogus/absent interface
# ═══════════════════════════════════════════════════════════════════════════════════
mirror_result = validate_mirror_traffic("definitely-not-a-real-interface-xyz", sample_seconds=0.1)
check("validate_mirror_traffic() returns a CapabilityResult, never raises",
      isinstance(mirror_result, CapabilityResult))
check("validate_mirror_traffic() on a nonexistent interface is not validated",
      mirror_result.validated is False)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: RAM detection distinguishes "checked, doesn't qualify" from "can't check"
# ═══════════════════════════════════════════════════════════════════════════════════
total_ram = detect_total_ram_gb()
check("detect_total_ram_gb() returns None or a positive float",
      total_ram is None or total_ram > 0)

llm_result = check_llm_eligible(min_gb=7.0)
check("check_llm_eligible() returns a CapabilityResult, never raises",
      isinstance(llm_result, CapabilityResult))
if total_ram is None:
    check("check_llm_eligible() reports unvalidated when RAM can't be read",
          llm_result.validated is False)
else:
    check("check_llm_eligible() reports validated when RAM was actually read",
          llm_result.validated is True)
    check("check_llm_eligible()'s present flag matches the real RAM-vs-floor comparison",
          llm_result.present == (total_ram >= 7.0))

# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: CapabilityRegistry -- bidirectional transition detection + persistence
# ═══════════════════════════════════════════════════════════════════════════════════
_scratch_dir = _PathForSysPath(__file__).resolve().parent / "_hc_test_scratch"
_scratch_dir.mkdir(exist_ok=True)

state_path = _scratch_dir / "first_success.json"
state_path.unlink(missing_ok=True)
registry = CapabilityRegistry(state_path=state_path)
registry.register("always_validated", lambda: CapabilityResult(
    name="always_validated", present=True, validated=True, detail="ok", checked_at=0.0))
results = registry.evaluate()
check("a capability validated for the first time is reported as 'appeared'",
      results["always_validated"]["transition"] == "appeared")
check("evaluate() persists a snapshot file",
      state_path.is_file())

disappear_path = _scratch_dir / "disappear.json"
disappear_path.write_text(json.dumps({
    "flaky": {"name": "flaky", "present": True, "validated": True, "detail": "ok", "checked_at": 0.0}
}), encoding="utf-8")
registry2 = CapabilityRegistry(state_path=disappear_path)
registry2.register("flaky", lambda: CapabilityResult(
    name="flaky", present=False, validated=False, detail="gone", checked_at=1.0))
results2 = registry2.evaluate()
check("a previously-validated capability that fails now is reported as 'disappeared'",
      results2["flaky"]["transition"] == "disappeared")

stable_path = _scratch_dir / "stable.json"
stable_path.unlink(missing_ok=True)
registry3 = CapabilityRegistry(state_path=stable_path)
registry3.register("stable", lambda: CapabilityResult(
    name="stable", present=True, validated=True, detail="ok", checked_at=0.0))
registry3.evaluate()
results3 = registry3.evaluate()
check("a capability that stays validated across two runs is reported as 'unchanged'",
      results3["stable"]["transition"] == "unchanged")

broken_path = _scratch_dir / "broken.json"
broken_path.unlink(missing_ok=True)
registry4 = CapabilityRegistry(state_path=broken_path)
def _boom():
    raise RuntimeError("simulated hardware read failure")
registry4.register("broken", _boom)
results4 = registry4.evaluate()
check("a check function that raises is caught, not propagated",
      results4["broken"]["validated"] is False and "simulated hardware read failure" in results4["broken"]["detail"])

# cleanup
for p in _scratch_dir.glob("*.json"):
    p.unlink(missing_ok=True)
_scratch_dir.rmdir()

if FAILURES:
    print(f"\n{len(FAILURES)} hardware-capabilities check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll hardware-capabilities checks PASSED.")
    sys.exit(0)
