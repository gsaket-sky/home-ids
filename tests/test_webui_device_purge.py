"""
Standalone runtime test for /api/ipc/device/{id}/purge (PRODUCTIZATION_ROADMAP.md
Phase 4 Maintenance page). Confirms a purge removes the device from
StateManager AND all three side files, and leaves other devices untouched.
Run directly: `python3 test_webui_device_purge.py`.
"""
import json
import sys
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.state_guard import StateManager

_tmp = _PathForSysPath(tempfile.mkdtemp())
_tmp.mkdir(exist_ok=True)

# ── StateManager.remove_device() ─────────────────────────────────────────────
sm = StateManager(state_path=str(_tmp / "ids_state.json"))
sm.get_or_create("dev_keep", "192.168.1.10", "keep-me")
sm.get_or_create("dev_purge", "192.168.1.20", "purge-me")
sm.bind_mac("aa:bb:cc:dd:ee:ff", "dev_purge")

check("both devices tracked before purge", sm.has_device("dev_keep") and sm.has_device("dev_purge"))

existed = sm.remove_device("dev_purge")
check("remove_device() returns True for a tracked device", existed is True)
check("purged device is gone", not sm.has_device("dev_purge"))
check("other device untouched by purge", sm.has_device("dev_keep"))
check("MAC index no longer resolves to the purged device", sm.get_device_id_for_mac("aa:bb:cc:dd:ee:ff") is None)

existed_again = sm.remove_device("dev_purge")
check("remove_device() returns False for an already-purged device", existed_again is False)

# ── webui_ipc.py's endpoint cascades to the side files ───────────────────────
state_dir = _tmp / "cascade"
state_dir.mkdir()
(state_dir / "device_fp_profiles.json").write_text(json.dumps({
    "dev_purge": {"fp_combined_suppress_threshold": {"value": 0.9}},
    "dev_keep": {"fp_combined_suppress_threshold": {"value": 0.8}},
}))
(state_dir / "fp_sigma_shifts.json").write_text(json.dumps({"dev_purge": 1.5, "dev_keep": 0.5}))

from middleware.routers.webui_ipc import _purge_fp_engine_device_files
from core.device_labels import set_label, get_label

set_label("dev_purge", "phone", str(state_dir))
set_label("dev_keep", "nas", str(state_dir))

_purge_fp_engine_device_files(str(state_dir), "dev_purge")
from core.device_labels import remove_label
remove_label("dev_purge", str(state_dir))

fp_profiles = json.loads((state_dir / "device_fp_profiles.json").read_text())
sigma_shifts = json.loads((state_dir / "fp_sigma_shifts.json").read_text())

check("purge removes the device from device_fp_profiles.json", "dev_purge" not in fp_profiles)
check("purge leaves other devices in device_fp_profiles.json", "dev_keep" in fp_profiles)
check("purge removes the device from fp_sigma_shifts.json", "dev_purge" not in sigma_shifts)
check("purge leaves other devices in fp_sigma_shifts.json", "dev_keep" in sigma_shifts)
check("purge removes the device's WebUI label", get_label("dev_purge", str(state_dir)) is None)
check("purge leaves other devices' WebUI labels", get_label("dev_keep", str(state_dir)) == "nas")


if FAILURES:
    print(f"\n{len(FAILURES)} device-purge check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll device-purge checks PASSED.")
    sys.exit(0)
