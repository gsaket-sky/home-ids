"""
Standalone runtime test for /api/ipc/device/{id}/purge (PRODUCTIZATION_ROADMAP.md
Phase 4 Maintenance page). Confirms a purge removes the device from
StateManager, its learned false-positive values in the graph and its label, and leaves
other devices untouched.
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

# ── webui_ipc.py's endpoint clears the device's learned values and label ─────
state_dir = _tmp / "cascade"
state_dir.mkdir()

from argus.graph.store import GraphStore
from middleware.routers.webui_ipc import _purge_learned_fp_values
from core.device_labels import set_label, get_label, remove_label

store = GraphStore(str(state_dir / "v13_graph.db"))
for dev, thr, shift in (("dev_purge", 0.9, 1.5), ("dev_keep", 0.8, 0.5)):
    store.update_device_metadata(dev, {"fp_profile": {"fp_combined_suppress_threshold": {"value": thr}},
                                       "sigma_shift": shift, "confirmed_threat_counts": {"_total": 2}}, timestamp=1.0)
store.close()
set_label("dev_purge", "phone", str(state_dir))
set_label("dev_keep", "nas", str(state_dir))

_purge_learned_fp_values(str(state_dir), "dev_purge")
remove_label("dev_purge", str(state_dir))

store = GraphStore(str(state_dir / "v13_graph.db"))
purged, kept = store.get_device_metadata("dev_purge"), store.get_device_metadata("dev_keep")
check("purge clears the device's per-device thresholds", purged.get("fp_profile") == {})
check("purge clears the device's sensitivity shift", purged.get("sigma_shift") == 0.0)
check("purge clears the device's confirmed-threat counts", purged.get("confirmed_threat_counts") == {})
check("purge leaves other devices' learned values",
      kept.get("fp_profile", {}).get("fp_combined_suppress_threshold", {}).get("value") == 0.8
      and kept.get("sigma_shift") == 0.5)
_purge_learned_fp_values(str(state_dir), "never_seen")
check("purging an unknown device adds nothing to the graph", store.get_device_metadata("never_seen") == {})
store.close()
check("purge removes the device's WebUI label", get_label("dev_purge", str(state_dir)) is None)
check("purge leaves other devices' WebUI labels", get_label("dev_keep", str(state_dir)) == "nas")


if FAILURES:
    print(f"\n{len(FAILURES)} device-purge check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll device-purge checks PASSED.")
    sys.exit(0)
