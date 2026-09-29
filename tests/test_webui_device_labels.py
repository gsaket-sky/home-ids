"""
Standalone runtime test for WebUI device-labeling (PRODUCTIZATION_ROADMAP.md
Phase 4) -- both the storage layer (device_labels.py) and its priority in
identity.py's apply_device_type(). Run directly:
`python3 test_webui_device_labels.py`.
"""
import sys
import tempfile
import types
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core import device_labels

_tmp = tempfile.mkdtemp()

# ── Storage layer ────────────────────────────────────────────────────────────
check("no label initially", device_labels.get_label("dev1", _tmp) is None)

device_labels.set_label("dev1", "phone", _tmp)
check("label persists after set_label()", device_labels.get_label("dev1", _tmp) == "phone")

try:
    device_labels.set_label("dev2", "not_a_real_type", _tmp)
    check("set_label() rejects an invalid device_type", False)
except ValueError:
    check("set_label() rejects an invalid device_type", True)

removed = device_labels.remove_label("dev1", _tmp)
check("remove_label() returns True for an existing label", removed is True)
check("label gone after remove_label()", device_labels.get_label("dev1", _tmp) is None)
removed_again = device_labels.remove_label("dev1", _tmp)
check("remove_label() returns False for an already-removed label", removed_again is False)

# ── Priority in identity.py's apply_device_type() ────────────────────────────
from core.identity import DeviceIdentityManager

device_labels.set_label("dev_confirmed", "nas", _tmp)
# Point device_labels.py's module-level cache at our tmp dir for this process --
# apply_device_type() calls get_confirmed_device_label(device_id) with no state_dir
# override, so it uses the default "state" -- patch the default via monkeypatch of
# the imported name in core.identity, the same boundary the real call crosses.
import core.identity as identity_module


def _patched_get_label(device_id):
    return device_labels.get_label(device_id, _tmp)


identity_module.get_confirmed_device_label = _patched_get_label

mgr = DeviceIdentityManager.__new__(DeviceIdentityManager)  # bypass __init__, only apply_device_type() under test

confirmed_state = types.SimpleNamespace(
    device_id="dev_confirmed", client_ip="192.168.1.5", hostname="some-iot-hostname",
    device_type="unknown", device_type_is_override=False, mac_address="unknown",
)
mgr.apply_device_type(confirmed_state, overrides={"some-iot-hostname": "iot"})
check("a WebUI-confirmed label outranks a config.yaml device_type_overrides match",
      confirmed_state.device_type == "nas",
      f"got {confirmed_state.device_type!r}, expected 'nas' (not the overrides-matched 'iot')")
check("device_type_is_override is set True for a confirmed label", confirmed_state.device_type_is_override is True)

unconfirmed_state = types.SimpleNamespace(
    device_id="dev_unconfirmed", client_ip="192.168.1.6", hostname="some-iot-hostname",
    device_type="unknown", device_type_is_override=False, mac_address="unknown",
)
mgr.apply_device_type(unconfirmed_state, overrides={"some-iot-hostname": "iot"})
check("an unlabeled device still falls through to config.yaml overrides",
      unconfirmed_state.device_type == "iot")


if FAILURES:
    print(f"\n{len(FAILURES)} device-labels check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll device-labels checks PASSED.")
    sys.exit(0)
