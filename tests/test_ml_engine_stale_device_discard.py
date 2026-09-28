"""
Standalone runtime test (not part of the pytest suite -- run directly:
`python3 test_ml_engine_stale_device_discard.py`), matching the style of
test_phase0_fixes.py.

Covers the 2026-09-21 memory-capacity investigation's fix: pipeline.py's
age-out device pruning (prune_stale_devices(), ~7-day idle default) now also
calls ml_registry.discard_device(dev_id, reason="prune") -- previously only
merge_into_canonical() ever called discard_device(), so a device that went
stale WITHOUT ever merging kept its DeviceMLEngine resident in
MultiDeviceMLEngine.devices forever (bounded only by the 200-active-device
LRU cap, which real household/small-business device counts never reach) and
its .pkl file on disk forever (re-globbed and re-loaded on every future
process restart via load_models(), regardless of the in-memory LRU cap).

This test exercises MultiDeviceMLEngine.discard_device() directly (the
primitive pipeline.py now calls) rather than pipeline.py's own _step(),
which -- per test_phase40_alert_button_containment_sync.py's own documented
reasoning -- is too large/deeply-embedded to invoke directly in a test.
"""
import shutil
import sys
import tempfile
from pathlib import Path as _PathForSysPath

sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

import numpy as np
from sklearn.ensemble import IsolationForest

from intelligence.ml_engine import MultiDeviceMLEngine

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


tmp_dir = tempfile.mkdtemp(prefix="ml_engine_discard_test_")
try:
    registry = MultiDeviceMLEngine(model_dir=tmp_dir)

    # ── Test 1: discard_device() removes a warmed-up device's in-memory engine
    # and its on-disk .pkl file ─────────────────────────────────────────────
    dev_id = "stale_device_0001"
    engine = registry._get_or_create_device(dev_id)
    engine.model = IsolationForest(contamination=0.01, random_state=42).fit(
        np.random.rand(20, 11)
    )
    engine.warmed_up = True
    registry.save_models(wait=True)

    model_path = registry.model_dir / f"{dev_id}.pkl"
    check("model file exists on disk before discard", model_path.exists())
    check("device is tracked in-memory before discard", dev_id in registry.devices)

    result = registry.discard_device(dev_id, reason="prune")
    check("discard_device() returns True when it actually removed something", result is True)
    check("device is no longer in the in-memory registry after discard",
          dev_id not in registry.devices)
    check("model file is deleted from disk after discard", not model_path.exists())

    # ── Test 2: idempotent no-op for a device that was never loaded ────────
    result_noop = registry.discard_device("never_seen_device", reason="prune")
    check("discard_device() on an unknown device_id returns False, doesn't raise",
          result_noop is False)

    # ── Test 3: discard_device() with reason="prune" behaves identically to
    # the pre-existing reason="merge" call site -- reason only labels the
    # metric, never changes removal behavior ───────────────────────────────
    dev_id_2 = "stale_device_0002"
    registry._get_or_create_device(dev_id_2)
    check("second device is tracked before discard", dev_id_2 in registry.devices)
    result_2 = registry.discard_device(dev_id_2, reason="merge")
    check("discard_device(reason='merge') still works exactly as before this fix",
          result_2 is True and dev_id_2 not in registry.devices)

finally:
    shutil.rmtree(tmp_dir, ignore_errors=True)


if FAILURES:
    print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
    sys.exit(1)
else:
    print("\nAll checks passed.")
