"""
Standalone runtime test for src/core/metrics_sync.py's MetricsExporter --
regression coverage for the 2026-09-23 restart-cadence investigation's fourth
finding: _get_metric_keys() called metric.collect() (a full scan of every
currently-registered label combination) once per device, every cycle, inside
the *_purge_stale_*() methods -- real O(devices^2) work per cycle across
~50 metrics, caught live stalling the main detection loop for 15-20s.

Fixed by caching each metric's collect() result for the span of one export
cycle (MetricsExporter.begin_metrics_cycle(), called once by pipeline.py's
_step() before its per-device loop, not per device). This test proves two
things black-box, with no monkeypatching:
  1. The cache actually caches (a label added mid-cycle is invisible to a
     second _get_metric_keys() call in the SAME cycle).
  2. The cache is not a permanent blind spot -- begin_metrics_cycle() at the
     start of the NEXT cycle makes a genuinely stale label purgeable, closing
     the exact class of bug (killchain_phase_metric, see metrics_sync.py's
     own comment on _DEVICE_GAUGES) this file was already patched for once.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_metrics_sync_purge_cache.py`
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


from core.metrics_sync import MetricsExporter  # noqa: E402
from metrics import threat_confidence_metric  # noqa: E402

exporter = MetricsExporter()

# --- 1: the cache actually caches within one cycle ---
exporter.begin_metrics_cycle()
threat_confidence_metric.labels("devA", "hostA", "iot").set(0.1)
keys_before = exporter._get_metric_keys(threat_confidence_metric)
check("1: devA's own freshly-set label is visible on the FIRST scan this cycle",
      ("devA", "hostA", "iot") in keys_before, f"got {keys_before}")

threat_confidence_metric.labels("devB", "hostB", "iot").set(0.2)
keys_after = exporter._get_metric_keys(threat_confidence_metric)
check("2: a label added AFTER the first scan is invisible to a second call in "
      "the SAME cycle -- proves this is actually served from cache, not a "
      "fresh collect() every call",
      ("devB", "hostB", "iot") not in keys_after, f"got {keys_after}")
check("2b: the cached result is stable (same object contents) across repeated "
      "calls within one cycle",
      keys_before == keys_after)

# --- 2: begin_metrics_cycle() at the next cycle boundary makes the new label
# visible again -- the cache is a per-cycle snapshot, not a permanent one ---
exporter.begin_metrics_cycle()
keys_next_cycle = exporter._get_metric_keys(threat_confidence_metric)
check("3: after begin_metrics_cycle() (the next real cycle boundary), devB's "
      "label -- added last cycle -- is now visible",
      ("devB", "hostB", "iot") in keys_next_cycle, f"got {keys_next_cycle}")

# --- 3: end-to-end purge correctness across a simulated hostname change,
# spanning two cycles -- the exact real-world scenario (identity manager
# reassigns a device's hostname) this whole mechanism exists to clean up.
# Real call order, matching export_device_telemetry() exactly: purge for
# THIS device runs BEFORE that same device's new value is set. ---
exporter.begin_metrics_cycle()
threat_confidence_metric.labels("devC", "old-host", "iot").set(0.5)

# Cycle 2: devC's hostname changes to "new-host".
exporter.begin_metrics_cycle()
exporter._purge_stale_device_labels("devC", "new-host")
threat_confidence_metric.labels("devC", "new-host", "iot").set(0.5)

keys_mid = exporter._get_metric_keys(threat_confidence_metric)
check("4: the stale old-host row was actually removed -- and _get_metric_keys() "
      "reflects that removal for the REST of the same cycle (the fix's own "
      "_remove_and_uncache() helper), not just in the live Prometheus registry",
      ("devC", "old-host", "iot") not in keys_mid, f"got {keys_mid}")
check("4b: the new-host row -- set AFTER this cycle's cache was already "
      "populated by the purge call above -- is correctly invisible until the "
      "NEXT cycle (same one-cycle-lag behavior proven in check 2, not a "
      "special case for a row that was just purged)",
      ("devC", "new-host", "iot") not in keys_mid, f"got {keys_mid}")

# --- 4: on the FOLLOWING cycle, devC's real current state (new-host) is
# fully visible, and a totally unrelated device (devD, purged in the same
# real call order: purge-before-set) is correctly left alone -- the shared
# per-cycle cache doesn't cross-contaminate devices, since every
# _purge_stale_*() call filters strictly on its own dev_id ---
exporter.begin_metrics_cycle()
exporter._purge_stale_device_labels("devD", "hostD")  # brand new device: nothing stale to remove
threat_confidence_metric.labels("devD", "hostD", "iot").set(0.9)
exporter.begin_metrics_cycle()
keys_final = exporter._get_metric_keys(threat_confidence_metric)
check("5: devC's new-host row is now visible (one cycle later, as designed)",
      ("devC", "new-host", "iot") in keys_final, f"got {keys_final}")
check("5b: devD's own row survived its own (no-op) purge call and is visible "
      "one cycle later, unaffected by devC's unrelated change",
      ("devD", "hostD", "iot") in keys_final, f"got {keys_final}")

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILURE(S): {FAILURES}")
    sys.exit(1)
else:
    print("All checks passed.")
