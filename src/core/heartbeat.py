"""
heartbeat.py -- the health manager's component-heartbeat registry (two channels).

Deliberately minimal imports (json/time/threading/pathlib only, no config.py, no
fastapi) so this module can be imported from scripts/scheduler.py and
middleware/main_api.py -- both separate OS processes from the main pipeline --
without pulling in the full engine. Same reasoning scripts/scheduler.py already
applies to reading config.yaml directly instead of importing config.py
(scripts/scheduler.py:58-61).

Two channels, because components live in two different places:

- IN-PROCESS components (the main pipeline loop, the identity-reconcile worker,
  the ThreatIntel refresh thread) all live inside the same Python process as the
  HealthManager that reads them -- a plain thread-safe in-memory dict is enough,
  no file I/O needed on every check cycle.
- CROSS-PROCESS components (the console/API subprocess, the scheduler subprocess)
  run in a SEPARATE process/memory space -- they self-report through a shared
  JSON file instead, same read-modify-write shape as utils.py's own
  write_job_health()/job_health.json (utils.py:209-222), just a different file
  and field set so components with a real health_state (not just "last success")
  don't have to share a schema with success-only batch-job telemetry.
"""
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from core.runtime_paths import runtime_dir

COMPONENT_HEARTBEAT_FILENAME = "component_heartbeat.json"   # in runtime_dir(): RAM in Docker


class HeartbeatRegistry:
    """In-process, thread-safe. One entry per component, overwritten on each beat()."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: Dict[str, Dict[str, Any]] = {}

    def beat(
        self,
        component: str,
        *,
        events_processed: Optional[int] = None,
        processing_latency: Optional[float] = None,
        queue_depth: Optional[int] = None,
        health_state: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> None:
        entry = {"last_heartbeat": time.time()}
        if events_processed is not None:
            entry["events_processed"] = events_processed
        if processing_latency is not None:
            entry["processing_latency"] = processing_latency
        if queue_depth is not None:
            entry["queue_depth"] = queue_depth
        if health_state is not None:
            entry["health_state"] = health_state
            if health_state in ("healthy", "ok"):
                entry["last_success"] = entry["last_heartbeat"]
        else:
            # No explicit health_state means "I ran without raising" -- treat as success.
            entry["last_success"] = entry["last_heartbeat"]
        if extra:
            entry.update(extra)
        with self._lock:
            existing = self._entries.get(component, {})
            merged = dict(existing)
            merged.update(entry)
            self._entries[component] = merged

    def get(self, component: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._entries.get(component)
            return dict(entry) if entry is not None else None

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self._entries.items()}


# Process-wide singleton -- every in-process component beats into this same instance.
HEARTBEATS = HeartbeatRegistry()


def write_component_heartbeat(state_dir, component: str, extra: Optional[dict] = None) -> None:
    """Cross-process channel counterpart to HeartbeatRegistry.beat() -- for a
    component running in a DIFFERENT OS process than the HealthManager that reads
    it (the console/API subprocess, the scheduler subprocess). Read-modify-write
    against one shared file, same last-write-wins acceptance as
    utils.write_job_health() (these are low-frequency writes, once per ~10s at
    most, from a small fixed set of known writers)."""
    path = runtime_dir(state_dir) / COMPONENT_HEARTBEAT_FILENAME
    entry = {"last_heartbeat": time.time(), "last_success": time.time()}
    if extra:
        entry.update(extra)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # W-12: five processes read-modify-write this one file. Held across the whole read-merge-write so two writers
        # cannot lose each other's entry, and replaced atomically so a reader never sees a torn file (a torn read made
        # a writer start from {} and drop everyone else's entry until they beat again: false "stale" heartbeats).
        from core.file_lock import exclusive_file_lock
        with exclusive_file_lock(path):
            try:
                existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            except Exception:
                existing = {}
            existing[component] = entry
            tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            os.replace(tmp, path)
    except Exception:
        pass  # best-effort -- a missed heartbeat write just reads as stale next cycle, not fatal.


def reset_component_heartbeats(state_dir) -> None:
    """BUGFIX (found live, 2026-09-14, immediately after the Health console tab
    deploy): component_heartbeat.json persists across process restarts (it's
    just a file, nothing clears it). On every soc.service restart, HealthManager's
    very first check cycle runs essentially immediately -- long before the
    freshly-spawned api_subprocess/scheduler_subprocess have had their own ~10s
    to write a first heartbeat -- and it would read whatever STALE entry
    survived from the PREVIOUS process's life instead. Confirmed live: this
    read as "946s stale" on a subprocess that had, in reality, been running
    and healthy for under a minute, correctly triggering a RECOVERY_ATTEMPT
    that bounced an already-fine subprocess on every single restart -- the
    exact "unnecessary restart churn" this subsystem's own design doc
    (My_way_forward.txt) explicitly warned against. Called once at the very
    top of main(), before either subprocess is spawned, so this boot starts
    with a clean slate -- HeartbeatRegistry-style "never beaten yet" is
    already a safe no-op (see health_manager.py's _evaluate_heartbeat_component),
    it's specifically a STALE-but-present entry that was the problem."""
    path = runtime_dir(state_dir) / COMPONENT_HEARTBEAT_FILENAME
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass


def read_component_heartbeats(state_dir) -> Dict[str, Dict[str, Any]]:
    path = runtime_dir(state_dir) / COMPONENT_HEARTBEAT_FILENAME
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
