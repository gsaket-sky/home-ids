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
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

COMPONENT_HEARTBEAT_FILENAME = "component_heartbeat.json"


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
    path = Path(state_dir) / COMPONENT_HEARTBEAT_FILENAME
    try:
        existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        existing = {}
    entry = {"last_heartbeat": time.time(), "last_success": time.time()}
    if extra:
        entry.update(extra)
    existing[component] = entry
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    except Exception:
        pass  # best-effort -- a missed heartbeat write just reads as stale next cycle, not fatal.


def read_component_heartbeats(state_dir) -> Dict[str, Dict[str, Any]]:
    path = Path(state_dir) / COMPONENT_HEARTBEAT_FILENAME
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
