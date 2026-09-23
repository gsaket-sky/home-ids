"""
job_result_channel.py -- hands a scheduled job's result (duration + its own numeric
stats) to the process that launched it, over an inherited pipe, so the launcher can
export it to Prometheus directly. No state file involved.

Why: scheduled jobs are short-lived subprocesses with no HTTP endpoint of their own.
Their results used to reach Prometheus only through state/job_health.json, a relay
file re-read by the main engine -- which also meant a job killed mid-run left no
trace at all. The scheduler daemon (scripts/scheduler.py) already owns every job's
Popen handle, sees its exit code and runtime first-hand, and now serves its own
/metrics endpoint; this channel carries the one thing it can't observe itself: the
job's own result numbers.

Protocol: the launcher creates a pipe, passes the write end to the child via
`pass_fds` and the environment variable RESULT_FD_ENV, and reads whatever the child
wrote once it exits. The child writes one JSON object per line. Every call here is
best-effort and non-blocking -- a result channel can never break or stall a job.
"""
import json
import logging
import os
from typing import Dict, Optional, Tuple

LOGGER = logging.getLogger("job_result_channel")

RESULT_FD_ENV = "HOME_IDS_JOB_RESULT_FD"
_MAX_RESULT_BYTES = 60_000  # stays under the smallest common pipe buffer (64 KiB) -- a write never blocks


def publish(job_name: str, duration_seconds: float, extra: Optional[dict] = None, status: str = "success") -> bool:
    """Child side. No-op (returns False) when not launched through a result channel."""
    raw_fd = os.environ.get(RESULT_FD_ENV)
    if not raw_fd:
        return False
    try:
        fd = int(raw_fd)
        payload = {"job": job_name, "status": status, "duration_seconds": float(duration_seconds),
                   "extra": extra or {}}
        data = (json.dumps(payload, default=str) + "\n").encode("utf-8")
        if len(data) > _MAX_RESULT_BYTES:
            payload["extra"] = {k: v for k, v in (extra or {}).items() if not isinstance(v, (dict, list))}
            payload["truncated"] = True
            data = (json.dumps(payload, default=str) + "\n").encode("utf-8")[:_MAX_RESULT_BYTES]
        os.write(fd, data)
        return True
    except Exception as exc:  # closed/invalid fd, full pipe -- never fatal to the job
        LOGGER.debug("job result channel write failed for %s: %s", job_name, exc)
        return False


def open_channel() -> Tuple[int, int]:
    """Launcher side: returns (read_fd, write_fd). The read end is non-blocking."""
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    return read_fd, write_fd


def child_env(write_fd: int) -> Dict[str, str]:
    env = dict(os.environ)
    env[RESULT_FD_ENV] = str(write_fd)
    return env


def collect(read_fd: int) -> Optional[dict]:
    """Launcher side, after the child exited: returns the LAST result the child
    published (a job normally publishes once, at the end), or None. Closes read_fd."""
    chunks = []
    try:
        while True:
            try:
                chunk = os.read(read_fd, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    except Exception as exc:
        LOGGER.debug("job result channel read failed: %s", exc)
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
    result = None
    for line in b"".join(chunks).decode("utf-8", errors="replace").splitlines():
        try:
            result = json.loads(line)
        except ValueError:
            continue
    return result


def numeric_fields(extra: dict, prefix: str = "") -> Dict[str, float]:
    """Flattens a job's extra dict one level deep into {field: number}, dropping
    anything non-numeric. Nested dicts become "outer.inner". Per-device maps (dicts
    of dicts, or large dicts) are NOT flattened here -- see per_device_fields()."""
    out: Dict[str, float] = {}
    for key, value in (extra or {}).items():
        name = f"{prefix}{key}"
        if isinstance(value, bool):
            out[name] = 1.0 if value else 0.0
        elif isinstance(value, (int, float)):
            out[name] = float(value)
        elif isinstance(value, dict) and not prefix and not key.endswith("_by_device"):
            out.update(numeric_fields(value, prefix=f"{name}."))
    return out


def per_device_fields(extra: dict) -> Dict[str, Dict[str, float]]:
    """{field: {device_id: number}} for every `*_by_device` map a job reports."""
    out: Dict[str, Dict[str, float]] = {}
    for key, value in (extra or {}).items():
        if key.endswith("_by_device") and isinstance(value, dict):
            out[key] = {str(dev): float(n) for dev, n in value.items()
                        if isinstance(n, (int, float)) and not isinstance(n, bool)}
    return out
