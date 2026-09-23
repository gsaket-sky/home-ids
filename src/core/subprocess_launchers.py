"""
subprocess_launchers.py -- shared Popen construction for the two subprocesses
main.py spawns (the console/API server, the background job scheduler).

Extracted out of main.py's own two inline blocks so boot-time startup and a
later health-manager RECOVERY_ATTEMPT restart share exactly one implementation
instead of two copies that can silently drift apart. Behavior is unchanged from
the original inline code -- same log file paths, same stdout/stderr redirect
(PHASE 9 FIX's own reasoning: a child with no explicit redirect inherits the
parent's fds, so DEVNULL would silently swallow the child's own logs too),
same failure handling.
"""
import logging
import subprocess
import sys
from pathlib import Path
from typing import IO, Optional, Tuple

LOGGER = logging.getLogger("home_ids.subprocess_launchers")

DEFAULT_SUBPROCESS_LOG_MAX_BYTES = 50 * 1024 * 1024  # 50MB per log, matches this repo's other size-capped writers' order of magnitude


def rotate_subprocess_log_if_oversized(path: Path, max_bytes: int = DEFAULT_SUBPROCESS_LOG_MAX_BYTES) -> bool:
    """Disk-retention audit fix: fritz_webhook.log/scheduler.log are raw
    `subprocess.Popen(stdout=open(path, "a"))` redirects held open for the life of
    the child process -- not Python logging, so RotatingFileHandler doesn't apply,
    and a simple rename-based rotation (this repo's AlertJSONWriter pattern) would
    leave the long-lived child still writing into the renamed-away file forever.
    Uses copytruncate instead: back up the current contents, then truncate the file
    to 0 bytes IN PLACE (not rename). This is safe specifically because Python's "a"
    mode sets O_APPEND, so the child's next write() atomically seeks to the kernel's
    current end-of-file (now 0) rather than its own cached pre-truncate offset --
    the same reasoning logrotate's own copytruncate strategy relies on. Returns True
    if a rotation happened. Meant to be polled periodically (e.g. the main loop's
    existing hourly prune tick), not on every subprocess spawn -- these processes
    can run for the box's entire uptime between restarts.
    """
    try:
        if not path.exists() or path.stat().st_size < max_bytes:
            return False
        backup_path = path.with_suffix(path.suffix + ".bak")
        try:
            if backup_path.exists():
                backup_path.unlink()
            backup_path.write_bytes(path.read_bytes())
        except Exception:
            pass  # backup is best-effort; truncating on time is what actually bounds disk usage
        with path.open("r+b") as f:
            f.truncate(0)
        LOGGER.warning("Subprocess log %s reached %d bytes; rotated (copytruncate).", path, max_bytes)
        return True
    except Exception as exc:
        LOGGER.error("Failed to rotate subprocess log %s: %s", path, exc)
        return False


def start_fastapi_subprocess(config) -> Tuple[Optional[subprocess.Popen], Optional[IO]]:
    """Starts middleware.main_api:app via uvicorn. Returns (proc, log_file) --
    both None if the port is invalid or the spawn itself failed. Caller owns
    the log_file handle's lifecycle (close it on shutdown, matches main.py's
    existing shutdown_handler pattern)."""
    fastapi_port = int(config.get("fastapi_port", 8010))
    if fastapi_port <= 0:
        LOGGER.warning("Configured fastapi_port %s is invalid; falling back to 8010.", fastapi_port)
        fastapi_port = 8010
    fastapi_bind_host = str(config.get("fastapi_bind_host", "127.0.0.1")) or "127.0.0.1"

    log_file = None
    try:
        webhook_log_path = Path("state/fritz_webhook.log")
        webhook_log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(webhook_log_path, "a")  # noqa: WPS515

        src_dir = str(Path(__file__).resolve().parent.parent)  # src/core -> src
        proc = subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn",
                "middleware.main_api:app",
                "--host", fastapi_bind_host,
                "--port", str(fastapi_port),
                "--app-dir", src_dir,
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        LOGGER.info("FastAPI Router Webhook daemon started (PID: %s). Logs -> %s", proc.pid, webhook_log_path)
        return proc, log_file
    except Exception as exc:
        LOGGER.error("Failed to start internal FastAPI daemon: %s", exc)
        if log_file and not log_file.closed:
            log_file.close()
        return None, None


def start_scheduler_subprocess() -> Tuple[Optional[subprocess.Popen], Optional[IO]]:
    """Starts scripts/scheduler.py. Returns (proc, log_file), both None on failure."""
    log_file = None
    try:
        scheduler_log_path = Path("state/scheduler.log")
        scheduler_log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(scheduler_log_path, "a")  # noqa: WPS515

        scheduler_path = Path(__file__).resolve().parent.parent / "scripts" / "scheduler.py"
        proc = subprocess.Popen(
            [sys.executable, str(scheduler_path)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        LOGGER.info("Scheduler daemon started (PID: %s). Logs -> %s", proc.pid, scheduler_log_path)
        return proc, log_file
    except Exception as exc:
        LOGGER.error("Failed to start scheduler daemon: %s", exc)
        if log_file and not log_file.closed:
            log_file.close()
        return None, None
