"""
file_lock.py - cross-process exclusive lock for read-modify-write of a shared JSON file.

Several processes (engine, API subprocess, WebUI, autotune) each read state/config_overrides.json,
merge one key, and atomically replace it. A threading.Lock only serialises threads inside one process,
so two processes could read the same snapshot and the later write silently drops the other's key (W / C:
config-overrides lost update). This takes an advisory lock on a sidecar "<file>.lock" file, which is
released when the holder exits even if it crashes.

POSIX (the Docker/Pi target) uses fcntl.flock; Windows (dev/test) uses msvcrt.locking.
"""
import contextlib
import os
import sys
from pathlib import Path


@contextlib.contextmanager
def exclusive_file_lock(target):
    lock_path = Path(str(target) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a+b") as fh:
        if sys.platform == "win32":
            import msvcrt
            fh.seek(0)
            # msvcrt.locking blocks only after retrying for ~10 s, so retry in a loop until it is held.
            import time
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def atomic_write_text(path, text: str, encoding: str = "utf-8") -> None:
    """Writes `text` to `path` through a temp file in the same directory and os.replace(): a reader, or a crash
    mid-write, never sees a torn file (W-12; runtime trace run 2 finding 4.5). The temp name carries the pid so two
    processes writing the same file never share one."""
    path = Path(path)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding=encoding)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def atomic_write_gzip_json(path, payload) -> None:
    """Same, for a gzip-compressed JSON document (the threat-intel feed snapshot)."""
    import gzip
    import json
    path = Path(path)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        with gzip.open(tmp, "wt", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
