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
