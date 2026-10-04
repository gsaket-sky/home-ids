"""
core/file_lock.exclusive_file_lock: serialises read-modify-write of a shared JSON file (config-overrides lost update).
Threads stand in for processes here; flock/msvcrt both exclude other holders of the same sidecar file.
"""
import sys
import threading
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.file_lock import exclusive_file_lock  # noqa: E402


def test_concurrent_read_modify_write_loses_no_updates(tmp_path):
    target = tmp_path / "config_overrides.json"
    target.write_text("{}", encoding="utf-8")
    import json

    def bump(i):
        with exclusive_file_lock(target):
            data = json.loads(target.read_text(encoding="utf-8"))
            data[f"key_{i}"] = i
            target.write_text(json.dumps(data), encoding="utf-8")

    threads = [threading.Thread(target=bump, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(json.loads(target.read_text(encoding="utf-8"))) == 20


def test_lock_released_after_exception(tmp_path):
    target = tmp_path / "x.json"
    with pytest.raises(RuntimeError):
        with exclusive_file_lock(target):
            raise RuntimeError("boom")
    with exclusive_file_lock(target):  # would hang if the lock leaked
        pass


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
