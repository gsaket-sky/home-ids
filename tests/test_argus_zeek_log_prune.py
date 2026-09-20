"""
Standalone runtime test for src/argus/ops/zeek_log_prune.py -- the scheduled
job that deletes Zeek's own dated raw-log directories past a retention window
(SSD/disk-capacity audit, 2026-09-20: found 83 days, 7.5GB, zero retention).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_zeek_log_prune.py`
"""
import json
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import argus.ops.zeek_log_prune as zeek_log_prune  # noqa: E402

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="zeek_log_prune_test_"))

# --- no zeek logs dir at all: a clean no-op, not an error ---
_no_dir = TMPDIR / "no_zeek_state"
_no_dir.mkdir()
zeek_log_prune.CONFIG = {"state_path": str(_no_dir / "ids_state.json")}
zeek_log_prune._ZEEK_LOGS_ROOT = TMPDIR / "does_not_exist"
zeek_log_prune.main()
check("main() is a clean no-op when the zeek logs root doesn't exist",
      json.loads((_no_dir / "job_health.json").read_text())["zeek_log_prune"]["skipped"] == "no_zeek_logs_dir")


# --- real directory sweep ---
_real_state = TMPDIR / "real_state"
_real_state.mkdir()
_zeek_root = TMPDIR / "zeek_logs"
_zeek_root.mkdir()

today = datetime.now(timezone.utc).date()
old_dir_name = (today - timedelta(days=20)).strftime("%Y-%m-%d")
recent_dir_name = (today - timedelta(days=2)).strftime("%Y-%m-%d")
old_dir = _zeek_root / old_dir_name
recent_dir = _zeek_root / recent_dir_name
old_dir.mkdir()
recent_dir.mkdir()
(old_dir / "conn.log.gz").write_bytes(b"fake old log")
(recent_dir / "conn.log.gz").write_bytes(b"fake recent log")

# `current` -- the live symlink -- must never be touched even though it sits in
# the same directory. Use a real dir standing in for it (symlinks aren't always
# creatable without elevated privilege on Windows); the is_symlink() check in
# zeek_log_prune.py's own filter is what actually matters in production, but the
# _DATED_DIR_PATTERN check alone already protects a non-dated name like this one.
current_stub = _zeek_root / "current"
current_stub.mkdir()

# A non-dated directory name should never match the pattern and must survive.
weird_dir = _zeek_root / "not_a_date_dir"
weird_dir.mkdir()

zeek_log_prune.CONFIG = {"state_path": str(_real_state / "ids_state.json"),
                          "zeek_log_retention_days": 14}
zeek_log_prune._ZEEK_LOGS_ROOT = _zeek_root
zeek_log_prune.main()

check("a dated directory older than the retention window is deleted",
      not old_dir.exists())
check("a dated directory within the retention window survives",
      recent_dir.exists())
check("the `current` directory is never touched, even though it's inside the same root",
      current_stub.exists())
check("a non-dated directory name is never touched",
      weird_dir.exists())

health = json.loads((_real_state / "job_health.json").read_text())
check("job_health.json records exactly one deleted directory",
      health["zeek_log_prune"]["deleted_dirs"] == 1,
      f"got {health['zeek_log_prune'].get('deleted_dirs')}")
check("job_health.json records the retention_days actually used",
      health["zeek_log_prune"]["retention_days"] == 14)
check("job_health.json has no 'error' key on a successful run",
      "error" not in health["zeek_log_prune"])

# --- idempotent: a second run with nothing left to prune is a safe no-op ---
zeek_log_prune.main()
health2 = json.loads((_real_state / "job_health.json").read_text())
check("a second run with nothing past the cutoff deletes 0 directories, not an error",
      health2["zeek_log_prune"]["deleted_dirs"] == 0 and "error" not in health2["zeek_log_prune"])


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All zeek_log_prune.py checks PASSED.")
