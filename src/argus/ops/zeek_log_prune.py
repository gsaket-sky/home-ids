"""
zeek_log_prune.py - deletes Zeek's own dated raw-log directories past a
retention window (SSD/disk-capacity audit, 2026-09-20).

Found live on .94: /opt/zeek/logs held 83 daily subdirectories (7.5GB, back to
2026-06-14, growing ~300-500MB/day recently) with ZERO retention ever applied.
Zeek's own rotation is already well-configured -- hourly, gzip-compressed --
the gap is purely that nothing ever deletes an old day. This matters more than
it might look: HEE never reads these archived directories back at all (the
live pipeline consumes Zeek's real-time tail/spool output as it's generated --
extractors/zeek_features.py's ZEEK_LOG_DIR points at the `current` symlink,
not a dated directory), so this data has zero ongoing value to any live
decision -- pure byproduct, unbounded by default. Explicit user decision
(2026-09-20): 14 days, a manual-forensic-review window after an incident,
matching the "everything capped, nothing unrestricted in production"
philosophy applied everywhere else in this data-lifecycle pass.

Deliberately filesystem-only, not GraphStore-based (a completely separate
subsystem/write path from the SQLite graph these other live_*.py jobs manage).
"""
import logging
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from extractors.zeek_features import ZEEK_LOG_DIR  # noqa: E402

LOGGER = logging.getLogger("zeek_log_prune")

# ZEEK_LOG_DIR itself is the `current` symlink into the live spool -- the dated
# archive directories this job manages are its siblings, one level up.
_ZEEK_LOGS_ROOT = ZEEK_LOG_DIR.parent
_DATED_DIR_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

DEFAULT_ZEEK_LOG_RETENTION_DAYS = 14.0


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    retention_days = float(CONFIG.get("zeek_log_retention_days", DEFAULT_ZEEK_LOG_RETENTION_DAYS))

    if not _ZEEK_LOGS_ROOT.is_dir():
        # Not every deployment runs Zeek (or it hasn't logged anything yet) -- matches
        # every other live_*.py job's own "nothing to do yet" no-op path.
        write_job_health(state_dir, "zeek_log_prune", time.time() - run_start,
                          extra={"deleted_dirs": 0, "skipped": "no_zeek_logs_dir"})
        return

    cutoff_date = datetime.now(timezone.utc).date().toordinal() - int(retention_days)
    deleted_dirs = []
    errors = []
    try:
        for entry in _ZEEK_LOGS_ROOT.iterdir():
            # `current` (the live symlink Zeek is actively writing through) and
            # anything not matching Zeek's own YYYY-MM-DD dated-directory naming are
            # deliberately never touched -- this job only ever removes a directory
            # it can positively identify as one of Zeek's own daily archives.
            if entry.is_symlink() or not entry.is_dir() or not _DATED_DIR_PATTERN.match(entry.name):
                continue
            try:
                dir_date = datetime.strptime(entry.name, "%Y-%m-%d").date()
            except ValueError:
                continue
            if dir_date.toordinal() >= cutoff_date:
                continue
            try:
                shutil.rmtree(entry)
                deleted_dirs.append(entry.name)
            except Exception as e:
                errors.append(f"{entry.name}: {e}")
                LOGGER.error("Failed to remove Zeek log directory %s: %s", entry, e)

        LOGGER.info("Removed %d Zeek log director(ies) older than %.0f days from %s%s",
                     len(deleted_dirs), retention_days, _ZEEK_LOGS_ROOT,
                     f" ({len(errors)} error(s))" if errors else "")
        extra = {"deleted_dirs": len(deleted_dirs), "retention_days": retention_days, "errors": errors}
        if errors:
            # Retention not achieved -- report it as a failure, not a success with a footnote
            # (on .94 every delete failed with "Read-only file system" for weeks, unnoticed).
            extra["error"] = f"{len(errors)} directory(ies) past retention could not be removed: {errors[0]}"
        write_job_health(state_dir, "zeek_log_prune", time.time() - run_start, extra=extra)
    except Exception as e:
        LOGGER.error("zeek_log_prune failed: %s", e, exc_info=True)
        write_job_health(state_dir, "zeek_log_prune", time.time() - run_start, extra={"error": str(e)})


if __name__ == "__main__":
    main()
