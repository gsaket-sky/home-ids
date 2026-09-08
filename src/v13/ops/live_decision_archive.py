"""
live_decision_archive.py - v13 full-architecture plan, Phase 10a: enforces
schema.sql's own documented decision-retention policy ("decisions: kept 1 year, then
archived (exported, not deleted)") -- nothing enforced this before this file existed,
the same real motivation live_prune.py had for evidence's own 90-day policy before it
existed.

Same shape as live_prune.py: a scheduled job (config.yaml's
scheduled_jobs.scheduler.live_decision_archive) against `.94`'s own live graph, using
the SAME state/v13_graph.db path every other v13 ops file writes to. Scheduled
MONTHLY, not daily -- matches the policy's own year-scale cadence, unlike
live_prune.py's own 90-day-window daily cadence.

EXPORT-THEN-DELETE ORDERING (the one thing this file is careful about that a naive
version wouldn't be): GraphStore.get_decisions_older_than() (a read) and
delete_decisions() (a write) are two SEPARATE calls, not one atomic method --
decisions are only ever deleted from the live graph AFTER their export to
state/decision_archive/*.jsonl has actually succeeded on disk. If the export write
raises for any reason (disk full, permissions), delete_decisions() is never called,
job_health.json records the error, and the SAME decisions are simply re-exported
(as a fresh, differently-named file) on the next scheduled run -- "archived, not
deleted" holds even under a failure, not just the happy path.

Retention is hardware_profile-driven, matching live_prune.py's own precedent
(_RETENTION_DAYS_BY_PROFILE) -- a pi_8gb deployment archives sooner (180 days)
than the schema-documented 365-day default, since a Pi's shared resource budget
means average decision row size matters more there, and this matters more now
that raw_payload_json carries the full alert_payload superset (v13 full-
architecture plan, alert/decision unification) instead of just v13's own internal
decision dict. x86_16gb/custom keep the original 365-day default unchanged.
"""
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from v13.config.trust_anchors import load_hardware_profile  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402

LOGGER = logging.getLogger("live_decision_archive")

# Matches schema.sql's own documented policy exactly ("decisions: kept 1 year") --
# the x86_16gb/custom default. pi_8gb overrides to a shorter window, see module docstring.
DEFAULT_RETENTION_DAYS = 365.0

_RETENTION_DAYS_BY_PROFILE = {
    "pi_8gb": 180.0,
    "x86_16gb": DEFAULT_RETENTION_DAYS,
    "custom": DEFAULT_RETENTION_DAYS,
}


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    db_path = state_dir / "v13_graph.db"

    if not db_path.exists():
        # Nothing to archive yet -- matches live_prune.py's own no-op path, same
        # reason (a box where engine="v_current", or live_engine.py has never run
        # with a device_id). Not an error.
        write_job_health(state_dir, "live_decision_archive", time.time() - run_start,
                          extra={"archived": 0, "skipped": "no_db_yet"})
        return

    retention_days = _RETENTION_DAYS_BY_PROFILE.get(
        load_hardware_profile(CONFIG), DEFAULT_RETENTION_DAYS)

    store = GraphStore(str(db_path))
    try:
        to_archive = store.get_decisions_older_than(retention_days)
        archived_count = 0

        if to_archive:
            archive_dir = state_dir / "decision_archive"
            archive_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            export_path = archive_dir / f"decisions_{stamp}.jsonl"

            with open(export_path, "w", encoding="utf-8") as f:
                for d in to_archive:
                    f.write(json.dumps(d) + "\n")

            # The export write above completed without raising -- only NOW is it
            # safe to remove these rows from the live graph (see this module's
            # own top-of-file docstring for why the ordering matters).
            archived_count = store.delete_decisions([d["decision_id"] for d in to_archive])
            LOGGER.info("Archived %d decision(s) older than %.0f days to %s",
                         archived_count, retention_days, export_path)
        else:
            LOGGER.info("No decisions older than %.0f days -- nothing to archive.", retention_days)

        write_job_health(state_dir, "live_decision_archive", time.time() - run_start,
                          extra={"archived": archived_count, "retention_days": retention_days})
    except Exception as e:
        LOGGER.error("live_decision_archive failed: %s", e, exc_info=True)
        write_job_health(state_dir, "live_decision_archive", time.time() - run_start, extra={"error": str(e)})
    finally:
        store.close()


if __name__ == "__main__":
    main()
