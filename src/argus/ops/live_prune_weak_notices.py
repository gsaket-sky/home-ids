"""
live_prune_weak_notices.py - schedules GraphStore.prune_weak_zeek_notices()
against .94's own live graph, on its own tight cadence (data-lifecycle
retuning, 2026-09-20).

Split out of live_prune.py's own daily 3:15am run: that job only sweeps once a
day, meaning a zeek_notice_weak row created just after the run effectively
lived ~23-24h in practice, roughly double its OWN documented 12h retention
policy at the peak (DEFAULT_WEAK_ZEEK_NOTICE_RETENTION_HOURS's own docstring --
weak-tier notices contribute ZERO scoring weight to any hypothesis, so this is
pure noise with zero detection value past that window). This job exists to
enforce that SLA properly, without tying it to live_prune.py's own much more
expensive evidence/device_destinations full-table scan (measured ~120s against
.94's live 8.5GB graph) -- deletion here is cheap and narrowly indexed
(idx_evidence_type_ts), so running it every few hours instead of once a day
costs almost nothing extra.
"""
import logging
import time
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from argus.graph.store import GraphStore, DEFAULT_WEAK_ZEEK_NOTICE_RETENTION_HOURS  # noqa: E402

LOGGER = logging.getLogger("live_prune_weak_notices")


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    db_path = state_dir / "v13_graph.db"

    if not db_path.exists():
        # Matches live_prune.py's own no-op path, same reason -- a box where
        # engine="v_current", or live_engine.py has never run with a device_id.
        write_job_health(state_dir, "live_prune_weak_notices", time.time() - run_start,
                          extra={"deleted": 0, "skipped": "no_db_yet"})
        return

    try:
        store = GraphStore(str(db_path))
        deleted = store.prune_weak_zeek_notices(older_than_hours=DEFAULT_WEAK_ZEEK_NOTICE_RETENTION_HOURS)
        store.close()
        LOGGER.info("Pruned %d zeek_notice_weak row(s) older than %.0fh from %s",
                     deleted, DEFAULT_WEAK_ZEEK_NOTICE_RETENTION_HOURS, db_path)
        write_job_health(state_dir, "live_prune_weak_notices", time.time() - run_start,
                          extra={"deleted": deleted,
                                 "retention_hours": DEFAULT_WEAK_ZEEK_NOTICE_RETENTION_HOURS})
    except Exception as e:
        LOGGER.error("live_prune_weak_notices failed: %s", e, exc_info=True)
        write_job_health(state_dir, "live_prune_weak_notices", time.time() - run_start, extra={"error": str(e)})


if __name__ == "__main__":
    main()
