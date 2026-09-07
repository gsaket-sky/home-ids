"""
live_prune.py - schedules src/v13/graph/store.py's GraphStore.prune_evidence() against
`.94`'s own live graph (v13 full-architecture plan, Phase 1 follow-up).

Registered as its own scheduled job (config.yaml's scheduled_jobs.scheduler.live_prune,
same mechanism as retro_hunter.py/shadow_watcher.py) rather than folded into the live
per-cycle pipeline -- pruning is a periodic maintenance concern, not something that
belongs inside pipeline.py's 2s decision loop (src/v13/ingest/daemon.py already keeps
this same separation for .19's own graph, via its own prune_interval_seconds gate).

Real motivation, not a speculative safeguard: A14's write-path bugs (fixed, see
Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md) demonstrated real, if since-fixed,
runaway growth potential, and nothing on .94 was enforcing schema.sql's own documented
90-day evidence retention policy at all until this file existed. Uses the SAME
`state/v13_graph.db` path `src/v13/ops/live_engine.py` writes to (configured the same
way, via config.yaml's state_path).

v13 full-architecture plan, Phase 10b: retention itself is now hardware_profile-driven
-- a pi_8gb deployment prunes sooner (30 days) than the schema-documented 90-day
default, given that box's own tighter, shared resource budget (see
V13_ARCHITECTURE_DEPENDENCY_MAP.md's "Hardware topology" section); x86_16gb/custom
keep the original 90-day default unchanged. A first-pass judgment call, not
empirically tuned (same honesty framing this project's own INDEPENDENCE_FAMILY_MAP
uses for a similar not-yet-validated number).
"""
import logging
import time
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from v13.config.trust_anchors import load_hardware_profile  # noqa: E402
from v13.graph.store import GraphStore, DEFAULT_EVIDENCE_RETENTION_DAYS  # noqa: E402

LOGGER = logging.getLogger("live_prune")

_RETENTION_DAYS_BY_PROFILE = {
    "pi_8gb": 30.0,
    "x86_16gb": DEFAULT_EVIDENCE_RETENTION_DAYS,
    "custom": DEFAULT_EVIDENCE_RETENTION_DAYS,
}


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    db_path = state_dir / "v13_graph.db"

    if not db_path.exists():
        # Nothing to prune yet -- the graph hasn't been written to at all (e.g. a
        # box where engine="v_current" and live_engine.py has never run with a
        # device_id). Not an error.
        write_job_health(state_dir, "live_prune", time.time() - run_start, extra={"deleted": 0, "skipped": "no_db_yet"})
        return

    retention_days = _RETENTION_DAYS_BY_PROFILE.get(
        load_hardware_profile(CONFIG), DEFAULT_EVIDENCE_RETENTION_DAYS)

    try:
        store = GraphStore(str(db_path))
        deleted = store.prune_evidence(older_than_days=retention_days)
        store.close()
        LOGGER.info("Pruned %d evidence row(s) older than %d days from %s", deleted, retention_days, db_path)
        write_job_health(state_dir, "live_prune", time.time() - run_start, extra={"deleted": deleted, "retention_days": retention_days})
    except Exception as e:
        LOGGER.error("live_prune failed: %s", e, exc_info=True)
        write_job_health(state_dir, "live_prune", time.time() - run_start, extra={"error": str(e)})


if __name__ == "__main__":
    main()
