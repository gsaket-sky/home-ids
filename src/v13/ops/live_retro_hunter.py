"""
live_retro_hunter.py - schedules v13's RetroHunter (src/v13/retro_hunter.py) against
`.94`'s own live graph (v13 full-architecture plan, Phase 4).

Registered as its own scheduled job (config.yaml's scheduled_jobs.scheduler.live_retro_hunter,
same mechanism as live_prune.py/retro_hunter.py) -- NOT a replacement for v-current's own
scripts/retro_hunter.py job (config key "retro_hunter", still enabled, still does its own
local-intel cross-reference, Telegram notification, and fp_engine sigma-tuning, none of
which v13's RetroHunter has -- see retro_hunter.py's own module docstring for the documented
scope cut). This job re-scans v13's OWN graph-backed destination history (state/v13_graph.db,
Phase 1) against fresh threat intel and writes any newly-confirmed-malicious destination back
as a real `reputation` Evidence item for the device that touched it -- picked up by that
device's very next live decision cycle through the same HypothesisEngine/DecisionEngine path
any other evidence goes through (this exact feedback loop is already proven end-to-end by
tests/test_v13_integration.py's own Step 8, against a test store).

Deliberately deferred, matching RetroHunter's own documented scope cut: cross-device
local-intel correlation, Telegram notification, per-device job-health breakdown -- small,
independently addable follow-ups once this basic wiring is confirmed working, not blocking
this phase.
"""
import logging
import time
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from v13.graph.store import GraphStore, DEFAULT_EVIDENCE_RETENTION_DAYS  # noqa: E402
from v13.retro_hunter import RetroHunter, real_threat_intel_lookup_factory  # noqa: E402

LOGGER = logging.getLogger("live_retro_hunter")

# v13 full-architecture plan, Phase 1a's item 5: "retro-hunter against the FULL
# retained history, not just recent days" -- now that live_prune.py actually enforces
# GraphStore's 90-day evidence retention (Phase 1's own follow-up fix), a newly
# confirmed-malicious destination can be checked against everything any device
# touched in the WHOLE retained window, not an arbitrary shorter slice. Was 14
# (matching RetroHunter.hunt()'s own default / scripts/retro_hunter.py's --days
# default) when this file was first written in Phase 4, before retention was
# actually being enforced on `.94` -- deliberately widened here, now that it is,
# rather than leaving an artificially narrow lookback that ignores 76 days of
# history the graph is already paying to retain.
DEFAULT_DAYS_BACK = DEFAULT_EVIDENCE_RETENTION_DAYS


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    db_path = state_dir / "v13_graph.db"

    if not db_path.exists():
        # Nothing to hunt yet -- matches live_prune.py's own no-op path, same reason
        # (a box where engine="v_current", or live_engine.py has never run with a
        # device_id yet). Not an error.
        write_job_health(state_dir, "live_retro_hunter", time.time() - run_start,
                          extra={"findings_count": 0, "skipped": "no_db_yet"})
        return

    try:
        store = GraphStore(str(db_path))
        lookup = real_threat_intel_lookup_factory(CONFIG, str(state_dir), refresh=True)
        hunter = RetroHunter(store, lookup)
        findings = hunter.hunt(days_back=DEFAULT_DAYS_BACK)
        store.close()
        LOGGER.info(
            "Retro-hunt complete: %d finding(s) against the last %d days of graph history.",
            len(findings), DEFAULT_DAYS_BACK,
        )
        write_job_health(state_dir, "live_retro_hunter", time.time() - run_start,
                          extra={"findings_count": len(findings)})
    except Exception as e:
        LOGGER.error("live_retro_hunter failed: %s", e, exc_info=True)
        write_job_health(state_dir, "live_retro_hunter", time.time() - run_start, extra={"error": str(e)})


if __name__ == "__main__":
    main()
