"""
v13 lightweight divergence-check cron entrypoint (Phase 7 wiring --
Documentation/V13_REMAINING_WORK.md, "next real blocker" prerequisite).

Runs one comparator cycle: src/v13/compare/divergence_log.py's real
AlertsJsonlTailer + run_comparison() against v13's own real decisions
(GraphStore, A7) and .94's real alerts.json (mounted via the v13-alerts
Samba share, A8). Intended to run on a schedule via a plain crontab entry on
.19 -- matches deploy_v13.sh's own existing 15-minute cron pattern, not a new
systemd service, per the user's explicit "lightweight" ask. This is NOT
gap_monitor.py (A9/A10's still-unbuilt auto-flip checker) -- this script only
accumulates comparison data; it never edits .94's config or restarts
anything.

Reuses daemon.py's load_config() (same real-config-vs-.example-fallback
split, same loud-not-silent CRITICAL log on a missing real config) rather
than duplicating that logic a second time.

Run: `python3 src/v13/ops/run_gap_check.py [path/to/config_v13.yaml]`
Crontab: `*/15 * * * * cd ~/myscripts/home_ids && python3 src/v13/ops/run_gap_check.py >> state/v13_gap_check.log 2>&1`
"""
import logging
import sys
import time
from collections import Counter
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_SRC_DIR))

from argus.compare.divergence_log import AlertsJsonlTailer, run_comparison  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.ingest.daemon import load_config  # noqa: E402

LOGGER = logging.getLogger("v13.ops.run_gap_check")


def run_once(config: dict, now: float = None) -> list:
    """The actual cron-cycle logic, factored out of main() so it's testable
    without argv/logging-setup side effects -- matches this project's own
    "pure logic vs. thin runnable wrapper" split (e.g. retro_hunter.py's
    hunt() vs. its own __main__ block). Returns the list of Divergence
    records found this cycle (possibly empty)."""
    now = now if now is not None else time.time()
    compare_cfg = config.get("compare", {})
    ingest_cfg = config.get("ingest", {})

    alerts_path = Path(compare_cfg.get("alerts_mount_path", "/mnt/v13-alerts/alerts.json"))
    cursor_path = Path(compare_cfg.get("cursor_path", "state/v13_divergence_cursor.json"))
    output_path = Path(compare_cfg.get("output_path", "state/v13_divergence.jsonl"))
    lookback_seconds = float(compare_cfg.get("lookback_seconds", 3600.0))
    graph_db_path = Path(ingest_cfg.get("graph_db_path", "state/v13_graph.db"))

    if not graph_db_path.exists():
        LOGGER.warning("Graph db %s does not exist yet -- nothing to compare against. "
                         "Skipping this cycle (not an error; the ingest daemon may not "
                         "have produced any decisions yet).", graph_db_path)
        return []

    store = GraphStore(str(graph_db_path))
    try:
        tailer = AlertsJsonlTailer(alerts_path, cursor_path)
        divergences = run_comparison(store, tailer, output_path, lookback_seconds=lookback_seconds, now=now)
    finally:
        store.close()

    if not divergences:
        LOGGER.info("No new v-current alerts since the last check -- nothing to compare.")
        return []

    counts = Counter(d.kind for d in divergences)
    LOGGER.info("Compared %d new alert(s): %s", len(divergences), dict(counts))
    for d in divergences:
        if d.kind in ("AGREE", "DIFFERENT_PATH"):
            LOGGER.info("  %s: %s @ %s -- v-current=%s/%s v13=%s/%s",
                         d.kind, d.device_ip, d.timestamp, d.vcurrent_decision_path,
                         d.vcurrent_signature, d.v13_state, d.v13_decision_path)
    return divergences


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    config = load_config(explicit_path)
    run_once(config)


if __name__ == "__main__":
    main()
