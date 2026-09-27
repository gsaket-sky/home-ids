"""
live_prune.py - schedules src/v13/graph/store.py's GraphStore.prune_evidence() against
`.94`'s own live graph (v13 full-architecture plan, Phase 1 follow-up).

Registered as its own scheduled job (config.yaml's scheduled_jobs.scheduler.live_prune,
same mechanism as retro_hunter.py/shadow_watcher.py) rather than folded into the live
per-cycle pipeline -- pruning is a periodic maintenance concern, not something that
belongs inside pipeline.py's 2s decision loop (src/v13/ingest/daemon.py already keeps
this same separation for .19's own graph, via its own prune_interval_seconds gate).

Real motivation, not a speculative safeguard: A14's write-path bugs (fixed, see
Documentation/ARGUS_AUTONOMY_DEPENDENCY_MAP.md) demonstrated real, if since-fixed,
runaway growth potential, and nothing on .94 was enforcing schema.sql's own documented
90-day evidence retention policy at all until this file existed. Uses the SAME
`state/v13_graph.db` path `src/v13/ops/live_engine.py` writes to (configured the same
way, via config.yaml's state_path).

v13 full-architecture plan, Phase 10b: retention itself is now hardware_profile-driven
-- a pi_8gb deployment prunes sooner (30 days) than the schema-documented 90-day
default, given that box's own tighter, shared resource budget (see
ARGUS_AUTONOMY_DEPENDENCY_MAP.md's "Hardware topology" section); x86_16gb/custom
keep the original 90-day default unchanged. A first-pass judgment call, not
empirically tuned (same honesty framing this project's own INDEPENDENCE_FAMILY_MAP
uses for a similar not-yet-validated number).
"""
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from argus.config.trust_anchors import load_hardware_profile  # noqa: E402
from argus.graph.store import (  # noqa: E402
    GraphStore, DEFAULT_EVIDENCE_RETENTION_DAYS, DEFAULT_DECISION_RETENTION_DAYS,
)

LOGGER = logging.getLogger("live_prune")

_RETENTION_DAYS_BY_PROFILE = {
    "pi_8gb": 30.0,
    "x86_16gb": DEFAULT_EVIDENCE_RETENTION_DAYS,
    "custom": DEFAULT_EVIDENCE_RETENTION_DAYS,
}

# Alert-trace graph (Documentation/ALERT_TRACE_GRAPH_PLAN.md, 2026-09-22): decisions/
# alert_events get their own, much longer retention window than evidence -- decisions
# are the audit trail, meant to legitimately outlive the evidence that fed them (same
# "two different retention windows" split schema.sql already documents for evidence
# vs. decisions). Mirrors GraphStore's own _DECISION_RETENTION_DAYS_BY_PROFILE,
# duplicated here rather than imported since that dict is private to store.py (same
# "private to its own module, small enough to keep in sync by hand" precedent as
# this file's own _RETENTION_DAYS_BY_PROFILE above).
_DECISION_RETENTION_DAYS_BY_PROFILE = {
    "pi_8gb": 180.0,
    "x86_16gb": DEFAULT_DECISION_RETENTION_DAYS,
    "custom": DEFAULT_DECISION_RETENTION_DAYS,
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

    # Explicit user decision (2026-09-20, data-lifecycle retuning): production runs
    # forever with zero unrestricted growth, no exceptions -- so archiving is OFF by
    # default and reserved for testing/dev sessions that explicitly opt in via
    # config.yaml. See GraphStore.prune_evidence()'s own docstring for what the
    # archive actually contains and why it's best-effort.
    archive_path = None
    if CONFIG.get("archive_network_activity_backup", False):
        archive_path = state_dir / "evidence_archive" / f"evidence_{datetime.now(timezone.utc):%Y-%m}.jsonl.gz"

    try:
        store = GraphStore(str(db_path))
        deleted = store.prune_evidence(older_than_days=retention_days, archive_path=archive_path)
        # BUGFIX (2026-09-20, data-lifecycle retuning): device_destinations used to
        # get its OWN fixed 30-day retention regardless of profile, reasoned only
        # against peer-cohort baselining's 7-day lookback. That missed a SECOND real
        # consumer -- live_retro_hunter.py's retroactive threat-intel re-scan reads
        # up to DEFAULT_EVIDENCE_RETENTION_DAYS (90) back by default -- so on
        # x86_16gb/custom, a destination touched 31-90 days ago was silently
        # invisible to retroactive cross-checking, a real coverage gap for exactly
        # the audit capability this table exists to support. Now reuses the SAME
        # profile-scaled `retention_days` evidence itself uses (this table is
        # currently ~0.6MB, so widening it costs nothing) -- also keeps
        # live_retro_hunter's OWN lookback (see that file's DEFAULT_DAYS_BACK,
        # separately made profile-aware the same day) from ever requesting more
        # history than this table -- or evidence itself -- actually retains.
        dd_deleted = store.prune_device_destinations(older_than_days=retention_days)
        # BUGFIX (2026-09-20, identity-merge handover follow-up): the concrete
        # "clean up stale/merged devices regularly" half of the device_baselines
        # 89-vs-13 anomaly -- riding along on this job's existing daily cadence
        # rather than a new cron entry, since it's a cheap, narrowly-targeted
        # DELETE (see GraphStore.prune_orphaned_device_baselines()'s own
        # docstring for why threshold_history is deliberately NOT included here).
        orphaned_baselines_deleted = store.prune_orphaned_device_baselines()
        # Alert-trace graph (2026-09-22): decisions had NO pruning job at all before
        # this -- riding along on this job's existing daily cadence, same reasoning
        # as prune_orphaned_device_baselines() above (a real but not per-cycle-urgent
        # sweep, no need for its own cron entry).
        decision_retention_days = _DECISION_RETENTION_DAYS_BY_PROFILE.get(
            load_hardware_profile(CONFIG), DEFAULT_DECISION_RETENTION_DAYS)
        decision_prune_counts = store.prune_decisions_and_alerts(older_than_days=decision_retention_days)
        # Disk-retention audit (2026-09-23): backtest_runs/threshold_history had NO
        # pruning of any kind before this -- same "ride along on this job's existing
        # daily cadence" reasoning as the two sweeps above, both cheap indexed
        # deletes (idx_backtest_runs_started, idx_threshold_history_device).
        backtest_runs_deleted = store.prune_backtest_runs()
        threshold_history_deleted = store.prune_threshold_history()
        stale_regime_baselines_deleted = store.prune_stale_regime_baselines()
        stale_regime_trust_deleted = store.prune_stale_regime_trust()
        # MOVED (2026-09-20, data-lifecycle retuning) to its own, much more frequent
        # job -- live_prune_weak_notices.py, every 4h instead of this job's own daily
        # 3:15am. Running only once/day meant a weak notice created just after this
        # run effectively lived ~23-24h, roughly double its OWN documented 12h
        # retention SLA at the peak (this method's cutoff-at-prune-TIME semantics
        # only enforce "no older than 12h AT THE MOMENT THIS RUNS", not a
        # continuously-enforced TTL). Deliberately NOT folded into a shorter cadence
        # for THIS whole job instead -- evidence/device_destinations pruning does a
        # real full-table scan (measured ~120s against .94's live graph) that doesn't
        # need to run 6x more often just to carry the cheap, narrowly-indexed
        # weak-notice sweep along with it.
        store.close()
        LOGGER.info("Pruned %d evidence row(s) older than %d days, %d device_destinations row(s) "
                     "older than %d days, %d orphaned device_baselines row(s), %d decision(s)/"
                     "%d alert_event(s) older than %d days, %d backtest_runs row(s), "
                     "%d threshold_history row(s), from %s",
                     deleted, retention_days, dd_deleted, retention_days, orphaned_baselines_deleted,
                     decision_prune_counts["decisions"], decision_prune_counts["alert_events"],
                     decision_retention_days, backtest_runs_deleted, threshold_history_deleted, db_path)
        write_job_health(state_dir, "live_prune", time.time() - run_start,
                          extra={"deleted": deleted, "retention_days": retention_days,
                                 "device_destinations_deleted": dd_deleted,
                                 "device_destinations_retention_days": retention_days,
                                 "orphaned_device_baselines_deleted": orphaned_baselines_deleted,
                                 "decision_retention_days": decision_retention_days,
                                 "backtest_runs_deleted": backtest_runs_deleted,
                                 "threshold_history_deleted": threshold_history_deleted,
                                 "stale_regime_baselines_deleted": stale_regime_baselines_deleted,
                                 "stale_regime_trust_deleted": stale_regime_trust_deleted,
                                 **{f"{k}_deleted": v for k, v in decision_prune_counts.items()}})
    except Exception as e:
        LOGGER.error("live_prune failed: %s", e, exc_info=True)
        write_job_health(state_dir, "live_prune", time.time() - run_start, extra={"error": str(e)})


if __name__ == "__main__":
    main()
