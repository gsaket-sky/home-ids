"""
disk_budget_governor.py - size-driven backstop on top of the age-based retention
jobs (live_prune.py, zeek_log_prune.py), added per an explicit user requirement
(2026-09-23): total disk usage must never exceed a hard ceiling (default 20GB),
regardless of device count or traffic pattern -- "trim everything, delete
everything around this max capacity."

WHY THIS EXISTS ON TOP OF live_prune.py/zeek_log_prune.py, not instead of them:
a fixed retention window (e.g. "decisions: 365 days") is the right PRIMARY
mechanism -- cheap, predictable, and what keeps this running forever at a
roughly steady size. But "roughly steady" still scales with device count and
each installation's own traffic pattern, so a single fixed day-count can't
GUARANTEE a hard ceiling for every deployment (50 devices vs 100, light vs
heavy traffic) -- that would mean hand-tuning a magic number per installation,
which is exactly what this project's standing "network/installation agnostic"
design rule rules out. This job runs AFTER the normal daily prune, measures the
REAL on-disk size, and only if still over budget, shrinks further by directly
deleting the oldest rows/directories still past an absolute safety floor --
self-correcting against reality instead of a guessed number, and converging
gracefully across multiple runs (bounded iterations per run) rather than
blocking for a long time in one go.

WHOLE-STACK SCOPE (2026-09-23 follow-up: "this also goes for all subsystems
included -- suricata, zeek, grafana, prometheus, loki/promtail, fritzbox
capture data... total 20GB max including everything"): the 20GB ceiling
covers the ENTIRE security/monitoring stack on the box, not just what this
project's own Python code writes. This module only enforces the two pieces
that had no retention/cap mechanism of their own at all (the graph DB, Zeek's
raw logs) -- everything else already has (or was given, as part of this same
pass) its OWN native retention/size mechanism, which is the right tool for
each rather than reinventing what Prometheus/Loki/Docker already do well:
  - graph DB (state/v13_graph.db + its WAL):        9.0GB -- this module
  - Zeek raw logs (/opt/zeek/logs):                  3.0GB -- zeek_log_prune.py + this module
  - Prometheus TSDB:                                 2.0GB -- native `--storage.tsdb.retention.size=2GB` flag
  - Loki:                                          ~14 days -- native compactor + retention_period=336h
  - Grafana (mostly static plugin code + its own small sqlite db): ~1.0GB -- no ongoing growth risk found
  - Suricata (/var/lib + /var/log):                  0.5GB -- pre-existing logrotate (14 rotations)
  - Cowrie honeypot (docker json-file log driver):   0.03GB -- docker-compose log-opts (max-size=10m, max-file=3)
  - everything else in state/ (all other files, incl. fritzbox reactive-
    capture data): 1.5GB -- monitored/logged only here, already tightly
    capped per-file by the earlier 2026-09-23 disk-retention audit's fixes,
    so a hard enforcement loop for this bucket isn't needed in practice
  (~18.1GB allocated, ~1.9GB unallocated buffer -- enforcement is periodic,
  not real-time, so some headroom is intentional)

SAFETY FLOORS (never violated even if still over budget): decisions 30 days,
evidence 7 days, Zeek logs 3 days. If the db is still over its budget once
every floor is hit, this logs an ERROR rather than either silently exceeding
the budget or silently deleting below a safe minimum audit window -- that
combination means the configured budget is genuinely too small for this
installation's real traffic, which is a decision for a human (raise the
budget, or add storage), not something to guess past.

INCREMENTAL VACUUM: deleting rows alone does NOT shrink a SQLite file on disk
-- freed pages just become available for reuse within the same file. Real
shrinkage needs auto_vacuum=INCREMENTAL (a one-time conversion, NOT done
automatically by this job -- see GraphStore.enable_incremental_vacuum()'s own
docstring for why a human decides when to run that the first time) plus
periodic small PRAGMA incremental_vacuum(N) calls, which this job does after
every trim round. Each step is bounded and cheap, unlike a full VACUUM (which
locks the whole file) -- this project has fought multiple severe pipeline-
freeze incidents from exactly that class of blocking I/O, so this deliberately
never issues a full VACUUM itself.
"""
import logging
import time
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.ops.zeek_log_prune import _ZEEK_LOGS_ROOT, _DATED_DIR_PATTERN  # noqa: E402

LOGGER = logging.getLogger("disk_budget_governor")

DEFAULT_TOTAL_BUDGET_GB = 20.0
DEFAULT_GRAPH_DB_BUDGET_GB = 9.0
DEFAULT_ZEEK_LOGS_BUDGET_GB = 3.0
DEFAULT_STATE_FILES_BUDGET_GB = 1.5

# Absolute safety floors -- trimming NEVER goes past these, budget or no budget.
MIN_DECISION_AGE_DAYS = 30.0
MIN_EVIDENCE_AGE_DAYS = 7.0
MIN_ZEEK_LOG_AGE_DAYS = 3.0

_DECISION_TRIM_BATCH = 2000
_EVIDENCE_TRIM_BATCH = 5000
_MAX_TRIM_ITERATIONS = 15  # bounds a single run's worst-case time; converges across runs otherwise
_INCREMENTAL_VACUUM_PAGES_PER_STEP = 4000  # ~16MB/step at the default 4KB page size


def _gb(bytes_val: float) -> float:
    return bytes_val / (1024.0 ** 3)


def _enforce_graph_db_budget(store: GraphStore, budget_gb: float, now: float) -> dict:
    result = {"trimmed_decision_batches": 0, "trimmed_evidence_batches": 0,
              "floor_hit": False, "final_size_gb": 0.0}
    budget_bytes = budget_gb * (1024.0 ** 3)

    # TRUNCATE-checkpoint FIRST, every run, regardless of budget status -- a large
    # WAL is real disk usage (.94's own WAL measured at 805MB during this audit)
    # that neither the age-based prune jobs nor incremental_vacuum_step() ever
    # address on their own (incremental_vacuum only shrinks the MAIN file).
    store.checkpoint_wal_truncate()

    usage = store.get_disk_usage_bytes()
    if usage["total_bytes"] <= budget_bytes:
        # Still under budget -- just reclaim whatever's already free, cheaply.
        # incremental_vacuum's own writes land in the WAL like any other write
        # in WAL mode, so a checkpoint after it is what actually makes the
        # reclaimed space show up in a real on-disk measurement.
        store.incremental_vacuum_step(_INCREMENTAL_VACUUM_PAGES_PER_STEP)
        store.checkpoint_wal_truncate()
        result["final_size_gb"] = _gb(store.get_disk_usage_bytes()["total_bytes"])
        return result

    LOGGER.warning("Graph DB is %.2fGB, over its %.2fGB budget -- trimming beyond the normal "
                    "age-based retention window.", _gb(usage["total_bytes"]), budget_gb)

    for _ in range(_MAX_TRIM_ITERATIONS):
        usage = store.get_disk_usage_bytes()
        if usage["total_bytes"] <= budget_bytes:
            break

        # decisions (+ their cascaded edges/alert_events) are the dominant cost in
        # every measurement this project has taken -- trim those first.
        cutoff_ts = store.get_decisions_batch_cutoff(_DECISION_TRIM_BATCH, MIN_DECISION_AGE_DAYS, now=now)
        if cutoff_ts is not None:
            # -1s (pushes prune's own derived cutoff to cutoff_ts + 1s, i.e. PAST
            # cutoff_ts): prune_decisions_and_alerts() deletes STRICTLY older
            # than its cutoff. Without this nudge, when multiple rows share the
            # exact batch-boundary timestamp (plausible -- many decisions in the
            # same cycle can share one `now`), the cutoff row's own ties never
            # get deleted, get_decisions_batch_cutoff() returns the SAME
            # timestamp again next iteration, and this loop churns through all
            # _MAX_TRIM_ITERATIONS without making real progress. Caught by this
            # module's own test suite (a first, sign-reversed version of this fix
            # made it WORSE -- excluded the boundary row instead of including it,
            # also caught by the same test), not by inspection.
            older_than_days = (now - cutoff_ts - 1.0) / 86400.0
            store.prune_decisions_and_alerts(older_than_days=older_than_days, now=now)
            result["trimmed_decision_batches"] += 1
            store.incremental_vacuum_step(_INCREMENTAL_VACUUM_PAGES_PER_STEP)
            continue

        # Decisions are already at their floor -- try evidence next.
        ev_cutoff_ts = store.get_evidence_batch_cutoff(_EVIDENCE_TRIM_BATCH, MIN_EVIDENCE_AGE_DAYS, now=now)
        if ev_cutoff_ts is not None:
            older_than_days = (now - ev_cutoff_ts - 1.0) / 86400.0  # same tie-breaking reasoning as above
            store.prune_evidence(older_than_days=older_than_days, now=now)
            result["trimmed_evidence_batches"] += 1
            store.incremental_vacuum_step(_INCREMENTAL_VACUUM_PAGES_PER_STEP)
            continue

        # Both decisions and evidence are already at their absolute safety floors
        # and the db is STILL over budget -- this installation's real traffic
        # doesn't fit the configured budget even at minimum retention. Stop
        # trimming (never violate the floors) and say so loudly.
        result["floor_hit"] = True
        break

    # The trim loop's own DELETEs land in the WAL before being checkpointed --
    # truncate again so the final measurement (and the floor_hit error below, if
    # any) reflect real post-trim disk usage, not an inflated pre-checkpoint size.
    store.checkpoint_wal_truncate()
    final_usage = store.get_disk_usage_bytes()
    result["final_size_gb"] = _gb(final_usage["total_bytes"])
    if result["floor_hit"] and final_usage["total_bytes"] > budget_bytes:
        LOGGER.error(
            "Graph DB is %.2fGB, still over its %.2fGB budget even at the minimum safety "
            "floors (decisions >= %.0fd, evidence >= %.0fd). This installation's real "
            "traffic doesn't fit the configured budget -- raise disk_budget_graph_db_gb "
            "or add storage; this will NOT trim below the floors automatically.",
            result["final_size_gb"], budget_gb, MIN_DECISION_AGE_DAYS, MIN_EVIDENCE_AGE_DAYS,
        )
    return result


def _enforce_zeek_logs_budget(budget_gb: float, now: float) -> dict:
    result = {"deleted_dirs": 0, "floor_hit": False, "final_size_gb": 0.0, "skipped": None}
    if not _ZEEK_LOGS_ROOT.is_dir():
        result["skipped"] = "no_zeek_logs_dir"
        return result

    budget_bytes = budget_gb * (1024.0 ** 3)
    from datetime import datetime, timezone
    floor_date_ordinal = datetime.now(timezone.utc).date().toordinal() - int(MIN_ZEEK_LOG_AGE_DAYS)

    def _dir_size(p: Path) -> int:
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())

    def _dated_dirs():
        dirs = []
        for entry in _ZEEK_LOGS_ROOT.iterdir():
            if entry.is_symlink() or not entry.is_dir() or not _DATED_DIR_PATTERN.match(entry.name):
                continue
            try:
                d = datetime.strptime(entry.name, "%Y-%m-%d").date()
            except ValueError:
                continue
            dirs.append((d.toordinal(), entry))
        dirs.sort(key=lambda t: t[0])  # oldest first
        return dirs

    total_bytes = _dir_size(_ZEEK_LOGS_ROOT)
    if total_bytes <= budget_bytes:
        result["final_size_gb"] = _gb(total_bytes)
        return result

    LOGGER.warning("Zeek logs are %.2fGB, over their %.2fGB budget -- deleting oldest days beyond "
                    "the normal %s-based retention.", _gb(total_bytes), budget_gb, "zeek_log_prune.py")

    for ordinal, entry in _dated_dirs():
        if total_bytes <= budget_bytes:
            break
        if ordinal >= floor_date_ordinal:
            result["floor_hit"] = True
            break
        import shutil
        try:
            freed = _dir_size(entry)
            shutil.rmtree(entry)
            total_bytes -= freed
            result["deleted_dirs"] += 1
        except Exception as e:
            LOGGER.error("Failed to remove Zeek log directory %s: %s", entry, e)

    result["final_size_gb"] = _gb(total_bytes)
    if result["floor_hit"] and total_bytes > budget_bytes:
        LOGGER.error(
            "Zeek logs are %.2fGB, still over their %.2fGB budget even at the minimum %.0f-day "
            "safety floor. Raise disk_budget_zeek_logs_gb or add storage.",
            result["final_size_gb"], budget_gb, MIN_ZEEK_LOG_AGE_DAYS,
        )
    return result


def _check_state_files_budget(state_dir: Path, budget_gb: float, db_path: Path) -> dict:
    """Monitoring only, no enforcement -- every individual file in state/ already
    has its own tight cap or age-prune (2026-09-23 disk-retention audit), so this
    bucket organically stays small. A warning here is a real signal something
    upstream regressed (a new unbounded writer appeared), not routine operation."""
    db_names = {db_path.name, db_path.name + "-wal", db_path.name + "-shm"}
    total = sum(f.stat().st_size for f in state_dir.rglob("*") if f.is_file() and f.name not in db_names)
    total_gb = _gb(total)
    if total_gb > budget_gb:
        LOGGER.error(
            "state/ (excluding the graph db) is %.2fGB, over its %.2fGB budget, despite every "
            "known file having its own cap -- likely a new, not-yet-bounded writer. Investigate.",
            total_gb, budget_gb,
        )
    return {"state_files_gb": total_gb, "over_budget": total_gb > budget_gb}


def main() -> None:
    run_start = time.time()
    now = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    db_path = state_dir / "v13_graph.db"

    if not bool(CONFIG.get("disk_budget_enabled", True)):
        write_job_health(state_dir, "disk_budget_governor", time.time() - run_start,
                          extra={"skipped": "disabled"})
        return

    graph_db_budget_gb = float(CONFIG.get("disk_budget_graph_db_gb", DEFAULT_GRAPH_DB_BUDGET_GB))
    zeek_logs_budget_gb = float(CONFIG.get("disk_budget_zeek_logs_gb", DEFAULT_ZEEK_LOGS_BUDGET_GB))
    state_files_budget_gb = float(CONFIG.get("disk_budget_state_files_gb", DEFAULT_STATE_FILES_BUDGET_GB))

    graph_result = {"skipped": "no_db_yet"}
    if db_path.exists():
        store = GraphStore(str(db_path))
        try:
            graph_result = _enforce_graph_db_budget(store, graph_db_budget_gb, now)
        finally:
            store.close()

    zeek_result = _enforce_zeek_logs_budget(zeek_logs_budget_gb, now)
    state_result = _check_state_files_budget(state_dir, state_files_budget_gb, db_path)

    LOGGER.info("Disk budget governor: graph_db=%s zeek_logs=%s state_files=%.2fGB",
                graph_result, zeek_result, state_result["state_files_gb"])
    write_job_health(state_dir, "disk_budget_governor", time.time() - run_start,
                      extra={"graph_db": graph_result, "zeek_logs": zeek_result, "state_files": state_result,
                             # the limits the sizes above are measured against -- exported with them
                             # (scheduler /metrics) so "used vs budget" is graphable, not just "used"
                             "budget_gb": {
                                 "graph_db": graph_db_budget_gb, "zeek_logs": zeek_logs_budget_gb,
                                 "state_files": state_files_budget_gb,
                                 "total": DEFAULT_TOTAL_BUDGET_GB,
                             }})


if __name__ == "__main__":
    main()
