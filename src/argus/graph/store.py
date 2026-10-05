"""
EvidenceGraph SQLite store.
Read/write API over graph/schema.sql. This module owns device/destination/evidence
read+write and audit-preserving identity merges; hypothesis/decision writes are
wired in by their own respective phases (the tables already exist in schema.sql,
just unused by this module until then -- incremental, not all-at-once).

Every Hypothesis.evaluate() (Phase 3) still takes a fresh per-cycle snapshot from
this store via plain queries -- nothing here holds a mutated in-memory graph object
across cycles, preserving the pure-evaluation model HEE_ROADMAP.md said not to break.
"""
import contextlib
import json
import logging
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from argus.evidence.model import Evidence, NO_DESTINATION
from utils import is_local_or_multicast_destination

LOGGER = logging.getLogger("home_ids.graph_store")

_SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

# Matches schema.sql's own documented policy (comment at the bottom of that file).
# evidence retention itself is now
# hardware_profile-driven too -- see live_prune.py's own _RETENTION_DAYS_BY_PROFILE
# (this constant stays the fallback for the "custom"/unrecognized-profile case and
# for any caller that doesn't go through that wiring, e.g. direct GraphStore use in
# tests).
DEFAULT_EVIDENCE_RETENTION_DAYS = 90
# device_destinations' fallback retention -- used as this method's own default
# parameter (direct/test callers only). BUGFIX (2026-09-20): live_prune.py's real
# scheduled job no longer uses this fixed 30 -- it reuses evidence's OWN
# profile-scaled retention_days instead, since a SECOND consumer beyond peer-cohort
# baselining's 7-day lookback (live_retro_hunter.py's retroactive threat-intel
# re-scan, up to 90 days back) was found silently losing coverage past 30 days.
# See live_prune.py's own comment at the call site for the full incident.
DEFAULT_DEVICE_DESTINATIONS_RETENTION_DAYS = 30
# zeek_notice_weak's own MUCH shorter retention (explicit user request, 2026-09-09 --
# "check the current evidence table's per-type row counts ... collapsing repeated
# identical weak notices... a real, separate optimization"). Confirmed live on .94:
# evidence_type='zeek_notice' (pre-fragmentation) was 214,795 of 218,405 total
# evidence rows (98.3%), and the single most common weak-tier note type alone
# (weird:data_before_established) accounted for 68,688 of those on its own -- the
# graph db was already 5.05GB after just 3.5 days of uptime. Weak-tier notices
# contribute ZERO scoring weight to any hypothesis (utils.py's
# ZEEK_NOTICE_TIER_SCORE_WEIGHT["weak"] == 0.0, argus/hypotheses/engine.py's
# NetworkIntrusionHypothesis/DeviceProfileBenignHypothesis both already ignore them)
# -- keeping them for the full 90-day evidence window has zero benefit to any live
# decision, only disk cost. 12 hours is generous relative to that zero-benefit
# baseline: enough for an operator reviewing "what happened in the last several
# hours" via the console/API, nowhere near the 24h graph-query-window corroboration
# actually depends on for evidence that DOES score.
DEFAULT_WEAK_ZEEK_NOTICE_RETENTION_HOURS = 12.0

# get_devices_targeting()'s BUGFIX #2 / _is_shared_infrastructure(): a destination
# touched by this fraction (or more) of the known device fleet, over this lookback,
# is treated as structurally shared household infrastructure (a router, hub, or
# another of the user's own devices most things on the LAN talk to) rather than
# meaningful cross-device coordination -- see that method's own docstring for the
# real incident (192.168.77.47, a second Fire TV touched by 7/household devices,
# repeatedly auto-blocked) this closes. 7 days matches PEER_DEVIATION_WINDOW_SECONDS'
# own precedent (live_engine.py) for "stable enough for a baseline, current enough
# to matter." MIN_FLEET_SIZE guards against a small household network where any
# ratio is meaningless (1 device touching something in a 2-3-device network is
# already 33-50%).
_SHARED_INFRASTRUCTURE_LOOKBACK_SECONDS = 7 * 86400
_SHARED_INFRASTRUCTURE_MIN_FLEET_SIZE = 5
_SHARED_INFRASTRUCTURE_DEVICE_RATIO = 0.4

# SQLite PRAGMA cache_size (negative = KB,
# per SQLite's own docs), sized against config/trust_anchors.py's own
# VALID_HARDWARE_PROFILES. A first-pass judgment call (this project's own
# established convention for a not-yet-empirically-tuned number, matching
# INDEPENDENCE_FAMILY_MAP's own "honest status" framing) -- SQLite's own default is
# -2000 (2MB); pi_8gb gets a modest bump given this box also runs Zeek/Suricata/
# Ollama concurrently (see this file's own "Hardware topology" section in
# ARGUS_AUTONOMY_DEPENDENCY_MAP.md), x86_16gb/custom get more headroom to spend on
# graph query performance since nothing else on that box is as resource-constrained.
_HARDWARE_PROFILE_CACHE_SIZE_KB: Dict[str, int] = {
    # 2026-09-10 (AUDIT_V14_REVIEW_RESPONSE.md §2.2): 4MB was closer to SQLite's own
    # 2MB default than a real cache for a WAL-enabled graph db this box also runs
    # Zeek/Suricata/Ollama concurrently against. 48MB is still a conservative,
    # not-empirically-tuned first-pass bump (same honesty framing as the edge-cap
    # constant below) -- there's no real Pi-8GB hardware to measure against yet
    # (ARGUS_AUTONOMY_DEPENDENCY_MAP.md's own hardware-topology note), so this
    # should be re-tuned with real iostat/RSS numbers once that hardware exists,
    # not treated as a final answer either direction.
    "pi_8gb": 48_000,
    "x86_16gb": 16_000,
    "custom": 16_000,
}

# the graph-engine migration, alert/decision unification, Phase 1 (write-side edge
# cap): real production data found ONE decision with 56,073 'supports' edges (a
# device with a very long evidence history) -- insert_decision() previously created
# one edge per evidence_id with no cap at all, the actual root cause behind the
# graph already holding 8M+ edge rows in production. The console's read side
# already caps display (graph_api.py's EVIDENCE_PER_DECISION_CAP), but that only
# bounded what got READ back, not what got WRITTEN -- this is the write-side fix.
# Same "first-pass judgment call, not empirically tuned" honesty framing as
# INDEPENDENCE_FAMILY_MAP. Audit completeness is not lost: insert_decision() still
# stores the FULL, uncapped evidence_id list inside raw_payload_json -- only the
# graph's edge-traversal representation is bounded, not the underlying truth.
_MAX_SUPPORTING_EVIDENCE_EDGES_BY_PROFILE: Dict[str, int] = {
    "pi_8gb": 25,
    "x86_16gb": 50,
    "custom": 50,
}

# BUGFIX (2026-09-20, memory-restart root-cause investigation): insert_decision()
# below also stashes payload["_all_evidence_ids"] uncapped whenever the edge cap is
# exceeded (autotune/reset.py's _full_evidence_ids_for_decision() genuinely needs
# the COMPLETE set for blast-radius correctness, so this key can't just be
# dropped). Found live on .94: a handful of legacy decisions (written before the
# edge cap above existed) had accumulated up to 68,915 evidence ids here, ~2.2MB
# of raw_payload_json for that key alone. 1000 is a generous, first-pass ceiling
# relative to the 25/50 edge cap -- large enough that no realistic post-fix
# decision should ever hit it (evidence keeps aging out via its own 30/90-day
# retention, so a decision accumulating 1000+ contributing items implies the
# SAME kind of long-lived-stuck-state pathology this fix is closing off), while
# bounding the worst case to ~33KB instead of multiple MB.
_MAX_ALL_EVIDENCE_IDS_STORED = 1000

# BUGFIX (2026-09-20, restart-cadence investigation): a real device found live on
# .94 generated 39,551 zeek_notice_weak items in 24 hours alone (~1 every 2.2s,
# non-stop) -- get_evidence_for_device()'s per-cycle window query correctly used
# its index (0.225s), but constructing and iterating 41,509 Evidence objects for
# ONE device, EVERY 2s decision cycle, was blowing the pipeline_main_loop's 60s
# heartbeat deadline and triggering self-restarts every ~12-14 minutes -- far
# worse than Root Causes #1/#2 ever were. Deliberately NOT scoped to zeek_notice_
# weak specifically (explicit user decision): any evidence_type could in
# principle flood this way for a genuinely infected/misbehaving device, not just
# a chatty smart-TV's routine protocol noise -- this caps EVERY type, uniformly,
# network-agnostic (no zeek-specific or household-specific assumption baked in).
# Most-recent-first (same ordering precedent as the supporting-evidence-edge cap
# above) preserves genuine severity signal for a real, sustained attack (up to
# the cap, every relevant item survives) while bounding the pathological-volume
# case. Verified this doesn't silently change scoring correctness for the
# uniform-confidence case that motivated it (ZEEK_NOTICE_TIER_CONFIDENCE is a
# FIXED per-tier constant, not computed per-observation -- averaging any subset
# of identical values gives the identical result) and independence_families is
# already a set (family-deduplicated for corroboration-counting purposes, only
# ever affected by DISTINCT families present, never by within-family volume) --
# this cap only removes redundant, informationally-empty duplicates, not signal.
_MAX_EVIDENCE_PER_TYPE_IN_WINDOW_BY_PROFILE: Dict[str, int] = {
    "pi_8gb": 50,
    "x86_16gb": 100,
    "custom": 100,
}
_DEFAULT_MAX_EVIDENCE_PER_TYPE_IN_WINDOW = 100

# BUGFIX (2026-09-20, restart-cadence investigation): prune_evidence()/
# prune_weak_zeek_notices() used to bind the FULL evidence_ids list as SQL
# parameters in one shot (twice, for the edges delete's two IN clauses) --
# never actually a problem at the volumes this project had seen until a
# one-time cleanup of the newly-folded-in legacy zeek_notice backlog
# (215,543 rows found live on .94) hit SQLite's own bound-parameter ceiling
# ("too many SQL variables"). 400 is conservative even against the OLD,
# widely-deployed SQLite default limit (999) -- the edges delete binds each
# id TWICE (src_id and dst_id clauses), so 400 ids -> 800 params, safely
# under it regardless of which SQLite build a given deployment ships.
_SQLITE_DELETE_BATCH_SIZE = 400

# How long merge-chain lookups (canonical id / ids resolving into it) are cached. Merges are rare and
# audit-preserving; this process invalidates its own cache on every merge, another process's merge is
# seen within this window.
_MERGE_CACHE_TTL_SECONDS = 15.0

# Alert-trace graph (Documentation/ALERT_TRACE_GRAPH_PLAN.md, 2026-09-22): decisions
# and alert_events share the SAME retention window -- an alert_event without its
# parent decision is meaningless, so they're pruned together, in one job. Closes a
# real, pre-existing gap: schema.sql documents a "1 year (180 days pi_8gb), then
# archived" policy for decisions, but no prune_decisions() of any kind existed
# before this constant + prune_decisions_and_alerts() -- decisions grew unbounded
# (45,650+ rows and still growing on .94's real deployment, confirmed by grepping
# this file for prune_decisions/archive_decisions before adding either).
DEFAULT_DECISION_RETENTION_DAYS = 365.0
_DECISION_RETENTION_DAYS_BY_PROFILE: Dict[str, float] = {
    "pi_8gb": 180.0,
    "x86_16gb": DEFAULT_DECISION_RETENTION_DAYS,
    "custom": DEFAULT_DECISION_RETENTION_DAYS,
}

# Disk-retention audit (2026-09-23): backtest_runs is one row/night forever with a
# row size that scales with device count -- the single largest unbounded contributor
# found in the whole schema. 90 days is generous (a golden-set/synthetic pass/fail
# summary's audit value is about recent trend, not a permanent record) while still
# comfortably covering the autotuner's own lookback needs.
DEFAULT_BACKTEST_RUNS_RETENTION_DAYS = 90.0

# threshold_history rows are small (no JSON blob) so this is a low-severity fix on
# raw bytes, but it's the autotuner's own change-history audit trail, so this gets a
# year-scale window matching decisions' own x86_16gb/custom default, not evidence's
# much shorter one.
DEFAULT_THRESHOLD_HISTORY_RETENTION_DAYS = 365.0

# device_baselines/cl_afpe_trust regime_id drift (disk-retention audit): year-scale,
# matching threshold_history's own window -- these are undo/reset traceability
# records, not routine per-cycle output, so this is deliberately conservative.
DEFAULT_STALE_REGIME_RETENTION_DAYS = 365.0

# Bounded semantic search (plan doc's "Semantic search (bounded add-on)" section):
# every query MUST supply a scope filter (time window and/or device_id) BEFORE
# embeddings are touched, and the scoped candidate set is hard-capped -- an honest
# "narrow your search" error past this, never a silent partial-result truncation.
ALERT_SEARCH_CANDIDATE_CAP = 5000


class AlertSearchScopeTooLarge(Exception):
    """Raised by search_alert_events_by_embedding() when the scoped candidate set
    still exceeds ALERT_SEARCH_CANDIDATE_CAP -- the caller must narrow the query
    (shorter time window and/or a device_id), never silently truncated."""
    def __init__(self, candidate_count: int, cap: int):
        self.candidate_count = candidate_count
        self.cap = cap
        super().__init__(f"{candidate_count} candidates exceeds cap of {cap} -- narrow the search")


def _chunked(seq: List[Any], size: int):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


class GraphStore:
    # Process-lifetime cache of db_paths that have already run _migrate_existing_db()
    # once -- see that call site's own BUGFIX comment below for why this exists.
    # Class-level (not per-instance): the whole point is to survive across the many
    # short-lived GraphStore instances open_store() constructs, one per console
    # API request.
    _migrated_db_paths: set = set()
    # Guards the check-then-migrate-then-cache sequence below: open_store() builds
    # a fresh GraphStore per FastAPI request on a threadpool, so without this lock
    # concurrent first-touch requests can all pass the "not yet migrated" check
    # before any of them adds db_path to the cache, each then running
    # _migrate_existing_db()'s executescript() concurrently against the same file.
    _migration_lock = threading.Lock()

    def __init__(self, db_path: str, hardware_profile: Optional[str] = None):
        self.db_path = db_path
        self._hardware_profile = hardware_profile
        is_new = not Path(db_path).exists()
        # E16/I9 (2026-10-04): a sqlite3 connection is bound to the thread that opened it, but this store is
        # shared by the main loop, the reactive-capture dispatcher and the threadpool. Each thread therefore
        # gets its own connection (see the _conn property) and its own transaction flag. SQLite's file locking
        # orders the writes between them, exactly as it already did between separate processes.
        self._tls = threading.local()
        self._all_conns: list = []
        self._all_conns_lock = threading.Lock()
        # BUGFIX (2026-09-20, SSD/SD-card wear audit): synchronous is a PER-CONNECTION
        # setting, unlike journal_mode (which persists in the db file itself once set) --
        # it does NOT survive into schema.sql's _apply_schema(), which only ever runs
        # for a brand-new file (is_new below), so setting it there would silently never
        # apply to any real, already-existing deployment (exactly .94's case). Must be
        # set here, on every connection open, same as foreign_keys/cache_size above.
        # NORMAL is SQLite's own documented recommended pairing with WAL mode (unlike
        # the default FULL, which fsyncs on every single commit): the db file itself
        # can never be corrupted by a power loss under WAL regardless of this setting,
        # the only risk is losing the most-recent commit(s) if power is lost before the
        # next checkpoint -- an acceptable tradeoff for this data, and a direct fix for
        # the fsync-per-commit write-amplification/wear pattern found live on .94.
        # (synchronous, busy_timeout and cache_size are applied per connection in _open_connection())
        # BUGFIX (2026-09-20, identity-merge handover -- "bonus finding"): Python's
        # sqlite3 module defaults connect()'s busy_timeout to 5000ms. Found live this
        # same session: a one-time maintenance script (this project's own cleanup
        # tooling -- live_prune_weak_notices.py/zeek_log_prune.py/
        # decision_bloat_cleanup.py) holding a competing write lock (a bulk DELETE or
        # VACUUM) for longer than that caused the live pipeline's own evidence/decision
        # write to fail outright with "database is locked" -- a silently lost row in
        # the durable audit trail (the live DECISION itself was already made and
        # returned before this write runs, so detection accuracy was never affected,
        # only this one cycle's record of it). Raised to a still-short but more
        # forgiving 10s: long enough to ride out a typical administrative-script
        # contention window without the live per-cycle write giving up immediately,
        # short enough to stay a small fraction of the 60s pipeline_main_loop
        # heartbeat deadline even in a genuinely stuck-writer worst case. Per-
        # connection, same as synchronous/cache_size above -- must be set here, not
        # schema.sql, for the identical reason (doesn't persist in the db file itself).
        # Phase 10b: optional -- omitting hardware_profile (every pre-existing
        # caller, including every test) leaves SQLite's own default cache_size
        # untouched, identical to this class's behavior before this param existed.
        self._in_transaction = False
        # Merge-chain lookups (resolve_canonical_device_id / _all_ids_resolving_to) ran several queries EACH,
        # thousands of times per detection cycle (profiled 2026-09-30: ~20 % of the engine's main loop).
        # Cached with a short TTL; dropped immediately when this process merges (merge_device). Another
        # process's merge is picked up within the TTL.
        self._merge_cache_ttl = _MERGE_CACHE_TTL_SECONDS
        self.decision_write_count = 0            # bumped by insert_decision(); see baseline is_learning_paused()
        self._canon_cache: Dict[str, tuple] = {}
        self._resolving_cache: Dict[str, tuple] = {}
        if is_new:
            self._apply_schema()
        elif db_path not in GraphStore._migrated_db_paths:
            # IPS containment unification: schema.sql
            # is ONLY ever executescript()'d for a brand-new db file (`is_new`
            # above) -- an EXISTING db (e.g. .94's real, already-populated
            # state/v13_graph.db) never re-runs it, so a table added to schema.sql
            # after a deployment's first run would never actually reach that
            # deployment. containment_actions' own CREATE TABLE/INDEX statements
            # already use IF NOT EXISTS specifically so this lightweight migration
            # step was ASSUMED safe to run unconditionally here too -- a no-op on
            # a db that already has it.
            #
            # BUGFIX (found live 2026-09-22, "the query takes too long"): that
            # no-op assumption held for a single long-lived writer, but
            # graph_client.py's open_store() constructs a FRESH GraphStore (and
            # so re-ran this DDL) on EVERY console API request. Each ALTER/CREATE
            # still needs a real write-intent lock, and with the main pipeline
            # process committing decisions/evidence every 1-4s plus the WAL
            # having grown large, several concurrent console requests piled up
            # here waiting out PRAGMA busy_timeout (10s) one after another --
            # confirmed live via py-spy: 6+ threads simultaneously stuck at this
            # exact call, /api/graph taking 40s+ to answer even limit=1. The
            # actual schema only ever needs migrating once per process (nothing
            # else in this same process alters it again mid-run) -- cached here,
            # per db_path, so only the FIRST GraphStore built in a process's
            # lifetime (still correctly migrating a freshly-restarted process
            # after a real schema change) pays this cost; every request after
            # that opens a plain, uncontended connection like the module
            # docstring always assumed.
            with GraphStore._migration_lock:
                if db_path not in GraphStore._migrated_db_paths:
                    self._migrate_existing_db()
                    GraphStore._migrated_db_paths.add(db_path)

    def _open_connection(self) -> sqlite3.Connection:
        # check_same_thread=False only so close() can reach every thread's connection; each one is still
        # used by the single thread that opened it.
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 10000")
        cache_kb = _HARDWARE_PROFILE_CACHE_SIZE_KB.get(self._hardware_profile or "")
        if cache_kb is not None:
            conn.execute(f"PRAGMA cache_size = -{cache_kb}")
        with self._all_conns_lock:
            self._all_conns.append(conn)
        return conn

    @property
    def _conn(self) -> sqlite3.Connection:
        """This thread's connection, opened on first use (E16/I9: never share one across threads)."""
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            conn = self._open_connection()
            self._tls.conn = conn
        return conn

    @property
    def _in_transaction(self) -> bool:
        return getattr(self._tls, "in_transaction", False)

    @_in_transaction.setter
    def _in_transaction(self, value: bool) -> None:
        self._tls.in_transaction = value

    def _apply_schema(self) -> None:
        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            self._conn.executescript(f.read())
        self._conn.commit()

    def _migrate_existing_db(self) -> None:
        """Runs the subset of schema.sql that's safe to apply to an already-populated
        db (IF NOT EXISTS-guarded CREATE TABLE/INDEX statements only) -- keeps an
        existing deployment's graph in sync with schema additions made after its
        first run, without a separate migration-runner framework. Extend this (still
        IF NOT EXISTS-guarded) the next time schema.sql gains a new table/index that
        needs to reach a database that already exists."""
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS containment_actions (
                action_id       TEXT PRIMARY KEY,
                device_id       TEXT NOT NULL REFERENCES devices(device_id),
                decision_id     TEXT REFERENCES decisions(decision_id),
                action_type     TEXT NOT NULL CHECK (action_type IN
                                   ('dns_block','tarpit','router_isolate','release','retry','dead_letter')),
                target          TEXT,
                status          TEXT NOT NULL,
                reason          TEXT,
                timestamp       REAL NOT NULL,
                released_at     REAL,
                metadata_json   TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_containment_device ON containment_actions(device_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_containment_status ON containment_actions(status);

            CREATE TABLE IF NOT EXISTS device_destinations (
                device_id      TEXT NOT NULL REFERENCES devices(device_id),
                destination_id TEXT NOT NULL REFERENCES destinations(destination_id),
                first_seen     REAL NOT NULL,
                last_seen      REAL NOT NULL,
                PRIMARY KEY (device_id, destination_id)
            );
            CREATE INDEX IF NOT EXISTS idx_device_destinations_device_ts ON device_destinations(device_id, last_seen);

            CREATE TABLE IF NOT EXISTS intel_sweeps (
                sweep_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     REAL NOT NULL,
                trigger       TEXT NOT NULL,
                summary_json  TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_evidence_type_ts ON evidence(evidence_type, timestamp);
            -- 2026-09-23 (live profiling on .94): get_evidence_for_device()'s capped
            -- per-type query (device_id + evidence_type + timestamp range, newest
            -- first, LIMIT) had no index covering both equality columns, so SQLite
            -- picked idx_evidence_type_ts and walked EVERY device's rows of that
            -- type in the 24h window (143k zeek_notice_weak rows), per device, per
            -- cycle: 135-275 ms per device, ~17% of the main loop. This index makes
            -- it a direct seek (1.6 s -> 0.18 s for a full pass over 20 devices).
            CREATE INDEX IF NOT EXISTS idx_evidence_device_type_ts ON evidence(device_id, evidence_type, timestamp);

            CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);

            -- Release 15, closed-loop autotuning architecture -- kept in exact sync
            -- with schema.sql's own copies of these six statements; extend both
            -- together, never just one.
            CREATE TABLE IF NOT EXISTS device_baselines (
                device_id            TEXT NOT NULL REFERENCES devices(device_id),
                metric                TEXT NOT NULL,
                hour                  INTEGER NOT NULL,
                regime_id             INTEGER NOT NULL DEFAULT 0,
                model_kind            TEXT NOT NULL CHECK (model_kind IN ('gaussian','beta','poisson','markov')),
                posterior_params_json TEXT NOT NULL DEFAULT '{}',
                run_length_json        TEXT NOT NULL DEFAULT '{}',
                n                     INTEGER NOT NULL DEFAULT 0,
                updated_at             REAL NOT NULL,
                PRIMARY KEY (device_id, metric, hour, regime_id)
            );
            CREATE INDEX IF NOT EXISTS idx_device_baselines_lookup ON device_baselines(device_id, metric);

            CREATE TABLE IF NOT EXISTS population_priors (
                device_type           TEXT NOT NULL,
                metric                TEXT NOT NULL,
                hour                  INTEGER NOT NULL,
                model_kind            TEXT NOT NULL CHECK (model_kind IN ('gaussian','beta','poisson','markov')),
                posterior_params_json TEXT NOT NULL DEFAULT '{}',
                contributed_by_json    TEXT NOT NULL DEFAULT '[]',
                updated_at             REAL NOT NULL,
                PRIMARY KEY (device_type, metric, hour)
            );

            CREATE TABLE IF NOT EXISTS cl_afpe_trust (
                device_id              TEXT NOT NULL REFERENCES devices(device_id),
                behavior_fingerprint    TEXT NOT NULL,
                destination_class       TEXT NOT NULL,
                hypothesis_id           TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
                evidence_family          TEXT NOT NULL,
                regime_id                INTEGER NOT NULL DEFAULT 0,
                trust_value              REAL NOT NULL DEFAULT 0.0,
                n                        INTEGER NOT NULL DEFAULT 0,
                last_updated              REAL NOT NULL,
                snapshot_id               TEXT,
                PRIMARY KEY (device_id, behavior_fingerprint, destination_class, hypothesis_id, evidence_family, regime_id)
            );
            CREATE INDEX IF NOT EXISTS idx_cl_afpe_trust_device ON cl_afpe_trust(device_id);

            CREATE TABLE IF NOT EXISTS threshold_history (
                change_id       TEXT PRIMARY KEY,
                device_id       TEXT REFERENCES devices(device_id),
                device_type      TEXT,
                parameter        TEXT NOT NULL,
                old_value        REAL,
                new_value        REAL,
                proposed_at      REAL NOT NULL,
                canary_until     REAL,
                promoted_at      REAL,
                rolled_back_at   REAL,
                reason           TEXT,
                backtest_run_id  TEXT,
                snapshot_id      TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_threshold_history_device ON threshold_history(device_id, proposed_at);

            CREATE TABLE IF NOT EXISTS baseline_snapshots (
                snapshot_id            TEXT PRIMARY KEY,
                device_id               TEXT NOT NULL REFERENCES devices(device_id),
                taken_at                 REAL NOT NULL,
                reason                   TEXT NOT NULL CHECK (reason IN
                                            ('scheduled','pre_regime_change','pre_autotune_batch','pre_cl_afpe_suppression','manual')),
                posterior_params_json    TEXT NOT NULL DEFAULT '{}',
                threshold_params_json     TEXT NOT NULL DEFAULT '{}',
                cl_afpe_trust_json        TEXT NOT NULL DEFAULT '{}',
                label                     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_baseline_snapshots_device ON baseline_snapshots(device_id, taken_at);

            CREATE TABLE IF NOT EXISTS backtest_runs (
                run_id                  TEXT PRIMARY KEY,
                started_at               REAL NOT NULL,
                finished_at               REAL,
                golden_set_result_json    TEXT NOT NULL DEFAULT '{}',
                synthetic_result_json     TEXT NOT NULL DEFAULT '{}',
                drift_result_json         TEXT NOT NULL DEFAULT '{}',
                coverage_json             TEXT NOT NULL DEFAULT '{}',
                overall_pass              INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_backtest_runs_started ON backtest_runs(started_at);

            -- Alert-trace graph (Documentation/ALERT_TRACE_GRAPH_PLAN.md, 2026-09-22) --
            -- kept in exact sync with schema.sql's own copies; extend both together.
            CREATE TABLE IF NOT EXISTS alert_events (
                alert_event_id       TEXT PRIMARY KEY,
                decision_id           TEXT NOT NULL REFERENCES decisions(decision_id),
                device_id             TEXT NOT NULL REFERENCES devices(device_id),
                incident_id            TEXT REFERENCES incidents(incident_id),
                timestamp               REAL NOT NULL,
                status                  TEXT NOT NULL CHECK (status IN
                                           ('FIRED','SUPPRESSED_AUTONOMOUS','LOGGED_ONLY')),
                fp_verdict               TEXT,
                fp_confidence             REAL,
                fp_stage                  TEXT,
                explanation_text           TEXT,
                explanation_embedding       BLOB,
                autotune_state_json          TEXT NOT NULL DEFAULT '{}',
                plain_explanation             TEXT,
                alert_payload_json            TEXT NOT NULL DEFAULT '{}',
                backfilled                    INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_alert_events_device_ts ON alert_events(device_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_alert_events_ts ON alert_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alert_events_decision ON alert_events(decision_id);
            CREATE INDEX IF NOT EXISTS idx_alert_events_incident ON alert_events(incident_id);

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id          TEXT PRIMARY KEY,
                device_id              TEXT NOT NULL REFERENCES devices(device_id),
                first_seen              REAL NOT NULL,
                last_seen                REAL NOT NULL,
                occurrence_count          INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_device_last_seen ON incidents(device_id, last_seen);

            CREATE TABLE IF NOT EXISTS operator_actions (
                operator_action_id    TEXT PRIMARY KEY,
                alert_event_id           TEXT NOT NULL REFERENCES alert_events(alert_event_id),
                action                    TEXT NOT NULL CHECK (action IN
                                             ('approve','release','revoke','immunize','block')),
                timestamp                  REAL NOT NULL,
                result_json                  TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_operator_actions_alert_event ON operator_actions(alert_event_id);

            -- Phase 7 of the autonomy-completion effort (2026-09-27) -- kept in exact
            -- sync with schema.sql's own copy of this table; extend both together.
            CREATE TABLE IF NOT EXISTS shadow_decisions (
                shadow_id       TEXT PRIMARY KEY,
                change_id       TEXT NOT NULL REFERENCES threshold_history(change_id),
                device_id       TEXT REFERENCES devices(device_id),
                timestamp       REAL NOT NULL,
                real_state      TEXT NOT NULL,
                shadow_state    TEXT NOT NULL,
                agree           INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_shadow_decisions_change ON shadow_decisions(change_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_shadow_decisions_timestamp ON shadow_decisions(timestamp);

            -- Phase 8 of the autonomy-completion effort (2026-09-27) -- kept in exact
            -- sync with schema.sql's own copy of these 3 tables; extend both together.
            CREATE TABLE IF NOT EXISTS device_cohort_membership (
                device_id   TEXT PRIMARY KEY REFERENCES devices(device_id),
                cohort_key  TEXT NOT NULL,
                joined_at   REAL NOT NULL,
                updated_at  REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_identity_stability (
                device_id                TEXT PRIMARY KEY REFERENCES devices(device_id),
                last_identity_change_at  REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cohort_priors (
                cohort_key             TEXT NOT NULL,
                metric                 TEXT NOT NULL,
                hour                   INTEGER NOT NULL,
                model_kind             TEXT NOT NULL CHECK (model_kind IN ('gaussian','beta','poisson')),
                posterior_params_json  TEXT NOT NULL DEFAULT '{}',
                contributed_by_json    TEXT NOT NULL DEFAULT '[]',
                updated_at              REAL NOT NULL,
                PRIMARY KEY (cohort_key, metric, hour)
            );
            """
        )
        # alert_event_id on containment_actions predates this column on any db created
        # before 2026-09-22 -- CREATE TABLE IF NOT EXISTS above no-ops on an existing
        # table regardless of columns, same ADD-COLUMN idiom as threshold_history.device_type
        # below (must also run, and commit, before any future index references this column).
        try:
            self._conn.execute("ALTER TABLE containment_actions ADD COLUMN alert_event_id TEXT REFERENCES alert_events(alert_event_id)")
        except sqlite3.OperationalError:
            pass  # column already exists
        # plain_explanation (2026-09-22): alert_events itself predates this column
        # on any db that already had the table created earlier the SAME day this
        # session shipped it (containment_actions above is the general pattern
        # for exactly this situation -- CREATE TABLE IF NOT EXISTS no-ops
        # regardless of columns).
        try:
            self._conn.execute("ALTER TABLE alert_events ADD COLUMN plain_explanation TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
        # 2026-09-16, per-device/category autotuning plan: threshold_history predates
        # this column -- CREATE TABLE IF NOT EXISTS above is a no-op on a db that
        # already has the table (regardless of which columns it has), so an existing
        # deployment's threshold_history needs an explicit ADD COLUMN. SQLite has no
        # `ADD COLUMN IF NOT EXISTS`; the try/except is the idiom for that, same
        # "no-op on a db that already has it, real migration on one that doesn't"
        # framing as every CREATE TABLE/INDEX above.
        #
        # BUGFIX (2026-09-16, found via test coverage + confirmed .94's own live db
        # still lacks this column despite two later deploys never actually reaching
        # .94): this ADD COLUMN must run, and commit, BEFORE any CREATE INDEX that
        # references device_type -- it used to live in the executescript block above,
        # which runs top-to-bottom as one unit against a genuinely old db (where
        # CREATE TABLE IF NOT EXISTS no-ops because the table already exists sans
        # this column): CREATE INDEX ON threshold_history(device_type, ...) hit the
        # column before this ALTER TABLE (which ran AFTER the whole executescript
        # call) ever got a chance to add it, raising
        # "sqlite3.OperationalError: no such column: device_type" out of
        # GraphStore.__init__ itself for every old-db deployment. Splitting the
        # index out of the script and issuing it here, after the ALTER TABLE, is
        # what makes the ordering actually safe.
        try:
            self._conn.execute("ALTER TABLE threshold_history ADD COLUMN device_type TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_threshold_history_device_type "
            "ON threshold_history(device_type, proposed_at)"
        )
        self._conn.commit()

    def close(self) -> None:
        # Closes every thread's connection, not just the caller's.
        with self._all_conns_lock:
            conns, self._all_conns = self._all_conns, []
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass

    def checkpoint_wal(self) -> None:
        """BUGFIX (2026-09-16, third-party audit finding P0 -- unbounded WAL
        growth): defense-in-depth for the ONE long-lived GraphStore singleton in
        this codebase (live_engine.py's own -- every other caller, including
        every console-API request via middleware/graph_client.py, opens a
        short-lived connection that's closed within one request/call, letting
        SQLite's own default auto-checkpoint handle things normally). That
        singleton's connection stays open for the life of the process (days of
        uptime), so PASSIVE never blocks on a concurrent reader/writer and never
        raises if one is active -- it just checkpoints whatever it safely can
        right now, a no-op cost when there's nothing to do. Callers should rate-
        limit calling this (see live_engine.py's own periodic call) rather than
        call it every cycle; SQLite's own automatic checkpoint (default: every
        ~1000 WAL pages) already handles the common case, this is a periodic
        backstop, not a replacement for it. Best-effort: never raises."""
        try:
            self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except Exception as e:
            LOGGER.warning("WAL checkpoint failed for %r (non-fatal): %s", self.db_path, e)

    def _maybe_commit(self) -> None:
        """Every mutating method calls this instead of self._conn.commit() directly.
        Outside a transaction() block, behavior is unchanged (commits immediately,
        same as before this existed). Inside one, defers to the transaction's own
        single commit at the end -- this is what lets a whole poll cycle's writes
        (many insert_evidence() calls + one insert_decision()) cost one commit
        instead of the ~4-per-item cost each of those methods used to pay alone."""
        if not self._in_transaction:
            self._conn.commit()

    @contextlib.contextmanager
    def transaction(self):
        """Groups every write made inside the `with` block into a single commit
        (or a single rollback if the block raises) -- callers writing a whole
        cycle's worth of evidence + a decision should wrap that in one of these
        rather than let each insert_evidence()/insert_decision() call commit on
        its own. Nested `with store.transaction():` blocks are a no-op pass-through
        (only the outermost one actually commits/rolls back)."""
        if self._in_transaction:
            yield
            return
        self._in_transaction = True
        try:
            yield
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            self._in_transaction = False

    # --- devices -----------------------------------------------------------

    # Flash wear (2026-10-02, measured on .94: ~25 GB/day from this store). The poll loop refreshes last_seen of
    # every active device, destination and device<->destination pair every ~2 s; each refresh dirtied the same 4 KB
    # table/index pages and every commit wrote them to the WAL (then again into the database at checkpoint). last_seen
    # is only ever compared over windows of minutes to days, so it is advanced only when it is more than this many
    # seconds old -- an UPDATE whose WHERE matches nothing touches no page. It also never moves backwards any more.
    LAST_SEEN_RESOLUTION_SECONDS = 300.0

    def upsert_device(self, device_id: str, display_label: Optional[str] = None,
                        device_type: Optional[str] = None, timestamp: Optional[float] = None) -> None:
        ts = timestamp if timestamp is not None else time.time()
        cur = self._conn.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,))
        if cur.fetchone() is None:
            self._conn.execute(
                "INSERT INTO devices (device_id, display_label, device_type, first_seen, last_seen, metadata_json) "
                "VALUES (?, ?, ?, ?, ?, '{}')",
                (device_id, display_label, device_type, ts, ts),
            )
        else:
            self._conn.execute(
                "UPDATE devices SET last_seen = MAX(last_seen, ?), "
                "display_label = COALESCE(?, display_label), "
                "device_type = COALESCE(?, device_type) "
                "WHERE device_id = ? AND (last_seen < ? "
                "OR (? IS NOT NULL AND display_label IS NOT ?) OR (? IS NOT NULL AND device_type IS NOT ?))",
                (ts, display_label, device_type, device_id, ts - self.LAST_SEEN_RESOLUTION_SECONDS,
                 display_label, display_label, device_type, device_type),
            )
        self._maybe_commit()

    def update_device_metadata(self, device_id: str, updates: Dict[str, Any],
                                 timestamp: Optional[float] = None) -> None:
        """Merges `updates` into a device's metadata_json (shallow -- top-level keys in
        `updates` overwrite the same key in the existing dict, everything else is left
        alone). Auto-upserts the device row first, so this is safe to call for a
        device_id that hasn't been seen via insert_evidence()/insert_decision() yet
        (the graph-engine migration, Phase 3 -- used to persist a trust anchor's
        learned MAC, surviving restarts, unlike core/identity.py's own single in-memory
        `_gateway_mac` field)."""
        self.upsert_device(device_id, timestamp=timestamp)
        row = self._conn.execute(
            "SELECT metadata_json FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        try:
            current = json.loads(row["metadata_json"]) if row and row["metadata_json"] else {}
        except (TypeError, ValueError):
            current = {}
        current.update(updates)
        self._conn.execute(
            "UPDATE devices SET metadata_json = ? WHERE device_id = ?",
            (json.dumps(current), device_id),
        )
        self._maybe_commit()

    def get_device_metadata(self, device_id: str) -> Dict[str, Any]:
        """Returns the device's metadata_json as a dict, or {} if the device doesn't
        exist yet or its metadata is malformed -- never raises."""
        row = self._conn.execute(
            "SELECT metadata_json FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        if row is None or not row["metadata_json"]:
            return {}
        try:
            return json.loads(row["metadata_json"])
        except (TypeError, ValueError):
            return {}

    def get_active_device_ids(self, seen_since: Optional[float] = None) -> set:
        """device_ids NOT merged away (merged_into_device_id IS NULL). `seen_since`
        (a unix timestamp), when given, also requires last_seen >= that cutoff --
        `devices` rows are otherwise permanent by design (tombstoned on merge, never
        deleted), so a device idle far longer than any real retention window would
        still count as "active" without this filter. Used by callers that persist a
        device-keyed dict OUTSIDE this store (e.g. train_fp_classifier.py's
        autotune_stats.json) to know which keys are still real, so entries for
        devices merged away or long gone can be pruned instead of accumulating
        forever (disk-retention audit)."""
        if seen_since is None:
            cur = self._conn.execute("SELECT device_id FROM devices WHERE merged_into_device_id IS NULL")
        else:
            cur = self._conn.execute(
                "SELECT device_id FROM devices WHERE merged_into_device_id IS NULL AND last_seen >= ?",
                (seen_since,),
            )
        return {row["device_id"] for row in cur.fetchall()}

    def _invalidate_merge_caches(self) -> None:
        self._canon_cache.clear()
        self._resolving_cache.clear()

    def resolve_canonical_device_id(self, device_id: str) -> str:
        """Cached (short TTL) front for `_resolve_canonical_uncached()` -- see __init__'s comment."""
        now = time.monotonic()
        hit = self._canon_cache.get(device_id)
        if hit is not None and hit[1] > now:
            return hit[0]
        canonical = self._resolve_canonical_uncached(device_id)
        if len(self._canon_cache) > 20000:
            self._canon_cache.clear()          # bounded: a few thousand device ids at most in practice
        self._canon_cache[device_id] = (canonical, now + self._merge_cache_ttl)
        return canonical

    def _resolve_canonical_uncached(self, device_id: str) -> str:
        """Walks the merged_into_device_id chain to the ultimate canonical id.
        Unlike StateManager.merge_into_canonical() (state_guard.py), an orphan's row
        is NEVER deleted -- this resolution is what makes that audit-preserving
        design actually transparent to every other read in this module."""
        seen = set()
        current = device_id
        while True:
            if current in seen:
                raise RuntimeError(f"merged_into_device_id cycle detected at '{current}'")
            seen.add(current)
            row = self._conn.execute(
                "SELECT merged_into_device_id FROM devices WHERE device_id = ?", (current,)
            ).fetchone()
            if row is None or row["merged_into_device_id"] is None:
                return current
            current = row["merged_into_device_id"]

    def merge_device(self, orphan_id: str, canonical_id: str, timestamp: Optional[float] = None) -> None:
        """Audit-preserving merge -- a deliberate improvement over StateManager's
        discard-on-merge (state_guard.py:436-439, called out in the plan for your
        sign-off, not a silent behavior change). The orphan row is tombstoned via
        merged_into_device_id, never deleted, so every evidence/edge row that
        pointed at it keeps resolving through resolve_canonical_device_id().

        BUGFIX (2026-09-16, live IPv6-rollout verification -- found via a recurring
        "merged_into_device_id cycle detected" warning, traced to a real 2-node
        cycle dating back to 2026-09-06, ten days before this fix, so a pre-existing
        latent bug rather than anything IPv6-related): this only ever checked for a
        direct self-merge (orphan_id == canonical_id), never whether canonical_id is
        ALREADY (transitively) merged into orphan_id. If some later re-identification
        decision calls merge_device(orphan_id=B, canonical_id=A) after an earlier
        cycle already wrote A -> B, the old code would happily write B -> A too,
        creating exactly the 2-cycle resolve_canonical_device_id() then loops
        forever on. Every real caller already wraps this in a broad
        try/except Exception treating a graph-mirror failure as best-effort
        (live_manager.py, pipeline.py, merge_fragmented_devices.py all log-and-
        continue, never blocking the state-side merge that already happened) -- so
        refusing here is safe: it just skips the graph-side mirror for this one
        conflicting call, exactly like any other best-effort graph write failure,
        rather than silently corrupting the merge chain into an infinite loop."""
        if orphan_id == canonical_id:
            raise ValueError("cannot merge a device into itself")
        try:
            resolved_canonical = self._resolve_canonical_uncached(canonical_id)   # never trust a cache for cycle detection
        except RuntimeError as e:
            raise ValueError(
                f"cannot merge '{orphan_id}' into '{canonical_id}': "
                f"'{canonical_id}'s own merge chain already cycles ({e})"
            ) from e
        if resolved_canonical == orphan_id:
            raise ValueError(
                f"cannot merge '{orphan_id}' into '{canonical_id}': "
                f"'{canonical_id}' is already (transitively) merged into '{orphan_id}' -- would create a cycle"
            )
        ts = timestamp if timestamp is not None else time.time()
        # P2 (architecture review 2026-10-02): one transaction for the whole merge -- the upserts, the tombstone,
        # the merged_into edge and the stability stamp used to commit one by one, so a crash in between could leave
        # a tombstone without its edge (or the reverse).
        with self.transaction():
            self._merge_device_rows(orphan_id, canonical_id, ts)

    def _merge_device_rows(self, orphan_id: str, canonical_id: str, ts: float) -> None:
        self.upsert_device(orphan_id, timestamp=ts)
        self.upsert_device(canonical_id, timestamp=ts)
        self._conn.execute(
            "UPDATE devices SET merged_into_device_id = ? WHERE device_id = ?",
            (canonical_id, orphan_id),
        )
        self._invalidate_merge_caches()
        self.add_edge("device", orphan_id, "device", canonical_id, "merged_into", ts)
        # Phase 8 (behavioral cohorts, autonomy-completion effort): every real
        # identity-merge call site (core/identity.py's real-time path,
        # pipeline.py's periodic reconciliation worker, merge_fragmented_devices.py)
        # already mirrors here -- one stamp catches "this device's identity just
        # changed" for all of them, no new call sites needed. Read via
        # get_identity_stable_days().
        self._conn.execute(
            "INSERT INTO device_identity_stability (device_id, last_identity_change_at) VALUES (?, ?) "
            "ON CONFLICT(device_id) DO UPDATE SET last_identity_change_at=excluded.last_identity_change_at",
            (canonical_id, ts),
        )
        self._maybe_commit()

    def get_identity_stable_days(self, device_id: str, now: Optional[float] = None) -> Optional[float]:
        """Days since this device's last identity-changing merge (an orphan folded
        into it via merge_device()). None if it has never been through a merge --
        callers should treat that as 'no signal either way' (never merged is not
        the same claim as 'confirmed stable'), not as maximally stable."""
        row = self._conn.execute(
            "SELECT last_identity_change_at FROM device_identity_stability WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        ts = now if now is not None else time.time()
        return (ts - row["last_identity_change_at"]) / 86400.0

    def upsert_device_cohort_membership(self, device_id: str, cohort_key: str, now: float) -> None:
        """Behavioral-cohort assignment (Phase 8, autonomy-completion effort) --
        joined_at only resets when cohort_key actually changes from what's already
        stored, so 'how long has this device been in its current cohort' stays a
        meaningful signal across nightly recomputation, not reset every run."""
        row = self._conn.execute(
            "SELECT cohort_key FROM device_cohort_membership WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if row is not None and row["cohort_key"] == cohort_key:
            self._conn.execute(
                "UPDATE device_cohort_membership SET updated_at = ? WHERE device_id = ?",
                (now, device_id),
            )
        else:
            self._conn.execute(
                "INSERT INTO device_cohort_membership (device_id, cohort_key, joined_at, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(device_id) DO UPDATE SET cohort_key=excluded.cohort_key, "
                "joined_at=excluded.joined_at, updated_at=excluded.updated_at",
                (device_id, cohort_key, now, now),
            )
        self._maybe_commit()

    def get_device_cohort_key(self, device_id: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT cohort_key FROM device_cohort_membership WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        return row["cohort_key"] if row is not None else None

    # --- destinations --------------------------------------------------------

    def upsert_destination(self, destination_id: str, kind: str, timestamp: Optional[float] = None) -> None:
        ts = timestamp if timestamp is not None else time.time()
        cur = self._conn.execute("SELECT destination_id FROM destinations WHERE destination_id = ?", (destination_id,))
        if cur.fetchone() is None:
            self._conn.execute(
                "INSERT INTO destinations (destination_id, kind, first_seen, last_seen, metadata_json) "
                "VALUES (?, ?, ?, ?, '{}')",
                (destination_id, kind, ts, ts),
            )
        else:
            self._conn.execute("UPDATE destinations SET last_seen = ? WHERE destination_id = ? AND last_seen < ?",
                               (ts, destination_id, ts - self.LAST_SEEN_RESOLUTION_SECONDS))
        self._maybe_commit()

    # --- evidence --------------------------------------------------------------

    def insert_evidence(self, ev: Evidence) -> None:
        """Auto-upserts the device and destination rows (including the NO_DESTINATION
        sentinel, already seeded by schema.sql) and the observed/targets edges --
        callers never have to remember the bookkeeping steps in the right order."""
        self.upsert_device(ev.device_id, timestamp=ev.timestamp)
        dest_kind = "ip" if ev.destination_id != NO_DESTINATION and _looks_like_ip(ev.destination_id) else "domain"
        self.upsert_destination(ev.destination_id, dest_kind, timestamp=ev.timestamp)

        row = ev.to_row()
        self._conn.execute(
            "INSERT INTO evidence (evidence_id, device_id, destination_id, evidence_type, "
            "independence_family, value, confidence, timestamp, source, provenance, features_json) "
            "VALUES (:evidence_id, :device_id, :destination_id, :evidence_type, "
            ":independence_family, :value, :confidence, :timestamp, :source, :provenance, :features_json)",
            row,
        )
        self.add_edge("device", ev.device_id, "evidence", ev.evidence_id, "observed", ev.timestamp)
        if ev.destination_id != NO_DESTINATION:
            self.add_edge("evidence", ev.evidence_id, "destination", ev.destination_id, "targets", ev.timestamp)
        self._maybe_commit()

    def insert_decision(self, device_id: str, timestamp: float, state: str,
                          decision_path: str, confidence: float, risk_score: float,
                          winning_hypothesis_id: Optional[str] = None,
                          mechanism_flags: Optional[Dict[str, str]] = None,
                          raw_payload: Optional[Dict[str, Any]] = None,
                          evidence_ids: Optional[List[str]] = None) -> str:
        # winning_hypothesis_id references the `hypotheses` table's own versioned
        # registry (schema.sql) -- not yet populated by any argus module (a
        # separate, not-yet-built concern: registering/versioning hypothesis
        # definitions as graph rows). Left None here deliberately rather than
        # inventing a fake row to satisfy the FK; the winning hypothesis NAME is
        # still fully recoverable from raw_payload_json's own "hypotheses" key.
        """Writes one row to schema.sql's `decisions` table -- the audit trail
        Phase 7's divergence comparator reads (raw_payload_json carries the full
        DecisionEngine.evaluate() return dict for that purpose, per schema.sql's
        own column comment). mechanism_flags records which mechanisms were
        shadow vs. live AT DECISION TIME, so a later divergence found while a
        mechanism was still shadow-only is distinguishable from one found after
        it flipped live -- schema.sql's own stated reason for this column,
        confirmed via direct read, not guessed.

        evidence_ids (Phase 1 fix, the graph-engine migration): the evidence_id of
        every Evidence item that contributed to this decision -- creates an
        evidence->decision 'supports' edge for each, UP TO a hardware-profile-driven
        cap (_MAX_SUPPORTING_EVIDENCE_EDGES_BY_PROFILE, most-recent-first) -- a real
        production decision was found with 56,073 such edges before this cap
        existed. The FULL, uncapped evidence_id list is preserved inside
        raw_payload_json's own "_all_evidence_ids" key regardless, so audit
        completeness isn't lost, only the graph's edge-traversal representation is
        bounded. prune_evidence()'s own "don't delete evidence a decision still
        references" exception (see that method's docstring) only sees the CAPPED
        set via edges -- an evidence item outside the cap that's otherwise past
        retention can still be pruned even though its id lingers in
        raw_payload_json, a deliberate tradeoff (the JSON reference is inert once
        the row is gone, same as any other historical audit text). Callers pass the
        SAME evidence list they gave the decision engine, by evidence_id.

        Returns the generated decision_id."""
        decision_id = uuid.uuid4().hex
        self.upsert_device(device_id, timestamp=timestamp)

        all_evidence_ids = list(evidence_ids or [])
        capped_evidence_ids = all_evidence_ids
        payload = dict(raw_payload or {})
        # BUGFIX (2026-09-20, memory-restart root-cause investigation): attack_evidence/
        # winning_evidence (decision/engine.py) are FULL serialized Evidence objects --
        # not ids -- built solely so pipeline.py's Telegram WHY-block can render
        # corroborating evidence that may have already aged out of its own short-TTL
        # in-memory store, a same-cycle, in-memory-only need. This method previously
        # persisted the SAME dict wholesale, so those fields ended up duplicated
        # forever in raw_payload_json with no cap -- found live on .94: individual
        # rows up to 22MB, one field alone (attack_evidence) accounting for 13.3MB of
        # that. Both are fully reconstructable after the fact via this decision's own
        # 'supports' edges + the evidence table (exactly what decision_replay.py's
        # get_decision_evidence() already does), so persisting them a second time here
        # is pure redundant bloat with no audit-completeness upside -- confirmed no
        # caller anywhere reads either key back OUT of a persisted raw_payload_json.
        payload.pop("attack_evidence", None)
        payload.pop("winning_evidence", None)
        if all_evidence_ids:
            cap = _MAX_SUPPORTING_EVIDENCE_EDGES_BY_PROFILE.get(
                self._hardware_profile or "", _MAX_SUPPORTING_EVIDENCE_EDGES_BY_PROFILE["x86_16gb"])
            if len(all_evidence_ids) > cap:
                placeholders = ",".join("?" * len(all_evidence_ids))
                rows = self._conn.execute(
                    f"SELECT evidence_id, timestamp FROM evidence WHERE evidence_id IN ({placeholders})",
                    all_evidence_ids,
                ).fetchall()
                ts_by_id = {r["evidence_id"]: r["timestamp"] for r in rows}
                # Evidence ids with no matching row yet (e.g. this cycle's own fresh
                # items, not committed until this same transaction's insert_evidence()
                # calls land) sort last by falling back to 0.0 -- harmless, since the
                # full list is preserved in raw_payload_json regardless of edge order.
                capped_evidence_ids = sorted(
                    all_evidence_ids, key=lambda eid: ts_by_id.get(eid, 0.0), reverse=True
                )[:cap]
                # BUGFIX (2026-09-20): this list itself used to be stored fully
                # uncapped -- see _MAX_ALL_EVIDENCE_IDS_STORED's own comment for why
                # it can't just be dropped (autotune/reset.py needs it) but must still
                # be bounded (found live: 68,915 ids, ~2.2MB, for one legacy row).
                # Most-recent-first, same ordering as capped_evidence_ids, so anything
                # trimmed here is also the oldest/least-relevant for a blast-radius check.
                payload["_all_evidence_ids"] = sorted(
                    all_evidence_ids, key=lambda eid: ts_by_id.get(eid, 0.0), reverse=True
                )[:_MAX_ALL_EVIDENCE_IDS_STORED]

        self._conn.execute(
            "INSERT INTO decisions (decision_id, device_id, timestamp, winning_hypothesis_id, "
            "state, decision_path, confidence, risk_score, mechanism_flags_json, raw_payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (decision_id, device_id, timestamp, winning_hypothesis_id, state, decision_path,
             confidence, risk_score, json.dumps(mechanism_flags or {}), json.dumps(payload)),
        )
        self.decision_write_count += 1           # lets readers cache "latest decision" until this changes
        for eid in capped_evidence_ids:
            self.add_edge("evidence", eid, "decision", decision_id, "supports", timestamp)
        self._maybe_commit()
        return decision_id

    def update_decision_payload(self, decision_id: str, updates: Dict[str, Any],
                                  timestamp: Optional[float] = None) -> bool:
        """alert/decision unification (Phase 2): merges
        `updates` into an existing decision's raw_payload_json (shallow -- top-level
        keys in `updates` overwrite the same key in the existing dict, everything
        else untouched), the SAME merge pattern update_device_metadata() already
        established for devices.metadata_json -- reused deliberately, not
        reinvented. Exists so pipeline.py can enrich a decision row already written
        by _write_graph()/insert_decision() earlier in the SAME cycle with fields
        that only become known later (alert_payload's rich network_context/
        features/reasoning_trail, fp_verdict, incident-notify outcome) -- without
        this, either the whole decision write would have to be deferred until the
        end of the cycle (a larger, riskier restructure) or that information would
        never reach the graph at all.

        `timestamp` is accepted for symmetry with update_device_metadata() but is
        NOT written anywhere -- decisions.timestamp is the decision's own original
        moment, not this enrichment call's; changing it here would corrupt
        get_decisions_since()/get_decisions_older_than()'s own time-window queries.

        Best-effort by DESIGN at the call site, not this method: this method itself
        still raises on a real DB error (a caller enriching a decision it just
        wrote wants to know if that failed) -- the "never affect the real alert"
        fail-safety is the CALLER's responsibility (wrap the call in try/except),
        matching every other argus graph write's own fail-safe convention documented
        at its own call site rather than swallowed silently in here.

        Returns False (no-op) if decision_id doesn't exist; True if updated."""
        row = self._conn.execute(
            "SELECT raw_payload_json FROM decisions WHERE decision_id = ?", (decision_id,)
        ).fetchone()
        if row is None:
            return False
        try:
            current = json.loads(row["raw_payload_json"]) if row["raw_payload_json"] else {}
        except (TypeError, ValueError):
            current = {}
        current.update(updates)
        self._conn.execute(
            "UPDATE decisions SET raw_payload_json = ? WHERE decision_id = ?",
            (json.dumps(current), decision_id),
        )
        self._maybe_commit()
        return True

    # --- alert-trace graph (Documentation/ALERT_TRACE_GRAPH_PLAN.md, 2026-09-22) ---

    def upsert_hypothesis(self, name: str, kind: str) -> str:
        """Catalog row, one per hypothesis TYPE (e.g. 'PEER_COHORT_DEVIATION'),
        reused across every decision that ever names it -- not one row per
        decision (confirmed feasible against real data: decision.get("hypotheses")
        already carries {"attack": {"name": ..., "score": ...}, "benign": {...}}
        every cycle, so the catalog just needs one row per distinct name seen,
        never hardcoded). `name` IS the hypothesis_id (schema.sql's own PK shape,
        e.g. 'NETWORK_INTRUSION') -- upserting on that makes repeat calls
        idempotent by construction, no separate existence check needed. `kind` is
        'attack' or 'benign' (schema.sql's own CHECK)."""
        self._conn.execute(
            "INSERT INTO hypotheses (hypothesis_id, kind, version) VALUES (?, ?, 1) "
            "ON CONFLICT(hypothesis_id) DO NOTHING",
            (name, kind),
        )
        self._maybe_commit()
        return name

    def add_hypothesis_edges(self, decision_id: str, hypotheses: Dict[str, Any],
                               winning_name: Optional[str], evidence_ids: List[str],
                               timestamp: float) -> None:
        """Writes the hypothesis layer of the trace graph insert_decision() alone
        never populated (winning_hypothesis_id is confirmed 0/45,650 rows on
        .94's real graph -- graph_api.py's own docstring). One 'corroborates'
        edge per hypothesis this cycle's HEE actually scored (typically
        {'attack': {...}, 'benign': {...}}, the SAME dict decision.get(
        "hypotheses") already carries every cycle -- no new computation), with
        {"won": bool, "score": ...} in the edge's own metadata_json distinguishing
        the winner from a considered-but-lost hypothesis. Reuses the already-
        allowed 'corroborates' relation (confirmed unused as a real written edge
        anywhere else in this codebase -- only mentioned in an unrelated
        docstring about a different table) rather than adding new CHECK values,
        which would force a rebuild of the live 8M+-row `edges` table for no
        benefit (see the plan doc's "Schema-safety refinement" section).

        `winning_name` is decisions.raw_payload_json["explanation"] -- the SAME
        field graph_api.py's get_graph() already reads back to recover the
        winner client-side; reused here, not a second convention.

        Also links `evidence_ids` (the SAME capped list insert_decision() already
        received) to the WINNING hypothesis via 'supports' (already-allowed,
        zero schema risk). Deliberately NOT attempted for the losing hypothesis:
        argus/decision/engine.py's HEE does not compute a per-evidence-item hypothesis
        attribution anywhere today (confirmed by reading it) -- an evidence->
        losing-hypothesis 'contradicts' edge would be inventing data this
        codebase doesn't actually have, not recovering it.

        Best-effort BY THE CALLER, same convention as update_decision_payload()
        -- this method itself still raises on a real DB error."""
        for key, h in (hypotheses or {}).items():
            if not isinstance(h, dict):
                continue
            name = h.get("name")
            if not name:
                continue
            kind = key if key in ("attack", "benign") else "attack"
            self.upsert_hypothesis(name, kind)
            won = bool(winning_name) and name == winning_name
            self.add_edge("hypothesis", name, "decision", decision_id, "corroborates",
                           timestamp, metadata={"won": won, "score": h.get("score")})
            if won:
                for eid in evidence_ids:
                    self.add_edge("evidence", eid, "hypothesis", name, "supports", timestamp)

    def upsert_incident(self, incident_id: str, device_id: str, timestamp: float) -> None:
        """One row per ongoing incident (schema.sql's own `incidents` table) --
        replaces the bare incident_id string alert_payload used to carry with no
        queryable entity behind it. Upserts occurrence_count/last_seen in place,
        the same INSERT...ON CONFLICT pattern upsert_device() already
        established, rather than one fresh row per occurrence."""
        self._conn.execute(
            "INSERT INTO incidents (incident_id, device_id, first_seen, last_seen, occurrence_count) "
            "VALUES (?, ?, ?, ?, 1) "
            "ON CONFLICT(incident_id) DO UPDATE SET "
            "last_seen = excluded.last_seen, occurrence_count = occurrence_count + 1",
            (incident_id, device_id, timestamp, timestamp),
        )
        self._maybe_commit()

    def insert_alert_event(self, decision_id: str, device_id: str, timestamp: float,
                             status: str, incident_id: Optional[str] = None,
                             fp_verdict: Optional[str] = None, fp_confidence: Optional[float] = None,
                             fp_stage: Optional[str] = None, explanation_text: Optional[str] = None,
                             explanation_embedding: Optional[bytes] = None,
                             autotune_state: Optional[Dict[str, Any]] = None,
                             plain_explanation: Optional[str] = None,
                             alert_payload: Optional[Dict[str, Any]] = None,
                             backfilled: bool = False) -> str:
        """One row per qualifying cycle (state crosses SUSPICIOUS+): FIRED (a real
        Telegram send happened), SUPPRESSED_AUTONOMOUS (CL-AFPE suppressed it), or
        LOGGED_ONLY (neither) -- append-only, NEVER
        overwritten (unlike decisions.raw_payload_json, which a recurring
        incident's repeated update_decision_payload() calls DO overwrite --
        confirmed live: 71,669 alerts.json lines vs 45,650 total decision rows,
        proof most individual firings/suppressions were never durable in the
        graph before this table existed). This is what replaces alerts.json's
        per-cycle history going forward. Returns the generated alert_event_id."""
        alert_event_id = uuid.uuid4().hex
        if incident_id:
            self.upsert_incident(incident_id, device_id, timestamp)
        self._conn.execute(
            "INSERT INTO alert_events (alert_event_id, decision_id, device_id, incident_id, "
            "timestamp, status, fp_verdict, fp_confidence, fp_stage, explanation_text, "
            "explanation_embedding, autotune_state_json, plain_explanation, alert_payload_json, backfilled) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (alert_event_id, decision_id, device_id, incident_id, timestamp, status,
             fp_verdict, fp_confidence, fp_stage, explanation_text, explanation_embedding,
             json.dumps(autotune_state or {}), plain_explanation,
             json.dumps(alert_payload or {}), int(backfilled)),
        )
        self._maybe_commit()
        return alert_event_id

    def insert_operator_action(self, alert_event_id: str, action: str,
                                 timestamp: Optional[float] = None,
                                 result: Optional[Dict[str, Any]] = None) -> str:
        """One row per Telegram tap (approve/release/revoke/immunize/block)
        against a specific alert_event -- previously had ZERO durable trace
        anywhere (alerts.py's "published_alert" ledger is in-memory,
        process-lifetime only, lost on every restart). Returns the generated
        operator_action_id."""
        operator_action_id = uuid.uuid4().hex
        ts = timestamp if timestamp is not None else time.time()
        self._conn.execute(
            "INSERT INTO operator_actions (operator_action_id, alert_event_id, action, timestamp, result_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (operator_action_id, alert_event_id, action, ts, json.dumps(result or {})),
        )
        self._maybe_commit()
        return operator_action_id

    def link_containment_action(self, action_id: str, alert_event_id: str) -> bool:
        """Best-effort: links an already-written containment_actions row to its
        alert_event after the fact (insert_containment_action() itself doesn't
        take alert_event_id -- IPSMitigator's own call sites don't always have
        one in scope at write time). Returns False if action_id doesn't exist."""
        cur = self._conn.execute(
            "UPDATE containment_actions SET alert_event_id = ? WHERE action_id = ?",
            (alert_event_id, action_id),
        )
        self._maybe_commit()
        return cur.rowcount > 0

    def get_alert_events(self, limit: int = 50, offset: int = 0, device_id: Optional[str] = None,
                           since: Optional[float] = None, until: Optional[float] = None,
                           status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Paginated, indexed read over alert_events (idx_alert_events_device_ts /
        idx_alert_events_ts) -- replaces _alert_log_utils.py's bounded-backward-
        scan hack over alerts.json's 170MB+ NDJSON file with a real indexed
        query, for the console's fired/suppressed alert view."""
        clauses: List[str] = []
        params: List[Any] = []
        if device_id is not None:
            clauses.append("device_id = ?")
            params.append(device_id)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(until)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM alert_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d.pop("explanation_embedding", None)  # binary vector, never serialized to the API
            for col in ("autotune_state_json", "alert_payload_json"):
                try:
                    d[col[:-5]] = json.loads(d.pop(col) or "{}")
                except (TypeError, ValueError):
                    d[col[:-5]] = {}
            out.append(d)
        return out

    def get_alert_events_by_decision_ids(self, decision_ids: List[str],
                                           cap_per_decision: int = 10) -> List[Dict[str, Any]]:
        """Console Evidence Graph tab (2026-09-22, user request: "is it possible
        to show [alerts] directly in graph"): the alert_events belonging to a
        capped set of decisions, for rendering as real graph nodes rather than
        only a separate table. Capped per-decision (most-recent-first, a SQL
        window function -- same "cap the write/read side, never let one busy
        entity blow up the response" discipline this module already applies to
        evidence-per-decision -- see EVIDENCE_PER_DECISION_CAP's own docstring in
        graph_api.py for the real 56,073-edge incident that established this
        pattern) because a single long-running incident whose decision never
        changes state can accumulate many alert_events against the SAME
        decision_id (unlike evidence, alert_events are deliberately never
        deduped/collapsed -- see this table's own module docstring)."""
        if not decision_ids:
            return []
        out: List[Dict[str, Any]] = []
        for chunk in _chunked(decision_ids, _SQLITE_DELETE_BATCH_SIZE):
            placeholders = ",".join("?" * len(chunk))
            rows = self._conn.execute(
                f"""
                SELECT alert_event_id, decision_id, device_id, incident_id, timestamp,
                       status, fp_verdict, fp_confidence, fp_stage, explanation_text, plain_explanation
                FROM (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY decision_id ORDER BY timestamp DESC
                    ) AS rn
                    FROM alert_events WHERE decision_id IN ({placeholders})
                ) WHERE rn <= ?
                """,
                chunk + [cap_per_decision],
            ).fetchall()
            out.extend(dict(r) for r in rows)
        return out

    def search_alert_events_by_embedding(self, query_vector: bytes, since: float,
                                           until: Optional[float] = None,
                                           device_id: Optional[str] = None,
                                           limit: int = 20) -> List[Dict[str, Any]]:
        """Cosine-similarity search over alert_events.explanation_embedding,
        scoped by a MANDATORY time window (`since` is a required parameter -- no
        unscoped "search everything" code path exists, per the plan doc's
        bounding rules) plus an optional device_id. Brute-force numpy over the
        scoped candidate set -- deliberately not an ANN index (sqlite-vec/FAISS):
        at this project's real scale a bounded brute-force scan is simpler and,
        per the plan doc's own resource analysis, well within the Pi-8GB budget.
        Raises AlertSearchScopeTooLarge if the scoped candidate count exceeds
        ALERT_SEARCH_CANDIDATE_CAP -- the caller must narrow the query (shorter
        window and/or a device_id), never a silent partial-result truncation."""
        import numpy as np
        clauses = ["explanation_embedding IS NOT NULL", "timestamp >= ?"]
        params: List[Any] = [since]
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(until)
        if device_id is not None:
            clauses.append("device_id = ?")
            params.append(device_id)
        where = " AND ".join(clauses)

        count = self._conn.execute(
            f"SELECT COUNT(*) AS c FROM alert_events WHERE {where}", params,
        ).fetchone()["c"]
        if count > ALERT_SEARCH_CANDIDATE_CAP:
            raise AlertSearchScopeTooLarge(count, ALERT_SEARCH_CANDIDATE_CAP)
        if count == 0:
            return []

        rows = self._conn.execute(
            f"SELECT alert_event_id, device_id, timestamp, status, explanation_text, "
            f"explanation_embedding FROM alert_events WHERE {where}", params,
        ).fetchall()
        q = np.frombuffer(query_vector, dtype=np.float32)
        q_norm = q / (np.linalg.norm(q) or 1.0)
        mat = np.stack([np.frombuffer(r["explanation_embedding"], dtype=np.float32) for r in rows])
        mat_norm = mat / (np.linalg.norm(mat, axis=1, keepdims=True) + 1e-9)
        scores = mat_norm @ q_norm
        order = np.argsort(-scores)[:limit]
        return [
            {
                "alert_event_id": rows[i]["alert_event_id"], "device_id": rows[i]["device_id"],
                "timestamp": rows[i]["timestamp"], "status": rows[i]["status"],
                "explanation_text": rows[i]["explanation_text"], "similarity": float(scores[i]),
            }
            for i in order
        ]

    # --- containment actions -----

    def insert_containment_action(self, device_id: str, action_type: str, status: str,
                                    timestamp: Optional[float] = None, target: Optional[str] = None,
                                    decision_id: Optional[str] = None, reason: Optional[str] = None,
                                    metadata: Optional[Dict[str, Any]] = None) -> str:
        """Write-only AUDIT MIRROR of a real containment action already taken by
        src/mitigation/ips.py (Pi-hole block, Layer-2 tarpit, Fritz!Box router
        isolation, or a retry/dead-letter bookkeeping event) -- this method NEVER
        decides or performs the real action, it only records that ips.py already
        did, immediately after ips.py's own StateManager-backed dict write. Callers
        must treat this as best-effort (wrap in try/except at the call site,
        matching every other argus graph write's own fail-safe convention) -- a
        failure here must never affect the real containment action, which has
        already happened by the time this is called.

        action_type is one of schema.sql's CHECK-constrained values
        ('dns_block','tarpit','router_isolate','release','retry','dead_letter').
        Returns the generated action_id."""
        ts = timestamp if timestamp is not None else time.time()
        action_id = uuid.uuid4().hex
        self.upsert_device(device_id, timestamp=ts)
        self._conn.execute(
            "INSERT INTO containment_actions (action_id, device_id, decision_id, action_type, "
            "target, status, reason, timestamp, released_at, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
            (action_id, device_id, decision_id, action_type, target, status, reason, ts,
             json.dumps(metadata or {})),
        )
        self._maybe_commit()
        return action_id

    def update_containment_status(self, action_id: str, status: str,
                                    timestamp: Optional[float] = None) -> bool:
        """Marks an existing containment_actions row's status (typically 'released'
        when ips.py's own release_device()/unblock_domain() runs). Sets released_at
        to `timestamp` (defaulting to now) ONLY when status == 'released' -- any
        other status transition leaves released_at untouched. Returns False if
        action_id doesn't exist; True if updated."""
        ts = timestamp if timestamp is not None else time.time()
        row = self._conn.execute(
            "SELECT action_id FROM containment_actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        if row is None:
            return False
        if status == "released":
            self._conn.execute(
                "UPDATE containment_actions SET status = ?, released_at = ? WHERE action_id = ?",
                (status, ts, action_id),
            )
        else:
            self._conn.execute(
                "UPDATE containment_actions SET status = ? WHERE action_id = ?",
                (status, action_id),
            )
        self._maybe_commit()
        return True

    def get_active_containment_for_device(self, device_id: str) -> List[Dict[str, Any]]:
        """All containment_actions rows for this device currently in a non-terminal
        state ('active' or 'retrying') -- the direct replacement for
        ips.py's own get_containment_status(), which today manually scans 3
        separate in-memory dicts by IP/MAC/dev_id with fallback chains. Resolves
        through merged/orphan device_ids the same way get_evidence_for_device()
        does, so a device that fragmented across an old orphan id still shows its
        real containment history under its current canonical id."""
        canonical = self.resolve_canonical_device_id(device_id)
        device_ids = self._all_ids_resolving_to(canonical)
        placeholders = ",".join("?" * len(device_ids))
        rows = self._conn.execute(
            f"SELECT * FROM containment_actions WHERE device_id IN ({placeholders}) "
            "AND status IN ('active','retrying') ORDER BY timestamp DESC",
            device_ids,
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            out.append(d)
        return out

    def get_containment_history(self, device_id: str, since: float) -> List[Dict[str, Any]]:
        """Full containment_actions history for this device (any status) since
        `since` -- for threat_hunt.py/decision_replay.py-style audit queries,
        distinct from get_active_containment_for_device()'s current-status-only
        view. Same merged/orphan device_id resolution as that method."""
        canonical = self.resolve_canonical_device_id(device_id)
        device_ids = self._all_ids_resolving_to(canonical)
        placeholders = ",".join("?" * len(device_ids))
        rows = self._conn.execute(
            f"SELECT * FROM containment_actions WHERE device_id IN ({placeholders}) "
            "AND timestamp >= ? ORDER BY timestamp DESC",
            device_ids + [since],
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            out.append(d)
        return out

    def get_evidence_for_device(self, device_id: str, since: Optional[float] = None,
                                  resolve_merges: bool = True,
                                  cap_per_type: Optional[int] = None) -> List[Evidence]:
        """Fresh, per-call snapshot -- never a cached/mutated object, matching the
        pure-per-cycle evaluation model every argus Hypothesis.evaluate() (Phase 3)
        relies on.

        cap_per_type (2026-09-20, restart-cadence investigation): None (the
        default) preserves this method's original, fully-unbounded behavior --
        every caller that needs the complete audit trail (decision_replay.py,
        console-API reads, etc.) is unaffected. Live callers pass a real cap
        (see _MAX_EVIDENCE_PER_TYPE_IN_WINDOW_BY_PROFILE's own comment for the
        full incident this closes) to bound how many rows of any ONE
        evidence_type get constructed into Evidence objects, most-recent-first
        -- a device generating tens of thousands of duplicate observations of
        the same type in one window must never cost proportionally more to
        process than a handful of genuinely distinct ones."""
        canonical = self.resolve_canonical_device_id(device_id) if resolve_merges else device_id
        if resolve_merges:
            # Every device_id that ever resolved (directly or transitively) to this
            # canonical id contributes its evidence -- the whole point of not
            # discarding orphans on merge.
            device_ids = self._all_ids_resolving_to(canonical)
        else:
            device_ids = [device_id]
        placeholders = ",".join("?" * len(device_ids))

        if cap_per_type is None:
            query = f"SELECT * FROM evidence WHERE device_id IN ({placeholders})"
            params: List[Any] = list(device_ids)
            if since is not None:
                query += " AND timestamp >= ?"
                params.append(since)
            query += " ORDER BY timestamp ASC"
            rows = self._conn.execute(query, params).fetchall()
            return [Evidence.from_row(dict(r)) for r in rows]

        # Capped path: find which evidence_types are actually present first (a
        # cheap, indexed query -- typically single-digit distinct types even
        # for a device with tens of thousands of rows), then one most-recent-
        # first, LIMIT-bounded query per type, unioned together. Two round
        # trips at most (regardless of how many total rows exist), never one
        # unbounded fetch -- this is what actually stops the pathological
        # volume case from ever reaching Python object construction at all,
        # not just from affecting anything downstream of it.
        type_query = f"SELECT DISTINCT evidence_type FROM evidence WHERE device_id IN ({placeholders})"
        type_params: List[Any] = list(device_ids)
        if since is not None:
            type_query += " AND timestamp >= ?"
            type_params.append(since)
        types = [r["evidence_type"] for r in self._conn.execute(type_query, type_params).fetchall()]

        # One query per (device_id, type) with device_id as an equality, never an
        # IN list: with IN (a, b) -- any device that has merged identities --
        # SQLite's planner falls back to idx_evidence_type_ts and scans every
        # device's rows of that type again (verified with EXPLAIN QUERY PLAN on
        # .94's graph). Each id's newest cap_per_type rows are merged and the
        # newest cap_per_type overall kept -- identical to the single IN query.
        per_type_query = "SELECT * FROM evidence WHERE device_id = ? AND evidence_type = ?"
        if since is not None:
            per_type_query += " AND timestamp >= ?"
        per_type_query += " ORDER BY timestamp DESC LIMIT ?"

        out: List[Evidence] = []
        for evidence_type in types:
            rows: List[dict] = []
            for dev in device_ids:
                params: List[Any] = [dev, evidence_type]
                if since is not None:
                    params.append(since)
                params.append(cap_per_type)
                rows.extend(dict(r) for r in self._conn.execute(per_type_query, params).fetchall())
            if len(device_ids) > 1:
                rows.sort(key=lambda r: r["timestamp"], reverse=True)
                rows = rows[:cap_per_type]
            out.extend(Evidence.from_row(r) for r in rows)
        out.sort(key=lambda ev: ev.timestamp)
        return out

    def get_evidence_by_ids(self, evidence_ids: List[str]) -> List[Evidence]:
        """Batch fetch by evidence_id -- added for the console API's graph-view
        endpoint, which resolves the evidence linked to several decisions at once via
        get_edges() and would otherwise pay one query per evidence_id (N+1).

        BUGFIX (2026-09-20, restart-cadence investigation): batched, same
        reason as prune_evidence()/prune_weak_zeek_notices() -- autotune/
        reset.py's blast-radius check can call this with up to
        _MAX_ALL_EVIDENCE_IDS_STORED (1000) ids, right at/over SQLite's own
        older, widely-deployed bound-parameter ceiling (999)."""
        if not evidence_ids:
            return []
        out: List[Evidence] = []
        for chunk in _chunked(evidence_ids, _SQLITE_DELETE_BATCH_SIZE):
            placeholders = ",".join("?" * len(chunk))
            rows = self._conn.execute(
                f"SELECT * FROM evidence WHERE evidence_id IN ({placeholders})", chunk,
            ).fetchall()
            out.extend(Evidence.from_row(dict(r)) for r in rows)
        return out

    def evidence_for_destination_exists(self, device_id: str, destination_id: str,
                                          since: float, before: float,
                                          resolve_merges: bool = True) -> bool:
        """BUGFIX (2026-09-20, restart-cadence investigation): window.py's
        domain_seen_before() used to answer this exact yes/no question by
        calling get_evidence_for_device() -- fetching and constructing EVERY
        evidence row for the device across the whole lookback window (up to
        90 days) just to check whether ANY of them matched one destination
        before one cutoff. For a device with a large evidence history this is
        a pure existence check paying the full cost of a bulk fetch -- `SELECT
        1 ... LIMIT 1` (SQLite short-circuits on the first match, using the
        SAME idx_evidence_device_ts index the bulk query already used) answers
        the identical question without ever constructing an Evidence object,
        let alone all of them."""
        canonical = self.resolve_canonical_device_id(device_id) if resolve_merges else device_id
        device_ids = self._all_ids_resolving_to(canonical) if resolve_merges else [device_id]
        placeholders = ",".join("?" * len(device_ids))
        query = (
            f"SELECT 1 FROM evidence WHERE device_id IN ({placeholders}) "
            f"AND destination_id = ? AND timestamp >= ? AND timestamp < ? LIMIT 1"
        )
        params: List[Any] = list(device_ids) + [destination_id, since, before]
        return self._conn.execute(query, params).fetchone() is not None

    def _all_ids_resolving_to(self, canonical_id: str) -> List[str]:
        """Every id that resolves (directly or transitively) into `canonical_id`, itself first. Cached with a
        short TTL like resolve_canonical_device_id(); callers get a copy, so they may mutate the list."""
        now = time.monotonic()
        hit = self._resolving_cache.get(canonical_id)
        if hit is not None and hit[1] > now:
            return list(hit[0])
        ids = self._all_ids_resolving_to_uncached(canonical_id)
        if len(self._resolving_cache) > 20000:
            self._resolving_cache.clear()
        self._resolving_cache[canonical_id] = (ids, now + self._merge_cache_ttl)
        return list(ids)

    def _all_ids_resolving_to_uncached(self, canonical_id: str, _seen: Optional[set] = None) -> List[str]:
        seen = _seen if _seen is not None else set()
        if canonical_id in seen:               # a corrupt merge cycle must not recurse forever
            return []
        seen.add(canonical_id)
        ids = [canonical_id]
        rows = self._conn.execute(
            "SELECT device_id FROM devices WHERE merged_into_device_id = ?", (canonical_id,)
        ).fetchall()
        for r in rows:
            ids.extend(self._all_ids_resolving_to_uncached(r["device_id"], seen))
        return ids

    # --- edges -----------------------------------------------------------------

    def add_edge(self, src_kind: str, src_id: str, dst_kind: str, dst_id: str,
                  relation: str, timestamp: Optional[float] = None,
                  metadata: Optional[Dict[str, Any]] = None) -> None:
        import json
        ts = timestamp if timestamp is not None else time.time()
        self._conn.execute(
            "INSERT INTO edges (src_kind, src_id, dst_kind, dst_id, relation, timestamp, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (src_kind, src_id, dst_kind, dst_id, relation, ts, json.dumps(metadata or {})),
        )
        self._maybe_commit()

    def get_devices_targeting(self, destination_id: str, since: float) -> List[str]:
        """Distinct CANONICAL device_ids that have touched this destination since
        `since` -- the real, cheap
        cross-device query `idx_evidence_destination` exists to support ("which
        devices have an edge targeting destination X in the last N minutes,"
        schema.sql's own stated reason for that index). Canonicalizes each raw
        device_id via resolve_canonical_device_id() and dedupes -- without this, a
        device that fragmented across an old orphan id and its current canonical id
        could be miscounted as two independent devices touching the same
        destination, when it's really one physical device.

        BUGFIX (live audit, 2026-09-08): short-circuits to [] for a multicast/link-
        local/broadcast destination_id (mDNS 224.0.0.251/ff02::fb, SSDP
        239.255.255.250, ICMPv6 ND/MLD ff02::1/ff02::16, etc.) -- every device on the
        LAN legitimately, constantly sends to these addresses as ordinary service
        discovery, so "which OTHER devices also touched this destination" is always
        true and means nothing; the SAME traffic shape already poisoned
        the CL-AFPE's confirmed-intel store before that store got this exact guard
        (see is_local_or_multicast_destination()'s own docstring). Without this,
        CoordinatedTargetingHypothesis (argus/hypotheses/engine.py) scores ordinary mDNS/
        SSDP/multicast chatter as cross-device attack corroboration -- confirmed live:
        83% of non-suppressed HIGH alerts in a 6h sample were exactly this shape.

        BUGFIX #2 (live audit, 2026-09-08, found investigating a real alert that
        SURVIVED the multicast fix above): also short-circuits to [] for a PRIVATE
        destination that's structurally shared household infrastructure -- a router,
        hub, or another of the user's own devices that a large fraction of the whole
        device fleet legitimately talks to. Confirmed live: 192.168.77.47 (a second
        Fire TV, "amazon_firetv_projector_fritz_box") was independently touched by 7
        of the household's devices; COORDINATED_TARGETING fired anyway (threshold is
        just 1 OTHER device) and had auto-blocked that device repeatedly over the
        prior ~36 hours. Deliberately NOT a blanket is_private exclusion (unlike the
        multicast case, two devices sharing an unusual PRIVATE destination can still
        be real lateral-movement signal) -- see _is_shared_infrastructure()'s own
        docstring for the ratio-based reasoning that keeps that signal intact."""
        if is_local_or_multicast_destination(destination_id):
            return []
        if self._is_shared_infrastructure(destination_id, since):
            return []
        rows = self._conn.execute(
            "SELECT DISTINCT device_id FROM evidence WHERE destination_id = ? AND timestamp >= ?",
            (destination_id, since),
        ).fetchall()
        canonical_ids = {self.resolve_canonical_device_id(r["device_id"]) for r in rows}
        return sorted(canonical_ids)

    def _is_shared_infrastructure(self, destination_id: str, since: float) -> bool:
        """True if `destination_id` is touched by a large enough SHARE of the whole
        known device fleet, over a longer lookback than the caller's own (typically
        short, single-cycle) `since` window, that "multiple devices touched it" is a
        structural fact about the destination (a router, a hub, another of the
        user's own devices most things on the LAN talk to) rather than a meaningful
        coincidence. get_devices_targeting()'s own docstring (BUGFIX #2) has the real
        incident this closes.

        Anchored to the CALLER's `since` (not wall-clock time.time()) so this stays
        correct under a re-derivation anchored to a past decision's own timestamp
        (live_llm_review.py) and deterministic under test fixtures that use a
        synthetic clock -- extends the lookback further into the past from whatever
        `since` already means to this call, never off real "now."

        Deliberately requires BOTH a minimum absolute fleet size (a 2-3-device
        household network makes any ratio meaningless -- one device touching
        something IS 33-50%) and a minimum device-share ratio, not either alone."""
        long_since = since - _SHARED_INFRASTRUCTURE_LOOKBACK_SECONDS
        touching = self._conn.execute(
            "SELECT DISTINCT device_id FROM evidence WHERE destination_id = ? AND timestamp >= ?",
            (destination_id, long_since),
        ).fetchall()
        touching_canonical = {self.resolve_canonical_device_id(r["device_id"]) for r in touching}
        if len(touching_canonical) < 2:
            return False
        fleet_row = self._conn.execute(
            "SELECT COUNT(*) as c FROM devices WHERE merged_into_device_id IS NULL AND last_seen >= ?",
            (long_since,),
        ).fetchone()
        fleet_size = int(fleet_row["c"]) if fleet_row and fleet_row["c"] is not None else 0
        if fleet_size < _SHARED_INFRASTRUCTURE_MIN_FLEET_SIZE:
            return False
        return (len(touching_canonical) / fleet_size) >= _SHARED_INFRASTRUCTURE_DEVICE_RATIO

    def get_devices_sharing_provenance(self, evidence_type: str, provenance: str, since: float) -> List[str]:
        """Release 14, net-new capability N4 (multi-signal campaign detection):
        the SAME cross-device query get_devices_targeting() answers for a shared
        DESTINATION, generalized to a shared PROVENANCE string -- e.g. a JA3/JA4
        fingerprint hash, encoded into provenance at the detector (see
        intelligence/detectors/zeek_network.py), matching this codebase's own
        established "provenance is the free-text discriminator slot" convention
        (already used for zeek_notice's note_type). An exact string match is
        correct here (two devices sharing the literal SAME TLS fingerprint hash
        is unambiguous), unlike DGA-seed correlation below, which needs a
        COMPUTED similarity key instead of an exact stored value. Canonicalizes
        each device_id, same reasoning as get_devices_targeting()."""
        rows = self._conn.execute(
            "SELECT DISTINCT device_id FROM evidence WHERE evidence_type = ? AND provenance = ? AND timestamp >= ?",
            (evidence_type, provenance, since),
        ).fetchall()
        canonical_ids = {self.resolve_canonical_device_id(r["device_id"]) for r in rows}
        return sorted(canonical_ids)

    def get_evidence_by_type_since(self, evidence_type: str, since: float,
                                     cap_per_device: Optional[int] = None) -> List[Evidence]:
        """All evidence of one type across EVERY device since `since` -- unlike
        get_evidence_for_device(), deliberately not scoped to one device. DGA-seed
        correlation (Release 14, N4) needs this raw cross-device fetch because it
        groups by a COMPUTED shape key (live_engine.py's own _dga_shape_key()),
        not a single stored value get_devices_sharing_provenance() could match on
        directly -- the grouping happens in Python after this fetch.

        cap_per_device (2026-09-20, restart-cadence investigation follow-up --
        flagged at the time as "the same bug class as Root Cause #3, lower
        priority, worth the same cap treatment if it ever is [large]"): None
        (the default) preserves this method's original, fully-unbounded
        behavior. When set, this is capped PER DEVICE, not to a flat total --
        unlike get_evidence_for_device()'s cap_per_type (safe to cap by total
        recency there, since it only ever affects ONE device's own evaluation),
        this query's whole POINT is counting how many DISTINCT devices share a
        pattern (see live_engine.py's `len(others) >= _COORDINATED_TARGETING_
        MIN_OTHER_DEVICES` check). A flat total-rows cap would let ONE flooding
        device's own volume silently crowd every other genuinely-distinct
        device's evidence out of the result, undercounting the very cardinality
        this correlation exists to detect -- exactly the opposite of what a
        defensive cap should do. Capping per-device instead bounds the worst
        case to O(active_devices x cap_per_device) while guaranteeing every
        device that has ANY evidence in the window still contributes at least
        one row (so it's never silently dropped from the distinct-device
        count), only that any single device's own row MULTIPLICITY is bounded."""
        if cap_per_device is None:
            rows = self._conn.execute(
                "SELECT * FROM evidence WHERE evidence_type = ? AND timestamp >= ?",
                (evidence_type, since),
            ).fetchall()
            return [Evidence.from_row(dict(r)) for r in rows]

        device_rows = self._conn.execute(
            "SELECT DISTINCT device_id FROM evidence WHERE evidence_type = ? AND timestamp >= ?",
            (evidence_type, since),
        ).fetchall()
        out: List[Evidence] = []
        for r in device_rows:
            per_device_rows = self._conn.execute(
                "SELECT * FROM evidence WHERE evidence_type = ? AND timestamp >= ? AND device_id = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (evidence_type, since, r["device_id"], cap_per_device),
            ).fetchall()
            out.extend(Evidence.from_row(dict(row)) for row in per_device_rows)
        return out

    def get_devices_with_metadata_value(self, key: str, value: Any) -> List[str]:
        """Release 14, N2 (peer-cohort behavioral baselining): all device_ids
        whose metadata_json[key] == value -- a full table scan, parsed in
        Python rather than a SQLite json_extract() query, deliberately, so this
        doesn't depend on the JSON1 extension being available in every
        deployment's SQLite build (the same reasoning every other argus metadata
        read in this module already applies). Device counts are small (tens,
        not thousands) on any real deployment this project targets, so a full
        scan is cheap -- this is a peer-cohort lookup run once per decision
        cycle per device, not a hot inner loop."""
        rows = self._conn.execute("SELECT device_id, metadata_json FROM devices").fetchall()
        out = []
        for r in rows:
            try:
                meta = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
            except (TypeError, ValueError):
                continue
            if meta.get(key) == value:
                out.append(r["device_id"])
        return out

    def get_device_metadata_values(self, key: str) -> Dict[str, Any]:
        """{device_id: metadata_json[key]} for every non-merged device that has `key` (same full scan as
        get_devices_with_metadata_value())."""
        rows = self._conn.execute(
            "SELECT device_id, metadata_json FROM devices WHERE merged_into_device_id IS NULL").fetchall()
        out = {}
        for r in rows:
            try:
                meta = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
            except (TypeError, ValueError):
                continue
            if key in meta:
                out[r["device_id"]] = meta[key]
        return out

    def get_device_type_cohorts(self) -> Dict[str, List[str]]:
        """Restart-cadence investigation follow-up (2026-09-28, open item #1 of
        Documentation/MEMORY_RESTART_ROOT_CAUSE_AND_CAPACITY_PLAN.md): same
        full-table-scan-in-Python rationale as get_devices_with_metadata_value()
        above, but groups every device by its own metadata_json['device_type']
        in ONE pass instead of requiring a separate scan per device_type.
        live_engine.py's _inject_peer_deviation_evidence() was calling
        get_devices_with_metadata_value() once per device per decision cycle --
        for a cycle that visits every device, that's N redundant full scans of
        this SAME table per cycle. This lets that caller do one scan per cycle
        (cached, see that module's own _refresh_peer_cohort_cache_if_stale())
        instead of one scan per device evaluated that cycle."""
        rows = self._conn.execute("SELECT device_id, metadata_json FROM devices").fetchall()
        out: Dict[str, List[str]] = {}
        for r in rows:
            try:
                meta = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
            except (TypeError, ValueError):
                continue
            device_type = meta.get("device_type")
            if device_type:
                out.setdefault(device_type, []).append(r["device_id"])
        return out

    def is_own_registered_device(self, destination_id: str) -> bool:
        """True if `destination_id` is provably one of THIS network's own
        already-registered devices, not an unknown/external host -- part C of the
        "3 automated-learning gaps" fix (2026-09-15). Checks two things: an exact
        `device_id` match (some identities are keyed by an IP/MAC-derived id
        directly), and membership as a KEY in any device's own
        `metadata_json.known_ips_history` (the real, confirmed shape --
        `{"192.168.1.41": <timestamp>, ...}` -- populated by
        LiveIdentityManager._mirror_identity_signals()). Deliberately NOT reusing
        get_devices_with_metadata_value() above: that does scalar equality on a
        whole metadata value, not membership-as-a-key inside a nested dict.
        Deliberately NOT reusing LiveIdentityManager.resolve_device_id() either --
        that's a heavier, stateful live resolver needing trust-anchor/state-manager
        wiring this store doesn't have; this is a simple, safe, read-only lookup
        against data already proven to exist on this table. Same full-table-scan-
        in-Python rationale as get_devices_with_metadata_value() (device counts are
        small on any real deployment) -- and, per feedback_network_agnostic_design.md,
        deliberately contains no protocol/port/vendor assumption: "is this my own
        hardware" is the only question asked, so it applies identically on any
        consumer network regardless of what discovery protocols its devices use."""
        if not destination_id or destination_id == NO_DESTINATION:
            return False
        rows = self._conn.execute("SELECT device_id, metadata_json FROM devices").fetchall()
        for r in rows:
            if r["device_id"] == destination_id:
                return True
            try:
                meta = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
            except (TypeError, ValueError):
                continue
            if destination_id in (meta.get("known_ips_history") or {}):
                return True
        return False

    def record_device_destinations(self, device_id: str, destination_ids, timestamp: Optional[float] = None) -> None:
        """Upserts one row per (device_id, destination_id) pair into
        device_destinations -- the REAL per-device traffic reality
        get_distinct_destination_count() below reads, independent of whether any
        evidence was ever created for a given destination. See that method's own
        BUGFIX comment (external architecture review, 2026-09-09) for the incident
        this exists to fix. Callers should pass EVERY real destination this device
        touched this cycle (e.g. pipeline.py's own zeek_fx.get_dest_ips() output),
        not just ones that happened to also trigger a detector -- auto-upserts the
        device/destination rows first (same bookkeeping insert_evidence() already
        does), so callers never have to remember the order.

        Deliberately does NOT filter multicast/local destinations at write time
        (matches get_distinct_destination_count()'s own read-time filtering, kept
        symmetric with insert_evidence()'s write-everything/filter-on-read
        convention) -- a future consumer wanting the unfiltered picture doesn't
        need a second write path.

        BUGFIX (2026-09-28, live root-cause investigation): this used to call
        upsert_device() once and upsert_destination() once PER destination_id
        OUTSIDE self.transaction() -- each of those commits on its own
        (_maybe_commit()'s documented behavior when not already inside a
        transaction), so a single device with N destinations this cycle cost N+2
        individual synchronous SQLite commits, on the live pipeline's own MainThread,
        every ~2s poll cycle, for every device with new/updated traffic. A live
        py-spy capture caught MainThread blocked inside get_distinct_destination_
        count()'s own SELECT waiting out PRAGMA busy_timeout -- this write pattern
        is the most direct explanation: many more, smaller commits than necessary
        means many more chances for a concurrent reader/writer (the metrics
        exporter's own thread, a scheduled job subprocess) to be holding the lock
        at exactly the moment this method (or the read right after it) needs it.
        Wrapping the whole method in self.transaction() reduces this to exactly ONE
        commit per call, matching the documented reason transaction() exists
        (its own docstring: "a whole poll cycle's writes... cost one commit instead
        of the ~4-per-item cost") -- this call site had simply never been moved onto
        it."""
        ts = timestamp if timestamp is not None else time.time()
        if not destination_ids:
            return
        with self.transaction():
            self.upsert_device(device_id, timestamp=ts)
            for dest_id in destination_ids:
                if not dest_id or dest_id == NO_DESTINATION:
                    continue
                dest_kind = "ip" if _looks_like_ip(dest_id) else "domain"
                self.upsert_destination(dest_id, dest_kind, timestamp=ts)
                self._conn.execute(
                    "INSERT INTO device_destinations (device_id, destination_id, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(device_id, destination_id) DO UPDATE SET last_seen = excluded.last_seen "
                    "WHERE device_destinations.last_seen < excluded.last_seen - ?",
                    (device_id, dest_id, ts, ts, self.LAST_SEEN_RESOLUTION_SECONDS),
                )

    def get_distinct_destination_count(self, device_id: str, since: float) -> int:
        """Release 14, N2: the behavioral metric peer-cohort baselining compares
        a device against its cohort on -- how many DISTINCT destinations this
        device has touched since `since`. Chosen because it's cheap (one
        indexed COUNT DISTINCT), needs no new evidence field, and is a
        genuinely meaningful anomaly axis for many device classes (e.g. most
        IoT devices talk to a small, stable set of cloud endpoints; a sudden
        jump in destination diversity is a real behavioral change worth a
        peer comparison, independent of whether any single destination looks
        suspicious on its own).

        BUGFIX (live audit, 2026-09-08): excludes multicast/link-local/broadcast
        destination_ids (mDNS, SSDP, ICMPv6 ND/MLD, etc.) before counting -- every
        device sends to several such protocol-group addresses as a side effect of
        ordinary LAN presence, inflating "distinct destination count" by a
        device-type-dependent amount that has nothing to do with real behavioral
        diversity, the exact axis PeerDeviationHypothesis compares against a peer
        cohort. Trades the previous single indexed COUNT(DISTINCT ...) for a fetch-
        then-filter -- acceptable per this method's own docstring reasoning (most
        devices' distinct-destination cardinality is small; this runs once per
        device per decision cycle, not a hot inner loop).

        BUGFIX (external architecture review, 2026-09-09): this used to query the
        `evidence` table -- which only ever has a row when SOME detector already
        flagged something notable about a destination -- as a proxy for "how many
        destinations has this device really talked to." That's a sparse,
        detector-biased count, not a real traffic measurement, and it created a
        self-reinforcing false-positive amplifier: confirmed live, a device
        generating heavy dns_evasion_anomaly/reputation/zeek_notice evidence (each
        with its own destination_id) had an artificially inflated count purely as
        a side effect of OTHER detectors firing, while quiet, evidence-free peer
        devices showed near-zero -- a "laptop cohort average of 0.3" and "phone
        cohort average of 2.2" over a 7-day window, both absurd for real devices.
        Now reads device_destinations (record_device_destinations() above),
        populated from real per-cycle traffic (pipeline.py's own
        zeek_fx.get_dest_ips()), never from evidence-creation as a side effect."""
        rows = self._conn.execute(
            "SELECT DISTINCT destination_id FROM device_destinations WHERE device_id = ? AND last_seen >= ?",
            (device_id, since),
        ).fetchall()
        return sum(1 for r in rows if not is_local_or_multicast_destination(r["destination_id"]))

    def set_destination_reputation(self, destination_id: str, tier: int,
                                     timestamp: Optional[float] = None) -> None:
        """Writes a live reputation-tier cache onto the shared `destinations` row
        (network-wide reputation
        propagation) -- schema.sql's own `reputation_tier_cache`/`reputation_cached_at`
        columns, confirmed unused by anything before this. Once one device's
        evidence confirms a destination as malicious (see retro_hunter.py's own
        call site), any OTHER device touching the same destination can inherit
        that verdict immediately via get_destination_reputation(), instead of each
        device re-earning its own corroboration from zero. Auto-upserts the
        destination row first, so this is safe to call for a destination not yet
        seen via insert_evidence()."""
        ts = timestamp if timestamp is not None else time.time()
        dest_kind = "ip" if _looks_like_ip(destination_id) else "domain"
        self.upsert_destination(destination_id, dest_kind, timestamp=ts)
        self._conn.execute(
            "UPDATE destinations SET reputation_tier_cache = ?, reputation_cached_at = ? "
            "WHERE destination_id = ?",
            (tier, ts, destination_id),
        )
        self._maybe_commit()

    def get_destination(self, destination_id: str) -> Optional[Dict[str, Any]]:
        """One row from `destinations` (kind/first_seen/last_seen/reputation fields),
        or None if it doesn't exist. Added for the console API's graph-view endpoint,
        which needs a destination's own kind/label rather than just its reputation
        cache (get_destination_reputation() below only returns the latter)."""
        row = self._conn.execute(
            "SELECT * FROM destinations WHERE destination_id = ?", (destination_id,)
        ).fetchone()
        return dict(row) if row is not None else None

    def get_destinations_matching(self, query: str) -> List[str]:
        """destination_ids containing `query` as a case-insensitive substring --
        get_devices_targeting() itself needs an EXACT destination_id, so a free-text
        search UI (the console's "devices touching X" hunt query) composes this first
        to resolve what the user typed into the exact id(s) to then look up."""
        rows = self._conn.execute(
            "SELECT destination_id FROM destinations WHERE destination_id LIKE ? ESCAPE '\\'",
            ("%" + query.replace("%", "\\%").replace("_", "\\_") + "%",),
        ).fetchall()
        return [r["destination_id"] for r in rows]

    def get_destination_reputation(self, destination_id: str) -> Optional[Dict[str, Any]]:
        """Returns {"tier": int, "cached_at": float} if this destination has a live
        reputation cache, or None if it was never set (including a destination
        that doesn't exist yet at all) -- never raises. Callers own their own
        staleness policy; this method never expires anything itself (see
        live_engine.py's own TTL constant for the actual policy applied to reads)."""
        row = self._conn.execute(
            "SELECT reputation_tier_cache, reputation_cached_at FROM destinations WHERE destination_id = ?",
            (destination_id,),
        ).fetchone()
        if row is None or row["reputation_tier_cache"] is None:
            return None
        return {"tier": row["reputation_tier_cache"], "cached_at": row["reputation_cached_at"]}

    def get_device_destinations_since(self, since: float) -> List[Any]:
        """Distinct (device_id, destination_id) pairs observed since `since` --
        used by retro_hunter.py (Phase 6) to re-scan historical destinations
        against freshly-updated threat intel, replacing the earlier engine's
        load_historical_domains()'s flat-file JSONL scan with a direct graph query."""
        rows = self._conn.execute(
            "SELECT DISTINCT device_id, destination_id FROM evidence "
            "WHERE timestamp >= ? AND destination_id != '(none)'",
            (since,),
        ).fetchall()
        return [(r["device_id"], r["destination_id"]) for r in rows]

    def get_traffic_destinations_since(self, since: float) -> List[Any]:
        """(device_id, destination_id) pairs from device_destinations (every real destination a device touched,
        recorded each cycle by record_device_destinations()), last seen since `since`, minus local/multicast
        addresses. Unlike get_device_destinations_since() this does not depend on a detector having flagged the
        destination, so a quiet command-and-control address is in it too."""
        rows = self._conn.execute(
            "SELECT device_id, destination_id FROM device_destinations WHERE last_seen >= ?", (since,)
        ).fetchall()
        return [(r["device_id"], r["destination_id"]) for r in rows
                if not is_local_or_multicast_destination(r["destination_id"])]

    INTEL_SWEEPS_KEPT = 500

    def record_intel_sweep(self, trigger: str, summary: Dict[str, Any], timestamp: Optional[float] = None) -> None:
        """One row per learning-period intel sweep (argus/learning_sweep.py). The very first row is kept forever (the
        onboarding report reads what the sweep found at first install); the rest are capped at INTEL_SWEEPS_KEPT."""
        ts = timestamp if timestamp is not None else time.time()
        with self.transaction():
            self._conn.execute("INSERT INTO intel_sweeps (timestamp, trigger, summary_json) VALUES (?, ?, ?)",
                               (ts, trigger, json.dumps(summary, default=str)))
            self._conn.execute(
                "DELETE FROM intel_sweeps WHERE sweep_id != (SELECT MIN(sweep_id) FROM intel_sweeps) AND sweep_id NOT IN "
                "(SELECT sweep_id FROM intel_sweeps ORDER BY sweep_id DESC LIMIT ?)", (self.INTEL_SWEEPS_KEPT,))

    def get_intel_sweeps(self, first: bool = False, limit: int = 20) -> List[Dict[str, Any]]:
        """Recorded intel sweeps, newest first; `first=True` returns only the oldest one (first install)."""
        sql = ("SELECT * FROM intel_sweeps ORDER BY sweep_id ASC LIMIT 1" if first
               else "SELECT * FROM intel_sweeps ORDER BY sweep_id DESC LIMIT ?")
        rows = self._conn.execute(sql, () if first else (int(limit),)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["summary"] = json.loads(d.pop("summary_json") or "{}")
            out.append(d)
        return out

    def get_pairs_written_by_source_since(self, source: str, since: float) -> set:
        """Distinct (device_id, destination_id) pairs that evidence of `source` was written for since `since`.
        The retro-hunter uses it to not report or write the same finding again on every run."""
        rows = self._conn.execute(
            "SELECT DISTINCT device_id, destination_id FROM evidence WHERE source = ? AND timestamp >= ?",
            (source, since),
        ).fetchall()
        return {(r["device_id"], r["destination_id"]) for r in rows}

    def get_decisions_since(self, since: float, until: Optional[float] = None) -> List[Dict[str, Any]]:
        """Real decisions (A7) in [since, until) -- the divergence comparator's
        (A8) own read side. raw_payload is parsed back into a dict (stored as
        JSON text, per insert_decision()); mechanism_flags likewise."""
        if until is not None:
            rows = self._conn.execute(
                "SELECT * FROM decisions WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp",
                (since, until),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM decisions WHERE timestamp >= ? ORDER BY timestamp",
                (since,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["raw_payload"] = json.loads(d.pop("raw_payload_json") or "{}")
            d["mechanism_flags"] = json.loads(d.pop("mechanism_flags_json") or "{}")
            out.append(d)
        return out

    def get_latest_decision_for_device(self, device_id: str, resolve_merges: bool = True) -> Optional[Dict[str, Any]]:
        """Release 15, closed-loop autotuning architecture: the no-learning-
        during-an-incident gate (Design Invariant 06) needs a device's
        CURRENT state, not a windowed query -- one row, newest first, backed
        by idx_decisions_device_ts so this is an index-order scan, not a
        table sort. Returns None for a device with no decision history yet
        (treated as BENIGN/no gate by callers, never as an error).

        BUGFIX (2026-09-20, identity-merge handover follow-up): used to query
        `device_id` literally, with no canonical resolution -- unlike
        get_evidence_for_device()'s already-established resolve_merges
        behavior. A stale reference to a since-merged orphan id would miss
        the canonical device's actual latest decision (or, worse, keep
        seeing whatever the orphan's own last decision was, frozen forever).
        Also considers decisions recorded under any OTHER id that ever
        resolved (directly or transitively) into this canonical id -- the
        orphan may well have its own real decision history from before it
        was merged away, and this device's incident-cooldown gate should see
        the whole physical device's history, not just its current identity's
        slice of it."""
        if resolve_merges:
            canonical = self.resolve_canonical_device_id(device_id)
            device_ids = self._all_ids_resolving_to(canonical)
        else:
            device_ids = [device_id]
        placeholders = ",".join("?" * len(device_ids))
        row = self._conn.execute(
            f"SELECT * FROM decisions WHERE device_id IN ({placeholders}) ORDER BY timestamp DESC LIMIT 1",
            device_ids,
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        try:
            d["mechanism_flags"] = json.loads(d.get("mechanism_flags_json") or "{}")
            d["raw_payload"] = json.loads(d.get("raw_payload_json") or "{}")
        except (TypeError, ValueError):
            d["mechanism_flags"] = {}
            d["raw_payload"] = {}
        return d

    def get_latest_decision_state(self, device_id: str, resolve_merges: bool = True) -> Optional[Dict[str, Any]]:
        """Just `{"state", "timestamp"}` of the device's newest decision (None when it has none). The
        incident-cooldown gate calls this for every metric of every device every cycle and only needs those two
        fields; get_latest_decision_for_device() loads the whole row and JSON-parses two payloads each time
        (profiled 2026-09-30: ~14 % of the engine's main loop)."""
        if resolve_merges:
            device_ids = self._all_ids_resolving_to(self.resolve_canonical_device_id(device_id))
        else:
            device_ids = [device_id]
        placeholders = ",".join("?" * len(device_ids))
        row = self._conn.execute(
            f"SELECT state, timestamp FROM decisions WHERE device_id IN ({placeholders}) ORDER BY timestamp DESC LIMIT 1",
            device_ids,
        ).fetchone()
        return None if row is None else {"state": row["state"], "timestamp": row["timestamp"]}

    def get_recent_decisions(self, limit: int, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """The console API's graph-view endpoint's actual read pattern: the most
        recent `limit` decisions across ALL devices, newest first -- NOT "every
        decision ever made, sorted and truncated in Python" (that used to be
        `get_decisions_since(0.0)`, which pulls the whole table -- including a
        JSON-deserialize of raw_payload_json/mechanism_flags_json for every single
        row -- just to keep the newest 25; on a live deployment with weeks of
        continuous decisions this is the same "fetch-all-then-truncate" anti-pattern
        already fixed for edges via get_edges(limit_most_recent=...), just not
        caught here yet). `ORDER BY timestamp DESC LIMIT ?` pushed into SQL, backed
        by idx_decisions_timestamp (schema.sql) so it's an index-order scan, not a
        full-table sort.

        `device_id` (found live 2026-09-22, "i still do not see the alert in
        graph": a real geofencing alert for one device was correctly present in
        the graph but unreachable from the console, because this call had no way
        to look past the most recent `limit` decisions ACROSS THE WHOLE NETWORK
        -- on a busy network that's a matter of minutes, no matter how old the
        target decision actually is) -- optional, scopes the same query to one
        device via idx_decisions_device_ts (schema.sql), still an index-order
        scan, not a full-table sort."""
        if device_id:
            rows = self._conn.execute(
                "SELECT * FROM decisions WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM decisions ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["raw_payload"] = json.loads(d.pop("raw_payload_json") or "{}")
            d["mechanism_flags"] = json.loads(d.pop("mechanism_flags_json") or "{}")
            out.append(d)
        return out

    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """Release 14, N1 (threat_hunt.py's decision-timeline lookup): one
        decision by id, same raw_payload/mechanism_flags parsing as
        get_decisions_since(). Returns None if no such decision exists (a
        typo'd or already-archived id is a real, expected case for a manual
        lookup tool, not an error)."""
        row = self._conn.execute("SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["raw_payload"] = json.loads(d.pop("raw_payload_json") or "{}")
        d["mechanism_flags"] = json.loads(d.pop("mechanism_flags_json") or "{}")
        return d

    def get_devices_with_latest_decision(self) -> List[Dict[str, Any]]:
        """Every non-merged-away device, LEFT JOINed to its own most recent decision
        (by MAX(timestamp) per device_id) -- added for the console API's device-list
        endpoint. There is no per-device "current state/risk" persisted anywhere
        (DeviceState/ids_state.json has none -- confirmed by direct inspection); the
        latest decision IS that value, matching how the existing Grafana "Master
        Threat Ledger" panel already sources it (home_ids_decision_state /
        home_ids_threat_confidence gauges, themselves populated from this same
        per-cycle decision). Devices with no decision yet return NULL for every
        decision_* column -- a real, expected case (a device seen by the pipeline but
        never yet evaluated), not an error.

        Excludes merged_into_device_id IS NOT NULL rows -- an orphaned identity that
        was merged into a canonical device_id shouldn't double-list alongside it.

        BUGFIX (2026-09-28, console "unidentified devices" investigation): d.device_type
        was being returned straight from the devices table's own COLUMN, which nothing
        on the live per-cycle write path ever populates -- confirmed live: 0 of 152 real
        devices on .94 had it set. The real value lives in metadata_json['device_type']
        (written by live_engine.py's _inject_peer_deviation_evidence(), same field
        get_devices_with_metadata_value()/get_device_type_cohorts() above already read
        from) -- this method just wasn't looking there, so the console silently lost a
        device_type it actually had on record for any device StateManager's own live
        identity cache had since aged out (confirmed live: 3225e9d4690a/c7ede3867502
        tagged "server", d12bf8b7dd2b tagged "iot" in metadata_json, all showing
        "unknown" in the console before this fix). metadata_json wins when both are
        present; the column is kept as a fallback for the one batch job
        (population_prior_builder.py) that does write it directly. display_label has
        the same "nothing populates it" gap (see live_retro_hunter.py's own comment)
        but no metadata_json equivalent to recover it from, so it's left as-is --
        hostname resolution already has a separate, working source (StateManager) at
        the API layer."""
        rows = self._conn.execute(
            """
            SELECT d.device_id, d.display_label, d.device_type, d.metadata_json,
                   d.first_seen, d.last_seen,
                   dec.decision_id, dec.state, dec.risk_score, dec.confidence,
                   dec.timestamp AS decision_timestamp
            FROM devices d
            LEFT JOIN decisions dec ON dec.decision_id = (
                SELECT decision_id FROM decisions WHERE device_id = d.device_id
                ORDER BY timestamp DESC LIMIT 1
            )
            WHERE d.merged_into_device_id IS NULL
            ORDER BY dec.timestamp DESC
            """
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            metadata_json = d.pop("metadata_json", None)
            try:
                meta = json.loads(metadata_json) if metadata_json else {}
            except (TypeError, ValueError):
                meta = {}
            d["device_type"] = meta.get("device_type") or d["device_type"]
            out.append(d)
        return out

    def get_edges(self, relation: Optional[str] = None, src_kind: Optional[str] = None,
                   src_id: Optional[str] = None, dst_kind: Optional[str] = None,
                   dst_id: Optional[str] = None, limit_most_recent: Optional[int] = None) -> List[Dict[str, Any]]:
        """Generic edge query -- kept here (not a relation-specific method) so
        GraphStore stays a plain graph CRUD layer; relation-specific semantics (e.g.
        CL-AFPE's 'trusts' edge TTL/scoping rules, Phase 4) live in their own module,
        not here.

        limit_most_recent (added for the console API's graph-view endpoint): pushes
        `ORDER BY timestamp DESC LIMIT N` down into SQL instead of the caller fetching
        every matching row and truncating in Python. Real, not hypothetical: one
        production decision has 56,073 edges pointing at it (one device alone accounts
        for ~79% of all evidence in the whole database) -- fetching all of those into
        Python just to keep the newest 15 cost ~3s per call; with idx_edges_dst already
        covering (dst_kind, dst_id), SQLite can satisfy ORDER BY ... LIMIT without
        scanning past what it needs. Returned order is DESC (newest first) when this is
        set, ASC otherwise -- unchanged default behavior for every existing caller."""
        import json
        clauses, params = [], []
        for col, val in (("relation", relation), ("src_kind", src_kind), ("src_id", src_id),
                          ("dst_kind", dst_kind), ("dst_id", dst_id)):
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        if limit_most_recent is not None:
            query = f"SELECT * FROM edges {where} ORDER BY timestamp DESC LIMIT ?"
            params = params + [limit_most_recent]
        else:
            query = f"SELECT * FROM edges {where} ORDER BY timestamp ASC"
        rows = self._conn.execute(query, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            except Exception:
                d["metadata"] = {}
            out.append(d)
        return out

    def get_recent_composite_trust(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Most recent cl_afpe_trust rows (composite_trust.py's own
        corroboration-accumulator table), newest-updated first -- for the
        console's Autonomy view (2026-09-15), the "still building trust"
        counterpart to get_recent_threshold_history() above and the `trusts`
        edges get_edges(relation='trusts') already exposes for "already
        resolved." Plain read; composite_trust.py itself keeps its own direct
        SQL for the corroboration-recording write path (a different module's
        job), this is just the console's read side."""
        rows = self._conn.execute(
            "SELECT * FROM cl_afpe_trust ORDER BY last_updated DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_threshold_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Most recent autotuner proposals (argus/autotune/engine.py's own
        threshold_history table), newest first -- for the console's Autonomy
        view (2026-09-15). The table is already a complete, self-explaining
        event log (old_value/new_value/reason/proposed_at/canary_until/
        promoted_at/rolled_back_at); this is a plain read, no new
        instrumentation needed. Kept here rather than as raw SQL in the router,
        matching every other table read in this class."""
        rows = self._conn.execute(
            "SELECT * FROM threshold_history ORDER BY proposed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def count_edges(self, relation: Optional[str] = None, src_kind: Optional[str] = None,
                      src_id: Optional[str] = None, dst_kind: Optional[str] = None,
                      dst_id: Optional[str] = None) -> int:
        """COUNT(*) counterpart to get_edges(), same filter columns -- lets a caller
        using limit_most_recent still report "N of TOTAL" without fetching TOTAL rows
        just to len() them (the console API's graph-view endpoint's own
        evidence_total/evidence_truncated fields)."""
        clauses, params = [], []
        for col, val in (("relation", relation), ("src_kind", src_kind), ("src_id", src_id),
                          ("dst_kind", dst_kind), ("dst_id", dst_id)):
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        row = self._conn.execute(f"SELECT COUNT(*) c FROM edges {where}", params).fetchone()
        return int(row["c"])

    def get_edges_capped_per_dst(self, dst_kind: str, dst_ids: List[str], limit_most_recent: int) -> List[Dict[str, Any]]:
        """Batched counterpart to get_edges(dst_kind=, dst_id=, limit_most_recent=)
        called in a loop -- ONE query for N dst_ids instead of N, each still capped
        to its own `limit_most_recent` most-recent edges (a window function, not a
        flat LIMIT, so one busy dst_id with thousands of edges can't crowd out a
        quiet one sharing the same query).

        Added for the console API's graph-view endpoint: with 25 decisions that used
        to mean 25 separate get_edges() calls plus 25 separate count_edges() calls
        (see count_edges_grouped_by_dst() below) -- 50 round-trips through a SQLite
        connection that's read-only against a database the main pipeline is
        concurrently, heavily writing to (WAL mode allows this without blocking, but
        Python's sqlite3 default 5s busy_timeout means each individual round-trip can
        still stall waiting for a writer's transaction/checkpoint). Confirmed live:
        the same endpoint's real response time on .94 ranged 0.96s-3.5s across
        back-to-back calls under real write load, vs 0.08s for the identical logic
        run standalone with no concurrent writer -- fewer round-trips means fewer
        chances to land inside a writer's transaction window, not just less query
        planning overhead.

        Empty dst_ids returns [] without touching the database (SQLite's `IN ()`
        with zero placeholders is invalid SQL, not just slow)."""
        import json
        if not dst_ids:
            return []
        placeholders = ",".join("?" for _ in dst_ids)
        query = f"""
            SELECT * FROM (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY dst_id ORDER BY timestamp DESC) AS rn
                FROM edges
                WHERE dst_kind = ? AND dst_id IN ({placeholders})
            )
            WHERE rn <= ?
            ORDER BY dst_id, timestamp DESC
        """
        params = [dst_kind] + list(dst_ids) + [limit_most_recent]
        rows = self._conn.execute(query, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d.pop("rn", None)
            try:
                d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            except Exception:
                d["metadata"] = {}
            out.append(d)
        return out

    def count_edges_grouped_by_dst(self, dst_kind: str, dst_ids: List[str]) -> Dict[str, int]:
        """Batched counterpart to count_edges(dst_kind=, dst_id=) called in a loop --
        see get_edges_capped_per_dst()'s own docstring for why this matters (fewer
        round-trips against a database under concurrent write load). Returns
        {dst_id: count}; a dst_id with zero matching edges is simply absent from the
        result rather than present with 0 -- callers already use dict.get(id, 0)."""
        if not dst_ids:
            return {}
        placeholders = ",".join("?" for _ in dst_ids)
        rows = self._conn.execute(
            f"SELECT dst_id, COUNT(*) c FROM edges WHERE dst_kind = ? AND dst_id IN ({placeholders}) GROUP BY dst_id",
            [dst_kind] + list(dst_ids),
        ).fetchall()
        return {r["dst_id"]: int(r["c"]) for r in rows}

    def get_destinations_by_ids(self, destination_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Batched counterpart to get_destination() called in a loop -- same
        round-trip-reduction reasoning as get_edges_capped_per_dst() above. Returns
        {destination_id: row}; a destination_id that doesn't exist is simply absent."""
        if not destination_ids:
            return {}
        placeholders = ",".join("?" for _ in destination_ids)
        rows = self._conn.execute(
            f"SELECT * FROM destinations WHERE destination_id IN ({placeholders})",
            list(destination_ids),
        ).fetchall()
        return {r["destination_id"]: dict(r) for r in rows}

    def delete_edge(self, edge_id: int) -> None:
        self._conn.execute("DELETE FROM edges WHERE edge_id = ?", (edge_id,))
        self._maybe_commit()

    # --- retention (schema.sql's own documented policy) -------------------------

    def prune_evidence(self, older_than_days: float = DEFAULT_EVIDENCE_RETENTION_DAYS,
                         now: Optional[float] = None, archive_path: Optional[Path] = None) -> int:
        """Deletes evidence older than the cutoff UNLESS referenced by a decision
        newer than the cutoff (decisions are the audit trail; keep what they point
        to) -- matches schema.sql's documented policy exactly, not a simplified
        version of it. Returns the number of rows deleted.

        BUGFIX (2026-09-07, live audit): this used to delete ONLY from the
        `evidence` table -- every evidence row's own 'observed' edge (device->
        evidence) and 'targets' edge (evidence->destination), plus any 'supports'
        edge from a decision OLDER than this cutoff but still inside the
        separate, much longer 1-year decision-retention window (schema.sql's own
        two DIFFERENT retention windows for evidence vs. decisions -- a decision
        can and does legitimately outlive its own supporting evidence by design),
        were left behind pointing at an evidence_id that no longer existed --
        genuinely dangling, not just stale. Left unbounded, this also meant the
        `edges` table itself never shrank even as `evidence` did, undermining the
        actual reason retention/pruning exists at all (A14's real runaway-growth
        incident). Now selects the evidence_ids being deleted FIRST, deletes
        every edge referencing any of them (either direction), then deletes the
        evidence rows themselves -- all inside one transaction, so a mid-failure
        can never leave edges half-cleaned relative to what evidence survived.

        archive_path (2026-09-20, data-lifecycle retuning, explicit user decision):
        None by default -- a straight delete, zero disk-growth risk, the right
        production behavior ("run forever, everything capped, no exceptions").
        Callers pass a real path ONLY under the config-gated
        archive_network_activity_backup toggle (see live_prune.py's call site),
        intended for testing/dev sessions that want a full historical record for
        incident investigation or decision-replay validation -- when given, every
        row being deleted is appended (one compact JSON object per line) to a
        gzip-compressed, size-rotated file at this path before the delete runs,
        mirroring live_decision_archive.py's existing export-then-delete shape.
        Best-effort: an archive write failure is logged and does NOT block the
        prune (losing the write-only backup copy is recoverable; leaving evidence
        unpruned indefinitely is the failure mode this method exists to prevent)."""
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        with self.transaction():
            rows = self._conn.execute(
                "SELECT * FROM evidence WHERE timestamp < ? AND evidence_id NOT IN ("
                "  SELECT src_id FROM edges WHERE src_kind = 'evidence' AND dst_kind = 'decision' "
                "  AND EXISTS (SELECT 1 FROM decisions d WHERE d.decision_id = edges.dst_id AND d.timestamp >= ?)"
                ")",
                (cutoff, cutoff),
            ).fetchall()
            if not rows:
                return 0
            evidence_ids = [r["evidence_id"] for r in rows]
            if archive_path is not None:
                _append_archive_jsonl_gz(archive_path, [dict(r) for r in rows])
            total_deleted = 0
            for chunk in _chunked(evidence_ids, _SQLITE_DELETE_BATCH_SIZE):
                placeholders = ",".join("?" * len(chunk))
                self._conn.execute(
                    f"DELETE FROM edges WHERE "
                    f"(src_kind = 'evidence' AND src_id IN ({placeholders})) OR "
                    f"(dst_kind = 'evidence' AND dst_id IN ({placeholders}))",
                    chunk + chunk,
                )
                cur = self._conn.execute(
                    f"DELETE FROM evidence WHERE evidence_id IN ({placeholders})", chunk,
                )
                total_deleted += cur.rowcount
            return total_deleted

    def prune_weak_zeek_notices(self, older_than_hours: float = DEFAULT_WEAK_ZEEK_NOTICE_RETENTION_HOURS,
                                  now: Optional[float] = None) -> int:
        """Deletes evidence_type='zeek_notice_weak' rows older than the cutoff --
        see DEFAULT_WEAK_ZEEK_NOTICE_RETENTION_HOURS's own docstring for why this
        gets its own much-shorter, tier-specific retention instead of waiting for
        prune_evidence()'s full 90-day (or hardware-profile-scaled) window. Same
        edge-cleanup-then-row-delete pattern as prune_evidence() (the ordering
        matters for the same reason -- see that method's own BUGFIX comment on
        dangling edges), just scoped to one evidence_type and hours instead of days.
        Same 'still referenced by a recent decision, keep it anyway' carve-out too --
        a decision that legitimately cited a weak notice (rare, since it contributes
        zero scoring weight, but not impossible if it showed up in a display-only
        context) shouldn't have its own audit trail invalidated by this faster
        sweep. Returns the number of rows deleted.

        BUGFIX (2026-09-20, restart-cadence investigation): also targets the
        legacy, unfragmented 'zeek_notice' type (not 'zeek_notice_weak') --
        confirmed live on .94: 215,543 rows across 21 devices, all dated to a
        narrow 10.8-13.9-day-old window matching exactly when the 2026-09-09
        tier-fragmentation fix landed (zeek_network.py now always writes
        zeek_notice_evidence_type(tier), never the bare type -- confirmed by
        reading that code directly, not assumed). This type scores nothing
        (not a member of any HYPOTHESIS_RELEVANT_EVIDENCE_TYPES set -- those
        all check for 'zeek_notice_{tier}' strings specifically) and cannot be
        newly created by any code path today, so it's pure historical debt,
        equally worthless as zeek_notice_weak and folded into the same fast
        sweep rather than waiting out prune_evidence()'s full 90-day window or
        needing a separate one-time migration script."""
        cutoff = (now if now is not None else time.time()) - older_than_hours * 3600
        with self.transaction():
            rows = self._conn.execute(
                "SELECT evidence_id FROM evidence WHERE evidence_type IN ('zeek_notice_weak', 'zeek_notice') "
                "AND timestamp < ? AND evidence_id NOT IN ("
                "  SELECT src_id FROM edges WHERE src_kind = 'evidence' AND dst_kind = 'decision' "
                "  AND EXISTS (SELECT 1 FROM decisions d WHERE d.decision_id = edges.dst_id AND d.timestamp >= ?)"
                ")",
                (cutoff, cutoff),
            ).fetchall()
            evidence_ids = [r["evidence_id"] for r in rows]
            if not evidence_ids:
                return 0
            total_deleted = 0
            for chunk in _chunked(evidence_ids, _SQLITE_DELETE_BATCH_SIZE):
                placeholders = ",".join("?" * len(chunk))
                self._conn.execute(
                    f"DELETE FROM edges WHERE "
                    f"(src_kind = 'evidence' AND src_id IN ({placeholders})) OR "
                    f"(dst_kind = 'evidence' AND dst_id IN ({placeholders}))",
                    chunk + chunk,
                )
                cur = self._conn.execute(
                    f"DELETE FROM evidence WHERE evidence_id IN ({placeholders})", chunk,
                )
                total_deleted += cur.rowcount
            return total_deleted

    def prune_device_destinations(self, older_than_days: float = DEFAULT_DEVICE_DESTINATIONS_RETENTION_DAYS,
                                    now: Optional[float] = None) -> int:
        """Deletes device_destinations rows not touched since the cutoff -- see
        schema.sql's own retention-policy comment for why this gets a shorter
        window than prune_evidence()'s 90 days. No decisions/evidence reference
        this table (it's a pure behavioral-baseline input, not part of the audit
        trail), so unlike prune_evidence() there's no "still referenced" carve-out
        to check -- last_seen < cutoff is sufficient on its own. Returns the
        number of rows deleted."""
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        cur = self._conn.execute("DELETE FROM device_destinations WHERE last_seen < ?", (cutoff,))
        self._maybe_commit()
        return cur.rowcount

    def prune_backtest_runs(self, older_than_days: float = DEFAULT_BACKTEST_RUNS_RETENTION_DAYS,
                              now: Optional[float] = None) -> int:
        """Deletes backtest_runs rows older than the cutoff (disk-retention audit
        finding: this table had ZERO deletion of any kind -- one row every night,
        forever, and unlike every other table in this schema its row size ALSO
        scales with device count via synthetic_result_json's per-device breakdown,
        making it the single largest unbounded contributor found). Pure delete, no
        archive -- these are point-in-time pass/fail snapshots, not an audit trail
        of an autonomous decision (unlike decisions/containment_actions), so
        nothing downstream needs the old rows once they've aged out.
        threshold_history.backtest_run_id references run_id "by convention" only
        (schema.sql's own comment -- no real FK), so a dangling reference after
        this prune is expected and harmless, same as every other soft-reference in
        this schema. Returns the number of rows deleted."""
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        cur = self._conn.execute("DELETE FROM backtest_runs WHERE started_at < ?", (cutoff,))
        self._maybe_commit()
        return cur.rowcount

    def prune_threshold_history(self, older_than_days: float = DEFAULT_THRESHOLD_HISTORY_RETENTION_DAYS,
                                  now: Optional[float] = None) -> int:
        """Deletes threshold_history rows older than the cutoff (disk-retention
        audit finding: pure append via propose_change(), zero deletion of any
        kind). Rows are small (no JSON blob), so this is a low-severity fix on
        raw bytes, but still a genuine "runs forever without bound" gap. A
        rolled-back-or-superseded proposal's audit value fades the same way an
        old decision's does -- same reasoning as prune_decisions_and_alerts(),
        just a much longer default window since this is the autotuner's own
        change-history record, not routine per-cycle output. Returns the number
        of rows deleted."""
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        cur = self._conn.execute("DELETE FROM threshold_history WHERE proposed_at < ?", (cutoff,))
        self._maybe_commit()
        return cur.rowcount

    def prune_stale_regime_baselines(self, older_than_days: float = DEFAULT_STALE_REGIME_RETENTION_DAYS,
                                       now: Optional[float] = None) -> int:
        """Disk-retention audit finding: device_baselines' regime_id column
        increments on every BOCPD changepoint, and schema.sql's own comment
        documents prior-regime rows as deliberately retained ("not overwritten...
        not deleted on promotion") for reset/undo traceability -- a real design
        choice, not an oversight, same category as containment_actions' own
        permanent-by-design retention. Blindly deleting every non-current regime
        would break that stated undo capability for a REGIME CHANGE THAT JUST
        HAPPENED. This only removes a (device, metric, hour) bucket's old-regime
        rows once they're BOTH superseded (not this bucket's current max
        regime_id) AND old (updated_at before the cutoff) -- recent undo history
        survives regardless of regime, and the current regime is never touched.
        Returns the number of rows deleted."""
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        cur = self._conn.execute(
            "DELETE FROM device_baselines WHERE updated_at < ? AND regime_id < ("
            "  SELECT MAX(regime_id) FROM device_baselines db2 WHERE "
            "  db2.device_id = device_baselines.device_id AND db2.metric = device_baselines.metric "
            "  AND db2.hour = device_baselines.hour"
            ")",
            (cutoff,),
        )
        self._maybe_commit()
        return cur.rowcount

    def prune_stale_regime_trust(self, older_than_days: float = DEFAULT_STALE_REGIME_RETENTION_DAYS,
                                   now: Optional[float] = None) -> int:
        """Same shape and same reasoning as prune_stale_regime_baselines(), for
        cl_afpe_trust's own regime_id-keyed rows -- only removes a tuple's
        old-regime rows once BOTH superseded and old; the current regime and any
        recent history survive untouched, preserving reset_tuple()'s undo
        capability for anything not already this stale. Returns the number of
        rows deleted."""
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        cur = self._conn.execute(
            "DELETE FROM cl_afpe_trust WHERE last_updated < ? AND regime_id < ("
            "  SELECT MAX(regime_id) FROM cl_afpe_trust t2 WHERE "
            "  t2.device_id = cl_afpe_trust.device_id AND t2.behavior_fingerprint = cl_afpe_trust.behavior_fingerprint "
            "  AND t2.destination_class = cl_afpe_trust.destination_class AND t2.hypothesis_id = cl_afpe_trust.hypothesis_id "
            "  AND t2.evidence_family = cl_afpe_trust.evidence_family"
            ")",
            (cutoff,),
        )
        self._maybe_commit()
        return cur.rowcount

    # --- disk-budget governor (2026-09-23): a size-driven backstop on top of the -----
    # age-based retention above. Age-based windows (prune_evidence/
    # prune_decisions_and_alerts) are the PRIMARY mechanism and stay unchanged --
    # they're what keeps this running forever at a roughly steady size. But "roughly
    # steady" still scales with device count and traffic pattern, which a single
    # fixed day-count can't guarantee stays under an explicit hard disk ceiling for
    # every installation (50 devices vs 100, light vs heavy traffic) -- exactly the
    # "network/installation agnostic" concern this project treats as a standing
    # design requirement. These methods let disk_budget_governor.py measure the
    # REAL on-disk size and, only if it's still over budget after the normal daily
    # prune already ran, shrink further by directly targeting "the oldest N rows
    # still past an absolute safety floor" rather than guessing a day-count that
    # happens to fit -- self-correcting against reality instead of an estimate.

    def get_disk_usage_bytes(self) -> Dict[str, int]:
        """Real on-disk bytes for the main db file + its WAL (self.db_path is the
        main file's path; the WAL sits alongside it as db_path + "-wal"). This is
        what disk_budget_governor.py measures against a configured ceiling --
        row-count-based estimates can't account for SQLite's own overhead, index
        size, or (critically) the fact that DELETE alone never shrinks the file,
        only VACUUM/incremental_vacuum does."""
        main_path = Path(self.db_path)
        wal_path = main_path.with_name(main_path.name + "-wal")
        main_bytes = main_path.stat().st_size if main_path.exists() else 0
        wal_bytes = wal_path.stat().st_size if wal_path.exists() else 0
        return {"main_bytes": main_bytes, "wal_bytes": wal_bytes, "total_bytes": main_bytes + wal_bytes}

    def enable_incremental_vacuum(self) -> bool:
        """One-time conversion to auto_vacuum=INCREMENTAL (mode 2). SQLite requires
        a full VACUUM to actually change an existing database's auto_vacuum mode --
        a no-op (returns False immediately) if already incremental, so this is safe
        to call every governor run without repeating the conversion. Deliberately
        NOT called automatically by anything in this codebase yet -- see
        disk_budget_governor.py's own module docstring for why a human decides
        when to run this the first time on an existing, populated database (the
        one-time conversion VACUUM briefly locks the whole file, unlike the small
        bounded incremental_vacuum_step() calls this unlocks going forward)."""
        current_mode = self._conn.execute("PRAGMA auto_vacuum").fetchone()[0]
        if current_mode == 2:
            return False
        self._conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        self._conn.execute("VACUUM")
        return True

    def checkpoint_wal_truncate(self) -> bool:
        """TRUNCATE-mode checkpoint: unlike checkpoint_wal()'s own PASSIVE mode
        (safe for the long-lived live_engine.py singleton to call every cycle),
        TRUNCATE actually shrinks the WAL file back down after moving its
        content into the main db file -- real disk-usage reduction, not just
        page reuse within the WAL. Found genuinely necessary, not speculative:
        .94's real WAL was measured at 805MB (almost as large as the 1.06GB main
        file) during this same audit -- PASSIVE checkpoints alone don't bound
        WAL growth under sustained write load. Needs no conflicting reader/
        writer holding the WAL to fully truncate; degrades to a partial/no-op
        checkpoint (never raises, never blocks past this connection's own
        busy_timeout) if one is -- meant for a short-lived connection
        (disk_budget_governor.py's own), not the long-lived singleton, which
        stays on the cheaper PASSIVE mode. Returns True if it completed without
        a busy/locked result."""
        try:
            row = self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            # row is (busy, log_pages, checkpointed_pages) -- busy=0 means it fully succeeded
            return bool(row) and row[0] == 0
        except Exception as e:
            LOGGER.warning("WAL truncate-checkpoint failed for %r (non-fatal): %s", self.db_path, e)
            return False

    def incremental_vacuum_step(self, pages: int = 2000) -> int:
        """Reclaims up to `pages` freed pages back to the OS (shrinking the file
        on disk), one small bounded step at a time -- unlike a full VACUUM, this
        never rewrites the whole database, so it can run every governor cycle
        without the freeze risk a full VACUUM carries on a live singleton
        connection. No-op (returns 0) if auto_vacuum isn't INCREMENTAL yet, or if
        there's nothing left to reclaim. Returns the free-list page count
        remaining AFTER this step (0 means fully reclaimed for now)."""
        if self._conn.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
            return 0
        # PRAGMA statements don't support "?" parameter binding -- `pages` is an
        # internal int (never user/network input), safe to inline directly.
        self._conn.execute(f"PRAGMA incremental_vacuum({int(pages)})")
        self._maybe_commit()
        remaining = self._conn.execute("PRAGMA freelist_count").fetchone()[0]
        return remaining

    def get_decisions_batch_cutoff(self, batch_size: int, min_age_days: float,
                                     now: Optional[float] = None) -> Optional[float]:
        """Returns the timestamp of the batch_size-th oldest decision that's still
        older than min_age_days (the absolute safety floor -- never eligible for
        budget-driven trimming regardless of how far over budget the db is), or
        None if fewer than batch_size such rows exist. Feed the result into
        prune_decisions_and_alerts(older_than_days=(now-result)/86400) to actually
        delete that batch, reusing its existing, already-tested FK-safe cascade
        rather than duplicating it here."""
        floor_cutoff = (now if now is not None else time.time()) - min_age_days * 86400
        row = self._conn.execute(
            "SELECT timestamp FROM decisions WHERE timestamp < ? ORDER BY timestamp ASC LIMIT 1 OFFSET ?",
            (floor_cutoff, max(0, batch_size - 1)),
        ).fetchone()
        return row["timestamp"] if row else None

    def get_evidence_batch_cutoff(self, batch_size: int, min_age_days: float,
                                    now: Optional[float] = None) -> Optional[float]:
        """Same shape as get_decisions_batch_cutoff(), for evidence -- feed the
        result into prune_evidence(older_than_days=...) to actually delete,
        reusing its existing "still referenced by a recent decision" carve-out."""
        floor_cutoff = (now if now is not None else time.time()) - min_age_days * 86400
        row = self._conn.execute(
            "SELECT timestamp FROM evidence WHERE timestamp < ? ORDER BY timestamp ASC LIMIT 1 OFFSET ?",
            (floor_cutoff, max(0, batch_size - 1)),
        ).fetchone()
        return row["timestamp"] if row else None

    def prune_decisions_and_alerts(self, older_than_days: float = DEFAULT_DECISION_RETENTION_DAYS,
                                     now: Optional[float] = None) -> Dict[str, int]:
        """Deletes decisions (and everything the alert-trace graph hangs off
        them -- operator_actions, alert_events, hypothesis/evidence edges
        pointing at the decision) older than the cutoff.

        Found genuinely necessary, not speculative: no prune_decisions() of any
        kind existed in this file before this method -- schema.sql documents a
        "1 year (180 days pi_8gb), then archived" policy that was never actually
        enforced (confirmed by grep before writing this), so decisions grew
        unbounded (45,650+ rows and still growing, .94's real deployment).
        alert_events shares this SAME retention window rather than getting its
        own clock, because an alert_event without its parent decision is
        meaningless -- see Documentation/ALERT_TRACE_GRAPH_PLAN.md's "Bounded
        growth" section.

        FK-safe delete order (PRAGMA foreign_keys = ON, so children must go
        first): operator_actions -> alert_events -> hypothesis/evidence edges
        referencing the decision -> the decision row itself. containment_actions
        rows are NEVER deleted here (schema.sql's own documented policy: "no
        automated retention yet... row count is inherently small" -- a hardware
        block is real audit history independent of how long the decision that
        triggered it is kept) -- instead their decision_id/alert_event_id FKs are
        nulled so the row survives detached, the same pattern already used for
        merged-device tombstoning elsewhere in this file. incidents are cleaned
        up last, only once NO alert_event references them any more (an incident
        can legitimately span both sides of the cutoff while it's still being
        pruned incrementally). Returns a dict of per-table deleted counts."""
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        deleted = {"decisions": 0, "alert_events": 0, "operator_actions": 0, "edges": 0, "incidents": 0}
        with self.transaction():
            decision_rows = self._conn.execute(
                "SELECT decision_id FROM decisions WHERE timestamp < ?", (cutoff,),
            ).fetchall()
            if not decision_rows:
                return deleted
            decision_ids = [r["decision_id"] for r in decision_rows]

            for chunk in _chunked(decision_ids, _SQLITE_DELETE_BATCH_SIZE):
                placeholders = ",".join("?" * len(chunk))

                alert_event_rows = self._conn.execute(
                    f"SELECT alert_event_id FROM alert_events WHERE decision_id IN ({placeholders})", chunk,
                ).fetchall()
                alert_event_ids = [r["alert_event_id"] for r in alert_event_rows]
                for ae_chunk in _chunked(alert_event_ids, _SQLITE_DELETE_BATCH_SIZE):
                    ae_placeholders = ",".join("?" * len(ae_chunk))
                    cur = self._conn.execute(
                        f"DELETE FROM operator_actions WHERE alert_event_id IN ({ae_placeholders})", ae_chunk,
                    )
                    deleted["operator_actions"] += cur.rowcount
                    self._conn.execute(
                        f"UPDATE containment_actions SET alert_event_id = NULL "
                        f"WHERE alert_event_id IN ({ae_placeholders})", ae_chunk,
                    )
                    cur = self._conn.execute(
                        f"DELETE FROM alert_events WHERE alert_event_id IN ({ae_placeholders})", ae_chunk,
                    )
                    deleted["alert_events"] += cur.rowcount

                self._conn.execute(
                    f"UPDATE containment_actions SET decision_id = NULL WHERE decision_id IN ({placeholders})",
                    chunk,
                )
                cur = self._conn.execute(
                    f"DELETE FROM edges WHERE "
                    f"(src_kind = 'decision' AND src_id IN ({placeholders})) OR "
                    f"(dst_kind = 'decision' AND dst_id IN ({placeholders}))",
                    chunk + chunk,
                )
                deleted["edges"] += cur.rowcount
                cur = self._conn.execute(
                    f"DELETE FROM decisions WHERE decision_id IN ({placeholders})", chunk,
                )
                deleted["decisions"] += cur.rowcount

            cur = self._conn.execute(
                "DELETE FROM incidents WHERE incident_id NOT IN "
                "(SELECT DISTINCT incident_id FROM alert_events WHERE incident_id IS NOT NULL)"
            )
            deleted["incidents"] = cur.rowcount
        return deleted

    def prune_orphaned_device_baselines(self) -> int:
        """Deletes device_baselines rows whose device_id has since been merged
        away (devices.merged_into_device_id IS NOT NULL) -- the concrete
        cleanup half of the 2026-09-20 identity-merge handover's
        device_baselines 89-vs-13-device_id anomaly. Root cause (see
        argus/baseline/engine.py's own resolve-at-entry fix, landed the same
        day): every device_baselines row used to be written under whatever
        device_id happened to be live AT THE TIME, with no merge awareness --
        an orphan that existed even briefly before merging into a richer
        canonical identity got its own permanent, invisible-to-canonical row.
        That fix stops NEW stray rows from accumulating; this method cleans up
        rows that already exist from before it shipped.

        Deliberately does NOT touch threshold_history (argus/autotune/engine.py's
        table) -- unlike baselines, a merged device's threshold_history rows
        are DELIBERATELY still treated as live (get_active_value() now
        resolves across every id that ever merged into a canonical, per this
        session's own explicit "a tuned threshold, unlike a statistical
        estimator, should carry forward" decision) -- deleting them here would
        silently regress that fix, reverting a genuinely-still-active
        promoted threshold back to its parent tier's default.

        Safe to call repeatedly (an already-clean state_baselines table has
        nothing matching the join and is a fast no-op). Runs a single indexed
        DELETE, not a full table scan -- device_baselines has no dedicated
        index on merged-device lookups, but the number of ever-merged
        device_ids is small (device count, not evidence-row count) relative
        to device_baselines' own likely row count, so the subquery itself is
        cheap regardless."""
        cur = self._conn.execute(
            "DELETE FROM device_baselines WHERE device_id IN "
            "(SELECT device_id FROM devices WHERE merged_into_device_id IS NOT NULL)"
        )
        self._maybe_commit()
        return cur.rowcount

    # --- decision archival -------------

    def get_decisions_older_than(self, days: float, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Read-only: decisions older than the cutoff, same parsed shape as
        get_decisions_since(). Matches schema.sql's own documented policy
        ("decisions: kept 1 year, then archived (exported, not deleted)").
        Deliberately kept as a SEPARATE step from delete_decisions() below
        (not one atomic archive-and-delete method) -- live_decision_archive.py's
        own export-then-delete ordering means nothing is ever removed from the
        live graph until the export write to disk has actually succeeded, so a
        failed export can never silently lose a decision."""
        cutoff = (now if now is not None else time.time()) - days * 86400
        rows = self._conn.execute(
            "SELECT * FROM decisions WHERE timestamp < ? ORDER BY timestamp", (cutoff,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["raw_payload"] = json.loads(d.pop("raw_payload_json") or "{}")
            d["mechanism_flags"] = json.loads(d.pop("mechanism_flags_json") or "{}")
            out.append(d)
        return out

    def delete_decisions(self, decision_ids: List[str]) -> int:
        """Deletes the given decisions AND their own 'supports' edges (so
        nothing is left dangling at a decision_id that no longer exists).
        Callers MUST have already durably exported these rows first -- this
        method has no knowledge of whether that happened, by design; the
        export-then-delete ordering is the caller's own responsibility (see
        get_decisions_older_than()'s own docstring)."""
        if not decision_ids:
            return 0
        placeholders = ",".join("?" * len(decision_ids))
        self._conn.execute(
            f"DELETE FROM edges WHERE dst_kind = 'decision' AND dst_id IN ({placeholders})", decision_ids,
        )
        cur = self._conn.execute(
            f"DELETE FROM decisions WHERE decision_id IN ({placeholders})", decision_ids,
        )
        self._maybe_commit()
        return cur.rowcount


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _append_archive_jsonl_gz(archive_path: Path, rows: List[Dict[str, Any]]) -> None:
    """Appends `rows` (already plain dicts, one JSON object per line) to a
    gzip-compressed file at archive_path, creating its parent directory and the
    file itself if either doesn't exist yet. Used only by prune_evidence()'s
    optional archive_network_activity_backup path (2026-09-20) -- deliberately
    NOT a general-purpose archive utility, just enough to mirror
    live_decision_archive.py's export-then-delete shape for evidence too. Opens
    in append (binary) mode each call rather than holding a handle open across
    the caller's own transaction() -- this runs once per scheduled prune, not
    per-row, so the extra open/close cost is irrelevant. Best-effort by design
    (see prune_evidence()'s own docstring for why a failure here must not block
    the actual prune): callers are expected to wrap this in try/except."""
    import gzip
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(archive_path, "at", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, default=str))
            f.write("\n")
