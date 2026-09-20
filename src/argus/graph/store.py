"""
v13 EvidenceGraph SQLite store (Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).
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
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from argus.evidence.model import Evidence, NO_DESTINATION
from utils import is_local_or_multicast_destination

LOGGER = logging.getLogger("home_ids.graph_store")

_SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

# Matches schema.sql's own documented policy (comment at the bottom of that file).
# v13 full-architecture plan, Phase 10b: evidence retention itself is now
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
# ZEEK_NOTICE_TIER_SCORE_WEIGHT["weak"] == 0.0, v13/hypotheses/engine.py's
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

# v13 full-architecture plan, Phase 10b: SQLite PRAGMA cache_size (negative = KB,
# per SQLite's own docs), sized against config/trust_anchors.py's own
# VALID_HARDWARE_PROFILES. A first-pass judgment call (this project's own
# established convention for a not-yet-empirically-tuned number, matching
# INDEPENDENCE_FAMILY_MAP's own "honest status" framing) -- SQLite's own default is
# -2000 (2MB); pi_8gb gets a modest bump given this box also runs Zeek/Suricata/
# Ollama concurrently (see this file's own "Hardware topology" section in
# V13_ARCHITECTURE_DEPENDENCY_MAP.md), x86_16gb/custom get more headroom to spend on
# graph query performance since nothing else on that box is as resource-constrained.
_HARDWARE_PROFILE_CACHE_SIZE_KB: Dict[str, int] = {
    # 2026-09-10 (AUDIT_V14_REVIEW_RESPONSE.md §2.2): 4MB was closer to SQLite's own
    # 2MB default than a real cache for a WAL-enabled graph db this box also runs
    # Zeek/Suricata/Ollama concurrently against. 48MB is still a conservative,
    # not-empirically-tuned first-pass bump (same honesty framing as the edge-cap
    # constant below) -- there's no real Pi-8GB hardware to measure against yet
    # (V13_ARCHITECTURE_DEPENDENCY_MAP.md's own hardware-topology note), so this
    # should be re-tuned with real iostat/RSS numbers once that hardware exists,
    # not treated as a final answer either direction.
    "pi_8gb": 48_000,
    "x86_16gb": 16_000,
    "custom": 16_000,
}

# v13 full-architecture plan, alert/decision unification, Phase 1 (write-side edge
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


def _chunked(seq: List[Any], size: int):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


class GraphStore:
    def __init__(self, db_path: str, hardware_profile: Optional[str] = None):
        self.db_path = db_path
        self._hardware_profile = hardware_profile
        is_new = not Path(db_path).exists()
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
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
        self._conn.execute("PRAGMA synchronous = NORMAL")
        # Phase 10b: optional -- omitting hardware_profile (every pre-existing
        # caller, including every test) leaves SQLite's own default cache_size
        # untouched, identical to this class's behavior before this param existed.
        cache_kb = _HARDWARE_PROFILE_CACHE_SIZE_KB.get(hardware_profile or "")
        if cache_kb is not None:
            self._conn.execute(f"PRAGMA cache_size = -{cache_kb}")
        self._in_transaction = False
        if is_new:
            self._apply_schema()
        else:
            # v13 full-architecture plan, IPS containment unification: schema.sql
            # is ONLY ever executescript()'d for a brand-new db file (`is_new`
            # above) -- an EXISTING db (e.g. .94's real, already-populated
            # state/v13_graph.db) never re-runs it, so a table added to schema.sql
            # after a deployment's first run would never actually reach that
            # deployment. containment_actions' own CREATE TABLE/INDEX statements
            # already use IF NOT EXISTS specifically so this lightweight migration
            # step is safe to run unconditionally here too -- a no-op on a db that
            # already has it (including a freshly-created one, which already got it
            # via _apply_schema() above), the actual migration on one that doesn't.
            self._migrate_existing_db()

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

            CREATE INDEX IF NOT EXISTS idx_evidence_type_ts ON evidence(evidence_type, timestamp);

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
            """
        )
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
        self._conn.close()

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
                "UPDATE devices SET last_seen = ?, "
                "display_label = COALESCE(?, display_label), "
                "device_type = COALESCE(?, device_type) "
                "WHERE device_id = ?",
                (ts, display_label, device_type, device_id),
            )
        self._maybe_commit()

    def update_device_metadata(self, device_id: str, updates: Dict[str, Any],
                                 timestamp: Optional[float] = None) -> None:
        """Merges `updates` into a device's metadata_json (shallow -- top-level keys in
        `updates` overwrite the same key in the existing dict, everything else is left
        alone). Auto-upserts the device row first, so this is safe to call for a
        device_id that hasn't been seen via insert_evidence()/insert_decision() yet
        (v13 full-architecture plan, Phase 3 -- used to persist a trust anchor's
        learned MAC, surviving restarts, unlike v-current's own single in-memory
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

    def resolve_canonical_device_id(self, device_id: str) -> str:
        """Walks the merged_into_device_id chain to the ultimate canonical id.
        Unlike v-current's merge_into_canonical() (state_guard.py), an orphan's row
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
        """Audit-preserving merge -- a deliberate improvement over v-current's
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
        continue, never blocking the real v1 merge that already happened) -- so
        refusing here is safe: it just skips the graph-side mirror for this one
        conflicting call, exactly like any other best-effort graph write failure,
        rather than silently corrupting the merge chain into an infinite loop."""
        if orphan_id == canonical_id:
            raise ValueError("cannot merge a device into itself")
        try:
            resolved_canonical = self.resolve_canonical_device_id(canonical_id)
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
        self.upsert_device(orphan_id, timestamp=ts)
        self.upsert_device(canonical_id, timestamp=ts)
        self._conn.execute(
            "UPDATE devices SET merged_into_device_id = ? WHERE device_id = ?",
            (canonical_id, orphan_id),
        )
        self.add_edge("device", orphan_id, "device", canonical_id, "merged_into", ts)
        self._maybe_commit()

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
            self._conn.execute("UPDATE destinations SET last_seen = ? WHERE destination_id = ?", (ts, destination_id))
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
        # registry (schema.sql) -- not yet populated by any v13 module (a
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

        evidence_ids (Phase 1 fix, v13 full-architecture plan): the evidence_id of
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
        for eid in capped_evidence_ids:
            self.add_edge("evidence", eid, "decision", decision_id, "supports", timestamp)
        self._maybe_commit()
        return decision_id

    def update_decision_payload(self, decision_id: str, updates: Dict[str, Any],
                                  timestamp: Optional[float] = None) -> bool:
        """v13 full-architecture plan, alert/decision unification (Phase 2): merges
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
        matching every other v13 graph write's own fail-safe convention documented
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

    # --- containment actions (v13 full-architecture plan, IPS unification) -----

    def insert_containment_action(self, device_id: str, action_type: str, status: str,
                                    timestamp: Optional[float] = None, target: Optional[str] = None,
                                    decision_id: Optional[str] = None, reason: Optional[str] = None,
                                    metadata: Optional[Dict[str, Any]] = None) -> str:
        """Write-only AUDIT MIRROR of a real containment action already taken by
        src/mitigation/ips.py (Pi-hole block, Scapy tarpit, Fritz!Box router
        isolation, or a retry/dead-letter bookkeeping event) -- this method NEVER
        decides or performs the real action, it only records that ips.py already
        did, immediately after ips.py's own StateManager-backed dict write. Callers
        must treat this as best-effort (wrap in try/except at the call site,
        matching every other v13 graph write's own fail-safe convention) -- a
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
        pure-per-cycle evaluation model every v13 Hypothesis.evaluate() (Phase 3)
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

        out: List[Evidence] = []
        for evidence_type in types:
            per_type_query = (
                f"SELECT * FROM evidence WHERE device_id IN ({placeholders}) AND evidence_type = ?"
            )
            per_type_params: List[Any] = list(device_ids) + [evidence_type]
            if since is not None:
                per_type_query += " AND timestamp >= ?"
                per_type_params.append(since)
            per_type_query += " ORDER BY timestamp DESC LIMIT ?"
            per_type_params.append(cap_per_type)
            rows = self._conn.execute(per_type_query, per_type_params).fetchall()
            out.extend(Evidence.from_row(dict(r)) for r in rows)
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
        ids = [canonical_id]
        rows = self._conn.execute(
            "SELECT device_id FROM devices WHERE merged_into_device_id = ?", (canonical_id,)
        ).fetchall()
        for r in rows:
            ids.extend(self._all_ids_resolving_to(r["device_id"]))
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
        `since` -- v13 full-architecture plan, Phase 1a: the real, cheap
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
        fp_engine.py's confirmed-intel store before that store got this exact guard
        (see is_local_or_multicast_destination()'s own docstring). Without this,
        CoordinatedTargetingHypothesis (hypotheses/engine.py) scores ordinary mDNS/
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

    def get_evidence_by_type_since(self, evidence_type: str, since: float) -> List[Evidence]:
        """All evidence of one type across EVERY device since `since` -- unlike
        get_evidence_for_device(), deliberately not scoped to one device. DGA-seed
        correlation (Release 14, N4) needs this raw cross-device fetch because it
        groups by a COMPUTED shape key (live_engine.py's own _dga_shape_key()),
        not a single stored value get_devices_sharing_provenance() could match on
        directly -- the grouping happens in Python after this fetch."""
        rows = self._conn.execute(
            "SELECT * FROM evidence WHERE evidence_type = ? AND timestamp >= ?",
            (evidence_type, since),
        ).fetchall()
        return [Evidence.from_row(dict(r)) for r in rows]

    def get_devices_with_metadata_value(self, key: str, value: Any) -> List[str]:
        """Release 14, N2 (peer-cohort behavioral baselining): all device_ids
        whose metadata_json[key] == value -- a full table scan, parsed in
        Python rather than a SQLite json_extract() query, deliberately, so this
        doesn't depend on the JSON1 extension being available in every
        deployment's SQLite build (the same reasoning every other v13 metadata
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
        need a second write path."""
        ts = timestamp if timestamp is not None else time.time()
        if not destination_ids:
            return
        self.upsert_device(device_id, timestamp=ts)
        for dest_id in destination_ids:
            if not dest_id or dest_id == NO_DESTINATION:
                continue
            dest_kind = "ip" if _looks_like_ip(dest_id) else "domain"
            self.upsert_destination(dest_id, dest_kind, timestamp=ts)
            self._conn.execute(
                "INSERT INTO device_destinations (device_id, destination_id, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(device_id, destination_id) DO UPDATE SET last_seen = excluded.last_seen",
                (device_id, dest_id, ts, ts),
            )
        self._maybe_commit()

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
        (v13 full-architecture plan, Phase 1a: network-wide reputation
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
        against freshly-updated threat intel, replacing v-current's
        load_historical_domains()'s flat-file JSONL scan with a direct graph query."""
        rows = self._conn.execute(
            "SELECT DISTINCT device_id, destination_id FROM evidence "
            "WHERE timestamp >= ? AND destination_id != '(none)'",
            (since,),
        ).fetchall()
        return [(r["device_id"], r["destination_id"]) for r in rows]

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

    def get_latest_decision_for_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Release 15, closed-loop autotuning architecture: the no-learning-
        during-an-incident gate (Design Invariant 06) needs a device's
        CURRENT state, not a windowed query -- one row, newest first, backed
        by idx_decisions_device_ts so this is an index-order scan, not a
        table sort. Returns None for a device with no decision history yet
        (treated as BENIGN/no gate by callers, never as an error)."""
        row = self._conn.execute(
            "SELECT * FROM decisions WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1",
            (device_id,),
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

    def get_recent_decisions(self, limit: int) -> List[Dict[str, Any]]:
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
        full-table sort."""
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
        was merged into a canonical device_id shouldn't double-list alongside it."""
        rows = self._conn.execute(
            """
            SELECT d.device_id, d.display_label, d.device_type, d.first_seen, d.last_seen,
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
        return [dict(r) for r in rows]

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

    # --- decision archival (v13 full-architecture plan, Phase 10a) -------------

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
