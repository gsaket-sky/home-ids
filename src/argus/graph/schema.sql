-- argus EvidenceGraph SQLite schema (design pass, Phase 0 -- see
-- Documentation/ARGUS_AUTONOMY_DEPENDENCY_MAP.md). This file documents the design;
-- graph/store.py (Phase 1) is the actual read/write API built on top of it. Answers
-- HEE_ROADMAP.md item 4's storage objection directly: a real embedded database with
-- indexes and an explicit retention policy, not another unbounded hand-rolled JSON
-- file with its own ad-hoc TTL logic (the exact failure shape Gap 6 traced its own
-- root cause to).
--
-- Design principles carried over from the plan:
--   1. Identity merges are audit-preserving (a tombstoned device row + a
--      merged_into edge), not discard-on-merge like today's
--      state_guard.py:merge_into_canonical() -- a deliberate improvement, not a
--      silent behavior change.
--   2. independence_family lives on evidence itself, separate from `type` -- the
--      core design correction (Phase 64's postmortem): relevance-for-scoring and
--      independence-for-corroboration are different concepts and must never be
--      read from the same column.
--   3. Every Hypothesis.evaluate() still takes a fresh per-cycle snapshot -- this
--      schema is queried, never held as a mutated in-memory object across cycles,
--      preserving the pure-evaluation model HEE_ROADMAP.md said not to break.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;  -- concurrent readers (comparator job) + one writer (ingest), without lock contention

-- One row per canonical device. Orphans from an identity merge are NEVER deleted --
-- tombstoned via merged_into_device_id, so every evidence/edge row that pointed at
-- the orphan keeps resolving through it. Contrast with today's
-- merge_into_canonical(), which discards the orphan's state entirely
-- (state_guard.py:436-439) -- this is a deliberate, called-out improvement.
CREATE TABLE devices (
    device_id           TEXT PRIMARY KEY,
    display_label       TEXT,
    device_type         TEXT,
    first_seen          REAL NOT NULL,
    last_seen           REAL NOT NULL,
    merged_into_device_id TEXT REFERENCES devices(device_id),
    metadata_json        TEXT NOT NULL DEFAULT '{}'  -- known_ips, mac, dhcp_fingerprint, etc.
);
CREATE INDEX idx_devices_merged_into ON devices(merged_into_device_id) WHERE merged_into_device_id IS NOT NULL;

-- One row per distinct domain/IP ever targeted. Reputation tier is a cache (the
-- authoritative source stays whatever live reputation classifier argus wires in) --
-- refreshed on read if stale, never trusted blindly past its own TTL.
CREATE TABLE destinations (
    destination_id      TEXT PRIMARY KEY,  -- normalized domain or IP string
    kind                TEXT NOT NULL CHECK (kind IN ('domain', 'ip')),
    first_seen          REAL NOT NULL,
    last_seen           REAL NOT NULL,
    reputation_tier_cache INTEGER,
    reputation_cached_at REAL,
    metadata_json        TEXT NOT NULL DEFAULT '{}'  -- ASN/owner, cloud/CDN flag, etc.
);

-- One row per Evidence item. domain/dest_ip attribution is MANDATORY -- fixes
-- reviewer #17 (_select_target_domain()'s heuristic) at the root: no evidence can
-- exist without a target, so a per-signature override chain is never needed. Use
-- the sentinel destination_id '(none)' (a real row, always present, seeded below)
-- for the rare evidence type that is genuinely not destination-shaped -- never NULL,
-- so "no target" is a explicit, queryable fact instead of an absent column.
CREATE TABLE evidence (
    evidence_id          TEXT PRIMARY KEY,
    device_id            TEXT NOT NULL REFERENCES devices(device_id),
    destination_id        TEXT NOT NULL REFERENCES destinations(destination_id),
    evidence_type         TEXT NOT NULL,       -- e.g. 'dns_tunnel_v2', 'malicious_ja3'
    independence_family   TEXT NOT NULL,       -- separate axis from evidence_type -- see INDEPENDENCE_FAMILY_MAP
    value                REAL,
    confidence           REAL NOT NULL DEFAULT 1.0,
    timestamp            REAL NOT NULL,
    source               TEXT NOT NULL,        -- detector module that produced it
    provenance           TEXT NOT NULL DEFAULT '',
    features_json         TEXT NOT NULL DEFAULT '{}'  -- raw feature values, for audit/replay
);
CREATE INDEX idx_evidence_device_ts ON evidence(device_id, timestamp);
CREATE INDEX idx_evidence_destination ON evidence(destination_id);
CREATE INDEX idx_evidence_family ON evidence(independence_family);
-- Supports prune_weak_zeek_notices()'s type+timestamp filter (and any other
-- type-scoped query) without a full table scan -- added alongside that method,
-- explicit user request, 2026-09-09, after confirming live that zeek_notice
-- evidence was 98.3% of this table's total rows on .94's real graph.
CREATE INDEX idx_evidence_type_ts ON evidence(evidence_type, timestamp);
CREATE INDEX idx_evidence_device_type_ts ON evidence(device_id, evidence_type, timestamp);

-- Named hypothesis catalog (NETWORK_INTRUSION, DGA_BOTNET_C2, DEVICE_PROFILE_TELEMETRY,
-- ...). `version` mirrors this codebase's existing VALIDATOR_SCHEMA_VERSION pattern
-- (ai_soc.py) -- bump it whenever a hypothesis's own relevant-evidence/independence
-- definition changes, so historical decisions can be read back against the
-- definition that was actually live when they were made, not today's.
CREATE TABLE hypotheses (
    hypothesis_id        TEXT PRIMARY KEY,     -- e.g. 'NETWORK_INTRUSION'
    kind                 TEXT NOT NULL CHECK (kind IN ('attack', 'benign')),
    version               INTEGER NOT NULL DEFAULT 1
);

-- One row per decision cycle's verdict for a device. mechanism_flags_json records
-- which argus mechanisms were shadow vs. live AT THE TIME -- essential for the
-- automated incremental-flip design: a divergence found after a mechanism flipped
-- live means something different than one found while it was still shadow-only.
CREATE TABLE decisions (
    decision_id           TEXT PRIMARY KEY,
    device_id             TEXT NOT NULL REFERENCES devices(device_id),
    timestamp             REAL NOT NULL,
    winning_hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
    state                 TEXT NOT NULL,        -- BENIGN | ANOMALOUS | SUSPICIOUS | HIGH | CRITICAL
    decision_path         TEXT,                  -- hard_stop | tier5_confirmed | hypothesis_high | ...
    confidence            REAL,
    risk_score            REAL,
    mechanism_flags_json   TEXT NOT NULL DEFAULT '{}',
    raw_payload_json        TEXT NOT NULL DEFAULT '{}'  -- full decision detail, for the comparator/divergence log
);
CREATE INDEX idx_decisions_device_ts ON decisions(device_id, timestamp);
-- Global "most recent N decisions across all devices" (the console's Evidence
-- Graph tab) can't use idx_decisions_device_ts above -- that index is scoped
-- per-device. Without this, ORDER BY timestamp DESC LIMIT N on the whole table
-- forces a full scan+sort every time the tab loads.
CREATE INDEX idx_decisions_timestamp ON decisions(timestamp);

-- IPS containment unification: a write-only AUDIT
-- MIRROR of src/mitigation/ips.py's real containment state (StateManager's own
-- ips_state dict stays the live, synchronous, hot-path source of truth -- the
-- actuator logic and its cooldown/retry-queue bookkeeping all need that fast,
-- every cycle, and are NOT replaced by this table). A dedicated table rather
-- than the generic `edges` table below, matching this file's own established
-- "generic edges + dedicated concept tables" split (same shape as `decisions`):
-- containment actions have real structured, UPDATEABLE fields (status
-- transitions, release time) that edges' append-only, CHECK-constrained
-- `relation` column doesn't support without its own migration anyway.
CREATE TABLE IF NOT EXISTS containment_actions (
    action_id       TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL REFERENCES devices(device_id),
    decision_id     TEXT REFERENCES decisions(decision_id),
    -- Alert-trace graph (2026-09-22): links this action to the specific alert_event
    -- that caused it -- a real FK instead of the timestamp/device-proximity guess
    -- that was the only option before alert_events existed. Forward reference to a
    -- table defined later in this file is fine -- SQLite resolves REFERENCES by
    -- name at enforcement time, not CREATE TABLE time.
    alert_event_id   TEXT REFERENCES alert_events(alert_event_id),
    action_type     TEXT NOT NULL CHECK (action_type IN
                       ('dns_block','tarpit','router_isolate','release','retry','dead_letter')),
    target          TEXT,               -- domain or MAC, whichever action_type implies
    status          TEXT NOT NULL,      -- active|released|failed|retrying
    reason          TEXT,
    timestamp       REAL NOT NULL,
    released_at     REAL,
    metadata_json   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_containment_device ON containment_actions(device_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_containment_status ON containment_actions(status);

-- Real per-device traffic reality, independent of whether any evidence was ever
-- created for a given destination (external architecture review, 2026-09-09; see
-- graph/store.py's get_distinct_destination_count() own BUGFIX comment for the full
-- incident). That method used to query the `evidence` table -- which only ever has a
-- row when SOME detector already flagged something notable -- as a proxy for "how
-- many destinations has this device really talked to," the exact axis
-- PeerDeviationHypothesis compares against a peer cohort. That's a sparse,
-- detector-biased count, not a real traffic measurement: a device that happens to
-- trigger MORE other (possibly false-positive) evidence ends up looking like a
-- peer-cohort outlier purely as a side effect, regardless of its real destination
-- diversity -- confirmed live, a device generating heavy dns_evasion_anomaly/
-- reputation/zeek_notice evidence (each with its own destination_id) had an
-- artificially inflated count while quiet, evidence-free peer devices showed
-- near-zero, a self-reinforcing false-positive amplifier layered on top of whatever
-- else was already noisy about that device.
--
-- One row per (device, destination) PAIR, upserted (never one row per raw
-- connection/cycle) -- naturally bounded by real distinct-destination cardinality
-- per device over its retention window, not per-cycle traffic volume.
CREATE TABLE device_destinations (
    device_id      TEXT NOT NULL REFERENCES devices(device_id),
    destination_id TEXT NOT NULL REFERENCES destinations(destination_id),
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    PRIMARY KEY (device_id, destination_id)
);
CREATE INDEX idx_device_destinations_device_ts ON device_destinations(device_id, last_seen);

-- Generalized edge table -- every relationship the graph needs is one row here
-- rather than a bespoke join table per relation type. src/dst are polymorphic
-- (kind + id), resolved by the reading code, not by foreign keys (SQLite has no
-- clean polymorphic FK) -- validated in application code (graph/store.py, Phase 1),
-- not at the schema level.
CREATE TABLE edges (
    edge_id               INTEGER PRIMARY KEY AUTOINCREMENT,
    src_kind              TEXT NOT NULL CHECK (src_kind IN ('device','evidence','destination','hypothesis','decision')),
    src_id                TEXT NOT NULL,
    dst_kind              TEXT NOT NULL CHECK (dst_kind IN ('device','evidence','destination','hypothesis','decision')),
    dst_id                TEXT NOT NULL,
    relation              TEXT NOT NULL CHECK (relation IN
                             ('observed','targets','supports','contradicts','merged_into','corroborates','trusts')),
    timestamp             REAL NOT NULL,
    metadata_json          TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_edges_src ON edges(src_kind, src_id);
CREATE INDEX idx_edges_dst ON edges(dst_kind, dst_id);
CREATE INDEX idx_edges_relation ON edges(relation);

-- Closed-loop autotuning architecture (Release 15). One row per (device, metric,
-- hour-of-day, regime) -- the Bayesian conjugate posterior + BOCPD run-length state
-- beside the pipeline's plain EWMABaseline (core/state.py) for this metric/hour. regime_id
-- increments on a detected changepoint; prior-regime rows are retained (not
-- overwritten) for reset/undo traceability, not deleted on promotion.
CREATE TABLE IF NOT EXISTS device_baselines (
    device_id            TEXT NOT NULL REFERENCES devices(device_id),
    metric                TEXT NOT NULL,        -- e.g. 'query_rate', 'outbound_bytes', 'activity_state'
    hour                  INTEGER NOT NULL,      -- 0-23, diurnal bucket
    regime_id             INTEGER NOT NULL DEFAULT 0,
    model_kind            TEXT NOT NULL CHECK (model_kind IN ('gaussian','beta','poisson','markov')),
    posterior_params_json TEXT NOT NULL DEFAULT '{}',
    run_length_json        TEXT NOT NULL DEFAULT '{}',  -- BOCPD live hypothesis weights, pruned each cycle
    n                     INTEGER NOT NULL DEFAULT 0,
    updated_at             REAL NOT NULL,
    PRIMARY KEY (device_id, metric, hour, regime_id)
);
CREATE INDEX IF NOT EXISTS idx_device_baselines_lookup ON device_baselines(device_id, metric);

-- Population-level priors for cold start, keyed by device_type (not device_id).
-- Only devices with a currently-clean backtest history may contribute (Sheet 00's
-- self-review fix #1) -- contributed_by_json records which device_ids fed this
-- prior, for the same reason: so a later-found-compromised contributor can be
-- identified and the prior rebuilt without them.
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

-- Behavioral cohort membership (Phase 8, autonomy-completion effort) -- a per-
-- device grouping DISTINCT from device_type, derived purely from this
-- device's OWN already-tracked behavioral statistics (device_baselines), not
-- from any user-set/self-reported category or household-specific rule. Exists
-- to let cohort_priors below pool devices by behavioral similarity for
-- devices with no device_type (or an "unknown" one) -- see
-- population_prior_builder.py's _compute_behavioral_cohorts() for the exact
-- bucketing algorithm and its honest first-pass scope.
CREATE TABLE IF NOT EXISTS device_cohort_membership (
    device_id   TEXT PRIMARY KEY REFERENCES devices(device_id),
    cohort_key  TEXT NOT NULL,
    joined_at   REAL NOT NULL,
    updated_at  REAL NOT NULL
);

-- Tracks the most recent identity-changing merge for a device (an orphan's
-- history folded into it via GraphStore.merge_device()) -- "days since last
-- identity change" is `now - last_identity_change_at`. Used as an ADDITIONAL
-- contributor-eligibility gate for cohort pooling only (a frequently-
-- remerged device's own historical baseline may span more than one physical
-- device, an unusually risky contributor for a coarse cross-device pool) --
-- deliberately NOT applied retroactively to the existing device_type
-- pooling above, a narrower scope for this phase.
CREATE TABLE IF NOT EXISTS device_identity_stability (
    device_id                TEXT PRIMARY KEY REFERENCES devices(device_id),
    last_identity_change_at  REAL NOT NULL
);

-- Population priors pooled by BEHAVIORAL COHORT instead of device_type --
-- same shape as population_priors above, read ONLY as a fallback when no
-- device_type-scoped prior exists yet (baseline/engine.py's
-- _seeded_model()/_load_markov()), never overriding a working device_type
-- prior. Gaussian/beta/poisson only (cohort-scoped Markov pooling is an
-- honest, documented scope limit -- not built this phase).
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

-- CL-AFPE's trust key (Sheet 03) -- the six-dimensional composite key, a dedicated
-- table rather than the generic `edges` table, matching this file's own established
-- "generic edges + dedicated concept table" split (same reasoning already applied to
-- containment_actions above). Sparse: only observed tuples get a row.
CREATE TABLE IF NOT EXISTS cl_afpe_trust (
    device_id              TEXT NOT NULL REFERENCES devices(device_id),
    behavior_fingerprint    TEXT NOT NULL,   -- Sheet 00's activity-state + surprise-magnitude bucket
    destination_class       TEXT NOT NULL,   -- CDN/ad-tech/cloud-storage/unclassified-foreign/...
    hypothesis_id           TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
    evidence_family          TEXT NOT NULL,
    regime_id                INTEGER NOT NULL DEFAULT 0,
    trust_value              REAL NOT NULL DEFAULT 0.0,
    n                        INTEGER NOT NULL DEFAULT 0,
    last_updated              REAL NOT NULL,
    snapshot_id               TEXT,           -- FK-by-convention to baseline_snapshots.snapshot_id
    PRIMARY KEY (device_id, behavior_fingerprint, destination_class, hypothesis_id, evidence_family, regime_id)
);
CREATE INDEX IF NOT EXISTS idx_cl_afpe_trust_device ON cl_afpe_trust(device_id);

-- Autotuner's own versioned parameter history (Sheet 03) -- every threshold change,
-- bounded-step, canaried, backtest-gated. snapshot_id links back to the exact
-- baseline_snapshots row that was live when this change was proposed.
-- device_type: 2026-09-16, per-device/category autotuning plan (Documentation/
-- PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md) -- a row has AT MOST ONE of device_id /
-- device_type set (a device-specific override, a category-wide override, or
-- neither = the global default), never both. Enforced in Python
-- (AutotuneEngine.propose_change()), not a CHECK constraint here -- SQLite CHECK
-- constraints on "at most one of two nullable columns" are awkward, and every
-- other invariant in this table is already validated in Python.
CREATE TABLE IF NOT EXISTS threshold_history (
    change_id       TEXT PRIMARY KEY,
    device_id       TEXT REFERENCES devices(device_id),  -- NULL for a fleet/cohort-level parameter
    device_type      TEXT,                                 -- NULL unless this is a category-wide override
    parameter        TEXT NOT NULL,
    old_value        REAL,
    new_value        REAL,
    proposed_at      REAL NOT NULL,
    canary_until     REAL,
    promoted_at      REAL,
    rolled_back_at   REAL,
    reason           TEXT,
    backtest_run_id  TEXT,                                 -- FK-by-convention to backtest_runs.run_id
    snapshot_id      TEXT
);
CREATE INDEX IF NOT EXISTS idx_threshold_history_device ON threshold_history(device_id, proposed_at);
CREATE INDEX IF NOT EXISTS idx_threshold_history_device_type ON threshold_history(device_type, proposed_at);

-- Per-device/cohort versioned snapshots (Sheet 04) -- taken before every regime
-- promotion, autotune batch, and CL-AFPE suppression decision, plus periodic/manual.
-- Retention (self-review fix #3): full-resolution 30 days, thinned to weekly after,
-- with pre_regime_change/manual snapshots exempt from thinning -- enforced by the
-- pruning job, not this schema, same split as evidence's own retention policy.
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

-- Nightly backtest harness output (Sheet 02) -- the audit trail and the autotuner's
-- own gating input. golden_set/synthetic results are stored as JSON summaries
-- (pass/fail counts + which devices/classes were actually covered, since coverage
-- itself can be degraded under resource pressure -- Health & degradation section).
CREATE TABLE IF NOT EXISTS backtest_runs (
    run_id                  TEXT PRIMARY KEY,
    started_at               REAL NOT NULL,
    finished_at               REAL,
    golden_set_result_json    TEXT NOT NULL DEFAULT '{}',
    synthetic_result_json     TEXT NOT NULL DEFAULT '{}',
    drift_result_json         TEXT NOT NULL DEFAULT '{}',
    coverage_json             TEXT NOT NULL DEFAULT '{}',   -- degraded-coverage bookkeeping
    overall_pass              INTEGER NOT NULL DEFAULT 0    -- 0/1, the autotuner's actual gate
);

-- Deterministic shadow evaluation (Phase 7 of the autonomy-completion effort,
-- 2026-09-27, Documentation/ARGUS_AUTONOMY_DEPENDENCY_MAP.md). Compact decision
-- DIFFS only (per the plan's own "shadow_deltas stores compact decision
-- differences only" requirement) -- never raw evidence/evidence snapshots, which
-- already live in `evidence`/`decisions` themselves and would just duplicate them
-- here. One row per (currently-in-canary change, device, real-decision-cycle)
-- comparison: what the REAL promoted/default value produced this cycle vs. what
-- the CANDIDATE (still-in-canary) value would have produced against the exact
-- same input, computed by argus/shadow/sandbox.py's ShadowContext. Bounded by
-- row count (not a schema-level TTL -- SQLite has none), enforced opportunistically
-- on write by the sandbox module itself, not a separate pruning job.
CREATE TABLE IF NOT EXISTS shadow_decisions (
    shadow_id       TEXT PRIMARY KEY,
    change_id       TEXT NOT NULL REFERENCES threshold_history(change_id),
    device_id       TEXT REFERENCES devices(device_id),  -- NULL for a global-scope candidate
    timestamp       REAL NOT NULL,
    real_state      TEXT NOT NULL,    -- this cycle's REAL decision state (BENIGN/SUSPICIOUS/HIGH/CRITICAL)
    shadow_state    TEXT NOT NULL,    -- what the CANDIDATE value would have produced against the same input
    agree           INTEGER NOT NULL  -- 0/1, real_state == shadow_state
);
CREATE INDEX IF NOT EXISTS idx_shadow_decisions_change ON shadow_decisions(change_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_shadow_decisions_timestamp ON shadow_decisions(timestamp);
CREATE INDEX IF NOT EXISTS idx_backtest_runs_started ON backtest_runs(started_at);

-- Alert-trace graph (Documentation/ALERT_TRACE_GRAPH_PLAN.md, 2026-09-22): one row
-- per qualifying cycle (state crosses SUSPICIOUS+): FIRED (a real Telegram send
-- happened), SUPPRESSED_AUTONOMOUS (CL-AFPE suppressed it), or LOGGED_ONLY
-- (neither -- a SUSPICIOUS-only monitor-only cycle, or a deduped repeat occurrence
-- of an already-notified ongoing incident, PHASE 21's own "no alert for suspicion"
-- rule). Whether hardware containment is separately awaiting HITL operator
-- approval is NOT a 4th status here -- that's orthogonal to whether a Telegram
-- message was sent (an awaiting-approval alert still IS a FIRED message, just with
-- pending containment) and stays inside alert_payload_json's own containment_status
-- field, same as it already is in alerts.json today. Never overwritten -- unlike `decisions`, which dedupes on
-- (state, decision_path) and gets its own raw_payload_json overwritten by a
-- recurring incident, this is append-only so every individual firing/suppression
-- survives. Deliberately NOT routed through the generic `edges` table (see the
-- plan doc's "Schema-safety refinement" section): edges' relation/kind CHECK
-- constraints would need a live 8M+-row table rebuild to widen, for no benefit --
-- this is a structured 1:1-with-its-decision relationship, exactly the same shape
-- containment_actions already established a direct-FK precedent for.
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
    explanation_embedding       BLOB,          -- 384 x float32, NULL until embedded
    autotune_state_json          TEXT NOT NULL DEFAULT '{}',  -- active tunables + change_id/scope this cycle
    -- Plain-English narrative (2026-09-22, user request: "rewrite the telegram
    -- alert ... readability for a normal user in plain text, no technical
    -- words"), built once at write time by mitigation/plain_explanation.py --
    -- device/evidence/hypothesis/counter-argument/outcome in one paragraph, no
    -- evidence-type codes or confidence percentages. NULL for backfilled rows
    -- (not recoverable from alerts.json's history the same way).
    plain_explanation             TEXT,
    alert_payload_json            TEXT NOT NULL DEFAULT '{}',
    backfilled                    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alert_events_device_ts ON alert_events(device_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_events_ts ON alert_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_events_decision ON alert_events(decision_id);
CREATE INDEX IF NOT EXISTS idx_alert_events_incident ON alert_events(incident_id);

-- One row per ongoing incident (replaces the bare incident_id string alert_payload
-- used to carry with no queryable entity behind it). Updated in place as new
-- alert_events belong_to it -- occurrence_count/last_seen accumulate, never a
-- fresh row per occurrence.
CREATE TABLE IF NOT EXISTS incidents (
    incident_id          TEXT PRIMARY KEY,
    device_id              TEXT NOT NULL REFERENCES devices(device_id),
    first_seen              REAL NOT NULL,
    last_seen                REAL NOT NULL,
    occurrence_count          INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_incidents_device_last_seen ON incidents(device_id, last_seen);

-- One row per operator response to an alert_event (Telegram approve/release/
-- revoke/immunize/block tap). Previously had ZERO durable trace anywhere --
-- alerts.py's in-memory "published_alert" ledger is process-lifetime only.
CREATE TABLE IF NOT EXISTS operator_actions (
    operator_action_id    TEXT PRIMARY KEY,
    alert_event_id           TEXT NOT NULL REFERENCES alert_events(alert_event_id),
    action                    TEXT NOT NULL CHECK (action IN
                                 ('approve','release','revoke','immunize','block')),
    timestamp                  REAL NOT NULL,
    result_json                  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_operator_actions_alert_event ON operator_actions(alert_event_id);

-- Seed row: the explicit "no real target" sentinel evidence rows use instead of NULL.
INSERT INTO destinations (destination_id, kind, first_seen, last_seen, metadata_json)
VALUES ('(none)', 'domain', 0, 0, '{"sentinel": true}');

-- Retention policy (Phase 1 implements the actual pruning job in graph/store.py;
-- this documents the intended default, sized against .19's measured budget once
-- Phase 0's resource work lands -- NOT yet enforced by this schema file alone):
--   - evidence/edges older than 90 days: pruned, unless referenced by a decision
--     newer than that (decisions are the audit trail; keep what they point to)
--   - decisions: kept 1 year (180 days on pi_8gb), then archived (exported, not
--     deleted) -- matches the "durable, prunable audit trail" goal from
--     HEE_ROADMAP.md item 4's objection
--   - devices/destinations: kept indefinitely (small row count, high identity value)
--   - containment_actions: no automated retention yet (row count is inherently
--     small -- bounded by real containment events, not per-cycle evidence volume)
--   - device_destinations: pruned at 30 days (prune_device_destinations()) -- its
--     only consumer (peer-cohort baselining) only ever looks back 7 days
--     (_PEER_DEVIATION_WINDOW_SECONDS), a shorter retention than evidence's 90 days
--     is deliberate since nothing else reads this table
--   - evidence_type='zeek_notice_weak' rows specifically: pruned at 12 HOURS
--     (prune_weak_zeek_notices(), explicit user request, 2026-09-09) -- confirmed
--     live that zeek_notice evidence was 98.3% of this table's total rows on .94's
--     real graph, and weak-tier notices contribute ZERO scoring weight to any
--     hypothesis (utils.py's ZEEK_NOTICE_TIER_SCORE_WEIGHT["weak"] == 0.0), so the
--     full 90-day window has no benefit to any live decision for this specific
--     evidence_type, only disk cost
