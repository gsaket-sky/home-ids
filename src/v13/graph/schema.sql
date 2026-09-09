-- v13 EvidenceGraph SQLite schema (design pass, Phase 0 -- see
-- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md). This file documents the design;
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
-- authoritative source stays whatever live reputation classifier v13 wires in) --
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
-- which v13 mechanisms were shadow vs. live AT THE TIME -- essential for the
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

-- v13 full-architecture plan, IPS containment unification: a write-only AUDIT
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
