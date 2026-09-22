# Alert Trace Graph Plan

Status: **PLANNED (2026-09-22)** — design agreed in conversation, nothing implemented
yet. Written in response to: "if we ignore alerts.json's history and consider the
new architecture, if we would have implemented it afresh how will it look like...
end to end trace in evidence graph for every entry from now on:
device-evidence-hypothesis-decision-alerts-suppressed... the graph db should follow
graph logic and no rows/columns just for storage" — followed by agreement to add a
resource-bounded semantic-search layer on top, then three follow-up decisions
(2026-09-22): hypothesis catalog is one row per hypothesis *type* (confirmed, not
per-decision), `operator_action` ships in scope from day one (not deferred), and
`alerts.json`'s history should be backfilled into the new shape wherever the source
data actually supports it, falling back to clean-cutover only for what it doesn't.

## Bottom line up front

This is **not** a rewrite of `GraphStore` or a new database engine. `devices`,
`evidence`, `destinations`, `decisions` plus the generic `edges(src_kind, src_id,
dst_kind, dst_id, relation, timestamp)` table are already real, traversable graph
structure — that part is sound and is reused as-is.

The actual gap is narrower: **two whole layers of the trace never became nodes.**
`hypothesis` and "was this alert fired or suppressed" both got flattened into
`decisions.raw_payload_json` — an opaque JSON blob only application code can parse.
`hypotheses` even exists as a real table already and is confirmed unused
(`winning_hypothesis_id` is 0/45,650 populated, per `graph_api.py`'s own docstring).
This plan finishes those two layers using the exact same node/edge pattern already
established, and separately fixes the fact that `alerts.json`'s per-cycle history
(71,669 lines) has no durable graph representation at all — `decisions` rows dedupe
on `(state, decision_path)` and get overwritten, so most individual alert firings/
suppressions are only ever in the flat file, never durably in the graph.

Per [[feedback_network_agnostic_design]]: nothing below encodes a fixed list of
hypothesis types, evidence types, or device categories — the hypothesis catalog
(below) is populated from whatever hypothesis names `decision_engine`/`argus`
actually emit, discovered the same way `device_type` is already discovered
elsewhere in this codebase, never hardcoded.

## Problem, precisely

| layer | today | should be |
|---|---|---|
| hypothesis | buried in `decisions.raw_payload_json["hypotheses"]` dict | real `hypothesis` catalog node + `--won-->`/`--considered_for-->` edges to `decision` |
| alert (fired/suppressed) | buried in `decisions.raw_payload_json["alert_payload"]`/`["fp_verdict"]`, **overwritten every cycle a recurring incident continues** | real `alert_event` node, one per qualifying cycle, never overwritten |
| incident grouping | a hash string (`incident_id`), not queryable as an entity | real `incident` node, `alert_event --belongs_to--> incident` |
| containment action | its own table, joined to an alert only by timestamp proximity | `alert_event --resulted_in--> containment_action` |
| operator action (Telegram approve/release/revoke/immunize) | in-memory-only "published_alert" ledger, no durable trace at all today | `alert_event --reviewed_by--> operator_action` |

## Node kinds

| kind | status | notes |
|---|---|---|
| `device` | exists | unchanged |
| `evidence` | exists | unchanged |
| `destination` | exists | unchanged |
| `hypothesis` | exists, unused | **DECIDED**: catalog of hypothesis *types* (dns_tunneling, c2_beaconing, port_scan, coordinated_targeting, benign, ...) — near-static, a few dozen rows, reused across every decision, populated dynamically from whatever names the decision engine actually emits (confirmed live: `hee_hypotheses` already carries exactly `{"attack": {"name": ..., "score": ...}, "benign": {"name": ..., "score": ...}}` per alert — the catalog just needs a row per distinct `name` seen), never hardcoded |
| `decision` | exists | `raw_payload_json` shrinks back to genuinely decision-scoped fields (reasoning trail text, mechanism flags); hypothesis/alert data move to their own nodes |
| `alert_event` | **new** | one row per qualifying cycle (state crosses SUSPICIOUS+), append-only, never overwritten — this is what replaces `alerts.json` going forward |
| `incident` | **new** | one row per ongoing incident, updated in place (occurrence_count, first/last seen) — replaces the bare `incident_id` string |
| `operator_action` | **new, IN SCOPE from day one** (decided 2026-09-22, not deferred) | one row per Telegram tap (approve/release/revoke/immunize) — currently has zero durable trace anywhere |
| `containment_action` | exists as standalone table | stays a table for its own scalar fields, but gets a real edge from `alert_event` instead of timestamp-proximity joins |

## Edge / relation vocabulary

Same `edges` table, new `relation` values:

```
device        --observed-->        evidence            (existing)
evidence      --targets-->         destination         (existing)
evidence      --supports-->        decision            (existing — stays, cheap/capped)
evidence      --supports-->        hypothesis           NEW
evidence      --contradicts-->     hypothesis           NEW  (currently invisible: evidence that argued AGAINST the winner and lost)
hypothesis    --considered_for-->  decision             NEW  (every hypothesis HEE scored this cycle, not just the winner)
hypothesis    --won-->             decision             NEW  (replaces the always-null winning_hypothesis_id FK)
decision      --raised-->          alert_event          NEW  (only exists when state crosses SUSPICIOUS+)
alert_event   --belongs_to-->      incident             NEW
alert_event   --resulted_in-->     containment_action   NEW
alert_event   --reviewed_by-->     operator_action      NEW
```

`alert_event` carries `status` (`FIRED` | `SUPPRESSED_AUTONOMOUS` | `AWAITING_APPROVAL`)
and the `fp_verdict` fields (verdict/confidence/stage) as real columns on that node —
not a graph violation, the same way `evidence.confidence` is already a column on
`evidence`. The rule this plan follows: **relationships are edges you can traverse;
scalar facts about one thing are columns on that thing.** `fp_verdict` only failed
that test before because it was a field inside *another node's* blob.

## Worked examples

```
FIRED:
  device:firetv_a1 --observed--> evidence:dns_tunnel_v2#412
  evidence#412     --supports-->  hypothesis:dns_tunneling
  hypothesis:dns_tunneling --won--> decision:9f2a
  decision:9f2a --raised--> alert_event:e77c {status: FIRED, fp_verdict: CONFIRMED_THREAT, confidence: 0.91}
  alert_event:e77c --belongs_to--> incident:inc_88 {occurrence_count: 3}
  alert_event:e77c --resulted_in--> containment_action:block_91 {target: firetv_a1, method: router_isolate}
  alert_event:e77c --reviewed_by--> operator_action:approve_44 {action: approve, at: ...}

SUPPRESSED:
  device:iphone_c2 --observed--> evidence:zeek_notice_weak#88
  evidence#88      --supports--> hypothesis:c2_beaconing
  hypothesis:c2_beaconing --considered_for--> decision:7b31   (didn't win)
  hypothesis:benign       --won--> decision:7b31
  decision:7b31 --raised--> alert_event:f102 {status: SUPPRESSED_AUTONOMOUS, fp_verdict: FALSE_POSITIVE, stage: cl_afpe_stage2, confidence: 0.87}
```

Both directions are now walkable: forward (device → outcome) and backward (an
`alert_event` → the exact evidence that caused it, **including** evidence that argued
the other way and lost) — the second is impossible today without grepping a JSON blob.

## Explicitly NOT graph-ified

`baseline_snapshots`, `device_baselines`, `population_priors`, `threshold_history`,
`cl_afpe_trust`, `backtest_runs` stay plain relational/time-series tables. They're
statistical rollups, not part of the device→evidence→hypothesis→decision→alert
*trace* — forcing them into nodes/edges would be over-correcting and buys nothing
queryable.

## Semantic search (bounded add-on)

Agreed scope: natural-language search over `alert_event` explanation text, to survive
this project's frequent evidence-type/hypothesis-taxonomy renames (e.g. the
zeek_notice tier split, the 09-08/09 evidence-family fixes) — an operator searching
"anything like this DNS tunneling thing" shouldn't miss alerts logged under an old
type name. **Not LLM-based** — an embedding/encoder model, no generation involved.

**Reuses existing infrastructure, adds nothing new to the dependency graph:**
- The FastEmbed MiniLM/bge-small-en-v1.5-onnx-q model already loaded by
  `fp_engine.py` Stage 3 (`< 15ms` embed time, per that module's own docstring) —
  same loaded instance, not a second copy.
- At `alert_event` write time: embed the explanation/reasoning text, store as a
  BLOB column (`explanation_embedding`, 384×float32 = 1536 bytes) on the node.
- At query time: cosine similarity via numpy, brute-force over a **scoped**
  candidate set only.

**Bounding rules (hard requirements, not suggestions):**
1. Every semantic-search query MUST supply at least one narrowing filter before
   embeddings are touched: a time window (default last 30 days, max 1 year) and/or
   a `device_id`. No "search all history, unscoped" code path exists — same
   discipline that was missing from `alerts.json`'s original backward-scan and had
   to be retrofitted; this time it's built in from the start.
2. Hard cap on candidate-set size per query (e.g. 5,000 rows, mirroring
   `EVIDENCE_PER_DECISION_CAP`'s precedent for "cap first, never silently degrade
   without saying so"). If the scoped filter still yields more than the cap, the
   API returns an honest "narrow your search further" error — never a silent
   truncation that looks complete but isn't.
3. Vectors are computed once at write time and stored, never re-embedded at query
   time except for the single query string itself (~15ms, one-time per search).
4. Storage growth budget: ~1.5KB/alert_event at float32; at current volume
   (~71K/15 days) that's roughly 100-150MB/year — trivial next to the >1GB graph DB
   already on disk. Re-evaluate (e.g. int8 quantization) only if actual growth
   materially deviates from this estimate.

## Schema-safety refinement (2026-09-22, found during implementation)

The original draft below assumed `hypothesis`/`decision`/`alert_event` relations
would all go through the generic `edges` table with new `src_kind`/`dst_kind`/
`relation` CHECK values. Checked against the live schema and found this would be
unsafe: `edges.relation`/`src_kind`/`dst_kind` are SQLite CHECK constraints, and
SQLite has no `ALTER TABLE ... ALTER CONSTRAINT` — widening a CHECK requires a full
table rebuild (create-new, copy, drop, rename). `.94`'s live `edges` table has
**8M+ rows** (confirmed via `graph_api.py`'s own docstring) — rebuilding that on a
Pi is a real risk, not a formality, for a schema change that doesn't need it:

- `hypothesis` and `decision` are **already** valid `edges` kinds, and `supports`/
  `contradicts` are **already** valid relations — `evidence --supports/contradicts-->
  hypothesis` needs zero CHECK changes.
- `hypothesis --won/considered_for--> decision`: reuses the already-allowed
  `corroborates` relation (confirmed unused anywhere in the live codebase, safe to
  repurpose — NOT `trusts`, which is actively used by CL-AFPE), with `{"won": true|false,
  "score": ...}` in the edge's own `metadata_json` column distinguishing winner from
  considered-only. No CHECK change needed.
- `alert_event`, `incident`, `operator_action` are **not** added as `edges` kinds at
  all. Instead, matching this schema's own established precedent
  (`containment_actions.decision_id` is a direct FK column, not an `edges` row,
  specifically because it has "real structured, UPDATEABLE fields... that edges'
  append-only CHECK-constrained relation column doesn't support" — schema.sql's own
  words) — `alert_events`, `incidents`, `operator_actions` link to each other and to
  `containment_actions` via direct FK columns on the new tables. Zero changes to the
  existing `edges` table's schema or CHECK constraints at all; the 8M-row rebuild
  risk is fully avoided.

## Bounded growth (2026-09-22, explicit requirement: nothing grows unchecked)

Every new table gets the same retention discipline `evidence`/`device_destinations`/
`zeek_notice_weak` already have — real pruning jobs, not size-based rotation
(`alerts.json`'s `AlertJSONWriter` only rotates at 1GB and keeps one `.bak`, which is
itself a latent unbounded-growth gap this design does not repeat).

- **`alert_events`**: retained on the same window as `decisions` (below) — pruned in
  the SAME job, since an `alert_event` without its parent `decision` is meaningless.
- **`incidents`**: pruned when its last remaining `alert_event` ages out (cascade,
  not a separate clock).
- **`operator_actions`**: pruned when its parent `alert_event` ages out (cascade,
  FK-deleted first to satisfy `PRAGMA foreign_keys = ON`).
- **`explanation_embedding` vectors**: bounded automatically — they live as a column
  on `alert_events`, so they're deleted exactly when their row is, no separate
  tracking needed. The storage-growth estimate in the semantic-search section above
  (~100-150MB/year) is a *steady-state* number once this retention window is active,
  not an ever-growing total.
- **`decisions` itself — found genuinely unbounded today**: schema.sql documents an
  intended "1 year (180 days on pi_8gb), then archived" policy, but no
  `prune_decisions()` was ever implemented — confirmed by grepping `graph/store.py`
  for it (only `prune_evidence()`/`prune_weak_zeek_notices()`/
  `prune_device_destinations()` exist). 45,650 rows today and growing forever. Since
  `alert_events` FKs to `decisions`, this plan closes that gap now rather than
  building bounded new tables on top of an unbounded parent: a new
  `prune_decisions(older_than_days=180 on pi_8gb / 365 on x86_16gb/custom)` deletes
  in FK-safe order (`operator_actions` → `alert_events` → hypothesis/evidence edges
  referencing the decision → the `decision` row itself), matching `prune_evidence()`'s
  existing delete-order discipline. This is a real, deliberate scope addition beyond
  the original ask, directly required by "no unchecked growth anywhere" — flagged
  here rather than done silently.
- Wired into whichever scheduler already calls `prune_evidence()`/
  `prune_weak_zeek_notices()`/`prune_device_destinations()` today (to confirm at
  implementation time — expected to be `live_prune.py`), not a new/separate cron
  entry.

## Autonomous-behavior traceability (2026-09-22, explicit requirement)

Global and per-device autonomous tuning (`AutotuneEngine`, `threshold_history` —
already device_id/device_type-scoped per
[PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md](PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md) — and
CL-AFPE's `cl_afpe_trust`) already has its own console visibility (the Autonomy tab,
[project_health_visibility_and_autonomy_console]). What's currently missing is the
**link between an individual alert and the autonomous state that shaped it** — today
the Autonomy tab and the alert view are two disconnected places; you can't look at
one fired/suppressed alert and see "this device's `hard_stop_candidate_sensitivity`
was auto-tightened by the autotuner 3 days ago, which is why this scored the way it
did."

Fix: `alert_events` gets one more plain column, `autotune_state_json` — a small
snapshot, captured at decision time, of the actually-active tunable values this
cycle used (`hard_stop_candidate_sensitivity`, `reputation_tier_*_floor`, etc.),
each tagged with whether it came from a device-specific override, a device-type/
category override, or the global default (mirrors `get_active_value()`'s own
3-tier resolution — no new computation, just persisting what it already resolved),
plus the `threshold_history.change_id` that produced it when the value isn't the
hardcoded default. A plain column, not an edge — same "scalar fact about one thing
stays a column" rule as `fp_verdict`, and avoids the same CHECK-constraint/8M-row
`edges` table risk already flagged above.

Console: the new per-alert view links out to the existing Autonomy tab's history for
whichever `change_id`s are named in that snapshot, closing the loop between the two
views without duplicating the Autonomy tab's own global/per-device history UI.

## Schema changes (draft — to refine at implementation time)

```sql
CREATE TABLE alert_events (
    alert_event_id       TEXT PRIMARY KEY,
    decision_id           TEXT NOT NULL REFERENCES decisions(decision_id),
    device_id             TEXT NOT NULL REFERENCES devices(device_id),
    incident_id            TEXT REFERENCES incidents(incident_id),
    timestamp               REAL NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN
                               ('FIRED','SUPPRESSED_AUTONOMOUS','AWAITING_APPROVAL')),
    fp_verdict               TEXT,
    fp_confidence             REAL,
    fp_stage                  TEXT,
    explanation_text           TEXT,
    explanation_embedding       BLOB,          -- 384 x float32, nullable until embedded
    autotune_state_json          TEXT NOT NULL DEFAULT '{}',  -- active tunables + their change_id/scope this cycle
    alert_payload_json            TEXT NOT NULL DEFAULT '{}',  -- everything not worth its own column yet
    backfilled                    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_alert_events_device_ts ON alert_events(device_id, timestamp);
CREATE INDEX idx_alert_events_ts ON alert_events(timestamp);
CREATE INDEX idx_alert_events_decision ON alert_events(decision_id);
CREATE INDEX idx_alert_events_incident ON alert_events(incident_id);

CREATE TABLE incidents (
    incident_id          TEXT PRIMARY KEY,
    device_id              TEXT NOT NULL REFERENCES devices(device_id),
    first_seen              REAL NOT NULL,
    last_seen                REAL NOT NULL,
    occurrence_count          INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_incidents_device_last_seen ON incidents(device_id, last_seen);

CREATE TABLE operator_actions (
    operator_action_id    TEXT PRIMARY KEY,
    alert_event_id           TEXT NOT NULL REFERENCES alert_events(alert_event_id),
    action                    TEXT NOT NULL CHECK (action IN
                                 ('approve','release','revoke','immunize','block')),
    timestamp                  REAL NOT NULL,
    result_json                  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_operator_actions_alert_event ON operator_actions(alert_event_id);

-- containment_actions (existing table) gets one additive column so
-- alert_event --resulted_in--> containment_action is a real FK, not a
-- timestamp-proximity guess. ALTER TABLE ADD COLUMN, same "no-op on a db that
-- already has it" idiom already used for threshold_history.device_type.
ALTER TABLE containment_actions ADD COLUMN alert_event_id TEXT REFERENCES alert_events(alert_event_id);
```

Hypothesis/decision relations reuse the existing `edges` table with NO schema
change (see "Schema-safety refinement" above): `evidence --supports/contradicts-->
hypothesis` (existing relations), `hypothesis --corroborates--> decision` with
`metadata_json={"won": true|false, "score": ...}` distinguishing the winner.

Indexes needed beyond the above: none new on `edges` (reusing existing
`idx_edges_src`/`idx_edges_dst`/`idx_edges_relation`).

## Pipeline wiring (implementation notes, not yet done)

- Write `alert_events` at the exact call site `self.alert_writer.write(alert_payload)`
  already uses (`pipeline.py:2784`) — purely additive, `alerts.json`'s write path is
  completely untouched, zero regression risk to `train_fp_classifier.py` or anything
  else reading the flat file today.
- Hypothesis edges (`--won-->`/`--considered_for-->`) written alongside
  `insert_decision()`, sourced from the same `decision.get("hypotheses", {})` dict
  already computed every cycle — no new computation, just persisting what already
  exists in memory as edges instead of leaving it in the blob.
- `operator_action` rows written from `alerts.py`'s `_handle_telegram_callback()` /
  `_handle_telegram_command()` handlers, at the same points that currently only
  send a Telegram confirmation text back — additive, no behavior change to the
  Telegram flow itself.
- All of the above best-effort (never raises into the live decision path), matching
  every other graph write's established convention in this codebase.

## Console / API

- New `GET /api/graph/alerts` — paginated, indexed query over `alert_events`
  (replaces `_alert_log_utils.py`'s bounded-backward-scan hack over a 170MB+ NDJSON
  file with a real indexed query — a genuine performance win on top of the
  visibility ask).
- New `GET /api/graph/alerts/search?q=...&device_id=...&since=...` — the bounded
  semantic-search endpoint described above.
- Console: new sub-view within the existing **Evidence Graph** tab listing fired/
  suppressed alerts, each linking into the existing graph visualization for its
  decision node.

## Backfill (decided 2026-09-22: backfill where the data supports it, cutover elsewhere)

`alerts.json` keeps being written exactly as it is today regardless (unchanged
write path, unchanged consumers — `train_fp_classifier.py` etc. are untouched).
The question is only whether *history* also gets imported into the new shape.

Checked against a real, current line from `.94`'s live `alerts.json` (not assumed):

```json
{
  "incident_id": "fc3e26115482|unknown|PEER_COHORT_DEVIATION",
  "fp_verdict": {"verdict": "CONFIRMED_THREAT", "confidence": 0.0048, "calibrated_confidence": null, "stage": "STAGE_3_COMBINED"},
  "hee_hypotheses": {"attack": {"name": "PEER_COHORT_DEVIATION", "score": 3.0, "checklist": {...}}, "benign": {"name": "UNKNOWN_BENIGN", "score": 0.0}},
  "hee_decision_path": "hypothesis_suspicious",
  "hee_evidence_families": []
}
```

**Feasible — every historical line carries what's needed:**
- `alert_events` — direct 1:1 import: `status` from `fp_verdict.verdict`/whether it
  was ever Telegram-sent, `fp_verdict`/`fp_confidence`/`fp_stage` straight from the
  `fp_verdict` object, `explanation_text` from `signature`, everything else from
  the record as-is.
- `incidents` — group backfilled lines by their own `incident_id` string (format
  confirmed identical to what `_incident_key()` produces today), derive
  `first_seen`/`last_seen`/`occurrence_count` from the group.
- Hypothesis edges — `hee_hypotheses` already carries both the winner (`attack`)
  and the runner-up (`benign`) with scores, so both `--won-->` and
  `--considered_for-->` edges are reconstructable, not just the winner.

**Not feasible — accept the gap, new data only:**
- `operator_action` — Telegram approve/release/revoke/immunize responses were
  never written back into `alerts.json` (or anywhere durable) at any point in this
  project's history. There is nothing to backfill; historical alerts will simply
  have no `operator_action` edges. Going forward, every new one is captured.
- `containment_action` linkage — the existing `containment_actions` table has no
  `alert_event_id`/`decision_id` FK today, so historical rows can only be matched
  to a backfilled `alert_event` by device_id + timestamp proximity, best-effort,
  not guaranteed exact. New data gets the real edge at write time; old data gets a
  best-effort one or none.

**Mechanics** — same proven pattern as `backfill_muted_log_to_graph.py` (2026-09-21,
the `autonomous_muted.jsonl` migration): a one-time script, run against a **copy** of
`v13_graph.db` first, spot-checked and row-count-compared against `wc -l` on the
source before ever touching the real file; deterministic IDs
(`f"backfill:alert:{timestamp}:{device_id}"`-shaped) so a re-run is idempotent, not
duplicating; `alert_payload_json` carries `{"backfilled": true}` so backfilled rows
are always distinguishable from real live ones; never deletes or modifies
`alerts.json` itself.

## Implementation phases

1. Schema: add `alert_events`, `incidents`, `operator_actions` tables + indexes;
   add new `edges.relation` values (no schema change needed there, it's already
   generic).
2. Pipeline: wire `alert_events` writes at the existing `alert_writer.write()` call
   site; wire hypothesis edges alongside `insert_decision()`.
3. Pipeline: wire `operator_action` writes from the Telegram callback/command
   handlers.
4. Embedding: wire `explanation_embedding` population at `alert_event` write time,
   reusing `fp_engine.py`'s already-loaded FastEmbed instance.
5. API: `/api/graph/alerts` (paginated list) and `/api/graph/alerts/search`
   (bounded semantic search).
6. Console: new Evidence Graph sub-view.
7. Verify live on `.94` against real traffic before considering `alerts.json`
   read paths for retirement (separate, later decision).
8. Backfill script (`backfill_alerts_to_graph.py`, modeled on
   `backfill_muted_log_to_graph.py`): import `alerts.json` history into
   `alert_events`/`incidents`/hypothesis edges. Run against a DB copy first,
   verify row counts, then run for real. `operator_action` and exact
   `containment_action` linkage are not backfillable — accepted gap for
   historical rows only, per the Backfill section above.

## Resolved decisions (2026-09-22)

- Hypothesis catalog: per-type (confirmed).
- `operator_action`: in scope from day one, not deferred (confirmed).
- Backfill: attempt it wherever the data supports it (`alert_events`, `incidents`,
  hypothesis edges — all confirmed feasible against real data); accept the gap for
  `operator_action` and exact `containment_action` linkage on historical rows only.
