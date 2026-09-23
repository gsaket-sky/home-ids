# Devices / Threat Hunt / Evidence Graph / Alerts API

Companion to `Documentation/CONFIG_API.md` (the Config tab's write-back API). This
covers the console's read-only data endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /api/devices`, `GET /api/devices/{id}`, `GET /api/devices/{id}/top_domains` | Device identity + latest verdict |
| `GET /api/hunt/devices_touching`, `GET /api/hunt/decision_timeline/{id}`, `GET /api/hunt/device_history/{id}`, `POST /api/hunt/replay/{id}` | Threat Hunt tab |
| `GET /api/graph` | Evidence Graph canvas — most recent decisions and everything connected to them. Takes `limit` (1-200) and an optional `device_id` to scope to one device's own most recent decisions instead of the whole network's (added 2026-09-22 — see "Evidence Graph device filter" below). |
| `GET /api/graph/alerts` | The fired/suppressed/logged-only alert list under the Evidence Graph tab's "Alerts" sub-view. Takes `limit`, `offset`, optional `status`/`device_id` filters. |
| `GET /api/graph/alerts/search` | Bounded natural-language semantic search over alert explanations. Takes `q` (required), optional `device_id`/`since`/`until` scope, `limit` (1-100). |

## Why device state/risk isn't in ids_state.json

There is no persisted "current verdict" anywhere in `DeviceState`/`state/ids_state.json`
— confirmed by direct inspection, not assumed. The real source is each device's most
recent Argus decision (`state`/`risk_score`/`confidence` on the `decisions` table),
the same way Grafana's own "Master Threat Ledger" panel already sources its State/Risk
columns (`home_ids_decision_state`/`home_ids_threat_confidence` gauges, themselves
populated from that same per-cycle decision). `GraphStore.get_devices_with_latest_decision()`
(new) does this join. `src/middleware/routers/devices_api.py` then merges that with
`StateManager`/`DeviceState` for identity fields (hostname, MAC, known_ips, ja4_seen,
dhcp_fingerprint) — two different sources for one device, by design.

## Top 10 domains (all-time) is not implemented

Deliberately, not an oversight. The Argus evidence graph only stores evidence-WORTHY
events (an entry only exists because a detector flagged something), not general query
volume — most of a device's routine DNS traffic never becomes an `evidence` row at
all. The real data for "top 10 domains" lives in Pi-hole's own query log, the same
source `scripts/top_domains_report.py` already uses, but only for a rolling 24h
window. An honest "not available yet" note ships in the console instead of a number
computed from the wrong data source. Making this genuinely all-time-per-device is
separate follow-up work: a new persistent aggregation, since Pi-hole's own log
retention may not cover a device's whole history either.

## GraphStore is opened fresh per request, never shared

`GraphStore.__init__` is a plain `sqlite3.connect()`, no `check_same_thread=False`.
FastAPI's sync `def` handlers run across a threadpool, so a shared instance risks
"SQLite objects created in a thread can only be used in that same thread." Every
router (`devices_api.py`, `hunt_api.py`, `graph_api.py`, `overview_api.py`,
`autonomy_api.py`) goes through `middleware/graph_client.py`'s `open_store()` context
manager — opens, yields, closes, every call. Confirmed safe against the real
deployment's `state/v13_graph.db` (WAL mode, baked into `schema.sql` at file
creation — any number of concurrent readers against the one writer, no lock
contention) — this is also exactly the pattern `src/argus/ops/threat_hunt.py`'s own
CLI already used for a second connection to the same file.

**BUGFIX (found live 2026-09-22, chronic console latency):** "opened fresh per
request" used to also mean `_migrate_existing_db()` — a ~40-statement schema
migration `executescript()` plus several `ALTER TABLE` attempts — re-ran on EVERY
single request, since it's part of `GraphStore.__init__`. Confirmed via `py-spy`
live: 6+ uvicorn worker threads simultaneously stuck acquiring the write-intent lock
that migration needs, colliding with the constantly-writing main pipeline process —
`/api/graph` taking 40+ seconds to answer even `limit=1`. `GraphStore.
_migrated_db_paths` (class-level, `argus/graph/store.py`) now caches "already
migrated" per db_path for the life of the process, so only the first `GraphStore`
built after a restart pays the migration cost; every connection after that is the
plain, uncontended `sqlite3.connect()` this section's title always assumed. A second,
related fix the same night: `StateManager` (used by every router above to resolve
hostnames) was being freshly re-constructed and re-parsed from a 5.7MB
`state/ids_state.json` on every single request across 14 call sites —
`middleware/state_client.py`'s `get_cached_state_manager()` now caches it with
mtime-based invalidation, scoped to these read-only routers only (never the
containment/mitigation-action endpoints in `pihole_api.py`/`fritzbox_api.py`, which
keep their own fresh, unshared instance deliberately).

## Real-data findings from verifying this against `.94`'s live database, not synthetic data

Both found by actually running the new endpoints against the real 2.1GB
`state/v13_graph.db` (63 devices, 95,330 evidence rows, 5,050 decisions, 8.3M edges at
the time) before considering this done — synthetic per-file unit tests alone would
not have caught either:

1. **One decision had 56,073 supporting edges** (`GET /api/graph?limit=15` returned
   57,258 nodes before the fix — a single noisy device, not a bug in the endpoint's
   own logic, but the endpoint still had to defend against it). That device alone
   accounts for ~79% of all evidence in the whole database. Fixed with
   `EVIDENCE_PER_DECISION_CAP = 15` in `graph_api.py` — the most RECENT 15 edges per
   decision, not an arbitrary/opaque subset, with `evidence_total`/`evidence_truncated`
   on each decision node so the UI can say "showing 15 of 56,073" honestly rather than
   silently truncate. `GraphStore.get_edges()` gained an optional `limit_most_recent`
   param (`ORDER BY timestamp DESC LIMIT ?` pushed into SQL, using the existing
   `idx_edges_dst` index) plus a new `count_edges()` for the total, replacing an
   earlier version of this fix that fetched every row and truncated in Python
   (~3.4s/request) — the SQL-level version is ~0.8s against the same real data.

2. **`decision_timeline`/`replay_decision` took 18-19s** against a busy device's
   decision, via the ALREADY-EXISTING `decision_replay.py:get_decision_evidence()`
   (Release 14, N3) — it fetched `get_evidence_for_device()` (every evidence row for
   that device — one real device has 75,464) and filtered down to the decision's own
   `supports`-edge evidence_ids in Python. Fixed by swapping that full-device scan for
   `GraphStore.get_evidence_by_ids()` (new, added for the graph endpoint's own N+1
   avoidance) — an indexed `evidence_id IN (...)` lookup, same resulting set (every
   `supports` edge only ever names evidence belonging to the decision's own device, by
   `insert_decision()`'s own wiring), sub-second regardless of how much evidence that
   device has accumulated. This is a shared fix — both `threat_hunt.py`'s
   `decision_timeline()` and `decision_replay.py`'s `replay_decision()`/`replay_range()`
   import `get_decision_evidence()` from the same place, so both got faster from one
   change. Verified against the existing standalone tests
   (`tests/test_v13_decision_replay.py`, `test_v13_threat_hunt.py`, `test_v13_graph_store.py`)
   — all still pass; this was a behavior-preserving swap, not a semantic change.

Neither finding was hypothetical or guessed at — both came from running the actual
code against the actual deployment's actual data before calling this done.

## log_level live-reload fix (bundled into this same pass)

Unrelated to the graph work, but shipped alongside per the user's own choice:
`src/main.py`'s `setup_logging()` used to call `logging.basicConfig(level=...)` exactly
once at boot, reading `log_level` at that moment — nothing re-applied a later
`config.yaml`/`config_overrides.json` change to the actual logging subsystem, even
though `config.yaml` documents the key `[LIVE]`. Fixed by registering a
`CONFIG.set_notify()` callback (that mechanism already existed, built for the autotune
job, previously unused by anything logging-related) that calls
`logging.getLogger().setLevel(...)` whenever `log_level` is among the changed keys —
now genuinely live, whether the change came from a config.yaml edit or a console PATCH.
`LiveConfig.revert_override()` (the Config API's DELETE path) also gained the same
`_notify_cb` firing it was missing — a revert-to-baseline is as much an
effective-value-changed event as a PATCH is.

## Suricata is not in the Argus graph (a pre-existing, already-documented gap)

Checked directly while scoping this work, not assumed: Suricata's batch-scan findings
(`intelligence/detectors/suricata_scan.py`) are still built as the OLD, pre-Argus
`Evidence` shape (`type=`, `device=`, `independence_group=`, `domain=`), not the Argus
`Evidence` dataclass this graph stores. `src/argus/ingest/sources.py`'s own module
docstring already says why: Suricata only runs in short batch invocations against
reactively-captured pcap bursts, not a continuous log stream, and wiring that into Argus
"needs the whole reactive-capture trigger/dispatch subsystem, not a log tailer... NOT
attempted here." So Suricata alerts don't appear in the Threat Hunt or Evidence Graph
tabs — not a limitation of this console work, a pre-existing, already-acknowledged
scope cut one layer down.

## Alerts are real graph nodes, not a side table (added 2026-09-22)

`alert_events`/`incidents`/`operator_actions` (schema in `argus/graph/schema.sql`) sit
alongside `decisions`/`evidence`/`destinations` — every cycle that crosses SUSPICIOUS+
gets a durable `alert_event` row (status FIRED/SUPPRESSED_AUTONOMOUS/LOGGED_ONLY),
written from `core/pipeline.py` via `GraphStore.insert_alert_event()` right after the
decision itself is written. `GET /api/graph` renders each one as its own `alert_event`
node connected to its decision, plus a companion `explanation` node carrying the
plain-English narrative (see below) so the graph canvas shows a full, readable
story — device → evidence → decision → alert → explanation — not just raw scores.

**Plain-English narrative, everywhere an alert shows up.** `mitigation/
plain_explanation.py`'s `build_plain_explanation()` generates one short paragraph per
alert — device, what was noticed, the destination (resolved to a hostname/ASN/country,
never a raw IP), the winning hypothesis, the honest counter-argument (the losing
hypothesis's own score, not hidden), and what happened as a result. The SAME text
appears in three places: the Telegram alert (leads the message), the graph's
`explanation` node, and `alert_event.plain_explanation` in both `/api/graph` and
`/api/graph/alerts`.

**Destinations are humanized everywhere**, not just in this narrative:
`middleware/humanize.py`'s `resolve_destination_info()` resolves a destination_id to a
local peer device's own hostname, a known domain, or an external IP's reverse-DNS
hostname + GeoIP ASN owner/country — `kind` in the response (`local_device`/`domain`/
`external_ip`) lets the console style/link it appropriately. Every `destination` node
in `/api/graph` and every `device_hostname` field in `/api/graph/alerts*` goes through
this, never a bare device_id or raw IP.

**Bounded semantic search**, not unbounded background indexing: each alert's
explanation text is embedded once, at write time, via `fp_engine.py`'s `embed_text()`
(FastEmbed `BAAI/bge-small-en-v1.5`, the SAME already-resident model Stage 3 CL-AFPE
uses — no second model load). `GET /api/graph/alerts/search` requires a scope (a time
window, optionally narrowed to one device) and enforces a hard candidate cap
(`GraphStore.ALERT_SEARCH_CANDIDATE_CAP = 5000`) — a search whose scope would exceed it
gets an honest 422 error instead of a silently truncated result. The console API
process embeds the SEARCH QUERY text itself via its own lazily-loaded, process-local
FastEmbed instance (`graph_api.py`'s `_get_query_embed_model()`) — a separate OS
process from the main pipeline, so it can't share that instance directly, but reads
from the same already-downloaded `models/fastembed_cache/` rather than re-downloading.

**Evidence Graph device filter** (found live 2026-09-22, "I still don't see the alert
in graph"): `/api/graph` used to show only the most recent `limit` (25-200) decisions
ACROSS THE WHOLE NETWORK, with no way to look up an older or single-device alert — on
a busy network that's a matter of minutes, regardless of how old the target actually
is. `device_id` (optional query param, `GraphStore.get_recent_decisions()`) scopes the
same query to one device via `idx_decisions_device_ts`. The console's Graph tab has a
matching device-filter input box, and every Alerts-tab row has a "View in graph"
button that jumps straight there.
