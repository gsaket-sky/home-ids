# Devices / Threat Hunt / Evidence Graph API

Companion to `Documentation/CONFIG_API.md` (the Config tab's write-back API). This
covers the three read-only endpoints that replaced the console's remaining sample
data: `GET /api/devices[/{id}]`, `GET /api/hunt/*`, `GET /api/graph`.

## Why device state/risk isn't in ids_state.json

There is no persisted "current verdict" anywhere in `DeviceState`/`state/ids_state.json`
— confirmed by direct inspection, not assumed. The real source is each device's most
recent v13 decision (`state`/`risk_score`/`confidence` on the `decisions` table),
the same way Grafana's own "Master Threat Ledger" panel already sources its State/Risk
columns (`home_ids_decision_state`/`home_ids_threat_confidence` gauges, themselves
populated from that same per-cycle decision). `GraphStore.get_devices_with_latest_decision()`
(new) does this join. `src/middleware/routers/devices_api.py` then merges that with
`StateManager`/`DeviceState` for identity fields (hostname, MAC, known_ips, ja4_seen,
dhcp_fingerprint) — two different sources for one device, by design.

## Top 10 domains (all-time) is not implemented

Deliberately, not an oversight. The v13 evidence graph only stores evidence-WORTHY
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
"SQLite objects created in a thread can only be used in that same thread." Every new
router (`devices_api.py`, `hunt_api.py`, `graph_api.py`) goes through
`middleware/graph_client.py`'s `open_store()` context manager — opens, yields, closes,
every call. Confirmed safe against the real deployment's `state/v13_graph.db` (WAL
mode, baked into `schema.sql` at file creation — any number of concurrent readers
against the one writer, no lock contention) — this is also exactly the pattern
`src/v13/ops/threat_hunt.py`'s own CLI already used for a second connection to the
same file.

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

## Suricata is not in the v13 graph (a pre-existing, already-documented gap)

Checked directly while scoping this work, not assumed: Suricata's batch-scan findings
(`intelligence/detectors/suricata_scan.py`) are still built as the OLD, pre-v13
`Evidence` shape (`type=`, `device=`, `independence_group=`, `domain=`), not the v13
`Evidence` dataclass this graph stores. `src/v13/ingest/sources.py`'s own module
docstring already says why: Suricata only runs in short batch invocations against
reactively-captured pcap bursts, not a continuous log stream, and wiring that into v13
"needs the whole reactive-capture trigger/dispatch subsystem, not a log tailer... NOT
attempted here." So Suricata alerts don't appear in the Threat Hunt or Evidence Graph
tabs — not a limitation of this console work, a pre-existing, already-acknowledged
scope cut one layer down.
