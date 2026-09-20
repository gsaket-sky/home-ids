# Memory-Driven Restarts: Root Cause + Capacity Planning Plan

**Status (2026-09-20, latest): Phases 1-4 all implemented, deployed to `.94`,
and verified.** Cadence verification AFTER deploying Phases 1-3 found the
restarts were still happening -- every ~12-14 minutes, WORSE than before --
from a completely different, previously-undiscovered cause (evidence-volume
flooding, not DB bloat). See "Root Cause #3" below for the full incident;
that fix is also now implemented, tested, and deployed. See "Implementation
status" near the end of this document for the concrete file-by-file list.

Written 2026-09-20 after a
live investigation on `.94` (read-only: `systemctl status`, `journalctl`,
`cgroup` files, and `SELECT`-only SQLite queries against the live
`state/v13_graph.db`; nothing was written to any live database or config, and
no service was restarted).

## Why this document exists

`soc.service` has been restarting every 1.5-3.5 hours on `.94` (8 restarts in
the 30 hours before this was written). The instinct was "memory leak or system
load." The real mechanism is more specific and more fixable than a classic
leak, and it directly blocks answering the user's real question -- "how many
devices can a Raspberry Pi 8GB handle" -- because right now the dominant
memory cost isn't proportional to device count at all. This doc is the single
place tracking: what's actually happening, why, what needs to change, and in
what order, so a future session (or a later phase of this one) doesn't have to
re-derive it.

## Confirmed root cause (not a guess -- traced to specific code and specific rows)

### 1. The restarts are `health_manager.py` working as designed, not a crash

`soc.service`'s cgroup shows `memory.events`: `oom_kill=0`. The kernel/cgroup
2GB hard cap (`MemoryMax=2G` in the systemd unit) has never fired. Instead,
`src/core/health_manager.py`'s own RSS-based pressure tiers
(`health_manager_rss_critical_mb`, default 1843MB) escalate to `CRITICAL`,
which after `health_manager_critical_sustain_checks` (default 3) triggers a
deliberate self-restart (`SIGTERM` to self, then `sys.exit(0)`) -- this is the
2026-09-14 `Restart=always` fix working correctly. The problem is what's
*feeding* RSS to 1843MB in 1.5-3.5 hours, every single cycle, indefinitely.

### 2. The feed: an 8.5GB SQLite graph DB for 13 devices

`state/v13_graph.db` measured 8.5GB on 2026-09-20, for a household with 13
devices, after ~24 days of the current architecture running. Broken down with
SQLite's `dbstat` virtual table:

| Table (+ its indexes) | Size | Rows | Status |
|---|---|---|---|
| `decisions` | 4.86 GB | 21,271 | **Root cause #1** |
| `edges` | ~3.6 GB (1.68GB + 3 indexes) | 15,069,462 | **Root cause #2** |
| `evidence` | 73 MB | (not counted) | Healthy -- retention confirmed working |
| everything else | < 60 MB combined | -- | Healthy |

**Root cause #1 -- unbounded evidence objects persisted into `decisions.raw_payload_json`.**

[`src/argus/decision/engine.py`](../src/argus/decision/engine.py) builds two
fields inside the dict `evaluate()` returns: `winning_evidence` (~line 486)
and `full_attack_evidence` (~line 540, keyed as `attack_evidence` in the
returned dict, ~line 561). These are lists of **full serialized Evidence
objects** (not IDs), built specifically so `pipeline.py`'s Telegram WHY-block
construction can render corroborating evidence that may have already aged out
of its own short-TTL in-memory store. That's a legitimate, narrow, transient
need for the *current cycle only*.

The bug: the exact same dict is passed as `raw_payload=decision` straight into
[`GraphStore.insert_decision()`](../src/argus/graph/store.py#L519), which
`json.dumps()`s the whole thing into `decisions.raw_payload_json` -- **forever,
uncapped**. Measured directly: one real row's `raw_payload_json` is 22.38MB;
`attack_evidence` alone is 13.3MB and `winning_evidence` is 6.97MB of that.
Row-size distribution is heavily skewed -- median is 3KB (healthy), but the
worst 100 rows (of 21,271) account for 1.77GB, and p99 is 2.4MB. These fields
are fully reconstructable after the fact via the `supports` edges +
`evidence` table lookup (this is *literally* what
[`decision_replay.py`](../src/argus/ops/decision_replay.py)'s
`get_decision_evidence()` already does), so persisting them a second time,
uncapped, inside the JSON blob is pure redundant bloat with no upside.

**Root cause #2 -- 2,779 legacy decisions never had the edge cap applied.**

`insert_decision()` already caps how many `evidence --supports--> decision`
edges a new decision creates
(`_MAX_SUPPORTING_EVIDENCE_EDGES_BY_PROFILE`: 25 for `pi_8gb`, 50 for
`x86_16gb`/`custom`) -- this fix is real, deployed, and working correctly for
every decision written *after* it landed. The problem is it's write-path only,
never retroactive. 2,779 of 14,311 decisions that have any `supports` edges
exceed the cap today; the worst has **68,915** edges to itself. Those rows
predate the cap and nothing has ever gone back to trim them.  `edges` is
94.7% `supports` (14,272,599 of 15,069,462 rows) -- this legacy backlog is
most of the table's size, not ongoing unbounded growth (new decisions are
correctly bounded already).

**Together these two account for ~8.46GB of the 8.5GB database.** Fixing them
is not a diet -- it's removing an actual bug's byproduct.

### 3. Pruning: partially working, not the root cause, but one gap to watch

- `evidence` retention (90 days, `x86_16gb` profile) and weak-tier
  `zeek_notice` retention (12h) are **confirmed working** -- `live_prune.py`
  last ran successfully (35.5h before this was written), deleted 65,881
  weak-tier notices per its 12h window. This is *why* `evidence` is only 73MB
  despite everything else. Don't touch this path; it's not part of the
  problem.
- `decisions` retention (`live_decision_archive.py`, 365-day window on
  `x86_16gb`, monthly cron `0 4 1 * *`) has **never run** -- but this is
  expected, not a bug: the job was added to the scheduler after 2026-09-01,
  so its first scheduled occurrence is 2026-10-01 04:00. **Re-check after
  that date** that it actually fires and records success in
  `state/job_health.json`. Even once it runs, 365-day retention won't delete
  anything for a system this young, and wouldn't have fixed Root Cause #1
  regardless (that's a per-row bloat bug, not a which-rows-are-too-old
  question).

### 4. Secondary finding: CPU quota drift (not a cause, but a landmine)

`soc.service`'s tracked unit file specifies `CPUQuota=40%`, with an explicit
comment explaining why (protect Pi-hole on the same box). The **live** cgroup
is actually running at `CPUQuota=200%` via an untracked
`systemctl set-property` drop-in
(`/etc/systemd/system.control/soc.service.d/50-CPUQuota.conf`). Current
throttling is minor (`nr_throttled` ~0.8% of periods) -- specifically *because*
of the 200% override. A future clean redeploy of the checked-in unit file
would silently drop back to 40% and likely reintroduce throttling-driven
backlog. This needs to be reconciled (understand why 200% was set, then
either fix the tracked file's comment+value or revert the override) --
tracked as Phase 5 below, not urgent but a real trap waiting for the next
full redeploy.

### 5. Not a concern

- Per-device ML models (`models/devices/*.pkl`): ~16MB total for 13 devices.
  Negligible next to the DB issue.
- WAL file (265MB) and a stale `v13_graph.db.pre-cleanup-backup-20260906_203544`
  (253MB) are disk hygiene, not RSS drivers, but should be cleaned up as part
  of Phase 2's maintenance pass regardless.

### 6. What's missing entirely: runtime memory/process profiling

There is currently **no memory profiling instrumentation anywhere in this
codebase** -- no `tracemalloc`, no periodic RSS/object-count breakdown, no
per-module attribution. `health_manager.py` knows *that* RSS crossed a
threshold, never *what* is holding the memory. This investigation only found
Root Causes #1/#2 by manually querying the SQLite file directly with ad hoc
scripts -- there's no standing capability to catch the next one of these
without another manual deep-dive.

## Why "how many devices can a Pi 8GB handle" can't be answered yet

The dominant memory/disk cost right now is a bug producing a small number of
pathological rows, not a steady-state per-device cost. Any benchmark built on
top of the *current* code would measure the bug, not real per-device scaling
-- an N=13 household hitting 8.5GB tells you nothing about what N=50 would
look like once the bug is fixed, because the relationship isn't linear in N
today. **Fix Phase 1 and 2 first; only then does a device-count-vs-memory
curve mean anything.**

## Plan

### Phase 1 -- Fix the write-path bug (stops new bloat)

In `GraphStore.insert_decision()` (or immediately before the call, in
`live_engine.py`'s `_write_graph()` -- decide at implementation time which is
more consistent with where the existing edge-cap logic already lives): strip
`attack_evidence` and `winning_evidence` from the dict *before* it's
`json.dumps()`'d into `raw_payload_json`. They stay in the in-memory `decision`
dict `evaluate()` returns (pipeline.py's WHY-block still needs them
same-cycle); they just never get persisted a second time. Also cap
`_all_evidence_ids` (currently unbounded, ~2MB on the worst legacy rows) the
same way -- store the count plus a capped sample, not the full list, matching
the honesty framing already used for the edge cap ("first-pass judgment call,
not empirically tuned").

Needs targeted tests (not the full 22-file suite -- ask before running that,
per standing rule) covering: a decision with 0 evidence, a decision under the
cap, a decision far over the cap (regression-test against the exact
68,915-edge shape found live), and confirming `decision_replay.py` still
reconstructs the same evidence via `supports` edges after the payload no
longer duplicates it.

### Phase 2 -- Retroactive cleanup migration (reclaims disk on existing data)

A one-time maintenance script, same family as `prune_evidence()`/
`delete_decisions()`, that for every existing decision:
- Trims excess `supports` edges down to the hardware-profile cap (same
  keep-most-recent-first logic `insert_decision()` already uses for new
  writes), reclaiming the bulk of the 3.6GB `edges` cost.
- Strips `attack_evidence`/`winning_evidence` from already-stored
  `raw_payload_json` for rows where they exist, reclaiming most of the 4.86GB
  `decisions` cost.
- Removes the stale `.pre-cleanup-backup-20260906_203544` file (253MB) after
  confirming it's no longer needed for anything.
- Runs `PRAGMA wal_checkpoint` and (if disk headroom allows -- needs 2x the
  DB's size temporarily) a `VACUUM` to actually shrink the file on disk, not
  just free internal pages.

**This touches the live `.94` database directly -- requires explicit
confirmation before running, per standing rule, and should run once as a
one-off with a full DB file backup taken immediately before.**

### Phase 3 -- Runtime memory/process profiling instrumentation -- IMPLEMENTED + DEPLOYED (2026-09-20), live on `.94`

`main.py` now calls `tracemalloc.start()` at the very top of boot (gated by
`health_manager_memory_diagnostics_enabled`, default `true`) -- has to start
before any real allocation happens, or a later snapshot has no history to
diff against. `health_manager.py`'s `_evaluate_resource_pressure()` now calls
`_maybe_capture_memory_diagnostics()` on every ESCALATING transition into
`CONSERVATION`/`CRITICAL` (not every transition -- recovering back to NORMAL
isn't informative here, and firing on every flap risked noise/overhead
exactly when the process is already under pressure). Each capture writes one
JSON line to `state/memory_diagnostics.jsonl`: top 15 allocations by
file:line (`tracemalloc`), a `gc.get_objects()` type histogram (top 20,
stdlib `collections.Counter` only -- no new dependency for the Pi target),
`fastapi`/`scheduler` subprocess RSS (`main`'s own RSS was already tracked),
and the graph db's size/WAL-size/decisions-and-edges row counts via a
short-lived read-only connection (never competes with `live_engine.py`'s own
long-held writer). Bounded at `_MAX_DIAGNOSTIC_ENTRIES` (500) -- a rewrite-
last-N pattern, not an unbounded append, matching every other retention
decision in this document.

**Resource-attribution follow-up, same day (explicit user request):** the
"deliberately not built" per-external-process scope-trim above was
un-deferred the same session. `_external_component_rss_mb()` does one
system-wide `psutil.process_iter()` scan per capture, matched against a
registry of real process names verified directly on `.94` (not assumed):
`zeek`, `suricata` (genuinely ephemeral -- only exists during a
reactive-capture burst, so absent is the expected common case), `prometheus`,
`prometheus-node-exporter`, `promtail`, `loki`, `ollama` (confirmed NOT
installed on `.94` at all today -- no service/binary/container; kept in the
registry so it's picked up automatically whenever it IS deployed), and
`grafana` -- which turned out to matter more than expected: its real
footprint is the main server PLUS 14 separate plugin-executor subprocesses
(`gpx_grafana-prometheus-datasource`, `gpx_sqlite-datasource`, etc.), *none*
of which contain "grafana" in their own process name -- a naive substring
match would have silently missed almost the entire thing. `gpx_grafana-lok`
(the Loki plugin) is also the exact false-positive risk that's why `loki`
itself matches on exact name, not substring -- confirmed via a dedicated
regression test that it lands only in the `grafana` bucket. CL-AFPE is
deliberately absent from this registry (it's in-process, part of the
already-measured "main" RSS, not a separate PID -- adding it would
double-count, not add coverage). Also added `_active_scheduled_job_processes()`
-- whichever of `scheduler_proc`'s children (any `scheduled_jobs.scheduler`
entry, including `live_llm_review.py`) happen to be actively running AT THE
MOMENT a capture fires, by script name + RSS -- usually empty (jobs are
short-lived), which is the value: catching the coincidence of a real
pressure spike with a specific job actively running. Stated purpose (user,
2026-09-20): a real per-component resource map to inform a future
resource-constraint decision on the Pi -- "what gets cut back first" --
rather than a guess.

Console-API surface still not built (genuinely deferred, not scope-trimmed
away this time -- the capture-and-log mechanism above is complete and is
this phase's actual deliverable). 24 targeted tests pass locally
(`tests/test_health_manager_memory_diagnostics.py` -- covering capture
triggers/shape/bounding/failure-isolation plus the new external-component
and scheduled-job attribution), plus all 65 pre-existing health_manager
tests still pass; found and fixed two real bugs during the original
implementation: `_graph_db_diagnostic_stats()` used `sqlite3` without its
own import -- silently swallowed by its own `except Exception: return {}`
-- and its read-only URI used an f-string instead of `Path.as_uri()`,
invalid on Windows even though it happens to work on every real Linux
deployment target; moved `sqlite3`/`tracemalloc`/`collections` to
module-level imports to fix the former.

### Phase 4 -- Device-count-vs-memory benchmark harness -- BUILT (2026-09-20), sweep not yet run

**No real Pi 8GB unit is available (explicit user answer, 2026-09-20)** --
simulating Pi constraints via cgroups on `.94` instead of real hardware.

**CPU calibration, researched not guessed**: looked up actual Geekbench 6
single-core scores rather than assume a ratio -- AMD Ryzen 5 3550H (`.94`'s
real CPU) scores ~1012, Raspberry Pi 5 scores ~770-774. That's a **1.31x**
gap -- much smaller than this document's own earlier "meaningfully faster
per-core" framing assumed before actually checking. `CPUQuota=76%`
(1/1.31) is the derived correction for a `systemd-run --scope` cgroup. This
corrects single-thread throughput only, not core-count/topology differences
(Pi 5: 4x Cortex-A76; `.94`: Ryzen 5 3550H, 4C/8T) -- a real Pi would still
give a more trustworthy number, per this doc's own open question below.

**`tools/benchmark_device_capacity.py`** drives the SAME real per-device
entry point `pipeline.py` itself calls -- `argus.ops.live_engine.evaluate()`
-- with synthetic evidence for N virtual devices, against an isolated state
dir (never the real `state/v13_graph.db`). Simulated time (an explicit,
advancing `now` passed to `evaluate()`, not real sleeps) so a multi-day
curve doesn't need multi-day wall-clock runtime. Traffic model calibrated
against `.94`'s own real measured rates from this same investigation (~530
evidence items/device/day, ~28 decision-state-changes/device/day), not
guessed.

Smoke-tested locally (3 devices, 1 simulated day, ~9.5s wall-clock): DB grew
to 4.11MB, ~1.37MB/device/day -- the same order of magnitude as Phase 5's
own analytical estimate (~1.67MB/device/day combining evidence+edges+
decisions), a reasonable cross-check that the synthetic traffic model isn't
wildly unrealistic.

**Important scope caveat, not yet resolved**: this harness measures ONLY
the `live_engine.evaluate()` code path's own RSS -- `GraphStore` +
`HypothesisEngine` + `DecisionEngine` + `BaselineEngine`. It does NOT run
Zeek/Suricata, the FastAPI/uvicorn process, the scheduler, LLM review,
CL-AFPE, or `health_manager.py` itself, all of which contribute to the REAL
`soc.service` process's RSS. The smoke test's own numbers (58.7MB baseline
-> 72.5MB after 1 day, 3 devices) are therefore NOT directly comparable to
the real 1843MB CRITICAL threshold -- concluding "a Pi could handle
thousands of devices" from this alone would be a real, live mistake. The
full N-sweep (13/25/50/100/200 devices x 7 simulated days each, run on `.94`
under the `CPUQuota=76%`/`MemoryMax=8G` cgroup) still needs to actually run
-- estimated wall-clock cost from the smoke test's own timing, roughly
linear in devices x days: ~2.5 hours for the full sweep sequentially.

### Phase 5 -- Capacity report + CPU quota reconciliation

Turn Phase 4's curve into a concrete number/range ("supports up to N devices
while keeping >X hours between forced restarts on 8GB"), and use the
measured data (not the current "first-pass judgment call" placeholders) to
set `pi_8gb`-specific retention/cache/cap values with actual justification.
Separately, resolve the CPUQuota drift found in section 4 above: understand
why 200% was set live, then either update the tracked unit file's value +
comment to match reality, or revert the live override -- don't leave the
tracked file lying about what's actually running.

## Data lifecycle retuning (added 2026-09-20, same investigation)

The user's stated principle: **don't keep anything in the live system that
HEE (the live decision loop) doesn't need; anything valuable for audit,
retroactive threat-intel cross-checking, or future model improvement should
be a *backup*, not live-DB weight.** This maps directly onto a hot/cold split
that the codebase already half-implements (`live_decision_archive.py`
exports decisions before deleting them) but doesn't apply consistently.
Surveyed every retention policy against its REAL consumers' actual lookback
needs (not the documented number) to answer "is daily cleaning appropriate":

### Current jobs and what actually reads each table

| Table | Current retention | Enforced by | Cadence | Real consumer need |
|---|---|---|---|---|
| `evidence` (general) | 90d (`x86_16gb`) / 30d (`pi_8gb`) | `live_prune.py` | daily 3:15am | Live HEE: seconds-minutes (in-memory `EvidenceStore`, not this table). Audit: as long as `decision_replay.py` needs it -- see gap below. |
| `evidence` (`zeek_notice_weak` only) | 12 hours | `live_prune.py` (same daily run) | daily 3:15am | Zero -- weak-tier contributes 0 scoring weight to any hypothesis. Pure noise once past its own dedup window. |
| `device_destinations` | 30d (flat, not profile-scaled) | `live_prune.py` | daily 3:15am | Peer-cohort baselining: 7 days. **`live_retro_hunter.py`'s threat-intel re-scan: 90 days** (`DEFAULT_DAYS_BACK = DEFAULT_EVIDENCE_RETENTION_DAYS`, not itself hardware-profile-scaled) -- see gap below. |
| `decisions` | 365d (`x86_16gb`) / 180d (`pi_8gb`) | `live_decision_archive.py` (export-then-delete) | monthly, 1st @ 4am | Console/UI + `decision_replay.py` regression testing. Slow-moving; row COUNT isn't the cost, row SIZE is (Root Cause #1 above). |
| `device_baselines` | none -- and needs none | n/a | n/a | Naturally bounded: `PRIMARY KEY (device_id, metric, hour, regime_id)` is an upsert, not an append log. Grows with device/metric cardinality, not with time or decision volume. 20,609 rows for 89 device_ids currently -- flagged below, separately, as worth checking why 89 when the household has 13 physical devices (likely stale rows under merged-away ephemeral MAC device_ids -- same shape as the dangling-reference class of bug already fixed elsewhere, not confirmed, not urgent). |
| `baseline_snapshots` | documented (30d full-res + weekly-thinned after) in `schema.sql`'s own comment | **nothing -- 0 rows exist, the pruning job schema.sql refers to was never built** | n/a | Not urgent today (table is empty), but don't forget this exists as a documented-but-unbuilt gap once this table starts being written to. |
| `threshold_history`, `backtest_runs`, `containment_actions` | none | n/a | n/a | Negligible volume today (backtest_runs: 0.7MB). Revisit only if they start growing -- no action now. |

### Is daily cleaning appropriate? -- table by table, not a single answer

- **`evidence` general sweep: yes, daily is fine.** This data isn't
  time-critical to prune faster -- nothing breaks by a row surviving 12 extra
  hours past its 90-day cutoff. Daily already keeps this table at 73MB.
- **`zeek_notice_weak`: daily is looser than the stated 12-hour policy in
  practice.** Because it only gets swept once a day, a weak notice created
  just after the 3:15am run effectively lives ~23-24 hours, not 12 --
  roughly double the stated SLA at the peak, even though the end-of-day
  measured size (73MB) already looks fine. Given this data has zero
  detection value and deletion is a cheap indexed operation, recommend
  splitting it into its own job on a **4-6 hour cadence** so peak live-table
  size stays flatter, rather than sawtoothing between prunes. Low cost, no
  behavior risk (it's provably worthless data).
- **`decisions`: monthly is appropriate, don't change the cadence.** This
  is a slow, year-scale retention policy for audit purposes; the actual
  problem was never how often it runs, it's Root Cause #1 (row size). Once
  Phase 1/2 land, decisions become small rows and monthly archival is the
  right rhythm for something meant to be a durable audit trail, not
  operational data.
- **`device_destinations`: retention window itself is wrong, not the
  cadence.** 30-day retention is *shorter* than `live_retro_hunter.py`'s own
  declared 90-day re-scan window -- meaning any destination touched 31-90
  days ago is silently invisible to retroactive threat-intel cross-checking
  today, a real coverage gap for exactly the "robust... cross-checking"
  goal the user named. Fix: extend `device_destinations` retention to match
  the real consumer (90 days, or hardware-profile-scaled to match whatever
  `live_retro_hunter` actually uses per profile) -- this table is currently
  0.6MB, so extending it 3x costs nothing.
- **Everything else: no pruning needed at today's volumes.** Don't build a
  cleanup job for a table that's empty or naturally bounded; that's
  premature-abstraction work with no current payoff (`baseline_snapshots` is
  the one to remember once it starts being written).

### The real gap: deletion without backup -- and the production decision on it

`prune_evidence()` (the general 90-day sweep) is a hard `DELETE`, full stop
-- no export step, unlike `live_decision_archive.py`'s deliberate
export-then-delete pattern. Once evidence ages out, it's gone today.

**Explicit decision (2026-09-20, user):** production must run forever with
zero unrestricted growth, everything capped, no exceptions -- matching the
standing project philosophy already in place elsewhere (Pi-target design
constraints, [[feedback_pi_target_and_v13_execution]]). An open-ended,
ever-growing archive violates that even if it's "just" 2-3GB/year, because
"just a few GB/year, forever" is still unbounded growth on a box meant to run
unattended indefinitely. So: **no always-on archive in production.**

Instead: add a single config key (e.g. `archive_network_activity_backup`,
default `false`) that gates whether `prune_evidence()` (and
`live_decision_archive.py`, which already exports but could still be toggled
for symmetry) export before deleting.
- **Production (`false`, the default):** pure delete, exactly like today,
  zero unbounded-growth risk. The hot DB's own retention windows (correctly
  tuned per the section above -- e.g. `device_destinations` extended to match
  `live_retro_hunter`'s real 90-day need) are the ENTIRE audit/cross-check
  capability in production. There is no second copy anywhere. This means
  retention-window correctness matters more, not less -- a window that's too
  short in production is a real, permanent loss, not just an inconvenience.
- **Testing/dev (`true`):** export-then-delete, giving a developer
  investigating a real incident, tuning the autotuner, or validating
  `decision_replay.py` a full historical record to work from. No rotation
  cap needed on this path -- it's for controlled, temporary diagnostic
  sessions, not a second production deployment, so open-ended growth there
  is an accepted, understood tradeoff, not a design flaw.

### Retuning changes to make (folded into Phase 1/2 below, not a new phase)

1. Add the `archive_network_activity_backup` config toggle (default `false`)
   to `prune_evidence()`, gating an optional export-before-delete path,
   mirroring `live_decision_archive.py`'s existing pattern when enabled.
2. Split `zeek_notice_weak` pruning out of the daily 3:15am `live_prune.py`
   run into its own 4-6 hour cadence (or add a second, cheaper invocation of
   the same job scoped to just that evidence_type).
3. Extend `device_destinations` retention to match `live_retro_hunter.py`'s
   actual 90-day (or profile-scaled) lookback instead of the current flat,
   too-short 30 days -- this is now load-bearing for audit capability in
   production, not just a nice-to-have, since there's no archive fallback.
4. Note for a future session: check why `device_baselines` has 89 distinct
   `device_id`s against 13 real devices -- possible dangling rows from
   merged-away ephemeral MACs, same class of bug as the already-fixed
   dangling-edge issue. Not urgent (this table doesn't bloat from it either
   way, since it's upsert-keyed), but worth a look once higher-priority
   Phase 1/2 work is done.

## Root Cause #3: evidence-volume flooding (found 2026-09-20, AFTER deploying Phases 1-3)

Cadence verification -- the actual point of this section, done right after
deploying Phases 1-3 -- found the restarts had NOT stopped. They'd gotten
**worse**: every ~12-14 minutes, versus the original 1.5-3.5 hours. This is a
different bug from Root Causes #1/#2, not a regression from today's fix (the
fix is confirmed working: newest decisions checked live were ~41KB, not 22MB,
and `attack_evidence`/`winning_evidence` are correctly absent from stored
payloads).

**Diagnosis** (all read-only against `.94`'s live system): the restarts were
`pipeline_main_loop -> UNHEALTHY (heartbeat stale for 312s, expected ~60s)` --
the PER-COMPONENT heartbeat state machine, not the RSS-based resource-pressure
tier this whole document was otherwise about. The dying process had consumed
6m14s of CPU over an 11m12s stall -- busy the whole time, not blocked/idle.
Found the cause: one real device (a smart TV, `2d313502b7d0`) generated
**41,509 evidence rows in 24 hours** (39,551 `zeek_notice_weak`, ~1 every
2.2s non-stop). The SQL query itself was fast (0.225s, correctly used
`idx_evidence_device_ts`) -- the cost was constructing and iterating 41,509
`Evidence` objects through the full HypothesisEngine (~20-30 separate O(N)
hypothesis checks, no single one quadratic, but K checks x N items adds up
fast) EVERY 2-second decision cycle, for one device, blowing the 60s
heartbeat deadline. Also found, same device: 180,274 rows of the OLD,
unfragmented `zeek_notice` type (not `_weak`/`_medium`), dated 10.8-13.9 days
ago -- pure historical debt from before the tier-classification fix landed
weeks ago, never cleaned up because it doesn't match the exact string
`prune_weak_zeek_notices()` filters on, sitting under the general 90-day
retention. Not the active cause (new writes are correctly classified), but
real, unaddressed debt.

**Why the obvious fix (exclude weak-tier from the live window) would have
been WRONG** -- checked before implementing, not assumed: `zeek_notice_weak`'s
confidence is a FIXED per-tier constant (0.4, `ZEEK_NOTICE_TIER_CONFIDENCE`),
and its family (`network_behavior`) IS in `_PARTIAL_SUPPORT_FAMILIES`,
feeding `evidence_verification_required` via an averaged `hypothesis_weight`
across all partial-support evidence. A blanket exclusion would have silently
broken that signal. But this is ALSO a latent scoring bug in its own right:
averaging thousands of identical 0.4 values together with a handful of
genuinely distinct signals can swamp real evidence down toward 0.4,
regardless of what the real signal actually shows -- duplicated observations
of the same tier carry zero additional information.

**The actual fix, network-agnostic per explicit user request** (not scoped
to zeek or to weak-tier specifically -- ANY evidence_type could flood this
way for a genuinely infected/misbehaving device, not just routine smart-TV
noise): `GraphStore.get_evidence_for_device()` gained an optional
`cap_per_type` parameter (`None` preserves the original, fully-unbounded
behavior for every audit/replay consumer) -- when set, at most N most-recent
rows of any ONE `evidence_type` get constructed into `Evidence` objects per
device, via a cheap distinct-types query plus one `LIMIT`-bounded,
most-recent-first query per type (2 round trips total, never one unbounded
fetch). `_MAX_EVIDENCE_PER_TYPE_IN_WINDOW_BY_PROFILE` (50 `pi_8gb` / 100
`x86_16gb`/`custom`) matches the existing profile-scaled-cap convention
already used for supporting-evidence edges. `live_engine.py`'s
`_query_graph_window()` (the actual live per-cycle call site) now passes this
cap. Confirmed mathematically lossless for the case that motivated it (a
fixed-confidence tier): averaging any subset of identical values gives the
identical result, and `independence_families` is already a Python `set` (only
ever affected by which DISTINCT families are present, never by within-family
volume) -- this cap only removes redundant, informationally-empty duplicates,
never genuine signal, and a real sustained attack still keeps every relevant
item up to the cap.

**A second, worse instance found by systematically checking siblings** (user
asked: is this hiding elsewhere -- evidence graph, HEE, Suricata?):
`window.py`'s `domain_seen_before()` -- "has this device ever contacted this
destination" -- called `get_evidence_for_device()` across up to a 90-day
lookback just to answer a yes/no question, meaning a device with a large
history could pay the FULL unbounded-fetch cost for a pure existence check.
Replaced with `GraphStore.evidence_for_destination_exists()`, a targeted
`SELECT 1 ... LIMIT 1` that short-circuits on the first match using the same
index -- identical result (verified against the pre-existing
`test_argus_graph_window.py` suite, unchanged, all still passing), without
ever constructing an `Evidence` object.

**Checked and confirmed CLEAN, not just assumed:**
- **HEE** (`hypotheses/engine.py`): ~20-30 hypothesis checks, each a plain
  `any()`/list-comprehension linear scan over the evidence list -- O(K x N),
  no quadratic pattern found. Fixing the INPUT size (both fixes above)
  proportionally fixes HEE's own exposure too; no separate HEE-side change
  needed.
- **Suricata** (`intelligence/detectors/suricata_scan.py`): write-only,
  batch/reactive-invocation based (confirmed earlier in this same
  investigation -- it only runs against a specific burst pcap file, not a
  continuous stream) -- never reads back historical per-device evidence at
  all, so it doesn't share this bug class.

**Flagged, not fixed (lower priority, structurally different)**:
`live_engine.py`'s DGA coordinated-targeting check calls
`get_evidence_by_type_since()` -- cross-device, ONE evidence_type, scoped to
`_COORDINATED_TARGETING_WINDOW_SECONDS` -- theoretically the same bug class
(system-wide DGA evidence volume, not one device's spam) but no live evidence
it's actually large in practice today. Worth the same cap treatment if it
ever is.

**Testing**: `tests/test_argus_graph_store.py` (cap_per_type correctness,
most-recent-first ordering, `evidence_for_destination_exists` correctness),
`tests/test_argus_graph_window.py` (pre-existing `domain_seen_before` suite,
unchanged, confirms the rewrite is behavior-identical), `tests/
test_argus_live_engine.py` (new section K: confirms `_query_graph_window()`
actually applies the cap end-to-end, not just that the primitive exists in
isolation), plus the FULL `test_real_world_alert_regression.py` suite (every
real historical incident's verdict unchanged) -- all passing.

## Storage capacity projection (added 2026-09-20)

Two different resources, easy to conflate: "Raspberry Pi 8GB" names the RAM
target; disk (SD card or USB SSD) is a separate, independently-sized
resource, and it's what this section answers. With the archive OFF in
production (decided above), **total disk footprint is just the hot DB,
which is bounded by design once Phase 1/2 land** -- there is no second,
unbounded number to add on top.

Estimated steady-state hot-DB size, using .94's real measured event rates
(29,157 evidence rows/day, 1,543 decisions/day, system-wide, at today's ~13
real / ~55 tracked-identity household) combined with each profile's
configured retention windows -- **first-pass estimates, not yet measured**,
since they assume a post-fix average decision-row size (~8KB) inferred from
stripping the bloat out of one sample row, not confirmed at scale:

| Profile | Evidence + its edges (30d/90d) | Decisions (180d/365d) | Decisions' own edges | **Total steady-state** |
|---|---|---|---|---|
| `pi_8gb` (30d evidence / 180d decisions) | ~544MB | ~2.22GB | ~144MB | **~2.9GB** |
| `x86_16gb`/`custom` (90d / 365d) | ~1.6GB | ~4.5GB | ~860MB | **~7.0GB** |

Non-obvious point worth remembering: fixing Root Causes #1/#2 cuts the
*daily growth rate* by ~95%, but does NOT mean the DB stays tiny forever on
`x86_16gb`/`custom` -- that profile deliberately keeps decisions a full
year, so steady state still climbs to several GB over that year through
normal, legitimate, BOUNDED growth (not the current runaway kind). The
`pi_8gb` profile's shorter windows keep the real ceiling meaningfully lower
(~2.9GB), which is exactly the reason that profile exists as a separate,
tighter-tuned config rather than just reusing `x86_16gb`'s defaults.

Either number is trivial against any SD card or USB SSD capacity -- this
was never actually a disk-capacity problem once bounded; it was an RSS/query
problem from a small number of oversized rows. Phase 4's benchmark harness
should confirm (or correct) these estimates once Phase 1/2 are implemented,
using the SAME event-rate-times-retention-window method, scaled across the
N-device sweep.

## Disk write patterns and SSD/SD-card wear (added 2026-09-20)

The user asked whether the read/write pattern could damage the SSD (and, on
the real Pi target, a microSD card or USB SSD -- both far more wear-sensitive
than `.94`'s server-grade NVMe). Important framing up front: **flash wear is
a write-cycle concern, not a read concern** -- reads are effectively free.
"Prefetching" therefore only helps latency/performance (keeping hot files in
the OS page cache), not wear; the actual wear question is about write
volume, write pattern (scattered-random vs. sequential-batched), and fsync
frequency. Checked all three, live on `.94`:

### 1. SQLite fsync frequency -- a real, fixable finding

`state/v13_graph.db` is correctly in WAL mode (`schema.sql` sets it), which
is already the SSD-friendlier choice (sequential WAL appends + periodic bulk
checkpoint, instead of rollback-journal mode's per-transaction journal
file churn). Per-cycle writes are also already batched into one
`transaction()`/commit in `_write_graph()`, not one commit per insert.

But the live PRAGMA values show `synchronous=2` (`FULL`) -- SQLite's
default, never overridden anywhere in this codebase. Under WAL mode with
`synchronous=FULL`, SQLite `fsync()`s the WAL file on **every single commit**.
SQLite's own documentation explicitly recommends `synchronous=NORMAL` (`1`)
as the standard pairing with WAL mode: it's still crash-safe (the DB file
itself can never be corrupted by a power loss under WAL mode regardless of
this setting), the only risk is losing the most-recently-committed
transaction(s) if power is lost in the exact instant before a checkpoint --
an acceptable tradeoff here, not financial/safety-critical data. This is a
one-line change (`PRAGMA synchronous = NORMAL` in `schema.sql`'s init) that
directly cuts fsync frequency, which is the dominant lever for both write
latency and flash wear -- much higher-value than anything else in this
section, and effectively zero risk.

### 2. Swap -- currently a real wear contributor, self-resolves with Phase 1/2

`vm.swappiness=60` (Linux default, fairly eager to swap), and the swap
partition (`nvme0n1p4`) is on the **same physical NVMe device** as
everything else (`/home` is `nvme0n1p8`) -- confirmed 255MB actively swapped
right now. Frequent small random writes from swapping are one of the worst
patterns for flash wear. This should improve substantially once Phase 1/2
land (RSS won't be climbing toward the cgroup's `MemorySwapMax` ceiling
every 1.5-3.5 hours), but two additional, independent points worth acting on
regardless:
- Lower `vm.swappiness` (e.g. to 10-20) so the kernel prefers reclaiming
  page cache over swapping out anonymous memory, given this box's actual
  workload profile.
- **For the real Pi 8GB target specifically**: don't use a disk-backed swap
  file/partition on the SD card/SSD at all. Use `zram` (compressed,
  RAM-only swap -- zero disk writes) instead. This is already standard,
  widely-documented Raspberry Pi practice specifically because SD cards wear
  out from exactly this write pattern; worth building into whatever install/
  setup process eventually ships for Pi deployments.

### 3. Zeek's raw logs -- a NEW finding, larger than the graph-DB issue, zero retention today

`/opt/zeek/logs` is **7.5GB**, spanning **83 daily subdirectories back to
2026-06-14**, growing at roughly 300-500MB/day recently. The good news:
Zeek's own rotation is already well-configured -- hourly rotation, already
gzip-compressed. The bad news: **nothing has ever deleted an old day's
logs.** This has been silently accumulating for over three months with zero
retention policy, on a completely separate code path from everything else
investigated in this document (Zeek's own log rotation, not anything in
`src/argus/`).

This matters more than it might first appear: unlike the SQLite tables,
HEE never reads these archived raw logs at all -- the live pipeline consumes
Zeek's real-time tail/spool output as it's generated (`current/`, a symlink
into the live spool), extracting evidence from it immediately; the
dated/archived directories exist purely as a historical byproduct with no
consumer anywhere in this codebase. By the exact same principle already
applied to the graph DB ("don't keep data HEE doesn't need, unless it's a
deliberate, capped audit/backup decision"), this needs an actual retention
job -- there currently is none. At recent growth rates this would eventually
consume `.94`'s entire 384GB disk (currently 71% used, 115GB free) within
under a year even on generous server hardware; a Pi's typically much
smaller SD card/SSD would fill far sooner. **This should be added to Phase
2's scope**: a scheduled job (matching the `live_prune.py` family's shape)
that deletes Zeek's own dated log directories past a retention window --
likely a much shorter one than the graph DB's, given nothing reads them
back automatically today (a manual forensic-investigation window, e.g. 7-14
days, is a reasonable starting point, pending the user's own preference on
how long they want raw packet-derived logs kept for manual review after an
incident).

### 4. Memory optimization / "prefetching" -- clarifying what actually helps here

Since reads don't wear flash, the memory-side lever isn't about protecting
the drive -- it's about reducing redundant disk I/O for performance, which
matters more once the box is memory-constrained (a Pi, not `.94`'s 12GB).
`GraphStore`'s `cache_size` PRAGMA is already hardware-profile-scaled
(48MB on `pi_8gb`, first-pass/not-yet-empirically-tuned per its own
comment). Reference files that are read repeatedly but rarely change
(GeoLite2 `.mmdb` files, ~78MB combined; the fastembed cache, ~129MB) will
stay warm in the OS page cache naturally as long as there's enough free RAM
for the kernel to hold them there -- which is really just another downstream
benefit of Phase 1/2's RSS fix (less of the Pi's 8GB consumed by the leak
means more left over for the OS to cache these files in), not something
that needs its own separate prefetching mechanism given how modest these
file sizes are.

## Implementation status (2026-09-20)

All of the below is implemented and covered by targeted tests run locally
(`tests/test_argus_graph_store.py`, `test_argus_live_prune.py`,
`test_argus_live_retro_hunter.py`, `test_argus_live_prune_weak_notices.py`,
`test_argus_zeek_log_prune.py`, `test_argus_decision_bloat_cleanup.py` -- all
passing, run individually, not the full suite). Not yet deployed to `.94`.

- **Root Cause #1 fixed**: `GraphStore.insert_decision()` (`src/argus/graph/
  store.py`) now strips `attack_evidence`/`winning_evidence` before
  persisting, and caps `_all_evidence_ids` at `_MAX_ALL_EVIDENCE_IDS_STORED`
  (1000) instead of leaving it fully unbounded -- kept, not removed, because
  `autotune/reset.py`'s blast-radius calculation genuinely reads it back.
- **SSD wear fix**: `PRAGMA synchronous = NORMAL` now set per-connection in
  `GraphStore.__init__()` (not `schema.sql`, which only runs for a brand-new
  db file and would never have reached `.94`'s real, already-existing one).
- **`archive_network_activity_backup` toggle** added (default `false`,
  `config.yaml.example`), wired into `prune_evidence()`'s new optional
  `archive_path` parameter -- production stays a pure delete; a dev/test
  session can opt in to a compressed, append-only `state/evidence_archive/
  *.jsonl.gz` export-before-delete.
- **`device_destinations` retention** fixed in `live_prune.py` to reuse
  evidence's own profile-scaled `retention_days` instead of a flat 30 --
  closes the real gap where `live_retro_hunter.py` needed up to 90 days but
  the table only kept 30. `live_retro_hunter.py`'s own lookback is now
  ALSO profile-aware (was a flat 90 regardless of profile) so it can never
  request more history than the graph actually retains.
- **`zeek_notice_weak` pruning** split into its own job
  (`src/argus/ops/live_prune_weak_notices.py`, every 4h) instead of riding
  along on `live_prune.py`'s much more expensive daily full-table scan.
- **Zeek raw-log retention** (the new finding, larger than the graph-DB
  issue): `src/argus/ops/zeek_log_prune.py`, daily, deletes dated log
  directories past `zeek_log_retention_days` (default 14, per explicit user
  decision).
- **Phase 2, the retroactive migration**: `src/argus/ops/
  decision_bloat_cleanup.py` -- a one-time, NOT-scheduled script. Defaults to
  `--dry-run` (report only); `--apply` always backs up the db file first
  (skippable only with `--no-backup`), trims every over-cap decision's
  `supports` edges down to the hardware profile's cap (keeping the
  most-recent-by-evidence-timestamp ones, matching `insert_decision()`'s own
  ordering), strips any lingering `attack_evidence`/`winning_evidence` from
  already-stored rows, then runs `PRAGMA wal_checkpoint(TRUNCATE)` + `VACUUM`
  to actually shrink the file on disk. Idempotent -- a second run against an
  already-clean db reports zero remaining work.
- **Stale file cleanup**: `.gitignore` updated (already pushed, commit
  `b658976`) to stop `fp_calibration.json`/`.deployed_commit`/`*.bak` from
  ever showing as untracked again. ~362MB of confirmed-unreferenced backup
  files on `.94` identified and approved for deletion (not yet executed --
  bundled into the same deploy pass as everything else here).

**Deployed to `.94` (2026-09-20, same session)**: commit+push, `git pull` +
`soc.service` restart, the two new `scheduled_jobs` entries + config keys
added to `.94`'s real `config.yaml`, ~362MB of stale backups deleted, and
`decision_bloat_cleanup.py --apply` run against the live database (service
briefly stopped for a clean VACUUM) -- **13,734,175 excess edges removed,
~4.56GB of JSON bloat stripped, db 9.13GB -> 957MB**, integrity verified,
`soc.service` restarted cleanly.

**Additional finding while first-running `zeek_log_prune.py`**: every dated
Zeek log directory was `drwxr-sr-x root:zeek` (group has read+execute but NOT
write -- `zeek.service`'s unit file set no `UMask`, so `zeek-archiver`
inherited systemd's default `0022`). `user` (the account `soc.service`,
and this job, run as) genuinely could not delete these regardless of group
membership -- deleting a file needs write on its CONTAINING directory, not
just the parent. User explicitly chose fixing this at the source over
baking `sudo` into the scheduled job itself (user already has unrestricted
passwordless sudo on this box, pre-existing, not something this session
introduced -- but using it from inside a recurring app job was judged riskier
than necessary here). Fix, live on `.94`: added `UMask=0002` to
`/etc/systemd/system/zeek.service` (backed up as `zeek.service.bak-
pre-umask-fix-20260920` first), `daemon-reload` + restart so all FUTURE
rotated directories are created group-writable; one-time `sudo chmod -R g+w
/opt/zeek/logs` to fix the 83 directories that already existed. Re-ran
`zeek_log_prune.py` immediately after: 68 directories deleted, 7.5GB -> 2.4GB
(15 days remaining), zero errors. **This unit-file change lives only on
`.94`'s live system, not in this git repo** -- a fresh Zeek install/reinstall
on any other box (including `.19`, or a future Pi deployment) would need the
same `UMask=0002` addition re-applied by hand; there is no installer script
in this repo yet that would carry it automatically.

Still not done: verifying the restart-cadence fix actually holds (needs
several hours of observation), deleting the migration's own 9.1GB safety
backup once that's confirmed, Phase 3 (runtime profiling instrumentation),
Phase 4 (the device-count-vs-memory benchmark harness), Phase 5 (an actual
Pi capacity number + the still-unresolved CPUQuota 200%-live-vs-40%-tracked
drift), and the `device_baselines` 89-vs-13-device_id anomaly noted earlier
(flagged, not investigated). `.19` was not touched at all this session --
if it runs the same graph-store code, it likely has the identical bloat,
unconfirmed either way.

## HANDOVER for another session: identity-merge races + device_baselines 89-vs-13 (2026-09-20)

**Update, same day, continuation session: Bug A below is now FIXED (not yet
deployed to `.94`).** Bug B and the device_baselines cleanup are still open --
see their own status notes further down. Everything in this section was
originally either a direct log quote/traceback from `.94` or a file:line read
directly, not inferred.

### The original anomaly: device_baselines has 89 distinct device_ids for ~13 real devices

Flagged earlier in this same investigation (see the data-lifecycle retuning
section above) and never dug into until now. Root cause turns out to be the
SAME identity-merge machinery as the two bugs below -- ephemeral MACs each
cold-start as their own `device_id` before (if ever) being merged into a
canonical one, and `device_baselines` is keyed by `device_id` with no
cleanup path when a device_id is later merged away. Not urgent on its own
(the table is naturally bounded -- `PRIMARY KEY (device_id, metric, hour,
regime_id)` is an upsert, not an append log -- so this doesn't bloat over
time), but it's a visible symptom of the two real bugs below, not its own
separate root cause.

### Bug A: `merge_into_canonical()` can abort, leaving BOTH sides stuck -- FIXED

Real log lines from `.94`, `state_guard.py` (the v1/legacy identity code,
`core/state_guard.py`), 4 occurrences in the last 14 days:

```
Sep 19 10:34:50 WARNING home_ids.state_guard merge_into_canonical() aborted: canonical_id 9989de06dc0f is not a currently tracked device (orphan_id=ad5456a8b6b0 left untouched).
Sep 19 10:34:50 WARNING home_ids.state_guard merge_into_canonical() aborted: canonical_id 513f41778e73 is not a currently tracked device (orphan_id=ad5456a8b6b0 left untouched).
Sep 19 10:34:50 WARNING home_ids.state_guard merge_into_canonical() aborted: canonical_id 08bdb9a778c2 is not a currently tracked device (orphan_id=e354d31fd1b1 left untouched).
Sep 19 10:36:02 WARNING home_ids.state_guard merge_into_canonical() aborted: canonical_id ad35ae47e5b6 is not a currently tracked device (orphan_id=10e395c31555 left untouched).
```

**Root cause, confirmed by reading `merge_into_canonical()` and
`resolve_device_id()` in full (the concrete next step this handover called
for):** `resolve_device_id()`'s IP/hostname/MAC-fallback branches
(`stable_device_id()`) are pure, state-unaware hashes of the input string --
they have zero memory of a device_id they minted before that's since been
discarded via a successful `merge_into_canonical()` call. A device that's
already MAC-anchored to a canonical identity can still hit a **per-flow MAC
capture miss** (Zeek didn't log `orig_l2_addr` on that one specific flow, even
though the MAC IS known elsewhere for the same device) -- when that happens,
`resolve_device_id()` falls through to the plain IP-hash branch and
regenerates the EXACT SAME hash as the device_id that was already merged away
and deleted. `get_or_create()` then silently resurrects a zombie DeviceState
under that dead id and rebinds `_ip_to_device_id` to it, stealing that
address's future traffic from its real canonical identity -- and, separately,
if some OTHER address for the same physical device attempts a merge against
that resurrected id as a "canonical" target before it exists, that's the
"aborted: canonical_id X is not a currently tracked device" log line. This is
also the real root cause of the `device_baselines` 89-vs-13 anomaly noted
above: each such transient zombie writes at least one baseline row under a
device_id that's gone again within a cycle or two.

**Fix (this session):** a new flat, persisted `StateManager._merge_redirects`
map (dead orphan_id -> live canonical_id, kept flat/single-hop by
`merge_into_canonical()` itself, capped at `_MAX_MERGE_REDIRECTS = 5000`,
survives a restart via `flush_to_disk()`/`load_from_disk()` the same way
`_ips_state`/`_action_ledger` already do). `resolve_merge_redirect()` is
consulted at every return point of BOTH `resolve_device_id()` overrides in
this codebase -- `core/identity.py`'s (the v1/legacy path) AND
`argus/identity/live_manager.py`'s `LiveIdentityManager.resolve_device_id()`
(the actual class running on `.94` -- it fully overrides the method rather
than delegating to the v1 version, confirmed by reading `live_manager.py`'s
own docstring, so the v1 fix alone would NOT have covered production). Also
re-checked defensively inside `merge_into_canonical()` itself (resolves both
`orphan_id` and `canonical_id` through the same map before doing anything),
so the method self-heals even against a stale id from a caller that isn't
`resolve_device_id()`. Verified via a real repro of the exact live failure
mode (merge, then re-resolve the orphan's own address with a simulated
MAC-capture miss) in both `tests/test_phase39_retroactive_identity_merge.py`
(v1 path, Section G) and `tests/test_argus_live_identity.py` (the live
`LiveIdentityManager` path, Section H) -- plus chain-flattening and
flush/reload persistence checks. Full existing identity/state-guard test
suite and the real-world alert regression suite both re-run clean, no
regressions. **Not yet deployed to `.94`** as of this write-up -- needs the
same commit -> push -> pull -> restart sequence every other fix this session
went through.

### Bug B: a `KeyError` here skips the ENTIRE decision cycle, not just one device

Real traceback, `.94`, twice on 2026-09-20 alone (07:02:29 and 14:49:32):

```
ERROR home_ids.state_guard Lock error: State for 'f3aaf1d0bca9' does not exist.
ERROR home_ids.pipeline Unhandled error during pipeline step execution: "Device state for 'f3aaf1d0bca9' does not exist in StateManager store."
Traceback (most recent call last):
  File "core/pipeline.py", line 1012, in run
    self._step(...)
  File "core/pipeline.py", line 1170, in _step
    with self.state_manager.lock_device(dev_id) as state:
  File "core/state_guard.py", line 170, in lock_device
    raise KeyError(f"Device state for '{device_id}' does not exist in StateManager store.")
```

`lock_device()` (`state_guard.py:165-172`) raises `KeyError` if `device_id`
isn't in `self._states` at call time. Confirmed directly (`pipeline.py:1167`):

```python
for dev_id in self.state_manager.get_all_device_ids():
    with self.state_manager.lock_device(dev_id) as state:
```

`get_all_device_ids()` returns a snapshot; `lock_device()` is called per
device INSIDE the loop. If a device is removed from `_states` (merged/
discarded) in the window between the snapshot and that device's turn in the
loop -- exactly the kind of concurrent identity-reconcile activity Bug A's
own log lines show happening -- `lock_device()` raises. That exception is
only caught at the OUTER `run()` loop (`pipeline.py:1009-1014`), one level
above `_step()`, not per-device inside the loop. **Real, confirmed blast
radius: every device later in that same cycle's iteration order gets
silently skipped, not just the one that was actually merged away** -- a
single mid-cycle merge can cost an entire decision cycle's coverage across
the whole fleet, not one device's.

Confirmed for this specific device: `f3aaf1d0bca9` was merged away hours
LATER the same day (18:55:01, "orphan f3aaf1d0bca9 discarded... redirected
to canonical 162a1335b869 (AppleWatch-User)") -- so either this device
churns in and out of tracking multiple times (plausible for MAC-rotating
devices), or there's an earlier merge/discard for the same id outside the
window checked. **Not yet confirmed**: whether this specific KeyError
always correlates with a concurrent merge (would confirm the race theory
outright) or can also happen some other way (e.g. a device genuinely never
added to `_states` reached via a stale reference from elsewhere) -- that's
the other concrete next step, alongside Bug A's source read.

### Bonus finding (lower priority, this session's own doing, not pre-existing): lost writes under lock contention

Found live tonight while running this session's own manual cleanup scripts
against the SAME live `state/v13_graph.db` the running service holds a
long-lived connection to:

```
ERROR home_ids.v13_live_engine Failed to write evidence/decision to GraphStore for device '2d313502b7d0' -- the live decision itself is already made and unaffected by this: database is locked
sqlite3.OperationalError: database is locked
```

`_write_graph()`'s best-effort try/except (`live_engine.py`) catches
`sqlite3.OperationalError: database is locked` and logs it, but does NOT
retry -- that cycle's evidence/decision write is silently lost (the live
DECISION itself was already made and returned before this runs, so nothing
about detection accuracy is affected, only the durable audit trail for that
one cycle). This specific occurrence was self-inflicted (this session's own
`live_prune_weak_notices.py`/`zeek_log_prune.py`/`decision_bloat_cleanup.py`
invocations competing with the live writer), not a standing bug -- but the
underlying gap (no retry-with-backoff on transient lock contention) is real
and would also fire under any OTHER source of write contention. Worth a
short `busy_timeout`-based retry if this recurs outside of manual
intervention.

### Suggested next steps for the session that picks this up

1. ~~Read `state_guard.py`'s `merge_into_canonical()` in full...~~ DONE --
   Bug A fixed this session, see above. Still open: deploy to `.94`.
2. Decide whether `pipeline.py:1167`'s device loop should catch `KeyError`
   PER-DEVICE (skip just that one device, log, continue the loop) rather
   than letting it propagate and abort the whole `_step()` call -- this
   alone would contain Bug B's blast radius. Bug A's own fix reduces how
   OFTEN a device goes missing mid-cycle (no more zombie churn), but doesn't
   eliminate every legitimate concurrent-merge window, so Bug B's
   containment fix is still independently worth doing.
3. Once Bug B is also addressed, revisit whether `device_baselines`' 89-vs-13
   device_id count drops back toward the real device count on its own now
   that Bug A's zombie-churn source is closed, or whether a separate
   one-time consolidation of any pre-fix stray baseline rows into their
   canonical device_id is still needed on top.

## Open questions for later phases, not blocking Phase 1

- Where exactly should the payload-stripping live -- `store.py` (centralizes
  it next to the existing edge cap, applies to every caller) vs.
  `live_engine.py` (keeps `store.py` a dumber, more general-purpose graph
  layer)? Decide during Phase 1 implementation, not now.
- Does a real Raspberry Pi 8GB unit exist to benchmark on directly, or is
  Phase 4 entirely cgroup-simulated on `.94`? Real hardware would remove the
  CPU-performance-correction guesswork.
