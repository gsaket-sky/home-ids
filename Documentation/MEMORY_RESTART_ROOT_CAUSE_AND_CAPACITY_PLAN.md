# Memory-Driven Restarts: Root Cause + Capacity Planning Plan

**Status (2026-09-28, HANDOVER — read this first): user reported "since adding
health manager, the script keeps getting restarted frequently" and separately
"processing delay is climbing." Investigation found 4 SEPARATE real bugs (not
one), all fixed, deployed, and live-verified on `.94` as of commit `906b47f`.
**None of this saga is closed** — see "Open items for the next session" at the
end of this entry before assuming anything below is finished.

**Bug 1 — most restarts were never a bug.** Checked `journalctl` + sudo audit
log for the Sep-27 evening restart flurry (11 restarts, some 6-9 min apart):
every one was `sudo systemctl restart soc.service` run manually from this same
dev PC (192.168.77.12) — confirmed via `sudo[...]: COMMAND=/usr/bin/systemctl
restart soc.service` lines matching each restart's timestamp exactly. Same
signature as the 09-23 diagnosis earlier in this file. Only ONE restart that
day (10:56:28) was a genuine health_manager self-heal, and it worked exactly
as designed (heartbeat stale 311s → CRITICAL → clean SIGTERM shutdown →
systemd restart). health_manager itself is not misbehaving.

**Bug 2 — real, found via py-spy: `sandbox.py`'s `ShadowEvaluator` did a
synchronous HTTP self-scrape of its own `/metrics` endpoint, once per device,
every ~2s main-loop cycle**, to check resource pressure before even looking at
whether a canary was active. A live py-spy capture caught `MainThread` blocked
inside that `urlopen()` call during a heartbeat-staleness incident; with 40+
devices each independently scraping the same self-hosted endpoint (itself
served by a thread competing for the same GIL), per-device socket timeouts
could sum to multi-minute heartbeat staleness — this is what caused Bug 1's one
real restart. Fixed: added `utils.is_resource_pressure_active_in_process()`
(reads the Prometheus Gauge object directly, no socket) for this in-process
call site; the 3 genuinely cross-process callers (`train_fp_classifier.py`,
`population_prior_builder.py`, `backtest_job.py` — separate OS subprocesses)
keep the original HTTP version unchanged. Commit `8844721`.

**Bug 3 — found while chasing the user's separate "falling behind" report:
`scripts/scheduler.py`'s starvation-backstop clock (`pending_since`) was a
plain in-memory dict**, wiped every time `soc.service` restarts (which also
kills/relaunches the scheduler daemon). `live_prune` — priority 1, the ONLY
job that prunes `device_destinations`/evidence/decisions, one cron slot/day
(03:15) — was deferred for "system under pressure" every single night since
09-23 at "0.0 min so far", NEVER escalating, because a restart kept resetting
the clock before it could reach the 60-min starvation backstop that's supposed
to force-admit it regardless of pressure. `job_health.json` confirmed
`live_prune`'s last real success was 09-21 — a full week silently skipped.
Fixed: moved the clock into `job_coordinator.py`'s existing disk-persisted
state (`record_deferral_start()`/`get_deferred_minutes()`/`clear_deferral()`),
so a scheduler restart can no longer reset it. Commit `8844721` (same commit
as Bug 2). **Manually force-ran `live_prune.py` once this session** (correct
invocation: `cd .../SOC && venv/bin/python3 src/argus/ops/live_prune.py` — it
silently no-ops if run from the wrong cwd, since `state_path` is resolved
relative to cwd and errors are swallowed into `job_health.json` writes that
themselves fail silently if the wrong `state/` dir gets created). Result:
`device_destinations_deleted: 0` — that table wasn't actually bloated, so this
specific fix's benefit is about the NEXT natural failure mode more than an
immediate win. `orphaned_device_baselines_deleted: 2373` was real cleanup.

**Bug 4 — the actual driver of "processing delay is climbing" (1.9s → 7s+
over ~20 min, still climbing pre-fix): `GraphStore.get_distinct_destination_
count()` (`src/argus/graph/store.py`), called once per device per cycle for
every device with ≥3 same-type peers (`_PEER_DEVIATION_MIN_PEERS=3` in
`live_engine.py`), fetches every `device_destinations` row for that device and
Python-filters each one through `utils.is_local_or_multicast_destination()`
(re-parses the string as an IP every single time).** Live query against `.94`'s
real graph: 71 devices reach this path each cycle, summing to ~8,400 rows
re-classified from scratch every ~2s cycle — a live, quantified instance of the
"O(N²) peer query" gap already flagged in `SHIPPABILITY_AND_SCALE_PLAN.md`.
Fixed: `@lru_cache(maxsize=4096)` on `is_local_or_multicast_destination()`
(pure function of its string arg, same convention `geoip.py` already uses for
the identical class of fix). Commit `906b47f`. **Investigated first**: a
device (`52a469cfd274`, 5,436 distinct destinations, the single biggest
outlier in the table) turned out to be a RED HERRING for this specific bug —
its `known_ips_history` includes `192.168.77.94` (it's `.94`'s own host
identity, Pi-hole/threat-intel background traffic attributed to itself as a
tracked "device"), and `device_type=dns_server` with zero same-type peers on
this network, so it never actually reaches the expensive path at all. Left
as-is (see open items).

**Also found, not yet fixed as its own thing but the direct write-side
counterpart of Bug 4's read-side fix**: `GraphStore.record_device_
destinations()` used to commit once per `upsert_device()` call PLUS once per
`upsert_destination()` call PLUS a final commit (N+2 individual synchronous
SQLite commits for a device with N destinations this cycle), never wrapped in
this same file's own `self.transaction()` helper despite 3 other call sites
already using it for exactly this reason. Fixed by wrapping the method body in
`self.transaction()`. Commit `ed931eb`. Added a regression test using
`sqlite3`'s trace callback (can't monkeypatch `sqlite3.Connection.commit`
directly — it's a read-only C-extension attribute; had to count `COMMIT`
statements via `set_trace_callback` instead — see
`tests/test_argus_graph_store.py`'s tail).

**Net result after all 4 fixes deployed** (verified via `/home/user/
freeze_diagnostics/watcher.log` and `curl localhost:9105/metrics | grep
collector_lag`): the freeze-watcher's heartbeat-staleness incidents (was
firing every 30-90s continuously) stopped. `home_ids_collector_lag_seconds`
stopped its unbounded climb and now fluctuates ~1.9-4.2s (avg ~3s) instead of
climbing straight through 7s+ — real improvement, but still above the 2.0s
`poll_interval` target, meaning there's at least one more contributor on the
same hot path not yet fixed (see open items #1 below).

## Open items for the next session

1. **`get_devices_with_metadata_value()` (`store.py`) is the next suspect for
   the residual ~3s average `collector_lag_seconds`.** Called from
   `_inject_peer_deviation_evidence()` (`live_engine.py`) once per device per
   cycle, it's documented as "a full table scan, parsed in Python rather than
   a SQLite `json_extract()` query" over the ENTIRE `devices` table (152 rows
   on `.94`, permanent by design — never pruned, only tombstoned on merge).
   Same general shape as Bug 4 but not yet measured/fixed. The natural fix is
   almost certainly caching the per-device-type peer list ONCE per cycle
   (matching `ShadowEvaluator._refresh_if_stale()`'s existing pattern in
   `sandbox.py`) instead of rebuilding it from scratch for every device that
   shares that type. NOT yet investigated with the same rigor as Bug 4 (no
   py-spy capture pinpointing it specifically) — confirm live before assuming.

2. **`live_prune` has not yet had its first NATURAL (cron-triggered) success
   since the Bug 3 fix deployed.** Its next real slot is tonight 03:15 (or,
   per the fix's own design, the FOLLOWING night at latest if deferred once
   more — the persisted clock should force-admit it by then regardless of
   pressure). Check `state/scheduler.log` for `'live_prune' deferred ... min
   ... admitting despite pressure (starvation backstop)` or a clean dispatch,
   and confirm `job_health.json`'s `live_prune.last_success` updates on its
   OWN (not from another manual SSH run) within 48h of 2026-09-28. If it's
   STILL silently skipped after 2 more nights, the persisted-clock fix itself
   has a bug — re-read `job_coordinator.py`'s `record_deferral_start()`/
   `get_deferred_minutes()`/`clear_deferral()` and `scripts/scheduler.py`'s
   `_try_dispatch()` before assuming the fix "should just work."

3. **Device `52a469cfd274` (`.94`'s own host, `device_type=dns_server`,
   5,436 distinct destinations) is architecturally messy but not urgent.**
   The monitoring box is tracking its OWN operational traffic (threat-intel
   refreshes, GeoIP/Tranco downloads, Pi-hole resolution) as if it were a
   managed network device. Not causing live cost right now (0 same-type
   peers → early return in `_inject_peer_deviation_evidence()`), but it's
   dead weight in `device_destinations` (5,436 rows and growing forever,
   since this device_type has no peers to ever trigger pruning-relevant
   analysis) and conceptually wrong (compare to the existing `is_own_
   registered_device()`/`safe_ips` exemption pattern already used elsewhere
   for the household's own Fritzbox — `.94` itself has no equivalent
   exemption). Low priority; flag if it resurfaces.

4. **Standing rule, unchanged**: every SSH/deploy/restart action on `.94`
   needs FRESH explicit confirmation each session — a prior session's "yes,
   deploy" does not carry forward. This session got that confirmation
   individually for each of the 3 restarts performed (commits `8844721`,
   `ed931eb`, `906b47f`) plus the one manual `live_prune.py` run. Don't assume
   continued authorization into a new session.

5. **Verification toolkit used this session, for whoever continues**:
   `ssh user@192.168.77.94` (key already set up, no `.19` involvement
   needed here); `journalctl -u soc.service` for app + systemd-level events
   (watch for the `oom`-in-`journalctl` `-i` grep false-positive from
   "StudyR**oom**Galaxy"-style hostnames — grep case-sensitively or use a
   tighter pattern); `/home/user/freeze_diagnostics/watcher.log` +
   `incident_*.txt` (each has a full `py-spy dump` section — this is what
   actually found Bugs 2 and 4, not guessing from logs alone);
   `curl -s http://127.0.0.1:9105/metrics | grep collector_lag` for the
   direct "is it falling behind" signal; `state/job_health.json` and
   `state/scheduler.log` for per-job last-success/deferral history; `sudo
   /home/user/myscripts/home-ids/venv/bin/py-spy dump --pid <MainPID>
   --nonblocking` for a live (non-incident) snapshot.

**Status (2026-09-23, real-data check-in): live `.94` RSS re-measured while
building the new whole-stack disk budget governor (56 real devices, well past
Phase 4's N=13/50/100 synthetic sweep below) — `soc.service` main-process RSS
1.30GB, cgroup `MemoryCurrent` 1.36GB total, comfortably inside the ~1.6-1.9GB
fixed-floor estimate and the 3.5G `MemoryMax` ceiling. Also measured the new
`disk_budget_governor.py` job itself (`/usr/bin/time -v`, real production DB,
not synthetic): 65.1MB peak RSS, 1.96s wall clock — runs as its own short-lived
subprocess via `job_coordinator.py` like every other scheduled job since the
OOM crash-loop fixes, so it adds nothing to `soc.service`'s own steady-state
RSS. Full detail in `Documentation/DISK_CAPACITY_AND_RETENTION_AUDIT.md`'s
"RAM benchmark: disk_budget_governor.py" section — not duplicated here.**

**Status (2026-09-22/23, latest): Root Cause #4 found and fixed — the same class
of bug as Root Cause #3 below (a synchronous operation blocking the main loop's
own heartbeat thread), but in `ml_engine.py`'s `save_models()`, not evidence-volume
flooding. Confirmed via `py-spy` live: `soc.service` had self-restarted 25 times in
one day, 84% needing a hard SIGKILL (the shutdown handler calls the same blocking
`save_models()` call), heartbeat stale up to 1819s (30+ min of zero detection
coverage) — worse than any of the incidents originally documented in this file.
Fixed with the same bounded-IO pattern `state_guard.py`'s `flush_to_disk()` already
used (a throwaway daemon thread + timeout, abandon-and-retry-next-cycle instead of
blocking forever). Verified live: restarts dropped to 1 in the following 8 hours,
with clean recovery. Full write-up: `Documentation/ARGUS_DECISIONS.md`'s "Periodic
disk I/O on the main detection loop's own thread must always be bounded" entry.
This restart-chasing saga is NOT necessarily fully closed — a `freeze-watcher.service`
diagnostic tool was left running on `.94` (`/home/user/freeze_diagnostics/`) to
catch and fully root-cause any further whole-process stall live, since the one
post-fix incident observed also stalled an unrelated thread (`pihole_poll`)
simultaneously, suggesting a possible broader disk-I/O contention pattern beyond
just this one now-fixed call site.**

**Status (2026-09-21, latest): Phase 4's benchmark sweep actually RUN (real
data below, not the earlier "not yet run" placeholder), Phase 5's capacity
question ANSWERED, `soc.service`'s `MemoryMax` raised again (2G -> 3.5G, this
was still too tight even after Phases 1-3's fixes), and a related real gap
fixed: `ml_engine.py`'s per-device model dict had no cleanup on age-out
eviction. See "Phase 4 -- REAL RESULTS" and "Phase 5 -- capacity answer"
below for the full 2026-09-21 update.**

**Status (2026-09-20): Phases 1-4 all implemented, deployed to `.94`,
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

**Important scope caveat**: this harness measures ONLY
the `live_engine.evaluate()` code path's own RSS -- `GraphStore` +
`HypothesisEngine` + `DecisionEngine` + `BaselineEngine`. It does NOT run
Zeek/Suricata, the FastAPI/uvicorn process, the scheduler, LLM review,
CL-AFPE, the legacy v1 engine (`fp_engine.py`/`ml_engine.py`/`threat_intel.py`,
which runs live in parallel with v13/argus by deliberate permanent design),
or `health_manager.py` itself, all of which also contribute to the REAL
`soc.service` process's RSS. Concluding "a Pi could handle thousands of
devices" from this benchmark ALONE would be a real mistake -- see "Phase 5 --
capacity answer" below for how this gets combined with the rest of the
process's real, measured footprint.

### Phase 4 -- REAL RESULTS (2026-09-21, this benchmark actually run)

Run locally (not on `.94` -- avoids adding load to a box that was actively
cycling every 10-45 minutes at the time; state-dir pointed at local disk, not
the network share the repo checkout itself lives on, after an initial N=13
run against the network share measured the SAME RSS numbers but ~3x slower
wall-clock purely from SQLite fsync latency over SMB -- confirms the RSS
figures below aren't an artifact of where the DB file lives, only the speed
of getting there is). `--hardware-profile pi_8gb` for all three runs.

| N devices | Simulated days run | Final RSS | Notable |
|---|---|---|---|
| 13 | 3.0 | 121.4MB | still climbing slightly at day 3 (not fully plateaued) |
| 50 | 6.0 | 132.2MB | plateaued by day ~2 (125.4MB) -- day 2->6 only +6.8MB despite db growing 127MB->392MB |
| 100 | 6.0 | 147.3MB | plateaued by day ~2-3 (133.4MB) -- day 3->6 only +9.3MB despite db growing 396MB->791MB |

**This engine layer's RSS is a clean linear fit**: `RSS(N) ≈ 117.1MB +
0.302MB × N`, confirmed against all three data points (N=13's predicted
plateau of 117.1+13×0.302=121.0MB matches its measured 121.4MB almost
exactly, even though N=13 hadn't fully finished climbing to plateau at day
3). The 117MB floor is dominated by two FIXED costs, not per-device state:
Python/library import overhead (~59MB, measured at simulated-day 0 before
any device activity) and the `pi_8gb` profile's own `cache_size` PRAGMA cap
(48,000KB = 48MB) filling up as the SQLite page cache warms -- both
independent of N. **The actual per-device marginal cost in this layer is
tiny: ~0.3MB/device.** Going from 50 to 100 devices costs this layer only
~15MB total, not a meaningful driver of capacity limits.

Separately measured, not from this benchmark (it doesn't exercise the legacy
v1 engine at all): `ml_engine.py`'s per-device model files on `.94` measured
at 15MB for 13 real devices (~1.15MB/device on disk, loaded fully into RAM
via `joblib.load()` with no cap until 200 active devices, which no real
household/small-business deployment reaches) -- and the threat-intel Tranco
top-1M-domain rank index measured directly at **121MB RSS** for exactly
1,000,000 entries (built the real dict locally, watched `psutil` RSS before/
after; this is a FIXED cost, independent of device count, rebuilt every 24h).

### Phase 5 -- capacity answer (2026-09-21)

Combining the measured pieces: `soc.service`'s real total footprint (main +
fastapi + scheduler processes) is dominated by a **fixed floor of roughly
1.6-1.9GB** -- the Tranco index (121MB), the legacy-v1-engine-running-
alongside-v13/argus overhead (the single largest unattributed chunk;
existing `tracemalloc`-based diagnostics don't yet attribute this precisely,
a real gap this investigation did not close), GeoIP DBs (~78MB, mmap'd),
CL-AFPE's ONNX sessions, and general Python/library overhead -- **plus a
genuinely small per-device marginal cost, roughly 0.3-1.5MB/device** (the
v13/argus layer's measured 0.3MB/device plus the legacy engine's ~1.15MB/
device ML models).

**Answer: device count (50 vs. 100) is NOT the capacity constraint.** At 50
devices, realistic total is ~1.7-2.0GB; at 100 devices, ~1.8-2.1GB -- a
difference of only ~100-150MB. `soc.service` was restarting every 10-45
minutes at TODAY's ~56 real devices because the 2G `MemoryMax` left
near-zero headroom above that fixed floor, not because of device-count
scaling. **Fix applied**: `MemoryMax` raised 2G -> 3.5G (see
`Documentation/INSTALL.md` section 7.2 for the full rationale) -- this gives
real headroom above the realistic 1.7-2.1GB ceiling at 50-100 devices, plus
room for normal bursts (LLM review, Suricata reactive capture, FP-model
retraining), instead of running flush against the wall as 2G did.

**Full-box implication for the real Raspberry Pi target**: `soc.service`
alone is not the whole picture -- this project's own `Documentation/
INSTALL.md` puts Pi-hole, Zeek, Suricata, Prometheus, Loki, Promtail, and
Grafana on the SAME box. Measured live on `.94`: Grafana 418MB + Prometheus
102MB + Loki 78MB + Promtail 26MB + node-exporter 20MB ≈ 645MB, plus Zeek
~265MB baseline. Rough full-box steady-state total: ~3.25GB (`soc.service`
with its new 3.5G cap, real usage inside it) + ~0.9GB (observability stack)
+ ~0.5GB (Zeek/Suricata) + ~0.15GB (Pi-hole) + ~0.5GB (OS) ≈ **~5.3GB**,
leaving ~2.7GB headroom on an 8GB Pi for zram-swap and burst absorption --
workable, but confirms 8GB is the right target with real margin, not an
over-provisioned choice; a 4GB Pi would not have adequate headroom under
this same accounting.

**Real gap fixed alongside this (2026-09-21)**: `pipeline.py`'s age-out
device pruning (`prune_stale_devices()`, ~7-day idle default) already
cleaned up `fp_engine.py`'s calibration profile and Prometheus metric labels
for a pruned device, but NOT `ml_engine.py`'s per-device model -- only
`merge_into_canonical()` ever called `MultiDeviceMLEngine.discard_device()`.
A device that went stale WITHOUT ever merging kept its `DeviceMLEngine`
resident in RAM (bounded only by a 200-active-device LRU cap that real
household/small-business scale never reaches) and its `.pkl` file on disk
forever, re-globbed and reloaded by `load_models()` on every future process
restart regardless of that LRU cap. Fixed: `pipeline.py`'s pruning loop now
also calls `self.ml_registry.discard_device(e_dev_id, reason="prune")`,
mirroring the existing `fp_engine.discard_device_profile(..., reason="prune")`
call right above it. Covered by a new standalone test,
`tests/test_ml_engine_stale_device_discard.py` (8 checks, all passing) --
exercises `MultiDeviceMLEngine.discard_device()` directly rather than
`pipeline.py`'s own `_step()`, which (per `test_phase40_alert_button_
containment_sync.py`'s own documented reasoning) is too large/deeply-embedded
to invoke directly in a test.

**Not yet done**: attributing the ~1.3GB "everything else" chunk of the
fixed floor to specific subsystems (the legacy-v1-engine-in-parallel
overhead is the largest suspect but wasn't isolated); the CPUQuota
200%-live-vs-40%-tracked drift noted in section 4 above remains unresolved;
zram-for-swap-on-the-real-Pi is a separate, machine-specific OS/systemd
config decision, not something this repo's own code can deploy -- see the
session notes for why `.94` (an x86 box with server-grade NVMe, not an SD
card) needs a different justification than the real Pi target for adopting
it, and why validating the setup on `.94` first (before real Pi hardware is
available) is still worth doing.

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

**Flagged, lower priority at the time -- FIXED (continuation session, same
day)**: `live_engine.py`'s DGA coordinated-targeting check calls
`get_evidence_by_type_since()` -- cross-device, ONE evidence_type, scoped to
`_COORDINATED_TARGETING_WINDOW_SECONDS` -- theoretically the same bug class
(system-wide DGA evidence volume, not one device's spam) but no live evidence
it was actually large in practice at the time. `GraphStore.get_evidence_by_type_since()`
gained an optional `cap_per_device` param (profile-scaled, same constants as
Root Cause #3's own cap) -- deliberately PER-DEVICE, not a flat total: this
query's whole point is counting how many DISTINCT devices share a DGA
pattern, so a flat cap would let one flooding device's own row volume crowd
out every other genuinely-distinct device from the result, undercounting the
exact cardinality this correlation exists to detect. Every device with ANY
evidence in the window still contributes at least one row; only a single
device's own row multiplicity is bounded.

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

**Third update, same day: everything in this handover is now FIXED.** Bug A,
Bug B, the DGA-correlation low-priority cap, the lock-contention bonus
finding, AND the device_baselines 89-vs-13 root cause are all closed out this
session. Deployed to `.94` -- see the deployment log at the end of this
section for exact commits/verification. Everything below was originally
either a direct log quote/traceback from `.94` or a file:line read directly,
not inferred.

**Second update, same day: merge-completeness follow-up.** After Bug A's fix,
the user asked that a device merge also correctly carry over everything
associated with the orphan -- the evidence graph, metrics, and per-device
files in state/model directories. Audited all three before changing anything
(per this project's own network-agnostic/verify-first standing rule):

- **Evidence graph**: already correct. `GraphStore.merge_device()` tombstones
  the orphan (`merged_into_device_id`, never deleted) and `get_evidence_for_device()`
  already walks that chain. One real gap found and fixed:
  `get_latest_decision_for_device()` queried `device_id` literally with no
  canonical resolution -- fixed to resolve through the merge chain the same
  way, with a `resolve_merges=True` default matching the evidence method's
  own convention.
- **Autotune per-device thresholds** (`argus/autotune/engine.py`): a real,
  previously-unaudited gap -- `get_active_value()`/`propose_change()`/the
  cooldown clock all matched `device_id` literally against `threshold_history`.
  A device's own tuned threshold, and its cooldown, would have gone silently
  invisible the moment it merged into a richer canonical identity. Fixed:
  reads now resolve across every id that ever merged into the current
  canonical; writes always resolve `device_id` to canonical BEFORE the row is
  written, so a new proposal can never land under a soon-to-be-orphaned id.
- **ML models / FP calibration / statistical baselines**: confirmed these are
  discarded, not blended, by DELIBERATE prior design (not a bug) -- orphan
  state is typically near-empty, and blending it into a mature canonical
  model/baseline would corrupt it, not improve it. Explicitly asked the user
  whether to keep or reverse this; user chose to keep it.
- **Metrics / per-device files**: `ml_engine.py`'s per-device `.pkl` file and
  `fp_engine.py`'s JSON-keyed calibration profile are correctly discarded
  alongside the same statistical state above (no orphaned files left behind
  either way). The one real gap: `confirmed_threat_count`/`fp_count`/
  `has_validated_threat` on `DeviceState` are simple counts of real,
  discrete operator actions (an operator confirmed a threat or marked a false
  positive), not statistical estimators -- these are DIFFERENT in kind and
  were being silently dropped on merge. Fixed: `merge_into_canonical()` now
  sums the counts and ORs the flag into the canonical device. This also
  automatically fixes the metrics/graph mirror for these three fields, since
  `DeviceState.to_graph_metadata()` already mirrors them into the graph on
  every `flush_to_disk()` -- no separate metrics-side change was needed.

All three fixes covered by real regression tests (`test_argus_graph_store.py`,
`test_argus_autotune_engine.py`, `test_phase39_retroactive_identity_merge.py`)
and the full real-world alert regression suite re-run clean. Not yet deployed
to `.94`.

### The original anomaly: device_baselines has 89 distinct device_ids for ~13 real devices -- ROOT CAUSE FIXED

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

**Fix (continuation session, same day):** confirmed directly by reading
`argus/baseline/engine.py` -- EVERY `device_baselines` query in that file
(`is_learning_paused()`, `score_metric()`, `score_activity_transition()`,
plus the in-memory `_trackers`/`_markov`/`_last_state`/`_changepoint_pending`
caches) matched `device_id` literally, with zero merge resolution, the exact
same gap class as `get_latest_decision_for_device()` and autotune's
`threshold_history` (see the merge-completeness follow-up above). Fixed by
resolving `device_id` to its live canonical id at the top of all three public
methods. Unlike the evidence/decisions/autotune fixes, this does NOT also
search across every id that ever merged into the canonical -- per this
session's explicit product decision, a merged-away orphan's own (typically
very brief, post-Bug-A) statistical history stays discarded, not adopted,
same reasoning as `core/state_guard.py`'s baselines/ML-model/FP-calibration
discard policy. This closes off any NEW stray `device_baselines` rows from
accumulating going forward. For the rows that already exist from before this
fix shipped: new `GraphStore.prune_orphaned_device_baselines()` deletes
`device_baselines` rows whose `device_id` has since been merged
(`devices.merged_into_device_id IS NOT NULL`) -- wired into `live_prune.py`'s
existing daily cadence (no new cron job needed) and also run once by hand on
`.94` as this session's one-time cleanup. Deliberately does NOT touch
`threshold_history` -- autotune's own merge-resolution fix makes a merged
device's promoted threshold DELIBERATELY still-live (found via the redirect
expansion), so deleting those rows would silently regress that fix.

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

### Bug B: a `KeyError` here skips the ENTIRE decision cycle, not just one device -- FIXED

**Fix (continuation session, same day):** `pipeline.py:1167`'s per-device loop
body (~2380 lines, three separate `lock_device()` re-entries per iteration)
is now wrapped in `try: ... except KeyError as exc: LOGGER.error(...);
continue`. A device removed from `StateManager` mid-cycle (a concurrent
merge/prune) now only skips ITS OWN iteration -- every other device in that
same cycle's `get_all_device_ids()` order still gets evaluated, instead of
the whole `_step()` call aborting. Applied mechanically (a script re-indented
the existing body by one level and inserted the try/except at the exact
loop boundaries) rather than hand-retyped, specifically to avoid introducing
a stray bug while touching code this large -- verified via `ast.parse`/
`py_compile` (still valid Python) and a whitespace-ignored `git diff -w`
(confirms literally nothing else in those ~2380 lines changed, only the
intended wrapper was added). No direct behavioral test was added: this
codebase's OWN existing test suite already documents (see
`test_phase40_alert_button_containment_sync.py`'s comments) that
`pipeline.py`'s `_step()` is too large/deeply-embedded to invoke directly in
a test -- other tests in this file work around that by testing extracted
logic as standalone copies, not by calling `_step()` itself. Bug A's own fix
independently reduces how OFTEN this race can even happen (no more
zombie-churn-driven spurious merges), so this containment fix is now a
backstop for the remaining, much rarer legitimate concurrent-merge window
(MAC-rotation reidentify, genuine fragmentation events), not a fix for an
actively-firing bug.

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

### Bonus finding (lower priority, this session's own doing, not pre-existing): lost writes under lock contention -- FIXED

**Fix (continuation session, same day):** `GraphStore.__init__` now sets
`PRAGMA busy_timeout = 10000` on every connection (was left at Python
sqlite3's own 5000ms default). Ten seconds comfortably rides out a typical
administrative-script contention window (a bulk DELETE or VACUUM from this
project's own maintenance tooling) without the live per-cycle write giving
up immediately, while staying a small fraction of the 60s
`pipeline_main_loop` heartbeat deadline even in a genuinely stuck-writer
worst case. Verified via a direct `PRAGMA busy_timeout` read-back in
`test_argus_graph_store.py`.

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

### Suggested next steps for the session that picks this up -- ALL DONE

1. ~~Read `state_guard.py`'s `merge_into_canonical()` in full...~~ DONE --
   Bug A fixed.
2. ~~Decide whether `pipeline.py:1167`'s device loop should catch `KeyError`
   PER-DEVICE...~~ DONE -- Bug B fixed (mechanical try/except wrap, see its
   own section above for how this was verified without a direct behavioral
   test).
3. ~~Once Bug B is also addressed, revisit whether `device_baselines`'
   89-vs-13 device_id count drops back...~~ DONE -- root cause fixed
   (`argus/baseline/engine.py` now resolves merges) AND the pre-existing
   stray rows cleaned up (`GraphStore.prune_orphaned_device_baselines()`, both
   scheduled daily and run once by hand on `.94`).

Also done this same continuation session, beyond this handover's original
scope: IPv6 address-rotation merge correctness explicitly verified (new
`tests/test_argus_live_identity.py` Section I -- multiple simulated SLAAC
privacy-address rotations, each correctly merging into the same accumulating
canonical identity, including the zombie-resurrection fix applying per
rotation, not just once); everything deployed to `.94` and verified live (see
the deployment log below).

### Deployment log (2026-09-20, continuation session)

Shipped in three commits: `860f7a4` (Bug A), `b6a6c27` (merge-completeness:
decisions/autotune/counters), `8d093ae` (Bug B + the DGA cap + the
busy_timeout fix + the device_baselines root cause) -- released as GitHub
tags `v15.9.0`/`v15.10.0`/v15.11.0 (this doc update included in a follow-up
commit under the same tag's spirit). Deployed to `.94`: `git pull --ff-only`
(70abccd -> 8d093ae, clean fast-forward, working tree was already clean),
`sudo systemctl restart soc.service` (came up clean, `NRestarts=0` throughout,
no tracebacks besides the pre-existing/benign FritzBox-webhook-not-up-yet
retry warning), then `GraphStore.prune_orphaned_device_baselines()` run once
by hand for the one-time cleanup.

**Device-count audit, directly queried from `.94`'s live `state/v13_graph.db`
and `state/ids_state.json` (not estimated):**

| | before cleanup | after cleanup |
|---|---|---|
| `devices` table, total ever seen | 114 | 114 (unchanged -- audit-preserving by design, never deleted) |
| `devices` table, live/unmerged (canonical) | 56 | 56 (unchanged -- cleanup only touched `device_baselines`) |
| `devices` table, merged away (tombstoned) | 58 | 58 |
| `device_baselines`, distinct device_ids | 92 | **48** |
| `device_baselines`, distinct ORPHANED device_ids (the actual bloat) | 44 | **0** |
| `device_baselines`, total rows | 21,315 | 19,724 (1,603 orphaned rows deleted; the ~12-row gap vs. a naive 21315-1603 subtraction is the live service's own normal scoring activity in the few minutes between the two snapshots) |
| `state/ids_state.json`, actively tracked right now | 43 | 43 (unaffected -- this file only reflects StateManager's own in-memory device set) |

**How many of the 56 "live" graph devices are "actually correct" (real,
distinct physical devices, not lingering fragments):** 46 of the 56 were
seen within the last 24h, with a plausible, diverse `device_type` spread
(smart_tv/laptop/iot/router/phone/tablet/printer/nas/dns_server/
gaming_console/server -- not a pile of near-identical types that would
suggest still-unmerged fragmentation). The remaining 10 range from 3.3 to
16.9 days idle -- these are candidates for the EXISTING `prune_stale_devices()`
hourly sweep to eventually age out of `state/ids_state.json` (several already
have -- that's exactly why `state/ids_state.json`'s 43 is lower than the
graph's 56), but their GRAPH `devices` row persists forever by the same
deliberate audit-preserving design `merge_device()` already uses, not a new
gap -- the row itself is negligible in size, and every retention-sensitive
table that hangs off it (evidence/decisions/device_baselines) already has its
own real pruning. This is a meaningfully HIGHER real count than the
originally-flagged "~13 real devices" estimate (from weeks earlier in this
same investigation) -- consistent with genuine network growth over that time,
not remaining fragmentation: `device_baselines`' distinct-device count (the
number that mattered for the 89-vs-13 anomaly) dropped from 92 to a real,
now-orphan-free 48, matching the live device population, not 13.

**Not separately re-verified over a multi-hour window this session** (time
constraints) -- the cadence-verification `Monitor` watch from earlier in this
continuation session already confirmed 14+ clean minutes / zero restarts
before this deploy; this deploy's own post-restart check (a few minutes,
`NRestarts=0`, no error/traceback lines, no lock-contention errors even
while the one-time cleanup query ran concurrently against the live db) is
consistent with that holding, but a longer unattended observation window
is still the strongest confirmation and wasn't run to completion here.

## Open questions for later phases, not blocking Phase 1

- Where exactly should the payload-stripping live -- `store.py` (centralizes
  it next to the existing edge cap, applies to every caller) vs.
  `live_engine.py` (keeps `store.py` a dumber, more general-purpose graph
  layer)? Decide during Phase 1 implementation, not now.
- Does a real Raspberry Pi 8GB unit exist to benchmark on directly, or is
  Phase 4 entirely cgroup-simulated on `.94`? Real hardware would remove the
  CPU-performance-correction guesswork.
