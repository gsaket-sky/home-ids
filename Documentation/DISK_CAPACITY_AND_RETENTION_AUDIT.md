# Disk Capacity & Retention Audit (10-Year Continuous Run)

Date: 2026-09-23
Scope: every file write and every SQLite graph-DB write in `src/`, audited for whether
each has a *real deletion* mechanism (not just export/archive) sufficient for an
unattended 10-year production run, plus a disk-capacity estimate for 50-100 devices.
Companion to `MEMORY_RESTART_ROOT_CAUSE_AND_CAPACITY_PLAN.md` (RAM), which this doc
does not duplicate — see that doc for the RAM-side analysis and benchmark methodology
this audit's capacity numbers follow.

Standing requirement this audit is scored against (explicit user instruction):
**"archive is not enough — files no longer needed need to be deleted to keep the
space always clean."** Anything that only exports-then-keeps-forever is flagged as
still-unbounded, same as anything with no cleanup at all.

## Addendum (2026-09-23, same day): hard 20GB whole-stack budget

Explicit user requirement, superseding the "budget your own headroom" framing
above: **total disk usage across the ENTIRE security/monitoring stack — not
just this project's own writes — must never exceed 20GB**, regardless of
device count or traffic pattern ("trim everything, delete everything around
this max capacity... this also goes for all subsystems included: Suricata,
Zeek, Grafana, Prometheus, Loki/Promtail, fritzbox capture data").

**Real measured data corrected the earlier capacity estimate significantly.**
Direct measurement of `.94`'s live graph DB (`dbstat`, 46,994 decisions/37.1
days, 962,435 edges, 180,382 evidence rows) found real per-row costs far below
what the original Phase-4-style projection assumed:

| | Old doc's assumption | Real measured (.94, 2026-09-23) |
|---|---|---|
| decisions | ~41KB/row | **14.3KB/row** (2.9x smaller) |
| evidence (+indexes) | ~1KB/row | **390 bytes/row** (2.6x smaller) |
| edges (+indexes) | ~240 bytes/row | **254 bytes/row** (confirmed accurate) |
| edges/decision | up to 2×cap+2 (worst case) | **~12.8 average** (most decisions don't hit the cap) |

At 100 devices, 365d/90d retention now projects to **~16GB** for the graph DB
alone (not 35-71GB) — a much more favorable picture. Still, a fixed
day-count can't *guarantee* a hard ceiling for every installation (heavier
traffic, more devices, algorithmic changes), so a **size-driven backstop**
was built on top of the existing age-based retention rather than just
re-tuning the day-counts (which would only be correct for this one
household's current traffic).

### Design: age-based retention (primary) + size-driven governor (backstop)

`src/argus/ops/disk_budget_governor.py` (new scheduled job, runs 15 min after
`live_prune.py`) measures REAL on-disk size and, only if still over its
budget after the normal daily prune, trims further:
- Targets the oldest rows first (`GraphStore.get_decisions_batch_cutoff()` /
  `get_evidence_batch_cutoff()`), reusing the existing, already-tested
  cascade-delete methods rather than duplicating that logic.
- **Absolute safety floors, never violated regardless of budget pressure**:
  decisions ≥30 days, evidence ≥7 days, Zeek logs ≥3 days. If still over
  budget once every floor is hit, it logs an ERROR (raise the budget or add
  storage) rather than silently exceeding the ceiling OR silently deleting
  below a safe minimum audit window.
- **Real space reclamation, not just row deletion**: SQLite's `DELETE` alone
  never shrinks a file on disk — freed pages just become reusable within the
  same file. `GraphStore.enable_incremental_vacuum()` (one-time conversion to
  `auto_vacuum=INCREMENTAL`) + `incremental_vacuum_step()` (small, bounded
  ~16MB/step reclaims) actually shrink the file, without the freeze risk a
  full `VACUUM` carries (this project has fought multiple severe pipeline-
  freeze incidents this same month from exactly that class of blocking I/O).
- **WAL truncation**: `.94`'s real WAL was measured at 805MB (almost as large
  as the 1.06GB main file) — `checkpoint_wal_truncate()` (`PRAGMA
  wal_checkpoint(TRUNCATE)`, a short-lived-connection-only operation, not run
  by the long-lived `live_engine.py` singleton) now runs every governor pass.
- Same logic, filesystem-only, for Zeek's dated log directories (oldest day
  deleted first, `current` symlink never touched, 3-day floor).

### Whole-stack budget table (as implemented)

| Component | Budget | Mechanism |
|---|---|---|
| Graph DB (main+WAL) | 9.0GB | `disk_budget_governor.py` (new) |
| Zeek raw logs | 3.0GB | `zeek_log_prune.py` (14d) + governor backstop |
| Prometheus TSDB | 2.0GB | native `--storage.tsdb.retention.size=2GB` flag (added; was time-only, 7d) |
| Loki | ~14 days | native `compactor` + `retention_period=336h` (added; had **zero** retention before — compactor wasn't even configured) |
| Grafana | ~1.0GB | mostly static plugin code (~798MB) + its own small sqlite db (~27MB); no ongoing growth risk found |
| Suricata | 0.5GB | pre-existing logrotate (14 rotations) — already adequate |
| Cowrie honeypot | 0.03GB | docker-compose `logging.options` (`max-size=10m`, `max-file=3`) — was **completely unbounded** (`json-file` driver, no options set) before this |
| Everything else in `state/` (incl. fritzbox capture) | 1.5GB | already capped per-file by this same day's earlier retention-audit fixes |
| *(unallocated buffer)* | ~1.9GB | — |

**One-time cleanup found but not yet done** (blocked by the platform's
safety classifier on a live host — needs to be run directly): a stale 27MB
`grafana.db.bak-preisolatefix-20260904T013827` backup from a 2026-09-04 fix,
never cleaned up since:
```
ssh 192.168.77.94 "sudo rm -v /var/lib/grafana/grafana.db.bak-preisolatefix-20260904T013827"
```

### RAM benchmark: `disk_budget_governor.py` (real, measured on `.94`, 2026-09-23)

Like every job this project has added to the scheduler since the OOM crash-loop
investigations, the new governor runs as its own short-lived subprocess via
`job_coordinator.py` (same mutex/priority/SIGSTOP-pause-resume mechanism audited
in `Documentation/RESOURCE_AWARE_SCHEDULING.md`), not inside `soc.service`'s own
long-lived process — so it does NOT add to that process's steady-state RSS
footprint at all, only its own separate, brief, bounded footprint while it runs.
Measured directly against `.94`'s real production database (not synthetic) with
`/usr/bin/time -v`:

| Metric | Real measured value |
|---|---|
| Maximum resident set size (peak RSS) | **65.1 MB** |
| Wall clock time | 1.96s |
| User+system CPU time | 1.94s (99% of one core, brief) |
| Major page faults | 0 |

Run against `.94`'s current real state: 46,994-decision / 0.99GB graph DB,
2.6GB of Zeek logs, 0.72GB of other `state/` files, 56 real devices — i.e. not
a toy fixture. Re-run a second time back-to-back to confirm idempotence
(no further trimming needed either run, `floor_hit: false` both times) and
that this peak RSS is stable, not a first-run cold-cache artifact.

At 65MB peak, this job is a rounding error against the `~1.6-1.9GB` fixed-floor
RAM budget `Documentation/MEMORY_RESTART_ROOT_CAUSE_AND_CAPACITY_PLAN.md`
established for `soc.service` itself — it was not a capacity risk, but this
confirms it rather than assuming it, consistent with this project's standing
"verify, don't assume" practice for every capacity claim.

For context, `soc.service`'s own live process RSS at the same moment (56 real
devices, well past the earlier Phase 4 benchmark's N=13/50/100 synthetic sweep):
**1.30GB** (`ps` RSS on the main PID), cgroup `MemoryCurrent` **1.36GB** total
across main+fastapi+scheduler — comfortably inside the `1.6-1.9GB` fixed-floor
estimate and the `3.5G` `MemoryMax` ceiling, with real headroom.

## Bottom line

- Graph DB (`state/v13_graph.db`) steady-state at 50-100 devices over 10 years:
  **~15-75GB**, driven mostly by `decisions` + their `edges` (row size measured at
  ~41KB live, not the ~8KB this repo's RAM doc had assumed; `add_hypothesis_edges()`
  added 2026-09-22 roughly doubles per-decision edge volume on top of that).
  Trivial for an SSD; not trivial for a small SD card deployment.
- File-based state adds a second, previously untracked growth class: several
  `state/*.jsonl`/`*.json` files have **zero retention at all** — plain append or
  read-modify-write-grow forever, no age cap, no size cap, no scheduled prune.
  None of these were flagged in the RAM-capacity doc (which only covers the DB and
  Zeek raw logs).
- No `PRAGMA auto_vacuum` is ever set and no scheduled job ever runs `VACUUM` /
  `wal_checkpoint(TRUNCATE)` — routine pruning frees pages for *reuse* but never
  shrinks the `.db` file. Size must be planned around historical high-water-mark,
  not average.

## Part 1 — Graph DB (17 tables): unbounded findings

Full per-table detail lives in the subagent report this doc summarizes; findings
ranked by real risk:

| # | Table | Problem | Est. 10yr size (50-100 dev) |
|---|---|---|---|
| 1 | `backtest_runs` | Zero deletion, ever. Nightly cron (`30 3 * * *`, now actually wired — a prior doc's "not yet wired" note is stale). Row size scales with device count (per-device JSON blob), unlike every other table. | ~350-620MB |
| 2 | `threshold_history` | Zero deletion. Pure append; per-device/category scoped proposals (fixed 2026-09-21) raised the real insert rate above what the schema assumed. | tens of MB |
| 3 | `containment_actions` | Zero deletion **by deliberate design** (hardware-block audit trail kept independent of its parent decision's lifetime) — a real, permanent exception to "no exceptions," not a bug. | tens of MB |
| 4 | `cl_afpe_trust` | Upsert-bounded per regime, but old-regime rows are never cleaned except by manual operator reset. Slow unbounded drift via `regime_id` over years. | tens of MB |
| 5 | `device_baselines` | Same regime_id caveat as #4; daily prune only removes rows for merged-away devices, not stale-regime rows for still-live ones. | tens of MB |
| 6 | `baseline_snapshots` | Writer exists (`autotune/reset.py:take_snapshot()`), **zero live callers anywhere in `src/`** — 0 rows today, but schema's own documented pruning policy (30d full-res + weekly-thinned) was never built. If ever wired up, ships with no cap. | 0 today; real gap if activated |
| 7 | `devices` / `destinations` | Zero deletion by design (identity-graph tombstoning). Low risk — rows tiny, cardinality is real-device/domain-bounded. | tens of MB |

Two related process findings (not unbounded tables, but real gaps):
- **Redundant/competing decision-retention jobs.** A daily pure-delete
  (`prune_decisions_and_alerts()`, added 2026-09-22) and the older monthly
  export-then-delete (`live_decision_archive.py`) use the *same* cutoff, but the
  daily one runs first — the monthly job now almost always finds nothing, making it
  effectively dead code while still running every month.
- **No VACUUM ever runs automatically.** The only place a real `VACUUM` +
  `wal_checkpoint(TRUNCATE)` happens is `decision_bloat_cleanup.py --apply`, a
  one-time manual script last run 2026-09-20. Recommend a periodic (e.g. quarterly)
  scheduled maintenance job, or explicitly accept high-water-mark sizing.

## Part 2 — File-based writes: unbounded findings

None of these are in the existing RAM-capacity doc. Ranked by fix value:

| # | File | Trigger | Problem |
|---|---|---|---|
| 1 | `state/local_confirmed_intel.json` | per confirmed IOC | **Highest-value fix.** Module is explicitly documented as TTL-bounded (30d) and already has a working `prune_expired()` — but it is never called anywhere in `src/`. TTL is only enforced at read time; the file itself grows forever. One-line scheduler wiring fix, no new code needed. |
| 2 | `state/decision_archive/decisions_*.jsonl` | monthly cron | **Biggest byte-volume risk.** This is the DB's own designated cold-archive destination for pruned decisions — multi-GB/year, zero retention of its own, unconditional (not even config-gated). Directly the "archive is not enough" gap the user described. |
| 3 | `state/fritz_webhook.log`, `state/scheduler.log` | continuous, every subprocess log line | Raw `subprocess.Popen(stdout=open(path,"a"))` redirect, not through Python logging — zero rotation, zero size cap, for the life of the box. |
| 4 | `state/confirmed_threat_counts.json` (174KB/3,220 entries today), `state/fp_sigma_shifts.json`, `state/autotune_stats.json` | per confirmed threat / sigma shift / weekly retrain | Sibling files to `device_fp_profiles.json` in the same modules, but missing that file's `discard_device_profile()`-on-merge/-prune hook. Compound fastest of the small-JSON findings. |
| 5 | `state/ollama_analysis_v13.jsonl` | every 4h | Pure append; also re-read in full every run (dedup+cache), so read cost grows with file size too. |
| 6 | `state/reports/top_domains_YYYYMMDD.md` | daily | New dated file every day, 3,650 files/10yr, never pruned. |
| 7 | `state/cl_afpe_divergence_v13.jsonl` | per alert | Pure append (241KB/718 lines today); stops growing once the CL-AFPE shadow flip happens, but never cleaned even after. |
| 8 | `state/config_changes.jsonl` | per human config edit | Human-paced (low volume) but genuinely uncapped. |
| 9 | `state/reactive_capture/reactive_capture_history.jsonl` | per capture burst | 1.5MB/2,190 lines today. Deliberately-permanent by design per the code's own comment — contradicts the "must delete" requirement. (The large raw `.pcap` files themselves ARE correctly deleted per-burst — only this summary log is unbounded.) |

Confirmed already correctly bounded (checked, no action needed): `ids_state.json`,
`models/devices/*.pkl`, `device_fp_profiles.json`, `memory_diagnostics.jsonl` (capped
500 entries), `health_manager_snapshot.json`, `component_heartbeat.json`,
`job_health.json`, `config_overrides.json`, `scheduled_job_slot.json`,
`state/alerts.json` (1GB size-rotated), threat-intel caches (2,000-entry eviction),
Zeek raw logs (14-day retention, already deployed), reactive-capture `.pcap` files.

Frozen/legacy files present on disk but no longer written by any current code (safe
one-time cleanup candidates, not ongoing risks): `state/autonomous_muted.jsonl`
(72.6MB/19,778 lines — retired 2026-09-21, replaced by the DB's
`fp_suppression_log` table, but the old file was never deleted), `state/shadow_decisions.jsonl`
(writer removed 2026-09-07), plus several apparent byproducts of retired scripts
(`ollama_run_stats.json`, `ollama_analysis_cache.json`, `confidence_calibration.json`,
`retro_hunt_findings.jsonl`). Also `decision_bloat_cleanup.py`'s own
`*.pre-bloat-cleanup-backup-*` DB snapshots — nothing ever deletes these automatically
on re-run (the existing 253MB backup from 2026-09-06 is a live instance of this).

## Part 3 — Disk capacity estimate, 50-100 devices, 10 years

Steady-state (bounded tables reach a fixed size within ~180-365 days, then stay
flat for the rest of the decade — this is the key structural fact for a 10-year
question):

| Component | pi_8gb @ 50 dev | pi_8gb @ 100 dev | x86_16gb @ 50 dev | x86_16gb @ 100 dev |
|---|---|---|---|---|
| Evidence + its edges | ~1.1GB | ~2.2GB | ~3.3GB | ~6.6GB |
| Decisions (measured ~41KB/row) | ~9.6GB | ~19.3GB | ~19.6GB | ~39.1GB |
| Decision edges (~2×cap+2/decision) | ~3.1GB | ~6.3GB | ~12.5GB | ~25.1GB |
| **Graph DB subtotal** | **~14GB** | **~28GB** | **~35GB** | **~71GB** |

Unbounded contributors, full 10-year total (both graph DB and files):

| Item | 10yr estimate |
|---|---|
| `backtest_runs` | 350-620MB |
| `decision_archive/*.jsonl` (file, monthly export) | multi-GB/year — dominant unbounded file cost, needs its own cap before this can be bounded |
| `threshold_history`, `containment_actions`, regime drift in `cl_afpe_trust`/`device_baselines`, `devices`/`destinations` | tens of MB each |
| `fritz_webhook.log`/`scheduler.log` | unbounded, workload-dependent (no cap = no ceiling to estimate against) |
| small per-device JSON files (findings #4-9 above) | low tens of MB, compounding |

**Recommendation**: budget **~100GB** as a practical 10-year floor for a 50-100
device x86_16gb deployment (graph DB high end + decision-archive growth at a
conservative multi-GB/year), and treat the pi_8gb/SD-card case as requiring the
retention fixes below to be in place before a 10-year unattended run is safe at all
— its bounded-table total alone (~28GB) already exceeds typical SD card capacity
once the currently-unbounded items are added in.

This is a first-pass estimate using real measured per-row sizes where available
(decisions, edges, evidence) and estimated sizes elsewhere (backtest_runs,
decision_archive). Recommend a direct at-scale measurement pass (same benchmark
method as the RAM doc's Phase 4) once device count is actually known, rather than
finalizing hardware purchase on this estimate alone.

## Part 4 — Unnecessary / too-frequent writes found

- `state/ollama_analysis_v13.jsonl` re-reads its *entire* file every 4h run just to
  rebuild an in-memory dedup set — this is a read-cost problem, not just a
  disk-growth one; grows worse the longer the box runs.
- `live_decision_archive.py` (monthly) is now redundant work in the common case —
  the daily `prune_decisions_and_alerts()` (added 2026-09-22) beats it to almost
  everything it would have archived. Either desync the cutoffs (so it can do real
  work) or retire it.
- No other cases of excessive write *frequency* were found — cycle-driven writes
  (evidence, decisions, device_baselines) are already correctly deduped/upserted
  rather than raw per-cycle inserts.

## Fix status (implemented 2026-09-23, tests in `tests/test_disk_retention_audit_fixes.py`)

1. **Done.** `LocalConfirmedIntel.prune_expired()` now runs hourly from
   `pipeline.py`'s existing prune tick (`core/pipeline.py`, alongside
   `prune_stale_devices()`).
2. **Done.** `live_decision_archive.py` now prunes `decision_archive/decisions_*.jsonl`
   files older than 730 days on every run, independent of whether that run archived
   anything itself. The redundant-monthly-job-vs-daily-prune overlap (both now use
   the same cutoff, daily wins the race) is flagged but NOT resolved — a deliberate
   choice between "retire the monthly job" and "desync the cutoffs so it does real
   work again," left for a human decision since it's about audit-trail policy, not
   a pure bug.
3. **Done.** `subprocess_launchers.rotate_subprocess_log_if_oversized()` — a
   copytruncate-based rotation (safe specifically because Python's `"a"` mode sets
   `O_APPEND`, verified with a real open file descriptor in the test suite, not just
   asserted) — polled hourly from `pipeline.py` for both `fritz_webhook.log` and
   `scheduler.log`.
4. **Done.** `discard_device_profile()` (`fp_engine.py`) now also clears
   `confirmed_threat_counts.json` (plain + `device_id||signature` scoped keys) and
   `fp_sigma_shifts.json` on merge/prune, matching the hook `device_fp_profiles.json`
   already had. `train_fp_classifier.py`'s `autotune_stats.json` gets an equivalent
   fix via a new `GraphStore.get_active_device_ids(seen_since=...)` method, pruning
   stale device entries out of its cumulative `devices` dict on every weekly write.
5. **Done**, except one deliberate exception. `ollama_analysis_v13.jsonl` (rotated
   at the top of every 4h run), `top_domains_report/*.md` (90-day age-prune),
   `config_changes.jsonl` (5MB cap), `reactive_capture_history.jsonl` (20MB cap,
   reverses that file's original "kept indefinitely by design" comment per this
   task's explicit "archive is not enough" requirement) all now use a shared
   `utils.rotate_jsonl_if_oversized()` / `utils.prune_dated_files()` helper.
   `cl_afpe_divergence_v13.jsonl` is the deliberate exception: its FULL history is
   load-bearing for `cl_afpe_flip_monitor.py`'s own volume-floor/false-negative-veto
   decision before the shadow-to-live flip happens — blindly rotating it could hide
   a real safety veto or reset the volume counter. Instead, the file is now deleted
   ONCE, automatically, the first run *after* the flip already happened (`check_bar()`
   already short-circuits before reading it at that point, so it's provably dead
   weight from then on) — bounded without weakening the safety gate while it matters.
6. **Partially done.** `backtest_runs` and `threshold_history` retention, plus
   `cl_afpe_trust`/`device_baselines` stale-regime cleanup (conservative: only a
   tuple's non-current regime AND past a 365-day cutoff — the current regime and
   anything recent is never touched, preserving `reset_tuple()`'s undo capability)
   are implemented and riding along on `live_prune.py`'s existing daily cadence.
   Periodic VACUUM/`wal_checkpoint(TRUNCATE)` was deliberately NOT implemented
   autonomously — a VACUUM holds the whole db file, and this project has fought
   multiple severe pipeline-freeze incidents this same month from exactly this class
   of blocking I/O. Recommend the user decide the cadence/mechanism explicitly rather
   than this being silently auto-added.
7. **Not done — needs explicit confirmation before touching live `.94` data.**
   One-time manual cleanup: the frozen `state/autonomous_muted.jsonl` (72.6MB,
   retired 2026-09-21, no code reads or writes it anymore) and stale
   `decision_bloat_cleanup.py` backup snapshots (e.g. the existing 253MB
   `v13_graph.db.pre-cleanup-backup-20260906_203544`).
