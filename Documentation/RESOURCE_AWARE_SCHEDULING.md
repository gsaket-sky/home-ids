# Resource-aware job scheduling

2026-09-22. Living doc -- update this whenever a job is added, removed, re-enabled
(`backtest_job`), or its `pausable`/`priority` classification changes.

## Why this exists

`scripts/scheduler.py` fires 7 cron-based jobs (plus `intelligence/fp_engine.py`'s own
boot-triggered weekly FP-classifier retrain) as independent subprocesses, all sharing
one systemd cgroup memory cap with the live detection engine. Before this change, the
only thing keeping them apart was manually staggering cron minutes -- fragile, and
already known to have failed once: a documented historical incident had `backtest_job`
and `population_prior_builder` overlap as two concurrent subprocesses, contributing to
an OOM. Separately, the weekly retrain used to run **in-process** on a background
thread inside the live engine's own PID; loading `alerts.json` (209MB+) and training
LightGBM there caused a 25+ hour continuous OOM crash loop (Sep 21 12:16 - Sep 22
13:11) before being caught and fixed by isolating it into a subprocess (see git log,
commit `b4568af`). This document covers the follow-up: genuine resource-aware
coordination across *every* scheduled job, not just that one.

## The two new modules

- **`src/core/resource_gate.py`** -- "is the system too busy to start a new job right
  now." Reads the shared cgroup's `memory.current`/`memory.max` (same paths
  `health_manager.py` reads for its own, differently-tuned purpose) plus a genuinely
  new signal: `os.getloadavg()[0] / os.cpu_count()` (CPU load-per-core -- nothing in
  this codebase measured CPU load before this). Returns the same four tier names as
  `health_manager.py` (`normal`/`resource_pressure`/`conservation`/`critical`) for
  operator familiarity, but with independently-tuned thresholds (`job_gate_*` config
  keys) -- deliberately NOT sharing `health_manager_*` thresholds or state, since that
  module answers a different question ("is *this process* in danger") with different,
  incident-scarred tuning that a second consumer could destabilize.

- **`src/core/job_coordinator.py`** -- the hard mutex: at most one scheduled
  subprocess job runs at a time, system-wide, via a single JSON lock file
  (`state/scheduled_job_slot.json`) plus an atomic O_CREAT|O_EXCL claim sentinel to
  arbitrate between `scripts/scheduler.py` (a separate OS process) and
  `fp_engine.py`'s retrain thread (inside `main.py`) racing for it. Supports
  priority-based preemption (a more urgent job SIGSTOPs a less-urgent *pausable* one
  and resumes it later) and orphan reconciliation (see below).

## Crash-safety (the part that matters most)

Every lock-file write is atomic (temp file + `os.replace()`); every read treats a
missing/corrupt file, or a recorded PID that's no longer alive, as "slot empty" --
this self-healing is the ACTUAL correctness guarantee, not any job's own `release()`
call (which is just the well-behaved fast path). A `SIGKILL` (OOM-killer or a forced
restart) at any point -- mid lock-file write, mid claim, mid a paused job's own
output write -- can never wedge the mutex or corrupt state. GraphStore/SQLite is
already crash-safe by construction (WAL mode); the one job excluded from pausing
(`live_prune`) is excluded *specifically* because it's the one job that wraps a long
transaction, where a pause (not a kill) could hold the write lock too long.

`train_fp_classifier.py`'s `fp_classifier.onnx`/`fp_calibration.json` writes, and
`top_domains_report.py`'s report file, and `live_decision_archive.py`'s export file,
were all switched to temp-file + `os.replace()` as part of this same change --
previously direct in-place writes, which a kill mid-write (now more exposed thanks to
the new pause capability) could have left truncated at the exact paths
`fp_engine.py`'s `_load_lgbm_model()` reads on every boot.

## Orphan prevention

On Linux, killing a parent does not kill its children -- they're reparented to init
and keep running invisibly. Every job is launched with
`subprocess.Popen(..., start_new_session=True)` (its own process group). Every
coordinator participant calls `job_coordinator.reconcile_on_boot()` at its own
startup **and every subsequent tick/poll** (not boot-only, despite the name) -- a
dead occupant self-heals via the normal read path; a genuinely stuck one (alive, but
past its own recorded `max_runtime_minutes`) gets its whole process group killed and
the slot reclaimed. This is also the *starvation backstop*: rather than ever
bypassing the mutex (which would risk a real double-run), a job denied the slot for
too long is guaranteed to eventually get it once the stuck occupant is reclaimed on
some subsequent tick. Pressure-based deferral (not mutex-based) has its own separate,
simpler backstop: `job_max_defer_minutes` (default 60) admits a job despite
lingering system pressure, but NEVER bypasses the mutex itself.

## Per-job classification

| job | priority | pausable | max_runtime_minutes | why |
|---|---|---|---|---|
| `live_prune` | 1 | **false** | 30 | Wraps its whole ~120s SELECT+chunked-DELETE in ONE `with self.transaction():` (store.py) -- SIGSTOP risks holding GraphStore's write lock past the live engine's own 10s busy_timeout. Highest priority anyway: unbounded evidence-table growth is a real, already-seen failure mode without it. |
| `train_fp_classifier` (both the legacy `autotune` cron entry AND `fp_engine.py`'s own weekly retrain -- **same coordinator job name**, since both invoke the literal same script) | 2 | true | 40 | No DB connection open during the heavy alerts.json/LightGBM phase; per-statement `GraphStore._maybe_commit()` afterward, no wrapping transaction. |
| `live_retro_hunter` | 3 | true | 30 | Per-statement commits; Ollama/Telegram calls just retry after resume. |
| `population_prior_builder` | 3 | true | 30 | Explicit per-item `_maybe_commit()`, confirmed no wrapping `transaction()`. |
| `live_llm_review` | 4 | true | 30 | Advisory-only per its own docstring; per-statement commits. |
| `live_decision_archive` | 5 | true | 30 | Per-statement auto-commit deletes; export-then-delete ordering already safe; export write now atomic. |
| `top_domains_report` | 5 | true | 20 | Read-only Pi-hole query + one (now atomic) file write; least urgent of all 7. |

**Not yet audited / not live on `.94` today** (config.yaml.example only --
`pausable: false` until individually reviewed the same way the 7 above were):
`live_prune_weak_notices`, `cl_afpe_flip_monitor` (retired), `zeek_log_prune`,
`backtest_job`. **`backtest_job` is the highest-priority one to review first** --
it's the exact job implicated in the historical overlap-OOM incident this whole
feature exists to prevent; review its DB usage pattern before ever flipping it to
`pausable: true`.

## Config keys

Top-level: `job_admission_max_pressure_tier` (default `resource_pressure`),
`job_max_defer_minutes` (default 60). Per-job (under
`scheduled_jobs.scheduler.<job>`, or `autotune_priority`/`autotune_pausable`/
`autotune_max_runtime_minutes` for the legacy entry): `priority` (int, lower = more
urgent), `pausable` (bool), `max_runtime_minutes` (float).

Note: `config.yaml` itself is gitignored (per-deployment) -- `config.yaml.example` is
the tracked template. A production box's own `config.yaml` needs these same keys
added by hand (or re-copied from the example) to actually pick up this feature; a
`git pull` alone does not touch it.
