# Health Manager — Dependency Map

**Origin (2026-09-14)**: `soc.service` on `.94` was killed by the **kernel** OOM
killer after its main process climbed to ~2GB RSS + 1.2GB swap within ~2 hours of
a fresh restart, dragging down unrelated processes on the box (no `MemorySwapMax`
existed at the time). A same-day stopgap was applied directly to the systemd unit
(`MemoryHigh=1600M`, `MemorySwapMax=256M`). This subsystem is the real fix
underneath that stopgap — catch resource pressure early and degrade gracefully
instead of running full-speed into a wall, per an external "watchdog + health
manager" design doc the user supplied and asked to have implemented in full.

Same session: two Explore passes + one Plan pass (46 tool calls total, every
citation spot-verified against live source before being trusted) established
that **no watchdog/heartbeat framework existed anywhere in this codebase before
this**, `psutil` had zero prior usage, and three "toggle off an expensive
feature" config keys (`otx_api_key`/`abuseipdb_api_key`/`virustotal_api_key`) are
`_STATIC_KEYS` — immune to the live config-override channel, requiring an
in-process flag on the already-constructed client object instead.

## Architecture

One daemon thread (`HealthManager`, `src/core/health_manager.py`), started from
`main.py` before the blocking `pipeline.run()` call — same pattern as the
pre-existing `boot_alert_thread` / `ti_engine.start_refresh_thread()`. Runs two
independent state machines every `health_manager_check_interval_seconds`
(default 15s).

## Heartbeat channels

| Component | Channel | Reported by |
|---|---|---|
| `pipeline_main_loop` | in-process (`HEARTBEATS` singleton, `core/heartbeat.py`) | `EnginePipeline._step()` |
| `identity_reconcile_worker` | in-process | `EnginePipeline._identity_reconcile_worker()` |
| `ti_refresh` | in-process | `ThreatIntel._refresh_loop()` |
| `api_subprocess` | cross-process file (`state/component_heartbeat.json`) | `middleware/main_api.py`'s startup background task, every ~10s |
| `scheduler_subprocess` | cross-process file | `scripts/scheduler.py`, once per minute-tick |
| `zeek` | probed directly | `HealthManager._check_zeek_freshness()` — same mtime check as `main.py`'s old boot-time alert, now repeating |
| `suricata` | probed directly | `intelligence.detectors.suricata_scan.check_suricata_health()`, unchanged, now repeating |
| `pihole` | probed directly | `IPSMitigator.check_pihole_health()`, unchanged, now repeating |
| `feed:<name>` | read from existing file | `state/feed_health.json` — classification only, never re-alerts what `feed_health.py` already alerts on |
| `job:<name>` | read from existing file | `state/job_health.json` — staleness = no success within `health_manager_job_staleness_hours` (default 30h, deliberately coarse, not cron-aware) |

In-process vs. cross-process is not a stylistic choice — `main.py` runs
`EnginePipeline.run()` on the main thread, while the console/API server and the
job scheduler are each spawned as **separate OS processes** via
`subprocess.Popen` (`core/subprocess_launchers.py`). A plain in-memory dict can't
cross that boundary; the file channel mirrors `utils.write_job_health()`'s
existing shape (`job_health.json`) with a different filename and field set.

## Per-component state machine

```
HEALTHY --(age/check ≥ 2x interval)--> DEGRADED --(≥ 5x interval, or hard failure)--> UNHEALTHY
                                                                                          |
                                                              has an ACTIONS entry +      |
                                                              backoff.attempt_allowed()   v
                                                                                   RECOVERY_ATTEMPT
                                                                                          |
                                                                              action() runs, PRE/ACTION/POST
                                                                            /                              \
                                                                    success                            failure
                                                                       |                                    |
                                                                    HEALTHY                          RECOVERY_FAILED
                                                                                                             |
                                                                                          backoff exhausted (5th attempt)
                                                                                                             v
                                                                                                        SAFE_MODE
                                                                                              (one alert, waits for a
                                                                                               later HEALTHY signal
                                                                                               on its own, no more
                                                                                               auto-recovery)
```

Backoff schedule (`core/backoff.py`, `RecoveryBackoff`): 1st attempt immediate,
then 30s / 2min / 10min, then exhausted (default `max_attempts=5`).

**Components with no `ACTIONS` entry** (`zeek`, `suricata`, `pihole`, every
`feed:*`/`job:*`) **stay UNHEALTHY forever, alert-only** — this is deliberate,
not a gap (see "Not built this phase" below).

For `pipeline_main_loop`/`identity_reconcile_worker`/`ti_refresh`/
`resource_pressure`, the recovery action is always `sys.exit(1)` — this never
returns, so `VERIFY`/`RECOVERY_FAILED` never actually execute for these four.
This is intentional: `soc.service`'s systemd unit already has
`Restart=on-failure`/`RestartSec=10`, so a clean self-exit is sufficient and
needs no new sudo/systemctl permission.

## Resource-pressure state machine

```
NORMAL -> RESOURCE_PRESSURE -> CONSERVATION -> CRITICAL
```

| Level | Trigger (any one) | Actions (cumulative — each tier keeps everything below it) |
|---|---|---|
| NORMAL | rss < 1024MB, swap < 40%, sysmem < 75% | none |
| RESOURCE_PRESSURE | rss ≥ 1024MB / swap ≥ 40% / sysmem ≥ 75% | one rate-limited alert; `gc.collect()`; `ti_engine.paused = abuseipdb.paused = virustotal.paused = True` |
| CONSERVATION | rss ≥ 1536MB / swap ≥ 60% / sysmem ≥ 85% | disable `reactive_capture_spotcheck_enabled` / `reactive_capture_wired_probe_trigger_enabled` / `reactive_capture_suricata_enabled` via the existing live config-override channel; raise the pipeline's poll-interval floor to 10s |
| CRITICAL | rss ≥ 1843MB (~90% of the 2026-09-14 incident's observed peak) / swap ≥ 80% / available < 512MB | immediate (non-rate-limited) alert; after `health_manager_critical_sustain_checks` (default 3, ~45s) **consecutive** CRITICAL cycles — not one spike — `sys.exit(1)` |

De-escalation steps down one tier at a time; TI un-pauses and config overrides
clear (reverting to config.yaml's real values) via `CONFIG.revert_override()`.

**The `_STATIC_KEYS` problem and how it's actually solved**: `otx_api_key`/
`abuseipdb_api_key`/`virustotal_api_key` can never be toggled through
`config_overrides.json` — `config.py`'s live-reload explicitly rejects any
mutation to a `_STATIC_KEYS` entry. `HealthManager` doesn't fight this: it holds
a direct object reference to `pipeline.ti_engine`/`pipeline.abuseipdb`/
`pipeline.virustotal` (the same objects `EnginePipeline.__init__` already
constructed with those keys baked in) and sets `.paused = True/False` directly
on them — a plain in-process attribute, checked at each fetch/enqueue call site
in `intelligence/threat_intel.py`. No config write involved at all.

The CONSERVATION-tier `reactive_capture_*` keys are the opposite case — none of
the three are `_STATIC_KEYS`, so `HealthManager._set_config_override()` reuses
the exact same `state/config_overrides.json` read-modify-write shape
`middleware/routers/config_api.py`'s own `_set_override()` uses (kept as a small
local copy inside `core/health_manager.py` rather than importing that module,
to avoid pulling `fastapi`/`pydantic` into the main pipeline process and creating
a `core/` → `middleware/` dependency that doesn't exist anywhere else in this
codebase).

## Known, explicitly-documented gap

`scheduler.ollama_soc.enabled` / `autotune_enabled` / `scheduler.retro_hunter.enabled`
are read by the **separate** `scripts/scheduler.py` process straight from
`config.yaml` on disk (never through `config_overrides.json`). Neither the
in-process-flag trick (different process/memory space) nor the live
config-override channel (that process never reads it) can reach these. Pausing
them under CONSERVATION/CRITICAL would require writing `config.yaml` at
runtime, breaking this codebase's established "nothing writes config.yaml at
runtime" invariant (`requirements.txt`'s own PHASE 13 note). **Not attempted.**
If this ever needs fixing, `scripts/scheduler.py` would need its own
config-override-aware load path first — a separate, larger change.

## Explicitly NOT built this phase

- **Active restart of Zeek/Suricata/Pi-hole-FTL.** All three are external to
  this codebase — no systemd unit files exist in this repo for them, no
  `systemctl` permission has ever been granted to this process. Alert-only by
  design (no `ACTIONS` entry — see `test_health_manager_healing_actions.py`'s
  `test_actions_catalog_has_no_entry_for_externally_managed_components`, which
  enforces this structurally). A future phase restoring them needs its own
  explicit sudo-grant decision.
- **Grafana/Loki heartbeats** — not managed by this codebase at all.
- **`POST /api/health/recover`** — a manual operator-triggered recovery
  endpoint. `middleware/routers/health_api.py` ships read-only
  (`GET /api/health/status`) this phase; reaching a live `HealthManager`
  instance from the *separate* console/API subprocess is a second IPC problem
  (the existing `.ipc_sync_signal` file mechanism solves the analogous problem
  for IPS state), deliberately deferred.
- **Retrofitting `RecoveryBackoff` into `scripts/scheduler.py`'s own dispatch
  loop** (currently zero retry logic at all). `core/backoff.py` was built
  generic/standalone specifically so this is a small follow-up, not required
  now.
- **Heartbeats for `AlertManager`'s own two daemon threads**
  (`telegram-alert-worker`, `telegram-bot-updates`) — natural next addition,
  out of scope for the OOM fix this phase targets.
- **A console "Health" tab UI** — only the read-only JSON endpoint ships; no
  `web/console.html` changes this phase.

## Files

New: `src/core/heartbeat.py`, `src/core/backoff.py`,
`src/core/subprocess_launchers.py`, `src/core/healing_actions.py`,
`src/core/health_manager.py`, `src/middleware/routers/health_api.py`.

Modified: `requirements.txt` (added `psutil>=5.9.0`), `config.yaml` (new
`health_manager:` category), `src/config.py` (`DEFAULT_CONFIG`),
`src/middleware/config_schema.py` (`CONFIG_SCHEMA` rows), `src/main.py`
(wiring + subprocess-launcher extraction), `src/core/pipeline.py` (heartbeat
calls + poll-floor read), `src/intelligence/threat_intel.py` (`.paused` flags
on `ThreatIntel`/`AbuseIPDB`/`VirusTotalClient`), `src/scripts/scheduler.py`
(heartbeat write), `src/middleware/main_api.py` (router + startup heartbeat
task).

Tests: `tests/test_heartbeat_registry.py`, `tests/test_recovery_backoff.py`,
`tests/test_health_manager_state_machine.py`,
`tests/test_resource_pressure_modes.py`,
`tests/test_health_manager_healing_actions.py` — 45 checks total, all
deterministic (no real psutil/network/subprocess). Caught and fixed one real
off-by-one bug in `RecoveryBackoff`'s schedule indexing during development
(every attempt after the 1st was being allowed immediately instead of backing
off) — see that file's own comment.
