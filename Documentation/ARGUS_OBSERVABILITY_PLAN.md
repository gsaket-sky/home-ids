# Argus Observability Plan: metrics, job fixes, Grafana redesign

Started 2026-09-23, after the [dashboard audit](GRAFANA_DASHBOARD_AUDIT_2026-09-23.md).
Living document: updated as each step lands.

**Goals**
1. Find out why `live_llm_review` and `train_fp_classifier` stopped succeeding on .94, and fix it.
2. Restore the false-positive filter (CL-AFPE) counters under the Argus engine.
3. Export the LLM-review and retro-hunt job stats.
4. Give every newer (Release 15–16) subsystem real metrics.
5. Redesign Grafana around the Argus architecture. Keep the Master Threat Ledger, with new columns and plain labels.

**Revised 09-23 (user direction):** Prometheus-native wherever possible, with **no new state files**,
and existing relay files to be retired later (inventory in section 5). No band-aids. Everything network-agnostic.

**Constraints:** Pi-8GB-class host (bounded memory, CPU and I/O). Nothing new may block the pipeline's main
loop (the 09-22 freeze history). Keep `src/argus/` free of Prometheus. Stay network-agnostic.

---

## 1. Why the two jobs stopped (diagnosed live on .94, 09-23)

Evidence: `.94:state/scheduler.log`, `state/job_health.json`, and two timed manual runs on .94.

| Job | Last success before fix | Measured standalone runtime | What happened |
|---|---|---|---|
| `live_llm_review` | 09-22 15:02 | **36.4 min** (5 remote Ollama calls on the LLM host at ~6–7 min each, 22 cache hits, 440 deferred) | Killed at its **30-min** budget on every run since 09-22 22:30 |
| `train_fp_classifier` | 09-22 15:59 | **41 s** (training included) | 09-23 03:00 run stalled for 40 min and was killed |

Root causes, each confirmed in code or live data:
1. **A preempted job was never resumed.** When a higher-priority job preempted (SIGSTOPped) a running
   one, `scheduler.py` never marked the victim's `running` entry as `paused`. The resume loop only
   resumes paused entries, so the victim stayed frozen until the watchdog killed it. (09-23 02:45/03:00:
   `live_llm_review` preempted twice, never resumed.)
2. **The LLM job cannot fit its budget and had no deadline of its own.** It allowed up to 5 remote calls of
   up to 900 s each (up to 75 min) inside a 30-min budget. The measured run took 36 min.
3. **A kill lost everything (death spiral).** Entries were buffered and `job_health` was written only at
   the end, so a SIGKILL saved nothing. The next run inherited a bigger backlog.
4. **Coordinator accounting.** Paused time counted against the budget. A promoted job inherited its
   preemptor's `started_at`. A reclaim deleted the slot file outright, orphaning any job parked beneath
   it (frozen forever).
5. **The classifier's 03:00 stall** happened under the old 200% cgroup CPU quota (raised to 600% at
   16:51 that day) while the host was under pressure (other jobs deferred at 03:15/03:30). Its real
   runtime is 41 s; no classifier-specific defect was found. Any recurrence is now counted
   (`home_ids_scheduler_task_kills_total`) instead of silent.

Fixes (structural, no budget bumps):
- `scheduler.py`: marks preempted jobs as paused so they resume. Per-task state, deferral, preemption,
  kill and exit are all exported to Prometheus.
- `job_coordinator.py`: budgets count active (unpaused) time. Each job keeps its own clock through
  park/promote. A wall-clock cap (3× budget) catches a job parked forever. A reclaim promotes a
  parked job instead of orphaning it. `reconcile_on_boot()` returns what it reclaimed, so the caller
  records it (no file).
- `live_llm_review.py`: a deadline from its own configured budget. No remote call starts with less
  than `llm_review_min_query_seconds` left, each call's timeout is capped to the time left, every
  entry is flushed, and it reports `stopped_for_deadline`.

Also found while testing on Linux (first time these suites ran there): two coordinator tests spawned
their "stuck job" in pytest's own process group, so a correct `killpg` SIGKILLed pytest itself. One
checked liveness before reaping a zombie. Both are fixed in the tests.

## 2. Metric catalog (dependency map: who writes what, from where)

Legend. Writer = the code that sets it. Source = where the value really comes from. Cadence = how often.

### 2.1 CL-AFPE (false-positive filter) under Argus
| Metric | Type / labels | Writer | Source | Cadence |
|---|---|---|---|---|
| `home_ids_fp_evaluations_total` | Counter | `pipeline.py` (Argus branch) | returned `fp_verdict` | per alert |
| `home_ids_fp_suppressed_total` | Counter | same | `fp_verdict.suppress` | per alert |
| `home_ids_fp_confirmed_threats_total` | Counter | same | stage ∈ hard-stop stages | per alert |
| `home_ids_fp_confidence_score` | Gauge {device, hostname} | same | `fp_verdict.confidence` | per alert |
| `home_ids_cl_afpe_verdicts_total` (new) | Counter {stage, verdict} | same | stage + verdict | per alert |
| `home_ids_fp_domains_immunized_total` | Counter {source} | same | `fp_verdict.action` immunize with `is_new` | per alert |

Double-count guard: if Argus raises and falls back to the legacy `fp_engine.evaluate()` (which increments
these itself), the pipeline marks the fallback through a wrapped callable and skips its own increments.

### 2.2 Scheduled jobs: the scheduler's own `/metrics` (port `scheduler_metrics_port`, default 9106)
Private registry (`core/scheduler_metrics.py`). The label is `task`, because Prometheus renames a
target's `job` label to `exported_job`. Job results travel job → scheduler through an inherited pipe
(`core/job_result_channel.py`, called from `utils.write_job_health()`), so no file is involved.

| Metric | Labels | Source |
|---|---|---|
| `home_ids_scheduler_task_enabled` / `_budget_minutes` | task | config (only enabled tasks, so retired ones drop out) |
| `home_ids_scheduler_task_state` | task | 0 idle, 1 running, 2 paused, 3 waiting |
| `home_ids_scheduler_task_runs_total` | task, outcome | success / error / skipped / failed / killed |
| `home_ids_scheduler_task_last_success_timestamp`, `_last_finish_timestamp`, `_last_duration_seconds` | task | Popen exit + job's result |
| `home_ids_scheduler_task_kills_total`, `_last_kill_active_minutes` | task | coordinator reclaim |
| `home_ids_scheduler_task_deferrals_total` | task, reason | pressure / slot |
| `home_ids_scheduler_task_preemptions_total` | task | preemption |
| `home_ids_scheduler_task_result` | task, field | every numeric result field (LLM: reviewed, queries_made, cache_hits, deferred, stopped_for_deadline; retro-hunt: findings_count, local_intel_matches_count; disk governor: sizes + `budget_gb.*`) |
| `home_ids_scheduler_task_result_by_device` | task, field, device | every `*_by_device` map (retro-hunt findings per device) |
| `home_ids_scheduler_last_tick_timestamp` | – | liveness |

### 2.3 Health manager (set in-process by `health_manager._publish_prometheus()`)
| Metric | Labels | Meaning |
|---|---|---|
| `home_ids_health_component_state` (new) | {component} | 0 healthy, 1 degraded, 2 unhealthy, 3 safe mode, 4 recovery failed, -1 retired |
| `home_ids_health_recovery_attempts` (new) | {component} | self-heal attempts |
| `home_ids_health_pressure_level` (new) | – | 0 normal, 1 resource pressure, 2 conservation, 3 critical |

### 2.4 Argus graph exporter (new `core/argus_metrics.py`)
A daemon thread with its own **read-only** SQLite connection (`mode=ro`). Every query is bounded by a
progress-handler timeout. It never scans `evidence` or `edges`, runs every `argus_metrics_interval_seconds`
(default 120), and never touches the pipeline loop.

| Metric | Labels | Query source |
|---|---|---|
| `home_ids_argus_alert_events_24h` | {status} | `alert_events` last 24h: FIRED / SUPPRESSED_AUTONOMOUS / LOGGED_ONLY |
| `home_ids_argus_alert_events_all` | {status} | `alert_events` all retained (restart-proof) |
| `home_ids_argus_decisions_24h` | {state} | `decisions` last 24h |
| `home_ids_argus_incidents_active_24h` | – | `incidents` with last_seen in the last 24h |
| `home_ids_autotune_active_value` | {parameter, scope, target} | latest promoted, not rolled back, per scope (global / category / device) in `threshold_history` |
| `home_ids_autotune_changes` | {parameter, status} | `threshold_history`: canary / promoted / rolled_back |
| `home_ids_autotune_last_rollback_timestamp` | – | `threshold_history.rolled_back_at` |
| `home_ids_cl_afpe_trust_entries` | {destination_class} | `cl_afpe_trust` rows |
| `home_ids_cl_afpe_trust_mean` | {destination_class} | mean `trust_value` |
| `home_ids_baseline_models` | {model_kind} | `device_baselines` |
| `home_ids_population_priors` | {device_type} | `population_priors` |
| `home_ids_backtest_last_pass`, `_last_run_timestamp` | – | latest `backtest_runs` |
| `home_ids_containment_actions` | {action_type, status} | `containment_actions` (restart-proof isolation history) |
| `home_ids_operator_actions` | {action} | `operator_actions` |
| **Per device (Master Threat Ledger)** | {device, hostname} | |
| `home_ids_device_alerts_fired_24h` | | `alert_events` FIRED, last 24h |
| `home_ids_device_alerts_suppressed_24h` | | `alert_events` SUPPRESSED_AUTONOMOUS, last 24h |
| `home_ids_device_learned_trust` | | mean `cl_afpe_trust.trust_value` |
| `home_ids_device_baseline_regime_shifts` | | max `device_baselines.regime_id` (BOCPD changepoints) |
| `home_ids_device_sigma_shift` | | `devices.metadata_json.sigma_shift` (Argus sensitivity shift) |

### 2.5 Per-device decision detail (writer: `metrics_sync.export_device_telemetry`, from the live decision dict)
| Metric | Source field |
|---|---|
| `home_ids_decision_independent_sources` | `decision.independent_sources` |
| `home_ids_decision_evidence_families` | `len(decision.evidence_families)` |
| `home_ids_decision_path_code` | `decision.decision_path`, mapped to a stable code (Grafana value-maps it back to words) |
| `home_ids_reputation_tier` | reputation vector tier (0–5) |

### 2.6 Disk budget
The disk governor reports its budgets (`budget_gb.*`) next to the measured sizes, both exported as
`home_ids_scheduler_task_result{task="disk_budget_governor"}`.

## 3. Grafana redesign (layers of the Argus pipeline)
1. **Overview.** Is it working, what reached me, the Master Threat Ledger.
2. **Threat Landscape.** Where traffic and threats come from (geo, TI, TLS, DNS).
3. **Device Deep Dive.** One device: decisions, evidence signals, baseline and regime, its own tuning.
4. **Autonomy & Learning.** CL-AFPE funnel, autotune (global / category / device, rollbacks), trust,
   population priors, LLM review, retro-hunt, backtests.
5. **System Health & Operations.** Health-manager components, pressure, scheduler and coordinator (kills,
   pauses), disk budget, containment, sensors, process resources.

Retired from dashboards: legacy local-confirmed-intel store panels, legacy stage-2/3 split, ollama_soc
panels, and the muted-log stream.

## 4. Status log
- [x] scheduler / coordinator / LLM fixes · [x] classifier diagnosed · [x] 2.1 · [x] 2.2 · [x] 2.3 · [x] 2.4 · [x] 2.5 · [x] 2.6
- [x] tests on .94: coordinator + observability 36/36. The covering suites are green except 3 pre-existing
  failures, identical on the untouched base code: test_config_api device-type override (needs a `state/` dir),
  test_phase32 (3 checks), test_phase41 (needs the GeoIP database).
- [ ] deploy .94 · [ ] Prometheus scrape job for 9106 · [ ] live verify · [ ] dashboards · [ ] release

## 5. File-based relays still present (retire later)
Nothing new reads these for Prometheus. Each is listed with its remaining readers.

| File | Written by | Still read by | Replacement |
|---|---|---|---|
| `state/job_health.json` | `utils.write_job_health()` | health_manager job checks, console | scheduler `/metrics` (already live) |
| `state/health_manager_snapshot.json` | health_manager | console API process | `home_ids_health_*` (already live) |
| `state/autotune_stats.json` | train_fp_classifier | `metrics_sync.sync_relay_metrics()` → legacy `home_ids_autotune_*_effective` | `home_ids_autotune_value` from the graph |
| `state/ollama_run_stats.json` | retired ollama_soc | `sync_relay_metrics()` (frozen) | scheduler task results |
| `state/alerts.json` → Loki | AlertJSONWriter | Grafana alert-log tables | graph `alert_events` (counts already live; a log view needs a graph-backed API) |
| `state/autonomous_muted.jsonl` → promtail job | nothing (retired v16) | nothing | remove the promtail job |
