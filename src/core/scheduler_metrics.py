"""
scheduler_metrics.py -- the scheduler daemon's own Prometheus metrics, served on its
own port (config `scheduler_metrics_port`, default 9106) from a PRIVATE registry.

Private registry on purpose: importing src/metrics.py here would re-export ~150
engine metrics as zeros from this second endpoint. The task label is `task`, not
`job` -- Prometheus reserves `job` for the scrape job and silently renames a
colliding target label to `exported_job` (exactly what broke the old job-health
dashboard table).

Everything here is observed first-hand by the scheduler (it owns every job's Popen
handle and the job coordinator's decisions) or handed over by the job itself through
core/job_result_channel.py -- no state file is read.
"""
import logging
from typing import Dict, Optional

from prometheus_client import CollectorRegistry, Counter, Gauge, start_http_server

from core import job_result_channel

LOGGER = logging.getLogger("scheduler_metrics")

REGISTRY = CollectorRegistry(auto_describe=True)

TASK_STATE_IDLE, TASK_STATE_RUNNING, TASK_STATE_PAUSED, TASK_STATE_WAITING = 0, 1, 2, 3

task_enabled = Gauge("home_ids_scheduler_task_enabled",
                     "1 for every task currently enabled in config.yaml's scheduler (retired tasks disappear)",
                     ["task"], registry=REGISTRY)
task_budget_minutes = Gauge("home_ids_scheduler_task_budget_minutes",
                            "Configured active-runtime budget before the job coordinator reclaims the task",
                            ["task"], registry=REGISTRY)
task_state = Gauge("home_ids_scheduler_task_state",
                   "0 idle, 1 running, 2 paused (preempted or throttled), 3 waiting (due but deferred)",
                   ["task"], registry=REGISTRY)
task_runs_total = Counter("home_ids_scheduler_task_runs_total",
                          "Finished runs by outcome: success, error (job reported an error), skipped (job chose not to run), "
                          "failed (non-zero exit, no result), killed (reclaimed over budget)",
                          ["task", "outcome"], registry=REGISTRY)
task_last_success = Gauge("home_ids_scheduler_task_last_success_timestamp",
                          "Unix time of the task's last successful run (as seen by this scheduler process)",
                          ["task"], registry=REGISTRY)
task_last_finish = Gauge("home_ids_scheduler_task_last_finish_timestamp",
                         "Unix time the task last finished, whatever the outcome",
                         ["task"], registry=REGISTRY)
task_last_duration = Gauge("home_ids_scheduler_task_last_duration_seconds",
                           "Runtime the task itself reported for its last finished run",
                           ["task"], registry=REGISTRY)
task_kills_total = Counter("home_ids_scheduler_task_kills_total",
                           "Times the job coordinator reclaimed (killed) the task for exceeding its budget",
                           ["task"], registry=REGISTRY)
task_last_kill_active_minutes = Gauge("home_ids_scheduler_task_last_kill_active_minutes",
                                      "Active (unpaused) minutes the task had run when it was last reclaimed",
                                      ["task"], registry=REGISTRY)
task_deferrals_total = Counter("home_ids_scheduler_task_deferrals_total",
                               "Scheduler ticks a due task was held back, by reason (pressure = resource gate, slot = another task running)",
                               ["task", "reason"], registry=REGISTRY)
task_preemptions_total = Counter("home_ids_scheduler_task_preemptions_total",
                                 "Times the task was paused so a more urgent task could run",
                                 ["task"], registry=REGISTRY)
task_result = Gauge("home_ids_scheduler_task_result",
                    "Numeric result fields the task reported for its last run (e.g. reviewed, queries_made, findings_count)",
                    ["task", "field"], registry=REGISTRY)
task_result_by_device = Gauge("home_ids_scheduler_task_result_by_device",
                              "Per-device result maps the task reported for its last run (e.g. findings_by_device)",
                              ["task", "field", "device"], registry=REGISTRY)
scheduler_last_tick = Gauge("home_ids_scheduler_last_tick_timestamp",
                            "Unix time of the scheduler daemon's last loop tick (liveness)", registry=REGISTRY)

_state: Dict[str, int] = {}


def start(port: int) -> bool:
    try:
        start_http_server(port, registry=REGISTRY)
        LOGGER.info("Scheduler Prometheus endpoint on port %d", port)
        return True
    except Exception as exc:  # port taken etc. -- scheduling must still run
        LOGGER.error("Scheduler metrics endpoint failed to start on port %d: %s", port, exc)
        return False


def sync_enabled_tasks(tasks: Dict[str, float]) -> None:
    """tasks: {task: budget_minutes} for every currently enabled task. A task
    disabled/removed from config disappears from every per-task gauge."""
    for name in list(_state):
        if name not in tasks:
            _state.pop(name, None)
            for g in (task_enabled, task_budget_minutes, task_state):
                try:
                    g.remove(name)
                except KeyError:
                    pass
    for name, budget in tasks.items():
        task_enabled.labels(task=name).set(1)
        task_budget_minutes.labels(task=name).set(budget)
        if name not in _state:
            set_state(name, TASK_STATE_IDLE)


def set_state(task: str, state: int) -> None:
    _state[task] = state
    task_state.labels(task=task).set(state)


def record_deferral(task: str, reason: str) -> None:
    task_deferrals_total.labels(task=task, reason=reason).inc()
    set_state(task, TASK_STATE_WAITING)


def record_preemption(task: str) -> None:
    task_preemptions_total.labels(task=task).inc()


def record_kill(reclaimed: Optional[dict]) -> None:
    if not reclaimed:
        return
    task = reclaimed.get("job") or "unknown"
    task_kills_total.labels(task=task).inc()
    task_runs_total.labels(task=task, outcome="killed").inc()
    task_last_kill_active_minutes.labels(task=task).set(float(reclaimed.get("active_minutes") or 0.0))


def record_exit(task: str, returncode: Optional[int], result: Optional[dict], now: float,
                killed: bool = False) -> None:
    """Called once per finished run. `result` is what the job published over its
    result channel (None if it published nothing, e.g. it crashed or was killed)."""
    set_state(task, TASK_STATE_IDLE)
    task_last_finish.labels(task=task).set(now)
    if killed:
        return  # already counted by record_kill()
    if result is None:
        task_runs_total.labels(task=task, outcome="success" if returncode == 0 else "failed").inc()
        if returncode == 0:
            task_last_success.labels(task=task).set(now)
        return
    outcome = result.get("status") or "success"
    task_runs_total.labels(task=task, outcome=outcome).inc()
    task_last_duration.labels(task=task).set(float(result.get("duration_seconds") or 0.0))
    if outcome in ("success", "skipped"):
        task_last_success.labels(task=task).set(now)
    extra = result.get("extra") or {}
    _replace_task_series(task_result, task, [({"field": k}, v)
                                             for k, v in job_result_channel.numeric_fields(extra).items()])
    _replace_task_series(task_result_by_device, task, [({"field": f, "device": dev}, n)
                                                       for f, m in job_result_channel.per_device_fields(extra).items()
                                                       for dev, n in m.items()])


def _replace_task_series(gauge: Gauge, task: str, rows) -> None:
    """Last-run semantics: drop this task's previous series first, so a device or
    field that vanished from the latest result doesn't linger with a stale value."""
    try:
        for labels in list(gauge._metrics.keys()):  # prometheus_client keys: tuple of label values
            if labels and labels[0] == task:
                gauge.remove(*labels)
    except Exception:
        pass
    for extra_labels, value in rows:
        gauge.labels(task=task, **extra_labels).set(value)
