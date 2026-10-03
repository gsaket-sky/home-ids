import os
import sys
import time
import logging
import subprocess
from datetime import datetime
from pathlib import Path

import yaml

# Ensures the script can resolve modules from the src directory
sys.path.append(str(Path(__file__).resolve().parent.parent))
from core.heartbeat import write_component_heartbeat  # noqa: E402 -- needs the sys.path.append above first
from core import resource_gate  # noqa: E402
from core import job_coordinator  # noqa: E402
from core import job_result_channel  # noqa: E402
from core import scheduler_metrics  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [SCHEDULER] %(message)s")
LOGGER = logging.getLogger("scheduler")

# Coordinator job name for the nightly false-positive retrain (train_fp_classifier.py). The engine picks up the new
# model on its own (argus/cl_afpe/ml_scoring.py reloads it when the file changes).
TRAIN_FP_CLASSIFIER_JOB_NAME = "train_fp_classifier"

# state/scheduler.log (embedded mode: this process's stdout, opened O_APPEND by
# core/subprocess_launchers.py) used to grow without limit. Above the cap the current
# file is copied to scheduler.log.1 (one generation) and truncated in place; with
# O_APPEND the next write lands at the new end. External mode logs to the journal /
# container log driver instead, so the file is simply absent there.
SCHEDULER_LOG_CAP_BYTES = 10 * 1024 * 1024


def _cap_scheduler_log(state_dir: Path, cap_bytes: int = SCHEDULER_LOG_CAP_BYTES) -> None:
    path = state_dir / "scheduler.log"
    try:
        if not path.exists() or path.stat().st_size <= cap_bytes:
            return
        rotated = path.with_name(path.name + ".1")
        with path.open("rb") as src, rotated.open("wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
        os.truncate(path, 0)
    except OSError as exc:
        LOGGER.warning(f"Could not cap {path}: {exc}")


def _flatten_config_categories(raw: dict) -> dict:
    """Mirror config.py's LiveConfig._load() flattening rule: merge every top-level
    mapping whose name doesn't start with "_"/"#" into one flat key->value namespace.
    Category names (network_and_devices, scheduled_jobs, ...) are purely organizational
    in config.yaml -- this scheduler reads the same flat keys regardless of which
    category they're grouped under, so renaming/reorganizing categories in config.yaml
    never requires a code change here."""
    flattened = {}
    for section_name, section_val in (raw or {}).items():
        if str(section_name).startswith("_") or str(section_name).startswith("#"):
            continue
        if isinstance(section_val, dict):
            flattened.update(section_val)
        else:
            flattened[section_name] = section_val
    return flattened

def check_cron(cron_str: str, current_time: datetime) -> bool:
    parts = cron_str.split()
    if len(parts) != 5:
        return False

    def match(val: int, part: str) -> bool:
        # A comma-separated list (e.g. "2,6,10,14,18,22") matches if any sub-part does --
        # added after live_llm_review's cron silently never fired for days: this used to
        # only support "*", "*/N", or a single exact integer, so int("2,6,10,...") raised
        # and the bare except below swallowed it into an unconditional False.
        if "," in part:
            return any(match(val, p) for p in part.split(","))
        if part == "*": return True
        if part.startswith("*/"):
            try: return val % int(part[2:]) == 0
            except: return False
        try: return val == int(part)
        except: return False

    # Standard cron day_of_week is 0-6 (Sunday=0), Python weekday() is 0-6 (Monday=0).
    # Since we only use * for day_of_week in our configs, we can just map it simply.
    python_dow = (current_time.weekday() + 1) % 7

    return (match(current_time.minute, parts[0]) and
            match(current_time.hour, parts[1]) and
            match(current_time.day, parts[2]) and
            match(current_time.month, parts[3]) and
            match(python_dow, parts[4]))

def load_config():
    """Returns the FLAT config namespace (already merged across every category), same
    as config.py's CONFIG.get(). Reads config.yaml directly (not through config.py's
    LiveConfig) so this standalone daemon doesn't need to boot the full engine."""
    config_path = Path(__file__).resolve().parent.parent.parent / "config.yaml"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return _flatten_config_categories(raw)
    except Exception as e:
        LOGGER.error(f"Failed to load config: {e}")
        return {}


def main():
    LOGGER.info("Starting Home-IDS Background Scheduler Daemon...")
    scripts_dir = Path(__file__).resolve().parent

    config = load_config()  # already flat -- merged across every config.yaml category
    state_dir = Path(config.get("state_path", "state/ids_state.json")).parent

    # Started as its own service (systemd unit / compose `scheduler`) while config.yaml still
    # says embedded: main.py is then running its own copy too, and both would dispatch every
    # job. Idle instead of exiting (an exit would just be restarted in a loop) and re-check,
    # so flipping the config to external is picked up without touching this service.
    if os.environ.get("IDS_SCHEDULER_STANDALONE") == "1":
        while str(config.get("scheduler_mode", "embedded")).lower() != "external":
            LOGGER.warning("Standalone scheduler idle: config.yaml has scheduler_mode != external, so the "
                           "engine runs its own embedded scheduler. Set scheduler_mode: external and restart "
                           "the engine to hand scheduling to this service. Re-checking in 5 min.")
            time.sleep(300)
            config = load_config()

    # This daemon owns every job's lifecycle, so it serves those facts to Prometheus
    # itself (core/scheduler_metrics.py) instead of relaying them through files.
    scheduler_metrics.start(int(config.get("scheduler_metrics_port", 9106)))

    # Resource-aware scheduling (Documentation/RESOURCE_AWARE_SCHEDULING.md): before
    # this process does anything else, reclaim any job left stuck past its own
    # recorded budget by a previous scheduler.py life (a restart/crash of THIS
    # process does not kill its children -- see job_coordinator.reconcile_on_boot()'s
    # own docstring for why that matters).
    scheduler_metrics.record_kill(job_coordinator.reconcile_on_boot(state_dir))

    # Track when a job was last run to prevent multiple executions within the same minute
    last_run = {}
    # job_name -> {"proc": Popen, "priority": int, "pausable": bool, "paused": bool,
    # "result_fd": int|None, "killed": bool} -- every job THIS scheduler.py instance has
    # launched and not yet seen exit.
    running = {}

    def _record_reclaim(reclaimed):
        """A coordinator reclaim kills the job; its exit is then seen by
        _reap_and_resume() and must not be double-counted as a plain failure."""
        scheduler_metrics.record_kill(reclaimed)
        if reclaimed:
            for info in running.values():
                if info["proc"].pid == reclaimed.get("pid"):
                    info["killed"] = True

    def _reap_and_resume():
        """Every tick: notice any tracked job that has exited (release its slot, or
        promote a paused one back to active), and resume any job THIS process itself
        previously paused once the coordinator says it's safe to."""
        for job_name in list(running.keys()):
            info = running[job_name]
            proc = info["proc"]
            if proc.poll() is not None:
                job_coordinator.release(state_dir, job_name, proc.pid)
                result = job_result_channel.collect(info["result_fd"]) if info.get("result_fd") is not None else None
                scheduler_metrics.record_exit(job_name, proc.returncode, result, time.time(),
                                              killed=info.get("killed", False))
                del running[job_name]
        for job_name, info in list(running.items()):
            if info.get("paused") and job_coordinator.should_resume(state_dir, job_name, info["proc"].pid):
                job_coordinator.resume_process(info["proc"].pid)
                job_coordinator.mark_running(state_dir, job_name, info["proc"].pid)
                info["paused"] = False
                scheduler_metrics.set_state(job_name, scheduler_metrics.TASK_STATE_RUNNING)
                LOGGER.info(f"Resumed previously-preempted job '{job_name}' (pid {info['proc'].pid}).")

    def _try_dispatch(job_name: str, priority: int, pausable: bool,
                       max_runtime_minutes: float, launch_fn, essential: bool = False) -> bool:
        """Runs launch_fn(popen_kwargs) (returning a Popen or None) only if
        admitted by BOTH the system-pressure gate and the job-priority mutex.
        Deferred jobs are retried every subsequent tick (not just their next cron
        match) via job_coordinator's persisted deferral-start record (2026-09-28:
        moved off an in-memory dict here -- see record_deferral_start()'s own
        docstring for why an in-memory clock silently defeated the backstop for
        once-a-day jobs like live_prune across scheduler restarts), with a
        pressure-only starvation backstop -- the mutex itself is never bypassed; a
        stuck mutex holder past its own budget is instead reclaimed by
        job_coordinator.reconcile_on_boot(), called every tick below, so starvation
        from a stuck occupant is closed safely without ever risking a genuine
        double-run."""
        max_defer = float(config.get("job_max_defer_minutes", 60))
        already_deferred = job_coordinator.is_deferred(state_dir, job_name)
        deferred_minutes = job_coordinator.get_deferred_minutes(state_dir, job_name)
        pressure_force = deferred_minutes >= max_defer
        # Deferred jobs are retried every tick, so only the first deferral is logged at
        # INFO -- otherwise every waiting job adds a line per minute to scheduler.log.
        defer_log = LOGGER.debug if already_deferred else LOGGER.info

        # `essential` jobs (the prune/cleanup jobs whose work RELIEVES pressure) are
        # never held back by the pressure gate -- deferring them under pressure is
        # self-defeating. They still go through the job mutex below.
        if not essential and not pressure_force and not resource_gate.may_admit_new_job(config):
            job_coordinator.record_deferral_start(state_dir, job_name)
            scheduler_metrics.record_deferral(job_name, "pressure")
            defer_log(f"Deferring '{job_name}' -- system under pressure ({deferred_minutes:.1f} min so far).")
            return False
        if pressure_force and not essential:
            LOGGER.warning(
                f"'{job_name}' deferred {deferred_minutes:.1f} min by system pressure alone -- "
                f"admitting despite pressure (starvation backstop). The job mutex itself is never bypassed."
            )

        if not job_coordinator.peek_admission(state_dir, priority):
            job_coordinator.record_deferral_start(state_dir, job_name)
            scheduler_metrics.record_deferral(job_name, "slot")
            defer_log(f"Deferring '{job_name}' -- slot held by a higher/equal-priority job ({deferred_minutes:.1f} min so far).")
            return False

        # Result pipe (core/job_result_channel.py): the job's own numbers reach
        # Prometheus through this process, no state file. POSIX-only (pass_fds);
        # elsewhere the job simply runs without a channel.
        read_fd = write_fd = None
        popen_kwargs = {}
        if os.name == "posix":
            try:
                read_fd, write_fd = job_result_channel.open_channel()
                popen_kwargs = {"pass_fds": (write_fd,), "env": job_result_channel.child_env(write_fd)}
            except OSError as exc:
                LOGGER.warning(f"Result channel unavailable for '{job_name}': {exc}")
                read_fd = write_fd = None
        try:
            proc = launch_fn(popen_kwargs)
        finally:
            if write_fd is not None:
                os.close(write_fd)  # the child holds its own copy; EOF once it exits
        if proc is None:
            if read_fd is not None:
                os.close(read_fd)
            return False

        outcome = job_coordinator.acquire_or_preempt(
            state_dir, job_name, proc.pid, priority, pausable, max_runtime_minutes
        )
        if outcome == job_coordinator.DENIED:
            # Lost the claim race between peek_admission() and the real launch --
            # rare (claim-protected), but must not leave an unowned subprocess
            # running outside the coordinator's view.
            LOGGER.info(f"'{job_name}' lost the race for the slot -- stopping the subprocess just started and deferring.")
            try:
                proc.terminate()
            except Exception:
                pass
            if read_fd is not None:
                os.close(read_fd)
            job_coordinator.record_deferral_start(state_dir, job_name)
            scheduler_metrics.record_deferral(job_name, "slot")
            return False
        if outcome.startswith(job_coordinator.PREEMPTED_PREFIX):
            old_pid = int(outcome.split(":", 1)[1])
            job_coordinator.pause_process(old_pid)
            for other_name, other in running.items():
                if other["proc"].pid == old_pid:
                    other["paused"] = True
                    scheduler_metrics.record_preemption(other_name)
                    scheduler_metrics.set_state(other_name, scheduler_metrics.TASK_STATE_PAUSED)
            LOGGER.info(f"Preempted pid {old_pid} to run higher-priority '{job_name}' (pid {proc.pid}).")

        running[job_name] = {"proc": proc, "priority": priority, "pausable": pausable, "paused": False,
                             "result_fd": read_fd, "killed": False}
        scheduler_metrics.set_state(job_name, scheduler_metrics.TASK_STATE_RUNNING)
        job_coordinator.clear_deferral(state_dir, job_name)
        return True

    while True:
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M")
        jobs_dispatched_this_tick = 0

        config = load_config()  # already flat -- merged across every config.yaml category
        state_dir = Path(config.get("state_path", "state/ids_state.json")).parent

        _cap_scheduler_log(state_dir)
        _record_reclaim(job_coordinator.reconcile_on_boot(state_dir))  # general watchdog every tick, not just at boot -- see its own docstring
        _reap_and_resume()
        scheduler_metrics.scheduler_last_tick.set(time.time())

        # Only tasks enabled RIGHT NOW are exported -- a retired/disabled task drops
        # out of Prometheus on its own, no dashboard-side name list needed.
        enabled_tasks = {
            name: float(cfg.get("max_runtime_minutes", 30))
            for name, cfg in (config.get("scheduler", {}) or {}).items()
            if isinstance(cfg, dict) and cfg.get("enabled", False)
        }
        if config.get("autotune_enabled", False):
            enabled_tasks[TRAIN_FP_CLASSIFIER_JOB_NAME] = float(config.get("autotune_max_runtime_minutes", 40))
        scheduler_metrics.sync_enabled_tasks(enabled_tasks)

        # 1. Check legacy autotune
        if config.get("autotune_enabled", False):
            cron = config.get("autotune_schedule_cron", "0 3 * * *")
            due = check_cron(cron, now) or job_coordinator.is_deferred(state_dir, TRAIN_FP_CLASSIFIER_JOB_NAME)
            if due and last_run.get("autotune") != now_str:
                script_path = scripts_dir / "train_fp_classifier.py"
                priority = int(config.get("autotune_priority", 2))
                pausable = bool(config.get("autotune_pausable", True))
                max_runtime = float(config.get("autotune_max_runtime_minutes", 40))

                def _launch(popen_kwargs, script_path=script_path):
                    LOGGER.info("Triggering legacy autotune (train_fp_classifier.py)...")
                    return subprocess.Popen([sys.executable, str(script_path)], start_new_session=True, **popen_kwargs)

                if _try_dispatch(TRAIN_FP_CLASSIFIER_JOB_NAME, priority, pausable, max_runtime, _launch):
                    last_run["autotune"] = now_str
                    jobs_dispatched_this_tick += 1

        # 2. Check new granular scheduler
        scheduler_cfg = config.get("scheduler", {})
        for script_name, cfg in scheduler_cfg.items():
            if cfg.get("enabled", False):
                cron = cfg.get("cron", "0 0 * * *")
                # BUGFIX (2026-09-30): a deferred job used to be retried only at its NEXT
                # cron match -- a day later for a daily job -- despite _try_dispatch()'s
                # docstring. On .94 that starved disk_budget_governor for 5 days and
                # backtest_job forever (both due 03:30, one slot). An open deferral record
                # now keeps the job due every tick until it actually dispatches.
                due = check_cron(cron, now) or job_coordinator.is_deferred(state_dir, script_name)
                if due and last_run.get(script_name) != now_str:
                    # BUGFIX: this used to always assume the job's config key IS the
                    # script's filename stem (f"{script_name}.py"). The "retrohunter" job
                    # key never matched the actual file (scripts/retro_hunter.py, with an
                    # underscore) — silently logging "not found" every day and never
                    # actually running, with nothing surfacing that failure beyond a
                    # daemon log line nobody was watching. An explicit "script" override
                    # is now supported per job so a config-key/filename mismatch like this
                    # can be corrected in config.json without needing a code change, and
                    # can't silently recur for a future script the same way.
                    script_filename = cfg.get("script", f"{script_name}.py")
                    script_path = scripts_dir / script_filename
                    priority = int(cfg.get("priority", 5))
                    pausable = bool(cfg.get("pausable", False))
                    max_runtime = float(cfg.get("max_runtime_minutes", 30))
                    essential = bool(cfg.get("essential", False))

                    if not script_path.exists():
                        LOGGER.error(
                            f"Scheduled job '{script_name}' is enabled but its script "
                            f"{script_path} does not exist — it will NOT run until this "
                            f"is fixed (either rename the job key/add a \"script\" "
                            f"override in config.yaml's scheduled_jobs.scheduler.{script_name}, "
                            f"or create the missing file)."
                        )
                        last_run[script_name] = now_str
                        continue

                    def _launch(popen_kwargs, script_name=script_name, script_path=script_path):
                        LOGGER.info(f"Triggering scheduled script: {script_path.name} (job='{script_name}') ...")
                        return subprocess.Popen([sys.executable, str(script_path)], start_new_session=True, **popen_kwargs)

                    if _try_dispatch(script_name, priority, pausable, max_runtime, _launch, essential=essential):
                        last_run[script_name] = now_str
                        jobs_dispatched_this_tick += 1

        # BUGFIX (health manager): self-reports this process's own liveness once per
        # minute-tick, since it's a separate OS process from the main pipeline that
        # would otherwise have no way to know this daemon is still alive/dispatching --
        # see core/heartbeat.py's module docstring for why this is a file, not shared
        # memory. Written at the end of the tick (not the start) so it can include how
        # many jobs this tick actually dispatched.
        try:
            write_component_heartbeat(
                state_dir, "scheduler_subprocess",
                extra={"pid": os.getpid(), "events_processed": jobs_dispatched_this_tick},
            )
        except Exception:
            pass

        # Sleep until the next minute begins
        time.sleep(60 - datetime.now().second)

if __name__ == "__main__":
    main()
