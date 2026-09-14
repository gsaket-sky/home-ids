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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [SCHEDULER] %(message)s")
LOGGER = logging.getLogger("scheduler")


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
    
    # Track when a job was last run to prevent multiple executions within the same minute
    last_run = {}
    
    while True:
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M")
        jobs_dispatched_this_tick = 0
        
        config = load_config()  # already flat -- merged across every config.yaml category

        # 1. Check legacy autotune
        if config.get("autotune_enabled", False):
            cron = config.get("autotune_schedule_cron", "0 3 * * *")
            if check_cron(cron, now) and last_run.get("autotune") != now_str:
                LOGGER.info("Triggering legacy autotune (train_fp_classifier.py)...")
                script_path = scripts_dir / "train_fp_classifier.py"
                subprocess.Popen([sys.executable, str(script_path)])
                last_run["autotune"] = now_str
                jobs_dispatched_this_tick += 1

        # 2. Check new granular scheduler
        scheduler_cfg = config.get("scheduler", {})
        for script_name, cfg in scheduler_cfg.items():
            if cfg.get("enabled", False):
                cron = cfg.get("cron", "0 0 * * *")
                if check_cron(cron, now) and last_run.get(script_name) != now_str:
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
                    LOGGER.info(f"Triggering scheduled script: {script_filename} (job='{script_name}') ...")
                    script_path = scripts_dir / script_filename
                    if script_path.exists():
                        subprocess.Popen([sys.executable, str(script_path)])
                    else:
                        LOGGER.error(
                            f"Scheduled job '{script_name}' is enabled but its script "
                            f"{script_path} does not exist — it will NOT run until this "
                            f"is fixed (either rename the job key/add a \"script\" "
                            f"override in config.yaml's scheduled_jobs.scheduler.{script_name}, "
                            f"or create the missing file)."
                        )
                    last_run[script_name] = now_str
                    jobs_dispatched_this_tick += 1

        # BUGFIX (health manager): self-reports this process's own liveness once per
        # minute-tick, since it's a separate OS process from the main pipeline that
        # would otherwise have no way to know this daemon is still alive/dispatching --
        # see core/heartbeat.py's module docstring for why this is a file, not shared
        # memory. Written at the end of the tick (not the start) so it can include how
        # many jobs this tick actually dispatched.
        try:
            state_dir = Path(config.get("state_path", "state/ids_state.json")).parent
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
