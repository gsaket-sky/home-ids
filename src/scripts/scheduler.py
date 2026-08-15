import os
import sys
import json
import time
import logging
import subprocess
from datetime import datetime
from pathlib import Path

# Ensures the script can resolve modules from the src directory
sys.path.append(str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [SCHEDULER] %(message)s")
LOGGER = logging.getLogger("scheduler")

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
    config_path = Path(__file__).resolve().parent.parent.parent / "config.json"
    try:
        with open(config_path, "r") as f:
            return json.load(f)
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
        
        config = load_config()
        dynamic = config.get("dynamic_live_reload", {})
        
        # 1. Check legacy autotune
        if dynamic.get("autotune_enabled", False):
            cron = dynamic.get("autotune_schedule_cron", "0 3 * * *")
            if check_cron(cron, now) and last_run.get("autotune") != now_str:
                LOGGER.info("Triggering legacy autotune (train_fp_classifier.py)...")
                script_path = scripts_dir / "train_fp_classifier.py"
                subprocess.Popen([sys.executable, str(script_path)])
                last_run["autotune"] = now_str
                
        # 2. Check new granular scheduler
        scheduler_cfg = dynamic.get("scheduler", {})
        for script_name, cfg in scheduler_cfg.items():
            if cfg.get("enabled", False):
                cron = cfg.get("cron", "0 0 * * *")
                if check_cron(cron, now) and last_run.get(script_name) != now_str:
                    LOGGER.info(f"Triggering scheduled script: {script_name}.py ...")
                    script_path = scripts_dir / f"{script_name}.py"
                    if script_path.exists():
                        subprocess.Popen([sys.executable, str(script_path)])
                    else:
                        LOGGER.error(f"Script {script_path} not found!")
                    last_run[script_name] = now_str
                    
        # Sleep until the next minute begins
        time.sleep(60 - datetime.now().second)

if __name__ == "__main__":
    main()
