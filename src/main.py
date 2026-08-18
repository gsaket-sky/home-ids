"""
main.py – Turnkey Home IDS Entry Point (Version 7.0.0).

This file serves as the primary launcher for the enterprise-grade Network Detection 
and Response (NDR) platform. It initializes all independent background engines 
(Threat Intelligence, GeoIP, Machine Learning, IPS) and injects them into the 
core processing pipeline.

RECENT ARCHITECTURAL ADDITIONS:
- ADDED (CL-AFPE): Closed-Loop Autonomous False-Positive Elimination Engine is now
  auto-instantiated inside EnginePipeline.__init__() and boots its background ML loader
  threads at pipeline start. No changes required in main.py – the engine is fully
  self-contained inside src/intelligence/fp_engine.py.
- FIXED (WEBHOOK LOG VISIBILITY): Replaced `subprocess.DEVNULL` with a dedicated 
  file stream (`state/fritz_webhook.log`) for the FastAPI Uvicorn subprocess. 
  This ensures access logs (such as `GET /hosts` background pulls) are successfully 
  captured and monitorable in real-time.
- FIXED (CRITICAL DATA LOSS): Instantiates a single, unified StateManager instance at boot 
  and passes it into both IPSMitigator and EnginePipeline. Eliminates stale StateManager
  collisions during flush_to_disk() calls on active mitigations.
- ADDED (LOGGING): Comprehensive debug and lifecycle loggers added across all startup sequences.
"""

import logging
import signal
import sys
import subprocess
import warnings
from pathlib import Path
import os

# Completely suppress all warnings (including sklearn/joblib loky worker spam)
# from polluting the systemd journald logs in production.
os.environ["PYTHONWARNINGS"] = "ignore"
warnings.simplefilter("ignore")
def _no_warning(*args, **kwargs): pass
warnings.showwarning = _no_warning
from config import CONFIG
from core.state_guard import StateManager
from core.pipeline import EnginePipeline
from extractors.dns_features import PiHoleCollector
from intelligence.threat_intel import ThreatIntel
from intelligence.geoip import GeoIPEngine
from intelligence.ml_engine import MLRegistry
from mitigation.ips import IPSMitigator

LOGGER = logging.getLogger("home_ids.main")


def setup_logging():
    """Configures the root logger based on the dynamic configuration."""
    log_level_str = CONFIG.get("log_level", "INFO").upper()
    numeric_level = getattr(logging, log_level_str, logging.INFO)
    logging.basicConfig(
        level=numeric_level, 
        format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    LOGGER.debug("Logging subsystem initialized at level: %s", log_level_str)


def main():
    """
    Bootstraps the IDS components and initiates the main processing loop.
    """
    scheduler_proc = None
    setup_logging()
    LOGGER.info("🚀 Booting Home IDS Network Detection & Response Platform...")

    # =====================================================================
    # 0. INITIALIZE UNIFIED STATE MANAGER (CRITICAL FIX FOR RACE CONDITIONS)
    # =====================================================================
    state_path = CONFIG.get("state_path", "state/ids_state.json")
    max_devices = int(CONFIG.get("max_device_states", 5000))
    baseline_alpha = float(CONFIG.get("baseline_alpha", 0.05))
    
    LOGGER.info("📦 Initializing Master StateManager at %s (max_devices=%d)", state_path, max_devices)
    master_state_manager = StateManager(state_path=state_path, max_devices=max_devices)
    loaded = master_state_manager.load_from_disk(alpha=baseline_alpha)
    LOGGER.debug("Master StateManager boot sequence completed. Loaded %d devices.", loaded)

    # =====================================================================
    # 1. INITIALIZE INTERNAL DAEMONS (FastAPI Webhook with File Logging)
    # =====================================================================
    fastapi_proc = None
    webhook_log_file = None  # AUDIT FIX #2: Always initialize to None to prevent UnboundLocalError
    if CONFIG.get("ips_router_enabled", False):
        fastapi_port = int(CONFIG.get("fastapi_port", 8010))
        if fastapi_port <= 0:
            LOGGER.warning("Configured fastapi_port %s is invalid; falling back to 8010.", fastapi_port)
            fastapi_port = 8010
        LOGGER.info("🔌 Starting internal FastAPI Router Webhook daemon on port %d...", fastapi_port)
        try:
            # ARCHITECTURAL FIX: Pipe Uvicorn stdout/stderr to a dedicated log file 
            # instead of DEVNULL so GET /hosts and access pings can be tracked.
            webhook_log_path = Path("state/fritz_webhook.log")
            webhook_log_path.parent.mkdir(parents=True, exist_ok=True)
            webhook_log_file = open(webhook_log_path, "a")  # noqa: WPS515

            src_dir = str(Path(__file__).resolve().parent)  # AUDIT FIX #11: use --app-dir for CWD-independent import resolution
            fastapi_proc = subprocess.Popen(
                [
                    sys.executable, "-m", "uvicorn",
                    "middleware.main_api:app",
                    "--host", "127.0.0.1",
                    "--port", str(fastapi_port),
                    "--app-dir", src_dir,
                ],
                stdout=webhook_log_file,
                stderr=subprocess.STDOUT
            )
            LOGGER.debug("FastAPI Router Webhook daemon started (PID: %s). Logs → %s", fastapi_proc.pid, webhook_log_path)
        except Exception as e:
            LOGGER.error("⚠️ Failed to start internal FastAPI daemon: %s", e)
            if webhook_log_file and not webhook_log_file.closed:
                webhook_log_file.close()
                webhook_log_file = None
    else:
        LOGGER.debug("Router webhook daemon disabled in configuration. Skipping FastAPI startup.")

    # =====================================================================
    # 2. INITIALIZE INTELLIGENCE ENGINES
    # =====================================================================
    LOGGER.debug("Initializing Intelligence Engines...")
    ti_cache = Path(CONFIG.get("state_path", "/app/state/ids_state.json")).parent / "ti_cache"
    
    LOGGER.debug("Booting ThreatIntel engine (Cache: %s)...", ti_cache)
    ti_engine = ThreatIntel(
        cache_dir=str(ti_cache),
        otx_api_key=CONFIG.get("otx_api_key", ""),
        refresh_interval=int(CONFIG.get("ti_refresh_interval", 3600)),
    )
    ti_engine.start_refresh_thread()

    LOGGER.debug("Booting MLRegistry...")
    ml_registry = MLRegistry(
        model_dir=Path(CONFIG.get("model_path", "/app/state/ids_model.pkl")).parent / "devices",
        global_model_path=Path(CONFIG.get("model_path", "/app/state/ids_model.pkl")),
    )

    try:
        LOGGER.debug("Booting GeoIPEngine...")
        geoip_engine = GeoIPEngine(
            db_path=CONFIG.get("geoip_db"), 
            asn_db_path=CONFIG.get("geoip_asn_db", "")
        )
    except Exception as exc:
        LOGGER.error("GeoIP disabled (Database missing): %s", exc)
        geoip_engine = None

    # =====================================================================
    # 3. INITIALIZE EXTRACTORS & MITIGATORS (Inject Unified StateManager)
    # =====================================================================
    LOGGER.debug("Initializing Mitigation and Extraction subsystems...")
    ips_mitigator = IPSMitigator(config=CONFIG, state_manager=master_state_manager)

    LOGGER.debug("Booting PiHoleCollector...")
    pihole_collector = PiHoleCollector(
        db_path=CONFIG.get("pihole_db", "/etc/pihole/pihole-FTL.db"),
        lookback_seconds=int(CONFIG.get("startup_lookback_seconds", 300)),
        excluded_ips=set(CONFIG.get("safe_ips", [])),
        excluded_patterns=set(CONFIG.get("safe_host_patterns", []))
    )

    # =====================================================================
    # 4. ASSEMBLE AND START THE PIPELINE
    # =====================================================================
    LOGGER.debug("Assembling Master EnginePipeline...")
    pipeline = EnginePipeline(
        config=CONFIG,
        state_manager=master_state_manager,
        ti_engine=ti_engine,
        ml_registry=ml_registry,
        geoip_engine=geoip_engine,
        ips_mitigator=ips_mitigator,
        pihole_collector=pihole_collector
    )

    LOGGER.debug("Booting Centralized Background Scheduler (subprocess)...")
    scheduler_log_file = None
    try:
        # PHASE 9 FIX: this used to redirect to DEVNULL, silently discarding not just
        # scheduler.py's own dispatch logs but — since scripts.scheduler launches
        # ollama_soc.py/retro_hunter.py/top_domains_report.py/train_fp_classifier.py via a
        # plain subprocess.Popen(...) with no stdout/stderr override of its own — EVERY
        # log line those four scripts ever produce too, since a child with no explicit
        # redirect inherits its parent's actual file descriptors, and scheduler.py's fd 1/2
        # were already pointed at the null device. Concretely: retro_hunter.py's sole
        # channel for reporting a genuine zero-day match is `LOGGER.critical(...)` — that
        # was going straight into the void, unrecoverable, no journalctl line, no file, no
        # notification. Same fix already applied to the FastAPI subprocess a few lines up
        # (`webhook_log_file`) — this was the one process-spawn site that fix didn't reach.
        scheduler_log_path = Path("state/scheduler.log")
        scheduler_log_path.parent.mkdir(parents=True, exist_ok=True)
        scheduler_log_file = open(scheduler_log_path, "a")  # noqa: WPS515

        scheduler_path = Path(__file__).resolve().parent / "scripts" / "scheduler.py"
        scheduler_proc = subprocess.Popen(
            [sys.executable, str(scheduler_path)],
            stdout=scheduler_log_file,
            stderr=subprocess.STDOUT
        )
        LOGGER.debug(f"Scheduler daemon started (PID: {scheduler_proc.pid}). Logs → {scheduler_log_path}")
    except Exception as e:
        LOGGER.error("⚠️ Failed to start scheduler daemon: %s", e)
        if scheduler_log_file and not scheduler_log_file.closed:
            scheduler_log_file.close()
            scheduler_log_file = None

    # =====================================================================
    # 5. SIGNAL HANDLING (Graceful Shutdown)
    # =====================================================================
    def shutdown_handler(signum, frame):
        LOGGER.info("🛑 Received termination signal (SIGINT/SIGTERM). Shutting down pipeline safely...")
        if fastapi_proc and fastapi_proc.poll() is None:
            LOGGER.info("🛑 Terminating internal FastAPI daemon...")
            fastapi_proc.terminate()
            try:
                fastapi_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                LOGGER.warning("⚠️ FastAPI daemon did not exit in 3s; killing process forcibly.")
                fastapi_proc.kill()
                try:
                    fastapi_proc.wait(timeout=1)
                except Exception:
                    pass
            LOGGER.debug("FastAPI daemon terminated.")
        if webhook_log_file and not webhook_log_file.closed:
            try:
                webhook_log_file.close()
            except Exception:
                pass
                
        if scheduler_proc and scheduler_proc.poll() is None:
            LOGGER.info("🛑 Terminating scheduler daemon...")
            scheduler_proc.terminate()
            try:
                scheduler_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                scheduler_proc.kill()
        if scheduler_log_file and not scheduler_log_file.closed:
            try:
                scheduler_log_file.close()
            except Exception:
                pass
        pipeline.stop()
        LOGGER.info("Engine termination complete. Exiting.")
        sys.exit(0)

    LOGGER.debug("Registering OS signal handlers...")
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # =====================================================================
    # 6. SEND STARTUP TELEGRAM ALERT
    # =====================================================================
    def async_telegram_alert():
        import time
        import threading
        
        LOGGER.info("⏳ Delaying Telegram boot alert until all background models load...")
        wait_start = time.time()
        while time.time() - wait_start < 120:
            ti_ready = (ti_engine._stats["last_refresh"] != "never") if getattr(ti_engine, "_stats", None) else True
            fp_ready = True
            if pipeline and getattr(pipeline, "fp_engine", None):
                fp_ready = pipeline.fp_engine._lgbm_session is not None and pipeline.fp_engine._embed_model is not None
            
            if ti_ready and fp_ready:
                break
            time.sleep(2)
            
        telegram_token = CONFIG.get("telegram_token", "")
        telegram_chat_id = CONFIG.get("telegram_chat_id", "")
        if telegram_token and telegram_chat_id:
            geoip_status = "✅ Online" if geoip_engine else "❌ Failed/Disabled"
            webhook_enabled = CONFIG.get("ips_router_enabled", False)
            webhook_status = "✅ Online" if webhook_enabled and fastapi_proc and fastapi_proc.poll() is None else ("❌ Failed" if webhook_enabled else "⚠️ Disabled")
            
            ti_status = "✅ Online" if (getattr(ti_engine, "_stats", None) and ti_engine._stats["last_refresh"] != "never") else "⚠️ Sync Failed/Timeout"
            
            fp_status = "⚠️ Partial/Timeout"
            if pipeline and getattr(pipeline, "fp_engine", None):
                if pipeline.fp_engine._lgbm_session and pipeline.fp_engine._embed_model:
                    fp_status = "✅ Online"
            else:
                fp_status = "❌ Disabled"
                
            msg_lines = [
                "🚀 <b>Home-IDS NDR Platform Boot Complete</b>",
                "",
                "<b>Subsystem Status:</b>",
                "• Master StateManager: ✅ Online",
                f"• Threat Intelligence: {ti_status}",
                "• ML/Anomaly Registry: ✅ Online",
                f"• FP Validation Engine: {fp_status}",
                f"• GeoIP Engine: {geoip_status}",
                "• IPS Mitigator: ✅ Online",
                "• Zeek/PiHole Collectors: ✅ Online",
                f"• FastAPI Webhook: {webhook_status}",
                "• Master Pipeline: ✅ Online"
            ]
            
            try:
                import json
                import urllib.request
                msg_text = "\n".join(msg_lines)
                data = json.dumps({"chat_id": telegram_chat_id, "text": msg_text, "parse_mode": "HTML"}).encode('utf-8')
                req = urllib.request.Request(f"https://api.telegram.org/bot{telegram_token}/sendMessage", data=data, headers={'Content-Type': 'application/json'}, method='POST')
                with urllib.request.urlopen(req, timeout=5) as resp:
                    pass
                LOGGER.info("📲 Startup Telegram alert sent successfully.")
            except Exception as e:
                LOGGER.error("⚠️ Failed to send startup Telegram alert: %s", e)

    import threading
    threading.Thread(target=async_telegram_alert, daemon=True, name="boot_alert_thread").start()

    # Hand over main thread execution to the pipeline
    LOGGER.debug("Handoff to EnginePipeline main loop.")
    pipeline.run()


if __name__ == "__main__":
    main()