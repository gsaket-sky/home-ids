"""
main.py – Turnkey Home IDS Entry Point (Version 5.0.0-HEE).

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
from pathlib import Path

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
                    "middleware.fritz_webhook:app",
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
        pipeline.stop()
        LOGGER.info("Engine termination complete. Exiting.")
        sys.exit(0)

    LOGGER.debug("Registering OS signal handlers...")
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # Hand over main thread execution to the pipeline
    LOGGER.debug("Handoff to EnginePipeline main loop.")
    pipeline.run()


if __name__ == "__main__":
    main()