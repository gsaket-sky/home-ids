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

    # BUGFIX: log_level is documented [LIVE] in config.yaml, but logging.basicConfig()
    # above only ever runs once, at boot -- nothing previously re-applied a later
    # config.yaml/config_overrides.json change to the actual logging subsystem, so
    # editing log_level via the console API silently had no effect on a running
    # process. CONFIG.set_notify() already fires with the set of changed keys on every
    # live reload (including from an override write) -- use it to make this genuinely
    # live instead of restart-only.
    def _on_config_changed(changed: dict) -> None:
        if "log_level" in changed:
            new_level_str = str(changed["log_level"]).upper()
            new_level = getattr(logging, new_level_str, None)
            if new_level is None:
                LOGGER.warning("Ignoring invalid live log_level '%s'", changed["log_level"])
                return
            logging.getLogger().setLevel(new_level)
            LOGGER.warning("Log level changed live to %s", new_level_str)

    CONFIG.set_notify(_on_config_changed)


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
    # BUGFIX (dead-code audit): this used to start ONLY when ips_router_enabled was true --
    # but this same FastAPI process is the only thing serving /api/ipc/immunize and
    # /api/ipc/revoke (pihole_api.py), which every "Mark False Positive"/"Revoke" Telegram
    # button hits regardless of hardware router isolation, and /api/ipc/release, /api/ipc/block
    # (fritzbox_api.py) for interactive approve/release. fp_revoke_notifications_enabled
    # defaults to True (it's the primary closed-loop safety net on autonomous suppressions)
    # while ips_router_enabled defaults to False -- so under DEFAULT config, this server
    # never started at all, yet Telegram was already sending Revoke buttons that pointed at
    # nothing. Now starts whenever ANY consumer of this webhook is enabled, not just the
    # hardware-isolation one.
    fastapi_needed = (
        bool(CONFIG.get("ips_router_enabled", False))
        or bool(CONFIG.get("interactive_blocking_enabled", False))
        or bool(CONFIG.get("fp_revoke_notifications_enabled", True))
    )
    if fastapi_needed:
        fastapi_port = int(CONFIG.get("fastapi_port", 8010))
        if fastapi_port <= 0:
            LOGGER.warning("Configured fastapi_port %s is invalid; falling back to 8010.", fastapi_port)
            fastapi_port = 8010
        fastapi_bind_host = str(CONFIG.get("fastapi_bind_host", "127.0.0.1")) or "127.0.0.1"
        if fastapi_bind_host != "127.0.0.1":
            LOGGER.warning(
                "🔓 fastapi_bind_host=%s -- the IPC control endpoints (isolate/release/block) "
                "are reachable from other devices on the network, protected only by "
                "fritz_api_token. Set fastapi_bind_host back to 127.0.0.1 to restrict them "
                "to this box only.", fastapi_bind_host,
            )
        LOGGER.info(
            "🔌 Starting internal FastAPI Router Webhook daemon on %s:%d...",
            fastapi_bind_host, fastapi_port,
        )
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
                    "--host", fastapi_bind_host,
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
    # PHASE 21-PATH-AUDIT: "/app/state/..." was a leftover Docker-era fallback (the
    # project dropped that layout well before this comment -- see retro_hunter.py's own
    # PHASE 9 fix for the sibling alert_json_path case). CONFIG.get() always resolves
    # the real config.yaml/DEFAULT_CONFIG value first ("state/ids_state.json") so this
    # fallback was realistically unreachable either way -- corrected to match
    # config.py's actual DEFAULT_CONFIG value for clarity, not because it ever fired.
    ti_cache = Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "ti_cache"
    
    LOGGER.debug("Booting ThreatIntel engine (Cache: %s)...", ti_cache)
    ti_engine = ThreatIntel(
        cache_dir=str(ti_cache),
        otx_api_key=CONFIG.get("otx_api_key", ""),
        refresh_interval=int(CONFIG.get("ti_refresh_interval", 3600)),
        # BUGFIX (live audit): reuses the SAME Pi-hole v6 REST API config ips.py's
        # block/unblock already uses, for is_pihole_gravity_domain() -- your own
        # Pi-hole's already-maintained ad/tracker classification, wired into the
        # telemetry-domain dampening in threat_signals.py.
        pihole_api_url=CONFIG.get("pihole_api_url", ""),
        pihole_api_password=CONFIG.get("pihole_api_password", ""),
        pihole_search_api_path=CONFIG.get("pihole_search_api_path", "/api/search"),
    )
    ti_engine.start_refresh_thread()

    LOGGER.debug("Booting MLRegistry...")
    ml_registry = MLRegistry(
        # Same stale-fallback cleanup as ti_cache above -- config.py's real default is
        # "models/ids_model.pkl", not the old Docker-layout path.
        model_dir=Path(CONFIG.get("model_path", "models/ids_model.pkl")).parent / "devices",
        global_model_path=Path(CONFIG.get("model_path", "models/ids_model.pkl")),
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
            # BUGFIX (live audit): every line below used to be either a hardcoded
            # "✅ Online" string (StateManager/ML Registry/IPS Mitigator/Zeek+PiHole
            # Collectors/Master Pipeline -- never actually checked at all) or a weak
            # proxy (webhook: "is the process still alive," not "does it actually
            # respond"; geoip: "is the object non-None," not "did the DB file actually
            # load"). None of those catch the exact failure mode being guarded against
            # here: the constructor didn't raise, but the thing doesn't actually work
            # (wrong path, no permission, bad credentials, empty file). Every line
            # below now does the real thing -- an actual read, an actual HTTP call, an
            # actual raw-socket probe, or an actual subprocess invocation -- and reports
            # the real reason on failure instead of a blanket "Online"/"Offline".
            import os as _os

            # -- StateManager: real filesystem check, not just "constructor returned" --
            try:
                state_dir = Path(state_path).parent
                state_writable = _os.access(str(state_dir), _os.W_OK)
                sm_status = f"✅ Online ({loaded} device(s) loaded, state dir writable)" if state_writable \
                    else f"❌ Failed ({loaded} device(s) loaded, but state dir NOT writable: {state_dir})"
            except Exception as exc:
                sm_status = f"❌ Failed ({exc})"

            # -- ThreatIntel: already a real check (did a feed refresh actually complete) --
            ti_status = "✅ Online" if (getattr(ti_engine, "_stats", None) and ti_engine._stats["last_refresh"] != "never") else "⚠️ Sync Failed/Timeout"

            # -- ML/Anomaly Registry: real check -- can it actually persist models? --
            try:
                ml_dir = getattr(ml_registry, "model_dir", None)
                if ml_dir is None:
                    ml_status = "⚠️ In-memory only (no model_dir configured)"
                elif _os.access(str(ml_dir), _os.W_OK):
                    warm = "warmed up" if getattr(ml_registry, "global_warmed_up", False) else "warming up"
                    ml_status = f"✅ Online (model dir writable, global model {warm})"
                else:
                    ml_status = f"❌ Failed (model dir NOT writable: {ml_dir})"
            except Exception as exc:
                ml_status = f"❌ Failed ({exc})"

            # -- FP Validation Engine: already a real check (are both models actually loaded) --
            fp_status = "⚠️ Partial/Timeout"
            if pipeline and getattr(pipeline, "fp_engine", None):
                if pipeline.fp_engine._lgbm_session and pipeline.fp_engine._embed_model:
                    fp_status = "✅ Online"
            else:
                fp_status = "❌ Disabled"

            # -- GeoIP: real check -- did the MaxMind DB file actually open? --
            if geoip_engine is None:
                geoip_status = "❌ Failed/Disabled (construction failed)"
            elif getattr(geoip_engine, "reader", None) is None:
                geoip_status = "❌ Failed (City DB did not load)"
            else:
                asn_note = "with ASN DB" if getattr(geoip_engine, "asn_reader", None) else "no ASN DB configured"
                geoip_status = f"✅ Online ({asn_note})"

            # -- IPS Mitigator sub-systems: real reachability/auth/permission checks --
            pihole_line = "⚠️ Not initialized"
            router_line = "⚠️ Not initialized"
            tarpit_line = "⚠️ Not initialized"
            if ips_mitigator is not None:
                try:
                    ok, detail = ips_mitigator.check_pihole_health()
                    pihole_line = f"✅ Online ({detail})" if ok else f"❌ Failed ({detail})"
                except Exception as exc:
                    pihole_line = f"❌ Failed ({exc})"

                router_enabled = bool(CONFIG.get("ips_router_enabled", False))
                if not router_enabled:
                    router_line = "⚠️ Disabled"
                else:
                    try:
                        fritz_ip = CONFIG.get("fritz_ip", "")
                        fritz_pass = CONFIG.get("fritz_password", "")
                        if not fritz_pass:
                            router_line = "❌ Failed (fritz_password not configured)"
                        else:
                            from fritzconnection import FritzConnection
                            FritzConnection(address=fritz_ip, user=CONFIG.get("fritz_user", "admin"),
                                             password=fritz_pass, timeout=3.0)
                            router_line = f"✅ Online (authenticated to {fritz_ip})"
                    except Exception as exc:
                        router_line = f"❌ Failed ({exc})"

                tarpit_line = "✅ Online (raw socket access verified)" if getattr(ips_mitigator, "tarpit_armed", False) \
                    else ("⚠️ Disabled" if not bool(CONFIG.get("ips_tarpit_enabled", True)) else "❌ Failed (no raw socket access -- needs root/CAP_NET_RAW)")

            # -- Zeek/PiHole Collectors: real check -- do the actual data sources exist and have recent data? --
            try:
                pihole_db = Path(CONFIG.get("pihole_db", "/etc/pihole/pihole-FTL.db"))
                pihole_db_status = "✅ found" if pihole_db.exists() else f"❌ not found at {pihole_db}"
            except Exception as exc:
                pihole_db_status = f"❌ error ({exc})"
            try:
                zeek_dir = Path(CONFIG.get("zeek_log_dir", "/opt/zeek/logs/current"))
                if not zeek_dir.exists():
                    zeek_status = f"❌ log dir not found at {zeek_dir}"
                else:
                    recent = any((time.time() - f.stat().st_mtime) < 3600 for f in zeek_dir.glob("*.log"))
                    zeek_status = "✅ producing recent logs" if recent else "⚠️ log dir exists but no recent (<1h) activity"
            except Exception as exc:
                zeek_status = f"❌ error ({exc})"
            collectors_status = f"Pi-hole DB {pihole_db_status}, Zeek {zeek_status}"

            # -- FastAPI Webhook: real check -- hit its actual /health endpoint, not just "is the process alive" --
            fastapi_needed_now = fastapi_proc is not None
            if not fastapi_needed_now:
                webhook_status = "⚠️ Disabled"
            elif fastapi_proc.poll() is not None:
                webhook_status = f"❌ Failed (process exited, code {fastapi_proc.returncode})"
            else:
                try:
                    import urllib.request as _ur
                    with _ur.urlopen(f"http://127.0.0.1:{CONFIG.get('fastapi_port', 8010)}/health", timeout=3) as r:
                        webhook_status = "✅ Online (process alive, /health responded)" if r.status == 200 else f"❌ Failed (/health returned {r.status})"
                except Exception as exc:
                    webhook_status = f"❌ Failed (process alive but /health unreachable: {exc})"

            # -- Suricata: real check -- binary executable, rules present, --build-info actually runs --
            try:
                from intelligence.detectors.suricata_scan import check_suricata_health
                from metrics import suricata_binary_health
                suricata_enabled = bool(CONFIG.get("reactive_capture_suricata_enabled", True))
                if not suricata_enabled:
                    suricata_status = "⚠️ Disabled"
                    # PHASE 30: left unset (absent from scrapes) rather than forced to 0/1 --
                    # "disabled" isn't a health state, and an absent series is the correct
                    # way to tell Grafana "not applicable" instead of "unhealthy."
                else:
                    ok, detail = check_suricata_health(
                        CONFIG.get("reactive_capture_suricata_bin", "/usr/bin/suricata"),
                        CONFIG.get("reactive_capture_suricata_rules_path", ""),
                    )
                    suricata_status = f"✅ Online ({detail})" if ok else f"❌ Failed ({detail})"
                    suricata_binary_health.set(1.0 if ok else 0.0)
            except Exception as exc:
                suricata_status = f"❌ Failed ({exc})"

            msg_lines = [
                "🚀 <b>Home-IDS NDR Platform Boot Complete</b>",
                "",
                "<b>Subsystem Status (real checks, not just \"constructed\"):</b>",
                f"• Master StateManager: {sm_status}",
                f"• Threat Intelligence: {ti_status}",
                f"• ML/Anomaly Registry: {ml_status}",
                f"• FP Validation Engine: {fp_status}",
                f"• GeoIP Engine: {geoip_status}",
                f"• IPS · Pi-hole: {pihole_line}",
                f"• IPS · Router (Fritz!Box): {router_line}",
                f"• IPS · Layer-2 Tarpit: {tarpit_line}",
                f"• Zeek/PiHole Collectors: {collectors_status}",
                f"• FastAPI Webhook: {webhook_status}",
                f"• Suricata (batch scan): {suricata_status}",
                "• Master Pipeline: ✅ Initialized",
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