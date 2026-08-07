"""
config.py – Configuration management engine.

RECENT FIXES:
- FIXED (STATE DRIFT VULNERABILITY): Enforced Configuration Immutability for static keys.
  During a live reload, if a key belonging to `_STATIC_KEYS` is altered in the JSON file,
  the `LiveConfig` engine explicitly rejects the in-memory mutation. This prevents live 
  daemons (like FastAPI or Prometheus) from decoupling from the `CONFIG` singleton state.
  A warning is logged notifying the operator that a restart is required.
"""
import json
import os
import threading
import time
import logging
from pathlib import Path

LOGGER = logging.getLogger("home_ids.config")
CONFIG_FILE = Path(__file__).parent.parent / "config.json"

_ENV_OVERRIDES = {
    "TELEGRAM_TOKEN":         "telegram_token",
    "TELEGRAM_CHAT_ID":       "telegram_chat_id",
    "OTX_API_KEY":            "otx_api_key",
    "ABUSEIPDB_API_KEY":      "abuseipdb_api_key",
    "ABUSEIPDB_KEY":          "abuseipdb_api_key",
    "VIRUSTOTAL_API_KEY":     "virustotal_api_key",
    "VIRUSTOTAL_KEY":         "virustotal_api_key",
    "PIHOLE_API_PASSWORD":    "pihole_api_password",
    "PIHOLE_API_URL":         "pihole_api_url",
    "ROUTER_WEBHOOK_URL":     "router_webhook_url",
    "FRITZ_USER":             "fritz_user",
    "FRITZ_PASS":             "fritz_password",
    "API_SECRET_TOKEN":       "fritz_api_token",
    "IDS_IPS_PIHOLE_ENABLED": "ips_pihole_enabled",
    "IDS_IPS_ROUTER_ENABLED": "ips_router_enabled",
    "IDS_IPS_TARPIT_ENABLED": "ips_tarpit_enabled",
}

_STATIC_KEYS = {
    "metrics_port", "state_path", "model_path", "geoip_db", "geoip_asn_db", 
    "pihole_db", "zeek_log_dir", "alert_json_path", "alert_json_max_bytes", 
    "max_device_states", "telegram_token", "telegram_chat_id", "otx_api_key", 
    "abuseipdb_api_key", "virustotal_api_key", "pihole_api_password", 
    "pihole_api_url", "router_webhook_url", "fritz_ip", "fritz_user", 
    "fritz_password", "fritz_api_token"
}

def apply_env_overrides(config: dict) -> None:
    for env_key, cfg_key in _ENV_OVERRIDES.items():
        val = os.environ.get(env_key)
        if val:
            if cfg_key.endswith("_enabled"):
                config[cfg_key] = val.strip().lower() in ("1", "true", "yes", "on")
            else:
                config[cfg_key] = val

DEFAULT_CONFIG = {
    "poll_interval": 2.0,
    "window_seconds": 300,
    "startup_lookback_seconds": 300,
    "max_device_states": 5000,
    "log_level": "INFO",
    "alert_threshold": 6.0,
    "threshold_std_dev": 3.0,
    "baseline_alpha": 0.05,
    "state_path": "state/ids_state.json",               
    "model_path": "state/ids_model.pkl",                
    "alert_json_path": "state/alerts.json",             
    "alert_json_max_bytes": 1073741824,
    "pihole_db": "/etc/pihole/pihole-FTL.db",
    "zeek_log_dir": "/opt/zeek/logs/current",
    "home_subnet": "192.168.1.0/24",
    "metrics_port": 9105,
    "geoip_db": "state/GeoLite2-City.mmdb",             
    "geoip_asn_db": "", 
    "ti_refresh_interval": 3600,
    "otx_api_key": "",
    "abuseipdb_api_key": "",
    "virustotal_api_key": "",
    "telegram_enabled": False,
    "telegram_token": "",
    "telegram_chat_id": "",
    "safe_ips": ["127.0.0.1"],
    "honeypot_ips": [],
    "safe_domains": [],       
    "safe_host_patterns": [],
    "ollama_url": "",         
    "ollama_model": "llama3", 
    "decay_factor": 0.995,    
    "device_type_overrides": {},
    "ips_pihole_enabled": True,    # Controls DNS Sinkholing
    "ips_router_enabled": False,   # Controls FastAPI Fritz!Box Hardware drop
    "ips_tarpit_enabled": True,    # Controls Layer-2 Scapy ARP Spoofing
    "interactive_blocking_enabled": False, # False = Autonomous Auto-Block, True = Require Telegram Approval
    "operator_release_cooldown_seconds": 3600.0, # 1-Hour Cooldown Period
    "pihole_api_url": "http://pihole",
    "pihole_api_password": "",
    "pihole_api_path": "/api/v2/domains",  # AUDIT FIX #9: configurable Pi-hole API path
    "router_webhook_url": "",
    "fritz_ip": "192.168.1.1",
    "fritz_user": "admin",
    "fritz_password": "",
    "fritz_api_token": "",
    "fastapi_port": 8010,          # AUDIT FIX #13: document fastapi_port in defaults
    "telegram_allowed_chat_ids": [], # AUDIT FIX #10: allowlist for Telegram command senders (empty = allow all, for backward compat)
}

class LiveConfig:
    def __init__(self, default_config: dict, file_path: Path):
        self.file_path = file_path
        self._config = dict(default_config)
        self._lock = threading.Lock()
        self._notify_cb = None
        self._last_loaded = 0.0
        self._watcher_active = False
        apply_env_overrides(self._config)
        self._load()

    def _load(self) -> None:
        if not self.file_path.exists():
            try:
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
                structured = {"static_requires_restart": {}, "dynamic_live_reload": {}}
                for k, v in self._config.items():
                    if k in _STATIC_KEYS:
                        structured["static_requires_restart"][k] = v
                    else:
                        structured["dynamic_live_reload"][k] = v
                self.file_path.write_text(json.dumps(structured, indent=2))
            except Exception as exc:
                LOGGER.error("Failed to create default config: %s", exc)
            return

        try:
            mtime = self.file_path.stat().st_mtime
            raw = json.loads(self.file_path.read_text())
            flattened = {}
            if "static_requires_restart" in raw or "dynamic_live_reload" in raw:
                flattened.update(raw.get("static_requires_restart", {}))
                flattened.update(raw.get("dynamic_live_reload", {}))
            else:
                flattened = raw

            changed = {}
            ignored_static_keys = []
            is_initial_boot = (self._last_loaded == 0.0)

            with self._lock:
                for k, v in flattened.items():
                    if str(k).startswith("_"):
                        continue
                        
                    current_val = self._config.get(k)
                    if current_val != v:
                        if not is_initial_boot and k in _STATIC_KEYS:
                            # State Drift Protection: Reject live-mutation of static keys
                            ignored_static_keys.append(k)
                        else:
                            # Safely apply dynamic keys or initial boot parameters
                            changed[k] = v
                            self._config[k] = v
                            
                apply_env_overrides(self._config)
            
            self._last_loaded = mtime
            
            # Surface rejected static mutations to the operator
            if ignored_static_keys:
                LOGGER.warning(
                    "⚠️ Live-reload rejected changes to static keys: %s. "
                    "A full service restart is required for these configurations to take effect.", 
                    ignored_static_keys
                )

            if changed and not is_initial_boot and self._notify_cb:
                self._notify_cb(changed)
                
        except Exception as exc:
            LOGGER.error("Failed to parse configuration file %s: %s", self.file_path, exc)

    def start_watcher(self, interval: float = 5.0) -> None:
        if self._watcher_active:
            return
        self._watcher_active = True
        
        def _watch():
            LOGGER.debug("Configuration file live-watcher activated.")
            while True:
                time.sleep(interval)
                try:
                    mtime = self.file_path.stat().st_mtime
                    if mtime > self._last_loaded:
                        LOGGER.info("Config file modification detected. Reloading dynamic parameters...")
                        self._load()
                except Exception as e:
                    LOGGER.debug("Config file watcher exception: %s", e)
                    
        t = threading.Thread(target=_watch, daemon=True, name="config-watcher")
        t.start()

    def set_notify(self, cb) -> None:
        self._notify_cb = cb

    def get(self, key: str, default=None):
        with self._lock:
            return self._config.get(key, default)

    def __getitem__(self, key: str):
        with self._lock:
            return self._config[key]

CONFIG = LiveConfig(DEFAULT_CONFIG, CONFIG_FILE)