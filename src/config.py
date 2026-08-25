"""
config.py – Configuration management engine.

RECENT FIXES:
- FIXED (STATE DRIFT VULNERABILITY): Enforced Configuration Immutability for static keys.
  During a live reload, if a key belonging to `_STATIC_KEYS` is altered in the config
  file, the `LiveConfig` engine explicitly rejects the in-memory mutation. This prevents
  live daemons (like FastAPI or Prometheus) from decoupling from the `CONFIG` singleton
  state. A warning is logged notifying the operator that a restart is required.
- CHANGED (2026-08-17, config.yaml migration): config.json is replaced by config.yaml —
  YAML instead of JSON so the file can carry real inline comments explaining what every
  setting does. Loading now goes through yaml.safe_load() instead of json.load()/loads().
  The old two-bucket static_requires_restart/dynamic_live_reload section split is gone;
  config.yaml instead groups keys into logical categories (network_and_devices,
  false_positive_engine, geofencing, etc.) — this was always purely cosmetic, since the
  actual restart-vs-live protection has always been enforced by whether a key's NAME is
  in `_STATIC_KEYS` below, independent of which file section it lived in. `_load()`'s
  flattening step now merges every top-level category (any top-level mapping whose name
  doesn't start with "_") instead of looking for those two specific section names.
"""
import os
import json
import threading
import time
import logging
from pathlib import Path

import yaml

LOGGER = logging.getLogger("home_ids.config")
CONFIG_FILE = Path(__file__).parent.parent / "config.yaml"

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
    "fritz_password", "fritz_api_token", "fastapi_port",
    "env_file"
}
# NOTE: "scheduled_tasks" was removed from this set (2026-08-17 config audit) — it was a
# legacy top-level schema (job -> {"enabled", "time"}) never actually read by any code.
# The real, working schedule lives under dynamic_live_reload.scheduler (job -> {"enabled",
# "cron", optional "script"}), polled by scripts/scheduler.py, plus autotune_schedule_cron
# for the weekly retrain job. See DEFAULT_CONFIG below.

def apply_env_overrides(config: dict) -> None:
    for env_key, cfg_key in _ENV_OVERRIDES.items():
        val = os.environ.get(env_key)
        if val:
            if cfg_key.endswith("_enabled"):
                config[cfg_key] = val.strip().lower() in ("1", "true", "yes", "on")
            else:
                config[cfg_key] = val

def load_env_file(env_path: Path) -> None:
    if not env_path.exists():
        return
    try:
        content = env_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            # Seamlessly handle copied systemd lines
            if line.startswith("Environment="):
                line = line[12:]
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception as e:
        LOGGER.error("Failed to load .env file %s: %s", env_path, e)

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
    "model_path": "models/ids_model.pkl",
    "alert_json_path": "alerts.json",
    "alert_json_max_bytes": 1073741824,
    "pihole_db": "/etc/pihole/pihole-FTL.db",
    "zeek_log_dir": "/opt/zeek/logs/current",
    "home_subnet": "192.168.1.0/24",
    # PHASE 0 FIX: multi-subnet support. Prefer this list; "home_subnet" (singular) is kept
    # only as a backward-compatible fallback for existing config files that don't set
    # this key yet — see resolve_home_subnets() below. Leave as [] to keep using the legacy
    # single-subnet key; populate it (e.g. ["192.168.1.0/24", "192.168.50.0/24"]) once you
    # have more than one home subnet to track.
    "home_subnets": [],
    "metrics_port": 9105,
    "geoip_db": "models/GeoLite2-City.mmdb",
    "geoip_asn_db": "",
    "ti_refresh_interval": 3600,
    "otx_api_key": "",
    "abuseipdb_api_key": "",
    "virustotal_api_key": "",
    "telegram_enabled": False,
    "telegram_token": "",
    "telegram_chat_id": "",
    "safe_ips": ["127.0.0.1", "192.168.1.1", "192.0.0.2"],
    "honeypot_ips": [],
    "safe_domains": [],       
    "safe_host_patterns": ["pihole", "pi-hole", "pi_hole", "pi.hole", "paperless", "fritz", "repeater"],
    "ollama_url": "",         
    "ollama_model": "llama3", 
    # PHASE 11: scripts/ollama_soc.py's per-pattern verdict cache TTL and per-run fresh-
    # query cap -- see config.yaml's threat_intel_and_ai category for the full rationale
    # (a live diagnostic run found single Ollama calls taking 14+ minutes under real load).
    "ollama_cache_ttl_seconds": 604800.0,
    "ollama_max_queries_per_run": 5,
    # Background job schedule, polled every 60s by scripts/scheduler.py. Cron fields are
    # minute/hour/day/month/dow with only "*", "*/N", or an exact integer supported per
    # field (no comma-lists, no ranges). "script" is an optional filename override for
    # when the job key doesn't match "<job_name>.py" — see scripts/retro_hunter.py, which
    # needs this because its job key doesn't match its own filename under the "scheduler"
    # key. The weekly/nightly retrain job (train_fp_classifier.py) is scheduled separately
    # via autotune_enabled/autotune_schedule_cron below, not through this dict. Times below
    # (2am / every-4h-from-midnight / 6am) are chosen so no two jobs fire in the same hour
    # as each other or as autotune_schedule_cron's 3am default.
    "scheduler": {
        "ollama_soc": {"enabled": True, "cron": "0 */4 * * *"},
        "retro_hunter": {"enabled": True, "cron": "0 2 * * *", "script": "retro_hunter.py"},
        "top_domains_report": {"enabled": True, "cron": "0 6 * * *"},
    },
    "decay_factor": 0.995,
    "device_type_overrides": {},
    "ips_enabled": True,           # Master switch for IPS
    "ips_pihole_enabled": True,    # Controls DNS Sinkholing
    "ips_router_enabled": False,   # Controls FastAPI Fritz!Box Hardware drop
    "ips_tarpit_enabled": True,    # Controls Layer-2 Scapy ARP Spoofing
    "interactive_blocking_enabled": False, # False = Autonomous Auto-Block, True = Require Telegram Approval
    "operator_release_cooldown_seconds": 3600.0, # 1-Hour Cooldown Period
    "pihole_api_url": "http://pihole",
    "pihole_api_password": "",
    "pihole_api_timeout_seconds": 5.0,
    "pihole_api_path": "/api/domains",  # AUDIT FIX #9: configurable Pi-hole API path (v6 base; code appends /deny/exact[/{domain}])
    "router_webhook_url": "http://127.0.0.1:8010/isolate",
    "router_webhook_timeout_seconds": 5.0,
    "fritz_ip": "192.168.1.1",
    "fritz_user": "admin",
    "fritz_password": "",
    "fritz_api_token": "",
    "fastapi_port": 8010,          # AUDIT FIX #13: document fastapi_port in defaults
    "telegram_allowed_chat_ids": [], # AUDIT FIX #10: allowlist for Telegram command senders (empty = allow all, for backward compat)
    "router_hosts_url": "http://127.0.0.1:8010/hosts",
    "router_hosts_timeout_seconds": 5.0,
    "ml_warmup_samples": 5000,
    "simulation_mode": False,
    "env_file": ".env",

    # CL-AFPE tunables (audit)
    "fp_lgbm_threshold": 0.75,
    "fp_embed_similarity_threshold": 0.82,
    "fp_combined_suppress_threshold": 0.80,
    "fp_combined_uncertain_threshold": 0.55,

    # PHASE 2: how long a SUSPICIOUS state with the same signature must persist
    # uninterrupted before it's escalated to HIGH.
    "suspicious_escalation_seconds": 600.0,
    # PHASE 3 (closed-loop autonomous actions): non-blocking "🔔 Auto-action" Telegram
    # notifications with a one-tap [Revoke] button, sent whenever fp_engine autonomously
    # immunizes a NEW domain. fp_revoke_action_ttl_seconds bounds how long the revoke
    # option stays offered.
    "fp_revoke_notifications_enabled": True,
    "fp_revoke_action_ttl_seconds": 86400.0,
    # PHASE 4 (device re-identification / MAC-rotation resilience — see
    # core/device_matching.py). All three are read by core/identity.py.
    "identity_reidentify_enabled": True,
    "identity_reidentify_min_confidence": 0.75,
    "identity_reidentify_window_seconds": 1800.0,

    # Device-identity fragmentation fix: the LAN's own gateway/router IP. A router
    # genuinely has multiple distinct physical MACs (one per LAN/WLAN/WAN interface), so
    # MAC-based cross-address-family correlation (identity_reidentify_* above) can never
    # fully unify it into one device_id on its own -- resolve_device_id() special-cases
    # this exact IP to always resolve to one fixed canonical device_id instead. Default
    # empty ("") so the special-case is inert until explicitly configured -- deliberately
    # NOT auto-derived from fritzbox_router.fritz_ip, which is a Fritz!Box-mitigation-
    # specific config value that happens to hold the same value on THIS deployment; kept
    # decoupled so device-identity resolution doesn't implicitly depend on the Fritz!Box
    # integration being configured/enabled.
    "gateway_ip": "",
}

class LiveConfig:
    def __init__(self, default_config: dict, file_path: Path):
        self.file_path = file_path
        self._config = dict(default_config)
        self._lock = threading.Lock()
        self._notify_cb = None
        self._last_loaded = 0.0
        self._watcher_active = False

        # PHASE 12: a separate, state-directory-scoped override layer for autonomous
        # tuning -- see _load_overrides() below for the full rationale. Computed the same
        # way env_path already is (relative to file_path's own directory) rather than via
        # the "state_path" config key, since that key comes FROM config and isn't resolved
        # yet at this point in __init__.
        self._overrides_path = self.file_path.parent / "state" / "config_overrides.json"
        self._last_overrides_loaded = 0.0

        env_path = self.file_path.parent / self._config.get("env_file", ".env")
        load_env_file(env_path)
        
        apply_env_overrides(self._config)
        self._load()

    def _load(self) -> None:
        if not self.file_path.exists():
            try:
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
                # Minimal auto-generated bootstrap (first-ever boot, no config.yaml on
                # disk yet) — a plain static/dynamic split with no per-key comments. The
                # rich, category-organized, fully-commented config.yaml is a hand-authored
                # deliverable (see CONFIG_AUDIT_REPORT.md); this fallback exists only so
                # the app never crashes on a totally fresh checkout with zero config.
                structured = {
                    "# NOTE": (
                        "auto-generated minimal bootstrap config — replace with the "
                        "fully-documented config.yaml from your deployment package for "
                        "real inline explanations of every setting."
                    ),
                    "static_requires_restart": {},
                    "dynamic_live_reload": {},
                }
                for k, v in self._config.items():
                    if k in _STATIC_KEYS:
                        structured["static_requires_restart"][k] = v
                    else:
                        structured["dynamic_live_reload"][k] = v
                self.file_path.write_text(yaml.safe_dump(structured, sort_keys=False), encoding="utf-8")
            except Exception as exc:
                LOGGER.error("Failed to create default config: %s", exc)
            return

        try:
            mtime = self.file_path.stat().st_mtime
            # PHASE 9 FIX: read_text() without an explicit encoding falls back to the
            # platform default (e.g. cp1252 on Windows, and even on Linux this is only
            # UTF-8 by convention, not guarantee — a minimal/POSIX C locale would hit the
            # same failure). config.yaml's comments are full of UTF-8 emoji/em-dashes, so a
            # non-UTF-8 default silently breaks every config reload with a decode error.
            # scheduler.py and scripts/ollama_soc.py's own config loaders already specified
            # encoding="utf-8" explicitly — this was the one inconsistent reader.
            raw = yaml.safe_load(self.file_path.read_text(encoding="utf-8")) or {}
            flattened = {}
            for section_name, section_val in raw.items():
                if str(section_name).startswith("_") or str(section_name).startswith("#"):
                    continue  # metadata, never treated as config
                if isinstance(section_val, dict):
                    # A category grouping (network_and_devices, false_positive_engine,
                    # scheduled_jobs, ... or the legacy static_requires_restart /
                    # dynamic_live_reload names) — merge its keys into the flat
                    # namespace CONFIG.get() actually reads from. Category names
                    # themselves are purely organizational; add/rename/split them
                    # freely in config.yaml without touching this code.
                    flattened.update(section_val)
                else:
                    # A bare top-level scalar/list — the file skipped categories
                    # entirely and is already flat. Still supported.
                    flattened[section_name] = section_val

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
                            
                env_path = self.file_path.parent / self._config.get("env_file", ".env")
                load_env_file(env_path)
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

            # PHASE 12: re-assert autonomous overrides on top of whatever config.yaml just
            # set. Without this, an operator editing any UNRELATED key in config.yaml would
            # silently clobber a previously-applied override back to its config.yaml
            # baseline (the per-key diff above compares self._config's current value
            # against the yaml value and treats a mismatch as "yaml changed this", with no
            # way to tell "the override changed it" apart from "the operator changed it in
            # config.yaml").
            self._load_overrides()

        except Exception as exc:
            LOGGER.error("Failed to parse configuration file %s: %s", self.file_path, exc)

    def _load_overrides(self) -> None:
        """PHASE 12: autonomous/self-tuning adjustments live HERE, never in config.yaml.
        config.yaml stays the human-authored, hand-edited baseline (the thing you'd diff,
        back up, or put under version control); this file
        (state/config_overrides.json) is a separate, plainly-inspectable layer written
        only by scripts/train_fp_classifier.py's threshold-calibration pass (see that
        file for the conservative, evidence-gated rule that writes to it) -- never by this
        class itself.

        Format: {"<config_key>": {"value": <override>, "baseline": <original>,
                 "set_at": <unix_ts>, "set_by": "<mechanism>", "reason": "<why>"}}

        Deleting this file (or any single key in it) instantly reverts to the config.yaml
        value on the next reload -- no code change, no restart, no config.yaml edit. Never
        touches _STATIC_KEYS: autonomous tuning is scoped to live-reloadable behavioral
        thresholds only, never paths/ports/secrets.

        Self-contained locking (acquires self._lock itself) -- callers must NOT already
        hold self._lock, since it's a plain non-reentrant threading.Lock and a second
        acquire from the same thread would deadlock.
        """
        if not self._overrides_path.exists():
            return
        try:
            mtime = self._overrides_path.stat().st_mtime
            raw = json.loads(self._overrides_path.read_text(encoding="utf-8"))
        except Exception as exc:
            LOGGER.warning("Failed to parse config overrides file %s: %s", self._overrides_path, exc)
            return

        applied = {}
        with self._lock:
            for key, entry in raw.items():
                if not isinstance(entry, dict) or "value" not in entry:
                    continue
                if key in _STATIC_KEYS:
                    LOGGER.warning(
                        "Ignoring autonomous override for static key '%s' -- self-tuning is "
                        "scoped to live-reloadable keys only.", key
                    )
                    continue
                value = entry["value"]
                if self._config.get(key) != value:
                    self._config[key] = value
                    applied[key] = value

        self._last_overrides_loaded = mtime
        if applied:
            LOGGER.info("🔧 Applied %d autonomous config override(s): %s", len(applied), applied)
            if self._notify_cb:
                self._notify_cb(applied)

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
                        self._load()  # re-applies overrides at the end too
                    else:
                        # PHASE 12: config.yaml itself didn't change, but the override
                        # layer is written by a completely separate process
                        # (train_fp_classifier.py) on its own schedule -- check it
                        # independently so an autonomous adjustment applies live instead
                        # of waiting on an unrelated config.yaml edit to trigger a reload.
                        # _load_overrides() acquires its own lock; do not wrap it here.
                        self._load_overrides()
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


def resolve_home_subnets(config) -> list:
    """PHASE 0 FIX: supports multiple home subnets. Prefers the new `home_subnets` list
    key; falls back to the legacy single `home_subnet` string key when the list is unset
    or empty, so existing config files keep working unchanged."""
    subnets = config.get("home_subnets", None)
    if subnets and isinstance(subnets, list):
        cleaned = [str(s).strip() for s in subnets if str(s).strip()]
        if cleaned:
            return cleaned
    legacy = config.get("home_subnet", "192.168.1.0/24")
    return [legacy] if legacy else []