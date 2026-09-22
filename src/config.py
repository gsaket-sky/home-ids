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
    "fritz_password", "fritz_api_token", "fastapi_port", "fastapi_bind_host",
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
    # 2026-09-16: rollback switch for argus/baseline/engine.py's Bayesian
    # Gaussian/Beta/Poisson/Markov + BOCPD changepoint scoring, live-wired into
    # argus/ops/live_engine.py's evaluate() this same day -- previously only ever run
    # by the separate, out-of-scope `.19` ingest daemon. Matches this codebase's own
    # standing precedent of a plain on/off switch for every newly-cut-over subsystem.
    "baseline_scoring_enabled": True,
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
    # Background job schedule, polled every 60s by scripts/scheduler.py. Cron fields are
    # minute/hour/day/month/dow with only "*", "*/N", or an exact integer supported per
    # field (no comma-lists, no ranges). "script" is an optional filename override for
    # when the job key doesn't match "<job_name>.py" — every job below needs it since
    # each one lives in src/argus/ops/, not src/scripts/. The weekly/nightly retrain job
    # (train_fp_classifier.py) is scheduled separately
    # via autotune_enabled/autotune_schedule_cron below, not through this dict. Times below
    # (2:45am / every-4h-from-midnight-at-:45 / 6am) are chosen so no two jobs fire in the
    # same hour as each other or as autotune_schedule_cron's 3am default.
    "scheduler": {
        # v16: the sole Layer-3 LLM review job (scripts/ollama_soc.py retired the same
        # release) — see config.yaml's own scheduled_jobs.scheduler.live_llm_review
        # comment for why. Also gated by detection_engine.llm_review_enabled.
        "live_llm_review": {"enabled": True, "cron": "45 */4 * * *", "script": "../argus/ops/live_llm_review.py"},
        # v16: the sole retro-hunt job (scripts/retro_hunter.py retired the same
        # release) — see config.yaml's own scheduled_jobs.scheduler.live_retro_hunter
        # comment for why.
        "live_retro_hunter": {"enabled": True, "cron": "45 2 * * *", "script": "../argus/ops/live_retro_hunter.py"},
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
    # BUGFIX (live audit, 2026-09-04): confirmed live that this Fritzbox's TR-064
    # GetWANAccessByIP query (used by reconcile_router_isolation_state()'s status
    # check, NOT the isolate/unisolate SET actions above) genuinely takes ~10s
    # round-trip -- every reconcile attempt was silently timing out against the 5s
    # router_webhook_timeout_seconds budget (caught by a bare except, nothing logged
    # above DEBUG), so example_pc's stale "still router-isolated" record never actually
    # got cleared despite the reconcile worker running on schedule and Fritzbox
    # genuinely reporting it unblocked. A separate, more generous timeout for the
    # read-only status QUERY path specifically -- the isolate/unisolate SET actions
    # keep their own existing 5s budget unchanged, since they aren't reported broken
    # and a SET's latency profile isn't necessarily the same as this GET's.
    "router_status_query_timeout_seconds": 20.0,
    "fritz_ip": "192.168.1.1",
    "fritz_user": "admin",
    "fritz_password": "",
    "fritz_api_token": "",
    "fastapi_port": 8010,          # AUDIT FIX #13: document fastapi_port in defaults
    # SECURITY: which interface main.py's internal FastAPI/uvicorn IPC daemon binds to.
    # Defaults to loopback-only -- the isolate/release/block endpoints are powerful
    # hardware-control actions, so out of the box a compromised/malicious device
    # elsewhere on the LAN can never reach them no matter what token it has, even if
    # the token leaks. Set to "0.0.0.0" (a deliberate, explicit operator choice -- see
    # config.yaml's own comment) only if you want those endpoints reachable from other
    # devices on your LAN (e.g. clicking Isolate/Release from a Grafana dashboard open
    # on a different machine) -- the bearer token becomes the only thing protecting
    # them at that point.
    "fastapi_bind_host": "127.0.0.1",
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

    # Health manager (core/health_manager.py) -- watchdog/heartbeat/resource-pressure
    # degradation, added 2026-09-14 in response to a real kernel-OOM-kill incident.
    # See Documentation/HEALTH_MANAGER_DEPENDENCY_MAP.md for the full design. None of
    # these are _STATIC_KEYS -- every value is read fresh via self.config.get(...) on
    # each check cycle, so tuning any threshold live via the console takes effect on
    # the next cycle, no restart needed.
    "health_manager_enabled": True,
    "health_manager_check_interval_seconds": 15.0,
    # Deliberately generous -- see health_manager.py's own bugfix comment on
    # _check_cycle()'s pipeline_main_loop check: this is NOT poll_interval (the
    # sleep between iterations), it's a floor for how long one _step() call can
    # legitimately take (a cold-start backlog, a burst of devices/evidence)
    # before being treated as stale. A too-tight value here false-triggered a
    # self-restart 44 seconds after this subsystem's first-ever boot.
    "health_manager_pipeline_loop_expected_interval_seconds": 60.0,
    "health_manager_auto_recovery_enabled": True,
    "health_manager_recovery_max_attempts": 5,
    "health_manager_rss_pressure_mb": 1024.0,
    "health_manager_rss_conservation_mb": 1536.0,
    "health_manager_rss_critical_mb": 1843.0,
    "health_manager_swap_pressure_pct": 40.0,
    "health_manager_swap_conservation_pct": 60.0,
    "health_manager_swap_critical_pct": 80.0,
    "health_manager_sysmem_pressure_pct": 75.0,
    "health_manager_min_available_mb": 512.0,
    "health_manager_critical_sustain_checks": 3,
    "health_manager_recovery_confirm_seconds": 60.0,
    "health_manager_job_staleness_hours": 30.0,
}

class LiveConfig:
    def __init__(self, default_config: dict, file_path: Path):
        self.file_path = file_path
        self._config = dict(default_config)
        self._lock = threading.Lock()
        # BUGFIX (2026-09-15, live audit -- console log_level change silently not
        # applying): this was a SINGLE callback slot (`self._notify_cb = None`,
        # `set_notify()` overwriting it), but main.py's setup_logging() (the
        # log-level live-reload hook) AND core/pipeline.py's EnginePipeline (its own
        # dynamic-config hook, for safe_ips/telegram_enabled/home_subnets/etc.) both
        # call set_notify() on the SAME process's CONFIG singleton -- confirmed live:
        # EnginePipeline registers its own callback AFTER setup_logging() already
        # registered log_level's, silently discarding it with no error/warning
        # anywhere. Console PATCH /api/config/log_level DID correctly update
        # CONFIG's in-memory value (confirmed via journalctl: "Applied 1 autonomous
        # config override(s)") and pipeline.py's OWN handler correctly fired
        # ("Dynamic configuration change detected") -- but main.py's handler, the
        # one that actually calls logging.getLogger().setLevel(), never ran again.
        # Now a list of subscribers, not one slot -- every registered callback
        # fires on every change, each isolated so one subscriber's exception can't
        # block another's (matches this class's own established non-fatal/caught
        # resilience pattern elsewhere).
        self._notify_cbs: list = []
        self._last_loaded = 0.0
        self._watcher_active = False

        # PHASE 12: a separate, state-directory-scoped override layer for autonomous
        # tuning -- see _load_overrides() below for the full rationale. Computed the same
        # way env_path already is (relative to file_path's own directory) rather than via
        # the "state_path" config key, since that key comes FROM config and isn't resolved
        # yet at this point in __init__.
        self._overrides_path = self.file_path.parent / "state" / "config_overrides.json"
        self._last_overrides_loaded = 0.0
        # BUGFIX (console hot-reload gap): tracks {key: baseline} for every override this
        # instance currently has applied FROM THE FILE, so the next poll can tell "this key
        # is still in the file" apart from "this key was just removed" -- see
        # _load_overrides()'s own comment for why this matters across process boundaries.
        self._active_file_overrides: dict = {}

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

            if changed and not is_initial_boot:
                self._fire_notify(changed)

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

        BUGFIX (console hot-reload gap, found live: reverting a config override in the
        console UI updated the console/API process's own CONFIG instantly, but the actual
        detection engine -- a SEPARATE OS process (main.py spawns middleware.main_api:app
        via subprocess.Popen, each with its own LiveConfig singleton) -- kept running on the
        stale overridden value indefinitely, only picking up config.yaml/override ADDITIONS
        via its 10s watcher poll (EnginePipeline.__init__ -> start_watcher()), never a
        removal, until a full service restart. This method used to only ever APPLY entries
        present in the file; config_api.py's DELETE endpoint could revert its OWN process's
        CONFIG (revert_override(), below) but had no way to reach any other process's
        instance except through this same file both sides already poll. Fixed by tracking
        which keys THIS instance applied from the file last time (_active_file_overrides)
        and reverting any that disappeared since, using the very baseline the override
        entry itself carried -- no new file or cross-process signal needed, since a revert
        is now just as observable from the file as a set already was.
        """
        if not self._overrides_path.exists():
            raw = {}
        else:
            try:
                mtime = self._overrides_path.stat().st_mtime
                raw = json.loads(self._overrides_path.read_text(encoding="utf-8"))
            except Exception as exc:
                LOGGER.warning("Failed to parse config overrides file %s: %s", self._overrides_path, exc)
                return

        applied = {}
        reverted = {}
        with self._lock:
            current_keys = set()
            for key, entry in raw.items():
                if not isinstance(entry, dict) or "value" not in entry:
                    continue
                if key in _STATIC_KEYS:
                    LOGGER.warning(
                        "Ignoring autonomous override for static key '%s' -- self-tuning is "
                        "scoped to live-reloadable keys only.", key
                    )
                    continue
                current_keys.add(key)
                value = entry["value"]
                if self._config.get(key) != value:
                    self._config[key] = value
                    applied[key] = value
                self._active_file_overrides[key] = entry.get("baseline")

            # Any key THIS instance previously applied from the file that's no longer in
            # it was removed elsewhere (another process's DELETE, or a hand-edit) --
            # revert it to the baseline that override entry itself recorded.
            removed_keys = set(self._active_file_overrides) - current_keys
            for key in removed_keys:
                baseline = self._active_file_overrides.pop(key)
                if baseline is not None and self._config.get(key) != baseline:
                    self._config[key] = baseline
                    reverted[key] = baseline

        self._last_overrides_loaded = mtime if self._overrides_path.exists() else time.time()
        if applied:
            LOGGER.info("🔧 Applied %d autonomous config override(s): %s", len(applied), applied)
        if reverted:
            LOGGER.info("↩️ Reverted %d config override(s) removed from %s: %s", len(reverted), self._overrides_path, reverted)
        if applied or reverted:
            self._fire_notify({**reverted, **applied})

    def revert_override(self, key: str, value) -> None:
        """Pushes `key` back to its config.yaml baseline value immediately, in-memory, in
        THIS process, without waiting for its own next watcher poll. Called directly by
        the config API's DELETE endpoint right after it removes the entry from
        state/config_overrides.json, so the process handling that HTTP request reflects
        the revert with zero latency instead of waiting up to its own poll interval.
        Callers pass the removed override entry's own "baseline" field as `value`. Never
        touches _STATIC_KEYS -- same restriction as _load_overrides(), enforced by the
        caller not exposing static keys as revertible in the first place, not re-checked
        here.

        This does NOT, by itself, reach any OTHER process's LiveConfig instance (e.g. the
        detection engine, running as its own OS process with its own instance) -- that
        happens separately, the next time each instance's own watcher polls the shared
        overrides file and _load_overrides() notices the key is gone (see that method's
        own bugfix note for why this used to never happen for removals).

        Fires every registered notify subscriber the same way _load_overrides()
        does -- a revert is as much a "this key's effective value just changed"
        event as an apply is (e.g. main.py's log_level live-reload hook needs to
        hear about a revert-to-baseline too, not just a PATCH).
        """
        with self._lock:
            changed = self._config.get(key) != value
            self._config[key] = value
            self._active_file_overrides.pop(key, None)
        if changed:
            self._fire_notify({key: value})

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
        """Registers `cb` as an ADDITIONAL config-change subscriber -- does not
        replace any previously-registered callback (see this class's own
        __init__ comment on _notify_cbs for the real bug this closes: multiple
        independent parts of this codebase each need their own dynamic-reload
        hook on the same process's CONFIG singleton)."""
        self._notify_cbs.append(cb)

    def _fire_notify(self, changed: dict) -> None:
        """Calls every registered subscriber with `changed`, isolated so one
        callback raising never prevents the others from running."""
        for cb in self._notify_cbs:
            try:
                cb(changed)
            except Exception:
                LOGGER.exception("Config-change notify callback raised, continuing with remaining subscribers")

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