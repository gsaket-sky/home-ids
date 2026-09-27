"""
config_schema.py -- hand-authored metadata for every config.yaml key: which section it
lives in, its type (for validation/coercion), a short human description, the suggested
default, and whether it actually requires a restart to take effect.

This is documentation, not derived from config.yaml at import time -- the descriptions
and suggested defaults are curated the same way config.yaml's own inline comments are,
and need updating by hand if config.yaml's own defaults/behavior change.

restart_required is NOT simply "key in _STATIC_KEYS": config.py's _STATIC_KEYS is the
set config.py itself enforces (rejects a live-reload mutation with a warning), but a
few keys are read only ONCE at object-construction time by their own consumer and are
therefore also effectively restart-only even though config.py would happily accept a
live change to them. RUNTIME_RESTART_KEYS below is that second, smaller set -- verified
against the actual read call sites (not assumed from config.yaml's inline comments,
which turned out to have at least one stale tag -- see the module docstring note in
Documentation/CONFIG_API.md):
  - lateral_movement_ports: src/core/pipeline.py's PipelineOrchestrator.__init__ passes
    it once into ZeekFeatureExtractor(...)'s constructor.
  - local_confirmed_intel_ttl_seconds: src/intelligence/fp_engine.py's
    AutonomousFPEngine.__init__ passes it once into LocalConfirmedIntel(...)'s
    constructor.
reactive_capture_zeek_memory_limit_mb / reactive_capture_suricata_memory_limit_mb were
also checked against their read site (src/extractors/fritzbox_capture.py:561-562, read
fresh via config.get() on every capture burst -- genuinely live, correctly NOT in this
set) -- see Documentation/CONFIG_API.md for why that's called out explicitly.

device_type_overrides is deliberately excluded from CONFIG_SCHEMA -- it's a dict, not a
scalar/list/enum, and gets its own dedicated merge-aware endpoints
(PATCH/DELETE /api/config/device_type_overrides/{pattern}) in routers/config_api.py
instead of the generic per-key PATCH/DELETE.
"""
from config import _STATIC_KEYS

RUNTIME_RESTART_KEYS = frozenset({
    "lateral_movement_ports",
    "local_confirmed_intel_ttl_seconds",
})


def is_restart_required(key: str) -> bool:
    return key in _STATIC_KEYS or key in RUNTIME_RESTART_KEYS


# Each row: s(ection), k(ey), t(ype: bool|number|string|list|enum), desc, def(ault).
# t drives validation/coercion in the API; "enum" rows carry an extra "options" list.
CONFIG_SCHEMA = [
    {"s": "service_ports", "k": "metrics_port", "t": "number", "def": 9105,
     "desc": "Prometheus /metrics scrape port -- Grafana dashboards read from here."},
    {"s": "service_ports", "k": "fastapi_port", "t": "number", "def": 8010,
     "desc": "Local IPC/webhook port for Telegram bot callbacks and Fritz!Box isolate/hosts endpoints. Not meant to be internet-exposed."},
    {"s": "service_ports", "k": "fastapi_bind_host", "t": "string", "def": "0.0.0.0",
     "desc": "Interface this process's webhook API binds to. 0.0.0.0 exposes isolate/release endpoints to the whole LAN -- protected only by the fritz_api_token secret."},

    {"s": "paths", "k": "state_path", "t": "string", "def": "state/ids_state.json",
     "desc": "Per-device baselines + IPS mitigation state, persisted between restarts."},
    {"s": "paths", "k": "model_path", "t": "string", "def": "models/ids_model.pkl",
     "desc": "Trained per-device/global ML anomaly model -- loaded at boot, saved on retrain."},
    {"s": "paths", "k": "geoip_db", "t": "string", "def": "models/GeoLite2-City.mmdb",
     "desc": "MaxMind city GeoIP DB -- required for GeoIP telemetry and for geofencing to fire at all."},
    {"s": "paths", "k": "geoip_asn_db", "t": "string", "def": "models/GeoLite2-ASN.mmdb",
     "desc": "Optional MaxMind ASN DB -- enables ASN/org name in GeoIP telemetry; missing file just leaves ASN as unknown."},
    {"s": "paths", "k": "alert_json_path", "t": "string", "def": "state/alerts.json",
     "desc": "Every evaluated alert is appended here -- also the training source for the weekly FP classifier retrain."},
    {"s": "paths", "k": "alert_json_max_bytes", "t": "number", "def": 1073741824,
     "desc": "Prune older alert entries once this file exceeds this size, in bytes (default 1 GiB)."},
    {"s": "paths", "k": "env_file", "t": "string", "def": ".env",
     "desc": "Path to the secrets file, relative to this config's own directory."},

    {"s": "network_and_devices", "k": "home_subnet", "t": "string", "def": "192.168.1.0/24",
     "desc": "Your LAN in CIDR form -- fallback used only while home_subnets is empty."},
    {"s": "network_and_devices", "k": "home_subnets", "t": "list", "def": [],
     "desc": "Preferred multi-subnet form -- a list of CIDR ranges. Populate once you track more than one subnet."},
    {"s": "network_and_devices", "k": "max_device_states", "t": "number", "def": 5000,
     "desc": "Safety cap on distinct devices tracked at once (memory/disk bound)."},
    {"s": "network_and_devices", "k": "safe_ips", "t": "list", "def": ["127.0.0.1", "192.168.1.1", "192.0.0.2"],
     "desc": "IPs never treated as suspicious destinations -- your own infra (DNS server, router, this host)."},
    {"s": "network_and_devices", "k": "honeypot_ips", "t": "list", "def": [],
     "desc": "Decoy IP(s) -- any device contacting one gets an instant max risk score. Only meaningful with a real fake listener there."},
    {"s": "network_and_devices", "k": "safe_domains", "t": "list", "def": [],
     "desc": "Domains never treated as suspicious anywhere -- exact-match exclusion."},
    {"s": "network_and_devices", "k": "safe_cdn_base_domains", "t": "list", "def": [],
     "desc": "eTLD+1 domains treated as known-safe CDN/vendor infra for the DNS-tunneling/evasion exemption checks specifically."},
    {"s": "network_and_devices", "k": "safe_host_patterns", "t": "list",
     "def": ["pihole", "pi-hole", "pi_hole", "pi.hole", "paperless", "fritz", "repeater"],
     "desc": "Hostname substrings marking a device as safe infrastructure -- dampens noisy behavioral evidence without suppressing reputation/honeypot findings."},

    {"s": "detection_engine", "k": "log_level", "t": "enum", "def": "INFO",
     "options": ["DEBUG", "INFO", "WARNING", "ERROR"], "desc": "Python logging verbosity."},
    {"s": "detection_engine", "k": "poll_interval", "t": "number", "def": 2.0,
     "desc": "Seconds between Pi-hole DB polls. 2s is optimal -- Pi-hole's DB is event-driven, lower doesn't help."},
    {"s": "detection_engine", "k": "window_seconds", "t": "number", "def": 300,
     "desc": "Sliding window for rate/entropy/uniqueness baselines (5 min)."},
    {"s": "detection_engine", "k": "startup_lookback_seconds", "t": "number", "def": 300,
     "desc": "How far back to backfill from existing logs before going live on startup."},
    {"s": "detection_engine", "k": "alert_threshold", "t": "number", "def": 6.0,
     "desc": "Risk score (0-10) at which an evaluation becomes an alert. Well-calibrated after FP sensitivity fixes."},
    {"s": "detection_engine", "k": "threshold_std_dev", "t": "number", "def": 3.0,
     "desc": "Standard-deviation multiplier for statistical anomaly thresholds."},
    {"s": "detection_engine", "k": "ml_warmup_samples", "t": "number", "def": 5000,
     "desc": "Samples a device's ML model needs before active scoring (~2.8h at current traffic)."},
    {"s": "detection_engine", "k": "baseline_alpha", "t": "number", "def": 0.05,
     "desc": "EWMA smoothing factor for rate/entropy/unique-domain baselines -- don't change without reason."},
    {"s": "detection_engine", "k": "baseline_scoring_enabled", "t": "bool", "def": True,
     "desc": "Bayesian Gaussian/Beta/Poisson/Markov + BOCPD changepoint baseline scoring, live per-device per-cycle. Rollback switch, not a tuning knob."},
    {"s": "detection_engine", "k": "llm_review_enabled", "t": "bool", "def": True,
     "desc": "Layer-3 LLM review job (argus/ops/live_llm_review.py). Advisory/reporting only -- does not autonomously suppress or confirm alerts."},
    {"s": "detection_engine", "k": "decay_factor", "t": "number", "def": 0.995,
     "desc": "Decay factor for domain-count baselines (~4.6 min half-life)."},
    {"s": "detection_engine", "k": "suspicious_escalation_seconds", "t": "number", "def": 600.0,
     "desc": "How long a SUSPICIOUS state must persist with the same signature before escalating to HIGH."},
    {"s": "detection_engine", "k": "incident_grouping_window_seconds", "t": "number", "def": 1800.0,
     "desc": "Gap since the last occurrence of a device+target+signature before it's a new incident rather than a continuation."},
    {"s": "detection_engine", "k": "incident_update_min_interval_seconds", "t": "number", "def": 900.0,
     "desc": "Minimum spacing between periodic Telegram re-notifications for one open incident. Severity escalations always notify immediately."},
    {"s": "detection_engine", "k": "arp_sweep_unique_targets_threshold", "t": "number", "def": 8,
     "desc": "Distinct IPs ARP-requested within one window to flag as a host-discovery sweep."},
    {"s": "detection_engine", "k": "lateral_movement_unique_targets_threshold", "t": "number", "def": 2,
     "desc": "Distinct destination IPs on lateral-movement ports within one window before it's treated as lateral movement rather than routine single-service access."},
    {"s": "detection_engine", "k": "lateral_movement_ports", "t": "list", "def": [22, 445, 3389, 5900, 23],
     "desc": "Destination ports treated as lateral-movement-relevant. RESTART REQUIRED: read once at ZeekFeatureExtractor construction (src/core/pipeline.py)."},

    {"s": "false_positive_engine", "k": "local_confirmed_intel_ttl_seconds", "t": "number", "def": 2592000.0,
     "desc": "How long a confirmed-threat IOC stays a hard-stop for other devices touching it (30 days). RESTART REQUIRED: read once at AutonomousFPEngine construction (src/intelligence/fp_engine.py)."},
    {"s": "false_positive_engine", "k": "fp_lgbm_threshold", "t": "number", "def": 0.75,
     "desc": "Stage 2: minimum LightGBM P(false positive) to lean toward suppression. Lower = trusts the tabular model more readily."},
    {"s": "false_positive_engine", "k": "fp_embed_similarity_threshold", "t": "number", "def": 0.82,
     "desc": "Stage 3: minimum cosine similarity to a known-safe vendor domain pattern to count as a match."},
    {"s": "false_positive_engine", "k": "fp_combined_suppress_threshold", "t": "number", "def": 0.80,
     "desc": "Combined confidence required to auto-suppress an alert as a false positive. Also the one value the weekly self-calibration pass may autonomously lower via this same override file -- editing it here just sets a new human-set baseline for that process."},
    {"s": "false_positive_engine", "k": "fp_combined_uncertain_threshold", "t": "number", "def": 0.55,
     "desc": "Combined confidence above which an alert that didn't clear suppression still gets tagged Low Confidence instead of a normal alert."},
    {"s": "false_positive_engine", "k": "fp_revoke_notifications_enabled", "t": "bool", "def": True,
     "desc": "Send a one-tap Revoke notification whenever the engine autonomously immunizes a new domain."},
    {"s": "false_positive_engine", "k": "fp_revoke_action_ttl_seconds", "t": "number", "def": 86400.0,
     "desc": "How long the one-tap Revoke option stays available after an autonomous immunization (24h)."},

    {"s": "device_identity", "k": "identity_reidentify_enabled", "t": "bool", "def": True,
     "desc": "Whether a device that rotates its MAC/IP can be auto-relinked to its prior identity instead of starting a fresh cold-start profile."},
    {"s": "device_identity", "k": "identity_reidentify_min_confidence", "t": "number", "def": 0.75,
     "desc": "Minimum match-confidence (DHCP fingerprint + JA3/JA4 overlap) required to auto-merge two identities."},
    {"s": "device_identity", "k": "identity_reidentify_window_seconds", "t": "number", "def": 1800.0,
     "desc": "How long a candidate stays eligible for re-identification merging after last being seen (30 min)."},
    {"s": "device_identity", "k": "gateway_ip", "t": "string", "def": "",
     "desc": "Your router's IP -- pinned to one canonical device_id since a router genuinely has multiple physical MACs. Blank disables this special case."},

    {"s": "ips_mitigation", "k": "ips_enabled", "t": "bool", "def": True,
     "desc": "Global kill switch for all active response. False = detection-only, nothing gets blocked."},
    {"s": "ips_mitigation", "k": "ips_pihole_enabled", "t": "bool", "def": True,
     "desc": "Controls DNS sinkholing specifically."},
    {"s": "ips_mitigation", "k": "ips_router_enabled", "t": "bool", "def": False,
     "desc": "Controls Fritz!Box hardware WAN-access isolation specifically."},
    {"s": "ips_mitigation", "k": "ips_tarpit_enabled", "t": "bool", "def": True,
     "desc": "Controls the Layer-2 ARP-tarpit response specifically."},
    {"s": "ips_mitigation", "k": "ips_tarpit_follows_router_isolation", "t": "bool", "def": True,
     "desc": "Router-level isolation (Fritz!Box TR-064) only blocks IPv4 -- when true, a router isolation also arms the Layer-2 tarpit for the same device, covering its IPv6 path too (router-agnostic; works regardless of the tarpit's own risk-score threshold). False restores the old behavior where each mechanism only fires on its own separate trigger."},
    {"s": "ips_mitigation", "k": "interactive_blocking_enabled", "t": "bool", "def": False,
     "desc": "True = a human must approve a hardware isolation action in Telegram before it executes. False = fully autonomous auto-block."},
    {"s": "ips_mitigation", "k": "operator_release_cooldown_seconds", "t": "number", "def": 3600.0,
     "desc": "Cooldown after a manual release before a device can be auto-isolated again (1h)."},
    {"s": "ips_mitigation", "k": "simulation_mode", "t": "bool", "def": False,
     "desc": "Log IPS actions as if they executed without touching the network -- dry-run/testing mode."},

    {"s": "pihole_integration", "k": "pihole_api_url", "t": "string", "def": "http://pihole",
     "desc": "Base URL of your Pi-hole instance's admin API."},
    {"s": "pihole_integration", "k": "pihole_api_path", "t": "string", "def": "/api/domains",
     "desc": "Pi-hole v6 API base path for domain sinkholing calls."},
    {"s": "pihole_integration", "k": "pihole_api_timeout_seconds", "t": "number", "def": 5.0,
     "desc": "HTTP timeout for Pi-hole API calls."},

    {"s": "fritzbox_router", "k": "fritz_ip", "t": "string", "def": "192.168.1.1",
     "desc": "Fritz!Box LAN IP -- target for TR-064 isolation calls."},
    {"s": "fritzbox_router", "k": "fritz_user", "t": "string", "def": "admin",
     "desc": "Fritz!Box admin username for TR-064 login."},
    {"s": "fritzbox_router", "k": "router_webhook_timeout_seconds", "t": "number", "def": 5.0,
     "desc": "HTTP timeout for the isolate-device webhook call."},
    {"s": "fritzbox_router", "k": "router_hosts_url", "t": "string", "def": "http://127.0.0.1:8010/hosts",
     "desc": "URL this process polls to keep the router's connected-hosts list in sync."},
    {"s": "fritzbox_router", "k": "router_hosts_timeout_seconds", "t": "number", "def": 5.0,
     "desc": "Timeout for that hosts-list poll."},
    {"s": "fritzbox_router", "k": "router_status_query_timeout_seconds", "t": "number", "def": 20.0,
     "desc": "Separate, more generous timeout for the reconcile status query -- measured ~10s round-trip on real hardware."},

    {"s": "telegram", "k": "telegram_enabled", "t": "bool", "def": False,
     "desc": "Master switch for Telegram alerting."},
    {"s": "telegram", "k": "telegram_allowed_chat_ids", "t": "list", "def": [],
     "desc": "Allowlist of chat IDs permitted to send bot commands. Empty = allow from any chat that has the bot."},

    {"s": "threat_intel_and_ai", "k": "ti_refresh_interval", "t": "number", "def": 3600,
     "desc": "How often OTX/AbuseIPDB/VirusTotal feeds refresh (hourly)."},
    {"s": "threat_intel_and_ai", "k": "ollama_url", "t": "string", "def": "",
     "desc": "Base URL of your local Ollama server for LLM-based alert triage/summaries."},
    {"s": "threat_intel_and_ai", "k": "ollama_model", "t": "string", "def": "llama3",
     "desc": "Ollama model name used for triage/summary requests."},
    {"s": "threat_intel_and_ai", "k": "ollama_v13_max_queries_per_run", "t": "number", "def": 5,
     "desc": "Hard cap on fresh Ollama calls per live_llm_review.py scheduled run -- cache hits don't count."},

    {"s": "geofencing", "k": "geofencing_enabled", "t": "bool", "def": True,
     "desc": "Master switch -- contacting a blocked country's IP gets an instant CRITICAL/block verdict."},
    {"s": "geofencing", "k": "geofencing_countries", "t": "list", "def": [],
     "desc": "ISO country codes to block. Blocklist only -- no allowlist or time-of-day mode today."},
    {"s": "geofencing", "k": "geofencing_exempt_ips", "t": "list", "def": [],
     "desc": "Destination IPs exempted from the geofencing hard-stop despite their country -- still subject to every other detector."},

    {"s": "reactive_capture", "k": "reactive_capture_enabled", "t": "bool", "def": True,
     "desc": "Master switch for diagnostic-capture bursts."},
    {"s": "reactive_capture", "k": "reactive_capture_max_bursts_per_hour", "t": "number", "def": 6,
     "desc": "Shared hourly budget every trigger draws from -- one burst captures the whole radio regardless of which trigger fired it."},
    {"s": "reactive_capture", "k": "reactive_capture_max_bytes_per_hour", "t": "number", "def": 500000000,
     "desc": "Second shared budget bounding cumulative bytes captured per hour. 0 disables (count-only)."},
    {"s": "reactive_capture", "k": "reactive_capture_max_scratch_bytes", "t": "number", "def": 5368709120,
     "desc": "Hard ceiling on the reactive_capture_scratch_dir's total disk usage (default 5GB). Oldest entries are pruned first when exceeded; if pruning can't recover enough space, new captures are rejected until it does. 0 falls back to the same 5GB default, not unlimited."},
    {"s": "reactive_capture", "k": "reactive_capture_new_device_trigger_enabled", "t": "bool", "def": True,
     "desc": "Fire a capture burst when a new device is first seen."},
    {"s": "reactive_capture", "k": "reactive_capture_arp_sweep_trigger_enabled", "t": "bool", "def": True,
     "desc": "Fire a capture burst on a detected ARP sweep."},
    {"s": "reactive_capture", "k": "reactive_capture_dns_trigger_enabled", "t": "bool", "def": True,
     "desc": "Fire a capture burst on a DNS-based trigger."},
    {"s": "reactive_capture", "k": "reactive_capture_high_severity_trigger_enabled", "t": "bool", "def": True,
     "desc": "Fire a capture burst on a HIGH/CRITICAL severity evaluation."},
    {"s": "reactive_capture", "k": "reactive_capture_reid_ambiguous_trigger_enabled", "t": "bool", "def": True,
     "desc": "Fire a burst when MAC-rotation re-identification finds a candidate too ambiguous to auto-merge."},
    {"s": "reactive_capture", "k": "reactive_capture_wired_probe_trigger_enabled", "t": "bool", "def": True,
     "desc": "Fire a burst when a new source IP contacts one of the wired-probe devices below."},
    {"s": "reactive_capture", "k": "reactive_capture_wired_probe_ips", "t": "list", "def": [],
     "desc": "Wired devices (full Zeek visibility already) this trigger watches for a new source."},
    {"s": "reactive_capture", "k": "reactive_capture_spotcheck_enabled", "t": "bool", "def": True,
     "desc": "Periodic in-process baseline spot-check burst."},
    {"s": "reactive_capture", "k": "reactive_capture_spotcheck_interval_seconds", "t": "number", "def": 1800.0,
     "desc": "Interval between spot-check bursts (30 min)."},
    {"s": "reactive_capture", "k": "reactive_capture_radios", "t": "list", "def": ["ath0", "ath1"],
     "desc": "Fritzbox radio interfaces captured per burst."},
    {"s": "reactive_capture", "k": "reactive_capture_burst_seconds", "t": "number", "def": 120.0,
     "desc": "Length of one capture burst -- ~100MB at measured dual-radio throughput."},
    {"s": "reactive_capture", "k": "reactive_capture_snaplen", "t": "number", "def": 1600,
     "desc": "Per-packet snapshot length (bytes) requested from the router."},
    {"s": "reactive_capture", "k": "reactive_capture_scratch_dir", "t": "string", "def": "state/reactive_capture",
     "desc": "Where raw/converted pcaps and Zeek scratch output are written."},
    {"s": "reactive_capture", "k": "reactive_capture_delete_after_ingest", "t": "bool", "def": True,
     "desc": "Delete raw pcaps/Zeek scratch right after ingestion. A compact JSONL summary is kept regardless."},
    {"s": "reactive_capture", "k": "reactive_capture_suricata_enabled", "t": "bool", "def": False,
     "desc": "Batch signature/exploit scan of the same burst pcap Zeek reprocesses -- runs once per burst, never continuously."},
    {"s": "reactive_capture", "k": "reactive_capture_suricata_timeout_seconds", "t": "number", "def": 240.0,
     "desc": "Max seconds for one batch Suricata scan before giving up (non-fatal)."},
    {"s": "reactive_capture", "k": "reactive_capture_zeek_memory_limit_mb", "t": "number", "def": 0,
     "desc": "Virtual-memory ceiling for the Zeek child process. 0 disables. POSIX-only. Read fresh per burst -- genuinely LIVE."},
    {"s": "reactive_capture", "k": "reactive_capture_suricata_memory_limit_mb", "t": "number", "def": 0,
     "desc": "Virtual-memory ceiling for the Suricata child process. 0 disables. POSIX-only. Read fresh per burst -- genuinely LIVE."},
    {"s": "reactive_capture", "k": "reactive_capture_zeek_bin", "t": "string", "def": "/opt/zeek/bin/zeek",
     "desc": "Path to the zeek binary used to reprocess a capture burst offline."},
    {"s": "reactive_capture", "k": "reactive_capture_suricata_bin", "t": "string", "def": "/usr/bin/suricata",
     "desc": "Path to the suricata binary for offline batch scans only."},
    {"s": "reactive_capture", "k": "reactive_capture_suricata_rules_path", "t": "string", "def": "",
     "desc": "Suricata rules file -- not shipped by this project, manage via suricata-update. Missing file = scan silently finds nothing."},

    {"s": "scheduled_jobs", "k": "autotune_enabled", "t": "bool", "def": True,
     "desc": "Weekly false-positive classifier retrain switch."},
    {"s": "scheduled_jobs", "k": "autotune_schedule_cron", "t": "string", "def": "0 3 * * *",
     "desc": "Cron for the weekly retrain (3am)."},
    {"s": "scheduled_jobs", "k": "scheduler.live_llm_review.enabled", "t": "bool", "def": True,
     "desc": "LLM alert-triage summary job (the sole Layer-3 reviewer as of v16)."},
    {"s": "scheduled_jobs", "k": "scheduler.live_llm_review.cron", "t": "string", "def": "45 */4 * * *",
     "desc": "Every 4 hours at :45."},
    {"s": "scheduled_jobs", "k": "scheduler.live_retro_hunter.enabled", "t": "bool", "def": True,
     "desc": "Retroactive threat-intel re-scan of recent history (the sole retro-hunt job as of v16)."},
    {"s": "scheduled_jobs", "k": "scheduler.live_retro_hunter.cron", "t": "string", "def": "45 2 * * *",
     "desc": "Runs at 2:45am."},
    {"s": "scheduled_jobs", "k": "scheduler.top_domains_report.enabled", "t": "bool", "def": True,
     "desc": "Daily top-domains-per-device Markdown + Telegram summary."},
    {"s": "scheduled_jobs", "k": "scheduler.top_domains_report.cron", "t": "string", "def": "0 6 * * *",
     "desc": "Runs at 6am."},

    {"s": "external_system_paths", "k": "pihole_db", "t": "string", "def": "/etc/pihole/pihole-FTL.db",
     "desc": "Pi-hole's own SQLite FTL database -- a DIFFERENT install's layout, not this app's data."},
    {"s": "external_system_paths", "k": "zeek_log_dir", "t": "string", "def": "/opt/zeek/logs/current",
     "desc": "Directory Zeek writes live logs into -- driven by YOUR zeekctl/node.cfg LogDir, not this file."},

    {"s": "health_manager", "k": "health_manager_enabled", "t": "bool", "def": True,
     "desc": "Master kill switch for the watchdog/health-manager subsystem. Disabling stops all heartbeat checks, resource-pressure monitoring, and auto-recovery."},
    {"s": "health_manager", "k": "health_manager_check_interval_seconds", "t": "number", "def": 15.0,
     "desc": "How often the health manager re-checks every component and resource levels."},
    {"s": "health_manager", "k": "health_manager_pipeline_loop_expected_interval_seconds", "t": "number", "def": 60.0,
     "desc": "Floor for how long one main-loop _step() call can legitimately take (NOT poll_interval, the sleep between calls) before being treated as stale. Too tight -> false self-restarts on a slow-but-working cycle."},
    {"s": "health_manager", "k": "health_manager_auto_recovery_enabled", "t": "bool", "def": True,
     "desc": "When false, heartbeats/alerts/resource-pressure monitoring still run, but no RECOVERY_ATTEMPT (process/subprocess restart) is ever triggered -- alert-only mode."},
    {"s": "health_manager", "k": "health_manager_recovery_max_attempts", "t": "number", "def": 5,
     "desc": "Recovery attempts (exponential backoff: immediate, 30s, 2min, 10min) before a component enters SAFE_MODE and waits for a human."},
    {"s": "health_manager", "k": "health_manager_rss_pressure_mb", "t": "number", "def": 1024.0,
     "desc": "Main process RSS above which resource-pressure mode engages (pauses TI enrichment)."},
    {"s": "health_manager", "k": "health_manager_rss_conservation_mb", "t": "number", "def": 1536.0,
     "desc": "RSS above which CONSERVATION mode engages (also disables reactive-capture bursts)."},
    {"s": "health_manager", "k": "health_manager_rss_critical_mb", "t": "number", "def": 1843.0,
     "desc": "RSS above which CRITICAL mode engages -- sustained, this triggers a proactive self-restart."},
    {"s": "health_manager", "k": "health_manager_swap_pressure_pct", "t": "number", "def": 40.0,
     "desc": "System swap-used percentage that alone can also trigger RESOURCE_PRESSURE."},
    {"s": "health_manager", "k": "health_manager_swap_conservation_pct", "t": "number", "def": 60.0,
     "desc": "System swap-used percentage that alone can also trigger CONSERVATION."},
    {"s": "health_manager", "k": "health_manager_swap_critical_pct", "t": "number", "def": 80.0,
     "desc": "Unused as of 2026-09-14 -- swap-% no longer triggers CRITICAL at all (a chronically-high-swap box with a healthy process would self-restart for nothing; see health_manager.py's own BUGFIX #2 comment). Kept defined, not removed, in case a future redesign restores a swap-driven CRITICAL path."},
    {"s": "health_manager", "k": "health_manager_sysmem_pressure_pct", "t": "number", "def": 75.0,
     "desc": "System-wide memory-used percentage that alone can also trigger RESOURCE_PRESSURE."},
    {"s": "health_manager", "k": "health_manager_min_available_mb", "t": "number", "def": 512.0,
     "desc": "System available-memory floor below which CRITICAL engages regardless of the RSS/swap thresholds above."},
    {"s": "health_manager", "k": "health_manager_critical_sustain_checks", "t": "number", "def": 3,
     "desc": "Consecutive CRITICAL-level checks required before the proactive self-restart fires -- guards against restarting on a single transient spike."},
    {"s": "health_manager", "k": "health_manager_recovery_confirm_seconds", "t": "number", "def": 60.0,
     "desc": "Seconds a lower pressure level must hold before stepping down one tier (un-pausing TI, re-enabling reactive capture)."},
    {"s": "health_manager", "k": "health_manager_job_staleness_hours", "t": "number", "def": 30.0,
     "desc": "Hours since a scheduled batch job's (live_llm_review/retro_hunter/etc.) last recorded success before the health manager flags it DEGRADED."},
]

# NOTE ON SECRETS: telegram_token, telegram_chat_id, otx_api_key, abuseipdb_api_key,
# virustotal_api_key, pihole_api_password, fritz_password, fritz_api_token are
# deliberately absent from CONFIG_SCHEMA above -- they come from .env, not config.yaml,
# and must never be returned by GET /api/config or made editable through this API,
# regardless of who's authenticated. They're also all in _STATIC_KEYS, so even if a
# schema row existed for one, is_restart_required() would already refuse a PATCH -- the
# exclusion here is the belt to that suspenders (never exposed in the GET response at
# all, not just blocked on write).
