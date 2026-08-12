# Changelog

All notable changes to the Home IDS project will be documented in this file.

## [Unreleased] - 2026-08-11

### 🧩 Stability & Security Hotfixes
- Fixed webhook auth behavior to reject remote unauthenticated requests when `fritz_api_token` is unset (loopback IPC remains trusted).
- Fixed hypothesis engine score carry-over by resetting per-evaluation state.
- Fixed ML learning order in pipeline to avoid pre-verdict poisoning in alert paths.
- Fixed retro hunter domain extraction for JSONL alert payload schema and config-resolved stream paths.
- Added Prometheus no-op fallback in `metrics.py` for constrained/offline environments.
- Fixed DNS zero-feature schema consistency (`dns_txt_null_ratio`, `suspicious_tld_ratio`, `beaconing_c2_1h`).
- Fixed regression test compatibility for trainer/FP-engine API drift.

## [Unreleased] - 2026-08-09

### 🔎 Operator Visibility & Mitigation Hardening
- Added explicit evidence-verification indicators to threat alerts and Telegram notifications for partially supported detections.
- Hardened Layer-2 tarpit handling so existing targets are refreshed with later MAC identification and unknown-MAC cases are logged clearly.
- Persisted Pi-hole block state across restarts with explicit active status metadata for better recovery and operator visibility.
- Preserved IP-first device identity while continuing to update MAC and hostname information from newer Zeek and ARP telemetry.
- Improved resilience around Pi-hole API failures so mitigation continues to proceed for router isolation and tarpit containment even when the Pi-hole endpoint is temporarily unreachable.

## [v5.0.0] - 2026-08-08

### 🚀 Major Architecture Overhaul: Hypothesis & Evidence Engine (HEE)
- **Completely Rebuilt Decision Engine** (`pipeline.py`, `ai_soc.py`): Transitioned from a flat arithmetic risk score to a deterministic, graph-based Evidence Store. The system now collects behavioral facts (e.g. `repeated_parent_domain`, `high_entropy`, `dns_tunneling`) and evaluates them against strict hypotheses (e.g. `DNS_TUNNELING`, `BEACONING`, `EXFIL`).
- **Local AI SOC Analyst (Ollama Integration)**: Integrated `llama3.1` running natively on `localhost:11434`. The LLM receives full JSON context for each alert and operates as an autonomous Tier 2 SOC Analyst to evaluate the evidence graph.
- **Deterministic AI Validator Guardrail**: Introduced a deterministic reputation guardrail. If an IP or domain holds a known Tier 5 malicious reputation from Threat Intel, the system will aggressively reject the LLM's opinion if it hallucinates a "BENIGN" verdict.
- **Telegram AI Summarization**: The Telegram alert dispatcher now offloads alert payloads to Ollama in a background thread to generate 1-sentence executive summaries of the threat, appended directly to Telegram messages.
- **Grafana Triage Hub Upgrades**: Overhauled the Grafana dashboards to replace the deprecated 0-10 Risk Score with the new `home_ids_threat_confidence` emitted by the HEE engine.

### 🧠 Machine Learning & Temporal Context
- **Temporal/Diurnal Awareness**: Injected `time_sin` and `time_cos` features into the `LightGBM` / `IsolationForest` ML pipelines to give the models contextual awareness of the time of day, vastly reducing false positive anomalies during non-standard hours.
- **Graceful Dimensionality Upgrades**: Upgraded the device state schemas to dynamically invalidate legacy 9-feature models and rebuild the new 11-feature temporal baselines without crashing.

### 🔧 Bug Fixes & Optimizations
- **Fixed StateManager Evidence Leak**: Ensured `self.evidence_store.clear_device(dev_id)` is explicitly called when stale devices are pruned from the pipeline, permanently fixing memory accumulation.
- **Hardened System Polling Loop**: Hardcoded strict `time.sleep()` blocking across all internal `while True` polling loops (Zeek, API requests, Alert Managers) to prevent catastrophic infinite-loop log spam that could previously overwhelm `rsyslogd`.

## [v4.0.8] - 2026-08-06

### 🔴 Critical Bug Fixes
- **Fixed `NameError`-class bug: `is_poisoned` used before definition** (`pipeline.py`): `is_poisoned` was
  referenced on line 309 of the ML training guard `if dev_id in all_active_ids and not is_poisoned` before
  being assigned on line 338. On the first device in every 2s cycle this caused a `NameError`; on subsequent
  devices it used a stale value from the previous loop iteration, silently poisoning ML training.
  `is_poisoned = state.is_poisoned(risk)` is now computed immediately after `risk_details` is available.
- **Fixed `UnboundLocalError` for `webhook_log_file`** (`main.py`): When `ips_router_enabled = false`
  (the default config), `webhook_log_file` was never assigned. `shutdown_handler()` referenced it
  unconditionally, raising `UnboundLocalError`. Initialized to `None` before the conditional block.

### 🟡 Performance & Reliability Fixes
- **Reduced `_global_lock` scope for expensive I/O** (`pipeline.py`): Per-device processing was restructured
  into 4 phases. ThreatIntel lookups, AbuseIPDB, and VirusTotal queries now run in Phase 2/3 **outside** the
  global device lock. The lock is now held only for quick state reads (Phase 1) and risk/ML writes (Phase 4),
  eliminating HTTP round-trip latency from the critical lock window.
- **Fixed `rolling.domains` unbounded accumulation** (`pipeline.py`, `state.py`): The per-device DNS domain
  `Counter` grew unboundedly across the device's lifetime. Now pruned each cycle via `domain_timestamps`
  entries older than `window_seconds`. `rolling.blocked` and `rolling.nxdomain` are now re-derived from
  the bounded `events` deque on each cycle so they can't inflate beyond the window.
- **Switched `AlertJSONWriter` to O(1) JSONL append mode** (`alerts.py`): Previously `write()` read the
  entire alert JSON array, parsed it, appended, and rewrote it on every alert (O(N) per write). Now uses
  `file.open("a")` append mode with one compact JSON line per alert. Existing JSON array files are
  automatically converted to JSONL on first startup.
- **Added O(1) MAC update via reverse IP index** (`state_guard.py`): `update_device_mac()` previously
  performed an O(N) linear scan across all device states for every Zeek ARP event. A `_ip_to_device_id`
  reverse index is now maintained on all device create/register/migrate operations, making MAC binding O(1).
- **Fixed HTTP call under lock in `release_device()`** (`ips.py`): `_unisolate_device_router()` was called
  while holding `self._lock`, causing the Fritz!Box HTTP round-trip (up to 10s timeout) to block all
  lock-protected operations. Restructured into: Phase 1 (collect targets under lock) → Phase 2 (HTTP outside
  lock).

### 🔒 Security Fixes
- **Telegram command authentication** (`alerts.py`): `/unblock`, `/release`, `/release_all` and inline
  button callbacks can now be restricted to authorized sender IDs via `telegram_allowed_chat_ids` in
  `config.json`. Default is empty list (allow all) for backward compatibility.
- **Uvicorn CWD-independent startup** (`main.py`): Changed module import from `src.middleware.fritz_webhook:app`
  to `middleware.fritz_webhook:app` with `--app-dir <src_dir>` flag so the daemon starts correctly regardless
  of the process working directory (e.g., systemd unit with a custom `WorkingDirectory`).

### 🟢 Minor Fixes & Configuration
- **Pi-hole API path is now configurable** (`ips.py`, `config.py`): Hardcoded `/api/v2/domains` replaced
  with `config.get("pihole_api_path", "/api/v2/domains")`. Set `pihole_api_path` in `config.json` to use
  Pi-hole v5 (`/api/dns/blacklist`) or a custom path.
- **`release_all_devices()` uses MAC as canonical key** (`ips.py`): Fixed edge case where two devices with
  identical hostnames would only generate one release call. Now uses MAC address as primary identifier,
  falling back to IP, then hostname.
- **`fastapi_port` and `telegram_allowed_chat_ids` added to `DEFAULT_CONFIG`** (`config.py`): Both keys
  were previously used in code without being documented in the defaults dict.
- **`router_isolated_devices` and `operator_released_devices` added to `_ips_state` defaults** (`state_guard.py`):
  Prevents `KeyError` if code accesses these keys on a fresh install before the first isolation event.
- **Honeypot IP sourced from `config["honeypot_ips"]`** (`scoring.py`, `pipeline.py`): Alert detail message
  previously hardcoded `192.168.1.200`. Now reads from `config.json["honeypot_ips"]` list, injected into
  the feature dict before scoring.
- **`_bot_updates_worker` responsive shutdown** (`alerts.py`): Replaced `time.sleep(5)` with
  `threading.Event.wait()`. Thread now stops within ≤1 second of `stop()` being called, instead of waiting
  up to 25 seconds for the Telegram long-poll to time out.
- **`get_ips_state()` TOCTOU warning added** (`state_guard.py`): Docstring now clearly warns that inner
  dicts are mutable references and directs callers to `update_ips_state_atomic()` for read-modify-write.

## [v4.0.7] - 2026-08-06

### 🔒 Security & Local Loopback IPC Trust
- **Local Loopback IPC Authentication**: Updated `verify_token` in `src/middleware/fritz_webhook.py` to automatically trust loopback requests (`127.0.0.1`, `::1`, `localhost`). This allows local CLI utilities (like `release_device.py`) to execute live daemon memory releases seamlessly without needing `API_SECRET_TOKEN` exported in the user's interactive shell profile.

## [v4.0.6] - 2026-08-06

### 🐛 Bug Fixes & Diagnostics
- **Enhanced CLI IPC Fallback Telemetry**: Updated `src/release_device.py` to output explicit exception details (`ConnectionRefusedError`, HTTP status codes) when live daemon IPC is offline or unconfigured, making CLI diagnostics transparent.

## [v4.0.5] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Unauthenticated Local IPC Support**: Updated `verify_token` in `src/middleware/fritz_webhook.py` to allow local IPC release calls (`POST /api/ipc/release`) when `fritz_api_token` is unconfigured (`""`) without throwing HTTP 500 configuration errors.

## [v4.0.4] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Telegram Alert Plain Text Fallback**: Added automatic plain text fallback in `AlertManager._dispatch_worker()` if Telegram rejects formatted alert messages with HTTP 400 (`can't parse entities`).
- **Telegram Inline Button Read Timeout Fix**: Increased local IPC timeout in `_handle_telegram_callback()` from `3.0s` to `10.0s` to prevent `HTTPConnectionPool Read timed out` exceptions when operators tap Telegram inline action buttons.

## [v4.0.3] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Fixed `NameError: name 'alert_threshold' is not defined`**: Defined `alert_threshold` float evaluation in `IPSMitigator.mitigate()` in `src/mitigation/ips.py` from `config.json` before checking Pi-hole domain block threshold conditions.

## [v4.0.2] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Fixed `NameError: name 'pihole_enabled' is not defined`**: Defined `pihole_enabled` boolean evaluation in `IPSMitigator.mitigate()` in `src/mitigation/ips.py` before checking Pi-hole domain block threshold conditions.
- **Regression Test Alignment**: Updated `test_09` in `src/test/test_ids_regression.py` to match the 5.5 risk score threshold for baseline poisoning freeze.

## [v4.0.1] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Graceful `tldextract` Fallback**: Updated `etld1()` in `src/utils.py` with try/except fallback logic so system execution operates smoothly without throwing `ModuleNotFoundError` if `tldextract` is missing from system Python.
- **Immediate Pi-hole DNS Sinkholing**: Ensured Pi-hole domain sinkholing executes 100% immediately upon threat detection; interactive Telegram approval (`interactive_blocking_enabled`) applies strictly to Layer-2/3 Hardware Isolation (Fritz!Box WAN drop and Scapy ARP/NDP tarpit).
- **Explicit HITL Startup Log Banner**: Added startup log banner in `IPSMitigator` notifying operators of active HITL vs Auto-block configuration on boot.
- **Repository Privacy & Clean Git Tracking**: Added root `.gitignore` excluding runtime logs, state snapshots, and compiled bytecode.

## [v4.0.0] - 2026-08-06

### 🚀 Major Features & Architectural Redesign

#### 1. Interactive Telegram Human-in-the-Loop (HITL) Mode
- **Configurable HITL**: Added `interactive_blocking_enabled: true/false` option in `config.py`.
- **Immediate DNS Sinkholing**: Pi-hole domain blocking remains 100% immediate and autonomous upon threat detection.
- **Interactive Hardware Isolation**: When `interactive_blocking_enabled: true` is set, Layer-2/3 Hardware Isolation (Fritz!Box WAN Drop and Scapy Layer-2 ARP/NDP Tarpit) is queued for Telegram operator approval.
- **Inline Action Buttons**: Telegram alerts feature live inline keyboard buttons:
  - `[ 🔒 Approve Hardware Isolation ]`
  - `[ 🔓 Release Device ]`
  - `[ 🛡️ Immunize FP Domain ]`
- **Telegram Bot Command Listener**: Asynchronous background worker (`_bot_updates_worker`) handles `/unblock <target>`, `/release <target>`, `/release_all`, and `/status` commands directly via Telegram chat.

#### 2. Process IPC & State Synchronization Architecture
- **FastAPI Local IPC Server**: Added local IPC endpoint `POST /api/ipc/release` on port 8010.
- **Split-Brain Prevention**: Updated CLI tool `release_device.py` to communicate directly with the running `soc.service` process memory over local IPC, preventing stale memory overwrites.
- **Full Scope Unblocking**: `release_device()` releases Layer-2 ARP tarpits, Fritz!Box WAN drops, and associated Pi-hole blocked domains simultaneously.

#### 3. 1-Hour Operator Release Cooldown & Lateral Movement Override
- **1-Hour Release Cooldown**: Releasing a device registers a 3600-second cooldown period, preventing immediate re-blocking on decaying background metrics.
- **Hard Safety Override**: If internal subnet port scanning or lateral movement (`zeek_lateral_moves > 0`) is detected during cooldown, the cooldown is **instantly bypassed**, hardware containment is re-enforced, and a high-priority alert is logged.

#### 4. Multi-Threat 9-Feature Matrix Alignment & Model Validation
- **Unified 9-Feature Vector**: Expanded anomaly feature vectors across `DeviceMLEngine` and `GlobalMLEngine` to include `zeek_lateral_moves`, `zeek_s0_rej_count`, and `zeek_app_protocol_weight`.
- **Automated Retraining & Hot-Reload**: Created `src/scripts/train_fp_classifier.py` and weekly daemon `_weekly_retrain_loop()` in `fp_engine.py` to auto-retrain and hot-reload `models/fp_classifier.onnx` on the full 9-feature matrix.
- **Dynamic ONNX Input Shape Guard**: Updated `_stage2_lgbm()` in `fp_engine.py` to dynamically inspect ONNX input tensor signatures at runtime (`[None, 6]` vs `[None, 9]`).

#### 5. Real-Time Prometheus & Grafana Metrics Synchronization
- **Real-Time Garbage Collection**: Added `garbage_collect_ips_metrics()` to the pipeline execution loop in `pipeline.py` to synchronize active gauge labels with live state.
- **Clean Label Removal**: Updated `unblock_domain()`, `release_device()`, and `release_all_devices()` to call `.set(0.0)` and `.remove()` on Prometheus metrics (`ips_tarpit_active`, `ips_router_isolated_active`, `ips_active_blocks_gauge`).

#### 6. Core Stability & Code Quality Fixes
- **Non-Blocking IsolationForest Training**: Replaced synchronous `.fit()` in `ml_engine.py` with background daemon threads (`_fit_worker`) and atomic model swapping under `_fit_lock`.
- **Atomic State Guard**: Added `update_ips_state_atomic()` to eliminate TOCTOU disk state race conditions.
- **LRU Cache Concurrency**: Wrapped `_ip_cache` in `identity.py` with thread locks and converted to `OrderedDict` with LRU eviction.
- **Clean Shutdown Handling**: Added explicit file handle closure (`webhook_log_file.close()`) in `main.py` signal handler to eliminate exit `ResourceWarning`.
