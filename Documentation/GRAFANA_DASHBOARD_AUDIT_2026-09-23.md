# Grafana Dashboard Audit: 2026-09-23 (after v16.5.0)

> **Superseded the same day** by the Argus-architecture redesign: see
> [ARGUS_OBSERVABILITY_PLAN.md](ARGUS_OBSERVABILITY_PLAN.md). The findings below remain the record of what was wrong;
> the Loki work-arounds and "not reported" flags described here are replaced by native Prometheus metrics.

**Scope:** every panel on all 5 dashboards (173 panels, 197 queries) in `grafana_dashboard/`.
**Method:** I didn't read the JSON and assume it was right. Every query ran against .94's live Prometheus and
Loki (commit `022b89c`, the v16.5.0 code), and every metric was traced back to the code that writes it.
**Result:** 78 fixes, all applied live and loaded by Grafana on .94 (confirmed through the stored dashboard checksums).

> Grafana on .94 provisions these files straight from the NAS path
> `/mnt/ServerData/ids_engine_github/home_ids/grafana_dashboard`. Over that NFS mount, Grafana's
> 10-second file polling does **not** notice changes. An edit only goes live after
> `sudo systemctl restart grafana-server`.

---

## 1. What was wrong: the short version

| # | Problem | How many panels | Why it happened |
|---|---|---|---|
| A | **False zeros from the false-positive (CL-AFPE) engine.** "Evaluations", "Suppressed", "Hard-stops", "Confidence", "Trust cache", "Stage 2 vs 3" all read 0 or empty, but the live data shows ~330 suppressions a day. | 12 | .94 runs `cl_afpe_engine: argus`. Every `home_ids_fp_*` counter is only written by the **legacy** `intelligence/fp_engine.py`, which no longer runs. The Argus engine exports no Prometheus metrics. |
| B | **Alert-log panels always empty.** | 3 | They filtered on a top-level `verdict` field that alerts no longer have (it's now `fp_verdict.verdict`). |
| C | **"Suppressed / Muted Log" always empty.** | 1 (+1 help panel) | It read `state/autonomous_muted.jsonl`, a file retired in v16. Suppressions are now `"suppressed": true` inside `alerts.json`. |
| D | **Wrong metric under the right label.** "Total Active Isolations" was showing *Pi-hole domain blocks* (27), not isolated devices (0). | 1 | Query pointed at `home_ids_ips_active_blocks`. |
| E | **"Lifetime", "Total" and "Cumulative" were false.** Prometheus counters reset to 0 on every engine restart, so these were really "since last restart", often with no data at all. | 21 | Raw counter shown in place of an increase over the selected time range. |
| F | **One tile showing many numbers.** Per-device/per-domain series shown in a single stat (29 values in "Total Alerts Triaged"). | 5 | Missing `sum()` / `count()`. |
| G | **Scheduled-Job Health table never showed job names.** | 1 | Prometheus renames the relay's `job` label to `exported_job` (it clashes with the scrape label). The table joined on the old name. |
| H | **Retired jobs shown as live.** Ollama panels read `ollama_soc` (retired, frozen since 09-21). Retro-hunt panels read `retro_hunter` (retired, frozen at 636). The job table listed 4 retired jobs. | 7 | v16 retirements weren't carried into the dashboards. |
| I | **Stale navigation and text.** Dead "Go to Transparency" link on every dashboard. Two dashboards numbered "4.". Welcome text said "4 dashboards". Isolate/Release buttons pointed at the wrong server IP and at a column name that no longer exists. | 9 | Leftovers from the dashboard merge and rename. |
| J | **Unreadable charts.** 15+ time series drew 43 to 86 unlabeled lines. | 20 | No legend format. |

## 2. What each fix does

Legend: **FIXED** = now shows the right thing · **FLAGGED** = no correct data source exists yet, so the
panel now says so instead of showing a misleading 0.

### Dashboard 1: Main Overview
| Panel | Before | Now |
|---|---|---|
| Total Active Isolations | Pi-hole domain blocks (27) | FIXED: devices tarpitted and/or router-isolated, counted once (live: 0) |
| Lifetime Threats Blocked | "No data", resets on restart | FIXED: **Domains Sinkholed (selected range)** |
| Total Alerts Triaged | 29 numbers; claimed "risk >= 6.0 only" | FIXED: **Alerts Evaluated (selected range)**, one number; the description explains it counts every candidate |
| High-Priority Security Alerts | always empty | FIXED: **Alerts That Reached You**, HIGH/CRITICAL and not suppressed (live: 2 in 24h, from ~1,980 candidates) |
| Alerts Triaged Over Time / Sinkhole Rate | 29 lines / "No data" | FIXED: one line each, 0 when idle |
| Welcome text, section text | "4 dashboards", "today" | FIXED |
| Isolate/Release links | `192.168.1.94`, broken field ref | FIXED: new **ids_api** box at the top plus the correct column. The API token is still a placeholder you paste in once. |

### Dashboard 2: Threat Landscape
| Panel | Now |
|---|---|
| Global Threat Events | FIXED: **All Evaluated Alerts**, with decision path and FP verdict columns. The description explains that FP-verdict `CONFIRMED_THREAT` means "not a false positive", **not** "confirmed attack". |
| Threat Intel IOC Hits | FIXED: hits per hour by feed (was a raw restart-resetting counter) |
| Lateral Movement / Honeypot Probes | FIXED: per hour, 0 instead of "No data" |
| C2 Beacons, JA3, JA4, DGA combo | FIXED: legends name the device and signal |

### Dashboard 3: Device Deep Dive
| Panel | Now |
|---|---|
| Device Specific Alert Log | FIXED: matches `device.hostname` exactly (the old text search broke on "All" or multi-select) |
| 15 per-device charts | FIXED: legends |
| Suppress / Long-Conn Threshold | FIXED: empty now reads "Uses global value" |
| Identity / Re-ID / Reclassification "Lifetime" tiles | FIXED: selected-range counts |
| "This Device's ML Model Lifecycle" | FIXED: title now says it's all devices (the metric can't be filtered per device) |
| Retro-Hunt Findings | FLAGGED: frozen, source job retired |

### Dashboard 4: Autonomous Behavior & Self-Learning
| Panel | Now |
|---|---|
| Decision-Path Mix | FIXED: per minute; description lists the real Argus paths |
| Ollama: Time Since Last Run | FIXED: **LLM Review** reads `live_llm_review` |
| Ollama Calls/Cache/Deferred; Ollama Validated Verdicts | REMOVED: sourced only from retired `ollama_soc` |
| Scheduled-Job Health | FIXED: job names show, retired jobs hidden, units and colours |
| Retro-Hunt Findings (+ by device) | FLAGGED: frozen |
| CL-AFPE 3-Stage Funnel, Suppressions by Stage | FIXED: now read from Loki (`alerts.json`), real numbers |
| Domains Immunized, Sensitivity Adjustments, Confirmed-Intel store (IPs/Domains/Growth), Cross-Device Hard-Stops | FLAGGED: "Not reported" (legacy fp_engine only) |
| Bursts, DNS-evasion, stale files, identity, discards "Total/Lifetime" | FIXED: selected-range counts |
| Data Captured per Radio | FIXED: bytes per hour |

### Dashboard 5: System Tuning, Healing & Health
| Panel | Now |
|---|---|
| Dashboard title | FIXED: "5." (was a second "4.") |
| Active Tarpits / WAN Isolations / Pi-hole Blocks | FIXED: one count each (0 = "Clear") |
| AFPE Evaluations / Suppressed / Hard-Stops / Confidence / Funnel | FIXED: from Loki, real numbers |
| Trust Cache Size | FLAGGED: "Not reported" |
| AFPE Suppressed/Muted Log | FIXED: **Suppressed Alerts Log** from `alerts.json` |
| AI Reasoning Transparency | FLAGGED: historical only (see §4) |
| Promtail prerequisite text | FIXED: describes the current stream layout |
| CPU usage | FIXED: title says 100% = one core |
| Mitigation errors, retry / dead-letter tables | FIXED: 0 / "Nothing stuck" instead of "No data" |
| Lifetime Router Isolations / Tarpit Activations | FIXED: selected range |

## 3. Newer features and their metrics

Checked every module added or reworked in Releases 15–16 for any Prometheus output:

| Feature | Has metrics? | Visible in Grafana? |
|---|---|---|
| Argus decision engine | Yes, `home_ids_decision_path_total` (written by pipeline.py) | Yes |
| Argus CL-AFPE (false-positive filter) | **No**, and the legacy counters went dead | Now via Loki (see A) |
| Autotune: global + per-device thresholds | Yes, via `state/autotune_stats.json` relay (now read from `threshold_history`) | Yes |
| Autotune: per-category tier, circuit-breaker rollbacks, auto-promotion | **No** | Console Autonomy tab only |
| Composite trust | **No** | Console only |
| Baseline / BOCPD scoring, population priors | **No** | No |
| Disk budget governor (20 GB cap) | Job heartbeat only | Job table only; no "bytes used vs budget" |
| Job coordinator / resource gate (pause, priority) | **No** | No |
| Health manager component states, freeze watcher | **No** | No |
| LLM review (`live_llm_review`) | Heartbeat only; its reviewed/cache/queries stats are in `job_health.json` but not exported | Heartbeat only |
| Retro-hunt (`live_retro_hunter`) | Findings recorded in `job_health.json` but not exported | No (old panel frozen) |
| Alert-trace graph / plain-English explanations | **No** | No |

**Old metrics no longer valid** (defined in `src/metrics.py`, never written on .94's current code path):
`home_ids_fp_evaluations_total`, `_fp_suppressed_total`, `_fp_confirmed_threats_total`,
`_fp_confidence_score`, `_fp_trust_cache_size`, `_fp_stage2_lgbm_hits_total`, `_fp_stage3_embed_hits_total`,
`_fp_domains_immunized_total`, `_fp_sigma_shifts_total`, `_local_confirmed_intel_size`,
`_local_confirmed_intel_hits_total`, plus the relay-fed `_ollama_*` gauges (frozen since `ollama_soc` retired).

Also found: 19 live metrics that appear on no dashboard (mostly raw Zeek/geo gauges such as
`home_ids_zeek_conn_count` and `home_ids_asn_risk_score`). They're harmless and left alone.

## 4. Follow-ups that need code or server changes (not done)

1. **Re-wire CL-AFPE metrics under Argus.** Emit `fp_evaluations/suppressed/confirmed/confidence` from the
   verdict dict right after `evaluate_cl_afpe_live()` in `core/pipeline.py` (one place, no change inside `argus/`).
   The FLAGGED panels could then go back to Prometheus.
2. **Export `live_retro_hunter` and `live_llm_review` stats** in `core/metrics_sync.py`'s job-health relay
   (the data is already in `job_health.json`).
3. **Promtail:** remove the dead `home_ids_muted` job. Optionally add `state/ollama_analysis_v13.jsonl` for LLM reasoning.
4. **New metrics worth adding:** disk-budget bytes used vs cap, autotune rollbacks, composite-trust outcomes,
   health-manager component state.

## 5. Operational issues the audit surfaced (live, 09-23 ~20:00)

- **`live_llm_review` last succeeded 09-22 15:02**, about 29 h ago. It's scheduled every 4 h.
- **`train_fp_classifier` (autotune calibration) missed today's 03:00 run.** Last success 09-22 15:59.

Both are now visible in the fixed Scheduled-Job Health table.
