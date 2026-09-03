# Decision-Logic Dependency Map

Living reference for the alert-classification path (`ReputationClassifier` →
`HypothesisEngine` → `DecisionEngine` → `pipeline.py`'s alert/containment
call sites). Built while tracking down a third-party review's "Confirmed
Malicious IOC" critique; extended incrementally as further work touches
this path — **update this file in the same change that touches any
function listed below**, don't let it go stale.

Each function entry lists every parameter: where it's **generated**, every
place it's **transformed** in transit, and every place it's **consumed**
downstream — not just "what calls what."

This document covers the decision-*making* path (how one alert's verdict is reached). For
what happens *after* a verdict — how corrections feed back into sigma-shift, trust-cache
immunization, per-device thresholds, and the other autonomous-learning loops — see
[`AUTONOMOUS_LEARNING.md`](AUTONOMOUS_LEARNING.md).

## Status

| Item | State | Notes |
|---|---|---|
| Gap 1 — reputation tier-5 privilege split (`verified_ioc`) | **Live** (2026-08-29, flipped from shadow) | A live recurrence (`family_pc_fritz_box` vs. `35.186.224.24`, CRITICAL 3x in one night on `AbuseIPDB=4.0` alone, benign hypothesis outscoring attack) matched the exact shape the Phase A backtest below had already found in 75/80 historical alerts. `decision_engine.py`'s live `tier==5` branch now itself splits on `rep.verified_ioc` / corroboration (mirrors the shadow logic that had been running alongside it since 2026-08-26) — see `ALERT_CATEGORIZATION_CATALOG.md` rows 5a/5b/5c for the resulting three-way outcome. The shadow computation for Gap 1 specifically is now redundant (live and shadow agree on tier-5 cases) but stays in place unmodified since it's combined with Gaps 2/3 in one code path — see those rows below, still shadow-only |
| Gap 2 — `has_malicious_tls`/`zeek_notice` conflation | **Shadow-live** (2026-08-26) | `NetworkIntrusionHypothesis.evaluate_shadow()` (`hypotheses/engine.py`) implements the split; `HypothesisEngine.evaluate_all()` returns an extra `shadow_attack` key (name/score using the fixed logic) alongside the unchanged `attack`/`benign` keys; `decision_engine.py`'s shadow block (below) consumes it. Cannot be backtested from `alerts.json` history — see limitation above; only live-observable via `state/shadow_decisions.jsonl` going forward. |
| `scripts/shadow_backtest.py` (Phase A, Gap 1 only) | Built, run 3x, results below | Re-run after Gap 2 wiring landed — numbers unchanged (5/75/0), as expected: the standalone backtest re-derives from stored `alerts.json` fields independently of the live code, so it wasn't and couldn't be affected by the Gap 2 change |
| Live shadow logging (Phase B, Gap 1 + Gap 2 composed) | **Implemented** (2026-08-26) | `decision_engine.py:evaluate()`'s shadow block now composes BOTH gaps in one pass (hard-stops reused as-is; tier==5 branch uses `rep.verified_ioc` + `shadow_attack_score > benign_score`; the hypothesis branch uses `shadow_attack_score`/`shadow_attack_name` in place of the live ones) — mirrors the real branch structure fresh rather than reusing/duplicating the live branch code, so there's exactly one "old" (unedited, still-shipped) and one "new" (fixed) implementation, never two drifting copies of the same logic. `pipeline.py:_log_shadow_divergence()` appends to `state/shadow_decisions.jsonl` whenever `shadow_changed` is True (state OR explanation differs) |
| Targeted test subset (9 files) | **All 9 PASS, 0 regressions, verified twice** (2026-08-26) — once after Gap 1, again after Gap 2 | Run directly as standalone scripts (`.venv/Scripts/python.exe tests/test_phaseN.py` from repo root) — these are NOT pytest-collected despite the filename convention (no `def test_*`/`if __name__`); `pytest` reports "no tests ran" for them, which is expected, not a failure. Must use the project's `.venv` (system `python3` lacks `PyYAML` and other deps — `ModuleNotFoundError: No module named 'yaml'`). First cold run of a file over the network share can take >2 min (model-loading fixtures + import latency) — this is normal, not a hang; confirmed by re-running in isolation with a longer window. `test_phase38` explicitly covers the tier-5/AbuseIPDB boundary Gap 1 reads (ti=3.5 → CRITICAL; abuse=3.78 → stays SUSPICIOUS) — unaffected both times, confirming neither shadow addition touched the live path. |
| Evidence-taxonomy module (`evidence_taxonomy.py`) | Not started | Deferred until after all three gaps' live-flip decision, per plan |
| Gap 3 — hard-stop evidence staleness (`has_honeypot` etc. firing on stale `EvidenceStore` presence, not a fresh cycle) | **Shadow-live** (2026-08-27) | Root cause confirmed via live SSH investigation (see "Gap 3 root cause" below), not inferred. `decision_engine.py` now takes an optional `features` param and computes `fresh_honeypot` (via `features["zeek_honeypot_hits"]`, the same raw signal `pipeline.py` itself gates evidence-creation on) and time-boxed `fresh_arp_spoof`/`fresh_geofence`/`fresh_confirmed_exploit` (via `_HARD_STOP_FRESHNESS_SECONDS = 120` against `e.timestamp` — diagnostic proxy, not yet live-confirmed the way honeypot is). `scripts/shadow_backtest.py` extended with `run_gap3_honeypot_backtest()`. 9/9 targeted tests pass. |
| Gap 3 Fix B (exempt `safe_ips` from the honeypot hard-stop) | **Live** (2026-08-27, explicit product decision, not shadow) | `pipeline.py:984` gates honeypot evidence-creation on `not is_safe`. `mitigate()` already no-oped for these devices, so this only removes a misleading alert, not real containment |
| "WAITING FOR APPROVAL" text for `is_safe` devices | **Live** (2026-08-27) | `pipeline.py`'s containment-status rewrite now also requires `not is_safe` |
| ASN/cloud-provider blind spot in local-intel store | **Live** (2026-08-27, keyword list broadened + gap closed 2026-08-29) | `fp_engine.py`'s `_is_ip_protected_from_confirmed_intel()` takes optional `asn_owner`, checks `utils.is_cloud_cdn_provider_org()`; threaded through `record_confirmed_threat()`, `evaluate()`, `_stage1_hard_stop()` (all 3 fp_engine call sites) and both `pipeline.py` call sites. Follow-up found 2026-08-29: `_CLOUD_CDN_ORG_KEYWORDS` was missing `"apple"`/`"facebook"` despite this guard's own docstring already claiming Apple was covered — confirmed live via poisoned Apple Push/Facebook CDN IPs in `state/local_confirmed_intel.json`. Fixed, broadened with a few more providers, and backed by a canary regression test (`tests/test_phase45_cloud_cdn_vpn_org_canary.py`) resolving ~20 real IPs through the actual `GeoLite2-ASN.mmdb` so a future missing keyword is caught in CI, not discovered live months later. `clean_confirmed_intel.py` extended the same day to also detect/purge already-poisoned cloud-owned entries (previously only checked `safe_ips`/private ranges) — removed 284 entries in the one-time cleanup. See `ALERT_CATEGORIZATION_CATALOG.md`'s audit-findings section for the full writeup. |
| WHY block decisive/context split | **Live** (2026-08-27) | `local_context`-group evidence (LOCAL_DEVICE_DISCOVERY) now renders under a separate "Also observed (context)" header, matching `ATTACK_EVIDENCE_FAMILIES`'s own exclusion |
| Lateral-scan label wording | **Live** (2026-08-27) | Only labeled "Lateral Scans" when `zeek_lateral_unique_targets >= lateral_movement_unique_targets_threshold` (same constant the containment gate uses); below it, labeled "Connection" |
| DNS sequence benign-blocked separation | **Live** (2026-08-27) | Trusted/telemetry domains that got Pi-hole-blocked now render under their own "Blocked by ad/tracker policy" header instead of "Threat-Filtered DNS Sequence" |
| Truncated `Application` field | **Live** (2026-08-27) | `zeek_features.py`'s `get_app_context()`: cap raised 40→80 chars, explicit `"..."` when actually truncated |
| Ollama cap/cadence | **Live** (2026-08-27) | `ollama_max_queries_per_run` 3→8; `scheduled_jobs.scheduler.ollama_soc.cron` corrected from a once-daily drift ("30 4 * * *") back to the documented 4-hourly intent ("30 */4 * * *") |
| Malicious Ollama verdict consequence | **Live** (2026-08-27) | `ollama_soc.py`: a validated `malicious` verdict now calls `fp_engine.record_confirmed_threat()` + `_apply_sigma_shift(TUNE_UP)`, and a batched Telegram digest is sent for the run (mirrors `retro_hunter.py`'s pattern) |
| retro_hunter → closed loop | **Live** (2026-08-27) | `check_local_intel_history()` matches now also call `record_confirmed_threat()` + sigma tune-up for the newly-implicated device, not notify-only |
| Gateway identity MAC-based fix | **Live** (2026-08-27) | `identity.py`'s `DeviceIdentityManager` learns `self._gateway_mac` the first time `gateway_ip` is seen with a real MAC, then binds any OTHER address (e.g. the router's IPv6 link-local) presenting that same MAC to the same canonical id — general, not a second hardcoded IP literal |
| IP geo/ASN enrichment on the "Contacted" line | **Live** (2026-08-27) | `pipeline.py`: when `target_display` is a raw IP, appends `(ASN org, country)` via `self.geoip_engine.lookup_asn()`/`.lookup()` (local mmdb, `@lru_cache`'d, cheap enough for every alert unlike the rate-limited AbuseIPDB/VT calls). Smoke-tested against real IPs on the box: `106.201.214.127` → "Bharti Airtel Ltd. AS for GPRS Service, India"; `35.186.224.24` → "Google LLC, United States"; a private IP → no enrichment, no crash. Prompted by the WireGuard/DNS_EVASION investigation, where the ASN lookup was the single most informative fact and previously required manual SSH investigation to see at all. |
| Evidence-provenance taxonomy module | **Still deferred** | Deliberately not built yet — meant to be the shared source of truth once Gaps 1-3's shadow data resolves; building it against still-unflipped logic risks having to redo it |
| A few days of live `state/shadow_decisions.jsonl` accumulation | **In progress** — box restarted 2026-08-26 12:58:52 CEST with commit `3dcac19` confirmed as HEAD (verified via SSH, not just the Unison-synced NAS mirror) | Nothing further to build until this has accumulated data |
| `scripts/shadow_watcher.py` (Telegram notification on first divergence) | **Deployed and running** (2026-08-26) | Fires Telegram the moment `state/shadow_decisions.jsonl` gets a new line; runs every 5 min via `scripts/scheduler.py`. Committed locally as `d7f18ad` (NOT pushed to `origin` yet) and deployed directly to the box via `scp` (not `git pull`) so it's live without waiting on a push/pull round-trip — **the box's git working tree is now ahead of its own `git log` for `config.yaml`/`shadow_watcher.py`** until someone pushes from the NAS checkout and pulls on the box to reconcile. Manually dry-run on the box against real production state (`job_health.json` confirms a clean run) before relying on the scheduler to pick it up. |
| Gap 4 — `scripts/ollama_soc.py`'s batch SOC review never consulted `HypothesisEngine`/`DecisionEngine` at all | **Live** (Phase 50) | Third-party review of a live SOC digest found the LLM path reasoning "TI=0/VT=0/AbuseIPDB=0 → low likelihood of malicious" and similar device-type-alone justifications reaching autonomous immunize actions — exactly the failure mode `decision_engine.py`'s tier-3-neutral handling and evidence-family independence gate already prevent on the LIVE path, three files away, unused by this one. Root cause: `ollama_soc.py` reconstructed a single ad-hoc `Evidence(type="reputation")` item from raw features and graded the LLM's free-text reply with `ai_soc.py`'s 2-rule `DeterministicValidator` (bare IOC≥4.0 veto, "telemetry"-substring veto) — no family count, no hypothesis competition, nothing from `HypothesisEngine` in the loop. Fix (see dedicated section below): `pipeline.py`'s `alert_payload` now persists `hee_hypotheses`/`hee_independent_sources`/`hee_decision_path`/`hee_evidence_families` — the SAME `decision` dict `decision_engine.py` already computed for that alert, previously discarded once the cycle ended. `ollama_soc.py` strips those fields from the LLM prompt (verdict-shaped, same treatment as `risk`/`signature`/`factors`) but threads them into `DeterministicValidator.validate()` as `ground_truth`, which now rejects a "benign" LLM verdict outright when the alert's original deterministic verdict already corroborated an attack hypothesis across ≥2 independent families (or a hard-stop/confirmed-IOC path) — `_STRONG_ATTACK_DECISION_PATHS = {hard_stop, tier5_confirmed, tier5_corroborated, hypothesis_high}`. Backward-compatible: alerts published before this change have no `hee_*` fields, `ground_truth` degrades to an empty dict, validator behavior is unchanged for those. 26/26 targeted checks pass (`tests/test_phase50_ollama_hee_ground_truth.py`) plus the pre-existing Phase 35/48/49 ollama_soc suites, unaffected. **Phase 51 (same day, structured evidence contract) — Live:** the LLM schema now asks for `hypothesis` (a specific named explanation, in `hypotheses/engine.py`'s own vocabulary where it fits — e.g. `DEVICE_PROFILE_TELEMETRY`, `NETWORK_INTRUSION`), `supporting_evidence[]`, `contradicting_evidence[]`, and `missing_evidence[]`, not just one free-text `reason` paragraph. `system_prompt` explicitly tells the model the absence of a TI/VT/AbuseIPDB hit is NOT supporting evidence on its own — the literal failure mode from the live digest that started this whole gap. `DeterministicValidator.validate()` now rejects any "benign" verdict with an empty (or whitespace-only) `supporting_evidence` list outright (an assertion, not a finding), and separately rejects one that lists its own `contradicting_evidence` but still recommends `suppress` (self-contradictory). `classification` itself deliberately stayed `benign|malicious` — every branch in `ollama_soc.py`'s `main()` already keys on those two exact strings; a 3-way enum rename would be a materially larger, separate change. `ttl_seconds` is captured (cache + report) but not yet wired into any suppression TTL — that's Phase 3's job. 20/20 targeted checks pass (`tests/test_phase51_ollama_structured_contract.py`); Phase 50's own suite updated (`BENIGN_REC` fixture now carries `supporting_evidence`, since it's a separate, now-mandatory requirement) and re-verified alongside Phase 35/48/49, unaffected. **Phase 52 (scoped suppression) — Live:** `fp_engine.py`'s domain/IP trust cache — the Stage-1 fast path `evaluate()` uses to suppress recurring alerts at zero CPU cost — was keyed purely on domain/IP, globally, no device or hypothesis dimension at all: an immunization from correcting ONE attack hypothesis against a domain could silently suppress a completely DIFFERENT, unrelated hypothesis against the SAME domain later, for every device on the network. Scoped **narrowly by explicit direction** after discovering the trust cache is consumed in 9 files total (`get_dynamic_trust_cache()` also feeds `pipeline.py`/`scoring.py`'s pre-hypothesis `is_domain_safe` dampener, and `utils.py`'s separate `register_dynamic_allowlist_domain` allowlist dampens DGA/tunneling detectors elsewhere) — fully scoping all of that was assessed as a much larger, separate, multi-file change; ONLY `evaluate()`'s own trust-cache-hit check (the actual gate deciding whether an alert is suppressed) was touched, those other 2 consumers deliberately left unscoped/global, unaffected by this phase. `_trust_cache` entries now carry `{ts, source, device_id, hypothesis, ttl_seconds}` (a dict) instead of a bare timestamp float — every reader (`_is_trust_cached`, `get_dynamic_trust_cache`, `_load_trust_cache`, `_prune_expired_fp_state`) goes through new shape-agnostic `_trust_entry_ts()`/`_trust_entry_ttl()` helpers so a mixed on-disk cache (old float entries alongside new dict ones — exactly what a live upgrade produces) never crashes a reader; a legacy bare-float entry is an unconditional always-match wildcard, same as every entry before this phase. `_is_trust_cached()` now requires the CURRENT alert's hypothesis to match what's recorded on any hit (always), and additionally requires the SAME device specifically for `DEVICE_SCOPED_TRUST_HYPOTHESES = {DNS_EVASION, DNS_ATTRIBUTION_GAP, DNS_POLICY_BYPASS}` — chosen because those are the only hypothesis names that structurally reach `mark_false_positive()`'s `signature` in practice whose correction is a claim about THAT device's own DNS usage rather than the destination's general safety (a PUBLISHED alert's signature is always the WINNING hypothesis, so a benign-only name like `DEVICE_PROFILE_TELEMETRY` never appears here at all — the original plan's assumption about which hypothesis needed device-scoping was corrected against what the code actually does before implementing). Every other hypothesis (`NETWORK_INTRUSION`, `DGA_BOTNET_C2`, generic reputation, …) stays domain-shared across devices — "combine both" per explicit direction: hypothesis-gated always, device-gated only where the underlying claim is genuinely device-specific. `mark_false_positive()` threads `device_id`+`signature` through to all 3 `_immunize_domain()` call sites uniformly (not just the LLM-sourced one) and gained an optional `ttl_seconds` param — `ollama_soc.py` threads its LLM's own Phase-51 `ttl_seconds` through as a per-entry TTL override, clamped to `[MIN_TRUST_ENTRY_TTL_SECONDS=1h, MAX_TRUST_ENTRY_TTL_SECONDS=14d]` so a malformed/hallucinated value can't create an effectively-permanent or instantly-expiring entry; an operator/autonomous correction with no `ttl_seconds` falls back to the unchanged 14-day global default. 47/47 targeted checks pass (`tests/test_phase52_scoped_trust_cache.py`), plus the pre-existing `test_phase3_revoke`/`test_phase6_fp_selfheal`/`test_phase26_fp_selfheal_new_detectors`/`test_phase27_local_intel_and_confirmed_tuning` fp_engine suites re-run, unaffected. **Remaining for this gap:** campaign-level correlation for the multi-device withhold guard — tracked separately, not yet started. Full scoping of `get_dynamic_trust_cache()`/`utils.py`'s allowlist (the other 2 of the 9 files) remains a deliberately out-of-scope, larger future track if ever wanted. |

## Phase A backtest results (`scripts/shadow_backtest.py` against `state/alerts.json`, 80 historical "Confirmed Malicious IOC" alerts, 2026-08-26)

**First pass** (corroboration = `num_independent_sources >= 1` alone): 67 real downgrades, 13 label-only.

**Refined pass**, after finding a live counter-example (see below): corroboration also requires `attack_score > benign_score` (both already computed at the top of `decision_engine.evaluate()`, just never consulted by the tier==5 branch). Result: **75 real downgrades (CRITICAL→HIGH), 5 label-only (stay CRITICAL, relabeled), 0 unchanged** (zero of the 80 had a genuine `ti_score > 2.0` curated-feed match — every single one relied on VT/AbuseIPDB aggregate scores alone).

**The counter-example that drove the refinement** — a live `family_pc_fritz_box` alert (`35.186.224.24`, Google LLC, AbuseIPDB=4.0, VT=0, TI=0) had this reasoning trail:
```
Hypotheses: attack='NETWORK_INTRUSION' (score=2.0) vs benign='LOCAL_DEVICE_DISCOVERY' (score=2.5) — 2 independent evidence source(s)
Verdict: CRITICAL / block — Confirmed Malicious IOC (confidence=0.99)
```
The **benign** hypothesis outscored the **attack** hypothesis (2.5 > 2.0), yet the alert still said "Confirmed Malicious IOC" — because the tier-5 branch is checked *before* the attack-vs-benign comparison and short-circuits it entirely. "Corroborating evidence exists" (`num_independent_sources >= 1`) is not the same claim as "the corroborating evidence supports an attack conclusion" — this alert had 2 independent sources, but they favored innocence, not guilt.

**Honest caveats on the backtest data (found while checking, not assumed):**
- 67 of the 75 downgrades are a single device (`paperless`, id `52a469cfd274`) on a single day (2026-08-17), all against Telegram's own server IP `149.154.166.110` — the exact case `classifier.py`'s own PHASE 8 comment already documents. These pre-date/coincide with the `abuse_score >= 4.0` threshold fix already shipped in the current code, so this specific historical failure mode is likely **already moot** under today's live thresholds — it validates that this *class* of bug is real, not that Gap 1 changes much going forward for this device.
- The other 8 downgrades (7 `family_pc_fritz_box` + 1 `galaxy_note9_fritz_box`) are current and ongoing (2026-08-22 through 2026-08-26) — `family_pc_fritz_box` alone has hit this exact `Confirmed Malicious IOC`/Google-Cloud-IP pattern **at least 7 times over 4 days**, which the original tarpit evidently didn't resolve (still recurring as of the morning of 2026-08-26). This is the more relevant evidence for what Gap 1 changes *today*.
- The `later_corrected_within_14d` check is a loose per-device proxy (any correction on the same device within 14 days, not proof it was correcting this exact alert) — treat "75/75 correlate with a correction" as suggestive, not proof, especially for `family_pc_fritz_box`, which is a generally high-alert-volume device likely to show *some* correction in any 14-day window regardless.
- Zero downgrades correlated with a device that has other confirmed-threat history (`confirmed_threat_counts.json`) — nothing in this backtest looks like it would have downgraded a genuinely dangerous device.

**Next step for Gap 2:** unlike Gap 1 (a single extra branch after the hypothesis competition already runs), Gap 2 lives *inside* `NetworkIntrusionHypothesis.evaluate()`, which directly feeds `attack_score` — splitting `has_malicious_tls`/`zeek_notice` there changes the hypothesis's own score, not just a downstream branch. To shadow it without touching live behavior, it needs a second, parallel `HypothesisEngine` instance running the patched hypothesis alongside the original, logged the same way. Not yet implemented — next concrete task.

## Known limitation found while tracing (important — governs what's backtestable)

`pipeline.py:1156/1194/1283` builds the alert's `factors` field as
`[{"name": decision["explanation"], "score": risk}]` — **one entry, the
final decision's own explanation string**, not a list of which raw
`Evidence.type` values fired. `reasoning_trail` (`decision.get("reasoning_trail")`,
stored at `pipeline.py:1516`) is closer — it's `decision_engine.py`'s own
`trail` list and includes the hard-stop-checks line and the
`"Hypotheses: attack='X' (score=Y) vs benign='Z' (score=W) — N independent
evidence source(s)"` line — but neither retains the raw evidence-type
breakdown `NetworkIntrusionHypothesis` needs (specifically, whether
`malicious_ja3`/`malicious_ja4` vs. `zeek_notice` was the thing that set
`has_malicious_tls=True`). **Conclusion: Gap 1 (reputation tier) is fully
reconstructable from historical `alerts.json`; Gap 2 (evidence-type
conflation inside `NetworkIntrusionHypothesis`) is not — it can only be
validated via live shadow logging going forward, not backtested.**

---

## `ReputationClassifier.classify()` — `intelligence/reputation/classifier.py:64`

```python
def classify(self, domain, vt_score=0.0, afpe_score=0.0, is_new=False,
             ti_score=0.0, abuse_score=0.0, asn_owner="Unknown") -> ReputationVector
```

| Param | Generated at | Transformed | Consumed by |
|---|---|---|---|
| `domain` | `pipeline.py:1073` passes `reputation_target` — itself set at `pipeline.py:782` (`= top_domain`), then overwritten at `:791`/`:800` if `ti_engine.lookup_domain()`/`lookup_ip()` found a higher-risk target, and at `:849`/`:867` if honeypot/VT found a higher one still | `.lower().strip(".")` inside `classify()` | Tier-0/1/2 suffix matching (`_suffix_or_domain_match`) |
| `ti_score` | `pipeline.py:804` `features["ti_risk"] = ti_risk`, computed `:784-802` from `self.ti_engine.lookup_domain()`/`lookup_ip()` — a **real curated-feed match** (Feodo/ThreatFox/OTX via `intelligence/threat_intel.py:229,246`), `confidence * 4.0` | none before reaching `classify()` | `confirmed_ioc = ... or ti_score > 2.0 ...` (`classifier.py:103`) — **this is the only one of the three that should ever grant zero-corroboration privilege (Gap 1 fix target)** |
| `vt_score` | `pipeline.py:868` `features["vt_risk"] = vt_risk`, computed `:855-867` via `self.virustotal.risk_contribution()` (`threat_intel.py:940-946`, VT multi-vendor detection ratio) | none | same `confirmed_ioc` check — **aggregate signal, not a feed match; part of the gap** |
| `abuse_score` | `pipeline.py:841` `features["abuseipdb_risk"] = abuse_risk`, computed `:818-841` (AbuseIPDB crowd-sourced score, capped `>=4.0` bar per the PHASE 8 fix in `classifier.py:92-102`) | none | same `confirmed_ioc` check — **crowd-sourced, weakest of the three; part of the gap** |
| `asn_owner` | `pipeline.py:1073` argument — traced no further yet (not needed for Gap 1/2) | — | `_SAFE_ASN_OWNER_KEYWORDS` tier-2 floor check |

**Returns** `ReputationVector(domain, tier, asn_owner, vt_detection_ratio, ti_risk, abuse_risk, cl_afpe_similarity, first_seen, source_confidence)` → consumed by `DecisionEngine.evaluate()` as `rep`, and by `pipeline.py`'s own reasoning-trail text (`rep_vt`/`rep_ti`/`rep_abuse` read back via `getattr` at `decision_engine.py:74-76`).

**Gap 1 fix point:** add `verified_ioc: bool` to `ReputationVector`, set `True` only when `ti_score > 2.0`, inside `classify()`'s `if tier == 3: if confirmed_ioc: tier = 5` branch (`classifier.py:113-115`).

---

## `HypothesisEngine.evaluate_all()` → `NetworkIntrusionHypothesis.evaluate()` — `intelligence/hypotheses/engine.py:64-104, 524-547`

| Param | Generated at | Transformed | Consumed by |
|---|---|---|---|
| `ev_store` | `pipeline.py`'s `self.evidence_store` (`intelligence/hypotheses/evidence.py`'s `EvidenceStore`), built up across the whole detection cycle via `.add(Evidence(...))` calls scattered through `pipeline.py` (honeypot at `:995`, lateral scan at `:1011`, local device discovery, etc.) | Read back per-device via `EvidenceStore.get_for_device()` (`evidence.py:84-100`), which **applies freshness decay** (10 min TTL default, 24h for `independence_group=="reputation"`) before handing it to any hypothesis | Every `Hypothesis.evaluate()` subclass; `DecisionEngine.evaluate()`'s own `num_independent_sources` count (`decision_engine.py:62-64`) |
| `rep` (`ReputationVector`) | Output of `ReputationClassifier.classify()` above | none | `contradicting_score` checks in every hypothesis (`rep_vector.tier in (1,2)`) |

Inside `NetworkIntrusionHypothesis.evaluate()` (`engine.py:68-104`):
```python
has_lateral_scan = any(e.type == "zeek_lateral_scan" and e.value > 0 for e in ev_store)
has_malicious_tls = any(e.type in ("malicious_ja3", "malicious_ja4", "zeek_notice") for e in ev_store)  # ← Gap 2
has_mac_flip = any(e.type == "arp_spoof_pending" for e in ev_store)
```
- `zeek_lateral_scan` evidence is **only ever created** at `pipeline.py:1006-1011` when `zeek_lateral_unique_targets >= lateral_movement_unique_targets_threshold` (config, default 2) — already fixed, not part of this gap.
- `malicious_ja3`/`malicious_ja4` are real Zeek TLS-fingerprint-database matches.
- `zeek_notice` is **any** Zeek `weird.log` policy notice — created generically wherever `pipeline.py` adds `Evidence(type="zeek_notice", ...)`; most weird types are protocol edge-cases, not malware indicators. Folding it into `has_malicious_tls` is Gap 2.

**Gap 2 fix point:** split into `has_malicious_tls` (ja3/ja4 only) and a separate `has_notable_notice` (zeek_notice), weight the latter lower in `strong_score` (`engine.py:87-88`) — see the fix sketch in the prior turn.

---

## Gap 3 root cause — hard-stop evidence staleness (found 2026-08-27, via live SSH investigation)

`EvidenceStore.get_for_device()` (`evidence.py:84-100`) keeps any evidence "active" for up to
its TTL (600s default) after creation, decaying `freshness` but never removing it early.
`decision_engine.py`'s `has_honeypot = any(e.type == "honeypot_access" for e in ev_store)`
(and the equivalent `has_arp_spoof`/`has_geofence`/`has_confirmed_exploit` checks) only test
**presence**, never `e.freshness` or `e.timestamp`. `pipeline.py:984` only creates a *new*
`honeypot_access` Evidence on the cycle where `features["zeek_honeypot_hits"] > 0` — every
cycle after that, for up to 10 more minutes, the *same* evidence object is still sitting in
`ev_store`, so the identical CRITICAL "Internal Honeypot Accessed" verdict re-fires on every
subsequent cycle, each with that cycle's own unrelated "most notable connection" in the
display line (which is why the Telegram alerts showed mDNS multicast addresses instead of the
honeypot's own IP).

**Confirmed live, not inferred**: pulled `home-router`'s "Internal Honeypot Accessed" alerts
from `state/alerts.json` on the box directly (not the Unison-mirrored NAS copy) — several had
`features["zeek_honeypot_hits"] == 0` in their own persisted snapshot, i.e. the alert's own
recorded evidence contradicts the verdict it produced. `scripts/shadow_backtest.py`'s
`run_gap3_honeypot_backtest()` quantifies this across all history: of every
"Internal Honeypot Accessed" alert ever, roughly a third have `zeek_honeypot_hits == 0`
(stale-echo) vs. a genuine fresh trigger — see the script's live output for current counts.

**Separately** (not a code bug — a real, or at least undiagnosed, deployment fact): several of
`home-router`'s honeypot hits ARE genuinely fresh (`zeek_honeypot_hits > 0`), meaning the
router itself periodically sends real, non-excluded-port traffic to the honeypot's IP —
plausibly Fritzbox's own "Home Network" device-map/UPnP/mDNS-repeater behavior treating the
honeypot's macvlan IP as a normal known host. This is a policy question (should a
`safe_ips`-listed device's honeypot hits be exempted the way its other hard-stops already
are?), not something Gap 3's freshness fix addresses — flagged to the user, decision pending.

Cowrie itself (`docker inspect soc_honeypot`) only exposes `2222/tcp` (SSH) and `2223/tcp`
(Telnet) — confirmed empirically from a separate LAN host that `192.168.1.200:53` gives no
response at all. The `family_pc_fritz_box` "Internal Honeypot Accessed" tarpit that prompted this
whole investigation was a single 41-byte UDP packet to port 53 — real evidence
(`zeek_honeypot_hits: 1`, not a stale echo), but to a service that structurally cannot have
answered it, alongside that same device's alert history being otherwise saturated with
ordinary Windows WSD/DLNA/Spotify-Connect discovery traffic. Not proof of non-infection, but
strong circumstantial evidence against it.

## `DecisionEngine.evaluate()` — `core/decision_engine.py:26-224`

Already traced in full above (`hyp_results`, `attack_score`/`benign_score`, `num_independent_sources`, `has_honeypot`/`has_arp_spoof`/`has_geofence`/`has_confirmed_exploit`, the `tier==5` branch at `:168-173`). Returns the dict consumed at `pipeline.py:1134` as `decision`, which then drives:
- `alert_payload["signature"|"factors"|"reasoning_trail"|...]` (`pipeline.py:1500-1527`)
- `self.ips_mitigator.mitigate(..., decision_state=containment_decision_state, ...)` (`pipeline.py:1690-1700`) → real Pi-hole block / router isolation / Layer-2 tarpit (`mitigation/ips.py`)
- Telegram WHY block (`pipeline.py:2035-2037`)

**Gap 1 fix point:** `decision_engine.py:168-173`, branch on `rep.verified_ioc` as sketched two turns ago.

---

## Gap 4 — `hee_*` alert-payload fields — `core/pipeline.py` → `scripts/ollama_soc.py` → `intelligence/ai_soc.py`

New in Phase 50. Traces the full round-trip of the live pipeline's own hypothesis-competition
result from where it's computed to where it finally gates an autonomous action, days later, in
a completely different process.

| Field | Generated at | Transformed | Consumed by |
|---|---|---|---|
| `hee_hypotheses` | `decision_engine.py`'s `evaluate()` return dict, `"hypotheses": hyp_results` (`:401`) — itself `HypothesisEngine.evaluate_all()`'s return (`engine.py:586-593`): `{attack: {name, score}, benign: {name, score}, shadow_attack: {...}}` | Copied verbatim onto `alert_payload["hee_hypotheses"]` at `pipeline.py` (alert-payload construction, right after `reasoning_trail`) — **no transformation**, same dict shape | `ollama_soc.py`'s `_VERDICT_SHAPED_FIELDS` (stripped from the LLM prompt) → read back into `ground_truth["hypotheses"]` → only used for the log line's `attack_name`, not for the pass/fail decision itself |
| `hee_independent_sources` | `decision_engine.py`'s `num_independent_sources` (`:92`) — count of distinct `independence_group` values among `ev_store` items whose group is in `ATTACK_EVIDENCE_FAMILIES` (`evidence.py:71`) | none | Same round-trip as above → `ground_truth["independent_sources"]` → log line only |
| `hee_decision_path` | `decision_engine.py`'s `decision_path` local (`:166`, reassigned at each branch — `hard_stop`/`tier5_confirmed`/`tier5_corroborated`/`tier5_uncorroborated`/`hypothesis_high`/`hypothesis_suspicious`/`tier4_unconfirmed`/`ml_anomaly`/`benign`) | none | **This is the field that actually drives the gate.** `ai_soc.py`'s `DeterministicValidator.validate()` rejects any `classification=="benign"` recommendation when `ground_truth["decision_path"] in _STRONG_ATTACK_DECISION_PATHS` (`{hard_stop, tier5_confirmed, tier5_corroborated, hypothesis_high}`) |
| `hee_evidence_families` | `sorted({ev.independence_group for ev in active_evidence if ev.independence_group})` at the `pipeline.py` alert-payload call site — reads the SAME `active_evidence` list `decision_engine.evaluate()` was just called with a few lines above | none | Stripped from the LLM prompt same as the others; surfaced in `ollama_soc.py`'s `.md` report ("Original HEE finding" line) by name, not just a count — the exact `✓ Internal Discovery → ARP sweep` style naming this whole gap was about |

**Known gap this does NOT close yet:** `hee_hypotheses`/`hee_independent_sources` are round-tripped but not currently used to gate anything themselves — only `hee_decision_path`'s membership in `_STRONG_ATTACK_DECISION_PATHS` does. A `hypothesis_suspicious` alert with `independent_sources=2` and an attack score just under the 3.0 HIGH bar still passes today (matches the live pipeline's own SUSPICIOUS/monitor treatment of that same case — not a bug, just worth remembering next time this section is extended: the two unused fields are there for a future finer-grained check, not dead weight).

**What Phase 50 deliberately left alone:** the structured `{hypothesis, supporting_evidence[], contradicting_evidence[], missing_evidence[]}` prompt-response contract (the LLM still returns free-text `reason`), condition-scoped suppression (`fp_engine.py`'s `mark_false_positive()`/`_apply_sigma_shift()` are still keyed on `device_id` alone, not device+destination+behavior+hypothesis), and campaign-level correlation for the multi-device withhold guard (`should_still_withhold()` still reasons on device-count spread, not shared-destination/IOC clustering). All three are separate, larger changes — not started.
