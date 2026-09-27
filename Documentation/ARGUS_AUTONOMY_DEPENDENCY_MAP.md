# Argus Autonomy Dependency Map

Living document for the full-autonomy build (16-parameter autotune, shadow evaluation,
BOCPD rebuild, behavioral cohorts, zero-site network bootstrap). Updated at the end of
every phase, not just once. See the source design doc
(`FullyAutonomousNetwork-AgnosticBoundedPlan.txt`, provided by the user) and the
approved implementation plan for phase definitions.

This replaces two dangling doc references that existed in ~22 files' comments/docstrings
(`Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md`, `Documentation/V13_FULL_ARCHITECTURE_SHIFT_PLAN.md`)
— both were named by code comments as far back as the original v13 build but never
created; casualties of the 2026-09-15 Argus rename/doc-consolidation pass that renamed
`src/v13/` -> `src/argus/` but didn't catch every in-code doc reference. All 27
occurrences across 22 files were repointed to this doc on 2026-09-27 (Phase 0).

## 1. The 16-parameter matrix

Status as of 2026-09-27 (Phase 0 baseline), live counts pulled directly from `.94`'s real
`threshold_history` table via SSH, not inferred:

| # | Parameter | Allowlisted (`autotune/engine.py`) | Consumption call site | Generator | Live proposals / promotions on `.94` |
|---|---|---|---|---|---|
| 1 | `reputation_tier_suspicious_floor` | yes | `ops/live_engine.py:286-289` (`_tuned_rep_vector`) | **FIXED 2026-09-27 (Phase 1)**: native generator in `backtest_job.py`'s `_propose_reputation_floor_changes()`, recall-based, reuses `_decide_scoped_change()` | 0/0 as of fix (real proposals depend on future confirmed-threat volume with the new `_autotune_state` score instrumentation) |
| 2 | `reputation_tier_high_floor` | yes | `ops/live_engine.py:288-289` | **FIXED 2026-09-27 (Phase 1)**: same generator as row 1 | 0/0 as of fix |
| 3 | `bocpd_hazard_rate` | yes | `baseline/engine.py:277-278` (`_load_tracker`, cache-miss only) | **FIXED 2026-09-27 (Phase 1)**: native generator `_propose_bocpd_hazard_changes()` (delayed-shift + flapping evidence); also corrected a stale module comment in `backtest_job.py` claiming "ZERO live consumer" -- BaselineEngine has been live in `live_engine.py` since 2026-09-16 | 0/0 as of fix |
| 4 | `fp_combined_suppress_threshold` | yes | `intelligence/fp_engine.py:2181-2191` | **BUG FIXED 2026-09-27 (Phase 1)**: `train_fp_classifier.py`'s `_collect_calibration_evidence()` was pooling corrections of ANY verdict (including STAGE_1_HARD_STOP's confidence=0.0 sentinel and CONFIRMED_THREAT corrections) instead of only UNCERTAIN-verdict corrections, permanently poisoning `lowest_corrected` near 0 | 0/0 as of fix -- confirmed via live `.94` data this is now a genuine "not enough unambiguous evidence yet" outcome, not a bug |
| 5 | `arp_sweep_unique_targets_threshold` | yes | `intelligence/fp_engine.py:2222-2229`, `cl_afpe/engine.py:398` | `train_fp_classifier.py`'s `_propose_and_promote()` | 18 / 11 |
| 6 | `hard_stop_candidate_sensitivity` | yes | `decision/engine.py:215,231` via `ops/live_engine.py:1025-1027` | `backtest_job.py` synthetic sweep | 70 / 1 |
| 7 | `peer_deviation_multiplier` | **YES (Phase 3)** | `ops/live_engine.py:_inject_peer_deviation_evidence()`, resolved via `get_active_value` | `backtest_job.py`'s `_propose_peer_deviation_changes()` (loosen-only, real evidence) | wired 2026-09-27 |
| 8 | `peer_deviation_min_absolute_count` | **YES (Phase 3)** | same call site as row 7 | same generator as row 7 | wired 2026-09-27 |
| 9 | `combined_uncertain_threshold` | **YES (Phase 3)** | `intelligence/fp_engine.py`'s new `get_device_uncertain_threshold()`, called from `evaluate()` | `train_fp_classifier.py`'s `calibrate_uncertain_threshold()` (loosen-only, mirrors `calibrate_suppress_threshold()`) | wired 2026-09-27 |
| 10 | `familiarity_trust_bar` | **YES (Phase 3)** | threaded plain-float through `decision/engine.py`→`hypotheses/engine.py`'s `evaluate_all()` (instance-attribute override on `DeviceProfileBenignHypothesis`), resolved in `live_engine.py`; `llm_review/validator.py`'s `DeterministicValidator.validate()` also takes it explicitly now (was reading the class constant directly, a real drift risk `validator.py`'s own docstring warns about) | `backtest_job.py`'s `_propose_familiarity_trust_bar_changes()` (loosen-only, real evidence) | wired 2026-09-27 |
| 11 | `trust_cache_ttl_seconds` | **YES (Phase 4)** | `cl_afpe/engine.py`'s `_active_trust_edges()`, global-scope only | `backtest_job.py`'s `_propose_trust_cache_ttl_changes()` (tighten-only, single-instance "trust blindness") | wired 2026-09-27 |
| 12 | `reputation_propagation_ttl_seconds` | **YES (Phase 4)** | `ops/live_engine.py`'s `_inject_graph_derived_evidence()`, device-scoped | `backtest_job.py`'s `_propose_reputation_propagation_ttl_changes()` (loosen-only, sample-floor-gated — mirror image of row 11, see its docstring for a real sign-error this file's own tests caught and fixed) | wired 2026-09-27 |
| 13 | `pool_gaussian_kappa` | **YES (Phase 4)** | `ops/population_prior_builder.py`'s `_pool_gaussian()`, category-scoped | `population_prior_builder.py`'s `_propose_pool_pseudocount_change()` (between/within-device dispersion ratio heuristic — a real, first-pass proxy for "population-prior error", not the fully rigorous posterior-predictive checking the plan's own evidence description implies; see that function's own HONEST SCOPE NOTE) | wired 2026-09-27 |
| 14 | `pool_gaussian_alpha` | **YES (Phase 4)** | same call site as row 13 | same generator as row 13 | wired 2026-09-27 |
| 15 | `pool_beta_total` | **YES (Phase 4)** | `ops/population_prior_builder.py`'s `_pool_beta()`, category-scoped | same generator family (dispersion ratio), `_beta_dispersion()` | wired 2026-09-27 |
| 16 | `pool_poisson_rate` | **YES (Phase 4)** | `ops/population_prior_builder.py`'s `_pool_poisson()`, category-scoped | same generator family, `_poisson_dispersion()` | wired 2026-09-27 |

**All 16 parameters are now wired end to end (allowlisted, consumed live, real forward generator) as of Phase 4, 2026-09-27.** Whether any given one has ever actually *fired* on real `.94` data is a separate question — check `threshold_history` directly, don't assume from this table.

This table is the single source of truth for "is parameter X actually tuning itself
right now" — update every row whose status changes at the end of the phase that
changes it.

## 2. `.94` deployed-state baseline

- Working dir: `/home/user/myscripts/home-ids/SOC`, service `soc.service`.
- Deployed commit as of 2026-09-27 (Phase 0): `0446bd1755ce2fa7e367a27bac1cf56b2ec26dd6`
  ("fix(pipeline): remove the recurring 15-19s main-loop stalls"), one commit behind
  local `main` (`fec50c2`, test-only fix — no functional drift).
- `.94` real IP: `192.168.77.94` (not `.1.94` — a past session's memory note was wrong
  about this).
- `.19` is out of scope for this entire effort per explicit user instruction — mentioned
  only where it's relevant as prior art NOT to build on (its separate `ingest/daemon.py`
  process, cited in Phase 7's shadow-eval research as a non-reusable "shadow-like"
  mechanism).

## 3. Narrow test subsets per subsystem

(Full ~137-file `tests/` directory is never run without asking first — these named
subsets gate each phase instead.)

- Autotune core/generators: `test_argus_autotune_engine.py`, `test_argus_autotune_reset.py`, `test_argus_backtest_job.py`
- Shadow-evaluation sandbox: `test_argus_shadow_sandbox.py`
- Baseline/BOCPD: `test_argus_baseline_engine.py`, `test_argus_bayesian_baseline.py`
- Population priors/cohorts: `test_argus_population_prior_builder.py`, `test_phase44_mac_vendor_and_device_type.py`
- Live engine/decision path: `test_argus_live_engine.py`, `test_argus_decision_engine.py`, `test_argus_hypotheses_engine.py`
- CL-AFPE: `test_argus_cl_afpe.py`, `test_argus_cl_afpe_composite_trust.py`, `test_argus_cl_afpe_flip_monitor.py`, `test_argus_cl_afpe_ml_scoring.py`, `test_argus_live_cl_afpe_shadow.py`
- Identity: `test_argus_identity_resolver.py`, `test_argus_live_identity.py`, `test_identity_reconcile_dhcp_ja4_signal.py`, `test_identity_reconcile_pass.py`, `test_phase39_retroactive_identity_merge.py`, `test_phase64_device_identity_guard.py`
- Health/resource: `test_health_manager_state_machine.py`, `test_resource_pressure_modes.py`, `test_health_manager_healing_actions.py`, `test_health_manager_memory_diagnostics.py`
- Router/mitigation: `test_mitigation_router_adapter.py`, `test_mitigation_api.py`, `test_ips_operator_actions.py`, `test_phase55_router_reconcile_timeout.py`
- Capture/disk: `test_phase23_fritzbox_capture.py`, `test_disk_budget_governor.py`
- Config/trust anchors: `test_argus_config_trust_anchors.py`
- Regression gate (run before/after any evidence-scoring or decision-path change): `test_real_world_alert_regression.py`

## 4. Arg-provenance sections (added as each subsystem is built)

### 4.1 Autotune native generator registry (Phases 1, 3, 4)
Phase 4 (2026-09-27) completes all 16 parameters:
- `trust_cache_ttl_seconds`/`reputation_propagation_ttl_seconds`: consumption in
  `cl_afpe/engine.py`'s `_active_trust_edges()` (global-scope, via a new lazy
  `_get_autotune_engine()` on `ClAfpeEngine`) and `live_engine.py`'s
  `_inject_graph_derived_evidence()` (device-scoped). Generators in
  `backtest_job.py` are mirror-image asymmetric (one tighten-only/single-
  instance, one loosen-only/sample-floor-gated) — a real sign error in the
  loosen one (computed the tighten formula, which for a `direction=-1`
  parameter moved the value the WRONG way) was caught by this phase's own test
  suite before it ever shipped, not by inspection. Worth re-reading if adding
  any new `direction=-1` parameter: the generic `current - direction*step`
  tighten / `current + direction*step` loosen formulas only give the right
  arithmetic sign when the evidence-to-action mapping (does THIS evidence mean
  tighten or loosen) is derived correctly first — get that backwards and the
  formula still "works", just moves the parameter the wrong way.
- `pool_gaussian_kappa`/`pool_gaussian_alpha`/`pool_beta_total`/`pool_poisson_rate`:
  consumption in `population_prior_builder.py`'s `_pool_gaussian()`/`_pool_beta()`/
  `_pool_poisson()`, category-scoped (population priors are inherently per-
  device_type, no per-device version makes sense). Generator
  (`_propose_pool_pseudocount_change()` + per-model-kind `_gaussian_dispersion()`/
  `_beta_dispersion()`/`_poisson_dispersion()` helpers, all in
  `population_prior_builder.py`) is a first-pass between/within-device dispersion
  ratio heuristic, explicitly NOT the fully rigorous posterior-predictive
  checking the plan doc's own "population-prior error" evidence description
  implies — that would need real, separate statistical infrastructure this phase
  didn't build from scratch; documented as an honest scope limit in the code
  itself, matching this repo's own established pattern for similar gaps
  (`bocpd_hazard_rate`'s retroactive-rollback scope limit, Phase 1).

Phase 3 (2026-09-27) wired the remaining Tier-2 parameters natively in
`src/argus/ops/backtest_job.py` (generators) plus consumption call sites across
`src/argus/ops/live_engine.py`, `src/intelligence/fp_engine.py`,
`src/argus/decision/engine.py`, `src/argus/hypotheses/engine.py`,
`src/argus/llm_review/validator.py`, `src/argus/ops/live_llm_review.py`,
`src/scripts/train_fp_classifier.py`:
- `peer_deviation_multiplier`/`peer_deviation_min_absolute_count`: consumption in
  `_inject_peer_deviation_evidence()`; generator `_propose_peer_deviation_changes()`
  is loosen-only (real evidence exists only for "this firing was a false positive,
  raise the bar" — no recorded signal exists for "this should have fired but
  didn't", an honest, structural scope limit, not an oversight).
- `combined_uncertain_threshold`: consumption via new `get_device_uncertain_threshold()`
  in `fp_engine.py` (mirrors `get_device_suppress_threshold()`'s own layered-fallback
  shape exactly); generator `calibrate_uncertain_threshold()` in
  `train_fp_classifier.py`, loosen-only, mirrors `calibrate_suppress_threshold()`
  but reads the OPPOSITE evidence population (CONFIRMED_THREAT-verdict corrections,
  not UNCERTAIN-verdict ones — mixing them would repeat Phase 1's own bug).
- `familiarity_trust_bar`: consumption threaded as a plain float from
  `live_engine.py` (device-scoped resolution) through `decision/engine.py` into
  `hypotheses/engine.py`'s `evaluate_all()`, applied as an INSTANCE-attribute
  override on the specific `DeviceProfileBenignHypothesis` object (deliberately not
  a new positional arg on every one of the other 15 hypothesis classes' shared
  `evaluate()` signature). Also threaded into `llm_review/validator.py`'s
  `DeterministicValidator.validate()` (previously read
  `DeviceProfileBenignHypothesis.FAMILIARITY_TRUST_BAR` directly at the class level
  — a real, latent drift risk between the two consumers that `validator.py`'s own
  docstring already warned about; now both read the SAME resolved per-device
  value). Generator `_propose_familiarity_trust_bar_changes()` in `backtest_job.py`,
  loosen-only, needed a NEW instrumentation field (`baseline_familiarity` added to
  `_autotune_state`, alongside the bar itself) since nothing previously recorded the
  familiarity score a decision was actually judged against.

New `_autotune_state` fields (all added `live_engine.py`, decisions before
2026-09-27 don't carry them): `familiarity_trust_bar`, `baseline_familiarity`.

Phase 1 (2026-09-27) landed natively in `src/argus/ops/backtest_job.py` (not a
separate module) — the generic propose/canary/promote/rollback machinery in
`autotune/engine.py` was already generic; Phase 1 added real candidate generators
for the 4 previously-dead Tier-1 parameters:
- `fp_combined_suppress_threshold`: root-cause bug fix in
  `src/scripts/train_fp_classifier.py`'s `_collect_calibration_evidence()` (verdict
  population mismatch, see the matrix table above) -- the generator itself
  (`calibrate_suppress_threshold()`/`_propose_and_promote()`) was already correct.
- `reputation_tier_suspicious_floor`/`reputation_tier_high_floor`: new
  `_propose_reputation_floor_changes()` + `_reputation_recall_hits_totals()` +
  `check_reputation_floor_retroactive_misses_and_rollback()`, all reusing the
  existing `_decide_scoped_change()`. Requires a NEW instrumentation field: every
  decision's `_autotune_state` block (already existed for audit) now also carries
  `reputation_vt_score`/`reputation_ti_score`/`reputation_abuse_score` (added in
  `src/argus/ops/live_engine.py`, ~line 1027) -- decisions recorded before
  2026-09-27 have no such field and are correctly treated as "no evidence", not
  silently backfilled.
- `bocpd_hazard_rate`: new `_propose_bocpd_hazard_changes()`, evidence = confirmed
  incidents with no preceding `regime_change` evidence (delayed shift, tightens) +
  a flapping veto (>= `_BOCPD_FLAP_MIN_UNCORROBORATED` uncorroborated regime_change
  events blocks loosening only). No retroactive-rollback check exists for this
  parameter -- it governs an algorithm's dynamics, not a scalar-vs-band comparison,
  so the pattern the other 5 parameters' rollback checks use doesn't structurally
  apply; documented as an honest scope limit in `backtest_job.py` itself.

All new tests added to `tests/test_argus_backtest_job.py` in the same hand-rolled
`check()`/`FAILURES` convention as the file's existing tests.

### 4.2 Capture-queue disk protection (Phase 2)
Shipped 2026-09-27. `src/extractors/fritzbox_capture.py`'s `ReactiveCaptureDispatcher`
gained `_check_disk_budget()`, a pre-dispatch gate on `reactive_capture_scratch_dir`'s
total size, called first (before the existing hourly count/bytes gates) from
`_check_and_consume_budget()`. Hard ceiling: `reactive_capture_max_scratch_bytes`
(config key, default 5GB = 5368709120 bytes). On overflow: prunes oldest-first
(excluding `reactive_capture_history.jsonl`/`.bak`, which are size-rotated separately
and never deleted as scratch overflow, but DO still count toward total usage); if
still over budget after pruning everything prunable, rejects the dispatch
(`outcome=deferred_disk_budget` on `home_ids_reactive_capture_bursts_total`,
`home_ids_reactive_capture_degraded` gauge set to 1) rather than ever violating the
ceiling. Separate from `disk_budget_governor.py`'s own 20GB whole-stack budget, which
explicitly treats this directory as monitor-only.

Real regression found and fixed during this same phase, not by inspection: a full
directory walk/stat on every `_check_and_consume_budget()` call (which fires on every
trigger attempt, not just real dispatches) turned a previously pure in-memory check
into synchronous disk I/O on the hot path, and broke a pre-existing concurrency test's
timing assumptions (4 rapid-fire triggers all dispatched instead of only the first).
Fixed by throttling the real scan to at most once per `_DISK_CHECK_INTERVAL_SECONDS`
(60s), reusing the cached `self._disk_degraded` verdict in between -- the same
"periodic, not per-call" precedent `cleanup_stale_scratch_files()` already
established in this file for the identical reason.

New metrics: `home_ids_reactive_capture_scratch_bytes` (gauge),
`home_ids_reactive_capture_scratch_pruned_total` (counter),
`home_ids_reactive_capture_degraded` (gauge). New config key documented in
`config.yaml.example` and `middleware/config_schema.py`. New tests in
`tests/test_phase25_reactive_capture_triggers.py`'s new "Section H".

### 4.3 BOCPD rebuild-on-promotion (Phase 5)
Shipped 2026-09-27. Closes `baseline/engine.py`'s own former "HONEST LIMITATION"
(a promoted `bocpd_hazard_rate` never reached an already-warm tracker until it was
next reconstructed). Two mechanisms, deliberately separate because one is inert on
the real deployed topology:

1. **The mechanism that actually matters**: `_load_tracker()`'s cache-HIT path now
   re-checks the promoted value at most once per `_HAZARD_RATE_RECHECK_SECONDS`
   (60s) and, if changed, updates `tracker.hazard_rate` **in place** — no eviction,
   no reload, hypothesis list/posterior state fully preserved (`BOCPDTracker.observe()`
   reads `self.hazard_rate` fresh every call, never bakes it into a closure, so this
   is a safe mutation). This works across the real process boundary:
   `bocpd_hazard_rate`'s own promoter (`backtest_job.py`'s `run_backtest()`) runs as
   its own scheduled OS subprocess, never in-process with the live `soc.service`
   pipeline `BaselineEngine` actually runs inside — the re-check works because it
   re-reads the shared SQLite `threshold_history` table, the real cross-process
   channel.
2. **`AutotuneEngine.set_notify()`/`_fire_notify()`**: a new generic promotion/rollback
   notify mechanism, mirroring `src/config.py`'s `LiveConfig` exactly (multi-subscriber,
   exception-isolated). `BaselineEngine` registers a callback that forces an immediate
   re-check (bypassing the 60s throttle) for the affected device's keys. Confirmed via
   direct investigation this is **defense-in-depth only** for the current deployment —
   it would matter for a future in-process promoter, but has zero effect on
   `bocpd_hazard_rate`'s real promotion path today, which is cross-process. Kept anyway
   since it's the same reusable, already-tested pattern this codebase established for
   config reload, and genuinely useful for any future in-process caller of
   `promote_change()`/`rollback_change()`.

`now` threaded through `_load_tracker()` (previously used `time.time()` directly,
inconsistent with this codebase's deterministic-testing convention). New tests in
`tests/test_argus_baseline_engine.py` (throttle, in-place update, hypothesis
preservation, rollback, notify) and `tests/test_argus_autotune_engine.py` (the
generic notify mechanism + exception isolation, independent of BOCPD).

### 4.4 Resource-aware autotune/shadow pause (Phase 6)
Shipped 2026-09-27. New `src/utils.py` function `is_resource_pressure_active(min_level=1,
metrics_url=...)`: the cross-process signal every candidate generator checks before
proposing anything new. HONEST DESIGN NOTE, confirmed via direct investigation:
the plan's own wording ("an in-process flag, same pattern as the existing
ti_engine/abuseipdb/virustotal `.paused` flags") assumes candidate generation runs
in-process with the live pipeline. It doesn't — `backtest_job.py`'s `run_backtest()`,
`train_fp_classifier.py`'s `run_threshold_calibration()`, and
`population_prior_builder.py`'s `build_population_priors()` all run as their own
scheduled OS subprocesses (`scripts/scheduler.py`), the same cross-process gap Phase 5
already found for `bocpd_hazard_rate`'s tracker cache. An in-process flag on
`self.pipeline` would be structurally invisible to them. Instead: a local scrape of
the live pipeline's own already-running `/metrics` endpoint (port 9105), reading the
EXISTING `home_ids_health_pressure_level` Prometheus gauge `health_manager.py` already
sets — no new state file, no new relay, matching the project's Prometheus-native
observability standard. Fails OPEN (not paused) on any scrape failure, so a metrics
outage can never silently disable autotuning.

Wired at the candidate-GENERATION layer only in all three files — `get_active_value()`
reads (active detection) are completely unaffected, and PROMOTION of already-canaried
changes also proceeds regardless (not "new candidate generation"). `job_coordinator.py`/
`resource_gate.py` deliberately untouched — those arbitrate separate OS subprocess
scheduling slots (a different resource question), not the live pipeline's own RSS/swap
health this pause is about.

New tests: `tests/test_resource_pressure_modes.py` (5 new tests for
`is_resource_pressure_active()` itself, using a real local HTTP server, not a mock) and
`tests/test_argus_backtest_job.py` (one integration test confirming `run_backtest()`
actually consults it and correctly separates "no new generation" from "promotion still
proceeds").

### 4.5 Shadow-evaluation sandbox (Phase 7)
**DONE 2026-09-27, shipped to `main`.** New `argus/shadow/sandbox.py` +
`ShadowEvaluator` module-level singleton in `argus/ops/live_engine.py`
(`_get_shadow_evaluator()`/`maybe_shadow_evaluate()`, same lazy-singleton shape as
`_get_cl_afpe_engine()`). Wired into `core/pipeline.py` immediately after the real
`argus_live_engine.evaluate(...)` call (the one that also feeds `decision` for this
cycle) — passes the SAME real inputs (`active_evidence`, `rep_vector`, `device_type`,
`baseline_familiarity`, `features`, `is_safe`, `dev_id`, `now`) plus `decision["state"]`
as the agreement baseline. Runs EVERY cycle (not gated on an alert firing), unlike
`evaluate_cl_afpe_shadow()`'s narrower alert-only call site — deliberate, so canary
parameters get statistically meaningful comparison data from BENIGN cycles too, not
just alert-worthy ones.

New tables: `shadow_decisions` (schema.sql + `_migrate_existing_db()`, both updated —
capped at 5000 rows, pruned oldest-first on write, no separate TTL job). New metrics:
`shadow_eval_comparisons_total{parameter,agree}`, `shadow_eval_errors_total`,
`shadow_eval_paused` (port 9106, `task` label convention).

Safety: the shadow `evaluate()` call is wrapped in a real `GraphStore.transaction()`,
force-rolled-back via an internal `_ShadowAbort` sentinel right after reading the
shadow decision's state — confirmed via grep that `core/pipeline.py` never itself
calls `store.transaction()`, so this is always the genuine outermost transaction, not
a no-op nested passthrough. Candidate substitution: `AutotuneEngine.get_active_value`
is monkey-patched at the CLASS level for the one target parameter only, for the
duration of the shadow call, always restored in a `finally`. Alert/mitigation
isolation needs no special guard: alerting/containment happen in `pipeline.py` AFTER
`evaluate()` returns, and the shadow caller never touches `alert_manager`/
`ips_mitigator` at all.

Candidate selection picks AT MOST ONE currently-in-canary `threshold_history` row per
cycle (`WHERE promoted_at IS NULL AND rolled_back_at IS NULL AND canary_until > now`),
preferring device-scoped > category-scoped > global — **a real priority-ordering bug
was found and fixed by this phase's own test coverage**: the original single-pass
loop broke on the FIRST scope match encountered in row order, so a device-scoped
canary occurring after a matching category/global row in scan order was wrongly
passed over. Fixed to three separate passes (device, then category, then global),
each independently confirmed by `tests/test_argus_shadow_sandbox.py`'s section D.
Resource-pressure-gated via the same `is_resource_pressure_active()` Prometheus scrape
Phase 6 introduced (`shadow_eval_paused` gauge tracks the pause state live).

Never touches `resolver.resolve_device_id()` directly (§4.9's landmine does not apply
here) — `device_id` arrives already-canonical from `core/pipeline.py`'s own call site.

Test: new `tests/test_argus_shadow_sandbox.py` (21 checks, hand-rolled convention) —
proves the rollback guarantee with real `evidence`/`decisions` row counts before/after,
the candidate-substitution mechanism actually reaches a stubbed `evaluate()`, the
fail-safe never propagates and always restores the patch, the (now-fixed) scope
priority order, the resource-pressure pause, and the row-count-cap pruning. Also ran
`tests/test_argus_live_engine.py`, `tests/test_argus_autotune_engine.py`,
`tests/test_real_world_alert_regression.py` — all green, no regression from the
`pipeline.py`/`live_engine.py` call-site additions.

### 4.6 Behavioral cohorts (Phase 8)
**DONE 2026-09-27, shipped to `main`.** The plan's own pointer ("cohort key reuses
`cl_afpe_trust.behavior_fingerprint`") was checked directly and does NOT fit:
`behavior_fingerprint` is `derive_activity_state(evidence_types_this_cycle)`
(`baseline/engine.py`'s 8-value `ACTIVITY_STATES` label) -- a coarse, shared
per-EVIDENCE-CYCLE label, identical for every device showing the same evidence
types, not a per-device behavioral signature. Built a genuinely new device-level
cohort key instead, reusing the closest REAL existing per-device behavioral
signal already tracked today: `device_baselines`' own learned Gaussian posteriors
for `query_rate`/`entropy_avg`/`unique_domains` (all generic, already-tracked
traffic statistics -- never anything household-specific,
[[feedback_network_agnostic_design]]).

`population_prior_builder.py`'s new `_compute_behavioral_cohorts()`: population-
RELATIVE tertile bucketing (rank-based, not value-cutoff-based -- an earlier
value-cutoff version was found by this phase's own test coverage to split two
near-identical devices across adjacent buckets purely because one straddled a
specific rank's boundary value; fixed to assign each device a bucket by its own
rank among the population instead). Requires real data on all 3 metrics (an
incomplete device gets no cohort_key, not a guessed one) and >= 6 devices with
complete data (below that, a tertile split is statistically meaningless).
Persists to new `device_cohort_membership` table (schema.sql +
`_migrate_existing_db()`, both updated).

New `device_identity_stability` table, stamped by `GraphStore.merge_device()`
itself (one hook catches every real merge call site: `core/identity.py`'s real-
time path, `pipeline.py`'s periodic reconciliation worker, and
`merge_fragmented_devices.py`, since all 3 already mirror through
`merge_device()`). Used as an ADDITIONAL contributor-eligibility gate for cohort
pooling only (>= 7 days stable, or never-merged) -- deliberately NOT applied
retroactively to the existing device_type pooling, a narrower scope for this
phase.

New `cohort_priors` table (same shape as `population_priors`, cohort-keyed
instead of device_type-keyed, gaussian/beta/poisson only -- cohort-scoped Markov
pooling is an honest, documented scope limit, not built this phase). Read ONLY
as a fallback in `baseline/engine.py`'s `_seeded_model()`/`_load_markov()` when
no device_type prior exists, never overriding a working device_type prior. Does
NOT get its own autotune-tunable pseudo-counts (the existing `pool_*` parameters
stay category/device_type-scoped, matching the closed 16-parameter set) -- fixed
module defaults only for cohort pooling, an honest first-pass scope limit.

**Real bug found and fixed as a paired fix while touching this same cold-start
path**: `_load_markov()` read ONLY the raw `devices.device_type` SQL column,
skipping `metadata_json` -- the exact footgun `_device_type_map()`'s own
docstring already documents (the column is NULL for every real device on `.94`).
This silently made the Markov axis's own device-type cold-start prior
permanently inert in production, unlike every other axis's `_seeded_model()`
call. Fixed to check `metadata_json` first, matching every other axis.

Test: extended `tests/test_argus_population_prior_builder.py` (new section O,
9 checks: cohort assignment, cross-cohort separation, cohort_priors pooling, the
identity-stability gate, the insufficient-population bail) and
`tests/test_argus_baseline_engine.py` (3 checks: cohort fallback works,
device_type prior still wins when both exist, the `_load_markov()` bugfix). Also
ran `tests/test_phase44_mac_vendor_and_device_type.py` (the NULL-footgun/no-
guessed-category regression guard this phase's own design explicitly respects)
and `tests/test_real_world_alert_regression.py` -- all green, no regression.

### 4.6b Zero-site bootstrap A: config-schema validation (Phase 9)
**DONE 2026-09-27, shipped to `main`.** `hardware_profile` and `network.trust_anchors`
were already loaded (`argus/config/trust_anchors.py`, since the v13 full-architecture
plan's Phase 2) but had NO `CONFIG_SCHEMA` entry at all -- invisible to
`GET /api/config`, validated only by a best-effort log warning at load time.

`middleware/config_schema.py`: `hardware_profile` is a plain top-level scalar, so it
now uses the existing generic "enum" mechanism unchanged, with `options` imported
directly from `trust_anchors.py`'s own `VALID_HARDWARE_PROFILES` (never copied --
can't silently drift out of sync with the real validation rule). `network.trust_anchors`
is a nested list-of-dicts (the same "doesn't fit the generic PATCH shape" problem
`device_type_overrides` already has) -- added as a READ-ONLY display row (the
existing dotted-key convention already forces this). Both added to
`RUNTIME_RESTART_KEYS` (verified against their real read call sites: `hardware_profile`
via `argus_live_engine.configure()` -> `GraphStore(..., hardware_profile=...)`;
`network.trust_anchors` via `core/pipeline.py`'s one-time `LiveIdentityManager`
construction).

`middleware/routers/config_api.py`'s `get_config()`: the `network.trust_anchors` row
gets real structural validation by calling `load_trust_anchors()` itself (the SAME
function `core/pipeline.py`'s own startup call site uses) against the raw configured
list, surfacing `trust_anchors_raw_count`/`trust_anchors_accepted_count`/
`trust_anchors_valid` -- an operator can now see a malformed trust_anchors entry from
the console without restarting and grepping logs. Coarse (accepted-vs-raw count, not
a per-entry issue list) is an honest first-pass scope limit -- the real function
already logs a specific warning per malformed entry; that detail isn't yet
duplicated into this API response.

Test: extended `tests/test_config_api.py` (6 new pytest cases: hardware_profile enum
PATCH-rejection + GET shape, trust_anchors dotted-key PATCH-rejection, and 3
validation-surface cases -- all valid, a malformed entry flagged, and no `network` key
configured at all). `tests/test_argus_config_trust_anchors.py` re-run unchanged
(nothing in `trust_anchors.py` itself was touched) -- all green.

### 4.7 Zero-site bootstrap: identity-resolution priority chain
Current state (Phase 0, unchanged from today's production behavior):
`LiveIdentityManager.resolve_device_id()` (`argus/identity/live_manager.py:227-297`) is
already live in production (imported/instantiated at `core/pipeline.py:53,760`),
already generalized past the single `gateway_ip` string-match to an arbitrary
`trust_anchors` list — but that list is still hand-edited YAML
(`config.yaml`'s `network.trust_anchors`), not auto-discovered. Priority chain today:
1. `client_ip` exactly matches a trust anchor -> fixed canonical id (using the literal
   configured `anchor.ip` via `v13_stable_device_id(anchor.ip)`, NOT `resolver.py`'s own
   role-based hash — `live_manager.py` deliberately overrides this for continuity, see
   §4.9 landmine note below).
2. client MAC matches a trust anchor's learned MAC on a different IP -> same anchor id.
3. client MAC found in existing mac->device_id binding -> that device_id.
4. private/trackable IP -> `stable_device_id(ip)`.
5. non-generic hostname -> `stable_device_id(f"host:{hostname}")`.
6. MAC fallback -> `stable_device_id(mac)`.
7. raw IP fallback -> `stable_device_id(ip)`.
_Will change in Phase 11 (resolver.py's own formula fixed at the source) and again in
Phase 13 (trust_anchors auto-populated, cutover from hand-edited config)._

#### 4.7b Zero-site bootstrap B: auto-discovery (Phase 10)
**DONE 2026-09-27, shipped to `main`.** New `argus/identity/discovery.py`, purely
additive and NOT yet wired into any live call site (Phase 13's cutover is what
makes its output authoritative) -- built and deployed for real per the user's
"no dry-run-only phase" instruction, verified once against `.94`'s real network
over SSH, then left in place unused rather than gated behind a flag.

Two roles discovered, both from generic OS/network primitives only (no
household-specific rule): `this_host` (`psutil.net_if_addrs()`, selecting
whichever non-loopback interface's own subnet actually contains the discovered
gateway -- avoids the multi-NIC ambiguity a naive "first interface" pick would
hit, e.g. a Docker bridge interface enumerated before the real LAN NIC) and
`gateway` (the kernel's own default-route table via `ip route show default`,
MAC resolved via a real ARP request/reply using `scapy.srp()` -- the same
generic L2 primitive `mitigation/ips.py`'s own tarpit already depends on, not a
new dependency). Output is the exact `[{role, ip, mac}, ...]` shape
`argus/config/trust_anchors.py`'s `load_trust_anchors()` already expects --
zero adaptation needed at the Phase 13 cutover.

`discover()` always logs a diff against whatever `trust_anchors` is currently
configured (WARNING-level if anything changed, INFO if not) -- a PERMANENT
feature every call makes, not a one-time dry-run gate, matching this whole
effort's "fix forward with live data" standing instruction.

**Real verification against `.94` (2026-09-27, over SSH)**: manually ran
`discover()` against `.94`'s actual live network state -- correctly found
`gateway` at the real FritzBox IP and `this_host` at `.94`'s own real LAN
IP+MAC, matching the hand-configured values already known-correct for this
network. (Exact IPs deliberately not repeated here --
[[feedback_no_real_pii_in_github]] -- see the session's own record for the
literal values if ever needed again.) The manual run's own ARP resolution
failed with a raw-socket PermissionError (expected: a plain SSH shell has
none of `soc.service`'s own `CAP_NET_RAW`/`CAP_NET_ADMIN` ambient capabilities,
confirmed present in the real unit file) -- `discover()`'s fail-safe correctly
degraded to `gateway` with `mac=None` rather than crashing, exactly the
behavior `tests/test_argus_identity_discovery.py`'s section D already covers.
Once wired into the live service in a later phase, ARP resolution will run
with the same ambient capabilities the tarpit already depends on and should
succeed there.

Test: new `tests/test_argus_identity_discovery.py` (11 checks) -- fully mocked
(`psutil.net_if_addrs()`, `subprocess.run()`, `scapy`'s ARP resolution), no
real packet capture or network I/O in the test itself. Covers: single-NIC
discovery, the multi-NIC subnet-matching selection (a Docker-bridge-style
decoy interface correctly loses out to the real LAN NIC), graceful
degradation when no default route or ARP reply is found (never a crash, never
a fabricated anchor), an empty interface table, and both drift-logging
branches.

## 4.8 Zero-site bootstrap: `RouterAdapter` (Phase 12)
**DONE 2026-09-27, shipped to `main`.** New `mitigation/router_adapter.py`,
implementing the shape `Documentation/SHIPPABILITY_AND_SCALE_PLAN.md`'s SS1
already proposed: `RouterAdapter` interface (`isolate`/`unisolate`/`get_hosts`/
`get_isolation_status`/`health_check`/`capture_supported`), `FritzBoxAdapter`
(thin wrapper, unchanged TR-064/FritzHosts logic) and `NoRouterAdapter` (the
safe default: Pi-hole DNS sinkholing + the Layer-2 tarpit stay fully active,
only hardware-level isolation and reactive AVM-format capture are
unavailable). Selected via a new `router_type` config key (`"fritzbox"`
default, `"none"` for a network with no supported router), resolved FRESH on
every request/dispatch (no caching), so changing it takes effect immediately,
no restart needed.

**Real discovery during investigation, not assumed**: `mitigation/ips.py` needed
ZERO changes for this phase. Confirmed via direct read that it already talks to
router isolation over a generic local HTTP webhook
(`router_webhook_url`/`router_hosts_url`, default `http://127.0.0.1:8010/...`),
never importing `fritzbox_api.py` or `FritzConnection` directly -- the
abstraction boundary this phase formalizes already existed at that HTTP layer.
The real Fritz!Box-specific logic lived entirely in
`middleware/routers/fritzbox_api.py`'s THREE route handlers (`/isolate`,
`/hosts`, `/api/ipc/router_isolation_status`), which now delegate to
`get_router_adapter(CONFIG)` instead of hardcoding TR-064/FritzHosts calls
inline -- moved behind the adapter unchanged, not reimplemented.
`main.py`'s startup diagnostic summary also now calls the adapter's
`health_check()` instead of hardcoding a `FritzConnection` probe, so
`router_type=none` correctly reports "no router configured" instead of a
misleading FritzBox connection failure.

`ips.py`'s own Layer-2 IPv6 NDP-tarpit mitigation
(`mitigate()`/`get_containment_status()`/`operator_isolate_router()`) is
completely untouched -- already vendor-agnostic, exactly the case
`SHIPPABILITY_AND_SCALE_PLAN.md`'s SS1 calls out as not needing this fix.
`_router_isolated_devices`/`_tarpit_active_targets` dict shapes unchanged.

Test: new `tests/test_mitigation_router_adapter.py` (mocked
`fritzbox_api`/`fritzconnection`, no real network I/O) covering factory
selection (including the fail-safe-to-`NoRouterAdapter` case for an
unrecognized `router_type`), every `NoRouterAdapter` method's safe-degrade
behavior, and `FritzBoxAdapter`'s real call-through/parsing/error-propagation
behavior. Also ran (and updated where the refactor moved a source-guarded
string) `tests/test_mitigation_api.py`, `tests/test_ips_operator_actions.py`,
`tests/test_phase55_router_reconcile_timeout.py` -- all green.
`tests/test_phase62_tarpit_release_on_benign.py` fails on `main` already, for
a reason unrelated to this phase (reads `src/scripts/ollama_soc.py`, retired
in an earlier commit consolidating Layer-3 LLM review onto
`live_llm_review.py` -- the test was never updated to match); flagged here,
not fixed, since it's out of this phase's scope.

### 4.9 Landmine CLOSED (Phase 11, 2026-09-27)
`argus/identity/resolver.py`'s pure `_anchor_device_id()` FIXED: an anchor with a
configured `ip` now resolves via `stable_device_id(anchor.ip)` directly (matching
pre-v13 code's own historical formula for its one anchor, `gateway_ip`), falling
back to the role-based hash (`stable_device_id(f"anchor:{role}")`) only for a
role-only anchor with no `ip` configured. Confirmed via grep at fix time:
`live_manager.py`'s `LiveIdentityManager` is `resolver.py`'s only real caller, and
its own `resolve_device_id()` never delegates `trust_anchors` into the pure
`resolve_device_id()` call at all (branches 1/2 there are dead code in production
today) -- so this fix has ZERO live behavior change, it closes the landmine before
Phase 10's discovery diff logic (or any other future caller) could hit it directly.
`live_manager.py`'s own inline workaround (`v13_stable_device_id(anchor.ip) if
anchor.ip else _anchor_device_id(role)`) is left in place, not refactored to
delegate to the now-fixed pure function -- a working, already-tested live code
path, deliberately not touched for a purely cosmetic DRY cleanup on a sensitive
identity-resolution path. New parity test (`tests/test_argus_live_identity.py`,
section C2) asserts the fixed pure function and the live manager's own real
behavior now agree byte-for-byte, for both an ip-configured anchor and a
role-only one -- the property this fix exists to guarantee for any future caller.
`tests/test_argus_identity_resolver.py`'s own pre-existing assertion (which had
encoded the OLD, broken formula as its expected value) updated to match the fix,
plus a new role-only-anchor case.
