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
| 7 | `peer_deviation_multiplier` | no | `ops/live_engine.py:750-751,805` (hardcoded `_PEER_DEVIATION_MULTIPLIER=3.0`) | none | n/a (unwired) |
| 8 | `peer_deviation_min_absolute_count` | no | `ops/live_engine.py:751,801` (hardcoded `=5`) | none | n/a (unwired) |
| 9 | `combined_uncertain_threshold` | no | `intelligence/fp_engine.py:453-455,882` (config key, default 0.55) | none | n/a (unwired) |
| 10 | `familiarity_trust_bar` | no | `hypotheses/engine.py:746,765` (hardcoded `FAMILIARITY_TRUST_BAR=0.6`) | none | n/a (unwired) |
| 11 | `trust_cache_ttl_seconds` | no | `cl_afpe/engine.py:148,306` (hardcoded `14*24*3600`) | none | n/a (unwired) |
| 12 | `reputation_propagation_ttl_seconds` | no | `ops/live_engine.py:145,657` (hardcoded `86400`) | none | n/a (unwired) |
| 13 | `pool_gaussian_kappa` | no | `ops/population_prior_builder.py:107,204-227` (hardcoded `5.0`) | none | n/a (unwired) |
| 14 | `pool_gaussian_alpha` | no | `ops/population_prior_builder.py:108,204-227` (hardcoded `10.0`) | none | n/a (unwired) |
| 15 | `pool_beta_total` | no | `ops/population_prior_builder.py:109,204-227` (hardcoded `10.0`) | none | n/a (unwired) |
| 16 | `pool_poisson_rate` | no | `ops/population_prior_builder.py:110,204-227` (hardcoded `5.0`) | none | n/a (unwired) |

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
- Baseline/BOCPD: `test_argus_baseline_engine.py`, `test_argus_bayesian_baseline.py`
- Population priors/cohorts: `test_argus_population_prior_builder.py`
- Live engine/decision path: `test_argus_live_engine.py`, `test_argus_decision_engine.py`, `test_argus_hypotheses_engine.py`
- CL-AFPE: `test_argus_cl_afpe.py`, `test_argus_cl_afpe_composite_trust.py`, `test_argus_cl_afpe_flip_monitor.py`, `test_argus_cl_afpe_ml_scoring.py`, `test_argus_live_cl_afpe_shadow.py`
- Identity: `test_argus_identity_resolver.py`, `test_argus_live_identity.py`, `test_identity_reconcile_dhcp_ja4_signal.py`, `test_identity_reconcile_pass.py`, `test_phase39_retroactive_identity_merge.py`, `test_phase64_device_identity_guard.py`
- Health/resource: `test_health_manager_state_machine.py`, `test_resource_pressure_modes.py`, `test_health_manager_healing_actions.py`, `test_health_manager_memory_diagnostics.py`
- Capture/disk: `test_phase23_fritzbox_capture.py`, `test_disk_budget_governor.py`
- Config/trust anchors: `test_argus_config_trust_anchors.py`
- Regression gate (run before/after any evidence-scoring or decision-path change): `test_real_world_alert_regression.py`

## 4. Arg-provenance sections (added as each subsystem is built)

### 4.1 Autotune native generator registry (Phases 1, 3, 4)
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
_Pending._

### 4.3 BOCPD rebuild-on-promotion (Phase 5)
_Pending._

### 4.4 Resource-aware autotune/shadow pause (Phase 6)
_Pending._

### 4.5 Shadow-evaluation sandbox (Phase 7)
_Pending._

### 4.6 Behavioral cohorts (Phase 8)
_Pending._

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

### 4.8 Zero-site bootstrap: `RouterAdapter` (Phase 12)
_Pending._

### 4.9 Known landmine, not yet fixed (tracked here until Phase 11 closes it)
`argus/identity/resolver.py`'s pure `_anchor_device_id()` uses a role-based hash
(`stable_device_id(f"anchor:{role}")`), different from the literal-IP hash
`live_manager.py`'s `LiveIdentityManager` actually uses in production
(`v13_stable_device_id(anchor.ip)`). `live_manager.py` already found and worked around
this discrepancy for its own call path; the pure function itself is still broken for
any other caller. Nothing in production calls the broken path today (confirmed via
grep at plan time), but Phase 7's shadow sandbox and Phase 10's discovery diff logic
are both candidates that could accidentally call `resolver.resolve_device_id()`
directly — Phase 11 fixes the source function before those exist.
