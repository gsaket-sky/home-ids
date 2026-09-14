# Closed-Loop Autotuning Architecture (Release 15)

Living dependency map for the closed-loop autotuning redesign — replaces the
human-gated Ollama sensitivity-tuning loop with a per-device statistical
closed loop. Updated as each sheet lands; this snapshot reflects Sheets
00–05, all shipped in Release 15 (v15.0.0, 9 commits).

## Why this exists

The old loop was: `detection → Ollama interpretation → human Telegram tap →
sensitivity change`. Ollama itself was never in the real-time *detection*
path (`v13/decision/engine.py` is and always was 100% deterministic) — but
it *was* the sole mechanism for post-hoc sensitivity tuning, gated behind a
human approval tap for the ambiguous (IP-only) case, and fully autonomous
for the unambiguous (has-a-domain / confirmed-malicious) cases. That
autonomous half was itself a real risk: an LLM's own independent judgment
directly writing to `fp_engine`'s trust cache and confirmed-intel store,
with no backtest, no versioning, no rollback.

Release 15 replaces this with a fully deterministic, versioned, backtest-
gated closed loop. Ollama is kept (per explicit product decision) but
demoted to narration only — it cannot influence any real decision anymore.

## Architecture invariant

Three processes, kept structurally separate, communicating only through the
evidence graph and versioned config — never a shortcut:

```
Evidence generation  →  Evidence Graph (SQLite)  →  Decision-making
                              ↓
                    Learning & Tuning (reads only,
                    writes versioned params)
```

- **Evidence generation** (Sheet 00) only ever *writes* Evidence rows.
- **Decision-making** (`v13/decision/engine.py`, untouched by this release)
  only ever *reads* a fresh per-cycle window.
- **Learning & tuning** (Sheets 01–04) only ever adjusts versioned
  parameters/trust state, gated by Sheet 02's backtest — never evidence or
  decisions directly.

No new evidence type this release introduces can ever, by itself, supply
the second independent source a HIGH verdict requires — see
`hypotheses/independence.py`'s `NON_ATTACK_FAMILIES` additions below.

## Sheet 00 — Bayesian/BOCPD/Markov baseline engine

**Files:** `src/v13/baseline/bayesian.py` (pure math), `src/v13/baseline/engine.py`
(GraphStore orchestration), wired into `src/v13/ingest/daemon.py`.

**Replaces:** `core/state.py`'s `EWMABaseline` (point-estimate, no
uncertainty) and `extractors/dns_features.py`'s static `_MARKOV_TRANSITIONS`
table — for v13's path only; v-current's own EWMABaseline/static table are
untouched (still live on `.94`, not yet safe to remove — see "What's
deliberately not done" below).

**Four conjugate model families**, each with a real posterior, not just a
point estimate:
- `GaussianBaseline` (Normal-Inverse-Gamma) — query_rate, entropy_avg,
  unique_domains, outbound_bytes.
- `BetaBaseline` (Beta-Binomial) — nxdomain_ratio, blocked_ratio.
- `PoissonBaseline` (Gamma-Poisson) — dga_hits, honeypot_touches.
- `MarkovBaseline` (Dirichlet-Categorical, order-1 with automatic order-2
  fallback per-context) — the cross-detector activity-state transition
  model (`derive_activity_state()`), replacing `_determine_killchain_phase()`'s
  first-match-wins threshold cascade with a state derived from the real
  evidence_type rows present each cycle.

**BOCPD** (`BOCPDTracker`) wraps any of the above in a run-length posterior
for changepoint detection (firmware/OS-update accommodation). Two real
instabilities found and fixed via this module's own tests before landing:
1. A flat-prior fresh hypothesis let ordinary noise out-compete a
   well-established one — fixed with `weaken_gaussian`/`weaken_beta`/
   `weaken_poisson` (anchor at the current estimate, not a blind reset).
2. Neither a single-cycle `cp_mass` check nor a consecutive-streak check
   reliably separates noise from a real shift (the mixture-model mechanics
   don't support it) — fixed with a two-stage design: freeze the pre-spike
   model as a fixed reference, require several subsequent observations to
   average real surprise against that unchanging anchor.

**New evidence types**, all registered `NON_ATTACK_FAMILIES` in
`hypotheses/independence.py` (corroborating-only, structurally, since
`decision/engine.py` re-derives family from `evidence_type` centrally —
verified via direct read, not assumed):
- `baseline_deviation` (family `baseline_deviation`)
- `regime_change` (family `regime_change`)
- `markov_activity_surprise` (family `sequence_dynamics`)

**No-learning-during-incident gate**: `BaselineEngine.is_learning_paused()`
— a device at SUSPICIOUS/HIGH/CRITICAL, or within a cooldown window after
returning to a non-incident state, gets no baseline/regime/Markov update
that cycle. Uses a plain elapsed-time check against the latest `decisions`
row, since `compute_decision()` only persists on verdict change.

**Schema additions** (`v13/graph/schema.sql`, migrated for existing DBs too
via `GraphStore._migrate_existing_db()`): `device_baselines`,
`population_priors`, `cl_afpe_trust`, `threshold_history`,
`baseline_snapshots`, `backtest_runs`.

**Honest gaps**: `risk` (the fifth planned Gaussian metric) isn't scored —
it depends on the same cycle's decision, computed after this runs. Beta
metrics use a fixed `trials=1.0` per cycle, not the real event count
(`dns_features` doesn't expose it).

## Sheet 01 — Synthetic anomaly injection

**Files:** `src/v13/synthetic/attacks.py`, `src/v13/synthetic/injector.py`.

Seven attack-class generators (port_scan, dga_dns_tunnel, c2_beaconing,
exfiltration, credential_stuffing, lateral_movement, honeypot_touch), each
varying magnitude/timing/variant across calls (signature diversity, against
an autotuner that could otherwise overfit to one canned shape) plus
`benign_drift()` for false-positive-resistance checks.

`injector.clone_device_state()` copies one device's real recent state into
an isolated in-memory `GraphStore` (never the live db); `inject_and_evaluate()`
runs a generated attack through the real `DecisionEngine`. `sweep()` is the
per-device unit Sheet 02 calls.

## Sheet 02 — Scheduled nightly backtest

**File:** `src/v13/ops/backtest_job.py`. Not yet wired into
`scripts/scheduler.py`/`config.yaml`'s `scheduled_jobs` — real follow-up.

`run_golden_set()` runs `tests/test_real_world_alert_regression.py` as a
**subprocess**, deliberately not refactored into an importable library (the
plan's original wording) — that file encodes real production-incident
reproductions; a rushed internal refactor risked silently corrupting one.
`run_synthetic_sweep()` runs Sheet 01 across a device sample, gracefully
degradable by `max_devices` under resource pressure (coverage always
recorded as reduced, never silently equated with a full sweep).
`run_backtest()` persists to `backtest_runs` — the audit trail and Sheet
03a's actual gating input.

**Honest gap**: `drift_result_json` is a placeholder — the posterior-
trajectory drift check is real, separate future work.

## Sheet 03a — Autotuner infrastructure

**File:** `src/v13/autotune/engine.py`.

`TUNABLE_PARAMETERS` is a closed allowlist (reputation-tier floors, BOCPD
hazard rate, hard-stop-candidate sensitivity) with per-parameter
min/max/max_step bounds — there is no code path by which this module can
touch the independent-sources minimum, family-collapse rules, or hard-stop
registry membership; those stay code-level invariants.

`propose_change()` refuses to even create a proposal without a passing
`backtest_run_id` (gated at proposal time, not just promotion), clamps to
bounded steps, and enforces a per-parameter cooldown. `promote_change()`
requires both the canary window elapsed AND a second, confirming backtest
pass. `rollback_change()` takes effect immediately and is idempotent.
`rollback_all_unconfirmed_for_backtest()` is the actual auto-rollback
consequence of a nightly regression.

**Honest gap, the big one**: not yet wired to make `decision/engine.py`
actually *read* these promoted values — that engine has very few
externally-tunable constants today (confirmed via direct grep:
`_HARD_STOP_FRESHNESS_SECONDS`, `_PARTIAL_SUPPORT_FAMILIES`, neither on the
allowlist). Live wiring is real, separate, deeper follow-up work.

## Sheet 03b — CL-AFPE composite trust key

**File:** `src/v13/cl_afpe/composite_trust.py`. **Additive**, not a
replacement — `v13/cl_afpe/engine.py`'s `ClAfpeEngine` already scopes trust
by (device, destination_id, hypothesis) via `is_trust_cached()`; this adds
the remaining three dimensions (behavior_fingerprint, destination_class,
evidence_family, regime) as a separate, more conservative gate. Not yet
wired into `ClAfpeEngine.evaluate()` — intended future integration is AND,
not OR, so this can only tighten what exists, never loosen it.

**The actual anti-gaming fix**: trust for a tuple only rises once at least
2 distinct evidence families have each independently corroborated it past
a floor — verified live in the test: 20 repeated corroborations from one
family pushes that family's own trust near 1.0, but `permits_suppression()`
stays False throughout. Trust decays without reinforcement; `regime_id` is
part of the key so a firmware/OS-update-driven regime change doesn't
silently inherit stale trust.

## Sheet 04 — Snapshots and reset/undo

**File:** `src/v13/autotune/reset.py`. Operator-invoked only — never called
autonomously by any closed loop in this release.

`take_snapshot()` captures a device's `device_baselines`, active promoted
`threshold_history`, and `cl_afpe_trust` rows. `reset_device()` restores
them and rolls back thresholds promoted after the snapshot.
`compute_reset_blast_radius()` finds decisions/containment_actions on
*other* devices via the `cross_device_correlation` evidence family — a
first-pass heuristic (features_json string match), everything classified
`contributing` (flagged for review), never auto-classified `sole_cause`
(that needs a real causal-graph traversal — separate future work).

## Sheet 05 — Ollama demoted to read-only advisory

**Files:** `src/scripts/ollama_soc.py` (`OLLAMA_HAS_DECISION_AUTHORITY =
False`), `src/mitigation/alerts.py` (the `approve_tune` Telegram callback
retired).

All three of Ollama's real decision-triggering call sites
(`fp_engine.mark_false_positive`, the `pending_tune_approvals` Telegram-
button queue, `fp_engine.record_confirmed_threat`/`_apply_sigma_shift`
TUNE_UP) are gated behind a single module constant — deliberately not a
rewrite of the surrounding calibration/streak/multi-device-guard logic,
which stays fully intact and keeps informing the narrative report text.
Real attack detection was never dependent on Ollama; this only removes
Ollama's own independent judgment from taking real action.

## What's deliberately not done in Release 15

- **Live wiring of Sheets 03a/03b into `decision/engine.py`/`cl_afpe/engine.py`.**
  The autotuner and composite trust key are complete, tested infrastructure
  that doesn't yet affect real decisions. Real, separate follow-up.
- **Phase 6 (soak + cutover).** Requires real elapsed time running in
  shadow on deployed infrastructure, plus explicit user sign-off before
  making the new loop authoritative on the live `.94` box and retiring
  `fp_engine.py`'s sigma-shift logic. Not something a single development
  session can complete regardless of authorization.
- **Removing v-current's EWMABaseline / static `_MARKOV_TRANSITIONS` table.**
  Still live and load-bearing on `.94` until Phase 6 cutover actually
  happens — removing them now would break the live system.
- **Broad dead-code removal.** No large, *safe* target was found this pass
  (v-current must stay intact pre-cutover; other candidates flagged in
  memory as "largely vestigial" — e.g. `v13/compare/divergence_log.py` —
  were not independently re-verified this session and are not deleted on
  an unconfirmed claim).
- **Sheet 00's `risk` metric, Beta metrics' real event counts, Sheet 00's
  posterior-trajectory drift check, Sheet 04's `sole_cause` classification,
  Sheet 02's scheduler wiring.** Each individually noted as an honest gap
  in its own module docstring, not silently absent.

## Verification

~150 new automated checks across 8 new test files
(`test_v13_bayesian_baseline.py`, `test_v13_baseline_engine.py`,
`test_v13_synthetic_injection.py`, `test_v13_backtest_job.py`,
`test_v13_autotune_engine.py`, `test_v13_cl_afpe_composite_trust.py`,
`test_v13_autotune_reset.py`, `test_v13_ollama_advisory_demotion.py`), all
passing, plus verified against every existing test file each change
touches. Several real bugs were found and fixed via this testing, not
assumed correct from the design alone — see each Sheet's own commit
message for specifics.
