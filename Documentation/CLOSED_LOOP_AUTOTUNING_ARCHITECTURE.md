# Closed-Loop Autotuning Architecture (Release 15)

Living dependency map for the closed-loop autotuning redesign — replaces the
human-gated Ollama sensitivity-tuning loop with a per-device statistical
closed loop. Updated as each sheet lands; this snapshot reflects Sheets
00–05, all shipped in Release 15 (v15.0.0, 9 commits), plus a 2026-09-15
follow-up pass closing most of that release's own honest gaps (see each
Sheet's own section below for what changed) — done in coordination with a
concurrent peer session (`home-ids-dc`) running the full existing test
suite against the shipped v15.0.0 state, to avoid two sessions editing the
same live production files at once.

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

**Honest gaps — CLOSED (2026-09-15 follow-up)**: `risk` is now scored via a
one-cycle-LAGGED attack score (`IngestDaemon._last_risk_score`, fed from the
PREVIOUS cycle's already-computed decision, since scoring it live would
still force the same circular dependency) — a ~poll-interval-seconds lag,
documented, not silently approximated. Beta metrics (`nxdomain_ratio`/
`blocked_ratio`) now use the REAL per-cycle event count as `trials`
(`dns_features["total"]` — `extractors/dns_features.py`'s `compute()`
already exposed this; the original claim that it didn't was simply wrong,
found on re-check) instead of a fixed `1.0`, skipped outright when a
window has zero events.

**Real bug found and fixed along the way, not just an honest gap**: wiring
real `trials` values exposed that Beta-metric scoring was silently
completely broken — `score_metric(..., "beta", ...)` crashed with a
`TypeError` on every call (a 1-arg fit lambda invoked with the 2-element
`(ratio, trials)` observation_args), swallowed by `daemon.py`'s per-device
try/except, which discarded that WHOLE cycle's gaussian/poisson/markov
evidence too, not just beta's, every cycle any device had DNS ratio data.
Root cause: `score_metric`/`BOCPDTracker.observe()` share one
`observation_args` tuple between the fit function and `model.update()`,
but `BetaBaseline.update()`'s own tested contract is `(successes, trials)`
while `.surprise()`/`.predictive_density()` operate on the ratio scale —
nothing enforced that split before. Fixed in `_fit_fn_for()`/the new
`_surprise_args_for()` helper (`v13/baseline/engine.py`), not by changing
either of `bayesian.py`'s own already-tested method signatures. Caught
because this fix's own new tests exercised `score_metric` with
`model_kind="beta"`/`"poisson"` for the first time — previously only
`"gaussian"` had ever been covered at the orchestration-layer test level.

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

**File:** `src/v13/ops/backtest_job.py`. Wired into
`config.yaml`'s `scheduled_jobs.scheduler.backtest_job` (2026-09-15
follow-up), nightly at 3:30am — clear of `autotune_schedule_cron` (3am) and
`live_prune` (3:15am), its two nearest neighbors in that file.

`run_golden_set()` runs `tests/test_real_world_alert_regression.py` as a
**subprocess**, deliberately not refactored into an importable library (the
plan's original wording) — that file encodes real production-incident
reproductions; a rushed internal refactor risked silently corrupting one.
`run_synthetic_sweep()` runs Sheet 01 across a device sample, gracefully
degradable by `max_devices` under resource pressure (coverage always
recorded as reduced, never silently equated with a full sweep).
`run_backtest()` persists to `backtest_runs` — the audit trail and Sheet
03a's actual gating input.

**Honest gap — CLOSED (2026-09-15 follow-up)**: `drift_result_json` is no
longer a placeholder. `v13.autotune.engine.compute_drift_result()` flags a
tunable parameter whose PROMOTED changes (per device, or globally for a
device-independent change) trend strictly, monotonically toward
"everything looks more benign" (`_LESS_SENSITIVE_DIRECTION`) across at
least 3 promotions within a 7-day lookback, with no `regime_change`
evidence for that device in the same window to explain it. Deliberately
NOT folded into `overall_pass` — a real, considered scope limit: drift is a
slower-moving, operator-review signal, not a fast correctness gate the way
the golden-set/synthetic checks are. Logged at `WARNING` by
`backtest_job.py`'s own `main()` when detected.

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

**Honest gap, the big one — PARTIALLY CLOSED (2026-09-15 follow-up)**:
`bocpd_hazard_rate` is now genuinely live: `BaselineEngine.__init__` owns an
`AutotuneEngine(store)` and `_load_tracker()` reads the per-device promoted
value (falling back to the original `_DEFAULT_HAZARD_RATE` constant) on
every tracker cache-miss — inert by construction until a real promotion
exists, verified live in `tests/test_v13_baseline_engine.py` (a promoted
value reaches the real `BOCPDTracker.hazard_rate`, not just the audit
trail). HONEST LIMITATION of this specific wiring: a value promoted AFTER a
device's tracker is already warm in a given process does not take effect
until that tracker is reconstructed (process restart, or the in-memory
cache key evicted) — live cache invalidation on promotion is real,
separate follow-up.

The other three allowlisted parameters (`reputation_tier_suspicious_floor`,
`reputation_tier_high_floor`, `hard_stop_candidate_sensitivity`) are NOT
yet live-wired — genuinely harder surgery than `bocpd_hazard_rate` was,
for a structural reason found while scoping it: `decision/engine.py` never
computes reputation TIER itself (it only reads `rep.tier`, an int already
decided by `intelligence/reputation/classifier.py`'s `classify()`), and
`classify()` is called from exactly ONE shared site,
`core/pipeline.py:1549` — v-current's own live file, used for BOTH engines
(the `engine: v13`/`v_current` switch only decides which DECISION engine
consumes the same `rep_vector`, not which reputation classification ran).
Wiring these three safely means touching `pipeline.py` itself (behind its
own `self.config.get("engine", "v13") == "v13"` branch, the same one that
already exists a few lines below at the `v13_live_engine.evaluate()` call
site) — real, deeper follow-up, deliberately not rushed into the same pass
as the lower-risk, single-file `bocpd_hazard_rate` wiring. `hard_stop_
candidate_sensitivity` maps, with reasonable confidence but not certainty,
to `decision/engine.py`'s `confirmed_exploit` hard-stop rule's hardcoded
`min_confidence=0.9` (its bounds `[0.5, 0.99]` bracket that exact default) —
noted here for whoever picks this up next, not yet implemented.

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
first-pass heuristic (features_json string match, still real and
sufficient: every writer of these evidence types embeds device_id as a
plain string token).

**Honest gap — CLOSED (2026-09-15 follow-up)**: `sole_cause` is now a real
classification, not an always-empty placeholder. A decision qualifies only
when its COMPLETE supporting-evidence set (the full, uncapped list from
`raw_payload_json['_all_evidence_ids']` when the write-side edge cap
applied, else the `supports` edges themselves — `GraphStore.insert_decision()`
caps edges at a hardware-profile limit but always preserves the full list)
consists ENTIRELY of cross-device-correlation evidence naming the reset
device — i.e. resetting it would leave that decision with zero remaining
support. `reset_device()`'s DEFAULT `undo_scope='sole_cause_only'` now
actually auto-releases these (previously a no-op, since nothing was ever
classified `sole_cause`); `include_contributing` still additionally
releases the wider, merely-`contributing` set. Still a bounded heuristic
("does every piece of evidence trace to this device," not "would the
verdict itself have differed") — a genuinely deeper causal-graph
traversal remains further, separate follow-up.

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

## What's deliberately not done (updated 2026-09-15)

- **Live wiring of `reputation_tier_suspicious_floor`/`reputation_tier_high_floor`/
  `hard_stop_candidate_sensitivity` into `decision/engine.py`, and Sheet 03b's
  composite trust key into `cl_afpe/engine.py`.** `bocpd_hazard_rate` (Sheet
  03a) IS now live — see that Sheet's own section above. The remaining three
  need real surgery in `core/pipeline.py` (the single shared `classify()`
  call site both engines read from) / `cl_afpe/engine.py` specifically,
  deliberately not rushed into the same pass as the lower-risk fixes here —
  those two files are also both large, heavily-tested, live production
  paths a peer session was running the full test suite against concurrently
  while this pass ran, so touching them was deferred to avoid two sessions
  editing the same file at once, not skipped for difficulty alone.
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

Sheet 00's `risk` metric, Beta metrics' real event counts (plus the live
Beta-scoring bug that surfaced while wiring them), Sheet 00's
posterior-trajectory drift check, Sheet 04's `sole_cause` classification,
and Sheet 02's scheduler wiring are now CLOSED — see each Sheet's own
section above for what changed and why.

## Verification

~150 new automated checks across 8 new test files from the original
Release 15 pass (`test_v13_bayesian_baseline.py`, `test_v13_baseline_
engine.py`, `test_v13_synthetic_injection.py`, `test_v13_backtest_job.py`,
`test_v13_autotune_engine.py`, `test_v13_cl_afpe_composite_trust.py`,
`test_v13_autotune_reset.py`, `test_v13_ollama_advisory_demotion.py`), plus
~15 more added in the 2026-09-15 follow-up pass covering the beta/poisson
`score_metric` path (previously untested at the orchestration layer — how
the live Beta-scoring bug went unnoticed), the `bocpd_hazard_rate` live-
wiring, `compute_drift_result()`, and `sole_cause` classification
(including a deliberate negative case: a decision with independent evidence
of its own must NOT classify as `sole_cause`) — all passing, plus
re-verified against every existing test file each change touches. Several
real bugs were found and fixed via this testing both passes, not assumed
correct from the design alone — see each Sheet's own section/commit
message for specifics.
