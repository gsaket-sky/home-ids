# Per-Device / Per-Category Autotuning Plan

Status: **IMPLEMENTED (2026-09-16)** — every section below shipped: the schema
migration, the 3-tier read path, the Wilson-bound safe-threshold gate, the
trust-radius and retroactive-drift failsafes, small-category sweep augmentation,
and console visibility. See "Implementation notes" at the end of this doc for
what shipped, one real design bug found and fixed during testing, and what's
deliberately still deferred (the retroactive miss circuit-breaker). Originally
written in response to: "make it network agnostic and build failsafe mechanism,
and a safe threshold value for enough real data to back a promotion" — a
follow-on to the user asking how to make the autotuner per-device and
per-device-category instead of global-only, then "implement per device also on
top of category with safety gate."

## Bottom line up front

This is a smaller lift than it looks, because most of the hard infrastructure
**already exists and is already live** — it was built with this exact extension in
mind and just never finished being driven per-scope:

- `AutotuneEngine.get_active_value(parameter, device_id, default)` **already does a
  device-specific-or-global lookup** (`WHERE device_id=? OR (device_id IS NULL AND
  ? IS NULL)`) and is **already called with a real `device_id` from the live decision
  path** for 3 of the 4 tunable parameters (`argus/ops/live_engine.py`, confirmed by
  direct read — `reputation_tier_suspicious_floor`, `reputation_tier_high_floor`,
  `hard_stop_candidate_sensitivity`). `device_type` is already sitting right next to
  it in the same function call (`_v13_engine.evaluate(merged_v2, tuned_rep,
  device_type=device_type, ...)`).
- `threshold_history.device_id` is a real schema column, already there.
- `run_synthetic_sweep()` (`argus/ops/backtest_job.py`) **already runs the nightly
  synthetic-attack sweep per individual device** (`per_device[device_id] =
  sweep(store, device_id, ...)`) — the raw per-device signal already exists every
  night. It just gets pooled into one global rate today (`_propose_tuning_change()`
  flattens every device's results into one `by_class` dict, discarding which device
  each hit/miss came from).
- `compute_drift_result()` **already groups promoted changes by `device_id`** for its
  drift check — it was written expecting device-scoped rows to show up eventually.

So the real remaining work is narrower than "build per-device tuning from scratch":
it's (1) add a `device_type` tier alongside the existing `device_id` tier, (2) stop
discarding per-device sweep results before proposing a change, (3) add the sample-size
safety the user asked for — because right now, **even the existing global tuning has
no minimum-sample-size gate at all** (`_propose_tuning_change()`'s tighten/loosen
logic acts on a raw rate regardless of how few synthetic attacks backed it). That gap
gets worse, not better, once slicing by device/category shrinks the sample per
decision — so it has to be fixed as part of this, not deferred.

## Network-agnostic design

Per [[feedback_network_agnostic_design]]: "category" is **whatever `device_type`
values actually exist on this network, discovered dynamically** — never a hardcoded
list. This already matches an existing pattern in this exact codebase:
`state_guard.py`'s baseline peer-cohort transfer-learning already groups devices by
`device_type` and seeds new devices' baselines from same-category peers
(`🌱 [TRANSFER LEARNING]` — `peer_states = [s for s in self._states.values() if
s.device_type == dev_type ...]`). The autotune extension below is the same idea,
applied to threshold *values* instead of behavioral *baselines*, using the exact
same "whatever categories are real on this network" discovery — no code anywhere
should ever branch on a literal `"smart_tv"` or `"router"` string; it only ever
iterates `device_type` values actually present in `devices`/`ids_state.json`.

Real category distribution on `.94` right now (checked directly, not assumed):
`iot: 9, laptop: 8, phone: 8, smart_tv: 7, router: 4, unknown: 2, tablet: 2,
server: 2, printer: 1, gaming_console: 1, nas: 1, dns_server: 1`. Four categories
have exactly **one** device. This is exactly why the sample-size design below can't
assume "more devices = more samples" — several real categories structurally can't
get more than one device's worth of sweep data per night unless the sweep itself is
repeated.

## 1. Schema: add a `device_type` tier

`ALTER TABLE threshold_history ADD COLUMN device_type TEXT` (nullable, sibling to
the existing `device_id` column), applied via `_migrate_existing_db()`'s existing
"safe to run unconditionally, no-op if already there" pattern (SQLite has no
`ADD COLUMN IF NOT EXISTS`, so wrap in `try/except sqlite3.OperationalError` matching
that function's own idiom elsewhere). A row has **at most one** of `device_id` /
`device_type` set — a device-specific override, a category-wide override, or neither
(the global default), never two at once; enforced in `propose_change()`, not the
schema (SQLite `CHECK` constraints on "at most one of two nullable columns" are
awkward; a Python-level assertion is clearer and this file already validates
everything else in Python).

## 2. Read path: 3-tier fallback

`AutotuneEngine.get_active_value()` gains a `device_type` parameter and tries, in
order: **device-specific → category-specific → global → caller's `default`**. One
extra indexed SELECT in the worst case (device-specific miss), still cheap — this
mirrors the exact fallback shape `_resolve_hostname()`-style code and the baseline
peer-cohort code already use elsewhere in this codebase (most specific known thing
first, generic default last), not a new pattern.

`live_engine.py`'s three existing call sites pass `device_type` too (it's already a
local variable right there) — no new plumbing needed to get the value to the call
site, just widening the existing calls by one argument.

## 3. Propose path: per-scope slicing with a real safety floor

### 3a. Stop discarding per-device results

`_propose_tuning_change()` currently does:
```python
for device_result in synthetic.get("per_device", {}).values():
    for cls, r in device_result.get("attack_results", {}).items():
        by_class.setdefault(cls, []).append(bool(r["detected"]))
```
— flattening away which device each result came from. The fix keeps the device_id
alongside each hit, then groups three ways per class: **globally** (existing
behavior, unchanged), **by device_id**, and **by device_type** (via a
`device_id -> device_type` lookup, same `devices` table / StateManager read
`autonomy_api.py`'s `_resolve_hostname()` already does this session). Global tuning
keeps working exactly as today — this is additive, not a replacement.

### 3b. The safe-threshold value: asymmetric, sample-size-aware

The existing global logic is already asymmetric on purpose, and that asymmetry is
exactly right — keep it, just add the missing sample-size floor:

- **Tightening** (a class detection rate looks weak) already fires on *any* miss,
  immediately, no waiting — "fails safe toward more detection." This needs **no
  minimum sample size** at any scope: a single confirmed miss for one device is
  itself real information worth tightening on, and under-reacting to a miss is the
  actually-dangerous failure mode, not over-reacting.
- **Loosening** (trusting a scope is safe to relax) is where a real floor is needed,
  and where the current code has a genuine, unguarded gap even at global scope
  today — a rate of 1.0 from 2 synthetic runs currently counts exactly the same as
  1.0 from 200.

**Recommended concrete gate** (flagged, matching this file's own existing
"first-pass, not-yet-empirically-tuned constant" honesty convention —
`_DEFAULT_ATTACK_FLOOR`/`_MIN_PROMOTIONS_FOR_TREND` are both already labeled this
way, this is the same kind of number):
- `_MIN_TRIALS_FOR_LOOSENING = 20` real per-class trials within the scope (device or
  category) being considered, **before a loosening proposal is even computed** for
  that scope — below this, the scope is left alone (inherits its parent tier's
  value; a category with too few trials falls back to the global rate, a device
  with too few falls back to its category's).
- The decision statistic itself is **not the raw rate** — it's the **Wilson score
  interval's lower bound** at 95% confidence, computed from `(hits, n)`. This is the
  textbook-correct way to avoid trusting a small-sample rate at face value: at
  n=20/20 (100% raw), the Wilson lower bound is ≈0.836; at n=100/100 it's ≈0.963 —
  the SAME raw rate produces a stricter, more honest bar for a scope with fewer
  samples, rather than a hard cutoff that either lets small samples in fully or
  blocks them entirely.
- Loosen only if the Wilson lower bound is `>= _TUNE_LOOSEN_CEILING` (reuse the
  existing 1.0 constant as the bound the lower-bound-adjusted rate must clear, not
  the raw rate) **and** `compute_drift_result()` shows no unexplained drift for that
  same scope **and**, for a category/device-scoped proposal specifically, the
  resulting value would not diverge from its parent tier's current value by more
  than `2 * max_step` (the new trust-radius cap, §4).

**Getting to 20 trials for a 1-device category**: rerun the synthetic sweep multiple
times against the same device within one nightly job (`sweep()` is already callable
repeatedly per device — synthetic attacks are synthetic, not limited by real
traffic), capped at e.g. 5 repetitions per device per class to bound nightly runtime.
A 1-device category with 5 repetitions still only reaches n=5, correctly staying
below the loosening floor and inheriting global — that's the honest outcome for a
category the network genuinely doesn't have enough of to specialize a threshold for,
not a bug to work around.

## 4. Failsafe mechanisms

Four layers, three of which extend machinery that already exists rather than
inventing new machinery:

1. **Canary + confirming backtest** (already exists, `promote_change()`) — a
   device/category-scoped proposal goes through the exact same canary-then-confirm
   lifecycle as a global one; no shortcut for scoped changes.
2. **Drift detection** (already exists, `compute_drift_result()` already groups by
   `device_id`) — extend the grouping to also key by `device_type`, so a category
   quietly trending less-sensitive over several promotions gets flagged the same way
   a single device already does.
3. **NEW: trust-radius cap** — a device-scoped value may never diverge from its
   category's current value, and a category-scoped value may never diverge from the
   global value, by more than `2 * max_step` (per parameter, from the existing
   `TUNABLE_PARAMETERS` bounds) in the less-sensitive direction. This is the direct
   guard against a statistical fluke (or a mis-classified `device_type`) pushing one
   scope's threshold to an extreme the rest of the network never validated. Tightening
   beyond the parent tier is *not* capped this way — becoming more cautious than the
   network-wide default is always safe to do freely, symmetric with point 3a's
   "tightening needs no sample floor" reasoning.
4. **NEW: retroactive miss circuit breaker** — nightly, for every currently-promoted
   device/category-scoped override, check whether any real (non-synthetic) confirmed
   threat in the last N days for a device in that exact scope would have been
   suppressed under the override's looser value but was correctly caught under its
   parent tier's value. Any such case **immediately rolls back that specific scoped
   override** (reusing `rollback_change()`, already idempotent and already the
   correct primitive) and logs it loudly — a real incident overrides an entire
   night's worth of synthetic confidence, no exceptions, no waiting for the next
   scheduled backtest cycle.

## 5. Console visibility

This session's earlier work already built the exact UI hook this needs: the
Autonomy tab's new "Per-device status" panel (`/api/autonomy/devices`) currently
shows composite-trust data per device with an explicit note that autotuner is
global-only. Once this plan ships, that note becomes wrong and needs updating —
add an `autotuner` array to each device's entry (own device-scoped changes) and a
parallel `by_category` breakdown alongside `devices` in the response, using the
same `direction`/`status` serialization `_serialize_threshold_history()` already
has. No new UI paradigm needed, just wiring real data into a panel structure that
already exists for this purpose.

## Sequencing

1. Schema: `device_type` column + migration.
2. `get_active_value()` 3-tier read path (safe on its own — reads only, nothing to
   propose yet, so this can ship and sit inert before anything writes a scoped row).
3. Wilson-lower-bound helper + `_MIN_TRIALS_FOR_LOOSENING` gate, applied to the
   **existing global** proposal first (closes the real, existing gap on its own,
   independently testable, no scope-slicing needed yet).
4. Per-device/per-category slicing of `run_synthetic_sweep()`'s results + repeated-
   sweep-for-small-scopes.
5. Trust-radius cap + retroactive miss circuit breaker.
6. `compute_drift_result()` device_type grouping.
7. Console: extend the per-device Autonomy panel + `by_category` view.

Each step is independently shippable and testable against this codebase's existing
direct-call test conventions (`test_argus_decision_engine.py`-style fixtures,
real temp SQLite, no mocking the store) — no step requires the later ones to be
useful or correct on its own.

## Non-goals

- Not touching `bocpd_hazard_rate` (confirmed zero live consumer on `.94` today,
  per `backtest_job.py`'s own existing comment — out of scope here, unrelated to
  per-device/category work).
- Not inventing a new synthetic-attack generator with device-category-aware
  behavior — the existing `sweep()` already runs meaningfully per device; this
  plan only changes how its OWN existing per-device results get aggregated and
  gated, not what it simulates.
- Not proposing individual-device tuning as the first deliverable — category-level
  is the correct first tier (more devices per slice than any single device, matches
  the existing baseline peer-cohort precedent exactly); device-level naturally falls
  out of the same code path once category-level works, but starts even further
  behind on sample count and should prove out on real data before being trusted at
  all, exactly per the phased big-picture point the user's own question raised.

## Implementation notes (2026-09-16)

Shipped, in the sequence above: `threshold_history.device_type` schema column +
migration; `AutotuneEngine.get_active_value()`'s 3-tier device → category →
global fallback; `wilson_lower_bound()` + the `_MIN_TRIALS_FOR_LOOSENING`/
`_TUNE_LOOSEN_WILSON_FLOOR` safe-threshold gate (applied to the pre-existing
global proposal too, closing that real, previously-unguarded gap); the
trust-radius cap; `compute_drift_result()`'s category grouping;
`augment_small_category_sweeps()`'s repeat-sweep augmentation for small
categories; `_propose_scoped_tuning_changes()` (category + device proposals,
layered on top of the existing global one, never replacing it); and the console's
new "Per-device status"/"Per-category autotuner status" panels.

**A real design bug found and fixed while writing tests, not shipped
untested**: `propose_change()`'s original "reject if both device_id and
device_type are given" validation was wrong. A device-scoped proposal's
old_value/trust-radius lookup genuinely needs to know that device's category to
resolve the correct PARENT tier — without it, `get_active_value()` skips
straight from the device tier to global, silently ignoring an already-tuned
category as if it didn't exist. Fixed by redefining the semantics: `device_id`
alone determines which scope a proposal WRITES to; `device_type`, when also
passed alongside it, is a parent-resolution HINT only, never written to the
row. `backtest_job.py`'s own device-scope proposal call was passing `device_id`
without this hint until the same fix — a genuine, real bug this session's own
test coverage caught before it shipped, not a hypothetical.

**UPDATE (same day, follow-on request): the retroactive circuit-breaker is now
also shipped.** `check_retroactive_misses_and_rollback()` (`backtest_job.py`):
for every currently-active loosened device/category override, finds real
`suricata_signature_match` evidence whose confidence falls in the band
`[parent_value, scope_value)` — would have cleared the PARENT tier's stricter
hard-stop bar, doesn't clear this scope's own looser one — for a device in
that scope. Cross-references against `decisions.raw_payload_json`'s
`fp_verdict.verdict == "CONFIRMED_THREAT"` (the SAME ground truth
`overview_api.py`'s `fp_confirmed_threats` tile already uses, not a new
definition invented here) within `_HARD_STOP_FRESHNESS_SECONDS` of the
evidence. Any hit rolls back that exact scoped override immediately, in the
same pass — no canary, no confirming backtest, no operator gate, per the
user's own explicit choice ("a hit should trigger an immediate autonomous
rollback"), since this is undoing an override real evidence already proved
wrong, not introducing a new guess. Wired into `run_backtest()` independently
of `overall_pass` (a real confirmed miss is worth rolling back even on a night
the synthetic backtest itself failed for an unrelated reason), runs before any
new proposal/promotion that same cycle. 7 new tests, all against real graph
fixtures (real evidence rows, real decision rows with real `raw_payload_json`)
— happy path, no-evidence, wrong-verdict, outside-freshness-window, tightened-
scope-never-checked, device-scoped-too, and `run_backtest()`'s own wiring.

**Testing**: 60+ new/updated checks across `test_argus_autotune_engine.py`,
`test_argus_backtest_job.py`, `test_argus_graph_store.py` (migration
idempotency), and `test_autonomy_api.py`, plus a full re-run of every
pre-existing test touching `get_active_value()`/`propose_change()`
(`test_argus_baseline_engine.py`, `test_argus_live_engine.py`) confirming zero
behavior change for every caller that predates this plan. All pass.
