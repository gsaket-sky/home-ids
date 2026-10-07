"""
argus/autotune/engine.py -- Release 15 Sheet 03a: the closed-loop autotuner
(sensitivity/threshold tuning half -- CL-AFPE, the FP-suppression half,
stays its own independent loop, see cl_afpe_trust.py in this same package).

Owns *sensitivity/threshold tuning* only: bounded, cooldown-limited,
versioned parameter changes, shadow-canaried before promotion, gated by
Sheet 02's backtest. Never writes evidence or decisions directly -- only
ever adjusts versioned, audited parameters (Design Invariant, closed-loop
autotuning plan).

WHAT IT MAY NEVER TOUCH, enforced by construction, not convention: the
independent-sources minimum, family-collapse rules, `escalated_via_
persistence` never alone authorizing autonomous containment, and hard-stop
registry membership are code-level invariants in argus/decision/engine.py,
not config -- TUNABLE_PARAMETERS below is an explicit, closed allowlist
that never includes any of them, so there is no code path by which this
module could touch them even by a bounded step.

HONEST SCOPE NOTE: this builds the complete propose/canary/promote/rollback
INFRASTRUCTURE, versioned in threshold_history (Release 15 schema addition,
already migrated) and gated by backtest_runs. It is NOT yet wired to make
argus/decision/engine.py actually READ these promoted values at decision
time -- that engine currently has very few externally-tunable constants
(confirmed via direct grep before writing this: _HARD_STOP_FRESHNESS_SECONDS
and _PARTIAL_SUPPORT_FAMILIES are the only module-level ones, neither on
the allowlist below), so live wiring is real, separate follow-up work, not
bundled into this commit -- the same honest-gap pattern already used for
Sheet 00's `risk` metric and Sheet 02's scheduler wiring.
"""
import contextlib
import contextvars
import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple

from argus.graph.store import GraphStore

LOGGER = logging.getLogger("argus.autotune.engine")

# Shadow evaluation (argus/shadow/sandbox.py) substitutes ONE candidate value for
# the duration of one evaluate() call. It used to patch the class attribute
# AutotuneEngine.get_active_value, which every thread saw: an allowlist check on
# another thread (is_allowlisted -> _active_trust_edges ->
# get_active_value("trust_cache_ttl_seconds")) could read the canary value while a
# shadow call ran (runtime trace run 2, finding 4.4). A ContextVar is per thread
# (a new thread starts with an empty context), so only the shadow call itself sees
# the override.
_SHADOW_OVERRIDE: "contextvars.ContextVar[Optional[Tuple[str, float]]]" = contextvars.ContextVar(
    "autotune_shadow_override", default=None)


@contextlib.contextmanager
def shadow_override(parameter: str, value: float) -> Iterator[None]:
    """Within this block, on this thread only, get_active_value(parameter) returns
    `value` at every scope. Other threads keep reading the promoted value."""
    token = _SHADOW_OVERRIDE.set((parameter, value))
    try:
        yield
    finally:
        _SHADOW_OVERRIDE.reset(token)

# Explicit, closed allowlist -- the ONLY parameters this module may ever
# propose a change to. (name -> (min, max, max_step_per_change)). Adding a
# new tunable parameter means adding a row here, deliberately, not widening
# an existing bound.
#
# max_step_up/max_step_down (optional, both default to max_step when absent)
# let a parameter have a genuinely asymmetric per-proposal step instead of a
# single symmetric one -- added 2026-09-21 for the legacy/Sheet 03a
# reconciliation, where arp_sweep_unique_targets_threshold's source system
# (train_fp_classifier.py's ARP_SWEEP_RAISE_STEP=4.0 vs
# ARP_SWEEP_LOWER_STEP=1.0) already has a real, deliberate asymmetry: raising
# the threshold only ever happens off strong one-sided evidence (>=2 corrected
# false positives, zero confirmed threats) and is allowed the bigger jump;
# lowering it moves more cautiously. See _clamp_step()'s own comment for how
# the two bounds are chosen (by the arithmetic sign of the proposed step, not
# by _LESS_SENSITIVE_DIRECTION below).
TUNABLE_PARAMETERS: Dict[str, Dict[str, float]] = {
    "reputation_tier_suspicious_floor": {"min": 1.0, "max": 5.0, "max_step": 0.5},
    "reputation_tier_high_floor": {"min": 2.0, "max": 5.0, "max_step": 0.5},
    "bocpd_hazard_rate": {"min": 1.0 / 2000.0, "max": 1.0 / 100.0, "max_step": 1.0 / 500.0},
    "hard_stop_candidate_sensitivity": {"min": 0.5, "max": 0.99, "max_step": 0.05},
    # Bounds mirror train_fp_classifier.py's own ARP_SWEEP_MIN_THRESHOLD/
    # ARP_SWEEP_MAX_THRESHOLD/ARP_SWEEP_RAISE_STEP/ARP_SWEEP_LOWER_STEP.
    "arp_sweep_unique_targets_threshold": {
        "min": 4.0, "max": 40.0, "max_step_up": 4.0, "max_step_down": 1.0,
    },
    # Bounds mirror AUTOTUNE_ABSOLUTE_FLOOR (the min) and AUTOTUNE_SAFETY_MARGIN-scale
    # per-cycle movement (the step) from the same source file. Symmetric max_step is
    # fine here even though legacy's own rule only ever lowers this value -- nothing
    # stops a future human-approved raise, and propose_change() has no direction lock.
    "fp_combined_suppress_threshold": {"min": 0.60, "max": 1.0, "max_step": 0.05},
    # 2026-09-27 (Phase 3 of the autonomy-completion effort). Bounds/steps match the
    # plan doc's own Tier-2 matrix exactly.
    "peer_deviation_multiplier": {"min": 1.5, "max": 10.0, "max_step": 0.5},
    "peer_deviation_min_absolute_count": {"min": 2.0, "max": 20.0, "max_step": 1.0},
    "combined_uncertain_threshold": {"min": 0.30, "max": 0.80, "max_step": 0.05},
    "familiarity_trust_bar": {"min": 0.30, "max": 0.90, "max_step": 0.05},
    # 2026-09-27 (Phase 4 of the autonomy-completion effort, completes all 16
    # parameters). Bounds/steps match the plan doc's own Tier-3 matrix exactly
    # (TTLs in seconds, not days/hours -- this module's own scale for every other
    # time-based bound elsewhere in the codebase).
    "trust_cache_ttl_seconds": {"min": 86400.0, "max": 30 * 86400.0, "max_step": 86400.0},
    "reputation_propagation_ttl_seconds": {"min": 3600.0, "max": 7 * 86400.0, "max_step": 3600.0},
    "pool_gaussian_kappa": {"min": 1.0, "max": 20.0, "max_step": 1.0},
    "pool_gaussian_alpha": {"min": 1.0, "max": 50.0, "max_step": 1.0},
    "pool_beta_total": {"min": 1.0, "max": 50.0, "max_step": 1.0},
    "pool_poisson_rate": {"min": 1.0, "max": 20.0, "max_step": 1.0},
}

# First-pass, not-yet-empirically-tuned constants (this codebase's own
# established honesty framing).
_DEFAULT_CANARY_SECONDS = 6 * 3600.0  # shadow-apply for N cycles before promotion is eligible
_COOLDOWN_SECONDS = 3600.0  # minimum gap between proposals for the SAME parameter+device

# Sheet 02 follow-up (closes that module's own former honest gap: backtest_job.py's
# run_backtest() used to write drift_result_json as an empty {} placeholder) -- which
# direction of movement for each tunable parameter means "systematically LESS
# sensitive / everything starts looking more benign." +1 = an INCREASING value is
# the less-sensitive direction, -1 = DECREASING is. Kept next to TUNABLE_PARAMETERS
# (not derived from it) since "which direction is less sensitive" is a semantic fact
# about each parameter's real-world meaning, not something inferable from its bounds.
_LESS_SENSITIVE_DIRECTION: Dict[str, int] = {
    "reputation_tier_suspicious_floor": 1,   # higher floor -> harder for a destination to reach tier 4
    "reputation_tier_high_floor": 1,         # higher floor -> harder for a destination to reach tier 5
    "bocpd_hazard_rate": -1,                 # lower hazard -> assumes regimes last longer, slower to flag a real change
    "hard_stop_candidate_sensitivity": 1,    # higher bar -> requires more confidence to even be a hard-stop candidate
    "arp_sweep_unique_targets_threshold": 1,  # higher threshold -> more unique targets needed to flag a sweep
    "fp_combined_suppress_threshold": -1,     # lower threshold -> suppresses more, less sensitive to real threats
    "peer_deviation_multiplier": 1,          # higher multiplier -> harder for a device to look like a cohort outlier
    "peer_deviation_min_absolute_count": 1,  # higher floor -> harder to clear the "not just a trivial small-number swing" bar
    "combined_uncertain_threshold": -1,       # lower threshold -> more borderline alerts get the softer UNCERTAIN tag instead of full-severity LIKELY_REAL
    "familiarity_trust_bar": -1,              # higher bar -> harder for a device to be treated as "familiar", MORE suspicion generated (increasing is the MORE-sensitive direction here, unlike every other +1 parameter above)
    "trust_cache_ttl_seconds": 1,              # longer TTL -> an immunized destination stays trusted/suppressed longer, less sensitive to it re-offending
    "reputation_propagation_ttl_seconds": -1,  # longer TTL -> a cached suspicious-tier classification keeps propagating as corroborating evidence to OTHER devices longer, more sensitive (like familiarity_trust_bar, increasing is the MORE-sensitive direction)
    "pool_gaussian_kappa": 1,                  # higher prior pseudo-count -> the population prior dominates a device's own observations more, damping real per-device anomalies, less sensitive
    "pool_gaussian_alpha": 1,                  # same reasoning as pool_gaussian_kappa -- both are Normal-Gamma prior pseudo-counts
    "pool_beta_total": 1,                      # same reasoning -- Beta prior's total pseudo-count
    "pool_poisson_rate": 1,                    # same reasoning -- a stronger/higher assumed baseline rate makes a real elevated count look less anomalous, less sensitive
}
_MIN_PROMOTIONS_FOR_TREND = 3  # first-pass, not-yet-empirically-tuned (same honesty framing)
_DEFAULT_DRIFT_LOOKBACK_SECONDS = 7 * 86400.0

# 2026-09-16, per-device/category autotuning (Documentation/
# PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md): the safe-threshold value for trusting a
# LOOSENING proposal at any scope (device, category, or global) -- tightening
# needs no such floor (see propose_scoped_change()'s own docstring for why that
# asymmetry is deliberate, not an oversight). First-pass, not-yet-empirically-
# tuned constant, same honesty framing as _DEFAULT_ATTACK_FLOOR/
# _MIN_PROMOTIONS_FOR_TREND above.
_MIN_TRIALS_FOR_LOOSENING = 20
_WILSON_Z_95 = 1.959963984540054  # standard normal quantile for a 95% two-sided CI

# A scoped (device- or category-level) value may never diverge from its PARENT
# tier's current value by more than this many max_steps, in the less-sensitive
# direction -- the trust-radius failsafe. Guards against one statistical fluke
# (or a mis-classified device_type) pushing a single scope's threshold to an
# extreme the rest of the network never validated. Tightening beyond the parent
# tier is never capped -- becoming MORE cautious than the network-wide default
# is always safe, symmetric with the "tightening needs no sample floor" rule.
_TRUST_RADIUS_MAX_STEPS = 2.0


def wilson_lower_bound(hits: int, n: int, z: float = _WILSON_Z_95) -> float:
    """The lower bound of the Wilson score confidence interval for a binomial
    proportion (hits/n) -- the textbook-correct way to avoid trusting a small-
    sample rate at face value. At n=20/20 (100% raw) this is ~0.836; at
    n=100/100 it's ~0.963 -- the SAME raw rate produces a stricter, more honest
    bar for a scope backed by fewer samples, rather than either trusting a
    small sample fully or blocking it outright. Returns 0.0 for n<=0 (nothing
    to estimate from -- the caller's own _MIN_TRIALS_FOR_LOOSENING gate should
    already have excluded this case, this is defense-in-depth, not the
    intended gate)."""
    if n <= 0:
        return 0.0
    phat = hits / n
    denom = 1.0 + z * z / n
    center = phat + z * z / (2 * n)
    margin = z * ((phat * (1 - phat) / n + z * z / (4 * n * n)) ** 0.5)
    return max(0.0, (center - margin) / denom)


@dataclass
class ProposalResult:
    accepted: bool
    change_id: Optional[str] = None
    reason: str = ""


def _clamp_step(parameter: str, old_value: float, new_value: float) -> float:
    """Clamps by the ARITHMETIC SIGN of the proposed step (new_value > old_value
    uses max_step_up, new_value < old_value uses max_step_down) -- not by
    _LESS_SENSITIVE_DIRECTION, which is a separate semantic fact about which
    RAW DIRECTION counts as "less sensitive" for a given parameter and can
    point either way relative to the arithmetic sign. Both bounds default to
    the single symmetric max_step, so every pre-existing symmetric parameter
    is unaffected."""
    bounds = TUNABLE_PARAMETERS[parameter]
    max_step_up = bounds.get("max_step_up", bounds.get("max_step"))
    max_step_down = bounds.get("max_step_down", bounds.get("max_step"))
    step = new_value - old_value
    if step > max_step_up:
        new_value = old_value + max_step_up
    elif step < -max_step_down:
        new_value = old_value - max_step_down
    return max(bounds["min"], min(bounds["max"], new_value))


def _directional_step_bound(bounds: Dict[str, float], direction: int) -> float:
    """The max-step bound in the given LESS-SENSITIVE-direction sense (+1/-1,
    matching _LESS_SENSITIVE_DIRECTION) -- distinct from _clamp_step()'s own
    arithmetic-sign-based lookup above. Used by the trust-radius check, which
    measures divergence specifically in the less-sensitive direction. Falls
    back to the single symmetric max_step for every parameter that has one."""
    key = "max_step_up" if direction > 0 else "max_step_down"
    return bounds.get(key, bounds.get("max_step"))


class AutotuneEngine:
    def __init__(self, store: GraphStore):
        self.store = store
        # 2026-09-27 (Phase 5 of the autonomy-completion effort): promotion-
        # notify subscribers -- mirrors src/config.py's own LiveConfig
        # (_notify_cbs/set_notify()/_fire_notify(), the exact pattern
        # core/pipeline.py's own _on_config_reload already consumes). Closes
        # baseline/engine.py's own documented "HONEST LIMITATION": a promoted
        # bocpd_hazard_rate change previously had no way to reach an already-warm
        # BOCPDTracker until that tracker was next reconstructed on its own.
        self._notify_cbs: list = []

    def set_notify(self, cb) -> None:
        """Registers `cb` as an ADDITIONAL promotion/rollback subscriber -- does
        not replace any previously-registered callback, same multi-subscriber
        reasoning as LiveConfig.set_notify()'s own docstring."""
        self._notify_cbs.append(cb)

    def _fire_notify(self, parameter: str, device_id: Optional[str], device_type: Optional[str],
                       event: str) -> None:
        """Calls every registered subscriber, isolated so one callback raising
        never prevents the others from running or blocks the promotion/rollback
        itself (the state change has already been committed by the time this
        fires -- a notify failure must never look like the promotion/rollback
        failed)."""
        for cb in self._notify_cbs:
            try:
                cb(parameter, device_id, device_type, event)
            except Exception:
                LOGGER.exception(
                    "Autotune promotion-notify callback raised for parameter=%r "
                    "device_id=%r device_type=%r event=%r, continuing with remaining subscribers",
                    parameter, device_id, device_type, event,
                )

    # ---------------------------------------------------------- reads

    def _promoted_value_at_scope(self, parameter: str, device_id: Optional[str],
                                    device_type: Optional[str]) -> Optional[float]:
        """One exact-scope lookup -- device-specific (device_id set, device_type
        NULL), category-specific (device_type set, device_id NULL), or global
        (both NULL). Never falls back on its own; get_active_value() below is
        what walks the tiers.

        BUGFIX (2026-09-20, identity-merge handover follow-up): the device
        tier used to match `device_id` literally -- a device-scoped
        threshold tuned BEFORE this device was merged into a richer
        canonical identity (see core/state_guard.py's merge_into_canonical())
        would silently become invisible after the merge, since the row is
        still stored under the orphan's old id and nothing ever re-pointed
        it. Mirrors get_evidence_for_device()/get_latest_decision_for_device()'s
        own resolve_merges convention: considers every id that ever resolved
        (directly or transitively) into this device's current canonical id,
        not just its literal current value."""
        if device_id is not None:
            candidate_ids = self.store._all_ids_resolving_to(
                self.store.resolve_canonical_device_id(device_id)
            )
            placeholders = ",".join("?" * len(candidate_ids))
            row = self.store._conn.execute(
                f"SELECT new_value FROM threshold_history WHERE parameter=? AND "
                f"device_id IN ({placeholders}) AND device_type IS NULL AND "
                f"promoted_at IS NOT NULL AND rolled_back_at IS NULL "
                f"ORDER BY promoted_at DESC LIMIT 1",
                [parameter, *candidate_ids],
            ).fetchone()
            return float(row["new_value"]) if row is not None else None
        row = self.store._conn.execute(
            "SELECT new_value FROM threshold_history WHERE parameter=? AND "
            "device_id IS NULL AND "
            "(device_type=? OR (device_type IS NULL AND ? IS NULL)) AND "
            "promoted_at IS NOT NULL AND rolled_back_at IS NULL "
            "ORDER BY promoted_at DESC LIMIT 1",
            (parameter, device_type, device_type),
        ).fetchone()
        return float(row["new_value"]) if row is not None else None

    def get_active_value(self, parameter: str, device_id: Optional[str] = None,
                            device_type: Optional[str] = None,
                            default: Optional[float] = None) -> Optional[float]:
        """The most recently PROMOTED (not merely proposed) value for
        `parameter`, walking a 3-tier fallback: device-specific -> category-
        specific -> global -> `default`. A promoted-but-later-rolled-back
        change does not count at any tier (rolled_back_at IS NULL is
        required), so a rollback takes effect for readers immediately, not
        just in the audit trail.

        2026-09-16 (per-device/category autotuning plan): device_type is new;
        every pre-existing caller that only ever passed device_id keeps
        working unchanged (device_type defaults to None, which simply skips
        the category tier and falls straight through device -> global, the
        exact original 2-tier behavior)."""
        override = _SHADOW_OVERRIDE.get()
        if override is not None and override[0] == parameter:
            return override[1]
        if device_id:
            value = self._promoted_value_at_scope(parameter, device_id, None)
            if value is not None:
                return value
        if device_type:
            value = self._promoted_value_at_scope(parameter, None, device_type)
            if value is not None:
                return value
        value = self._promoted_value_at_scope(parameter, None, None)
        return value if value is not None else default

    def _last_proposal_time(self, parameter: str, device_id: Optional[str],
                              device_type: Optional[str] = None) -> Optional[float]:
        """Cooldown lookup is an EXACT scope match, deliberately not a fallback --
        a pending device-scoped proposal's cooldown must never be confused with
        its category's own, separate cooldown clock.

        BUGFIX (2026-09-20, identity-merge handover follow-up): same
        merge-blindness gap as _promoted_value_at_scope() above -- a device's
        cooldown clock must keep ticking across an identity merge (it's the
        same physical device), not silently reset because its proposal
        history is still filed under an id that's since been merged away.
        `propose_change()` always passes the ALREADY-RESOLVED canonical
        device_id here (see its own resolve-at-entry fix), so this call
        itself always uses row_device_id == the canonical id -- the IN-clause
        expansion is what makes an EARLIER proposal, written under the
        orphan's own pre-merge id, still count against that same cooldown."""
        if device_id is not None:
            candidate_ids = self.store._all_ids_resolving_to(
                self.store.resolve_canonical_device_id(device_id)
            )
            placeholders = ",".join("?" * len(candidate_ids))
            row = self.store._conn.execute(
                f"SELECT proposed_at FROM threshold_history WHERE parameter=? AND "
                f"device_id IN ({placeholders}) AND device_type IS NULL "
                f"ORDER BY proposed_at DESC LIMIT 1",
                [parameter, *candidate_ids],
            ).fetchone()
            return float(row["proposed_at"]) if row is not None else None
        row = self.store._conn.execute(
            "SELECT proposed_at FROM threshold_history WHERE parameter=? AND "
            "device_id IS NULL AND "
            "(device_type=? OR (device_type IS NULL AND ? IS NULL)) "
            "ORDER BY proposed_at DESC LIMIT 1",
            (parameter, device_type, device_type),
        ).fetchone()
        return float(row["proposed_at"]) if row is not None else None

    # ---------------------------------------------------------- propose / canary / promote / rollback

    def propose_change(self, parameter: str, new_value: float, reason: str,
                         device_id: Optional[str] = None, device_type: Optional[str] = None,
                         backtest_run_id: Optional[str] = None,
                         snapshot_id: Optional[str] = None, now: Optional[float] = None,
                         default: Optional[float] = None) -> ProposalResult:
        """Proposes a bounded-step change. `device_id` alone determines WHICH
        SCOPE this proposal actually writes to: global (both args None),
        category (device_type given, device_id absent), or device (device_id
        given) -- matching the schema's own "at most one of device_id/
        device_type on the written row" invariant (schema.sql's comment on
        threshold_history.device_type).

        When device_id IS given, `device_type` may ALSO be passed alongside it
        -- purely as a HINT for correctly resolving that device's PARENT tier
        (its category) for old_value/trust-radius purposes, never written to
        the row itself (the row's own device_type column stays NULL for a
        device-scoped proposal, always). Without this hint, a device proposal
        would incorrectly skip straight to the global tier for its parent
        lookup, treating a device with an already-tuned category as if that
        category didn't exist -- found and fixed while writing this same
        session's own test coverage, not a design that shipped untested.

        `default` MUST be the same semantic default the caller itself used to
        compute `new_value` (i.e. whatever it passed as `get_active_value(...,
        default=X)`'s own X to derive "current"). BUGFIX (2026-09-28, console
        audit): every caller across backtest_job.py/population_prior_builder.py/
        train_fp_classifier.py computes "current" using a parameter's REAL
        semantic default (e.g. hard_stop_candidate_sensitivity's 0.9, matching
        decision/engine.py's own hardcoded default) -- but this method used to
        independently re-derive old_value with a DIFFERENT, unrelated fallback
        (the bare arithmetic midpoint of TUNABLE_PARAMETERS' min/max, 0.745 for
        that same parameter) whenever nothing had ever been promoted for this
        exact scope yet (the common case: a scope's FIRST-ever proposal). The
        two defaults silently disagreeing fed a bogus old_value into
        _clamp_step(), which clamps by the ARITHMETIC gap between old_value and
        new_value -- so a real -0.05 tighten computed off 0.9 could be stored
        as a +0.05 INCREASE off the wrong 0.745 baseline, flipping the direction
        console readers see (and reuse's own `reason` text, fixed at proposal
        time, never caught this because it doesn't depend on the arithmetic
        result at all). Falls back to the old bounds-midpoint behavior only
        when a caller still omits `default` -- every in-repo caller now passes
        one; see Documentation/AUTOTUNE_DEFAULT_CONSISTENCY_FIX.md.

        Rejected outright (not silently clamped to a no-op) if: the parameter
        isn't on the allowlist, the cooldown since the last proposal for this
        EXACT written scope hasn't elapsed, backtest_run_id is missing/failed,
        or (device/category scope only, loosening direction only) the trust-
        radius cap would be exceeded -- this is the concrete backtest-gating
        the plan requires: a proposal cannot even be CREATED off a failing or
        absent backtest, not just blocked at promotion time.

        2026-09-16 (per-device/category autotuning plan): device_type is new.
        Every pre-existing caller (global-only, device_id-only, no
        device_type hint) keeps working unchanged -- the trust-radius check
        below only ever engages for a scope that actually HAS a parent tier
        to diverge from (device_id or device_type set), so a global
        proposal's behavior is byte-for-byte identical to before this
        change."""
        now = now if now is not None else time.time()
        if parameter not in TUNABLE_PARAMETERS:
            return ProposalResult(False, reason=f"'{parameter}' is not on the tunable allowlist")

        # BUGFIX (2026-09-20, identity-merge handover follow-up): resolve device_id
        # to its live canonical id BEFORE it's used for anything below -- a NEW
        # proposal must never be written under an id that's already been (or is
        # about to be) merged away, or it would join the same class of
        # merge-blindness bug _promoted_value_at_scope()/_last_proposal_time()
        # were just fixed for. A no-op for the ordinary case (device_id was
        # never merged, or was already canonical).
        if device_id is not None:
            device_id = self.store.resolve_canonical_device_id(device_id)

        # The row's OWN scope -- device_id wins if given (device_type, if also
        # given, is a parent-resolution hint only, never written).
        row_device_id = device_id
        row_device_type = device_type if device_id is None else None

        last_proposed = self._last_proposal_time(parameter, row_device_id, row_device_type)
        if last_proposed is not None and (now - last_proposed) < _COOLDOWN_SECONDS:
            return ProposalResult(False, reason=f"cooldown active ({now - last_proposed:.0f}s < {_COOLDOWN_SECONDS:.0f}s)")

        if backtest_run_id is None:
            return ProposalResult(False, reason="no backtest_run_id given -- a proposal cannot be made without one")
        backtest_row = self.store._conn.execute(
            "SELECT overall_pass FROM backtest_runs WHERE run_id=?", (backtest_run_id,),
        ).fetchone()
        if backtest_row is None or not backtest_row["overall_pass"]:
            return ProposalResult(False, reason=f"backtest_run_id {backtest_run_id} did not pass")

        bounds = TUNABLE_PARAMETERS[parameter]
        # BUGFIX (2026-09-28): default_mid (bare bounds-midpoint) used to be the
        # ONLY fallback here, independent of whatever real semantic default the
        # caller used for its own "current" read -- see this method's own
        # docstring for the corruption that caused. `default`, when given by the
        # caller, is used instead; default_mid survives only for a caller that
        # still omits it.
        default_mid = default if default is not None else (bounds["min"] + bounds["max"]) / 2.0
        # Full 3-tier fallback for old_value -- uses BOTH raw args (device_type
        # as a hint is exactly what lets a device proposal correctly inherit
        # its category's value here, not skip straight to global).
        old_value = self.get_active_value(parameter, device_id, device_type, default=default_mid)
        clamped_new_value = _clamp_step(parameter, old_value, new_value)
        # 2026-10-07: a proposal that moves nothing is refused, not recorded. Callers compute "current" from their
        # own state (e.g. the legacy ARP-sweep rule's per-device threshold); when that already equals the active
        # value here, a row 'old == new' was written, promoted, and listed as a change (27 such rows on .94).
        if abs(clamped_new_value - old_value) < 1e-12:
            return ProposalResult(False, reason=f"no change: {parameter} is already {old_value:g} at this scope")

        # Trust-radius failsafe: a device-scoped value may never diverge from
        # its category's current value (or global, if no category value
        # exists), and a category-scoped value may never diverge from global,
        # by more than _TRUST_RADIUS_MAX_STEPS max_steps in the LESS-SENSITIVE
        # direction. Only engages for a scoped proposal that's actually moving
        # less-sensitive -- tightening beyond the parent tier is always safe
        # (becoming MORE cautious than the network-wide default needs no cap,
        # symmetric with the "tightening needs no sample floor" rule
        # elsewhere in this plan) and a global proposal has no parent tier to
        # diverge from at all.
        if row_device_id or row_device_type:
            direction = _LESS_SENSITIVE_DIRECTION.get(parameter, 1)
            moved_less_sensitive = (clamped_new_value - old_value) != 0 and \
                ((clamped_new_value - old_value > 0) == (direction > 0))
            if moved_less_sensitive:
                # Parent tier: a device's parent is its category (using the
                # device_type HINT, whether or not it matches row_device_type
                # -- row_device_type is always None here since row_device_id
                # is set) or global if no category hint was given; a
                # category's parent is always global.
                parent_device_type = device_type if row_device_id else None
                parent_value = self.get_active_value(parameter, device_id=None, device_type=parent_device_type,
                                                        default=default_mid)
                radius = _TRUST_RADIUS_MAX_STEPS * _directional_step_bound(bounds, direction)
                divergence = (clamped_new_value - parent_value) * direction  # positive = less-sensitive divergence
                if divergence > radius:
                    scope_label = f"device {row_device_id}" if row_device_id else f"category {row_device_type}"
                    return ProposalResult(False, reason=(
                        f"trust-radius exceeded: {scope_label}'s proposed value {clamped_new_value:.4f} would "
                        f"diverge from its parent tier's value {parent_value:.4f} by more than "
                        f"{_TRUST_RADIUS_MAX_STEPS:.0f} max_steps in the less-sensitive direction"
                    ))

        # threshold_history.device_id is a real FK to devices(device_id) (schema.sql).
        # A device-scoped proposal for a device that has never yet produced graph
        # evidence (insert_evidence()/insert_decision() upserts devices as a side
        # effect, but a caller reacting to an operator correction on a brand-new or
        # otherwise graph-disconnected device may run BEFORE that ever happened) would
        # otherwise fail this INSERT with a FOREIGN KEY constraint error. Same
        # defensive auto-upsert pattern already established for this exact situation
        # elsewhere in this module (see GraphStore.update_device_metadata()'s own
        # docstring) -- a no-op UPDATE if the device already exists, never touches
        # device_type/display_label since this call passes neither.
        if row_device_id is not None:
            self.store.ensure_device(row_device_id, timestamp=now)

        change_id = uuid.uuid4().hex
        self.store._conn.execute(
            "INSERT INTO threshold_history "
            "(change_id, device_id, device_type, parameter, old_value, new_value, proposed_at, canary_until, "
            "reason, backtest_run_id, snapshot_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (change_id, row_device_id, row_device_type, parameter, old_value, clamped_new_value, now,
             now + _DEFAULT_CANARY_SECONDS, reason, backtest_run_id, snapshot_id),
        )
        self.store._maybe_commit()
        return ProposalResult(True, change_id=change_id)

    def promote_change(self, change_id: str, confirming_backtest_run_id: str, now: Optional[float] = None) -> bool:
        """Promotes a proposed change once its canary window has elapsed AND
        a SUBSEQUENT backtest run (confirming the canary period didn't
        regress anything) also passed. Returns False (no-op, not an
        exception) for any change that isn't eligible yet -- canary not
        elapsed, already promoted, already rolled back, or the confirming
        backtest didn't pass."""
        now = now if now is not None else time.time()
        row = self.store._conn.execute(
            "SELECT * FROM threshold_history WHERE change_id=?", (change_id,),
        ).fetchone()
        if row is None or row["promoted_at"] is not None or row["rolled_back_at"] is not None:
            return False
        if now < float(row["canary_until"] or 0):
            return False
        backtest_row = self.store._conn.execute(
            "SELECT overall_pass FROM backtest_runs WHERE run_id=?", (confirming_backtest_run_id,),
        ).fetchone()
        if backtest_row is None or not backtest_row["overall_pass"]:
            return False
        self.store._conn.execute(
            "UPDATE threshold_history SET promoted_at=? WHERE change_id=?", (now, change_id),
        )
        self.store._maybe_commit()
        # 2026-09-27 (Phase 5): fired AFTER commit -- a subscriber sees the
        # already-durable state change, never a promotion that could still be
        # rolled back by a concurrent failure between the write and the notify.
        self._fire_notify(row["parameter"], row["device_id"], row["device_type"], "promoted")
        return True

    def rollback_change(self, change_id: str, reason: str, now: Optional[float] = None) -> bool:
        """Rolls back a change -- promoted or still in canary. get_active_
        value() stops returning it immediately (rolled_back_at IS NOT NULL
        excludes it). Idempotent: rolling back an already-rolled-back
        change is a safe no-op, not an error."""
        now = now if now is not None else time.time()
        row = self.store._conn.execute(
            "SELECT parameter, device_id, device_type, rolled_back_at FROM threshold_history WHERE change_id=?",
            (change_id,),
        ).fetchone()
        if row is None:
            return False
        if row["rolled_back_at"] is not None:
            return True  # already rolled back -- idempotent no-op
        self.store._conn.execute(
            "UPDATE threshold_history SET rolled_back_at=?, reason=reason || ' | rollback: ' || ? WHERE change_id=?",
            (now, reason, change_id),
        )
        self.store._maybe_commit()
        # 2026-09-27 (Phase 5): a rollback also invalidates any tracker built
        # with the now-reverted value -- same notify, different event label.
        self._fire_notify(row["parameter"], row["device_id"], row["device_type"], "rolled_back")
        return True

    def rollback_all_unconfirmed_for_backtest(self, backtest_run_id: str, reason: str,
                                                 now: Optional[float] = None) -> int:
        """A backtest regression's actual consequence: every change still
        in canary (not yet promoted) that this specific backtest run was
        supposed to confirm gets rolled back immediately, the same cycle
        the regression is detected -- not left dangling for a human to
        notice. Returns the number of changes rolled back."""
        now = now if now is not None else time.time()
        rows = self.store._conn.execute(
            "SELECT change_id FROM threshold_history WHERE backtest_run_id=? "
            "AND promoted_at IS NULL AND rolled_back_at IS NULL",
            (backtest_run_id,),
        ).fetchall()
        count = 0
        for row in rows:
            if self.rollback_change(row["change_id"], reason, now=now):
                count += 1
        return count


# ---------------------------------------------------------- Sheet 00/02 posterior-trajectory drift check

def _is_monotonic_less_sensitive(values: List[float], direction: int) -> bool:
    """True if `values` (chronological order) moved STRICTLY, monotonically
    in the less-sensitive `direction` (+1 increasing, -1 decreasing) across
    its whole span -- a single reversal anywhere breaks the trend (this is
    meant to catch a sustained drift, not ordinary back-and-forth tuning
    noise around a stable point)."""
    if len(values) < 2:
        return False
    pairs = list(zip(values, values[1:]))
    if direction > 0:
        return all(b >= a for a, b in pairs) and values[-1] > values[0]
    return all(b <= a for a, b in pairs) and values[-1] < values[0]


def _has_regime_change_explanation(store: GraphStore, device_ids: List[str], since: float, until: float) -> bool:
    """True if a real `regime_change` evidence item exists in [since, until]
    for one of `device_ids` (or, when `device_ids` is empty -- a
    device-independent/global tunable's own drift -- anywhere at all) --
    the "matching real explanation" (e.g. a firmware/OS update) a drift
    finding needs in order to NOT be flagged as unexplained."""
    if not device_ids:
        row = store._conn.execute(
            "SELECT 1 FROM evidence WHERE evidence_type='regime_change' AND timestamp >= ? AND timestamp <= ? LIMIT 1",
            (since, until),
        ).fetchone()
        return row is not None
    placeholders = ",".join("?" * len(device_ids))
    row = store._conn.execute(
        f"SELECT 1 FROM evidence WHERE evidence_type='regime_change' AND device_id IN ({placeholders}) "
        "AND timestamp >= ? AND timestamp <= ? LIMIT 1",
        (*device_ids, since, until),
    ).fetchone()
    return row is not None


def compute_drift_result(store: GraphStore, lookback_seconds: float = _DEFAULT_DRIFT_LOOKBACK_SECONDS,
                           now: Optional[float] = None) -> Dict[str, Any]:
    """Sheet 00's posterior-trajectory drift check ("flag a cycle where
    thresholds trend toward everything-benign without a matching real
    explanation") -- Sheet 02's own former honest gap: run_backtest() used
    to persist drift_result_json as an empty {} placeholder every run.

    For each TUNABLE_PARAMETERS entry, groups PROMOTED (never canary-only --
    those aren't live yet) changes within `lookback_seconds` by scope
    (device_id / device_type / neither=global, each its own group -- a row
    has at most one of the first two set), and flags a group whose values
    moved strictly, monotonically toward _LESS_SENSITIVE_DIRECTION across at
    least _MIN_PROMOTIONS_FOR_TREND promotions -- UNLESS a real regime_change
    evidence item for that same scope (that one device; every device of that
    category; or anywhere, for a global change) in the same window explains
    it. A genuine firmware/OS-update-driven regime shift is a legitimate
    reason for thresholds to relax repeatedly; an unexplained one is exactly
    the "quietly getting less sensitive for no real reason" failure mode
    this check exists to catch -- run_backtest()'s own `overall_pass` does
    NOT gate on this (a real, deliberate scope limit: drift is a flag for
    operator review, not yet wired as its own pass/fail bar -- see this
    function's caller).

    2026-09-16 (per-device/category autotuning plan): grouping extended from
    device_id-only to (device_id, device_type) -- every pre-existing global/
    device-scoped row (device_type always NULL until this plan's proposal
    path starts writing category-scoped ones) groups and explains exactly as
    before; category-scoped rows are new groups, not a change to old ones."""
    now = now if now is not None else time.time()
    since = now - lookback_seconds
    findings: List[Dict[str, Any]] = []

    for parameter, direction in _LESS_SENSITIVE_DIRECTION.items():
        rows = store._conn.execute(
            "SELECT device_id, device_type, new_value, promoted_at FROM threshold_history WHERE parameter=? "
            "AND promoted_at IS NOT NULL AND promoted_at >= ? AND rolled_back_at IS NULL "
            "ORDER BY promoted_at ASC",
            (parameter, since),
        ).fetchall()

        by_scope: Dict[tuple, List[float]] = {}
        for row in rows:
            scope_key = (row["device_id"], row["device_type"])
            by_scope.setdefault(scope_key, []).append(float(row["new_value"]))

        for (device_id, device_type), values in by_scope.items():
            if len(values) < _MIN_PROMOTIONS_FOR_TREND:
                continue
            if not _is_monotonic_less_sensitive(values, direction):
                continue
            if device_id is not None:
                scope_devices = [device_id]
            elif device_type is not None:
                scope_devices = [r["device_id"] for r in store._conn.execute(
                    "SELECT device_id FROM devices WHERE device_type=? AND merged_into_device_id IS NULL",
                    (device_type,),
                ).fetchall()]
            else:
                scope_devices = []
            if _has_regime_change_explanation(store, scope_devices, since, now):
                continue
            findings.append({
                "parameter": parameter, "device_id": device_id, "device_type": device_type,
                "promotions": len(values), "first_value": values[0], "last_value": values[-1],
            })

    return {"drift_detected": bool(findings), "findings": findings, "lookback_seconds": lookback_seconds}
