"""
v13/autotune/engine.py -- Release 15 Sheet 03a: the closed-loop autotuner
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
registry membership are code-level invariants in v13/decision/engine.py,
not config -- TUNABLE_PARAMETERS below is an explicit, closed allowlist
that never includes any of them, so there is no code path by which this
module could touch them even by a bounded step.

HONEST SCOPE NOTE: this builds the complete propose/canary/promote/rollback
INFRASTRUCTURE, versioned in threshold_history (Release 15 schema addition,
already migrated) and gated by backtest_runs. It is NOT yet wired to make
v13/decision/engine.py actually READ these promoted values at decision
time -- that engine currently has very few externally-tunable constants
(confirmed via direct grep before writing this: _HARD_STOP_FRESHNESS_SECONDS
and _PARTIAL_SUPPORT_FAMILIES are the only module-level ones, neither on
the allowlist below), so live wiring is real, separate follow-up work, not
bundled into this commit -- the same honest-gap pattern already used for
Sheet 00's `risk` metric and Sheet 02's scheduler wiring.
"""
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from v13.graph.store import GraphStore

# Explicit, closed allowlist -- the ONLY parameters this module may ever
# propose a change to. (name -> (min, max, max_step_per_change)). Adding a
# new tunable parameter means adding a row here, deliberately, not widening
# an existing bound.
TUNABLE_PARAMETERS: Dict[str, Dict[str, float]] = {
    "reputation_tier_suspicious_floor": {"min": 1.0, "max": 5.0, "max_step": 0.5},
    "reputation_tier_high_floor": {"min": 2.0, "max": 5.0, "max_step": 0.5},
    "bocpd_hazard_rate": {"min": 1.0 / 2000.0, "max": 1.0 / 100.0, "max_step": 1.0 / 500.0},
    "hard_stop_candidate_sensitivity": {"min": 0.5, "max": 0.99, "max_step": 0.05},
}

# First-pass, not-yet-empirically-tuned constants (this codebase's own
# established honesty framing).
_DEFAULT_CANARY_SECONDS = 6 * 3600.0  # shadow-apply for N cycles before promotion is eligible
_COOLDOWN_SECONDS = 3600.0  # minimum gap between proposals for the SAME parameter+device


@dataclass
class ProposalResult:
    accepted: bool
    change_id: Optional[str] = None
    reason: str = ""


def _clamp_step(parameter: str, old_value: float, new_value: float) -> float:
    bounds = TUNABLE_PARAMETERS[parameter]
    step = new_value - old_value
    if step > bounds["max_step"]:
        new_value = old_value + bounds["max_step"]
    elif step < -bounds["max_step"]:
        new_value = old_value - bounds["max_step"]
    return max(bounds["min"], min(bounds["max"], new_value))


class AutotuneEngine:
    def __init__(self, store: GraphStore):
        self.store = store

    # ---------------------------------------------------------- reads

    def get_active_value(self, parameter: str, device_id: Optional[str] = None,
                            default: Optional[float] = None) -> Optional[float]:
        """The most recently PROMOTED (not merely proposed) value for
        `parameter` -- a promoted-but-later-rolled-back change does not
        count (rolled_back_at IS NULL is required), so a rollback takes
        effect for readers immediately, not just in the audit trail."""
        row = self.store._conn.execute(
            "SELECT new_value FROM threshold_history WHERE parameter=? AND "
            "(device_id=? OR (device_id IS NULL AND ? IS NULL)) AND "
            "promoted_at IS NOT NULL AND rolled_back_at IS NULL "
            "ORDER BY promoted_at DESC LIMIT 1",
            (parameter, device_id, device_id),
        ).fetchone()
        return float(row["new_value"]) if row is not None else default

    def _last_proposal_time(self, parameter: str, device_id: Optional[str]) -> Optional[float]:
        row = self.store._conn.execute(
            "SELECT proposed_at FROM threshold_history WHERE parameter=? AND "
            "(device_id=? OR (device_id IS NULL AND ? IS NULL)) "
            "ORDER BY proposed_at DESC LIMIT 1",
            (parameter, device_id, device_id),
        ).fetchone()
        return float(row["proposed_at"]) if row is not None else None

    # ---------------------------------------------------------- propose / canary / promote / rollback

    def propose_change(self, parameter: str, new_value: float, reason: str,
                         device_id: Optional[str] = None, backtest_run_id: Optional[str] = None,
                         snapshot_id: Optional[str] = None, now: Optional[float] = None) -> ProposalResult:
        """Proposes a bounded-step change. Rejected outright (not silently
        clamped to a no-op) if: the parameter isn't on the allowlist, the
        cooldown since the last proposal for this exact (parameter,
        device_id) hasn't elapsed, or backtest_run_id is missing/failed --
        this is the concrete backtest-gating the plan requires: a proposal
        cannot even be CREATED off a failing or absent backtest, not just
        blocked at promotion time."""
        now = now if now is not None else time.time()
        if parameter not in TUNABLE_PARAMETERS:
            return ProposalResult(False, reason=f"'{parameter}' is not on the tunable allowlist")

        last_proposed = self._last_proposal_time(parameter, device_id)
        if last_proposed is not None and (now - last_proposed) < _COOLDOWN_SECONDS:
            return ProposalResult(False, reason=f"cooldown active ({now - last_proposed:.0f}s < {_COOLDOWN_SECONDS:.0f}s)")

        if backtest_run_id is None:
            return ProposalResult(False, reason="no backtest_run_id given -- a proposal cannot be made without one")
        backtest_row = self.store._conn.execute(
            "SELECT overall_pass FROM backtest_runs WHERE run_id=?", (backtest_run_id,),
        ).fetchone()
        if backtest_row is None or not backtest_row["overall_pass"]:
            return ProposalResult(False, reason=f"backtest_run_id {backtest_run_id} did not pass")

        old_value = self.get_active_value(parameter, device_id, default=(
            TUNABLE_PARAMETERS[parameter]["min"] + TUNABLE_PARAMETERS[parameter]["max"]) / 2.0)
        clamped_new_value = _clamp_step(parameter, old_value, new_value)

        change_id = uuid.uuid4().hex
        self.store._conn.execute(
            "INSERT INTO threshold_history "
            "(change_id, device_id, parameter, old_value, new_value, proposed_at, canary_until, "
            "reason, backtest_run_id, snapshot_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (change_id, device_id, parameter, old_value, clamped_new_value, now, now + _DEFAULT_CANARY_SECONDS,
             reason, backtest_run_id, snapshot_id),
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
        return True

    def rollback_change(self, change_id: str, reason: str, now: Optional[float] = None) -> bool:
        """Rolls back a change -- promoted or still in canary. get_active_
        value() stops returning it immediately (rolled_back_at IS NOT NULL
        excludes it). Idempotent: rolling back an already-rolled-back
        change is a safe no-op, not an error."""
        now = now if now is not None else time.time()
        row = self.store._conn.execute(
            "SELECT rolled_back_at FROM threshold_history WHERE change_id=?", (change_id,),
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
