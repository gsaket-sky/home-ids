"""
argus/shadow/sandbox.py -- Deterministic shadow evaluation (Phase 7 of the
autonomy-completion effort, 2026-09-27, Documentation/ARGUS_AUTONOMY_DEPENDENCY_MAP.md).

WHAT THIS IS: for a currently-in-canary autotune candidate (a threshold_history row
with promoted_at IS NULL, rolled_back_at IS NULL, canary_until > now), re-decides THIS
cycle with ONLY that one candidate value substituted, and records whether the resulting
state agrees with the real decision's.

HOW (U7, 2026-10-14, DETECTION_CORE_REWORK section I): live_engine splits a cycle into
gather (impure, once: graph reads, the stateful baseline/Markov learners), decide (pure)
and commit (graph writes, per-device bookkeeping). The shadow is live_engine.decide() on
the real cycle's own GatheredCycle with the real decision's champion DecisionParameters,
one field replaced -- it reads nothing new and writes nothing but its own shadow_decisions
row. Before, it re-ran the whole evaluate() inside a graph transaction it rolled back; the
rollback undid graph rows only, while the in-memory learners had observed the cycle again
and the device's "last decision" bookkeeping took the shadow's values (U7's defect).

WHICH PARAMETERS: only live_engine.DECIDE_PARAMETERS -- the ones decide() reads. A
candidate for any other tunable (one acting in a stateful learner, a detector or the
false-positive engine) is not shadow-compared per cycle: re-deciding a cycle cannot show
its effect, and the rows this module used to write for them were trivially "agree".

Alerting and containment are decided in core/pipeline.py after the real decision; this
module never reaches alert_manager or ips_mitigator.
"""
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

import dataclasses

from argus.graph.store import GraphStore
from metrics import shadow_eval_comparisons_total, shadow_eval_errors_total, shadow_eval_paused
from utils import is_resource_pressure_active_in_process

LOGGER = logging.getLogger("argus.shadow.sandbox")

# First-pass, not-yet-empirically-tuned constants, same honesty framing this
# codebase already uses elsewhere. Canaries last hours (_DEFAULT_CANARY_SECONDS,
# autotune/engine.py); re-scanning threshold_history this rarely is more than
# sufficient and keeps this module's own per-cycle cost negligible.
_ACTIVE_CANARIES_REFRESH_SECONDS = 300.0
# Bounds shadow_decisions' own row count -- the plan's own "strict TTL, row-count,
# and disk-size limits" requirement. Pruned opportunistically on write (same
# pattern rotate_jsonl_if_oversized() uses for size-capped files), not a separate
# scheduled job.
_MAX_SHADOW_DECISIONS = 5000


def _active_canary_rows(store: GraphStore, now: float) -> List[Dict[str, Any]]:
    rows = store._conn.execute(
        "SELECT change_id, parameter, device_id, device_type, new_value FROM threshold_history "
        "WHERE promoted_at IS NULL AND rolled_back_at IS NULL AND canary_until > ?",
        (now,),
    ).fetchall()
    return [dict(r) for r in rows]


def _prune_shadow_decisions_if_oversized(store: GraphStore) -> None:
    (count,) = store._conn.execute("SELECT COUNT(*) FROM shadow_decisions").fetchone()
    if count <= _MAX_SHADOW_DECISIONS:
        return
    excess = count - _MAX_SHADOW_DECISIONS
    store._conn.execute(
        "DELETE FROM shadow_decisions WHERE shadow_id IN "
        "(SELECT shadow_id FROM shadow_decisions ORDER BY timestamp ASC LIMIT ?)",
        (excess,),
    )


def _record_shadow_decision(store: GraphStore, change_id: str, device_id: Optional[str],
                               now: float, real_state: str, shadow_state: str) -> None:
    agree = real_state == shadow_state
    store._conn.execute(
        "INSERT INTO shadow_decisions (shadow_id, change_id, device_id, timestamp, real_state, "
        "shadow_state, agree) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (uuid.uuid4().hex, change_id, device_id, now, real_state, shadow_state, 1 if agree else 0),
    )
    _prune_shadow_decisions_if_oversized(store)
    store._maybe_commit()


def evaluate_candidate_shadow(store: GraphStore, change_id: str, parameter: str, candidate_value: float,
                                 cycle, real_state: str, now: float) -> Optional[bool]:
    """Runs ONE shadow comparison for a single currently-in-canary change on the real
    cycle `cycle` (live_engine.EvaluatedCycle: its gathered facts and champion parameters).
    Returns True/False (agreement), or None when the parameter is not a decide-stage one
    or the shadow decide failed (logged, counted, never raised -- a shadow failure must
    never affect the real decision this cycle already produced).

    `real_state` is the REAL decision's own state for this cycle, never recomputed here."""
    import argus.ops.live_engine as live_engine  # local import: avoids a live_engine <-> shadow.sandbox import cycle

    if parameter not in live_engine.DECIDE_PARAMETERS:
        return None
    try:
        params = dataclasses.replace(cycle.params, **{parameter: float(candidate_value)})
        shadow_decision, _merged = live_engine.decide(cycle.gathered, params)
        shadow_state = shadow_decision.get("state")
    except Exception:
        LOGGER.exception("[SHADOW_EVAL] shadow decide() failed for change_id=%r parameter=%r "
                           "device_id=%r, non-fatal, no comparison recorded",
                           change_id, parameter, cycle.gathered.device_id)
        shadow_eval_errors_total.inc()
        return None
    if shadow_state is None:
        return None

    agree = shadow_state == real_state
    try:
        _record_shadow_decision(store, change_id, cycle.gathered.device_id, now, real_state, shadow_state)
    except Exception:
        LOGGER.exception("[SHADOW_EVAL] failed to record shadow_decisions row (non-fatal)")
    shadow_eval_comparisons_total.labels(parameter=parameter, agree=str(agree)).inc()
    return agree


_SHADOW_EVAL_MIN_INTERVAL_SECONDS = 60.0
_SHADOW_EVAL_MAX_TRACKED = 5000


class ShadowEvaluator:
    """One instance per process, matching every other module-level singleton in
    this codebase (e.g. live_engine.py's own _autotune_engine/_baseline_engine).
    Caches the active-canary list, throttled -- canaries last hours, so re-scanning
    threshold_history on literally every cycle would be pure waste."""

    def __init__(self, store: GraphStore):
        self.store = store
        self._active_canaries: List[Dict[str, Any]] = []
        self._cache_refreshed_at: float = 0.0
        self._last_eval: Dict[str, float] = {}      # device_id -> last shadow evaluation (bounded, see _SHADOW_EVAL_MAX_TRACKED)

    def _refresh_if_stale(self, now: float) -> None:
        if now - self._cache_refreshed_at >= _ACTIVE_CANARIES_REFRESH_SECONDS:
            self._active_canaries = _active_canary_rows(self.store, now)
            self._cache_refreshed_at = now

    def maybe_shadow_evaluate(self, cycle, real_state: str, now: Optional[float] = None) -> None:
        """Best-effort, called once per real decision cycle from core/pipeline.py -- shadow-
        tests AT MOST ONE currently-active canary per call (the first one whose
        scope matches this device/category, or a global one), keeping per-cycle
        cost bounded regardless of how many parameters are simultaneously in
        canary. Never raises -- a shadow-eval failure must never affect the real
        cycle it's riding alongside."""
        now = now if now is not None else time.time()
        try:
            import argus.ops.live_engine as live_engine  # local import, see evaluate_candidate_shadow()
            device_id = cycle.gathered.device_id
            device_type = cycle.gathered.device_type
            if is_resource_pressure_active_in_process():
                shadow_eval_paused.set(1)
                return
            shadow_eval_paused.set(0)

            self._refresh_if_stale(now)
            # Only decide-stage parameters can be compared by re-deciding a cycle (module docstring).
            canaries = [row for row in self._active_canaries if row["parameter"] in live_engine.DECIDE_PARAMETERS]
            if not canaries:
                return

            # Device-scoped beats category-scoped beats global, regardless of which
            # order threshold_history happened to return them in -- three separate
            # passes (not a single pass with an early break) so a device-scoped
            # canary occurring AFTER a matching category/global row in scan order is
            # still correctly preferred. Found and fixed via this module's own test
            # coverage: a single-pass early-break version picked whichever scope
            # matched FIRST in row order, not the most specific one, whenever a
            # broader-scoped canary happened to be scanned first.
            candidate = None
            for row in canaries:
                if row["device_id"] is not None and row["device_id"] == device_id:
                    candidate = row
                    break
            if candidate is None:
                for row in canaries:
                    if row["device_id"] is None and row["device_type"] is not None and row["device_type"] == device_type:
                        candidate = row
                        break
            if candidate is None:
                for row in canaries:
                    if row["device_id"] is None and row["device_type"] is None:
                        candidate = row
                        break
            if candidate is None:
                return

            # One sample per device per interval is plenty for a canary that lasts hours (a full second evaluate()
            # was ~30% of the engine loop when run every cycle; decide() alone is far cheaper, the cap stays).
            key = device_id or ""
            last = self._last_eval.get(key)
            if last is not None and now - last < _SHADOW_EVAL_MIN_INTERVAL_SECONDS:
                return
            if len(self._last_eval) >= _SHADOW_EVAL_MAX_TRACKED:
                cutoff = now - _SHADOW_EVAL_MIN_INTERVAL_SECONDS
                self._last_eval = {k: t for k, t in self._last_eval.items() if t >= cutoff}
            self._last_eval[key] = now

            evaluate_candidate_shadow(
                self.store, candidate["change_id"], candidate["parameter"], candidate["new_value"],
                cycle, real_state, now,
            )
        except Exception:
            LOGGER.exception("[SHADOW_EVAL] maybe_shadow_evaluate() failed (non-fatal, real decision unaffected)")
