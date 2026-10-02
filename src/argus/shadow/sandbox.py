"""
argus/shadow/sandbox.py -- Deterministic shadow evaluation (Phase 7 of the
autonomy-completion effort, 2026-09-27, Documentation/ARGUS_AUTONOMY_DEPENDENCY_MAP.md).

WHAT THIS IS: for a currently-in-canary autotune candidate (a threshold_history row
with promoted_at IS NULL, rolled_back_at IS NULL, canary_until > now), re-runs THIS
cycle's real decision inputs through the SAME real decision path
(argus/ops/live_engine.py's evaluate()) with ONLY that one candidate value
substituted, and compares the resulting state against what the real value actually
produced -- without ever sending an alert, without ever leaving a trace in the real
graph.

HOW SAFETY IS ACTUALLY GUARANTEED, confirmed via direct investigation, not assumed:
live_engine.evaluate() is NOT a pure function when given a device_id -- it reads AND
WRITES the graph (evidence/decisions rows, device metadata) as a real side effect of
computing a decision (this is needed for several of the 16 parameters, e.g.
hard_stop_candidate_sensitivity/familiarity_trust_bar/reputation floors, which are
only resolved inside evaluate()'s own `if device_id:` block). Re-invoking it a second
time for shadow purposes therefore risks REAL, PERMANENT double-writes (duplicate
evidence/decisions rows, double-counted peer-cohort baselines) unless something
prevents that. This module does NOT refactor evaluate() to separate pure computation
from persistence (a much larger, riskier change) and does NOT swap in an isolated
clone of the graph (which would make the shadow call see slightly stale/incomplete
input compared to the real decision's own frozen snapshot). Instead: the ENTIRE
shadow evaluate() call is wrapped in a real GraphStore transaction() that is always,
unconditionally rolled back via an internal sentinel exception once the shadow
decision has been read out -- every write evaluate() makes during the shadow call is
undone before this function returns, regardless of what it wrote or how, with zero
changes to evaluate() itself. GraphStore.transaction()'s own docstring confirms this
is safe to nest arbitrarily (a no-op passthrough when already inside one) OR to be
the outermost transaction (confirmed via direct grep: core/pipeline.py never calls
store.transaction() itself, so this call is always the real outermost one in
practice, and the rollback is real).

Alert/mitigation isolation is simpler and doesn't need a special guard: alerting and
containment are decided in core/pipeline.py AFTER evaluate() returns, never inside
evaluate() itself -- this module's own caller (maybe_shadow_evaluate() below) only
ever calls evaluate() and records a comparison, never touches alert_manager/
ips_mitigator at all, so there is no code path by which a shadow evaluation could
reach either.
"""
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from argus.autotune.engine import AutotuneEngine
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


class _ShadowAbort(Exception):
    """Internal sentinel only -- raised inside the shadow transaction to force an
    unconditional rollback of every write the shadow evaluate() call made, caught
    immediately by the same function that raises it, never propagated further."""


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
                                 device_id: Optional[str], device_type: str,
                                 active_evidence_v1: List, rep_vector, features: Optional[dict],
                                 is_safe: bool, baseline_familiarity: float, real_state: str,
                                 now: float) -> Optional[bool]:
    """Runs ONE shadow comparison for a single currently-in-canary change against
    THIS cycle's real inputs. Returns True/False (agreement) or None if the shadow
    call itself failed (logged, counted, never raised to the caller -- a shadow
    failure must never affect the real decision this cycle already produced).

    `real_state` is the REAL decision's own `state` for this exact cycle, already
    computed by the caller -- never recomputed here, so the comparison is always
    against the actual thing that governed this cycle's real alert/mitigation
    behavior, not a second, possibly-different real evaluation."""
    import argus.ops.live_engine as live_engine  # local import: avoids a live_engine <-> shadow.sandbox import cycle

    original_get_active_value = AutotuneEngine.get_active_value

    def _patched_get_active_value(self, param, device_id=None, device_type=None, default=None):
        if param == parameter:
            return candidate_value
        return original_get_active_value(self, param, device_id=device_id, device_type=device_type, default=default)

    shadow_state: Optional[str] = None
    try:
        AutotuneEngine.get_active_value = _patched_get_active_value
        try:
            with store.transaction():
                shadow_decision = live_engine.evaluate(
                    active_evidence_v1, rep_vector, device_type=device_type,
                    baseline_familiarity=baseline_familiarity, features=features, is_safe=is_safe,
                    device_id=device_id, now=now,
                )
                shadow_state = shadow_decision.get("state")
                raise _ShadowAbort()
        except _ShadowAbort:
            pass
    except Exception:
        LOGGER.exception("[SHADOW_EVAL] shadow evaluate() failed for change_id=%r parameter=%r "
                           "device_id=%r, non-fatal, no comparison recorded", change_id, parameter, device_id)
        shadow_eval_errors_total.inc()
        shadow_state = None
    finally:
        AutotuneEngine.get_active_value = original_get_active_value

    if shadow_state is None:
        return None

    agree = shadow_state == real_state
    try:
        _record_shadow_decision(store, change_id, device_id, now, real_state, shadow_state)
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

    def maybe_shadow_evaluate(self, device_id: Optional[str], device_type: str,
                                 active_evidence_v1: List, rep_vector, features: Optional[dict],
                                 is_safe: bool, baseline_familiarity: float, real_state: str,
                                 now: Optional[float] = None) -> None:
        """Best-effort, called once per real decision cycle (mirroring
        evaluate_cl_afpe_shadow()'s own call shape in core/pipeline.py) -- shadow-
        tests AT MOST ONE currently-active canary per call (the first one whose
        scope matches this device/category, or a global one), keeping per-cycle
        cost bounded regardless of how many parameters are simultaneously in
        canary. Never raises -- a shadow-eval failure must never affect the real
        cycle it's riding alongside."""
        now = now if now is not None else time.time()
        try:
            if is_resource_pressure_active_in_process():
                shadow_eval_paused.set(1)
                return
            shadow_eval_paused.set(0)

            self._refresh_if_stale(now)
            if not self._active_canaries:
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
            for row in self._active_canaries:
                if row["device_id"] is not None and row["device_id"] == device_id:
                    candidate = row
                    break
            if candidate is None:
                for row in self._active_canaries:
                    if row["device_id"] is None and row["device_type"] is not None and row["device_type"] == device_type:
                        candidate = row
                        break
            if candidate is None:
                for row in self._active_canaries:
                    if row["device_id"] is None and row["device_type"] is None:
                        candidate = row
                        break
            if candidate is None:
                return

            # A shadow comparison is a full second evaluate(); one sample per device per interval is plenty for a
            # canary that lasts hours, and it was ~30% of the engine loop when run every cycle.
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
                device_id, device_type, active_evidence_v1, rep_vector, features, is_safe,
                baseline_familiarity, real_state, now,
            )
        except Exception:
            LOGGER.exception("[SHADOW_EVAL] maybe_shadow_evaluate() failed (non-fatal, real decision unaffected)")
