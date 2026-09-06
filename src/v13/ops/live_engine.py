"""
live_engine.py - the actual swap-in adapter `pipeline.py` calls instead of
`core/decision_engine.py`'s `DecisionEngine.evaluate()`, per the v13 fast-cutover plan
(Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md, the entry recording this cutover).

Converts v-current's real per-cycle Evidence/features into v13 Evidence v2 (mirroring
`src/v13/ingest/sources.py`'s own `fallback_context` split exactly, since pipeline.py's
real detectors have the same `zeek_exfiltration`/`zeek_beaconing` destination gap
`sources.py` already works around -- see that file's own A2 comment) and calls v13's
own `DecisionEngine.evaluate()`, now the LIVE decision path, not a shadow comparison.

Dependency direction stays one-way (core -> v13, never v13 -> core): this module never
imports `core.decision_engine` itself. The caller (`pipeline.py`) passes its own
v-current `evaluate` as `fallback_evaluate`, used ONLY if v13's engine raises. This is
the one piece of the old per-mechanism-flip caution machinery kept from the superseded
plan -- a fail-safe costs nothing and this project always keeps an escape hatch. Any
fallback firing is logged loudly (never silent) since it should never happen in normal
operation and would mean something needs investigating.

GRAPH WRITE + WINDOWED READ (v13 full-architecture plan, Phase 1): when `device_id` is
supplied, every call also (a) queries `RollingWindowView.evidence_in_window()` for that
device's persisted history and merges it with this cycle's fresh evidence before
deciding, and (b) writes this cycle's fresh evidence + the resulting decision into the
same GraphStore. Both are best-effort -- a graph failure never affects the returned
decision, only means this cycle is missing from the durable trail (logged loudly, not
silent). `device_id=None` (the default) skips both entirely, unchanged from before this
existed -- so existing callers that don't pass it keep working exactly as they do today.
The decision row is deduped by (state, decision_path) per device (`_last_decision_key`,
mirroring `src/v13/ingest/daemon.py`'s own `only_persist_if_changed_from` pattern) -- a
real fix found live on `.94`'s first restart with this wiring: without it, every device
writes a new decisions-table row every ~2s poll cycle regardless of whether the verdict
actually changed (611 rows observed in well under a minute of real runtime before this
was added). Evidence itself is never deduped this way -- every fresh item is a real
observation worth recording.

WHY QUERY UP TO THE LONGEST TTL, NOT A SHORTER "ROLLING WINDOW": confirmed by reading
`src/v13/hypotheses/engine.py`'s own `compute_freshness()` -- it already discards
anything older than 600s (default) / 86400s (reputation family) per item, matching
v-current's `EvidenceStore` TTLs exactly. Querying a shorter window than that would only
ever return a SUBSET of what scoring already considers fresh; querying up to the longest
TTL and letting `compute_freshness()` do the real trimming is simpler and strictly
correct. The actual new capability this unlocks is NOT "see further back in time than a
single cycle already could" (a single cycle's `EvidenceStore`-backed `active_evidence`
already covers the same TTL window) -- it's that this survives a `soc.service` restart,
which wipes `EvidenceStore` completely (100% in-memory, no persistence at all) but not
the graph. A device mid-way through building up a slow pattern doesn't lose that history
just because the service restarted for an unrelated reason.
"""
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from v13.evidence.ingest import convert_list
from v13.hypotheses.independence import INDEPENDENCE_FAMILY_MAP
from v13.decision.engine import DecisionEngine as V13DecisionEngine
from v13.graph.store import GraphStore
from v13.graph.window import RollingWindowView

LOGGER = logging.getLogger("home_ids.v13_live_engine")

# Mirrors src/v13/ingest/sources.py's _NEEDS_LAST_DEST_IP_FALLBACK / _NO_DEST_SENTINEL
# exactly -- these two v-current detectors (threat_signals.py:247-274) never set
# Evidence.domain themselves; everyone else either sets it directly or has no domain
# concept at all, so a fallback would be misleading, not helpful.
_NEEDS_LAST_DEST_IP_FALLBACK = frozenset({"zeek_exfiltration", "zeek_beaconing"})
_NO_DEST_SENTINEL = "unknown"  # ZeekFeatureExtractor._last_connection_meta's own "no data yet" sentinel

# The longest TTL hypotheses/engine.py's own compute_freshness() honors (the
# "reputation" independence_family, 86400s) -- see the module docstring above for why
# querying up to this bound, not a shorter one, is the correct design.
_GRAPH_QUERY_WINDOW_SECONDS = 86400

_v13_engine = V13DecisionEngine()

_GRAPH_DB_PATH = "state/v13_graph.db"
_graph_store: Optional[GraphStore] = None

# Mirrors src/v13/ingest/daemon.py's own _last_decision_key dict + compute_decision()'s
# only_persist_if_changed_from param exactly (see that docstring) -- without this, every
# device gets a NEW decisions-table row every single ~2s poll cycle regardless of
# whether the verdict actually changed (confirmed live: 611 decision rows after well
# under a minute of real runtime on .94's first restart with this wiring). Evidence
# itself is NOT deduped this way -- every fresh item is a real observation worth
# recording; it's specifically the DERIVED verdict that shouldn't be re-written when
# nothing about it changed.
_last_decision_key: Dict[str, Tuple[str, str]] = {}


def configure(graph_db_path: str) -> None:
    """Optional: call once at startup to point the live graph store somewhere other
    than the default 'state/v13_graph.db' (relative to the process's CWD, matching
    every other v13 ops file's own state_dir convention). Safe to call before any
    real evaluate() call; if never called, the default path is opened lazily on
    first use with a device_id."""
    global _GRAPH_DB_PATH, _graph_store
    _GRAPH_DB_PATH = graph_db_path
    _graph_store = None  # force re-init against the new path on next use


def _get_graph_store() -> GraphStore:
    global _graph_store
    if _graph_store is None:
        _graph_store = GraphStore(_GRAPH_DB_PATH)
    return _graph_store


def _build_fallback_context(features: dict) -> Optional[Dict[str, str]]:
    dest_ip = str((features or {}).get("last_dest_ip", "") or "")
    if not dest_ip or dest_ip == _NO_DEST_SENTINEL:
        return None
    return {"dest_ip": dest_ip}


def _convert_active_evidence(v1_evidence_list, features: dict):
    """Same split as run_detection_cycle(): only the two known-gap types get a
    fallback_context, so a zeek_notice/malicious_ja3/etc. item never gets a misleading
    destination attached just because it happened to share a batch with one that does."""
    needs_fallback = [ev for ev in v1_evidence_list if ev.type in _NEEDS_LAST_DEST_IP_FALLBACK]
    no_fallback_needed = [ev for ev in v1_evidence_list if ev.type not in _NEEDS_LAST_DEST_IP_FALLBACK]

    out = []
    if no_fallback_needed:
        out.extend(convert_list(no_fallback_needed, INDEPENDENCE_FAMILY_MAP))
    if needs_fallback:
        fallback_context = _build_fallback_context(features)
        out.extend(convert_list(needs_fallback, INDEPENDENCE_FAMILY_MAP, fallback_context=fallback_context))
    return out


def _query_graph_window(device_id: str, now: float) -> List:
    """Best-effort: returns [] on any failure rather than raising, so a graph
    problem degrades to "decide on this cycle's fresh evidence only" (exactly
    today's pre-Phase-1 behavior), never blocks a real decision."""
    try:
        store = _get_graph_store()
        window = RollingWindowView(store)
        return window.evidence_in_window(device_id, _GRAPH_QUERY_WINDOW_SECONDS, now=now)
    except Exception as e:
        LOGGER.warning(
            "Failed to query GraphStore window for device %r, deciding on this "
            "cycle's fresh evidence only: %s", device_id, e,
        )
        return []


def _write_graph(device_id: str, timestamp: float, fresh_v2: List, merged_v2: List,
                   decision: Dict[str, Any]) -> None:
    """Best-effort: never raises out to the caller. A failure here means this
    cycle is missing from the durable audit trail -- it must never affect the
    live decision, which has already been computed and returned by the time
    this runs.

    The decision row is deduped by (state, decision_path) via _last_decision_key,
    matching src/v13/ingest/daemon.py's own only_persist_if_changed_from pattern
    exactly -- evidence is NEVER deduped this way (every fresh item is a real
    observation), only the derived verdict row. Skips the graph entirely (no
    transaction opened at all) when there's neither new evidence nor a changed
    decision to write, for cheap no-op cycles."""
    current_key = (decision["state"], decision["decision_path"])
    decision_changed = _last_decision_key.get(device_id) != current_key
    if not fresh_v2 and not decision_changed:
        return
    try:
        store = _get_graph_store()
        with store.transaction():
            for ev in fresh_v2:
                store.insert_evidence(ev)
            if decision_changed:
                store.insert_decision(
                    device_id=device_id, timestamp=timestamp,
                    state=decision["state"], decision_path=decision["decision_path"],
                    confidence=float(decision.get("threat_confidence", 0.0) or 0.0),
                    risk_score=float(decision.get("hypotheses", {}).get("attack", {}).get("score", 0.0) or 0.0),
                    raw_payload=decision,
                    evidence_ids=[ev.evidence_id for ev in merged_v2],
                )
                _last_decision_key[device_id] = current_key
    except Exception as e:
        LOGGER.error(
            "Failed to write evidence/decision to GraphStore for device %r -- the live "
            "decision itself is already made and unaffected by this: %s",
            device_id, e, exc_info=True,
        )


def evaluate(active_evidence_v1: List, rep_vector, device_type: str = "",
             baseline_familiarity: float = 0.0, features: Optional[dict] = None,
             is_safe: bool = False, fallback_evaluate=None,
             device_id: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """The live call site `pipeline.py` uses in place of
    `core/decision_engine.py`'s `DecisionEngine.evaluate()`. Same positional/keyword
    shape as v-current's own `evaluate()` (plus the new, optional `device_id`/`now`)
    so the original call site swap in pipeline.py stayed a one-line change; passing
    `device_id` is what opts a call into the graph read/write behavior described in
    this module's own docstring above -- omitting it (the default) is unaffected by
    any of that, identical to this function's pre-Phase-1 behavior."""
    try:
        fresh_v2 = _convert_active_evidence(active_evidence_v1, features or {})
        ts = now if now is not None else time.time()

        merged_v2 = fresh_v2
        if device_id:
            windowed_v2 = _query_graph_window(device_id, ts)
            seen_ids = {ev.evidence_id for ev in windowed_v2}
            merged_v2 = windowed_v2 + [ev for ev in fresh_v2 if ev.evidence_id not in seen_ids]

        decision = _v13_engine.evaluate(
            merged_v2, rep_vector, device_type=device_type,
            baseline_familiarity=baseline_familiarity, features=features, is_safe=is_safe,
            now=ts,
        )

        if device_id:
            _write_graph(device_id, ts, fresh_v2, merged_v2, decision)

        return decision
    except Exception as e:
        LOGGER.error(
            "v13 live engine raised %s -- falling back to v-current's decision engine "
            "for this cycle. This should never happen in normal operation; investigate.",
            e, exc_info=True,
        )
        if fallback_evaluate is not None:
            return fallback_evaluate(
                active_evidence_v1, rep_vector, device_type, baseline_familiarity,
                features=features, is_safe=is_safe,
            )
        raise
