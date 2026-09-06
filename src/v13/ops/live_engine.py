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
"""
import logging
from typing import Any, Dict, List, Optional

from v13.evidence.ingest import convert_list
from v13.hypotheses.independence import INDEPENDENCE_FAMILY_MAP
from v13.decision.engine import DecisionEngine as V13DecisionEngine

LOGGER = logging.getLogger("home_ids.v13_live_engine")

# Mirrors src/v13/ingest/sources.py's _NEEDS_LAST_DEST_IP_FALLBACK / _NO_DEST_SENTINEL
# exactly -- these two v-current detectors (threat_signals.py:247-274) never set
# Evidence.domain themselves; everyone else either sets it directly or has no domain
# concept at all, so a fallback would be misleading, not helpful.
_NEEDS_LAST_DEST_IP_FALLBACK = frozenset({"zeek_exfiltration", "zeek_beaconing"})
_NO_DEST_SENTINEL = "unknown"  # ZeekFeatureExtractor._last_connection_meta's own "no data yet" sentinel

_v13_engine = V13DecisionEngine()


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


def evaluate(active_evidence_v1: List, rep_vector, device_type: str = "",
             baseline_familiarity: float = 0.0, features: Optional[dict] = None,
             is_safe: bool = False, fallback_evaluate=None) -> Dict[str, Any]:
    """The live call site `pipeline.py` uses in place of
    `core/decision_engine.py`'s `DecisionEngine.evaluate()`. Same positional/keyword
    shape as v-current's own `evaluate()` so the call site swap in pipeline.py is a
    one-line change, not a signature rework."""
    try:
        v2_evidence = _convert_active_evidence(active_evidence_v1, features or {})
        return _v13_engine.evaluate(
            v2_evidence, rep_vector, device_type=device_type,
            baseline_familiarity=baseline_familiarity, features=features, is_safe=is_safe,
        )
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
