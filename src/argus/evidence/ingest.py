"""
v13 evidence ingest adapter (Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).
Converts v-current's Evidence (intelligence/hypotheses/evidence.py) into v13's
Evidence v2 (v13/evidence/model.py) at one chokepoint, so every v13 module downstream
can rely on mandatory destination attribution without re-deriving it per detector.

HONEST SCOPE NOTE (do not overclaim): this adapter guarantees every v2 Evidence item
HAS a destination_id (NO_DESTINATION when nothing better is available) -- it does
NOT retroactively fix the two detectors (zeek_exfiltration, zeek_beaconing --
threat_signals.py:247-274, confirmed via direct research this session) that build
their v1 Evidence without ever setting .domain at all. Fixing THOSE at the source
means threading real dest_ip/domain context into those two detectors' own call
sites -- separate, tracked, not-yet-done work (see the dependency map's open items).
This adapter's `fallback_context` param exists specifically so a caller that HAS
that context available (e.g. pipeline.py's own connection-tuple data) can supply it
without waiting on that upstream detector fix -- best-effort, not a substitute for it.
"""
import ipaddress
from typing import Any, Dict, Optional

from argus.evidence.model import Evidence, NO_DESTINATION

try:
    from intelligence.hypotheses.evidence import Evidence as V1Evidence
except ImportError:  # pragma: no cover -- only used for isinstance checks below
    V1Evidence = None


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def convert(v1_evidence: Any, independence_family: str,
             fallback_context: Optional[Dict[str, Any]] = None) -> Evidence:
    """Converts one v-current Evidence item to v13 Evidence v2.

    independence_family is REQUIRED and passed explicitly by the caller (from
    hypotheses/independence.py's INDEPENDENCE_FAMILY_MAP, Phase 3) rather than
    read off v1's own `independence_group` -- v1's field conflates "which family
    this evidence belongs to for reporting" with what v13 needs independence_family
    to mean specifically ("what can legitimately corroborate this for scoring
    purposes"), the exact Phase 64 category-error this project already hit once.
    Reusing v1's value blindly would silently reintroduce that same conflation
    into v13 -- so it's never read from v1_evidence here, even though the field
    exists and looks tempting to reuse.

    fallback_context, if given, may carry 'dest_ip' and/or 'dest_domain' -- checked
    only when v1_evidence.domain is None. Prefers dest_domain over dest_ip when
    both are present (matches this codebase's own existing preference, e.g.
    pipeline.py's target-selection logic).
    """
    domain = getattr(v1_evidence, "domain", None)
    if not domain and fallback_context:
        domain = fallback_context.get("dest_domain") or fallback_context.get("dest_ip")
    destination_id = domain if domain else NO_DESTINATION

    return Evidence(
        device_id=v1_evidence.device,
        destination_id=destination_id,
        evidence_type=v1_evidence.type,
        independence_family=independence_family,
        timestamp=v1_evidence.timestamp,
        source=v1_evidence.source,
        confidence=v1_evidence.confidence,
        value=v1_evidence.value,
        provenance=v1_evidence.provenance or f"v13_ingest:{v1_evidence.source}",
        features={"baseline": v1_evidence.baseline} if v1_evidence.baseline is not None else {},
    )


def convert_list(v1_evidence_list, independence_family_lookup: Dict[str, str],
                   default_independence_family: str = "general",
                   fallback_context: Optional[Dict[str, Any]] = None):
    """Batch form. independence_family_lookup maps evidence_type -> family (the
    INDEPENDENCE_FAMILY_MAP shape, Phase 3) -- falls back to
    default_independence_family for any evidence_type not yet registered there,
    so ingest never crashes on a type the map hasn't caught up to yet, but that
    fallback is visible (features['independence_family_defaulted']=True), not silent."""
    out = []
    for ev in v1_evidence_list:
        family = independence_family_lookup.get(ev.type)
        defaulted = family is None
        v2 = convert(ev, family or default_independence_family, fallback_context=fallback_context)
        if defaulted:
            v2.features["independence_family_defaulted"] = True
        out.append(v2)
    return out
