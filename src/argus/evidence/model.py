"""
v13 Evidence v2 (Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Fixes reviewer #17 (_select_target_domain()'s heuristic, pipeline.py:2626) at the
root: destination attribution is MANDATORY on every Evidence item, never a silently
absent .domain the way today's Evidence (hypotheses/evidence.py) allows. A detector
with no real destination for a given piece of evidence must say so explicitly via
NO_DESTINATION -- "no target" becomes a queryable fact, not an absent column that
downstream code has to guess about or patch around with a per-signature override.

independence_family is a SEPARATE field from evidence_type -- the core design
correction carried into every v13 module (see the plan's own writeup of Phase 64's
postmortem): "what a hypothesis's own evaluate() reads" (evidence_type, matched
against HYPOTHESIS_RELEVANT_EVIDENCE_TYPES) and "what can legitimately corroborate
it" (independence_family, matched against the new INDEPENDENCE_FAMILY_MAP,
hypotheses/independence.py) are different questions and must never be read from the
same column -- that conflation is what broke the first per-hypothesis independence
attempt in v-current.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import uuid

# Matches graph/schema.sql's seeded destinations row -- the explicit "this evidence
# genuinely has no destination" sentinel, never a silent None/absent field.
NO_DESTINATION = "(none)"


def new_evidence_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Evidence:
    device_id: str
    destination_id: str          # mandatory -- use NO_DESTINATION, never "" or None
    evidence_type: str           # e.g. "dns_tunnel_v2", "malicious_ja3" -- what a Hypothesis.evaluate() reads
    independence_family: str     # e.g. "dns_behavior", "tls_fingerprint" -- what can corroborate across families
    timestamp: float
    source: str                  # detector module that produced this item
    confidence: float = 1.0
    value: Optional[float] = None
    provenance: str = ""
    features: Dict[str, Any] = field(default_factory=dict)
    evidence_id: str = field(default_factory=new_evidence_id)

    def __post_init__(self) -> None:
        if not self.device_id:
            raise ValueError("Evidence.device_id is mandatory")
        if not self.destination_id:
            raise ValueError(
                "Evidence.destination_id is mandatory -- pass NO_DESTINATION "
                "explicitly for evidence with no real target, never '' or None"
            )
        if not self.evidence_type:
            raise ValueError("Evidence.evidence_type is mandatory")
        if not self.independence_family:
            raise ValueError(
                "Evidence.independence_family is mandatory -- see "
                "hypotheses/independence.py's INDEPENDENCE_FAMILY_MAP for the "
                "registry this should come from, never left blank or copied "
                "from evidence_type"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Evidence.confidence must be in [0.0, 1.0], got {self.confidence}")

    def effective_weight(self, freshness: float = 1.0) -> float:
        """Mirrors v-current's Evidence.effective_weight() (hypotheses/evidence.py)
        -- confidence * freshness. Freshness is NOT stored on the item itself here
        (unlike v-current's EvidenceStore-managed decay) -- it's a property of *when*
        a query runs relative to the item's timestamp, computed by the caller
        (graph/window.py, Phase 1) at query time, not baked into the stored row."""
        return self.confidence * freshness

    def to_row(self) -> Dict[str, Any]:
        """Serialization matching graph/schema.sql's evidence table columns exactly
        -- graph/store.py (Phase 1) uses this rather than hand-mapping fields at
        each call site."""
        import json
        return {
            "evidence_id": self.evidence_id,
            "device_id": self.device_id,
            "destination_id": self.destination_id,
            "evidence_type": self.evidence_type,
            "independence_family": self.independence_family,
            "value": self.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "source": self.source,
            "provenance": self.provenance,
            "features_json": json.dumps(self.features),
        }

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "Evidence":
        import json
        return cls(
            evidence_id=row["evidence_id"],
            device_id=row["device_id"],
            destination_id=row["destination_id"],
            evidence_type=row["evidence_type"],
            independence_family=row["independence_family"],
            value=row["value"],
            confidence=row["confidence"],
            timestamp=row["timestamp"],
            source=row["source"],
            provenance=row["provenance"],
            features=json.loads(row["features_json"]) if row.get("features_json") else {},
        )
