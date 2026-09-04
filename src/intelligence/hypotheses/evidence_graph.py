"""
PHASE 61 (Gap 6 item 5, evidence graph -- Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md):
a device<->destination<->evidence<->hypothesis graph, built ON DEMAND from data that
already exists -- NOT a second live store pipeline.py must keep in sync alongside
EvidenceStore (hypotheses/evidence.py). EvidenceStore stays the single source of
truth for what evidence exists; EvidenceGraph is a read-only, derived VIEW over it
(plus a HypothesisEngine result), reusable for reporting/debugging/future
visualization without touching the live evidence-collection path at all.

Deliberately scoped this way rather than a full graph-database rewrite: the third-
party review's proposed architecture treats "Evidence Graph" as a first-class
storage layer between the Evidence Engine and the Hypothesis Engine. Replacing
EvidenceStore's actual storage would be a large, high-risk rewrite of the live
detection path for a benefit this codebase's current scale doesn't clearly need --
see this session's own assessment (asked and answered explicitly: build the
epistemics, not the org-chart). A derived, on-demand graph view captures the same
"how does this device's evidence connect to destinations and hypotheses" question
the original review was actually asking, without that risk.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from intelligence.hypotheses.evidence import Evidence


@dataclass
class GraphNode:
    node_id: str
    kind: str  # "device" | "destination" | "evidence" | "hypothesis"
    label: str
    attrs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    src_id: str
    dst_id: str
    relation: str  # "observed" | "targets" | "supports" | "contradicts" | "unrelated"


class EvidenceGraph:
    """Nodes: one `device` node, one `destination` node per distinct evidence.domain
    seen, one `evidence` node per Evidence item, and (if a HypothesisEngine result is
    added) one `hypothesis` node per named attack/benign winner. Edges: device
    `observed` each evidence item; an evidence item `targets` its destination (if
    any); an evidence item `supports`/`contradicts`/`unrelated` a hypothesis, per
    HYPOTHESIS_RELEVANT_EVIDENCE_TYPES (hypotheses/engine.py, Phase 59) -- reusing
    that same relevance registry rather than inventing a second one."""

    def __init__(self, device_id: str, device_label: Optional[str] = None):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._device_node_id = f"device:{device_id}"
        self.nodes[self._device_node_id] = GraphNode(
            self._device_node_id, "device", device_label or device_id, {"device_id": device_id},
        )

    def _destination_node_id(self, destination: str) -> str:
        return f"destination:{destination}"

    def _evidence_node_id(self, ev: Evidence, idx: int) -> str:
        # PHASE 61: Evidence has no stable identity field of its own (two items can
        # share every field except timestamp) -- idx (position in the list passed to
        # add_evidence_list()) plus type/timestamp keeps node ids unique and stable
        # within one graph build without needing to add an id field to Evidence
        # itself, which every other consumer of that dataclass would then have to
        # tolerate.
        return f"evidence:{ev.type}:{ev.timestamp}:{idx}"

    def add_evidence_list(self, ev_store: List[Evidence]) -> None:
        for idx, ev in enumerate(ev_store):
            ev_node_id = self._evidence_node_id(ev, idx)
            self.nodes[ev_node_id] = GraphNode(
                ev_node_id, "evidence", ev.type,
                {"value": ev.value, "confidence": ev.confidence, "source": ev.source,
                 "independence_group": ev.independence_group, "provenance": ev.provenance},
            )
            self.edges.append(GraphEdge(self._device_node_id, ev_node_id, "observed"))
            if ev.domain:
                dest_id = self._destination_node_id(ev.domain)
                if dest_id not in self.nodes:
                    self.nodes[dest_id] = GraphNode(dest_id, "destination", ev.domain, {})
                self.edges.append(GraphEdge(ev_node_id, dest_id, "targets"))

    def add_hypothesis_relevance(self, hypothesis_name: str, relevant_evidence_types: frozenset,
                                  hypothesis_kind: str = "attack") -> None:
        """Adds a hypothesis node and one relation edge FROM every evidence node
        already in this graph -- "supports" if that evidence's type is in
        relevant_evidence_types, "unrelated" otherwise (deliberately not
        "contradicts" -- distinguishing genuine negative/contradicting evidence from
        merely-irrelevant evidence needs per-hypothesis logic this graph doesn't
        reimplement, see Phase 59's own comment on why that stayed out of scope for
        a structural, non-content-judging check)."""
        hyp_node_id = f"hypothesis:{hypothesis_name}"
        self.nodes[hyp_node_id] = GraphNode(hyp_node_id, "hypothesis", hypothesis_name, {"kind": hypothesis_kind})
        for node_id, node in list(self.nodes.items()):
            if node.kind != "evidence":
                continue
            relation = "supports" if node.label in relevant_evidence_types else "unrelated"
            self.edges.append(GraphEdge(node_id, hyp_node_id, relation))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {"id": n.node_id, "kind": n.kind, "label": n.label, "attrs": n.attrs}
                for n in self.nodes.values()
            ],
            "edges": [
                {"src": e.src_id, "dst": e.dst_id, "relation": e.relation} for e in self.edges
            ],
        }

    def render_text(self) -> str:
        """Compact, human-readable rendering for a report -- one line per
        device->evidence->(destination/hypothesis) path, not a full node/edge dump."""
        lines = []
        device_node = self.nodes[self._device_node_id]
        lines.append(f"{device_node.label}")
        for edge in self.edges:
            if edge.relation != "observed":
                continue
            ev_node = self.nodes[edge.dst_id]
            targets = [self.nodes[e.dst_id].label for e in self.edges
                       if e.src_id == edge.dst_id and e.relation == "targets"]
            hyp_edges = [e for e in self.edges if e.src_id == edge.dst_id and e.relation in ("supports", "contradicts")]
            suffix = ""
            if targets:
                suffix += f" -> {targets[0]}"
            if hyp_edges:
                hyp_labels = ", ".join(f"{self.nodes[e.dst_id].label}({e.relation})" for e in hyp_edges)
                suffix += f"  [{hyp_labels}]"
            lines.append(f"  +- {ev_node.label}{suffix}")
        return "\n".join(lines)
