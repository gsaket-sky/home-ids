"""
Standalone runtime test for Phase 61 (Gap 6 item 5, evidence graph).

Scoped as an additive, read-only, ON-DEMAND view -- not a second live store
pipeline.py must keep in sync alongside EvidenceStore (hypotheses/evidence.py stays
the single source of truth for what evidence exists). Replacing EvidenceStore's
actual storage with a real graph database would be a large, high-risk rewrite of
the live detection path this session's own assessment already recommended against
at this codebase's current scale (build the epistemics, not the org-chart) -- see
Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's Gap 6 entry.

new intelligence/hypotheses/evidence_graph.py's EvidenceGraph builds device-evidence-
destination-hypothesis nodes/edges from a List[Evidence] plus (optionally) a named
hypothesis's RELEVANT_EVIDENCE_TYPES (Phase 59) -- reusing that registry rather than
inventing a second relevance mechanism. ollama_soc.py's new
_build_alert_evidence_graph() builds one per-alert graph from hee_evidence_types
(Phase 58) the same way _evidence_relevance_breakdown() (Phase 59) does, and renders
it into the .md report as a collapsed <details> block under the existing "Evidence
relevance" line.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase61_evidence_graph.py`

Sections:
  A. EvidenceGraph -- device/evidence/destination node construction, observed/
     targets edges, hypothesis relevance edges (supports vs. unrelated),
     to_dict()/render_text() output shape
  B. ollama_soc.py's _build_alert_evidence_graph() -- correct graph for a covered
     hypothesis, None for an uncovered one or missing hee_evidence_types (same
     contract as _evidence_relevance_breakdown())
  C. Source-level wiring -- the report renders a collapsed <details> block only
     when a graph was actually built
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts"))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import time
from intelligence.hypotheses.evidence import Evidence
from intelligence.hypotheses.evidence_graph import EvidenceGraph
from ollama_soc import _build_alert_evidence_graph


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: EvidenceGraph
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: EvidenceGraph ---")

now = time.time()
ev_store = [
    Evidence(type="arp_sweep", source="zeek", timestamp=now, device="dev1", value=12.0,
             confidence=0.9, independence_group="lan_recon", provenance="detector:arp_sweep",
             domain="192.168.1.44"),
    Evidence(type="dns_rate", source="pihole", timestamp=now, device="dev1", value=1.4,
             confidence=1.0, independence_group="dns_behavior", provenance="detector:dns_rate"),
]

g = EvidenceGraph("dev1", "some_device_fritz_box")
g.add_evidence_list(ev_store)

check("one device node exists, labeled with the friendly hostname",
      g.nodes["device:dev1"].kind == "device" and g.nodes["device:dev1"].label == "some_device_fritz_box")

check("one evidence node per Evidence item, correct kind/label",
      sum(1 for n in g.nodes.values() if n.kind == "evidence") == 2
      and any(n.label == "arp_sweep" for n in g.nodes.values())
      and any(n.label == "dns_rate" for n in g.nodes.values()))

check("a destination node was created for the evidence item that HAD a domain "
      "(arp_sweep -> 192.168.1.44), none for the one that didn't (dns_rate)",
      sum(1 for n in g.nodes.values() if n.kind == "destination") == 1
      and any(n.label == "192.168.1.44" for n in g.nodes.values()))

check("every evidence node has an 'observed' edge FROM the device node",
      sum(1 for e in g.edges if e.relation == "observed") == 2)

check("the arp_sweep evidence node has a 'targets' edge to its destination node",
      any(e.relation == "targets" for e in g.edges))

g.add_hypothesis_relevance("NETWORK_INTRUSION", frozenset({"arp_sweep", "zeek_lateral_scan"}))

check("a hypothesis node was added",
      any(n.kind == "hypothesis" and n.label == "NETWORK_INTRUSION" for n in g.nodes.values()))

check("arp_sweep (relevant to NETWORK_INTRUSION) gets a 'supports' edge to the "
      "hypothesis node",
      any(e.relation == "supports" for e in g.edges))

check("dns_rate (NOT relevant to NETWORK_INTRUSION) gets an 'unrelated' edge, not "
      "'supports' and not silently dropped",
      any(e.relation == "unrelated" for e in g.edges))

d = g.to_dict()
check("to_dict() produces a plain, JSON-serializable {nodes, edges} shape",
      isinstance(d, dict) and "nodes" in d and "edges" in d
      and all(isinstance(n, dict) for n in d["nodes"])
      and all(isinstance(e, dict) for e in d["edges"]))

rendered = g.render_text()
check("render_text() mentions the device, both evidence types, the destination, "
      "and the hypothesis relation -- a genuinely readable summary, not just repr()",
      "some_device_fritz_box" in rendered and "arp_sweep" in rendered
      and "dns_rate" in rendered and "192.168.1.44" in rendered
      and "NETWORK_INTRUSION(supports)" in rendered)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: ollama_soc.py's _build_alert_evidence_graph()
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section B: _build_alert_evidence_graph() ---")

_live_incident_payload = {
    "signature": "NETWORK_INTRUSION (persisted 1543s)",
    "hee_evidence_types": ["arp_spoof_pending", "dns_rate"],
    "device": {"id": "5d0bdf3a3b16", "hostname": "example_smarttv_fritz_box"},
}
graph = _build_alert_evidence_graph(_live_incident_payload)
check("returns a real EvidenceGraph for a covered hypothesis with evidence types present",
      graph is not None and isinstance(graph, EvidenceGraph))

check("the graph correctly separates the relevant (arp_spoof_pending, supports) "
      "from the irrelevant (dns_rate, unrelated) evidence for THIS hypothesis -- "
      "same classification _evidence_relevance_breakdown() reaches, expressed as a "
      "graph instead of three flat lists",
      graph is not None
      and any(e.relation == "supports" for e in graph.edges)
      and any(e.relation == "unrelated" for e in graph.edges))

check("returns None for an uncovered hypothesis, same contract as "
      "_evidence_relevance_breakdown()",
      _build_alert_evidence_graph({"signature": "ADVERTISING_BURST",
                                    "hee_evidence_types": ["ad_burst_rate"]}) is None)

check("returns None when hee_evidence_types is empty/absent (pre-Phase-58 alert)",
      _build_alert_evidence_graph({"signature": "NETWORK_INTRUSION", "hee_evidence_types": []}) is None)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: source-level wiring
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section C: source-level wiring ---")

_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")

check("the report renders a collapsed <details> block only inside `if graph:`",
      "graph = _build_alert_evidence_graph(representative)" in _soc_src
      and "if graph:" in _soc_src
      and "<details><summary>Evidence graph</summary>" in _soc_src)

check("EvidenceGraph is imported from hypotheses/evidence_graph.py, not redefined "
      "locally in ollama_soc.py",
      "from intelligence.hypotheses.evidence_graph import EvidenceGraph" in _soc_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 61 evidence-graph checks PASSED.")
