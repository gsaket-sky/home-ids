"""
graph_api.py -- real evidence-graph data for the console's Evidence Graph tab,
replacing its original sample nodes/edges.

Scoped to the most recent `limit` decisions, not the whole historical graph -- the
real deployment's state/v13_graph.db already has 5000+ decisions and 8M+ edges rows;
returning everything would be neither a useful visualization nor a fast response.

winning_hypothesis_id (schema.sql's own column on `decisions`) is never actually
populated by any v13 module yet -- confirmed empirically against the real deployment
(0 non-null rows out of 5050 decisions). The winning hypothesis's NAME is recovered
from each decision's own raw_payload_json["explanation"] instead, which IS reliably
populated (confirmed against real data: e.g. {"state": "BENIGN", "explanation":
"UNKNOWN_BENIGN", "hypotheses": {"attack": {"name": ...}, "benign": {"name": ...}}}).

EVIDENCE_PER_DECISION_CAP exists because of a real finding against the live deployment,
not a hypothetical: one decision (device 2d313502b7d0) had 56,073 supporting edges --
that device alone accounts for ~79% of all evidence rows in the whole database. Without
a per-decision cap, `limit=15` (decisions) still returns 57k+ nodes if even one of those
15 happens to be this kind of decision -- the decision count alone does not bound
response size. Capped to the most RECENT edges per decision (by edge timestamp), not an
arbitrary/opaque confidence-based subset -- "the latest evidence that fed this verdict"
is the honest, explainable thing to show when there's more than fits.

BUGFIX (query time, found live 2026-09-14): this endpoint used to issue one
count_edges()/get_edges() pair PER decision (50 separate round-trips for limit=25)
plus one get_destination() PER destination (~34 more) -- 84+ small queries against a
SQLite connection that's read-only against a database the main pipeline is
concurrently, heavily writing to. Each round-trip is a chance to land inside a
writer's transaction/checkpoint window and stall on Python sqlite3's default 5s
busy_timeout; confirmed live, the same logic ran in 0.08s standalone (no concurrent
writer) vs 0.96s-3.5s through the actual live API under real write load. Now uses
GraphStore's batched get_edges_capped_per_dst()/count_edges_grouped_by_dst()/
get_destinations_by_ids() -- 3 queries total regardless of how many decisions/
destinations are involved.

BUGFIX (graph readability, found live 2026-09-14, user report: "similar entries...
different timestamp"): confirmed against .94's real data that 147 of 230 evidence
nodes in a typical limit=25 response (64%) were just zeek_notice_weak/
zeek_notice_medium repeated for the same device -- the same recurring signal,
timestamped differently, rendered as separate nodes with no extra information the
type/family/destination/device doesn't already carry. Evidence is now grouped by
(device_id, evidence_type, independence_family, destination_id) into one compressed
node per group when more than one member exists, carrying a `count` and the
newest/oldest member's timestamps -- a single non-repeated evidence item is
unaffected (same shape as before, no `count` field). This also shrinks response size
proportionally, on top of the query-time fix above.

Node/edge layout (x/y positions) is NOT computed here -- the console's existing
client-side layout logic (grouping by kind into columns) already does that; this
endpoint returns plain kind/label/sub/relation data for it to consume.
"""
from fastapi import APIRouter, Depends, Query

from middleware.auth import verify_token, CONFIG
from middleware.graph_client import open_store
from middleware.humanize import label_evidence_type, label_hypothesis
from core.state_guard import StateManager

router = APIRouter()

# See module docstring -- a real decision in production had 56,073 supporting edges.
EVIDENCE_PER_DECISION_CAP = 15


@router.get("/api/graph")
def get_graph(limit: int = Query(25, ge=1, le=200), token: str = Depends(verify_token)):
    with open_store() as store:
        if store is None:
            return {"nodes": [], "edges": [], "decision_count": 0}

        decisions = store.get_recent_decisions(limit)
        decision_ids = [d["decision_id"] for d in decisions]
        device_ids = sorted({d["device_id"] for d in decisions})

        edge_totals_by_decision = store.count_edges_grouped_by_dst("decision", decision_ids)
        evidence_edges = store.get_edges_capped_per_dst("decision", decision_ids, EVIDENCE_PER_DECISION_CAP)

        evidence_ids = sorted({e["src_id"] for e in evidence_edges if e["src_kind"] == "evidence"})
        evidence_list = store.get_evidence_by_ids(evidence_ids)
        evidence_by_id = {e.evidence_id: e for e in evidence_list}

        destination_ids = sorted({e.destination_id for e in evidence_list})
        destinations = store.get_destinations_by_ids(destination_ids)

    sm = StateManager(state_path=CONFIG.get("state_path", "state/ids_state.json"))
    sm.load_from_disk()

    nodes = []
    edges = []

    for device_id in device_ids:
        hostname = None
        if sm.has_device(device_id):
            with sm.lock_device(device_id) as state:
                hostname = state.hostname
        nodes.append({
            "id": f"device:{device_id}", "kind": "device",
            "label": (hostname if hostname and hostname != "unknown" else device_id),
            "sub": device_id,
        })

    # --- group near-duplicate evidence into single compressed nodes -----------
    # See module docstring's second BUGFIX note. Grouping key deliberately
    # excludes timestamp/confidence -- those are exactly the fields that differ
    # between repeats of "the same thing happening again."
    groups: dict = {}
    for ev in evidence_by_id.values():
        key = (ev.device_id, ev.evidence_type, ev.independence_family, ev.destination_id)
        groups.setdefault(key, []).append(ev)

    evidence_id_to_node_id = {}
    for (device_id, evidence_type, family, destination_id), members in groups.items():
        members.sort(key=lambda e: e.timestamp)
        newest = members[-1]
        is_grouped = len(members) > 1
        node_id = (
            f"evidence-group:{device_id}|{evidence_type}|{family}|{destination_id}"
            if is_grouped else f"evidence:{newest.evidence_id}"
        )
        for m in members:
            evidence_id_to_node_id[m.evidence_id] = node_id

        type_label, type_description = label_evidence_type(evidence_type)
        node = {
            "id": node_id, "kind": "evidence",
            "label": evidence_type, "sub": family,
            "confidence": max(m.confidence for m in members),
            "timestamp": newest.timestamp,
            "source": newest.source,
            "type_label": type_label, "type_description": type_description,
            # console's column layout clusters each kind's rows by source device
            # so related nodes land on nearby y -- needs the raw device_id, not
            # just the "observed" edge, so it doesn't have to reverse-traverse
            # edges to figure out which device a node belongs to.
            "device_id": device_id,
        }
        if is_grouped:
            node["count"] = len(members)
            node["first_timestamp"] = members[0].timestamp
        nodes.append(node)

        edges.append({"from": f"device:{device_id}", "to": node_id, "relation": "observed"})
        if destination_id != "(none)":
            edges.append({"from": node_id, "to": f"destination:{destination_id}", "relation": "targets"})

    for did, dest in destinations.items():
        if dest is None or did == "(none)":
            continue
        nodes.append({"id": f"destination:{did}", "kind": "destination", "label": did, "sub": dest["kind"]})

    for d in decisions:
        winning = (d.get("raw_payload") or {}).get("explanation")
        winning_label, winning_description = label_hypothesis(winning)
        total_edges = edge_totals_by_decision.get(d["decision_id"], 0)
        nodes.append({
            "id": f"decision:{d['decision_id']}", "kind": "decision", "label": d["state"],
            "sub": d["decision_id"], "risk_score": d["risk_score"], "confidence": d["confidence"],
            "timestamp": d["timestamp"], "winning_hypothesis": winning,
            "winning_hypothesis_label": winning_label, "winning_hypothesis_description": winning_description,
            "evidence_total": total_edges,
            "evidence_truncated": total_edges > EVIDENCE_PER_DECISION_CAP,
            # see evidence node's own comment above -- same device-clustering reason.
            "device_id": d["device_id"],
        })

    # evidence->decision edges, rewritten to point at each evidence item's
    # (possibly grouped) node id, deduping repeats of the exact same
    # (node, decision, relation) triple that grouping alone would otherwise
    # produce -- e.g. 40 individually-timestamped zeek_notice_weak edges all
    # supporting the SAME decision collapse to one edge, not 40 overlapping
    # lines. Distinct relations (supports vs contradicts) to the same decision
    # are kept separate -- that's real structural information, not a repeat.
    seen_decision_edges = set()
    for e in evidence_edges:
        if e["src_kind"] != "evidence":
            continue
        node_id = evidence_id_to_node_id.get(e["src_id"])
        if node_id is None:
            continue
        key = (node_id, e["dst_id"], e["relation"])
        if key in seen_decision_edges:
            continue
        seen_decision_edges.add(key)
        edges.append({"from": node_id, "to": f"decision:{e['dst_id']}", "relation": e["relation"]})

    return {"nodes": nodes, "edges": edges, "decision_count": len(decisions)}
