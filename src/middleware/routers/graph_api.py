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

        # BUGFIX (console Evidence Graph tab loading slowly/timing out over a
        # client): get_decisions_since(0.0) pulled and JSON-deserialized EVERY
        # decision ever recorded just to Python-sort and keep the newest `limit` --
        # the same fetch-all-then-truncate anti-pattern this file's own docstring
        # already flags for edges, just not caught here. get_recent_decisions()
        # pushes ORDER BY timestamp DESC LIMIT into SQL instead (idx_decisions_timestamp).
        decisions = store.get_recent_decisions(limit)
        decision_ids = [d["decision_id"] for d in decisions]
        device_ids = sorted({d["device_id"] for d in decisions})

        evidence_edges = []
        edge_totals_by_decision = {}
        for did in decision_ids:
            edge_totals_by_decision[did] = store.count_edges(dst_kind="decision", dst_id=did)
            per_decision = store.get_edges(dst_kind="decision", dst_id=did, limit_most_recent=EVIDENCE_PER_DECISION_CAP)
            evidence_edges.extend(per_decision)
        evidence_ids = sorted({e["src_id"] for e in evidence_edges if e["src_kind"] == "evidence"})
        evidence_list = store.get_evidence_by_ids(evidence_ids)
        evidence_by_id = {e.evidence_id: e for e in evidence_list}

        destination_ids = sorted({e.destination_id for e in evidence_list})
        destinations = {did: store.get_destination(did) for did in destination_ids}

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

    for eid, ev in evidence_by_id.items():
        type_label, type_description = label_evidence_type(ev.evidence_type)
        nodes.append({
            "id": f"evidence:{eid}", "kind": "evidence",
            "label": ev.evidence_type, "sub": ev.independence_family,
            "confidence": ev.confidence, "timestamp": ev.timestamp, "source": ev.source,
            "type_label": type_label, "type_description": type_description,
            # console's column layout clusters each kind's rows by source device
            # so related nodes land on nearby y -- needs the raw device_id, not
            # just the "observed" edge, so it doesn't have to reverse-traverse
            # edges to figure out which device a node belongs to.
            "device_id": ev.device_id,
        })
        edges.append({"from": f"device:{ev.device_id}", "to": f"evidence:{eid}", "relation": "observed"})
        if ev.destination_id != "(none)":
            edges.append({"from": f"evidence:{eid}", "to": f"destination:{ev.destination_id}", "relation": "targets"})

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

    for e in evidence_edges:
        if e["src_kind"] != "evidence":
            continue
        edges.append({"from": f"evidence:{e['src_id']}", "to": f"decision:{e['dst_id']}", "relation": e["relation"]})

    return {"nodes": nodes, "edges": edges, "decision_count": len(decisions)}
