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
import threading
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from middleware.auth import verify_token, CONFIG
from middleware.graph_client import open_store
from middleware.humanize import label_evidence_type, label_hypothesis
from core.state_guard import StateManager
from argus.graph.store import AlertSearchScopeTooLarge

router = APIRouter()

# See module docstring -- a real decision in production had 56,073 supporting edges.
EVIDENCE_PER_DECISION_CAP = 15

# Same "cap the busy-entity case" discipline as EVIDENCE_PER_DECISION_CAP above,
# applied to alert_events -- see GraphStore.get_alert_events_by_decision_ids()'s
# own docstring for why alert_events specifically (unlike evidence) can pile up
# per decision.
ALERT_EVENTS_PER_DECISION_CAP = 10


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

        # Alert-trace graph (2026-09-22, user request: "is it possible to show
        # [alerts] directly in graph"): the alert_events belonging to these SAME
        # decisions, capped per-decision by the store method itself -- see its
        # own docstring for why (a long-running incident's decision never
        # changes state, so alert_events -- deliberately never deduped, unlike
        # evidence -- can pile up against one decision_id).
        alert_events = store.get_alert_events_by_decision_ids(decision_ids, cap_per_decision=ALERT_EVENTS_PER_DECISION_CAP)

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

    # Alert-trace graph: alert_event nodes + decision->alert_event 'raised' edges.
    # Real facts about the alert (status/fp_verdict/explanation) live as columns
    # on this ONE node, not a second lookup -- same "scalar fact about one thing
    # stays a column" rule the alert_events table itself follows.
    for ae in alert_events:
        nodes.append({
            "id": f"alert_event:{ae['alert_event_id']}", "kind": "alert_event",
            "label": ae["status"], "sub": ae.get("explanation_text") or "",
            "timestamp": ae["timestamp"], "device_id": ae["device_id"],
            "fp_verdict": ae.get("fp_verdict"), "fp_confidence": ae.get("fp_confidence"),
            "incident_id": ae.get("incident_id"),
            # Plain-English narrative (2026-09-22, user request) -- built once at
            # write time by mitigation/plain_explanation.py, shown as-is here so
            # the console never has to re-derive it client-side.
            "plain_explanation": ae.get("plain_explanation"),
        })
        edges.append({
            "from": f"decision:{ae['decision_id']}", "to": f"alert_event:{ae['alert_event_id']}",
            "relation": "raised",
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


# ==============================================================================
# Alert-trace graph (Documentation/ALERT_TRACE_GRAPH_PLAN.md, 2026-09-22): the
# console's fired/suppressed alert list + bounded semantic search. Reads
# alert_events via the new indexed table (GraphStore.get_alert_events()/
# search_alert_events_by_embedding()), replacing _alert_log_utils.py's bounded-
# backward-scan hack over alerts.json's 170MB+ NDJSON file for this specific view.
# ==============================================================================

DEFAULT_ALERT_LIST_LIMIT = 50
MAX_ALERT_LIST_LIMIT = 200
DEFAULT_SEARCH_WINDOW_DAYS = 30.0
MAX_SEARCH_WINDOW_DAYS = 365.0


@router.get("/api/graph/alerts")
def get_alerts(
    limit: int = Query(DEFAULT_ALERT_LIST_LIMIT, ge=1, le=MAX_ALERT_LIST_LIMIT),
    offset: int = Query(0, ge=0),
    device_id: Optional[str] = None,
    since: Optional[float] = None,
    until: Optional[float] = None,
    status: Optional[str] = None,
    token: str = Depends(verify_token),
):
    """Paginated fired/suppressed alert list for the console -- one row per
    alert_events entry (append-only, never overwritten by a recurring
    incident -- see the plan doc), newest first."""
    with open_store() as store:
        if store is None:
            return {"alerts": [], "count": 0}
        alerts = store.get_alert_events(
            limit=limit, offset=offset, device_id=device_id,
            since=since, until=until, status=status,
        )
        return {"alerts": alerts, "count": len(alerts)}


# Lazy-loaded, process-local FastEmbed instance for embedding SEARCH QUERY text in
# this API process. Deliberately NOT the same in-memory object as the main pipeline
# process's fp_engine.py instance (they are separate OS processes -- middleware.
# main_api:app runs as its own uvicorn subprocess, per soc.service's own unit file)
# -- this is the smallest honest deviation from "reuse the exact same instance"
# the plan doc's resource analysis assumed: the underlying ~85MB ONNX model file is
# still the SAME already-disk-cached artifact (models/fastembed_cache/), so this is
# a cheap from-cache load, not a second real download/training cost, and it loads
# lazily on first search request (not at API startup) rather than slowing down
# every console page load for a feature most requests never touch.
_query_embed_model = None
_query_embed_lock = threading.Lock()


def _get_query_embed_model():
    global _query_embed_model
    if _query_embed_model is None:
        with _query_embed_lock:
            if _query_embed_model is None:
                from fastembed import TextEmbedding
                from pathlib import Path as _P
                # Matches fp_engine.py's own _model_dir() derivation EXACTLY
                # (config's model_path, defaulting to "models/ids_model.pkl") --
                # not state_path's own directory, a different one -- so this loads
                # the SAME already-downloaded cache the main pipeline process
                # already populated, never re-downloads.
                cache_dir = str(_P(CONFIG.get("model_path", "models/ids_model.pkl")).parent / "fastembed_cache")
                _query_embed_model = TextEmbedding(
                    model_name="BAAI/bge-small-en-v1.5", cache_dir=cache_dir, threads=1)
    return _query_embed_model


@router.get("/api/graph/alerts/search")
def search_alerts(
    q: str = Query(..., min_length=1, description="Natural-language search text"),
    device_id: Optional[str] = None,
    since: Optional[float] = None,
    until: Optional[float] = None,
    limit: int = Query(20, ge=1, le=100),
    token: str = Depends(verify_token),
):
    """Bounded semantic search over alert_events.explanation_text (plan doc's
    "Semantic search (bounded add-on)" section) -- survives this project's
    frequent evidence-type/hypothesis-taxonomy renames, e.g. finding an old
    "zeek_notice" alert when searching for its current "zeek_notice_weak" name.

    `since` is REQUIRED-in-effect: defaults to DEFAULT_SEARCH_WINDOW_DAYS (30)
    back, capped at MAX_SEARCH_WINDOW_DAYS (365) -- no unscoped "search
    everything" code path exists anywhere in this stack, per the plan doc's
    bounding rules. Returns HTTP 422 (not a silent truncation) if the scoped
    candidate set still exceeds GraphStore.ALERT_SEARCH_CANDIDATE_CAP -- the
    caller must narrow (shorter window and/or a device_id)."""
    now = time.time()
    if since is None:
        since = now - DEFAULT_SEARCH_WINDOW_DAYS * 86400
    elif since < now - MAX_SEARCH_WINDOW_DAYS * 86400:
        since = now - MAX_SEARCH_WINDOW_DAYS * 86400

    try:
        model = _get_query_embed_model()
        query_vector = list(model.embed([q]))[0].astype("float32").tobytes()
    except ImportError:
        raise HTTPException(status_code=503, detail="Semantic search unavailable: fastembed not installed.")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Semantic search embedding failed: {exc}")

    with open_store() as store:
        if store is None:
            return {"results": [], "count": 0}
        try:
            results = store.search_alert_events_by_embedding(
                query_vector, since=since, until=until, device_id=device_id, limit=limit,
            )
        except AlertSearchScopeTooLarge as exc:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Search scope too large ({exc.candidate_count} candidate alerts, "
                    f"cap is {exc.cap}) -- narrow the time window and/or specify a device_id."
                ),
            )
        return {"results": results, "count": len(results)}
