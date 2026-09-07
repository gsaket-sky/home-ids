"""
v13 full-architecture plan, Phase 8c: INDEPENDENCE_FAMILY_MAP validation report.

For every DIFFERENT_PATH divergence the comparator (v13/compare/divergence_log.py)
has already logged, looks up v13's own matching decision and its supporting
evidence, then asks one narrow, mechanical question: under v13's ACTUAL (finer,
INDEPENDENCE_FAMILY_MAP) split, does the independent-source count cross
HypothesisEngine's own 2-source corroboration bar differently than it would under
v-current's coarser, single-"zeek_network"-family grouping? This does NOT validate
the grouping choice itself -- that still needs real accumulated divergence data over
time, exactly as hypotheses/independence.py's own module docstring says ("treat this
mapping itself as a hypothesis to test... not a settled fact just because it's now
code") -- it turns "is this an open question" into a concrete, inspectable
per-divergence list instead of an unanswered flag in a docstring.

V1-EQUIVALENT COARSER GROUPING: reconstructed from hypotheses/independence.py's own
"KNOWN DISCREPANCY FROM v-CURRENT" docstring paragraph (confirmed via direct read,
not guessed) -- the three v13 families named there (tls_fingerprint,
network_behavior, data_transfer_pattern) collapse back into one "zeek_network"
family here; every other v13 family already agrees with v-current's own grouping
per that same paragraph, so nothing else needs remapping.

A DIFFERENT_PATH divergence itself doesn't carry v13's own decision_id or its
supporting evidence -- only state/decision_path (divergence_log.py's own Divergence
dataclass). This re-derives the SAME temporal-proximity match compare_window()
originally used (device_ip + timestamp within TOLERANCE_SECONDS) to get back to a
concrete decision_id, then reads its supporting evidence via the 'supports' edges
insert_decision() already writes (v13 full-architecture plan, Phase 1's evidence-
retention fix) -- no new graph capability needed, just a new reader.
"""
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SRC_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_SRC_DIR))

from v13.graph.store import GraphStore  # noqa: E402
from v13.compare.divergence_log import TOLERANCE_SECONDS  # noqa: E402
from v13.hypotheses.independence import family_for, NON_ATTACK_FAMILIES  # noqa: E402
from v13.ingest.daemon import load_config  # noqa: E402

LOGGER = logging.getLogger("v13.ops.independence_family_report")

# hypotheses/independence.py's own documented KNOWN DISCREPANCY -- these three v13
# families all collapse into v-current's single lumped "zeek_network" family.
_V1_LUMPED_ZEEK_NETWORK_TYPES = frozenset({
    "malicious_ja3", "malicious_ja4",
    "zeek_notice", "zeek_lateral_scan", "zeek_conn_abuse", "zeek_long_conn",
    "zeek_exfiltration", "zeek_beaconing",
})

# HypothesisEngine's own real corroboration bar (matches decision/engine.py's `>= 2`
# independent-source threshold used throughout this codebase's tier logic).
_CORROBORATION_BAR = 2


def _v1_equivalent_family(evidence_type: str) -> str:
    if evidence_type in _V1_LUMPED_ZEEK_NETWORK_TYPES:
        return "zeek_network"
    return family_for(evidence_type)


def _independent_source_counts(evidence_types: List[str]) -> Tuple[int, int]:
    """Returns (v13_actual_count, v1_equivalent_count) -- distinct families under
    v13's own finer split vs. v-current's coarser one, both excluding
    NON_ATTACK_FAMILIES (matches decision/engine.py's own attack_evidence filter,
    e.g. local_device_discovery/first_contact never count toward corroboration)."""
    attack_types = [t for t in evidence_types if family_for(t) not in NON_ATTACK_FAMILIES]
    v13_families = {family_for(t) for t in attack_types}
    v1_families = {_v1_equivalent_family(t) for t in attack_types}
    return len(v13_families), len(v1_families)


def _find_matching_decision(store: GraphStore, device_ip: str, timestamp: float,
                              tolerance_seconds: float = TOLERANCE_SECONDS) -> Optional[Dict[str, Any]]:
    """Re-derives the SAME temporal-proximity match divergence_log.py's own
    compare_window() used when it first classified this divergence."""
    candidates = store.get_decisions_since(timestamp - tolerance_seconds, until=timestamp + tolerance_seconds + 1)
    best, best_delta = None, None
    for d in candidates:
        if d["device_id"] != device_ip:
            continue
        delta = abs(d["timestamp"] - timestamp)
        if delta <= tolerance_seconds and (best_delta is None or delta < best_delta):
            best, best_delta = d, delta
    return best


def _supporting_evidence_types(store: GraphStore, decision_id: str) -> List[str]:
    edges = store.get_edges(relation="supports", dst_kind="decision", dst_id=decision_id)
    types: List[str] = []
    for e in edges:
        row = store._conn.execute(
            "SELECT evidence_type FROM evidence WHERE evidence_id = ?", (e["src_id"],)
        ).fetchone()
        if row:
            types.append(row["evidence_type"])
    return types


def generate_report(store: GraphStore, divergences: List[Dict[str, Any]],
                      tolerance_seconds: float = TOLERANCE_SECONDS) -> List[Dict[str, Any]]:
    """Takes already-loaded divergence dicts (e.g. from state/v13_divergence.jsonl),
    returns one report row per DIFFERENT_PATH divergence whose matching v13
    decision could still be found. A divergence whose decision has since aged out
    of retention (live_prune.py) or was never written (a best-effort graph-write
    failure that cycle) is silently skipped, not fatal -- this report is advisory
    tooling, not an audit trail of its own."""
    rows: List[Dict[str, Any]] = []
    for div in divergences:
        if div.get("kind") != "DIFFERENT_PATH":
            continue
        decision = _find_matching_decision(store, div["device_ip"], div["timestamp"], tolerance_seconds)
        if decision is None:
            continue
        evidence_types = _supporting_evidence_types(store, decision["decision_id"])
        v13_count, v1_count = _independent_source_counts(evidence_types)
        family_split_contributed = (v13_count >= _CORROBORATION_BAR) != (v1_count >= _CORROBORATION_BAR)
        rows.append({
            "timestamp": div["timestamp"],
            "device_ip": div["device_ip"],
            "v13_decision_path": div.get("v13_decision_path"),
            "vcurrent_decision_path": div.get("vcurrent_decision_path"),
            "evidence_types": sorted(evidence_types),
            "v13_independent_sources_actual": v13_count,
            "v13_independent_sources_v1_equivalent": v1_count,
            "family_split_contributed": family_split_contributed,
        })
    return rows


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not path.exists():
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def run_once(config: dict) -> List[Dict[str, Any]]:
    compare_cfg = config.get("compare", {})
    ingest_cfg = config.get("ingest", {})
    divergence_path = Path(compare_cfg.get("output_path", "state/v13_divergence.jsonl"))
    graph_db_path = Path(ingest_cfg.get("graph_db_path", "state/v13_graph.db"))
    report_path = Path(compare_cfg.get("independence_report_path", "state/independence_family_report_v13.jsonl"))

    if not graph_db_path.exists():
        LOGGER.warning("Graph db %s does not exist yet -- nothing to report on.", graph_db_path)
        return []

    divergences = _load_jsonl(divergence_path)
    store = GraphStore(str(graph_db_path))
    try:
        rows = generate_report(store, divergences)
    finally:
        store.close()

    if rows:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        # A fresh, complete recompute every run (overwrite, not append) -- the
        # input divergence log is itself read fresh in full each time, so this
        # stays trivially idempotent with no dedup bookkeeping of its own needed.
        with open(report_path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")

    contributing = sum(1 for r in rows if r["family_split_contributed"])
    LOGGER.info(
        "Independence-family report: %d DIFFERENT_PATH divergence(s) examined, %d where "
        "the finer family split changed whether the %d-source corroboration bar was crossed.",
        len(rows), contributing, _CORROBORATION_BAR,
    )
    return rows


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    config = load_config(explicit_path)
    run_once(config)


if __name__ == "__main__":
    main()
