"""
decision_replay.py - Release 14, net-new capability N3 (Documentation/
V13_FULL_ARCHITECTURE_SHIFT_PLAN.md, "now possible, not yet built"): decision
replay / regression testing.

Re-runs any historical decision's REAL supporting evidence (preserved via the
graph's own `supports` edges -- Phase 1's own evidence-retention fix exists
specifically so this stays possible) through the CURRENT
HypothesisEngine/DecisionEngine code, and reports whether the verdict would
change. The direct, concrete value this project's own "now possible" framing
named: de-risk a future hypothesis/scoring change against real historical
incidents, before it ships live -- not just synthetic test scenarios.

NOT a scheduled job, not part of soc.service -- a manual/CI-style diagnostic
tool. Run directly:
  python3 src/v13/ops/decision_replay.py --since-days 7
  python3 src/v13/ops/decision_replay.py --since-days 30 --device-id <id>
  python3 src/v13/ops/decision_replay.py --db /path/to/v13_graph.db --since-days 1 --changed-only

REAL, DOCUMENTED LIMITATION, not hidden: a decision's `rep` (ReputationVector),
`device_type`, `baseline_familiarity`, and `is_safe` context at the time it was
made are NOT stored on the decision row and can't be perfectly reconstructed
from evidence alone. `_rep_from_evidence()` derives a best-effort duck-typed
rep from any 'reputation' evidence item present; device_type/baseline_
familiarity/is_safe default to their safe/neutral values unless overridden.
This tool answers "does the CURRENT hypothesis-scoring logic reach a different
verdict against the SAME real evidence" -- a real, useful regression signal
that doesn't require a byte-perfect environment reconstruction to be valid.
"""
import argparse
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))  # -> src/

from v13.decision.engine import DecisionEngine as V13DecisionEngine  # noqa: E402
from v13.evidence.model import Evidence  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402


def get_decision_evidence(store: GraphStore, decision: Dict[str, Any]) -> List[Evidence]:
    """The decision's own real supporting evidence, resolved via its 'supports'
    edges. Reuses get_evidence_for_device() (no new GraphStore method needed)
    filtered down to just the evidence_ids the edges actually name -- a decision
    made before A14's evidence_ids wiring (or one whose evidence has since aged
    past its own 90-day retention, correctly exempted while a NEWER decision
    references it, but this one might be older) legitimately has zero supports
    edges; callers must treat that as "no evidence available to replay", not a
    trivial all-BENIGN comparison."""
    edges = store.get_edges(relation="supports", dst_kind="decision", dst_id=decision["decision_id"])
    supporting_ids = {e["src_id"] for e in edges}
    if not supporting_ids:
        return []
    all_evidence = store.get_evidence_for_device(decision["device_id"], resolve_merges=False)
    return [e for e in all_evidence if e.evidence_id in supporting_ids]


def _rep_from_evidence(evidence_list: List[Evidence]) -> Any:
    """Best-effort ReputationVector-like duck object -- see this module's own
    top-of-file docstring for exactly what is and isn't recoverable."""
    rep_items = [e for e in evidence_list if e.evidence_type == "reputation"]
    tier = int(max(rep_items, key=lambda e: e.confidence).value) if rep_items else 0
    return SimpleNamespace(
        tier=tier, verified_ioc=False, domain="", asn_owner="Unknown",
        vt_detection_ratio=0.0, ti_risk=0.0, abuse_risk=0.0,
    )


def replay_decision(store: GraphStore, decision: Dict[str, Any],
                      decision_engine: Optional[V13DecisionEngine] = None) -> Dict[str, Any]:
    """Re-runs the CURRENT DecisionEngine against one historical decision's real
    evidence. Returns a comparison dict -- never raises; a re-evaluation failure
    is reported as its own outcome, not a crashed batch run."""
    base = {
        "decision_id": decision["decision_id"],
        "device_id": decision["device_id"],
        "timestamp": decision["timestamp"],
        "old_state": decision["state"],
        "old_decision_path": decision["decision_path"],
    }
    evidence_list = get_decision_evidence(store, decision)
    if not evidence_list:
        return {**base, "outcome": "no_evidence_available"}
    try:
        engine = decision_engine or V13DecisionEngine()
        rep = _rep_from_evidence(evidence_list)
        new_result = engine.evaluate(evidence_list, rep, now=decision["timestamp"])
    except Exception as e:
        return {**base, "outcome": "replay_error", "error": str(e)}
    changed = (new_result["state"] != decision["state"]
               or new_result["decision_path"] != decision["decision_path"])
    return {
        **base,
        "outcome": "changed" if changed else "unchanged",
        "evidence_count": len(evidence_list),
        "new_state": new_result["state"],
        "new_decision_path": new_result["decision_path"],
    }


def replay_range(store: GraphStore, since: float, until: Optional[float] = None,
                   device_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Replays every decision in [since, until] (device_id-filtered if given).
    Not itself a scheduled job -- callers (main() below, or an interactive
    session) decide the window and what to do with the report."""
    decision_engine = V13DecisionEngine()
    decisions = store.get_decisions_since(since)
    if until is not None:
        decisions = [d for d in decisions if d["timestamp"] <= until]
    if device_id is not None:
        decisions = [d for d in decisions if d["device_id"] == device_id]
    return [replay_decision(store, d, decision_engine=decision_engine) for d in decisions]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--db", default="state/v13_graph.db", help="Path to v13_graph.db")
    parser.add_argument("--since-days", type=float, default=7.0,
                         help="Replay decisions from this many days ago through now")
    parser.add_argument("--device-id", default=None, help="Limit to one device_id")
    parser.add_argument("--changed-only", action="store_true",
                         help="Only print decisions whose verdict would change")
    parser.add_argument("--out", default=None, help="Optional path to write the full JSONL report")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"No graph database at {db_path} -- nothing to replay.", file=sys.stderr)
        sys.exit(1)

    store = GraphStore(str(db_path))
    since = time.time() - args.since_days * 86400
    results = replay_range(store, since, device_id=args.device_id)
    store.close()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")

    changed = [r for r in results if r["outcome"] == "changed"]
    unchanged = [r for r in results if r["outcome"] == "unchanged"]
    no_evidence = [r for r in results if r["outcome"] == "no_evidence_available"]
    errors = [r for r in results if r["outcome"] == "replay_error"]

    for r in (changed if args.changed_only else results):
        if r["outcome"] == "changed":
            print(f"[CHANGED] {r['device_id']} @ {r['timestamp']:.0f}: "
                  f"{r['old_state']}/{r['old_decision_path']} -> {r['new_state']}/{r['new_decision_path']} "
                  f"({r['evidence_count']} evidence item(s))")
        elif not args.changed_only:
            print(f"[{r['outcome']}] {r['device_id']} @ {r['timestamp']:.0f}")

    print(f"\n{len(results)} decision(s) replayed: {len(changed)} changed, {len(unchanged)} unchanged, "
          f"{len(no_evidence)} no-evidence-available, {len(errors)} error(s).")


if __name__ == "__main__":
    main()
