"""
threat_hunt.py - Release 14, net-new capability N1 (Documentation/
ARGUS_AUTONOMY_DEPENDENCY_MAP.md, "now possible, not yet built"): an ad-hoc
historical threat-hunting surface.

"Show every device that ever touched X" or "trace the full evidence timeline
behind this decision" as a direct query, not a log grep -- the data's already
indexed and relational (argus's whole point); this was a query-surface problem,
not a storage problem, so this file is deliberately thin: three small
functions over GraphStore's own already-built read methods, plus a CLI.

NOT a scheduled job, not part of soc.service -- a manual diagnostic tool for an
operator or a future session investigating a real incident. Run directly:

  python3 src/argus/ops/threat_hunt.py devices --destination evil.example.com
  python3 src/argus/ops/threat_hunt.py timeline --decision-id <decision_id>
  python3 src/argus/ops/threat_hunt.py device --device-id <device_id> [--since-days N]
"""
import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))  # -> src/

from argus.graph.store import GraphStore  # noqa: E402
from argus.ops.decision_replay import get_decision_evidence  # noqa: E402


def _human_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def devices_touching(store: GraphStore, destination_id: str, since: float = 0.0) -> List[str]:
    """Every device (canonical, orphan-merges already resolved) that has ever
    touched this destination since `since` -- reuses get_devices_targeting()
    unchanged; the only thing new here is treating `since=0.0` as "the beginning
    of retained history" instead of a short live-decision window, which that
    method already supports without modification."""
    return store.get_devices_targeting(destination_id, since=since)


def decision_timeline(store: GraphStore, decision_id: str) -> Optional[Dict[str, Any]]:
    """The full evidence timeline behind one decision -- the decision itself
    plus every real evidence item that supported it (via the graph's own
    `supports` edges), in chronological order. Returns None if the decision_id
    doesn't exist at all (not an error -- a typo'd or already-archived id is a
    real, expected case for a manual tool)."""
    decision = store.get_decision(decision_id)
    if decision is None:
        return None
    evidence_list = get_decision_evidence(store, decision)
    evidence_list = sorted(evidence_list, key=lambda e: e.timestamp)
    return {"decision": decision, "evidence": evidence_list}


def device_history(store: GraphStore, device_id: str, since: float = 0.0) -> Dict[str, Any]:
    """A single device's full evidence + decision history since `since`,
    chronologically merged for a "what has this device actually done" read.
    Canonicalizes device_id first, matching every other argus read's own
    convention -- a merged orphan's history is included transparently."""
    canonical = store.resolve_canonical_device_id(device_id)
    evidence_list = sorted(store.get_evidence_for_device(canonical, since=since), key=lambda e: e.timestamp)
    device_ids = set(store.device_ids_for(canonical))   # decisions made under its earlier ids too
    decisions = sorted(
        (d for d in store.get_decisions_since(since) if d["device_id"] in device_ids),
        key=lambda d: d["timestamp"],
    )
    return {"canonical_device_id": canonical, "evidence": evidence_list, "decisions": decisions}


def _print_timeline(result: Dict[str, Any]) -> None:
    decision = result["decision"]
    print(f"Decision {decision['decision_id']} -- device={decision['device_id']} "
          f"state={decision['state']} decision_path={decision['decision_path']} "
          f"@ {_human_ts(decision['timestamp'])}")
    winning = decision["raw_payload"].get("hypotheses", {}).get("attack", {}).get("name")
    if winning:
        print(f"  winning attack hypothesis: {winning}")
    print(f"  {len(result['evidence'])} supporting evidence item(s):")
    for e in result["evidence"]:
        print(f"    [{_human_ts(e.timestamp)}] {e.evidence_type} -> {e.destination_id} "
              f"(confidence={e.confidence:.2f}, family={e.independence_family})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--db", default="state/v13_graph.db", help="Path to v13_graph.db")
    sub = parser.add_subparsers(dest="command", required=True)

    p_devices = sub.add_parser("devices", help="Every device that ever touched a destination")
    p_devices.add_argument("--destination", required=True)
    p_devices.add_argument("--since-days", type=float, default=None,
                            help="Limit to the last N days (default: all retained history)")

    p_timeline = sub.add_parser("timeline", help="Full evidence timeline behind one decision")
    p_timeline.add_argument("--decision-id", required=True)

    p_device = sub.add_parser("device", help="One device's full evidence + decision history")
    p_device.add_argument("--device-id", required=True)
    p_device.add_argument("--since-days", type=float, default=None)

    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"No graph database at {db_path} -- nothing to query.", file=sys.stderr)
        sys.exit(1)
    store = GraphStore(str(db_path))

    if args.command == "devices":
        since = time.time() - args.since_days * 86400 if args.since_days else 0.0
        devices = devices_touching(store, args.destination, since=since)
        print(f"{len(devices)} device(s) have touched {args.destination}"
              + (f" in the last {args.since_days:.0f} day(s)" if args.since_days else "") + ":")
        for d in devices:
            print(f"  {d}")

    elif args.command == "timeline":
        result = decision_timeline(store, args.decision_id)
        if result is None:
            print(f"No decision found with decision_id={args.decision_id!r} "
                  f"(check the id, or it may have aged past the 1-year decision-archival window).",
                  file=sys.stderr)
            sys.exit(1)
        _print_timeline(result)

    elif args.command == "device":
        since = time.time() - args.since_days * 86400 if args.since_days else 0.0
        result = device_history(store, args.device_id, since=since)
        print(f"Device {args.device_id} (canonical: {result['canonical_device_id']}) -- "
              f"{len(result['evidence'])} evidence item(s), {len(result['decisions'])} decision(s):")
        for d in result["decisions"]:
            print(f"  [{_human_ts(d['timestamp'])}] DECISION {d['state']}/{d['decision_path']}")
        for e in result["evidence"]:
            print(f"  [{_human_ts(e.timestamp)}] evidence {e.evidence_type} -> {e.destination_id}")

    store.close()


if __name__ == "__main__":
    main()
