"""
reconcile_graph_merges.py - compare the engine's device merges with the evidence graph, and optionally replay the
merges the graph is missing.

The running pipeline already does this after every identity-reconcile pass (graph_merge_repair_enabled, see
argus/graph/merge_consistency.py for the kinds and why the engine is the reference). This tool is for looking first:
the dry run lists every disagreement with what each store knows about the devices involved, and changes nothing.

Usage (from anywhere -- resolves state relative to config.yaml's state_path):
  1. Dry run (read-only, safe while the pipeline runs):
       python3 src/reconcile_graph_merges.py
  2. Replay the `missing` and `diverged` merges into the graph:
       python3 src/reconcile_graph_merges.py --apply
     Safe while the pipeline runs (SQLite locking orders the writes; the pipeline's canonical-id cache expires
     within 15 s). Back up state/v13_graph.db first: a merge is audit-preserving (tombstone + edge, nothing
     deleted) but there is no un-merge command.
"""
import json
import sqlite3
import sys
import time
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG
from core import state_store
from argus.graph.merge_consistency import check_merges, describe, repair_merges


def _when(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts))) if ts else "-"


def _graph_rows(graph_db: Path) -> dict:
    conn = sqlite3.connect(f"file:{graph_db.as_posix()}?mode=ro", uri=True, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        return {r["device_id"]: dict(r) for r in conn.execute(
            "SELECT device_id, merged_into_device_id, display_label, device_type, first_seen, last_seen FROM devices")}
    finally:
        conn.close()


def _engine_line(engine_devices: dict, device_id: str) -> str:
    raw = engine_devices.get(device_id)
    if raw is None:
        return "engine: not tracked"
    try:
        d = json.loads(raw)
    except ValueError:
        return "engine: unreadable row"
    return (f"engine: hostname={d.get('hostname', '?')!r} type={d.get('device_type', '?')!r} "
            f"mac={d.get('mac_address', '?')!r} last_seen={_when(d.get('last_seen'))}")


def _graph_line(graph: dict, device_id: str) -> str:
    row = graph.get(device_id)
    if row is None:
        return "graph: no row"
    merged = f" merged_into={row['merged_into_device_id']}" if row["merged_into_device_id"] else " live"
    return (f"graph:{merged} label={row['display_label']!r} type={row['device_type']!r} "
            f"first_seen={_when(row['first_seen'])} last_seen={_when(row['last_seen'])}")


def main() -> int:
    apply_changes = "--apply" in sys.argv
    state_path = CONFIG.get("state_path", "state/ids_state.json")
    graph_db = Path(state_path).parent / "v13_graph.db"

    rows = state_store.read_rows(state_path, ("devices", "kv"))
    if rows is None:
        print(f"No engine state database for {state_path} -- nothing to compare.")
        return 1
    if not graph_db.exists():
        print(f"No graph database at {graph_db} -- nothing to compare.")
        return 1
    redirects = json.loads(rows["kv"].get("merge_redirects") or "{}")
    engine_devices = rows["devices"]
    graph = _graph_rows(graph_db)

    report = check_merges(redirects, {d: r["merged_into_device_id"] for d, r in graph.items()})
    counts = report.counts()
    print(f"Engine merges: {len(report.items)}  " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    ghosts = [d for d in redirects if d in graph and graph[d]["merged_into_device_id"] is None]
    print(f"Ids the engine merged away that are still live devices in the graph: {len(ghosts)}")
    for item in report.disagreements():
        print(f"\n{describe(item)}")
        for label, dev in (("orphan", item.orphan_id), ("engine canonical", item.canonical_id),
                           ("graph root", item.graph_root)):
            if dev and (label != "graph root" or dev not in (item.orphan_id, item.canonical_id)):
                print(f"  {label} {dev}\n    {_engine_line(engine_devices, dev)}\n    {_graph_line(graph, dev)}")

    repairable = counts["missing"] + counts["diverged"]
    if not apply_changes:
        print(f"\nDry run -- nothing changed. {repairable} merge(s) would be replayed into the graph; "
              f"{counts['unresolved']} unresolved left as they are. Re-run with --apply to replay "
              f"(back up {graph_db} first).")
        return 0

    from argus.graph.store import GraphStore
    store = GraphStore(str(graph_db))
    try:
        after = repair_merges(store, redirects)
    finally:
        store.close()
    print(f"\nReplayed {after.repaired} merge(s), {after.repair_failures} failed. After: "
          + "  ".join(f"{k}={v}" for k, v in after.counts().items()))
    return 0 if not after.repair_failures else 2


if __name__ == "__main__":
    sys.exit(main())
