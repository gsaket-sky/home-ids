"""
identity_shadow_report.py -- does the identity ledger agree with the engine? (Documentation/internal/IDENTITY_MODEL.md, P1)

Usage:
  python src/identity_shadow_report.py [--json]

P1 runs the binding ledger in shadow beside today's identity logic. This report compares the two, read-only:
  mac      a device's MAC in the engine is bound to that device in the ledger
  address  a device's current address in the engine is bound to that device in the ledger
  orphan   an open ledger binding names a device the engine does not have (and no merge redirect explains it)
Every disagreement is listed with both sides. P1 is accepted when every disagreement on .94 has an explanation
(IDENTITY_MODEL.md, section 8). Exit code 0 when they agree, 1 otherwise.
"""
import json
import sqlite3
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import StateManager  # noqa: E402


def compare(sm: StateManager, graph_conn) -> dict:
    """{"checked": {...}, "disagreements": [{"kind", "identifier", "engine", "ledger", ...}]}."""
    rows = graph_conn.execute("SELECT id_kind, id_value, device_id, valid_from, last_seen, evidence "
                              "FROM identity_bindings WHERE valid_to IS NULL AND retracted_at IS NULL").fetchall()
    ledger = {(r[0], r[1]): {"device_id": r[2], "valid_from": r[3], "last_seen": r[4], "evidence": r[5]} for r in rows}
    redirects = sm.get_merge_redirects()
    out, checked = [], {"mac": 0, "address": 0, "orphan": 0}
    devices = set(sm.get_all_device_ids())
    for dev in sorted(devices):
        with sm.lock_device(dev) as st:
            mac = getattr(st, "mac_address", "unknown") or "unknown"
            ip = getattr(st, "client_ip", "") or ""
        if mac != "unknown":
            checked["mac"] += 1
            led = ledger.get(("mac", mac))
            if led is None or led["device_id"] != dev:
                out.append({"kind": "mac", "identifier": mac, "engine": dev,
                            "ledger": led["device_id"] if led else None})
        if ip and ip != "unknown":
            checked["address"] += 1
            led = ledger.get(("address", ip))
            if led is None or led["device_id"] != dev:
                out.append({"kind": "address", "identifier": ip, "engine": dev,
                            "ledger": led["device_id"] if led else None,
                            "ledger_evidence": led["evidence"] if led else None})
    for (kind, value), led in sorted(ledger.items()):
        if kind == "legacy_id":
            continue
        checked["orphan"] += 1
        if led["device_id"] not in devices and led["device_id"] not in redirects:
            out.append({"kind": "orphan", "identifier": f"{kind} {value}", "engine": None, "ledger": led["device_id"]})
    return {"checked": checked, "disagreements": out}


def main() -> int:
    from config import CONFIG
    state_path = CONFIG.get("state_path", "state/ids_state.json")
    sm = StateManager(state_path=state_path)
    sm.load_from_disk(ledger=False)                       # read-only: never flushes
    graph = Path(state_path).parent / "v13_graph.db"
    if not graph.exists():
        print(f"No graph at {graph}.")
        return 2
    conn = sqlite3.connect(f"file:{graph}?mode=ro", uri=True)
    try:
        report = compare(sm, conn)
    except sqlite3.OperationalError as exc:
        print(f"The graph has no identity ledger yet ({exc}).")
        return 2
    if "--json" in sys.argv:
        print(json.dumps(report, indent=1))
    else:
        c = report["checked"]
        print(f"checked: {c['mac']} MACs, {c['address']} current addresses, {c['orphan']} open ledger bindings")
        for d in report["disagreements"]:
            extra = f" (ledger evidence: {d['ledger_evidence']})" if d.get("ledger_evidence") else ""
            print(f"  {d['kind']:8s} {d['identifier']}: engine={d['engine']} ledger={d['ledger']}{extra}")
        print("agree" if not report["disagreements"] else f"{len(report['disagreements'])} disagreement(s)")
    return 0 if not report["disagreements"] else 1


if __name__ == "__main__":
    sys.exit(main())
