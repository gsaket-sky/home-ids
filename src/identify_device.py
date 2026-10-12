"""
identify_device.py -- which device the engine considers an address, MAC, device id or name to be (read-only).

Usage:
  python src/identify_device.py <ADDRESS|MAC|DEVICE_ID|NAME> [--json]

Examples:
  python src/identify_device.py 192.168.1.50
  python src/identify_device.py fe80::1c2d:3e4f:5a6b:7c8d
  python src/identify_device.py aa:bb:cc:dd:ee:ff
  python src/identify_device.py 3f2a9c81d0e4

Verdicts:
  EXACT      one device holds it and is identified exactly (its own MAC, no other device with that MAC or currently
             using its address) -- the device an operator action (Tarpit, Isolate, Block) acts on
  NOT EXACT  one device holds it, but its identity is not certain yet (the reason is printed); it is identified again
             the next time its traffic is observed -- wait, then check again
  AMBIGUOUS  several devices currently claim it
  UNKNOWN    no device currently holds it (devices that held it before are listed as history)

Reads the state the engine last flushed (about once a minute); never writes. 2026-10-12: an address is a lease, not
an identity -- a device is the MAC its traffic was observed from (core/state_guard.py).
"""
import ipaddress
import json
import re
import sys
import time
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import StateManager  # noqa: E402

_MAC_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.I)


def _summary(sm: StateManager, dev_id: str) -> dict:
    with sm.lock_device(dev_id) as st:
        out = {"device_id": dev_id, "hostname": getattr(st, "hostname", "unknown"),
               "mac": getattr(st, "mac_address", "unknown"), "address": getattr(st, "client_ip", ""),
               "address_history": st.known_ips.to_list(), "last_seen": getattr(st, "last_seen", 0.0) or 0.0}
    out["identity"] = sm.identity_check(dev_id)
    return out


def timeline(conn, kind: str, value: str, limit: int = 30) -> dict:
    """The identity ledger for `value` (IDENTITY_MODEL.md P1): its bindings -- which device held this identifier when
    -- and the identity events about it, newest first. `conn` is a read-only sqlite3 connection to the graph; a graph
    without the ledger tables (before P1) gives empty lists."""
    out = {"bindings": [], "events": []}
    if conn is None:
        return out
    try:
        if kind == "device_id":
            b = conn.execute("SELECT * FROM identity_bindings WHERE device_id = ? ORDER BY valid_from DESC LIMIT ?",
                             (value, limit)).fetchall()
            e = conn.execute("SELECT * FROM identity_events WHERE device_id = ? OR other_device_id = ? "
                             "ORDER BY ts DESC, event_id DESC LIMIT ?", (value, value, limit)).fetchall()
        else:
            id_kind = "mac" if kind == "mac" else "address"
            b = conn.execute("SELECT * FROM identity_bindings WHERE id_kind = ? AND id_value = ? "
                             "ORDER BY valid_from DESC LIMIT ?", (id_kind, value, limit)).fetchall()
            e = conn.execute("SELECT * FROM identity_events WHERE (id_kind = ? AND id_value = ?) OR mac = ? OR "
                             "address = ? ORDER BY ts DESC, event_id DESC LIMIT ?",
                             (id_kind, value, value, value, limit)).fetchall()
        cols_b = [d[0] for d in conn.execute("SELECT * FROM identity_bindings LIMIT 0").description]
        cols_e = [d[0] for d in conn.execute("SELECT * FROM identity_events LIMIT 0").description]
        out["bindings"] = [dict(zip(cols_b, r)) for r in b]
        out["events"] = [dict(zip(cols_e, r)) for r in e]
    except Exception:
        pass
    return out


def identify(sm: StateManager, query: str, graph_conn=None) -> dict:
    """{"query", "kind", "merged_into", "current": [summary], "history": [summary], "verdict", "detail"}."""
    q = query.strip()
    kind, current, history, merged_into = "name", [], [], None
    ids = sm.get_all_device_ids()
    if _MAC_RE.match(q):
        kind, mac = "mac", q.lower().replace("-", ":")
        for d in ids:
            with sm.lock_device(d) as st:
                if (getattr(st, "mac_address", "") or "").lower() == mac:
                    current.append(d)
    else:
        try:
            ipaddress.ip_address(q)
            kind = "address"
        except ValueError:
            pass
        if kind == "address":
            for d in ids:
                with sm.lock_device(d) as st:
                    if getattr(st, "client_ip", "") == q:
                        current.append(d)
                    elif q in st.known_ips:
                        history.append(d)
        elif sm.has_device(q) or sm.resolve_merge_redirect(q) != q or q in sm.get_identity_splits():
            kind = "device_id"
            target = sm.resolve_merge_redirect(q)
            merged_into = target if target != q else None
            if sm.has_device(target):
                current.append(target)
        else:
            for d in ids:
                with sm.lock_device(d) as st:
                    if (getattr(st, "hostname", "") or "").lower() == q.lower():
                        current.append(d)
    cur = sorted((_summary(sm, d) for d in current), key=lambda s: -s["last_seen"])
    hist = sorted((_summary(sm, d) for d in history), key=lambda s: -s["last_seen"])
    if len(cur) == 1:
        ident = cur[0]["identity"]
        verdict = "EXACT" if ident["exact"] else "NOT EXACT"
        detail = cur[0]["device_id"] if ident["exact"] else f"{cur[0]['device_id']}: {ident['reason']}"
    elif cur:
        verdict, detail = "AMBIGUOUS", f"{len(cur)} devices currently claim {q}: " + ", ".join(s["device_id"] for s in cur)
    else:
        verdict = "UNKNOWN"
        detail = (f"no device currently holds {q}; in the history of " + ", ".join(s["device_id"] for s in hist)
                  if hist else f"no device known for {q}")
    split = sm.get_identity_splits().get(q)
    value = q.lower().replace("-", ":") if kind == "mac" else q
    return {"query": q, "kind": kind, "merged_into": merged_into, "current": cur, "history": hist,
            "verdict": verdict, "detail": detail, "split_from": split,
            "timeline": timeline(graph_conn, kind if kind in ("mac", "address", "device_id") else "address", value)}


def _age(ts: float) -> str:
    if not ts:
        return "never"
    s = max(0.0, time.time() - ts)
    return f"{int(s // 60)} min ago" if s < 3600 else f"{s / 3600:.1f} h ago" if s < 86400 else f"{s / 86400:.1f} d ago"


def _when(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts))) if ts else "-"


def _print(result: dict) -> None:
    print(f"{result['query']} ({result['kind']}): {result['verdict']} -- {result['detail']}")
    if result["merged_into"]:
        print(f"  {result['query']} was merged into {result['merged_into']}")
    if result.get("split_from"):
        sp = result["split_from"]
        print(f"  {result['query']} had been merged into {sp['from']}; split again {_age(sp['ts'])}: its traffic came "
              f"from MAC {sp['mac']}")
    for label, rows in (("current", result["current"]), ("history only", result["history"])):
        for s in rows:
            print(f"  [{label}] {s['device_id']}  name={s['hostname']!r}  mac={s['mac']}  address={s['address']}  "
                  f"seen {_age(s['last_seen'])}")
            print(f"      address history: {', '.join(s['address_history']) or '-'}")
            if not s["identity"]["exact"]:
                print(f"      not exact: {s['identity']['reason']}")
    tl = result.get("timeline") or {}
    if tl.get("bindings"):
        print("  bindings (who held it when, newest first):")
        for b in tl["bindings"]:
            until = "now" if b.get("valid_to") is None else _when(b["valid_to"])
            flag = f"  RETRACTED ({b['retracted_by']})" if b.get("retracted_at") else ""
            print(f"    {b['id_kind']} {b['id_value']} -> {b['device_id']}  {_when(b['valid_from'])} .. {until}"
                  f"  [{b.get('evidence') or '-'}]{flag}")
    if tl.get("events"):
        print("  identity events (newest first):")
        for e in tl["events"]:
            parts = [e["kind"], e.get("device_id") or "", ("-> " + e["other_device_id"]) if e.get("other_device_id") else "",
                     e.get("id_value") or e.get("mac") or e.get("address") or "", e.get("reason") or ""]
            print(f"    {_when(e['ts'])}  " + "  ".join(p for p in parts if p))


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--json"]
    if len(args) != 1:
        print(__doc__.strip().split("\n\n")[1])
        return 2
    from config import CONFIG
    sm = StateManager(state_path=CONFIG.get("state_path", "state/ids_state.json"))
    sm.load_from_disk(ledger=False)          # read-only: such an instance never flushes
    graph_conn = None
    graph = Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "v13_graph.db"
    if graph.exists():
        import sqlite3
        graph_conn = sqlite3.connect(f"file:{graph}?mode=ro", uri=True)      # read-only: no migrations, no writes
    result = identify(sm, args[0], graph_conn)
    if "--json" in sys.argv:
        print(json.dumps(result, indent=1, default=str))
    else:
        _print(result)
    return 0 if result["verdict"] == "EXACT" else 1


if __name__ == "__main__":
    sys.exit(main())
