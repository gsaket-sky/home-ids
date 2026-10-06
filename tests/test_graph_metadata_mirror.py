"""
The engine's device-state mirror into the graph (runtime trace run 2, finding 4.2).

main.py builds the shared StateManager without a graph store, so StateManager._mirror_graph_metadata() never ran on
.94 (none of 72 live devices had a mirrored field). EnginePipeline now attaches the store
(StateManager.attach_graph_store) and the mirror writes through GraphStore.mirror_device_metadata(). Covers: a device the
graph has gets its cold fields; a device only the engine has is NOT created in the graph (no false "seen now"); a merged
row is left alone; an unchanged second flush writes nothing; a change writes again; last_seen never moves.

Run directly: `venv/Scripts/python.exe tests/test_graph_metadata_mirror.py`
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.graph.store import GraphStore  # noqa: E402
from core.state_guard import StateManager  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="graph_mirror_"))
store = GraphStore(str(tmp / "graph.db"))
T0 = 1_000_000.0
store.upsert_device("in_graph", timestamp=T0)
store.update_device_metadata("in_graph", {"sigma_shift": 0.25})
store.upsert_device("merged_away", timestamp=T0)
store._conn.execute("UPDATE devices SET merged_into_device_id = 'in_graph' WHERE device_id = 'merged_away'")
store._conn.commit()

sm = StateManager(state_path=str(tmp / "ids_state.json"))
sm.get_or_create(device_id="in_graph", client_ip="10.20.30.40", hostname="lounge-tv")
sm.get_or_create(device_id="engine_only", client_ip="10.20.30.41", hostname="old-printer")
sm.get_or_create(device_id="merged_away", client_ip="10.20.30.42", hostname="ghost")

check("a StateManager built without a store accepts one later", sm._graph_store is None)
sm.attach_graph_store(store)
check("...and keeps it", sm._graph_store is store)
other = GraphStore(str(tmp / "other.db"))
sm.attach_graph_store(other)
check("attach does not replace a store that is already set", sm._graph_store is store)

check("the flush succeeds", sm.flush_to_disk() is True)
md = store.get_device_metadata("in_graph")
check("a device the graph has gets its mirrored cold fields", md.get("hostname") == "lounge-tv", str(md))
check("...without losing metadata other writers put there", md.get("sigma_shift") == 0.25, str(md))
check("a device only the engine knows is NOT created in the graph",
      store._conn.execute("SELECT 1 FROM devices WHERE device_id = 'engine_only'").fetchone() is None)
check("a merged-away row is left alone",
      "hostname" not in store.get_device_metadata("merged_away"))
check("mirroring never moves last_seen",
      store._conn.execute("SELECT last_seen FROM devices WHERE device_id = 'in_graph'").fetchone()[0] == T0)

snap = {"in_graph": sm._states["in_graph"].to_graph_metadata()}
check("an unchanged second pass writes no row", store.mirror_device_metadata(snap) == 0)
with sm.lock_device("in_graph") as st:
    st.fp_count += 1
snap = {"in_graph": sm._states["in_graph"].to_graph_metadata()}
check("a changed field writes the row again", store.mirror_device_metadata(snap) == 1)
check("...with the new value", store.get_device_metadata("in_graph").get("fp_count") == snap["in_graph"]["fp_count"])

if FAILURES:
    print(f"\n{len(FAILURES)} check(s) FAILED")
    sys.exit(1)
print("\nAll graph metadata mirror checks PASSED.")
