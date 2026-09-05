"""
Standalone runtime test for v13's GraphStore (src/v13/graph/store.py, Phase 1 --
Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: schema auto-initialization on first open, device/destination upsert,
evidence insert with automatic device/destination/edge bookkeeping, the
audit-preserving merge design (an orphan's evidence keeps resolving through the
canonical device_id, unlike v-current's discard-on-merge), and retention pruning.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_graph_store.py`
"""
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.graph.store import GraphStore  # noqa: E402
from v13.evidence.model import Evidence, NO_DESTINATION  # noqa: E402

tmpdir = tempfile.mkdtemp(prefix="v13_graph_test_")
db_path = str(_PathForSysPath(tmpdir) / "test_graph.db")
store = GraphStore(db_path)

check("schema auto-applied on first open (evidence table exists)",
      store._conn.execute("SELECT name FROM sqlite_master WHERE name='evidence'").fetchone() is not None)
check("seed sentinel destination row present",
      store._conn.execute("SELECT destination_id FROM destinations WHERE destination_id=?",
                            (NO_DESTINATION,)).fetchone() is not None)

# --- device upsert ---
store.upsert_device("dev1", display_label="Test Device", device_type="iot", timestamp=100.0)
row = store._conn.execute("SELECT * FROM devices WHERE device_id='dev1'").fetchone()
check("device inserted with correct fields", row["display_label"] == "Test Device" and row["first_seen"] == 100.0)

store.upsert_device("dev1", timestamp=200.0)
row2 = store._conn.execute("SELECT * FROM devices WHERE device_id='dev1'").fetchone()
check("re-upserting a device updates last_seen without clobbering first_seen",
      row2["first_seen"] == 100.0 and row2["last_seen"] == 200.0)
check("re-upserting a device without a label doesn't clobber the existing one",
      row2["display_label"] == "Test Device")

# --- evidence insert with auto device/destination/edge bookkeeping ---
ev = Evidence(device_id="dev2", destination_id="evil.example.com", evidence_type="dns_tunnel_v2",
              independence_family="dns_behavior", timestamp=300.0, source="dns_features", confidence=0.9)
store.insert_evidence(ev)

check("insert_evidence auto-creates the device row",
      store._conn.execute("SELECT 1 FROM devices WHERE device_id='dev2'").fetchone() is not None)
check("insert_evidence auto-creates the destination row",
      store._conn.execute("SELECT 1 FROM destinations WHERE destination_id='evil.example.com'").fetchone() is not None)
check("insert_evidence creates an 'observed' edge from device to evidence",
      store._conn.execute("SELECT 1 FROM edges WHERE relation='observed' AND src_id='dev2' AND dst_id=?",
                            (ev.evidence_id,)).fetchone() is not None)
check("insert_evidence creates a 'targets' edge from evidence to destination",
      store._conn.execute("SELECT 1 FROM edges WHERE relation='targets' AND src_id=? AND dst_id='evil.example.com'",
                            (ev.evidence_id,)).fetchone() is not None)

ev_no_dest = Evidence(device_id="dev2", destination_id=NO_DESTINATION, evidence_type="arp_sweep",
                        independence_family="network_recon", timestamp=310.0, source="arp")
store.insert_evidence(ev_no_dest)
check("NO_DESTINATION evidence does NOT create a spurious 'targets' edge",
      store._conn.execute("SELECT 1 FROM edges WHERE relation='targets' AND src_id=?",
                            (ev_no_dest.evidence_id,)).fetchone() is None)

# --- retrieval ---
fetched = store.get_evidence_for_device("dev2")
check("get_evidence_for_device returns both inserted items", len(fetched) == 2)
check("get_evidence_for_device returns items ordered by timestamp",
      fetched[0].evidence_id == ev.evidence_id and fetched[1].evidence_id == ev_no_dest.evidence_id)

fetched_since = store.get_evidence_for_device("dev2", since=305.0)
check("get_evidence_for_device respects the since= filter", len(fetched_since) == 1 and fetched_since[0].evidence_id == ev_no_dest.evidence_id)

# --- audit-preserving merge ---
ev_orphan = Evidence(device_id="orphan1", destination_id="x.com", evidence_type="dns_tunnel_v2",
                       independence_family="dns_behavior", timestamp=400.0, source="dns_features")
store.insert_evidence(ev_orphan)
store.merge_device("orphan1", "canonical1", timestamp=500.0)

check("merged orphan device row still exists (not deleted)",
      store._conn.execute("SELECT 1 FROM devices WHERE device_id='orphan1'").fetchone() is not None)
check("merged orphan's merged_into_device_id points at the canonical id",
      store._conn.execute("SELECT merged_into_device_id FROM devices WHERE device_id='orphan1'").fetchone()[0] == "canonical1")
check("resolve_canonical_device_id resolves the orphan to the canonical id",
      store.resolve_canonical_device_id("orphan1") == "canonical1")
check("resolve_canonical_device_id is a no-op for an already-canonical id",
      store.resolve_canonical_device_id("canonical1") == "canonical1")

merged_evidence = store.get_evidence_for_device("canonical1")
check("querying the CANONICAL id after merge still returns the orphan's evidence "
      "(the whole point of audit-preserving merge over v-current's discard-on-merge)",
      any(e.evidence_id == ev_orphan.evidence_id for e in merged_evidence))

merged_evidence_via_orphan = store.get_evidence_for_device("orphan1")
check("querying the ORPHAN id after merge also resolves through to the same evidence",
      any(e.evidence_id == ev_orphan.evidence_id for e in merged_evidence_via_orphan))

check("merge creates a 'merged_into' edge",
      store._conn.execute("SELECT 1 FROM edges WHERE relation='merged_into' AND src_id='orphan1' AND dst_id='canonical1'").fetchone() is not None)

try:
    store.merge_device("same", "same")
    check("merging a device into itself is rejected", False, "no exception raised")
except ValueError:
    check("merging a device into itself is rejected", True)

# --- cycle detection ---
try:
    store.merge_device("cycleA", "cycleB", timestamp=600.0)
    store.merge_device("cycleB", "cycleA", timestamp=601.0)
    store.resolve_canonical_device_id("cycleA")
    check("a merge cycle is detected rather than infinite-looping", False, "no exception raised")
except RuntimeError as e:
    check("a merge cycle is detected rather than infinite-looping", "cycle" in str(e))

# --- retention pruning ---
now = 10_000_000.0
old_ev = Evidence(device_id="devold", destination_id=NO_DESTINATION, evidence_type="x",
                    independence_family="f", timestamp=now - 200 * 86400, source="s")
recent_ev = Evidence(device_id="devold", destination_id=NO_DESTINATION, evidence_type="x",
                       independence_family="f", timestamp=now - 1 * 86400, source="s")
store.insert_evidence(old_ev)
store.insert_evidence(recent_ev)
deleted = store.prune_evidence(older_than_days=90, now=now)
check("prune_evidence deletes evidence older than the retention window",
      store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?", (old_ev.evidence_id,)).fetchone() is None)
check("prune_evidence keeps evidence within the retention window",
      store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?", (recent_ev.evidence_id,)).fetchone() is not None)
check("prune_evidence returns a real deleted-row count", deleted >= 1)

# --- generic edge query/delete (used by cl_afpe/engine.py, Phase 4) ---
store.add_edge("device", "queryedge_dev", "destination", "queryedge_dest", "trusts", timestamp=999.0,
                 metadata={"source": "test"})
found = store.get_edges(relation="trusts", src_id="queryedge_dev")
check("get_edges filters by relation and src_id correctly", len(found) == 1 and found[0]["dst_id"] == "queryedge_dest")
check("get_edges deserializes metadata_json back into a dict", found[0]["metadata"] == {"source": "test"})

none_found = store.get_edges(relation="trusts", src_id="nonexistent")
check("get_edges returns an empty list for no matches, not an error", none_found == [])

store.delete_edge(found[0]["edge_id"])
after_delete = store.get_edges(relation="trusts", src_id="queryedge_dev")
check("delete_edge actually removes the edge", after_delete == [])

# --- get_device_destinations_since (used by retro_hunter.py, Phase 6) ---
store.insert_evidence(Evidence(device_id="retro_dev", destination_id="retro-dest.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=5_000_000.0, source="s"))
pairs = store.get_device_destinations_since(4_999_000.0)
check("get_device_destinations_since finds a recent (device, destination) pair",
      ("retro_dev", "retro-dest.com") in pairs)
pairs_too_recent_cutoff = store.get_device_destinations_since(5_000_001.0)
check("get_device_destinations_since excludes pairs before the cutoff",
      ("retro_dev", "retro-dest.com") not in pairs_too_recent_cutoff)
check("get_device_destinations_since excludes the NO_DESTINATION sentinel",
      not any(dest == NO_DESTINATION for _, dest in store.get_device_destinations_since(0)))

store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 GraphStore checks PASSED.")
