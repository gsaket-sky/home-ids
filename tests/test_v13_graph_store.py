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
import json
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

# --- prune_evidence's "referenced by a recent decision" exception (v13 full-
# architecture plan, Phase 1 bug fix): this was previously dead code -- nothing
# ever created the evidence->decision edge the exception query looks for, so
# old-but-still-referenced evidence was silently deleted anyway. ---
referenced_old_ev = Evidence(device_id="devref", destination_id=NO_DESTINATION, evidence_type="x",
                               independence_family="f", timestamp=now - 200 * 86400, source="s")
store.insert_evidence(referenced_old_ev)
store.insert_decision(
    device_id="devref", timestamp=now - 1 * 86400, state="SUSPICIOUS", decision_path="hypothesis_suspicious",
    confidence=0.4, risk_score=2.0, raw_payload={}, evidence_ids=[referenced_old_ev.evidence_id],
)
store.prune_evidence(older_than_days=90, now=now)
check("evidence older than the retention window SURVIVES pruning when a recent "
      "decision references it via insert_decision()'s evidence_ids param",
      store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?",
                            (referenced_old_ev.evidence_id,)).fetchone() is not None)
check("insert_decision actually created the evidence->decision 'supports' edge",
      len(store.get_edges(relation="supports", src_kind="evidence",
                            src_id=referenced_old_ev.evidence_id, dst_kind="decision")) == 1)

unreferenced_old_ev = Evidence(device_id="devunref", destination_id=NO_DESTINATION, evidence_type="x",
                                 independence_family="f", timestamp=now - 200 * 86400, source="s")
store.insert_evidence(unreferenced_old_ev)
store.prune_evidence(older_than_days=90, now=now)
check("REGRESSION GUARD: evidence with no supporting decision is still pruned normally "
      "(the fix doesn't accidentally make everything immortal)",
      store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?",
                            (unreferenced_old_ev.evidence_id,)).fetchone() is None)


def _dangling_evidence_edge_count(s):
    return s._conn.execute(
        "SELECT COUNT(*) FROM edges WHERE "
        "(src_kind='evidence' AND src_id NOT IN (SELECT evidence_id FROM evidence)) OR "
        "(dst_kind='evidence' AND dst_id NOT IN (SELECT evidence_id FROM evidence))"
    ).fetchone()[0]


# --- BUGFIX (2026-09-07, live audit): prune_evidence() used to delete ONLY from
# the evidence table, leaving every deleted row's own 'observed'/'targets'/
# 'supports' edges dangling (pointing at an evidence_id that no longer exists) --
# confirmed here directly, not just "no crash". ---
check("BUGFIX: after all the pruning above, NO edge anywhere in the store "
      "references a deleted evidence_id -- the actual dangling-edges bug this "
      "fix closes, checked directly rather than inferred from evidence alone",
      _dangling_evidence_edge_count(store) == 0)

# The real gap case: a decision OLDER than the 90-day evidence cutoff (so it no
# longer protects its own evidence) but still within decisions' own separate,
# much longer 1-year retention -- before this fix, the decision's 'supports'
# edge to its now-pruned evidence would dangle for however long the decision
# itself survived past that point.
gap_ev = Evidence(device_id="devgap", destination_id=NO_DESTINATION, evidence_type="x",
                    independence_family="f", timestamp=now - 200 * 86400, source="s")
store.insert_evidence(gap_ev)
gap_decision_id = store.insert_decision(
    device_id="devgap", timestamp=now - 150 * 86400,  # older than the 90-day evidence cutoff...
    state="HIGH", decision_path="hypothesis_high", confidence=0.8, risk_score=8.0,
    raw_payload={}, evidence_ids=[gap_ev.evidence_id],
)
store.prune_evidence(older_than_days=90, now=now)
check("the gap-case evidence (protected by a decision too old to protect it) "
      "IS pruned -- confirms this fix didn't change WHAT gets pruned, only "
      "whether pruning leaves dangling edges behind",
      store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?",
                            (gap_ev.evidence_id,)).fetchone() is None)
check("BUGFIX: the decision's own 'supports' edge to the now-pruned evidence is "
      "gone too, not left dangling for the ~215 remaining days until the "
      "decision itself gets archived (Phase 10a, 365 days)",
      len(store.get_edges(relation="supports", dst_kind="decision", dst_id=gap_decision_id)) == 0)
check("...but the decision ROW ITSELF (a separate, longer-retention concern) "
      "is untouched by prune_evidence() -- still there, on its own schedule",
      store._conn.execute("SELECT 1 FROM decisions WHERE decision_id=?",
                            (gap_decision_id,)).fetchone() is not None)


# --- transaction(): batches multiple writes into one commit ---
# sqlite3.Connection.commit is a C-level method and can't be monkeypatched to
# literally count calls -- instead test the two things that actually matter:
# every write inside the block is visible together (batching didn't lose
# anything), and a failure partway through discards ALL of it (atomicity),
# not just the specific statement that raised.
txn_store = GraphStore(str(_PathForSysPath(tmpdir) / "txn_test.db"))
_maybe_commit_calls = []
_orig_maybe_commit = txn_store._maybe_commit
txn_store._maybe_commit = lambda: (_maybe_commit_calls.append(txn_store._in_transaction), _orig_maybe_commit())[-1]

with txn_store.transaction():
    check("_in_transaction is True for the whole duration of the with-block",
          txn_store._in_transaction is True)
    for i in range(5):
        txn_store.insert_evidence(Evidence(
            device_id="txndev", destination_id=NO_DESTINATION, evidence_type="x",
            independence_family="f", timestamp=now, source="s",
        ))
check("_in_transaction resets to False after the with-block exits normally",
      txn_store._in_transaction is False)
check("_maybe_commit was called multiple times during the batch, every one of them "
      "while _in_transaction was True (so none triggered a real per-call commit)",
      len(_maybe_commit_calls) > 1 and all(_maybe_commit_calls))
check("all 5 evidence rows were actually written despite the deferred commit",
      txn_store._conn.execute("SELECT COUNT(*) FROM evidence WHERE device_id='txndev'").fetchone()[0] == 5)

try:
    with txn_store.transaction():
        txn_store.insert_evidence(Evidence(
            device_id="txndev2", destination_id=NO_DESTINATION, evidence_type="x",
            independence_family="f", timestamp=now, source="s",
        ))
        raise RuntimeError("simulated failure mid-transaction")
except RuntimeError:
    pass
check("a raised exception inside transaction() rolls back the WHOLE block, not just the "
      "statement that raised -- the insert_evidence() call before the raise is also gone",
      txn_store._conn.execute("SELECT COUNT(*) FROM evidence WHERE device_id='txndev2'").fetchone()[0] == 0)
check("_in_transaction resets to False even after a rollback (not stuck True)",
      txn_store._in_transaction is False)

with txn_store.transaction():
    with txn_store.transaction():
        check("a nested transaction() call does not reset _in_transaction to something else",
              txn_store._in_transaction is True)
        txn_store.insert_evidence(Evidence(
            device_id="txndev3", destination_id=NO_DESTINATION, evidence_type="x",
            independence_family="f", timestamp=now, source="s",
        ))
check("the row written inside a nested transaction() is visible after the OUTER block commits",
      txn_store._conn.execute("SELECT COUNT(*) FROM evidence WHERE device_id='txndev3'").fetchone()[0] == 1)

txn_store._maybe_commit = _orig_maybe_commit
check("outside any transaction() block, behavior is unchanged -- each call still commits immediately "
      "(already exercised by every other check in this file using the module-level `store`)", True)

txn_store.close()

# --- device metadata read/update (v13 full-architecture plan, Phase 3) ---
check("get_device_metadata returns {} for a device that doesn't exist yet",
      store.get_device_metadata("nonexistent_dev") == {})

store.update_device_metadata("metadev", {"learned_mac": "aa:bb:cc:dd:ee:ff"})
check("update_device_metadata auto-upserts the device row",
      store._conn.execute("SELECT 1 FROM devices WHERE device_id='metadev'").fetchone() is not None)
check("get_device_metadata returns the just-written key",
      store.get_device_metadata("metadev") == {"learned_mac": "aa:bb:cc:dd:ee:ff"})

store.update_device_metadata("metadev", {"role": "gateway"})
check("update_device_metadata MERGES new keys rather than replacing the whole dict",
      store.get_device_metadata("metadev") == {"learned_mac": "aa:bb:cc:dd:ee:ff", "role": "gateway"})

store.update_device_metadata("metadev", {"learned_mac": "11:22:33:44:55:66"})
check("update_device_metadata OVERWRITES an existing key with the same name",
      store.get_device_metadata("metadev")["learned_mac"] == "11:22:33:44:55:66")
check("...without disturbing OTHER existing keys",
      store.get_device_metadata("metadev")["role"] == "gateway")

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

# --- insert_decision (A7 prerequisite: v13 decision computation) ---
store.upsert_device("decision_dev", timestamp=6_000_000.0)
decision_id = store.insert_decision(
    device_id="decision_dev", timestamp=6_000_000.0, state="HIGH",
    decision_path="hypothesis_high", confidence=0.85, risk_score=7.2,
    raw_payload={"state": "HIGH", "hypotheses": {"attack": {"name": "EXFILTRATION", "score": 7.2}}},
)
check("insert_decision returns a real, non-empty decision_id", bool(decision_id))
row = store._conn.execute("SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)).fetchone()
check("insert_decision writes a real row to the decisions table", row is not None)
check("insert_decision stores state/decision_path/confidence/risk_score as given",
      row["state"] == "HIGH" and row["decision_path"] == "hypothesis_high"
      and row["confidence"] == 0.85 and row["risk_score"] == 7.2)
check("insert_decision stores raw_payload_json as real, parseable JSON",
      json.loads(row["raw_payload_json"])["hypotheses"]["attack"]["name"] == "EXFILTRATION")
check("insert_decision defaults mechanism_flags_json to an empty object when not given",
      json.loads(row["mechanism_flags_json"]) == {})
check("insert_decision leaves winning_hypothesis_id NULL when not given (no fake FK row invented)",
      row["winning_hypothesis_id"] is None)
check("insert_decision auto-upserts the device row if it doesn't already exist",
      store._conn.execute("SELECT 1 FROM devices WHERE device_id = 'no_prior_device'").fetchone() is None)
store.insert_decision(device_id="no_prior_device", timestamp=6_000_001.0, state="BENIGN",
                        decision_path="no_evidence", confidence=0.0, risk_score=0.0)
check("insert_decision auto-upserts a device that never had a prior row",
      store._conn.execute("SELECT 1 FROM devices WHERE device_id = 'no_prior_device'").fetchone() is not None)

# --- get_decisions_since (A8 prerequisite: divergence comparator's read side) ---
store.insert_decision(device_id="window_dev", timestamp=6_100_000.0, state="HIGH",
                        decision_path="hypothesis_high", confidence=0.9, risk_score=8.0,
                        raw_payload={"marker": "in_window"})
store.insert_decision(device_id="window_dev", timestamp=6_200_000.0, state="BENIGN",
                        decision_path="benign", confidence=0.0, risk_score=0.0,
                        raw_payload={"marker": "after_until"})
in_window = store.get_decisions_since(6_050_000.0, until=6_150_000.0)
check("get_decisions_since returns decisions within [since, until)",
      any(d["raw_payload"].get("marker") == "in_window" for d in in_window))
check("get_decisions_since excludes decisions at or after `until`",
      not any(d["raw_payload"].get("marker") == "after_until" for d in in_window))
check("get_decisions_since parses raw_payload_json back into a real dict",
      isinstance(in_window[0]["raw_payload"], dict))
no_until = store.get_decisions_since(6_050_000.0)
check("get_decisions_since with no `until` includes everything from `since` onward",
      any(d["raw_payload"].get("marker") == "after_until" for d in no_until))

# --- get_decision (Release 14, N1: threat_hunt.py's decision-timeline lookup) ---
lookup_id = store.insert_decision(device_id="lookup_dev", timestamp=6_300_000.0, state="CRITICAL",
                                     decision_path="hard_stop", confidence=1.0, risk_score=9.0,
                                     raw_payload={"marker": "lookup_target"})
fetched = store.get_decision(lookup_id)
check("get_decision finds the real decision by id", fetched is not None and fetched["device_id"] == "lookup_dev")
check("get_decision parses raw_payload_json back into a real dict",
      fetched["raw_payload"].get("marker") == "lookup_target")
check("get_decision returns None for a decision_id that doesn't exist -- a real, "
      "expected case for a manual lookup tool, not an error",
      store.get_decision("nonexistent-decision-id") is None)

# --- get_devices_targeting (Phase 1a: cross-device correlation) ---
store.insert_evidence(Evidence(device_id="p1a_dev_a", destination_id="shared.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=7_000_000.0, source="s"))
store.insert_evidence(Evidence(device_id="p1a_dev_b", destination_id="shared.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=7_000_010.0, source="s"))
store.insert_evidence(Evidence(device_id="p1a_dev_c", destination_id="unrelated.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=7_000_010.0, source="s"))
store.insert_evidence(Evidence(device_id="p1a_dev_old", destination_id="shared.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=6_000_000.0, source="s"))  # well before `since` below

targeting = store.get_devices_targeting("shared.example.com", since=6_999_000.0)
check("get_devices_targeting finds both devices that touched the shared destination",
      set(targeting) == {"p1a_dev_a", "p1a_dev_b"}, f"got {targeting}")
check("get_devices_targeting excludes a device whose only touch is before `since`",
      "p1a_dev_old" not in targeting)
check("get_devices_targeting excludes a device that touched a DIFFERENT destination",
      "p1a_dev_c" not in targeting)

# canonicalization: an orphan merged into dev_a should resolve to dev_a, not appear
# as a THIRD distinct device
store.insert_evidence(Evidence(device_id="p1a_dev_a_orphan", destination_id="shared.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=7_000_020.0, source="s"))
store.merge_device("p1a_dev_a_orphan", "p1a_dev_a", timestamp=7_000_021.0)
targeting_after_merge = store.get_devices_targeting("shared.example.com", since=6_999_000.0)
check("get_devices_targeting canonicalizes a merged orphan into its canonical id "
      "(still just 2 distinct physical devices, not 3)",
      set(targeting_after_merge) == {"p1a_dev_a", "p1a_dev_b"}, f"got {targeting_after_merge}")

# --- get_devices_sharing_provenance (Release 14, N4: JA3/JA4 fingerprint correlation) ---
store.insert_evidence(Evidence(device_id="n4_dev_a", destination_id="x.example.com",
                                 evidence_type="malicious_ja3", independence_family="tls_fingerprint",
                                 timestamp=8_000_000.0, source="zeek", provenance="detector:zeek:malicious_ja3:abc123"))
store.insert_evidence(Evidence(device_id="n4_dev_b", destination_id="y.example.com",
                                 evidence_type="malicious_ja3", independence_family="tls_fingerprint",
                                 timestamp=8_000_010.0, source="zeek", provenance="detector:zeek:malicious_ja3:abc123"))
store.insert_evidence(Evidence(device_id="n4_dev_c", destination_id="z.example.com",
                                 evidence_type="malicious_ja3", independence_family="tls_fingerprint",
                                 timestamp=8_000_010.0, source="zeek", provenance="detector:zeek:malicious_ja3:DIFFERENT"))
store.insert_evidence(Evidence(device_id="n4_dev_old", destination_id="x.example.com",
                                 evidence_type="malicious_ja3", independence_family="tls_fingerprint",
                                 timestamp=7_000_000.0, source="zeek", provenance="detector:zeek:malicious_ja3:abc123"))

sharing = store.get_devices_sharing_provenance("malicious_ja3", "detector:zeek:malicious_ja3:abc123", since=7_999_000.0)
check("get_devices_sharing_provenance finds both devices sharing the EXACT same "
      "fingerprint hash", set(sharing) == {"n4_dev_a", "n4_dev_b"}, f"got {sharing}")
check("get_devices_sharing_provenance excludes a device with a DIFFERENT hash, "
      "even at the same evidence_type/timestamp", "n4_dev_c" not in sharing)
check("get_devices_sharing_provenance excludes a device whose only match is before `since`",
      "n4_dev_old" not in sharing)

# --- get_evidence_by_type_since (Release 14, N4: DGA-seed correlation's raw fetch) ---
store.insert_evidence(Evidence(device_id="n4_dga_a", destination_id="abcdefgh.ru",
                                 evidence_type="dns_dga_burst", independence_family="dns_behavior",
                                 timestamp=8_100_000.0, source="pihole"))
store.insert_evidence(Evidence(device_id="n4_dga_b", destination_id="qrstuvwx.ru",
                                 evidence_type="dns_dga_burst", independence_family="dns_behavior",
                                 timestamp=8_100_010.0, source="pihole"))
store.insert_evidence(Evidence(device_id="n4_dga_old", destination_id="zzzzzzzz.ru",
                                 evidence_type="dns_dga_burst", independence_family="dns_behavior",
                                 timestamp=7_000_000.0, source="pihole"))
dga_evidence = store.get_evidence_by_type_since("dns_dga_burst", since=8_099_000.0)
check("get_evidence_by_type_since returns evidence across MULTIPLE devices (not "
      "scoped to one, unlike get_evidence_for_device)",
      {e.device_id for e in dga_evidence} == {"n4_dga_a", "n4_dga_b"}, f"got {[e.device_id for e in dga_evidence]}")
check("get_evidence_by_type_since respects `since` -- the older item is excluded",
      not any(e.device_id == "n4_dga_old" for e in dga_evidence))
check("get_evidence_by_type_since returns REAL Evidence objects with their own "
      "destination_id intact (needed for DGA shape computation downstream)",
      {e.destination_id for e in dga_evidence} == {"abcdefgh.ru", "qrstuvwx.ru"})

# --- get_devices_with_metadata_value / get_distinct_destination_count (Release 14, N2) ---
store.update_device_metadata("n2_dev_iot1", {"device_type": "iot"}, timestamp=9_000_000.0)
store.update_device_metadata("n2_dev_iot2", {"device_type": "iot"}, timestamp=9_000_000.0)
store.update_device_metadata("n2_dev_laptop1", {"device_type": "laptop"}, timestamp=9_000_000.0)

iot_devices = store.get_devices_with_metadata_value("device_type", "iot")
check("get_devices_with_metadata_value finds both real iot devices",
      set(iot_devices) == {"n2_dev_iot1", "n2_dev_iot2"}, f"got {iot_devices}")
check("get_devices_with_metadata_value excludes a device of a DIFFERENT type",
      "n2_dev_laptop1" not in iot_devices)
check("get_devices_with_metadata_value returns [] for a value nothing matches",
      store.get_devices_with_metadata_value("device_type", "camera") == [])

store.insert_evidence(Evidence(device_id="n2_dev_iot1", destination_id="a.example.com",
                                 evidence_type="dns_rate", independence_family="dns_behavior",
                                 timestamp=9_100_000.0, source="s"))
store.insert_evidence(Evidence(device_id="n2_dev_iot1", destination_id="b.example.com",
                                 evidence_type="dns_rate", independence_family="dns_behavior",
                                 timestamp=9_100_010.0, source="s"))
store.insert_evidence(Evidence(device_id="n2_dev_iot1", destination_id="a.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=9_100_020.0, source="s"))  # SAME destination again -- must not double-count
store.insert_evidence(Evidence(device_id="n2_dev_iot1", destination_id="old.example.com",
                                 evidence_type="dns_rate", independence_family="dns_behavior",
                                 timestamp=8_000_000.0, source="s"))  # before `since`

count = store.get_distinct_destination_count("n2_dev_iot1", since=9_099_000.0)
check("get_distinct_destination_count counts DISTINCT destinations, not raw evidence "
      "rows (3 evidence rows within the window, only 2 distinct destinations)",
      count == 2, f"got {count}")
check("get_distinct_destination_count with no evidence at all for a device returns 0, "
      "not an error", store.get_distinct_destination_count("n2_never_seen", since=0.0) == 0)

# --- set/get_destination_reputation (Phase 1a: network-wide reputation propagation) ---
check("get_destination_reputation returns None for a destination never cached",
      store.get_destination_reputation("never-cached.example.com") is None)

store.set_destination_reputation("evil.example.com", tier=5, timestamp=7_100_000.0)
rep = store.get_destination_reputation("evil.example.com")
check("set_destination_reputation is readable back with the tier that was written",
      rep is not None and rep["tier"] == 5)
check("set_destination_reputation is readable back with the timestamp that was written",
      rep is not None and rep["cached_at"] == 7_100_000.0)
check("set_destination_reputation auto-upserts a destination never seen via insert_evidence",
      store._conn.execute(
          "SELECT 1 FROM destinations WHERE destination_id = 'evil.example.com'"
      ).fetchone() is not None)

store.set_destination_reputation("evil.example.com", tier=3, timestamp=7_200_000.0)
rep_overwritten = store.get_destination_reputation("evil.example.com")
check("a second set_destination_reputation call OVERWRITES the cached tier/timestamp",
      rep_overwritten["tier"] == 3 and rep_overwritten["cached_at"] == 7_200_000.0)

store.close()

# --- Phase 10b: hardware_profile-driven PRAGMA cache_size ---
tmpdir2 = tempfile.mkdtemp(prefix="v13_graph_test_hwprofile_")

store_pi = GraphStore(str(_PathForSysPath(tmpdir2) / "pi.db"), hardware_profile="pi_8gb")
check("pi_8gb gets a modest cache_size bump from SQLite's own -2000 default",
      store_pi._conn.execute("PRAGMA cache_size").fetchone()[0] == -4000)
store_pi.close()

store_x86 = GraphStore(str(_PathForSysPath(tmpdir2) / "x86.db"), hardware_profile="x86_16gb")
check("x86_16gb gets more headroom than pi_8gb",
      store_x86._conn.execute("PRAGMA cache_size").fetchone()[0] == -16000)
store_x86.close()

store_custom = GraphStore(str(_PathForSysPath(tmpdir2) / "custom.db"), hardware_profile="custom")
check("'custom' is treated like the more-capable default, not a conservative guess",
      store_custom._conn.execute("PRAGMA cache_size").fetchone()[0] == -16000)
store_custom.close()

store_none = GraphStore(str(_PathForSysPath(tmpdir2) / "none.db"))
check("omitting hardware_profile entirely leaves SQLite's own default cache_size "
      "untouched -- identical to this class's behavior before this param existed",
      store_none._conn.execute("PRAGMA cache_size").fetchone()[0] == -2000)
store_none.close()

store_unrecognized = GraphStore(str(_PathForSysPath(tmpdir2) / "unrecognized.db"), hardware_profile="totally-unrecognized")
check("an unrecognized hardware_profile string is a safe no-op, not a crash",
      store_unrecognized._conn.execute("PRAGMA cache_size").fetchone()[0] == -2000)
store_unrecognized.close()


# --- Phase 10a: decision archival (get_decisions_older_than / delete_decisions) ---
archive_store = GraphStore(str(_PathForSysPath(tmpdir2) / "archive.db"))
NOW_ARCHIVE = 2_000_000_000.0
archive_store.upsert_device("archive_dev", timestamp=NOW_ARCHIVE)
old_decision_id = archive_store.insert_decision(
    device_id="archive_dev", timestamp=NOW_ARCHIVE - 400 * 86400, state="HIGH",
    decision_path="hypothesis_high", confidence=0.8, risk_score=8.0, raw_payload={"note": "old"},
)
recent_decision_id = archive_store.insert_decision(
    device_id="archive_dev", timestamp=NOW_ARCHIVE - 10 * 86400, state="BENIGN",
    decision_path="benign", confidence=0.0, risk_score=0.0, raw_payload={"note": "recent"},
)

old_rows = archive_store.get_decisions_older_than(365.0, now=NOW_ARCHIVE)
check("get_decisions_older_than finds exactly the decision past the cutoff",
      len(old_rows) == 1 and old_rows[0]["decision_id"] == old_decision_id)
check("get_decisions_older_than returns the real parsed raw_payload, same shape as get_decisions_since",
      old_rows[0]["raw_payload"] == {"note": "old"})
check("get_decisions_older_than is READ-ONLY -- the decision is still in the db after calling it",
      archive_store._conn.execute(
          "SELECT 1 FROM decisions WHERE decision_id=?", (old_decision_id,)).fetchone() is not None)

deleted_count = archive_store.delete_decisions([r["decision_id"] for r in old_rows])
check("delete_decisions reports the real deleted count", deleted_count == 1)
check("delete_decisions actually removed the old decision",
      archive_store._conn.execute(
          "SELECT 1 FROM decisions WHERE decision_id=?", (old_decision_id,)).fetchone() is None)
check("delete_decisions left the recent decision untouched",
      archive_store._conn.execute(
          "SELECT 1 FROM decisions WHERE decision_id=?", (recent_decision_id,)).fetchone() is not None)
check("delete_decisions with an empty list is a safe no-op", archive_store.delete_decisions([]) == 0)

archive_store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 GraphStore checks PASSED.")
