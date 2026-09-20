"""
Standalone runtime test for v13's GraphStore (src/v13/graph/store.py, Phase 1 --
Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: schema auto-initialization on first open, device/destination upsert,
evidence insert with automatic device/destination/edge bookkeeping, the
audit-preserving merge design (an orphan's evidence keeps resolving through the
canonical device_id, unlike v-current's discard-on-merge), and retention pruning.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_graph_store.py`
"""
import json
import sqlite3
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


from argus.graph.store import GraphStore  # noqa: E402
from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402

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

# --- cycle prevention / detection ---
# BUGFIX (2026-09-16, live IPv6-rollout verification): a real 2-node cycle was
# found live on .94, dating back to 2026-09-06 -- merge_device() only ever
# checked for a direct self-merge, never whether canonical_id was ALREADY
# (transitively) merged into orphan_id, so a later, conflicting merge_device()
# call could silently write the second half of a cycle. Now refused at write
# time, not just detected after the fact.
store.merge_device("cycleA", "cycleB", timestamp=600.0)
try:
    store.merge_device("cycleB", "cycleA", timestamp=601.0)
    check("merge_device refuses to write the second half of a cycle "
          "(cycleB into cycleA, when cycleA is already merged into cycleB)", False, "no exception raised")
except ValueError as e:
    check("merge_device refuses to write the second half of a cycle "
          "(cycleB into cycleA, when cycleA is already merged into cycleB)", "cycle" in str(e).lower())
check("REGRESSION GUARD: the refused merge left cycleB's own row untouched (still canonical, "
      "not pointed anywhere) -- the write was rejected outright, not partially applied",
      store._conn.execute("SELECT merged_into_device_id FROM devices WHERE device_id='cycleB'").fetchone()[0] is None)

# Defense-in-depth: resolve_canonical_device_id() must still survive a cycle that
# reaches the data some OTHER way (e.g. the exact real .94 cycle this fix was
# built from predates this fix and had to be repaired via direct SQL, not through
# merge_device() at all) -- simulate that directly, bypassing merge_device()'s new
# guard entirely, and confirm the read path still degrades safely instead of
# looping forever.
store._conn.execute("INSERT OR REPLACE INTO devices (device_id, first_seen, last_seen) VALUES ('rawCycleA', 700.0, 700.0)")
store._conn.execute("INSERT OR REPLACE INTO devices (device_id, first_seen, last_seen) VALUES ('rawCycleB', 700.0, 700.0)")
# Both rows must already exist before either FK reference is set (merged_into_device_id
# REFERENCES devices(device_id)), so the cross-pointing UPDATE has to come after both INSERTs.
store._conn.execute("UPDATE devices SET merged_into_device_id = 'rawCycleB' WHERE device_id = 'rawCycleA'")
store._conn.execute("UPDATE devices SET merged_into_device_id = 'rawCycleA' WHERE device_id = 'rawCycleB'")
try:
    store.resolve_canonical_device_id("rawCycleA")
    check("resolve_canonical_device_id still detects a cycle written by some other means, "
          "rather than infinite-looping", False, "no exception raised")
except RuntimeError as e:
    check("resolve_canonical_device_id still detects a cycle written by some other means, "
          "rather than infinite-looping", "cycle" in str(e))

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

# BUGFIX regression (live audit, 2026-09-08): multicast/link-local/broadcast
# destinations must never report cross-device "targeting" -- every device sends mDNS/
# SSDP/ICMPv6-ND to these addresses as ordinary LAN presence, which previously scored
# as COORDINATED_TARGETING attack corroboration (83% of non-suppressed HIGH alerts in
# a live 6h sample were exactly this shape).
store.insert_evidence(Evidence(device_id="mc_dev_a", destination_id="224.0.0.251",
                                 evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                 timestamp=7_000_000.0, source="s"))
store.insert_evidence(Evidence(device_id="mc_dev_b", destination_id="224.0.0.251",
                                 evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                 timestamp=7_000_010.0, source="s"))
store.insert_evidence(Evidence(device_id="mc_dev_c", destination_id="ff02::fb",
                                 evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                 timestamp=7_000_010.0, source="s"))
store.insert_evidence(Evidence(device_id="mc_dev_d", destination_id="ff02::fb",
                                 evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                 timestamp=7_000_020.0, source="s"))
store.insert_evidence(Evidence(device_id="mc_dev_e", destination_id="192.168.1.255",
                                 evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                 timestamp=7_000_020.0, source="s"))
store.insert_evidence(Evidence(device_id="mc_dev_f", destination_id="192.168.1.255",
                                 evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                 timestamp=7_000_030.0, source="s"))
check("get_devices_targeting returns [] for an IPv4 multicast destination (mDNS group)",
      store.get_devices_targeting("224.0.0.251", since=6_999_000.0) == [])
check("get_devices_targeting returns [] for an IPv6 multicast destination (mDNS group)",
      store.get_devices_targeting("ff02::fb", since=6_999_000.0) == [])
check("get_devices_targeting returns [] for an IPv4 subnet-broadcast destination",
      store.get_devices_targeting("192.168.1.255", since=6_999_000.0) == [])
check("get_devices_targeting still works normally for a real (non-multicast) shared destination",
      set(store.get_devices_targeting("shared.example.com", since=6_999_000.0)) == {"p1a_dev_a", "p1a_dev_b"})

# BUGFIX #2 regression (live audit, 2026-09-08): a PRIVATE destination that's
# structurally shared household infrastructure (a router/hub/another of the user's
# own devices most of the fleet talks to) must not report cross-device "targeting"
# either -- confirmed live: 192.168.77.47 (a second Fire TV) was independently
# touched by 7/household devices and got auto-blocked repeatedly even after the
# multicast fix above, because the bar was just 1 OTHER device with no regard for
# how large a share of the whole fleet that destination is normal for.
si_store = GraphStore(str(_PathForSysPath(tmpdir) / "test_graph_shared_infra.db"))
# A 10-device fleet (all last_seen inside the lookback window used below).
for i in range(10):
    si_store.insert_evidence(Evidence(device_id=f"si_fleet_{i}", destination_id="sentinel.example.com",
                                        evidence_type="dns_entropy", independence_family="dns_behavior",
                                        timestamp=10_000_000.0, source="s"))
# 5 of those 10 (50% >= the 0.4 ratio bar) independently touch a shared local hub IP.
for i in range(5):
    si_store.insert_evidence(Evidence(device_id=f"si_fleet_{i}", destination_id="192.168.1.47",
                                        evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                        timestamp=10_000_100.0 + i, source="s"))
check("get_devices_targeting returns [] for a PRIVATE destination touched by a majority "
      "of a large-enough fleet (5/10 = 50% >= 40% bar) -- structural shared infrastructure",
      si_store.get_devices_targeting("192.168.1.47", since=10_000_050.0) == [])

# Real coordination must still work: only 2 of the same 10-device fleet touch an
# otherwise-unusual destination (20% < the 40% bar) -- genuine corroboration signal.
for i in range(2):
    si_store.insert_evidence(Evidence(device_id=f"si_fleet_{i}", destination_id="192.168.1.199",
                                        evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                        timestamp=10_000_200.0 + i, source="s"))
si_minority = si_store.get_devices_targeting("192.168.1.199", since=10_000_150.0)
check("get_devices_targeting still reports real coordination when only a MINORITY of "
      "the fleet (2/10 = 20% < 40% bar) shares an unusual private destination",
      set(si_minority) == {"si_fleet_0", "si_fleet_1"}, f"got {si_minority}")

# A small household network (< MIN_FLEET_SIZE) must never be ratio-suppressed --
# 1 device touching something in a 2-device fleet is 50%, but the fleet is too small
# for a ratio to mean anything.
si_small = GraphStore(str(_PathForSysPath(tmpdir) / "test_graph_shared_infra_small.db"))
si_small.insert_evidence(Evidence(device_id="sm_dev_a", destination_id="192.168.1.1",
                                    evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                    timestamp=11_000_000.0, source="s"))
si_small.insert_evidence(Evidence(device_id="sm_dev_b", destination_id="192.168.1.1",
                                    evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                    timestamp=11_000_010.0, source="s"))
si_small_targeting = si_small.get_devices_targeting("192.168.1.1", since=10_999_000.0)
check("get_devices_targeting does NOT ratio-suppress a small fleet (2 devices, below "
      "MIN_FLEET_SIZE) even though the touching ratio would otherwise be high",
      set(si_small_targeting) == {"sm_dev_a", "sm_dev_b"}, f"got {si_small_targeting}")

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

# --- is_own_registered_device (2026-09-15, gap 3 of the "3 automated-learning gaps"
# audit -- part C, the shared identity check both the reputation-tier fix and the
# new local-origin auto-corroboration path build on) ---
store.upsert_device("own_dev_by_id", timestamp=9_000_000.0)
check("a destination_id that IS itself a real device_id is recognized as own hardware",
      store.is_own_registered_device("own_dev_by_id"))

store.upsert_device("own_dev_by_ip", timestamp=9_000_000.0)
# Deliberately a different-looking private range than this project's own real
# household subnet (192.168.77.0/24) -- per feedback_network_agnostic_design.md,
# this check is a plain metadata lookup, not tied to any one network's addressing.
store.update_device_metadata("own_dev_by_ip", {"known_ips_history": {"10.77.0.5": 9_000_000.0}},
                               timestamp=9_000_000.0)
check("a destination_id that appears as a KEY in some device's known_ips_history is "
      "recognized as own hardware, even though it's not that device's OWN device_id",
      store.is_own_registered_device("10.77.0.5"))
check("a destination_id that is NOT any device's id and NOT in anyone's "
      "known_ips_history is correctly NOT recognized as own hardware -- an unknown "
      "external host stays unknown",
      not store.is_own_registered_device("203.0.113.200"))
check("an empty destination_id is rejected outright, never crashes",
      not store.is_own_registered_device(""))
check("the NO_DESTINATION sentinel is rejected outright",
      not store.is_own_registered_device(NO_DESTINATION))

store.record_device_destinations("n2_dev_iot1", ["a.example.com", "b.example.com"],
                                  timestamp=9_100_000.0)
store.record_device_destinations("n2_dev_iot1", ["a.example.com"],
                                  timestamp=9_100_020.0)  # SAME destination again -- must not double-count
store.record_device_destinations("n2_dev_iot1", ["old.example.com"],
                                  timestamp=8_000_000.0)  # before `since`

count = store.get_distinct_destination_count("n2_dev_iot1", since=9_099_000.0)
check("get_distinct_destination_count counts DISTINCT destinations, not raw traffic "
      "records (2 real destinations seen within the window; the third was before `since`)",
      count == 2, f"got {count}")
check("get_distinct_destination_count with no traffic at all for a device returns 0, "
      "not an error", store.get_distinct_destination_count("n2_never_seen", since=0.0) == 0)

# BUGFIX regression (live audit, 2026-09-09): distinct-destination counting must be based
# on real observed traffic (device_destinations), not on the evidence table -- the evidence
# table only gets a row when SOME OTHER detector already flagged something, which is a
# detector-biased proxy for traffic rather than traffic itself, and created a self-reinforcing
# false-positive loop with PeerDeviationHypothesis (more noise from unrelated detectors ->
# more evidence rows -> inflated distinct-destination count -> more PEER_COHORT_DEVIATION).
#
# BUGFIX regression (live audit, 2026-09-08): multicast/broadcast destinations must
# not inflate a device's distinct-destination count -- they're ordinary LAN protocol
# chatter every device sends, not real behavioral/destination diversity, and
# previously fed PeerDeviationHypothesis's device-vs-cohort comparison directly.
store.record_device_destinations("n2_dev_mc", ["a.example.com"], timestamp=9_100_000.0)
store.record_device_destinations(
    "n2_dev_mc", ["224.0.0.251", "ff02::fb", "239.255.255.250"], timestamp=9_100_020.0)
mc_count = store.get_distinct_destination_count("n2_dev_mc", since=9_099_000.0)
check("get_distinct_destination_count excludes multicast/broadcast destinations "
      "(1 real destination + 3 multicast group addresses -> count is 1, not 4)",
      mc_count == 1, f"got {mc_count}")

# --- record_device_destinations / prune_device_destinations (real-traffic redesign, 2026-09-09) ---
store.record_device_destinations("n2_dev_rt", ["c.example.com", "d.example.com"],
                                  timestamp=9_200_000.0)
store.record_device_destinations("n2_dev_rt", ["c.example.com"],
                                  timestamp=9_300_000.0)  # re-seen later -- must bump last_seen, not duplicate
rt_count = store.get_distinct_destination_count("n2_dev_rt", since=9_150_000.0)
check("record_device_destinations upserts on (device_id, destination_id) -- re-recording "
      "an already-seen destination does not create a second row",
      rt_count == 2, f"got {rt_count}")
rt_count_after_bump = store.get_distinct_destination_count("n2_dev_rt", since=9_250_000.0)
check("record_device_destinations updates last_seen on re-observation -- c.example.com's "
      "last_seen moved to 9_300_000.0 so it is still counted with a `since` after its "
      "original first_seen but before its updated last_seen",
      rt_count_after_bump == 1, f"got {rt_count_after_bump}")

deleted = store.prune_device_destinations(older_than_days=1, now=9_300_000.0 + 2 * 86400)
check("prune_device_destinations deletes rows older than the retention window",
      deleted >= 2, f"got {deleted}")
check("prune_device_destinations actually removes the pruned rows -- count drops to 0",
      store.get_distinct_destination_count("n2_dev_rt", since=0.0) == 0)

# --- prune_weak_zeek_notices (explicit user request, 2026-09-09 -- zeek_notice was
# 98.3% of .94's real evidence table; weak-tier alone accounted for the overwhelming
# majority, contributing ZERO scoring weight to any hypothesis) ---
_wnow = 9_400_000.0
store.insert_evidence(Evidence(device_id="wn_dev1", destination_id=NO_DESTINATION,
                                 evidence_type="zeek_notice_weak", independence_family="network_behavior",
                                 timestamp=_wnow - 13 * 3600, source="s"))  # older than 12h -- prunable
store.insert_evidence(Evidence(device_id="wn_dev1", destination_id=NO_DESTINATION,
                                 evidence_type="zeek_notice_weak", independence_family="network_behavior",
                                 timestamp=_wnow - 1 * 3600, source="s"))  # within 12h -- kept
store.insert_evidence(Evidence(device_id="wn_dev1", destination_id=NO_DESTINATION,
                                 evidence_type="zeek_notice_medium", independence_family="network_behavior",
                                 timestamp=_wnow - 13 * 3600, source="s"))  # same age, but NOT weak -- kept
weak_deleted = store.prune_weak_zeek_notices(older_than_hours=12.0, now=_wnow)
check("prune_weak_zeek_notices deletes exactly the old WEAK-tier row, nothing else",
      weak_deleted == 1, f"got {weak_deleted}")
remaining_weak = store._conn.execute(
    "SELECT COUNT(*) AS c FROM evidence WHERE device_id = 'wn_dev1' AND evidence_type = 'zeek_notice_weak'"
).fetchone()["c"]
remaining_medium = store._conn.execute(
    "SELECT COUNT(*) AS c FROM evidence WHERE device_id = 'wn_dev1' AND evidence_type = 'zeek_notice_medium'"
).fetchone()["c"]
check("REGRESSION GUARD: the recent weak-tier row survives (within the 12h window)",
      remaining_weak == 1, f"got {remaining_weak}")
check("REGRESSION GUARD: a medium-tier row of the SAME age is untouched -- this prune "
      "is scoped to weak tier specifically, not a blanket age-based sweep",
      remaining_medium == 1, f"got {remaining_medium}")
check("prune_weak_zeek_notices with nothing to prune is a safe no-op (0, not an error)",
      store.prune_weak_zeek_notices(older_than_hours=12.0, now=_wnow) == 0)

# --- BUGFIX (2026-09-20, restart-cadence investigation): the legacy, unfragmented
# 'zeek_notice' type (pre-2026-09-09 fragmentation fix, 215,543 rows found live on
# .94 across 21 devices) is now folded into the SAME fast sweep -- it scores nothing
# and cannot be newly created by any code path today, so it's pure dead weight. ---
store.insert_evidence(Evidence(device_id="wn_dev2", destination_id=NO_DESTINATION,
                                 evidence_type="zeek_notice", independence_family="network_behavior",
                                 timestamp=_wnow - 13 * 3600, source="s"))  # legacy bare type, old -- prunable
store.insert_evidence(Evidence(device_id="wn_dev2", destination_id=NO_DESTINATION,
                                 evidence_type="zeek_notice", independence_family="network_behavior",
                                 timestamp=_wnow - 1 * 3600, source="s"))  # legacy bare type, recent -- kept
legacy_deleted = store.prune_weak_zeek_notices(older_than_hours=12.0, now=_wnow)
check("prune_weak_zeek_notices ALSO deletes the old legacy bare 'zeek_notice' row",
      legacy_deleted == 1, f"got {legacy_deleted}")
remaining_legacy = store._conn.execute(
    "SELECT COUNT(*) AS c FROM evidence WHERE device_id = 'wn_dev2' AND evidence_type = 'zeek_notice'"
).fetchone()["c"]
check("REGRESSION GUARD: the recent legacy-type row survives (within the 12h window, "
      "same age-cutoff logic as every other type this sweep handles)",
      remaining_legacy == 1, f"got {remaining_legacy}")

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
      # 2026-09-10, AUDIT_V14_REVIEW_RESPONSE.md §2.2: bumped from -4000 (4MB, closer
      # to SQLite's own -2000 default than a real cache) to -48000 (48MB) -- see
      # store.py's own _HARDWARE_PROFILE_CACHE_SIZE_KB comment for why.
      store_pi._conn.execute("PRAGMA cache_size").fetchone()[0] == -48000)
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

# =============================================================================
# threshold_history.device_type migration -- 2026-09-16, per-device/category
# autotuning plan. ALTER TABLE ADD COLUMN has no "IF NOT EXISTS" in SQLite;
# _migrate_existing_db() wraps it in try/except OperationalError -- confirm
# that's actually idempotent (re-opening a db that already has the column
# doesn't raise) using a REAL FILE-backed db, since :memory: can't be
# reopened to exercise this at all (every other test in this file already
# implicitly exercises the "column already exists" path once per :memory:
# instance, just never a genuine SECOND open of the SAME db).
# =============================================================================
with tempfile.TemporaryDirectory() as tmpdir:
    migration_db_path = str(_PathForSysPath(tmpdir) / "migration_test.db")
    first_open = GraphStore(migration_db_path)
    check("threshold_history has the device_type column on first open (fresh db, via schema.sql)",
          any(row[1] == "device_type" for row in first_open._conn.execute("PRAGMA table_info(threshold_history)")))
    first_open.close()

    try:
        second_open = GraphStore(migration_db_path)
        reopened_ok = True
    except Exception as exc:
        reopened_ok = False
        second_open = None
        _reopen_error = exc
    check("threshold_history migration is idempotent -- reopening a db that "
          "already has device_type does not raise",
          reopened_ok, "" if reopened_ok else str(_reopen_error))
    if second_open is not None:
        check("threshold_history still has exactly one device_type column after "
              "a second open (no duplicate-column corruption)",
              sum(1 for row in second_open._conn.execute("PRAGMA table_info(threshold_history)")
                   if row[1] == "device_type") == 1)
        second_open.close()  # Windows: an unclosed sqlite connection blocks the
                              # TemporaryDirectory's own cleanup on __exit__.

# 2026-09-16 REGRESSION COVERAGE: the check above never actually exercised a
# GENUINELY old db -- it only reopens a db that _apply_schema() (the fresh-db
# path) already created WITH device_type, so "column already exists" was the
# only branch it ever took. The real bug (confirmed live: .94's own
# state/v13_graph.db, predating this migration, has no device_type column)
# was that _migrate_existing_db()'s CREATE INDEX ...(device_type, ...) used to
# sit INSIDE the executescript block, running against threshold_history BEFORE
# the ALTER TABLE ADD COLUMN (issued after the script) ever got a chance to
# add it -- raising "no such column: device_type" out of GraphStore.__init__
# for every old-db deployment. This builds an old-shaped db by hand (the exact
# pre-2026-09-16 threshold_history column set) to actually exercise that path.
with tempfile.TemporaryDirectory() as tmpdir:
    old_db_path = str(_PathForSysPath(tmpdir) / "genuinely_old.db")
    # Build a fully valid, CURRENT-schema db first (every real table, via the
    # normal schema.sql path) so this fixture never drifts from the actual
    # schema -- then surgically revert ONLY threshold_history to its
    # pre-2026-09-16 shape, mirroring exactly what was confirmed live on .94's
    # own real database (device_id, parameter, old_value, new_value,
    # proposed_at, canary_until, promoted_at, rolled_back_at, reason,
    # backtest_run_id, snapshot_id -- no device_type).
    seed_store = GraphStore(old_db_path)
    seed_store.close()
    raw_conn = sqlite3.connect(old_db_path)
    raw_conn.execute("DROP INDEX IF EXISTS idx_threshold_history_device_type")
    raw_conn.execute("ALTER TABLE threshold_history DROP COLUMN device_type")
    raw_conn.commit()
    raw_conn.close()

    _c = sqlite3.connect(old_db_path)
    pre_cols = [row[1] for row in _c.execute("PRAGMA table_info(threshold_history)")]
    _c.close()
    check("fixture actually lacks device_type before GraphStore ever opens it (sanity check on the test itself)",
          "device_type" not in pre_cols, str(pre_cols))

    try:
        old_store = GraphStore(old_db_path)
        old_open_ok = True
    except Exception as exc:
        old_open_ok = False
        old_store = None
        _old_open_error = exc
    check("GraphStore opens a genuinely pre-device_type db without raising "
          "(the real bug: this used to throw 'no such column: device_type')",
          old_open_ok, "" if old_open_ok else f"{type(_old_open_error).__name__}: {_old_open_error}")

    if old_store is not None:
        migrated_cols = [row[1] for row in old_store._conn.execute("PRAGMA table_info(threshold_history)")]
        check("device_type column was actually added to the old table by migration",
              "device_type" in migrated_cols)
        idx_names = [row[0] for row in old_store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='threshold_history'")]
        check("idx_threshold_history_device_type index was created after the column existed",
              "idx_threshold_history_device_type" in idx_names)
        # end-to-end: the whole point of the column is a device_type-scoped write/read
        old_store.upsert_device("dev_regression_test")
        old_store._conn.execute(
            "INSERT INTO threshold_history (change_id, device_id, device_type, parameter, "
            "old_value, new_value, proposed_at) VALUES (?, ?, ?, 'x', 0.1, 0.2, ?)",
            ("regress1", "dev_regression_test", "iot", time.time()),
        )
        old_store._maybe_commit()
        row = old_store._conn.execute(
            "SELECT device_type FROM threshold_history WHERE change_id='regress1'").fetchone()
        check("a device_type-scoped row can actually be written and read back after migration",
              row is not None and row[0] == "iot")
        old_store.close()
        second_open.close()

# --- BUGFIX (2026-09-20, memory-restart root-cause investigation) -----------
# insert_decision() used to persist attack_evidence/winning_evidence (full
# serialized Evidence objects, built only for pipeline.py's same-cycle Telegram
# WHY-block) wholesale into raw_payload_json forever -- found live on .94 as a
# 22MB single row, 13.3MB of that from attack_evidence alone. Also used to store
# _all_evidence_ids fully uncapped when the edge cap was exceeded -- one legacy
# row had 68,915 ids there (~2.2MB) despite the edge cap being only 50.
_bugfix_dir = tempfile.mkdtemp(prefix="v13_graph_bugfix_test_")
bugfix_db_path = str(_PathForSysPath(_bugfix_dir) / "test_graph.db")
bugfix_store = GraphStore(bugfix_db_path, hardware_profile="x86_16gb")

sync_mode = bugfix_store._conn.execute("PRAGMA synchronous").fetchone()[0]
check("synchronous is NORMAL (1), not the fsync-per-commit FULL default -- "
      "set per-connection in __init__ since it does NOT persist in the db "
      "file the way journal_mode does",
      sync_mode == 1, f"got {sync_mode}")

bugfix_dev = "dev_bugfix_test"
bugfix_store.upsert_device(bugfix_dev)
bugfix_evidence_ids = []
for i in range(5):
    ev = Evidence(device_id=bugfix_dev, destination_id=NO_DESTINATION, evidence_type="x",
                   independence_family="f", timestamp=time.time(), source="s")
    bugfix_store.insert_evidence(ev)
    bugfix_evidence_ids.append(ev.evidence_id)

small_payload = {
    "state": "BENIGN", "decision_path": "test",
    "attack_evidence": [{"evidence_id": e, "big": "x" * 1000} for e in bugfix_evidence_ids],
    "winning_evidence": [{"evidence_id": e} for e in bugfix_evidence_ids],
}
small_decision_id = bugfix_store.insert_decision(
    device_id=bugfix_dev, timestamp=time.time(), state="BENIGN", decision_path="test",
    confidence=0.0, risk_score=0.0, raw_payload=small_payload, evidence_ids=bugfix_evidence_ids,
)
stored_row = bugfix_store._conn.execute(
    "SELECT raw_payload_json FROM decisions WHERE decision_id=?", (small_decision_id,)).fetchone()
stored_payload = json.loads(stored_row["raw_payload_json"])
check("attack_evidence is stripped from the PERSISTED payload (still fine to "
      "exist transiently in the in-memory dict pipeline.py's WHY-block uses "
      "same-cycle -- this only checks what actually lands in the db)",
      "attack_evidence" not in stored_payload)
check("winning_evidence is stripped from the PERSISTED payload",
      "winning_evidence" not in stored_payload)
check("the rest of the payload (state/decision_path) survives the strip",
      stored_payload.get("state") == "BENIGN" and stored_payload.get("decision_path") == "test")

# Regression test against the exact real-world shape found live: a decision
# whose evidence list is far larger than any hardware-profile edge cap.
huge_dev = "dev_huge_evidence_test"
bugfix_store.upsert_device(huge_dev)
huge_evidence_ids = []
for i in range(120):
    ev = Evidence(device_id=huge_dev, destination_id=NO_DESTINATION, evidence_type="x",
                   independence_family="f", timestamp=time.time() + i, source="s")
    bugfix_store.insert_evidence(ev)
    huge_evidence_ids.append(ev.evidence_id)
# Simulates the real 68,915-id shape without actually inserting that many rows --
# _all_evidence_ids only needs the ids themselves, not real backing evidence rows,
# to exercise the cap logic (the real evidence rows above establish timestamps for
# the 120 that ARE real, the synthetic ones exercise the "no matching row yet"
# fallback path the same way fresh-this-cycle evidence does).
synthetic_huge_ids = huge_evidence_ids + [f"synthetic-{i}" for i in range(2000)]
huge_decision_id = bugfix_store.insert_decision(
    device_id=huge_dev, timestamp=time.time(), state="BENIGN", decision_path="test",
    confidence=0.0, risk_score=0.0, raw_payload={}, evidence_ids=synthetic_huge_ids,
)
huge_row = bugfix_store._conn.execute(
    "SELECT raw_payload_json FROM decisions WHERE decision_id=?", (huge_decision_id,)).fetchone()
huge_payload = json.loads(huge_row["raw_payload_json"])
check("_all_evidence_ids is capped at _MAX_ALL_EVIDENCE_IDS_STORED (1000), not "
      "left fully uncapped -- found live: 68,915 ids (~2.2MB) on one legacy row",
      len(huge_payload.get("_all_evidence_ids", [])) == 1000,
      f"got {len(huge_payload.get('_all_evidence_ids', []))}")
supports_edge_count = bugfix_store._conn.execute(
    "SELECT COUNT(*) c FROM edges WHERE dst_id=? AND relation='supports'", (huge_decision_id,)
).fetchone()["c"]
check("the edge cap itself (x86_16gb: 50) is unaffected by this change",
      supports_edge_count == 50, f"got {supports_edge_count}")

bugfix_store.close()

# --- prune_evidence() archive_network_activity_backup path -------------------
archive_dir = tempfile.mkdtemp(prefix="v13_graph_archive_test_")
archive_db_path = str(_PathForSysPath(archive_dir) / "test_graph.db")
archive_store = GraphStore(archive_db_path)
old_ts = time.time() - 200 * 86400
archived_ev = Evidence(device_id="dev_archive_test", destination_id=NO_DESTINATION,
                         evidence_type="x", independence_family="f", timestamp=old_ts, source="s")
archive_store.insert_evidence(archived_ev)

no_archive_path = _PathForSysPath(archive_dir) / "no_archive.jsonl.gz"
deleted_no_archive = archive_store.prune_evidence(older_than_days=90, archive_path=None)
check("prune_evidence() with archive_path=None (the production default) deletes "
      "the row without writing any archive file -- zero unbounded-growth risk",
      deleted_no_archive == 1 and not no_archive_path.exists())

archived_ev2 = Evidence(device_id="dev_archive_test2", destination_id=NO_DESTINATION,
                          evidence_type="x", independence_family="f", timestamp=old_ts, source="s")
archive_store.insert_evidence(archived_ev2)
real_archive_path = _PathForSysPath(archive_dir) / "evidence_archive.jsonl.gz"
deleted_with_archive = archive_store.prune_evidence(older_than_days=90, archive_path=real_archive_path)
check("prune_evidence() with an archive_path (dev/test opt-in only) deletes AND "
      "writes the row to the archive file first",
      deleted_with_archive == 1 and real_archive_path.exists())
if real_archive_path.exists():
    import gzip as _gzip
    with _gzip.open(real_archive_path, "rt", encoding="utf-8") as f:
        archived_lines = [json.loads(line) for line in f if line.strip()]
    check("the archived line actually contains the deleted evidence row's data",
          any(line.get("evidence_id") == archived_ev2.evidence_id for line in archived_lines))
archive_store.close()

# --- BUGFIX (2026-09-20, restart-cadence investigation) ----------------------
# get_evidence_for_device()'s cap_per_type: a real device found live on .94
# generated 41,509 evidence rows (39,551 zeek_notice_weak) in ONE 24h window,
# blowing the pipeline's 60s heartbeat deadline every ~2s decision cycle and
# self-restarting every ~12-14 minutes. cap_per_type bounds how many rows of
# any ONE evidence_type get constructed, most-recent-first, per device.
cap_dir = tempfile.mkdtemp(prefix="v13_graph_cap_test_")
cap_db_path = str(_PathForSysPath(cap_dir) / "test_graph.db")
cap_store = GraphStore(cap_db_path)
cap_dev = "dev_cap_test"
cap_store.upsert_device(cap_dev)
now_cap = time.time()

# 500 zeek_notice_weak items (simulates the pathological volume) + 3 genuinely
# distinct dns_behavior items -- the exact mixed shape a real chatty device has.
weak_ids_oldest_to_newest = []
for i in range(500):
    ev = Evidence(device_id=cap_dev, destination_id=NO_DESTINATION, evidence_type="zeek_notice_weak",
                   independence_family="network_behavior", timestamp=now_cap + i, source="s", confidence=0.4)
    cap_store.insert_evidence(ev)
    weak_ids_oldest_to_newest.append(ev.evidence_id)
dns_ids = []
for i in range(3):
    ev = Evidence(device_id=cap_dev, destination_id=NO_DESTINATION, evidence_type="dns_behavior",
                   independence_family="dns_behavior", timestamp=now_cap + 1000 + i, source="s", confidence=0.8)
    cap_store.insert_evidence(ev)
    dns_ids.append(ev.evidence_id)

uncapped = cap_store.get_evidence_for_device(cap_dev)
check("cap_per_type=None (the default) preserves the original fully-unbounded behavior",
      len(uncapped) == 503, f"got {len(uncapped)}")

capped = cap_store.get_evidence_for_device(cap_dev, cap_per_type=50)
weak_in_capped = [e for e in capped if e.evidence_type == "zeek_notice_weak"]
dns_in_capped = [e for e in capped if e.evidence_type == "dns_behavior"]
check("cap_per_type=50 bounds the 500 zeek_notice_weak items down to 50",
      len(weak_in_capped) == 50, f"got {len(weak_in_capped)}")
check("cap_per_type=50 does NOT truncate a type with fewer items than the cap (all 3 dns_behavior survive)",
      len(dns_in_capped) == 3, f"got {len(dns_in_capped)}")
check("the capped result is still sorted ascending by timestamp (this method's own documented contract)",
      all(capped[i].timestamp <= capped[i + 1].timestamp for i in range(len(capped) - 1)))
kept_weak_ids = {e.evidence_id for e in weak_in_capped}
most_recent_50_ids = set(weak_ids_oldest_to_newest[-50:])
check("the 50 zeek_notice_weak items KEPT are the most-recent 50, not an arbitrary/oldest subset",
      kept_weak_ids == most_recent_50_ids)

cap_store.close()

# --- evidence_for_destination_exists() (replaces domain_seen_before()'s own
# previous full-fetch-then-scan implementation with a targeted EXISTS query) --
exists_dir = tempfile.mkdtemp(prefix="v13_graph_exists_test_")
exists_db_path = str(_PathForSysPath(exists_dir) / "test_graph.db")
exists_store = GraphStore(exists_db_path)
exists_dev = "dev_exists_test"
exists_store.upsert_device(exists_dev)
now_exists = time.time()
old_hit = Evidence(device_id=exists_dev, destination_id="a.com", evidence_type="x",
                     independence_family="f", timestamp=now_exists - 1800, source="s")
exists_store.insert_evidence(old_hit)

check("evidence_for_destination_exists finds a.com's older hit within a wide window",
      exists_store.evidence_for_destination_exists(
          exists_dev, "a.com", since=now_exists - 100_000, before=now_exists))
check("evidence_for_destination_exists correctly returns False for a domain never contacted",
      not exists_store.evidence_for_destination_exists(
          exists_dev, "z.com", since=now_exists - 100_000, before=now_exists))
check("evidence_for_destination_exists respects the `before` cutoff -- a.com's hit at "
      "-1800s is excluded when `before` exclude everything after -3600s",
      not exists_store.evidence_for_destination_exists(
          exists_dev, "a.com", since=now_exists - 100_000, before=now_exists - 3600))
check("evidence_for_destination_exists respects the `since` floor -- a.com's hit at "
      "-1800s is excluded when `since` starts at -900s",
      not exists_store.evidence_for_destination_exists(
          exists_dev, "a.com", since=now_exists - 900, before=now_exists))
exists_store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 GraphStore checks PASSED.")
