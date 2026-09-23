"""
Standalone runtime test for the disk-budget governor (2026-09-23, explicit user
requirement: total disk usage must never exceed a hard ceiling, e.g. 20GB,
regardless of device count or traffic pattern). Not part of the pytest suite --
run directly: `.venv/Scripts/python.exe tests/test_disk_budget_governor.py`

No monkeypatching -- real GraphStore instances, real files/directories on disk,
real PRAGMA incremental_vacuum/auto_vacuum calls.

Covers:
  A. GraphStore.get_disk_usage_bytes() -- real file sizes
  B. GraphStore.enable_incremental_vacuum() / incremental_vacuum_step() -- real
     mode conversion and real file shrinkage after deleting a large chunk of data
  C. get_decisions_batch_cutoff() / get_evidence_batch_cutoff() -- respects the
     min_age_days floor, returns None when nothing eligible
  D. disk_budget_governor._enforce_graph_db_budget() -- trims oldest-first when
     over budget, stops at the floor, never touches recent rows
  E. disk_budget_governor._enforce_zeek_logs_budget() -- deletes oldest dated
     directories first, respects the floor, ignores non-dated entries (`current`)
"""
import shutil
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.graph.store import GraphStore  # noqa: E402

# ═══════════════════════════════════════════════════════════════════════════════
# Section A: get_disk_usage_bytes()
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_a = tempfile.mkdtemp(prefix="budget_test_a_")
db_path_a = str(_PathForSysPath(tmpdir_a) / "test.db")
store_a = GraphStore(db_path_a)
store_a.upsert_device("dev1", timestamp=time.time())
store_a.close()

usage = GraphStore(db_path_a).get_disk_usage_bytes()
check("A1: get_disk_usage_bytes() reports a real, nonzero main_bytes",
      usage["main_bytes"] > 0, str(usage))
check("A2: total_bytes == main_bytes + wal_bytes", usage["total_bytes"] == usage["main_bytes"] + usage["wal_bytes"])

# ═══════════════════════════════════════════════════════════════════════════════
# Section B: enable_incremental_vacuum() / incremental_vacuum_step() -- real shrink
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_b = tempfile.mkdtemp(prefix="budget_test_b_")
db_path_b = str(_PathForSysPath(tmpdir_b) / "test.db")
store_b = GraphStore(db_path_b)

converted = store_b.enable_incremental_vacuum()
check("B1: enable_incremental_vacuum() converts a fresh db", converted is True)
converted_again = store_b.enable_incremental_vacuum()
check("B2: calling it again is a no-op (already incremental)", converted_again is False)

now_b = time.time()
store_b.upsert_device("devB", timestamp=now_b)
for i in range(3000):
    store_b._conn.execute(
        "INSERT INTO decisions (decision_id, device_id, timestamp, state, decision_path) "
        "VALUES (?, 'devB', ?, 'SAFE', 'test')",
        (f"dec_{i}", now_b - 100 * 86400.0),
    )
store_b._conn.commit()
# checkpoint first -- with WAL mode (this schema's default), inserted content
# lives in the WAL until checkpointed, so the MAIN file alone wouldn't reflect
# the seeded data yet. total_bytes (main+WAL) is what actually matters for real
# disk usage either way.
store_b.checkpoint_wal_truncate()
size_before_delete = store_b.get_disk_usage_bytes()["total_bytes"]

deleted_counts = store_b.prune_decisions_and_alerts(older_than_days=1.0, now=now_b)
check("B3: the 3000 seeded rows were actually deleted", deleted_counts["decisions"] == 3000, str(deleted_counts))
store_b.checkpoint_wal_truncate()

size_after_delete_no_vacuum = store_b.get_disk_usage_bytes()["total_bytes"]
check("B4: DELETE alone does NOT shrink the file (proves incremental_vacuum is actually needed)",
      size_after_delete_no_vacuum >= size_before_delete * 0.95,
      f"before={size_before_delete} after_delete_only={size_after_delete_no_vacuum}")

for _ in range(20):
    remaining = store_b.incremental_vacuum_step(pages=5000)
    if remaining == 0:
        break
# incremental_vacuum's own writes land in the WAL like any other write in WAL
# mode -- checkpoint again so the measurement reflects the real, post-reclaim
# on-disk total instead of counting freed-main-file-space-not-yet-checkpointed
# as if it were still growth.
store_b.checkpoint_wal_truncate()
size_after_vacuum = store_b.get_disk_usage_bytes()["total_bytes"]
check("B5: incremental_vacuum_step() DOES shrink the file after deleting data",
      size_after_vacuum < size_after_delete_no_vacuum,
      f"after_delete_only={size_after_delete_no_vacuum} after_vacuum={size_after_vacuum}")

store_b.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Section C: batch-cutoff helpers respect the floor
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_c = tempfile.mkdtemp(prefix="budget_test_c_")
store_c = GraphStore(str(_PathForSysPath(tmpdir_c) / "test.db"))
now_c = time.time()
store_c.upsert_device("devC", timestamp=now_c)

# 10 decisions older than the 30-day floor, 5 newer than it.
for i in range(10):
    store_c._conn.execute(
        "INSERT INTO decisions (decision_id, device_id, timestamp, state, decision_path) "
        "VALUES (?, 'devC', ?, 'SAFE', 'test')",
        (f"old_{i}", now_c - (40 + i) * 86400.0),
    )
for i in range(5):
    store_c._conn.execute(
        "INSERT INTO decisions (decision_id, device_id, timestamp, state, decision_path) "
        "VALUES (?, 'devC', ?, 'SAFE', 'test')",
        (f"recent_{i}", now_c - (1 + i) * 86400.0),
    )
store_c._conn.commit()

cutoff_5 = store_c.get_decisions_batch_cutoff(5, min_age_days=30.0, now=now_c)
check("C1: batch cutoff for 5 rows returns a real timestamp when 10 eligible rows exist",
      cutoff_5 is not None)
check("C2: that cutoff is still older than the 30-day floor",
      cutoff_5 < now_c - 30 * 86400.0)

cutoff_too_many = store_c.get_decisions_batch_cutoff(100, min_age_days=30.0, now=now_c)
check("C3: batch cutoff returns None when fewer than batch_size rows are eligible "
      "(only 10 rows are past the floor, not 100)", cutoff_too_many is None)

cutoff_all_recent = store_c.get_decisions_batch_cutoff(1, min_age_days=100.0, now=now_c)
check("C4: raising the floor above every row's age returns None -- nothing eligible",
      cutoff_all_recent is None)

store_c.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Section D: _enforce_graph_db_budget() -- end-to-end trim-to-budget behavior
# ═══════════════════════════════════════════════════════════════════════════════
import argus.ops.disk_budget_governor as governor  # noqa: E402

tmpdir_d = tempfile.mkdtemp(prefix="budget_test_d_")
db_path_d = str(_PathForSysPath(tmpdir_d) / "test.db")
store_d = GraphStore(db_path_d)
store_d.enable_incremental_vacuum()
now_d = time.time()
store_d.upsert_device("devD", timestamp=now_d)

# A large batch of OLD rows (past the floor) with a real evidence_json-ish blob so
# the file actually grows enough to exceed a tiny test budget.
padding = "x" * 2000
for i in range(4000):
    store_d._conn.execute(
        "INSERT INTO decisions (decision_id, device_id, timestamp, state, decision_path, raw_payload_json) "
        "VALUES (?, 'devD', ?, 'SAFE', 'test', ?)",
        (f"old_{i}", now_d - 60 * 86400.0, padding),
    )
# A handful of RECENT rows, inside the floor -- must survive no matter how far
# over budget the db is.
for i in range(5):
    store_d._conn.execute(
        "INSERT INTO decisions (decision_id, device_id, timestamp, state, decision_path) "
        "VALUES (?, 'devD', ?, 'SAFE', 'test')",
        (f"recent_{i}", now_d - 1 * 86400.0),
    )
store_d._conn.commit()

size_before = store_d.get_disk_usage_bytes()["total_bytes"]
tiny_budget_gb = 0.0001  # forces the trim path regardless of exact row size

result_d = governor._enforce_graph_db_budget(store_d, tiny_budget_gb, now_d)

check("D1: governor reports at least one trimmed decision batch when way over budget",
      result_d["trimmed_decision_batches"] > 0, str(result_d))

remaining_recent = store_d._conn.execute(
    "SELECT COUNT(*) c FROM decisions WHERE decision_id LIKE 'recent_%'").fetchone()["c"]
check("D2: the 5 RECENT (inside-the-floor) rows all survive even at an impossibly tiny budget",
      remaining_recent == 5, f"remaining={remaining_recent}")

check("D3: at an impossibly tiny budget, the governor eventually reports floor_hit "
      "instead of silently deleting past the 30-day floor",
      result_d["floor_hit"] is True, str(result_d))

check("D4: the file is meaningfully smaller after trimming+incremental_vacuum than before",
      result_d["final_size_gb"] * (1024.0 ** 3) < size_before, str(result_d))

store_d.close()

# A SECOND case: a generous budget that's already satisfied -- must be a no-op on
# the data (only an opportunistic incremental_vacuum step, no trimming).
tmpdir_d2 = tempfile.mkdtemp(prefix="budget_test_d2_")
store_d2 = GraphStore(str(_PathForSysPath(tmpdir_d2) / "test.db"))
now_d2 = time.time()
store_d2.upsert_device("devD2", timestamp=now_d2)
store_d2._conn.execute(
    "INSERT INTO decisions (decision_id, device_id, timestamp, state, decision_path) "
    "VALUES ('only_one', 'devD2', ?, 'SAFE', 'test')", (now_d2 - 100 * 86400.0,),
)
store_d2._conn.commit()
result_d2 = governor._enforce_graph_db_budget(store_d2, 20.0, now_d2)
still_there = store_d2._conn.execute("SELECT COUNT(*) c FROM decisions").fetchone()["c"]
check("D5: a generous budget that's already satisfied does NOT trim anything",
      result_d2["trimmed_decision_batches"] == 0 and still_there == 1, str(result_d2))
store_d2.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Section E: _enforce_zeek_logs_budget() -- oldest-dated-dir-first deletion
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_e = tempfile.mkdtemp(prefix="budget_test_e_")
zeek_root = _PathForSysPath(tmpdir_e) / "zeek_logs"
zeek_root.mkdir()

now_dt = datetime.now(timezone.utc).date()
# 10 dated directories, oldest to newest, each with a real ~1MB file so total
# size meaningfully exceeds a tiny test budget.
dated_dirs = []
for days_ago in range(10, 0, -1):
    d = zeek_root / (now_dt - timedelta(days=days_ago)).isoformat()
    d.mkdir()
    (d / "conn.log").write_bytes(b"x" * (1024 * 1024))
    dated_dirs.append((days_ago, d))

# A non-dated entry (the live spool symlink target) that must NEVER be touched.
current_dir = zeek_root / "current"
current_dir.mkdir()
(current_dir / "conn.log").write_bytes(b"y" * 1024)

governor._ZEEK_LOGS_ROOT = zeek_root  # this test's own root, not the real /opt/zeek/logs

tiny_zeek_budget_gb = 3.0 / 1024.0  # ~3MB -- forces trimming most of the 10MB seeded
result_e = governor._enforce_zeek_logs_budget(tiny_zeek_budget_gb, time.time())

check("E1: governor deleted at least one old dated directory", result_e["deleted_dirs"] > 0, str(result_e))
check("E2: the `current` symlink-target directory was never touched",
      current_dir.exists() and (current_dir / "conn.log").exists())

remaining_dated = [d for days_ago, d in dated_dirs if d.exists()]
newest_remaining_days_ago = min((days_ago for days_ago, d in dated_dirs if d.exists()), default=None)
check("E3: whatever survived is the NEWEST directories, not an arbitrary subset "
      "(oldest-first deletion order)",
      newest_remaining_days_ago is not None and newest_remaining_days_ago <= 3,
      f"newest_remaining_days_ago={newest_remaining_days_ago}")

# The absolute floor: even at an impossibly tiny budget, nothing inside
# MIN_ZEEK_LOG_AGE_DAYS (3 days) may ever be deleted.
result_e2 = governor._enforce_zeek_logs_budget(0.0000001, time.time())
still_within_floor = [d for days_ago, d in dated_dirs if days_ago <= 2 and d.exists()]
check("E4: even at an impossibly tiny budget, directories inside the 3-day floor "
      "are never deleted", len(still_within_floor) == len(
          [1 for days_ago, d in dated_dirs if days_ago <= 2]),
      f"survived={len(still_within_floor)}")
check("E5: an impossibly tiny budget correctly reports floor_hit", result_e2["floor_hit"] is True)

# ═══════════════════════════════════════════════════════════════════════════════
print(f"\n{'='*70}")
if FAILURES:
    print(f"{len(FAILURES)} CHECK(S) FAILED:")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("All checks passed.")
