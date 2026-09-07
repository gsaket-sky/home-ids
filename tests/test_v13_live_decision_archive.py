"""
Standalone runtime test for src/v13/ops/live_decision_archive.py -- the scheduled job
that enforces schema.sql's own documented decision-retention policy ("decisions: kept
1 year, then archived (exported, not deleted)") on .94's own live graph (v13
full-architecture plan, Phase 10a).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_live_decision_archive.py`
"""
import json
import sys
import tempfile
import time
from unittest.mock import patch
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import v13.ops.live_decision_archive as live_decision_archive  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="live_decision_archive_test_"))


# --- no db yet: a clean no-op, not an error ---
_no_db_dir = TMPDIR / "no_db"
_no_db_dir.mkdir()
live_decision_archive.CONFIG = {"state_path": str(_no_db_dir / "ids_state.json")}
live_decision_archive.main()
check("main() is a clean no-op when the graph db doesn't exist yet",
      not (_no_db_dir / "v13_graph.db").exists())
check("main() still writes job_health.json even on the no-op path",
      json.loads((_no_db_dir / "job_health.json").read_text())["live_decision_archive"]["skipped"] == "no_db_yet")


# --- real archival: one old (>1yr) decision, one recent one ---
_real_dir = TMPDIR / "real"
_real_dir.mkdir()
db_path = _real_dir / "v13_graph.db"
store = GraphStore(str(db_path))
now = time.time()
store.upsert_device("dev1", timestamp=now)
old_id = store.insert_decision(
    device_id="dev1", timestamp=now - 400 * 86400, state="HIGH", decision_path="hypothesis_high",
    confidence=0.8, risk_score=8.0, raw_payload={"hypotheses": {"attack": {"name": "NETWORK_INTRUSION"}}},
)
recent_id = store.insert_decision(
    device_id="dev1", timestamp=now - 1 * 86400, state="BENIGN", decision_path="benign",
    confidence=0.0, risk_score=0.0, raw_payload={},
)
store.close()

live_decision_archive.CONFIG = {"state_path": str(_real_dir / "ids_state.json")}
live_decision_archive.main()

verify_store = GraphStore(str(db_path))
check("main() removed the old (>1yr) decision from the live graph",
      verify_store._conn.execute("SELECT 1 FROM decisions WHERE decision_id=?", (old_id,)).fetchone() is None)
check("main() kept the recent decision in the live graph",
      verify_store._conn.execute("SELECT 1 FROM decisions WHERE decision_id=?", (recent_id,)).fetchone() is not None)
verify_store.close()

archive_files = list((_real_dir / "decision_archive").glob("*.jsonl"))
check("main() wrote exactly one export file under state/decision_archive/", len(archive_files) == 1)
exported = [json.loads(l) for l in archive_files[0].read_text().splitlines() if l.strip()] if archive_files else []
check("the exported file contains exactly the OLD decision, not the recent one",
      len(exported) == 1 and exported[0]["decision_id"] == old_id)
check("the exported row carries the real raw_payload, not a stub",
      exported and exported[0]["raw_payload"]["hypotheses"]["attack"]["name"] == "NETWORK_INTRUSION")

health = json.loads((_real_dir / "job_health.json").read_text())
check("job_health.json records archived=1", health["live_decision_archive"]["archived"] == 1)
check("job_health.json has no 'error' key on a successful run",
      "error" not in health["live_decision_archive"])


# --- nothing old enough: a clean, correct no-op (not an error, no export file) ---
_quiet_dir = TMPDIR / "quiet"
_quiet_dir.mkdir()
quiet_db_path = _quiet_dir / "v13_graph.db"
quiet_store = GraphStore(str(quiet_db_path))
quiet_store.upsert_device("dev2", timestamp=now)
quiet_store.insert_decision(
    device_id="dev2", timestamp=now - 1 * 86400, state="BENIGN", decision_path="benign",
    confidence=0.0, risk_score=0.0, raw_payload={},
)
quiet_store.close()

live_decision_archive.CONFIG = {"state_path": str(_quiet_dir / "ids_state.json")}
live_decision_archive.main()
check("no export directory is created when nothing is old enough to archive",
      not (_quiet_dir / "decision_archive").exists())
quiet_health = json.loads((_quiet_dir / "job_health.json").read_text())
check("job_health.json correctly records archived=0 on a quiet run",
      quiet_health["live_decision_archive"]["archived"] == 0)


# --- export-then-delete ordering: a failed export must NEVER lose the decision ---
_fail_dir = TMPDIR / "export_fails"
_fail_dir.mkdir()
fail_db_path = _fail_dir / "v13_graph.db"
fail_store = GraphStore(str(fail_db_path))
fail_store.upsert_device("dev3", timestamp=now)
fail_old_id = fail_store.insert_decision(
    device_id="dev3", timestamp=now - 400 * 86400, state="HIGH", decision_path="hypothesis_high",
    confidence=0.8, risk_score=8.0, raw_payload={},
)
fail_store.close()

live_decision_archive.CONFIG = {"state_path": str(_fail_dir / "ids_state.json")}
_real_open = open


def _open_that_fails_only_for_the_export_file(path, *args, **kwargs):
    # Only the export write fails -- job_health.json's own (different-path)
    # write must still succeed, so the failure is actually OBSERVABLE via
    # job_health.json below, not masked by a second, unrelated write failure.
    if "decision_archive" in str(path):
        raise OSError("simulated disk full")
    return _real_open(path, *args, **kwargs)


with patch("builtins.open", side_effect=_open_that_fails_only_for_the_export_file):
    live_decision_archive.main()

fail_verify_store = GraphStore(str(fail_db_path))
check("EXPORT-THEN-DELETE ORDERING: when the export write itself fails, the decision "
      "is NEVER deleted from the live graph -- 'archived, not deleted' holds even "
      "under a failure, not just the happy path",
      fail_verify_store._conn.execute(
          "SELECT 1 FROM decisions WHERE decision_id=?", (fail_old_id,)).fetchone() is not None)
fail_verify_store.close()
fail_health = json.loads((_fail_dir / "job_health.json").read_text())
check("the export failure is recorded in job_health.json, not silently swallowed",
      "error" in fail_health["live_decision_archive"])


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All live_decision_archive.py checks PASSED.")
