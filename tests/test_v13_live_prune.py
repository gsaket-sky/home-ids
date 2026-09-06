"""
Standalone runtime test for src/v13/ops/live_prune.py -- the scheduled job that
enforces GraphStore's retention policy on .94's own live graph (v13 full-architecture
plan, Phase 1 follow-up -- the real duplication bug this session found and fixed
showed nothing was enforcing retention on .94 at all until this existed).

Not part of the pytest suite -- run directly: `python3 tests/test_v13_live_prune.py`.
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


import v13.ops.live_prune as live_prune  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402
from v13.evidence.model import Evidence, NO_DESTINATION  # noqa: E402

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="live_prune_test_"))


# --- no db yet: a clean no-op, not an error ---
_no_db_dir = TMPDIR / "no_db"
_no_db_dir.mkdir()
live_prune.CONFIG = {"state_path": str(_no_db_dir / "ids_state.json")}
live_prune.main()
check("main() is a clean no-op when the graph db doesn't exist yet (engine=v_current, "
      "or live_engine.py has never run with a device_id)",
      not (_no_db_dir / "v13_graph.db").exists())
check("main() still writes job_health.json even on the no-op path",
      json.loads((_no_db_dir / "job_health.json").read_text())["live_prune"]["skipped"] == "no_db_yet")


# --- real pruning against a real graph with old + recent evidence ---
_real_dir = TMPDIR / "real"
_real_dir.mkdir()
db_path = _real_dir / "v13_graph.db"
store = GraphStore(str(db_path))
now = time.time()
old_ev = Evidence(device_id="dev1", destination_id=NO_DESTINATION, evidence_type="x",
                    independence_family="f", timestamp=now - 200 * 86400, source="s")
recent_ev = Evidence(device_id="dev1", destination_id=NO_DESTINATION, evidence_type="x",
                       independence_family="f", timestamp=now - 1 * 86400, source="s")
store.insert_evidence(old_ev)
store.insert_evidence(recent_ev)
store.close()

live_prune.CONFIG = {"state_path": str(_real_dir / "ids_state.json")}
live_prune.main()

verify_store = GraphStore(str(db_path))
check("main() actually pruned the old (>90 day) evidence row",
      verify_store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?", (old_ev.evidence_id,)).fetchone() is None)
check("main() kept the recent evidence row",
      verify_store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?", (recent_ev.evidence_id,)).fetchone() is not None)

health = json.loads((_real_dir / "job_health.json").read_text())
check("job_health.json records a real deleted count (>=1)",
      health["live_prune"]["deleted"] >= 1)
check("job_health.json has no 'error' key on a successful run",
      "error" not in health["live_prune"])


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All live_prune.py checks PASSED.")
