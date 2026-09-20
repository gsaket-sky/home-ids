"""
Standalone runtime test for src/argus/ops/live_prune_weak_notices.py -- split
out of live_prune.py onto its own tight cadence (data-lifecycle retuning,
2026-09-20) so zeek_notice_weak's documented 12h retention is actually enforced
close to 12h, not the ~23-24h a once-daily sweep left in practice.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_live_prune_weak_notices.py`
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


import argus.ops.live_prune_weak_notices as live_prune_weak_notices  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="live_prune_weak_notices_test_"))

# --- no db yet: a clean no-op, not an error ---
_no_db_dir = TMPDIR / "no_db"
_no_db_dir.mkdir()
live_prune_weak_notices.CONFIG = {"state_path": str(_no_db_dir / "ids_state.json")}
live_prune_weak_notices.main()
check("main() is a clean no-op when the graph db doesn't exist yet",
      json.loads((_no_db_dir / "job_health.json").read_text())["live_prune_weak_notices"]["skipped"] == "no_db_yet")


# --- real pruning: old weak-tier row goes, recent + non-weak rows stay ---
_real_dir = TMPDIR / "real"
_real_dir.mkdir()
db_path = _real_dir / "v13_graph.db"
store = GraphStore(str(db_path))
now = time.time()
old_weak = Evidence(device_id="dev1", destination_id=NO_DESTINATION, evidence_type="zeek_notice_weak",
                      independence_family="f", timestamp=now - 13 * 3600, source="s")
recent_weak = Evidence(device_id="dev1", destination_id=NO_DESTINATION, evidence_type="zeek_notice_weak",
                         independence_family="f", timestamp=now - 1 * 3600, source="s")
old_medium = Evidence(device_id="dev1", destination_id=NO_DESTINATION, evidence_type="zeek_notice_medium",
                        independence_family="f", timestamp=now - 13 * 3600, source="s")
store.insert_evidence(old_weak)
store.insert_evidence(recent_weak)
store.insert_evidence(old_medium)
store.close()

live_prune_weak_notices.CONFIG = {"state_path": str(_real_dir / "ids_state.json")}
live_prune_weak_notices.main()

verify_store = GraphStore(str(db_path))
check("main() pruned the old (>12h) weak-tier row",
      verify_store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?", (old_weak.evidence_id,)).fetchone() is None)
check("main() kept the recent weak-tier row",
      verify_store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?", (recent_weak.evidence_id,)).fetchone() is not None)
check("main() left a same-age NON-weak row untouched -- scoped to weak tier only, not a blanket age sweep",
      verify_store._conn.execute("SELECT 1 FROM evidence WHERE evidence_id=?", (old_medium.evidence_id,)).fetchone() is not None)
verify_store.close()

health = json.loads((_real_dir / "job_health.json").read_text())
check("job_health.json records exactly 1 deleted row",
      health["live_prune_weak_notices"]["deleted"] == 1, f"got {health['live_prune_weak_notices'].get('deleted')}")
check("job_health.json has no 'error' key on a successful run",
      "error" not in health["live_prune_weak_notices"])


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All live_prune_weak_notices.py checks PASSED.")
