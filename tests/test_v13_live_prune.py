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


# --- Phase 10b: hardware_profile-driven retention aggressiveness ---
_hw_dir = TMPDIR / "hw_profile"
_hw_dir.mkdir()
hw_db_path = _hw_dir / "v13_graph.db"
hw_store = GraphStore(str(hw_db_path))
now2 = time.time()
# 45 days old: outside pi_8gb's 30-day retention, but still within the 90-day default.
mid_age_ev = Evidence(device_id="dev_hw", destination_id=NO_DESTINATION, evidence_type="x",
                        independence_family="f", timestamp=now2 - 45 * 86400, source="s")
hw_store.insert_evidence(mid_age_ev)
hw_store.close()

live_prune.CONFIG = {"state_path": str(_hw_dir / "ids_state.json"), "hardware_profile": "pi_8gb"}
live_prune.main()
hw_verify_store = GraphStore(str(hw_db_path))
check("Phase 10b: a pi_8gb deployment prunes a 45-day-old row that the 90-day "
      "default would have kept -- retention is genuinely shorter, not just "
      "logged as if it were",
      hw_verify_store._conn.execute(
          "SELECT 1 FROM evidence WHERE evidence_id=?", (mid_age_ev.evidence_id,)).fetchone() is None)
hw_verify_store.close()
hw_health = json.loads((_hw_dir / "job_health.json").read_text())
check("job_health.json records the actual retention_days used (30 for pi_8gb)",
      hw_health["live_prune"]["retention_days"] == 30.0)

# --- x86_16gb (and the unconfigured default) keep the original 90-day window ---
_hw_dir2 = TMPDIR / "hw_profile_x86"
_hw_dir2.mkdir()
hw_db_path2 = _hw_dir2 / "v13_graph.db"
hw_store2 = GraphStore(str(hw_db_path2))
mid_age_ev2 = Evidence(device_id="dev_hw2", destination_id=NO_DESTINATION, evidence_type="x",
                         independence_family="f", timestamp=now2 - 45 * 86400, source="s")
hw_store2.insert_evidence(mid_age_ev2)
hw_store2.close()

live_prune.CONFIG = {"state_path": str(_hw_dir2 / "ids_state.json"), "hardware_profile": "x86_16gb"}
live_prune.main()
hw_verify_store2 = GraphStore(str(hw_db_path2))
check("x86_16gb keeps the same 45-day-old row the original 90-day default would "
      "have kept -- retention is unchanged for this profile",
      hw_verify_store2._conn.execute(
          "SELECT 1 FROM evidence WHERE evidence_id=?", (mid_age_ev2.evidence_id,)).fetchone() is not None)
hw_verify_store2.close()

# --- no hardware_profile configured at all: falls back to the original default ---
live_prune.CONFIG = {"state_path": str(_real_dir / "ids_state.json")}
default_health = json.loads((_real_dir / "job_health.json").read_text())
check("with no hardware_profile configured at all, retention_days falls back to "
      "the original 90-day default (already exercised by the 'real pruning' "
      "section above -- this just confirms the value logged there)",
      default_health["live_prune"]["retention_days"] == 90)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All live_prune.py checks PASSED.")
