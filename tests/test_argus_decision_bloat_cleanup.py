"""
Standalone runtime test for src/argus/ops/decision_bloat_cleanup.py -- the
ONE-TIME retroactive migration for decisions written before the write-path fix
(GraphStore.insert_decision(), 2026-09-20) existed. Builds a synthetic db with
the exact pathological shape found live on .94 (a decision with far more
'supports' edges than its hardware profile's cap, and a stored payload still
carrying attack_evidence/winning_evidence) and confirms dry-run changes
nothing, --apply fixes it correctly and idempotently, and a backup is made.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_decision_bloat_cleanup.py`
"""
import json
import subprocess
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

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="decision_bloat_cleanup_test_"))
STATE_DIR = TMPDIR / "state"
STATE_DIR.mkdir()
db_path = STATE_DIR / "v13_graph.db"

# Build the pathological shape directly (bypassing today's already-fixed
# insert_decision()) -- exactly what a decision written by the OLD, pre-fix
# code would look like: 150 supports edges (x86_16gb's cap is 50) and a stored
# payload still carrying attack_evidence/winning_evidence.
store = GraphStore(str(db_path), hardware_profile="x86_16gb")
dev = "dev_legacy_bloat"
store.upsert_device(dev)
evidence_ids = []
now = time.time()
for i in range(150):
    ev = Evidence(device_id=dev, destination_id=NO_DESTINATION, evidence_type="x",
                   independence_family="f", timestamp=now + i, source="s")
    store.insert_evidence(ev)
    evidence_ids.append(ev.evidence_id)

legacy_decision_id = "legacy_bloat_decision"
bloated_payload = {
    "state": "BENIGN", "decision_path": "test",
    "attack_evidence": [{"evidence_id": e, "junk": "x" * 500} for e in evidence_ids],
    "winning_evidence": [{"evidence_id": e} for e in evidence_ids[:20]],
    "_all_evidence_ids": evidence_ids,
}
store._conn.execute(
    "INSERT INTO decisions (decision_id, device_id, timestamp, state, decision_path, "
    "confidence, risk_score, mechanism_flags_json, raw_payload_json) "
    "VALUES (?, ?, ?, 'BENIGN', 'test', 0.0, 0.0, '{}', ?)",
    (legacy_decision_id, dev, now, json.dumps(bloated_payload)),
)
for eid in evidence_ids:  # all 150, unbounded -- the pre-fix shape
    store.add_edge("evidence", eid, "decision", legacy_decision_id, "supports", now)

# A second, already-healthy decision (within cap, no bloated keys) that must
# survive completely untouched -- the migration must be surgical, not a
# blanket rewrite of every row.
healthy_decision_id = store.insert_decision(
    device_id=dev, timestamp=now + 1000, state="ANOMALOUS", decision_path="test2",
    confidence=0.5, risk_score=0.5, raw_payload={"state": "ANOMALOUS"},
    evidence_ids=evidence_ids[:5],
)
store._conn.commit()
store.close()

before_edge_count = 150
py = sys.executable


def run(args):
    return subprocess.run(
        [py, "src/argus/ops/decision_bloat_cleanup.py", "--db-path", str(db_path),
         "--hardware-profile", "x86_16gb"] + args,
        cwd=str(_PathForSysPath(__file__).resolve().parent.parent),
        capture_output=True, text=True,
    )


# --- dry run changes nothing ---
dry_result = run([])
check("dry run exits cleanly", dry_result.returncode == 0, dry_result.stderr[-500:])
check("dry run reports the one over-cap decision", "1" in dry_result.stdout.split("edge cap:")[0][-5:] or "Decisions exceeding the edge cap: 1" in dry_result.stdout)

verify1 = GraphStore(str(db_path))
edge_count_after_dry = verify1._conn.execute(
    "SELECT COUNT(*) c FROM edges WHERE dst_id=? AND relation='supports'", (legacy_decision_id,)
).fetchone()["c"]
check("dry run did NOT modify the edge count", edge_count_after_dry == before_edge_count,
      f"got {edge_count_after_dry}")
payload_after_dry = json.loads(verify1._conn.execute(
    "SELECT raw_payload_json FROM decisions WHERE decision_id=?", (legacy_decision_id,)
).fetchone()["raw_payload_json"])
check("dry run did NOT strip attack_evidence", "attack_evidence" in payload_after_dry)
verify1.close()


# --- real apply, with backup ---
apply_result = run(["--apply"])
check("--apply exits cleanly", apply_result.returncode == 0, apply_result.stderr[-1000:])

backups = list(STATE_DIR.glob("v13_graph.db.pre-bloat-cleanup-backup-*"))
check("a backup file was created before applying changes", len(backups) == 1, f"found {len(backups)}")
if backups:
    check("the backup is a real, non-empty copy", backups[0].stat().st_size > 0)

verify2 = GraphStore(str(db_path))
edge_count_after_apply = verify2._conn.execute(
    "SELECT COUNT(*) c FROM edges WHERE dst_id=? AND relation='supports'", (legacy_decision_id,)
).fetchone()["c"]
check("--apply trimmed the legacy decision's edges down to the hardware profile's cap (50)",
      edge_count_after_apply == 50, f"got {edge_count_after_apply}")

kept_ids = {r["src_id"] for r in verify2._conn.execute(
    "SELECT src_id FROM edges WHERE dst_id=? AND relation='supports'", (legacy_decision_id,)).fetchall()}
most_recent_50 = set(evidence_ids[-50:])
check("the edges KEPT are the most-recent 50 by evidence timestamp, matching insert_decision()'s own ordering",
      kept_ids == most_recent_50)

payload_after_apply = json.loads(verify2._conn.execute(
    "SELECT raw_payload_json FROM decisions WHERE decision_id=?", (legacy_decision_id,)
).fetchone()["raw_payload_json"])
check("--apply stripped attack_evidence from the stored payload",
      "attack_evidence" not in payload_after_apply)
check("--apply stripped winning_evidence from the stored payload",
      "winning_evidence" not in payload_after_apply)
check("--apply left the rest of the payload (state/decision_path) intact",
      payload_after_apply.get("state") == "BENIGN" and payload_after_apply.get("decision_path") == "test")

healthy_row = verify2._conn.execute(
    "SELECT raw_payload_json FROM decisions WHERE decision_id=?", (healthy_decision_id,)).fetchone()
healthy_edge_count = verify2._conn.execute(
    "SELECT COUNT(*) c FROM edges WHERE dst_id=? AND relation='supports'", (healthy_decision_id,)
).fetchone()["c"]
check("the already-healthy decision's edges are untouched (5, never exceeded any cap)",
      healthy_edge_count == 5, f"got {healthy_edge_count}")
check("the already-healthy decision's payload is untouched",
      json.loads(healthy_row["raw_payload_json"]) == {"state": "ANOMALOUS"})
verify2.close()


# --- idempotency: a second --apply on an already-clean db does nothing further ---
second_apply = run(["--apply", "--no-backup"])
check("a second --apply exits cleanly (idempotent, nothing left to do)",
      second_apply.returncode == 0, second_apply.stderr[-500:])
check("a second --apply reports zero remaining over-cap decisions",
      "Decisions exceeding the edge cap: 0" in second_apply.stdout)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All decision_bloat_cleanup.py checks PASSED.")
