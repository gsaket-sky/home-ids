"""
Standalone runtime test for scripts/backfill_muted_log_to_graph.py (2026-09-21,
legacy/Sheet 03a autotune reconciliation, Phase G3 -- the one-time migration of
state/autonomous_muted.jsonl's pre-existing history into the graph). Not part of
the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_backfill_muted_log_to_graph.py`

Covers: reading a fixture JSONL file, inserting the expected decisions rows
(correctly skipping entries with no usable device_id), tagging each row
"backfilled": true, preserving the original fp_suppression_log entry verbatim,
and idempotency (re-running must never duplicate rows).
"""
import sys
import json
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
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "backfill_muted_log_to_graph",
    str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "backfill_muted_log_to_graph.py"),
)
backfill_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(backfill_mod)

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    tmpdir = _PathForSysPath(tmpdir)
    muted_path = tmpdir / "autonomous_muted.jsonl"
    now = time.time()
    entries = [
        {"ts_unix": now - 100, "type": "OPERATOR_MARKED_FALSE_POSITIVE", "confidence": 1.0,
         "reasons": [], "device": {"id": "dev_backfill_a"}, "domain": "example.com",
         "original_alert": {"device": {"id": "dev_backfill_a"}}},
        {"ts_unix": now - 50, "type": "AUTONOMOUS_FP_SUPPRESSED", "confidence": 0.9,
         "reasons": [], "device": {"id": "dev_backfill_b"}, "domain": "example2.com",
         "original_alert": {"device": {"id": "dev_backfill_b"}}},
        {"type": "MALFORMED_NO_DEVICE", "confidence": 0.5},  # no device.id -- must be skipped
        {"ts_unix": now - 30, "type": "OPERATOR_MARKED_FALSE_POSITIVE", "confidence": 1.0,
         "device": {"id": "unknown"}, "original_alert": {}},  # sentinel id -- must be skipped
    ]
    muted_path.write_text("\n".join(json.dumps(e) for e in entries) + "\nnot valid json\n", encoding="utf-8")

    store = GraphStore(str(tmpdir / "v13_graph.db"))
    read_entries = backfill_mod._read_muted_log_lines(muted_path)
    check("reads every valid line from the fixture file, skipping the malformed one",
          len(read_entries) == 4, f"got {len(read_entries)}")

    summary = backfill_mod.backfill(store, read_entries)
    check("inserts exactly 2 rows -- skips the no-device-id and 'unknown'-device entries",
          summary["inserted"] == 2 and summary["skipped_no_device_id"] == 2, f"summary={summary}")

    rows = store._conn.execute("SELECT decision_id, device_id, raw_payload_json FROM decisions").fetchall()
    check("exactly 2 decisions rows exist in the graph", len(rows) == 2, f"got {len(rows)}")
    for row in rows:
        payload = json.loads(row["raw_payload_json"])
        check(f"row for {row['device_id']} is tagged backfilled=True",
              payload.get("backfilled") is True, f"payload={payload}")
        check(f"row for {row['device_id']} carries the original fp_suppression_log entry verbatim",
              payload.get("fp_suppression_log", {}).get("device", {}).get("id") == row["device_id"])
        check(f"row for {row['device_id']} was auto-upserted into devices (FK satisfied)",
              store._conn.execute("SELECT 1 FROM devices WHERE device_id=?", (row["device_id"],)).fetchone()
              is not None)

    # Idempotency: re-running against the SAME entries must never duplicate rows.
    summary2 = backfill_mod.backfill(store, read_entries)
    check("re-running the backfill is idempotent -- both real entries already present, zero new inserts",
          summary2["inserted"] == 0 and summary2["skipped_already_present"] == 2, f"summary2={summary2}")
    row_count_after = store._conn.execute("SELECT COUNT(*) AS c FROM decisions").fetchone()["c"]
    check("row count unchanged after re-running", row_count_after == 2, f"got {row_count_after}")
    store.close()


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All backfill_muted_log_to_graph.py checks PASSED.")
