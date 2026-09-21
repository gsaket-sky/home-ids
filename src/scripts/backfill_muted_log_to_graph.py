"""
backfill_muted_log_to_graph.py -- one-time migration of state/autonomous_muted.jsonl's
pre-existing history into the graph (2026-09-21, legacy/Sheet 03a autotune
reconciliation, Phase G3).

WHY THIS EXISTS: fp_engine.py's _write_muted_log() no longer appends to
state/autonomous_muted.jsonl -- every new suppression/correction is written as
decisions.raw_payload_json.fp_suppression_log instead (see that method's own
docstring). This script moves the file's EXISTING history over so nothing already
recorded is lost, as a one-time run, not a scheduled job.

For each line in the source file(s), this inserts a SYNTHETIC decisions row:
  - decision_id: deterministic (f"backfill:muted:{ts_unix}:{device_id}"), so
    re-running this script is idempotent -- a decision_id collision is silently
    skipped, never duplicated.
  - device_id: the entry's own device.id, re-resolved through
    GraphStore.resolve_canonical_device_id() so a device merged AFTER this entry
    was originally written lands under its CURRENT canonical id, not a stale
    snapshot -- correctly reusing today's identity mapping rather than trusting
    the entry's own recorded id at face value.
  - state: "BENIGN" (closest existing decisions.state convention for a confirmed
    non-threat; that column has no CHECK constraint, just a documented
    convention -- see schema.sql). The real classification/reasons stay inside
    raw_payload_json, not this column.
  - raw_payload_json: {"fp_suppression_log": <the original entry, unchanged>,
    "backfilled": true} -- readers that already understand fp_suppression_log
    (see train_fp_classifier.py's calibration functions, retro_hunter.py,
    shadow_backtest.py, identify_corrupted_training_rows.py, cl_afpe/engine.py)
    pick this up with no special-casing; the "backfilled" flag lets anyone who
    cares distinguish historical migrated rows from real live ones.

USAGE (per the plan's own explicit instruction -- run against a COPY first):
    python src/scripts/backfill_muted_log_to_graph.py --db /path/to/a/copy/v13_graph.db \
        --muted-log /path/to/a/copy/autonomous_muted.jsonl
    # inspect the result, spot-check a few rows, compare row count to `wc -l` on the
    # source file, THEN and only then run against the real files:
    python src/scripts/backfill_muted_log_to_graph.py --db state/v13_graph.db

Does NOT delete the source file(s) -- that is a deliberate manual follow-up step
once the backfill is verified, not something this script does automatically.
"""
import argparse
import json
import logging
import sys
import time
import uuid
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from argus.graph.store import GraphStore  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
LOGGER = logging.getLogger("home_ids.backfill_muted_log")


def _read_muted_log_lines(path: Path) -> list:
    if not path.exists():
        return []
    entries = []
    for line_num, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError as exc:
            LOGGER.warning("Skipping malformed line %d in %s: %s", line_num, path, exc)
            continue
        if isinstance(doc, dict):
            entries.append(doc)
    return entries


def backfill(store: GraphStore, entries: list) -> dict:
    """Inserts one synthetic decisions row per entry. Returns a summary dict:
    {"inserted": N, "skipped_no_device_id": N, "skipped_no_timestamp": N,
    "skipped_already_present": N, "failed": N}."""
    summary = {
        "inserted": 0, "skipped_no_device_id": 0, "skipped_no_timestamp": 0,
        "skipped_already_present": 0, "failed": 0,
    }
    for entry in entries:
        raw_device_id = (entry.get("device") or {}).get("id")
        ts_unix = entry.get("ts_unix")
        if not raw_device_id or raw_device_id == "unknown":
            summary["skipped_no_device_id"] += 1
            continue
        if ts_unix is None:
            summary["skipped_no_timestamp"] += 1
            continue
        try:
            device_id = store.resolve_canonical_device_id(raw_device_id)
            store.upsert_device(device_id, timestamp=float(ts_unix))
            decision_id = f"backfill:muted:{ts_unix}:{device_id}"
            existing = store._conn.execute(
                "SELECT 1 FROM decisions WHERE decision_id=?", (decision_id,)
            ).fetchone()
            if existing is not None:
                summary["skipped_already_present"] += 1
                continue
            confidence = entry.get("confidence")
            store._conn.execute(
                "INSERT INTO decisions (decision_id, device_id, timestamp, state, decision_path, "
                "confidence, risk_score, mechanism_flags_json, raw_payload_json) "
                "VALUES (?, ?, ?, 'BENIGN', 'backfill_muted_log', ?, ?, '{}', ?)",
                (
                    decision_id, device_id, float(ts_unix),
                    float(confidence) if confidence is not None else None,
                    float(entry.get("risk_score") or 0.0),
                    json.dumps({"fp_suppression_log": entry, "backfilled": True}),
                ),
            )
            summary["inserted"] += 1
        except Exception as exc:
            LOGGER.error("Failed to backfill entry (device=%r, ts_unix=%r): %s", raw_device_id, ts_unix, exc)
            summary["failed"] += 1
    store._maybe_commit()
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default="state/v13_graph.db",
                         help="Graph db to write into. Point this at a COPY first -- see this "
                              "script's own module docstring.")
    parser.add_argument("--muted-log", default="state/autonomous_muted.jsonl",
                         help="Source JSONL file. Its optional .bak sibling (from any prior ad "
                              "hoc rotation) is also read automatically if present.")
    args = parser.parse_args()

    muted_path = Path(args.muted_log)
    bak_path = muted_path.with_suffix(".bak")
    entries = _read_muted_log_lines(muted_path) + _read_muted_log_lines(bak_path)
    LOGGER.info("Read %d entries from %s%s", len(entries), muted_path,
                f" + {bak_path}" if bak_path.exists() else "")
    if not entries:
        LOGGER.info("Nothing to backfill.")
        return

    store = GraphStore(args.db)
    try:
        summary = backfill(store, entries)
    finally:
        store.close()

    LOGGER.info("Backfill summary: %s", summary)
    LOGGER.info(
        "Spot-check before deleting the source file(s): compare 'inserted' + "
        "'skipped_already_present' above against `wc -l %s`, and diff a few individual "
        "rows by hand.", muted_path,
    )


if __name__ == "__main__":
    main()
