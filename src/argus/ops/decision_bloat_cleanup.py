"""
decision_bloat_cleanup.py - ONE-TIME retroactive migration (memory-restart
root-cause investigation, 2026-09-20), NOT a scheduled job.

GraphStore.insert_decision() previously persisted attack_evidence/
winning_evidence (full serialized Evidence objects, meant only for pipeline.py's
same-cycle Telegram WHY-block) wholesale into raw_payload_json forever, and
stashed _all_evidence_ids fully uncapped whenever the supporting-evidence-edge
cap was exceeded. Both are now fixed at the write path (GraphStore.
insert_decision(), 2026-09-20) -- but that fix only stops NEW bloat. Found live
on .94: 2,779 decisions written before either fix existed still carry their
original uncapped shape (up to 68,915 'supports' edges and 22MB raw_payload_json
rows), accounting for ~8.46GB of the graph db's 8.5GB total. This script is the
one-time cleanup for THAT already-written backlog.

Safety, given this runs against a real production database:
  - Defaults to --dry-run: reports exactly what WOULD change (row counts, edge
    counts, byte estimates) without writing anything.
  - A real run (--apply) ALWAYS copies the db file to a timestamped backup
    first (skippable only with --no-backup, for re-running after a already-
    verified-good first pass) -- this is a bulk UPDATE/DELETE + VACUUM against
    the live file; a mid-run interruption should never mean unrecoverable data.
  - Idempotent: a decision already within cap and without the stripped keys is
    left untouched, so re-running after an interruption (or just to confirm
    "nothing left to do") is always safe.
  - Never touches evidence/edges belonging to a decision that's still WITHIN
    its cap -- only decisions actually exceeding it are modified.

Usage: python3 src/argus/ops/decision_bloat_cleanup.py [--apply] [--no-backup]
       [--db-path PATH] [--hardware-profile pi_8gb|x86_16gb|custom]
"""
import argparse
import gzip
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from argus.config.trust_anchors import load_hardware_profile  # noqa: E402
from argus.graph.store import (  # noqa: E402
    _MAX_SUPPORTING_EVIDENCE_EDGES_BY_PROFILE, _MAX_ALL_EVIDENCE_IDS_STORED,
)

_BLOAT_KEYS = ("attack_evidence", "winning_evidence")


def _edge_cap_for(hardware_profile: str) -> int:
    return _MAX_SUPPORTING_EVIDENCE_EDGES_BY_PROFILE.get(
        hardware_profile or "", _MAX_SUPPORTING_EVIDENCE_EDGES_BY_PROFILE["x86_16gb"])


def find_bloated_decisions(conn: sqlite3.Connection, edge_cap: int):
    """Returns (decision_id, current_edge_count, payload_len) for every decision
    that either exceeds the edge cap or still has a stripped-at-write-time key
    lingering in its stored payload from before the write-path fix existed."""
    rows = conn.execute(
        "SELECT d.decision_id, "
        "  (SELECT COUNT(*) FROM edges e WHERE e.dst_id = d.decision_id AND e.relation = 'supports') AS edge_count, "
        "  LENGTH(d.raw_payload_json) AS payload_len "
        "FROM decisions d"
    ).fetchall()
    out = []
    for decision_id, edge_count, payload_len in rows:
        if edge_count > edge_cap:
            out.append((decision_id, edge_count, payload_len))
    return out


def find_stripped_key_decisions(conn: sqlite3.Connection):
    """Rows whose stored payload still has attack_evidence/winning_evidence --
    cheaper than parsing every row's JSON: a LIKE prefilter on the raw text
    first (both keys are always top-level, always quoted the same way), THEN
    a real json.loads() only on rows that plausibly match, to avoid a false
    positive against these substrings appearing inside some OTHER field's
    free-text value."""
    rows = conn.execute(
        "SELECT decision_id, raw_payload_json FROM decisions WHERE "
        "raw_payload_json LIKE '%\"attack_evidence\"%' OR raw_payload_json LIKE '%\"winning_evidence\"%'"
    ).fetchall()
    out = []
    for decision_id, raw in rows:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if any(k in payload for k in _BLOAT_KEYS):
            out.append(decision_id)
    return out


def apply_cleanup(conn: sqlite3.Connection, edge_cap: int, evidence_id_cap: int) -> dict:
    stats = {"decisions_trimmed_edges": 0, "edges_deleted": 0, "decisions_stripped_payload": 0,
              "bytes_reclaimed_estimate": 0}

    overcap = find_bloated_decisions(conn, edge_cap)
    for decision_id, edge_count, _ in overcap:
        # Keep the most-recent-by-evidence-timestamp `edge_cap` supports edges --
        # the SAME ordering insert_decision() uses for a fresh write, so a
        # retroactively-trimmed decision ends up in exactly the shape it would
        # have been written in if the cap had existed from day one.
        keep_ids = [r[0] for r in conn.execute(
            "SELECT e.src_id FROM edges e JOIN evidence ev ON ev.evidence_id = e.src_id "
            "WHERE e.dst_id = ? AND e.relation = 'supports' "
            "ORDER BY ev.timestamp DESC LIMIT ?",
            (decision_id, edge_cap),
        ).fetchall()]
        if not keep_ids:
            # Every referenced evidence row has already aged out (prune_evidence()
            # deletes the edge along with its evidence) -- nothing left to keep,
            # delete them all for this decision.
            cur = conn.execute(
                "DELETE FROM edges WHERE dst_id = ? AND relation = 'supports'", (decision_id,))
        else:
            placeholders = ",".join("?" * len(keep_ids))
            cur = conn.execute(
                f"DELETE FROM edges WHERE dst_id = ? AND relation = 'supports' "
                f"AND src_id NOT IN ({placeholders})",
                [decision_id] + keep_ids,
            )
        stats["decisions_trimmed_edges"] += 1
        stats["edges_deleted"] += cur.rowcount

    stripped_ids = find_stripped_key_decisions(conn)
    for decision_id in stripped_ids:
        row = conn.execute(
            "SELECT raw_payload_json FROM decisions WHERE decision_id = ?", (decision_id,)).fetchone()
        before_len = len(row[0])
        payload = json.loads(row[0])
        for k in _BLOAT_KEYS:
            payload.pop(k, None)
        all_ids = payload.get("_all_evidence_ids")
        if isinstance(all_ids, list) and len(all_ids) > evidence_id_cap:
            payload["_all_evidence_ids"] = all_ids[:evidence_id_cap]
        new_json = json.dumps(payload)
        conn.execute(
            "UPDATE decisions SET raw_payload_json = ? WHERE decision_id = ?", (new_json, decision_id))
        stats["decisions_stripped_payload"] += 1
        stats["bytes_reclaimed_estimate"] += max(0, before_len - len(new_json))

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                         help="Actually modify the database. Without this, only reports what would change.")
    parser.add_argument("--no-backup", action="store_true",
                         help="Skip the pre-apply backup copy (only for re-running after an already-verified pass).")
    parser.add_argument("--db-path", default=None, help="Override the db path (default: CONFIG's state_path).")
    parser.add_argument("--hardware-profile", default=None,
                         help="Override hardware_profile (default: CONFIG's own configured value).")
    args = parser.parse_args()

    db_path = Path(args.db_path) if args.db_path else Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "v13_graph.db"
    if not db_path.exists():
        print(f"No database at {db_path} -- nothing to do.")
        return

    hardware_profile = args.hardware_profile or load_hardware_profile(CONFIG)
    edge_cap = _edge_cap_for(hardware_profile)

    conn = sqlite3.connect(str(db_path))
    before_size = db_path.stat().st_size

    overcap = find_bloated_decisions(conn, edge_cap)
    stripped = find_stripped_key_decisions(conn)
    total_excess_edges = sum(max(0, ec - edge_cap) for _, ec, _ in overcap)
    total_bloated_bytes = sum(pl for _, _, pl in overcap)

    print(f"Database: {db_path} ({before_size / 1e9:.2f} GB)")
    print(f"Hardware profile: {hardware_profile} (edge cap: {edge_cap})")
    print(f"Decisions exceeding the edge cap: {len(overcap)} ({total_excess_edges} excess edges, "
          f"{total_bloated_bytes / 1e6:.1f} MB of raw_payload_json across them)")
    print(f"Decisions with a stripped-at-write-time key still stored: {len(stripped)}")

    if not args.apply:
        print("\nDRY RUN -- nothing was changed. Re-run with --apply to actually clean this up.")
        conn.close()
        return

    if not args.no_backup:
        backup_path = db_path.with_name(f"{db_path.name}.pre-bloat-cleanup-backup-{time.strftime('%Y%m%d_%H%M%S')}")
        print(f"Backing up {db_path} -> {backup_path} before making any changes...")
        conn.close()
        shutil.copy2(db_path, backup_path)
        conn = sqlite3.connect(str(db_path))

    print("Applying cleanup...")
    stats = apply_cleanup(conn, edge_cap, _MAX_ALL_EVIDENCE_IDS_STORED)
    conn.commit()
    print(f"  Trimmed excess 'supports' edges on {stats['decisions_trimmed_edges']} decision(s), "
          f"{stats['edges_deleted']} edge row(s) deleted.")
    print(f"  Stripped bloated payload keys on {stats['decisions_stripped_payload']} decision(s), "
          f"~{stats['bytes_reclaimed_estimate'] / 1e6:.1f} MB of JSON text reclaimed.")

    print("Checkpointing WAL and running VACUUM to reclaim disk space (this may take a while)...")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("VACUUM")
    conn.close()

    after_size = db_path.stat().st_size
    print(f"\nDone. Database size: {before_size / 1e9:.2f} GB -> {after_size / 1e9:.2f} GB "
          f"({(before_size - after_size) / 1e9:.2f} GB reclaimed).")


if __name__ == "__main__":
    main()
