"""
v13 EvidenceGraph SQLite store (Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).
Read/write API over graph/schema.sql. This module owns device/destination/evidence
read+write and audit-preserving identity merges; hypothesis/decision writes are
wired in by their own respective phases (the tables already exist in schema.sql,
just unused by this module until then -- incremental, not all-at-once).

Every Hypothesis.evaluate() (Phase 3) still takes a fresh per-cycle snapshot from
this store via plain queries -- nothing here holds a mutated in-memory graph object
across cycles, preserving the pure-evaluation model HEE_ROADMAP.md said not to break.
"""
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from v13.evidence.model import Evidence, NO_DESTINATION

_SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

# Matches schema.sql's own documented policy (comment at the bottom of that file) --
# not yet configurable per hardware_profile; Phase 0's config draft names this as
# a future hardware_profile-driven knob, not built yet.
DEFAULT_EVIDENCE_RETENTION_DAYS = 90


class GraphStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        is_new = not Path(db_path).exists()
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if is_new:
            self._apply_schema()

    def _apply_schema(self) -> None:
        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            self._conn.executescript(f.read())
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # --- devices -----------------------------------------------------------

    def upsert_device(self, device_id: str, display_label: Optional[str] = None,
                        device_type: Optional[str] = None, timestamp: Optional[float] = None) -> None:
        ts = timestamp if timestamp is not None else time.time()
        cur = self._conn.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,))
        if cur.fetchone() is None:
            self._conn.execute(
                "INSERT INTO devices (device_id, display_label, device_type, first_seen, last_seen, metadata_json) "
                "VALUES (?, ?, ?, ?, ?, '{}')",
                (device_id, display_label, device_type, ts, ts),
            )
        else:
            self._conn.execute(
                "UPDATE devices SET last_seen = ?, "
                "display_label = COALESCE(?, display_label), "
                "device_type = COALESCE(?, device_type) "
                "WHERE device_id = ?",
                (ts, display_label, device_type, device_id),
            )
        self._conn.commit()

    def resolve_canonical_device_id(self, device_id: str) -> str:
        """Walks the merged_into_device_id chain to the ultimate canonical id.
        Unlike v-current's merge_into_canonical() (state_guard.py), an orphan's row
        is NEVER deleted -- this resolution is what makes that audit-preserving
        design actually transparent to every other read in this module."""
        seen = set()
        current = device_id
        while True:
            if current in seen:
                raise RuntimeError(f"merged_into_device_id cycle detected at '{current}'")
            seen.add(current)
            row = self._conn.execute(
                "SELECT merged_into_device_id FROM devices WHERE device_id = ?", (current,)
            ).fetchone()
            if row is None or row["merged_into_device_id"] is None:
                return current
            current = row["merged_into_device_id"]

    def merge_device(self, orphan_id: str, canonical_id: str, timestamp: Optional[float] = None) -> None:
        """Audit-preserving merge -- a deliberate improvement over v-current's
        discard-on-merge (state_guard.py:436-439, called out in the plan for your
        sign-off, not a silent behavior change). The orphan row is tombstoned via
        merged_into_device_id, never deleted, so every evidence/edge row that
        pointed at it keeps resolving through resolve_canonical_device_id()."""
        if orphan_id == canonical_id:
            raise ValueError("cannot merge a device into itself")
        ts = timestamp if timestamp is not None else time.time()
        self.upsert_device(orphan_id, timestamp=ts)
        self.upsert_device(canonical_id, timestamp=ts)
        self._conn.execute(
            "UPDATE devices SET merged_into_device_id = ? WHERE device_id = ?",
            (canonical_id, orphan_id),
        )
        self.add_edge("device", orphan_id, "device", canonical_id, "merged_into", ts)
        self._conn.commit()

    # --- destinations --------------------------------------------------------

    def upsert_destination(self, destination_id: str, kind: str, timestamp: Optional[float] = None) -> None:
        ts = timestamp if timestamp is not None else time.time()
        cur = self._conn.execute("SELECT destination_id FROM destinations WHERE destination_id = ?", (destination_id,))
        if cur.fetchone() is None:
            self._conn.execute(
                "INSERT INTO destinations (destination_id, kind, first_seen, last_seen, metadata_json) "
                "VALUES (?, ?, ?, ?, '{}')",
                (destination_id, kind, ts, ts),
            )
        else:
            self._conn.execute("UPDATE destinations SET last_seen = ? WHERE destination_id = ?", (ts, destination_id))
        self._conn.commit()

    # --- evidence --------------------------------------------------------------

    def insert_evidence(self, ev: Evidence) -> None:
        """Auto-upserts the device and destination rows (including the NO_DESTINATION
        sentinel, already seeded by schema.sql) and the observed/targets edges --
        callers never have to remember the bookkeeping steps in the right order."""
        self.upsert_device(ev.device_id, timestamp=ev.timestamp)
        dest_kind = "ip" if ev.destination_id != NO_DESTINATION and _looks_like_ip(ev.destination_id) else "domain"
        self.upsert_destination(ev.destination_id, dest_kind, timestamp=ev.timestamp)

        row = ev.to_row()
        self._conn.execute(
            "INSERT INTO evidence (evidence_id, device_id, destination_id, evidence_type, "
            "independence_family, value, confidence, timestamp, source, provenance, features_json) "
            "VALUES (:evidence_id, :device_id, :destination_id, :evidence_type, "
            ":independence_family, :value, :confidence, :timestamp, :source, :provenance, :features_json)",
            row,
        )
        self.add_edge("device", ev.device_id, "evidence", ev.evidence_id, "observed", ev.timestamp)
        if ev.destination_id != NO_DESTINATION:
            self.add_edge("evidence", ev.evidence_id, "destination", ev.destination_id, "targets", ev.timestamp)
        self._conn.commit()

    def get_evidence_for_device(self, device_id: str, since: Optional[float] = None,
                                  resolve_merges: bool = True) -> List[Evidence]:
        """Fresh, per-call snapshot -- never a cached/mutated object, matching the
        pure-per-cycle evaluation model every v13 Hypothesis.evaluate() (Phase 3)
        relies on."""
        canonical = self.resolve_canonical_device_id(device_id) if resolve_merges else device_id
        if resolve_merges:
            # Every device_id that ever resolved (directly or transitively) to this
            # canonical id contributes its evidence -- the whole point of not
            # discarding orphans on merge.
            device_ids = self._all_ids_resolving_to(canonical)
        else:
            device_ids = [device_id]
        placeholders = ",".join("?" * len(device_ids))
        query = f"SELECT * FROM evidence WHERE device_id IN ({placeholders})"
        params: List[Any] = list(device_ids)
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since)
        query += " ORDER BY timestamp ASC"
        rows = self._conn.execute(query, params).fetchall()
        return [Evidence.from_row(dict(r)) for r in rows]

    def _all_ids_resolving_to(self, canonical_id: str) -> List[str]:
        ids = [canonical_id]
        rows = self._conn.execute(
            "SELECT device_id FROM devices WHERE merged_into_device_id = ?", (canonical_id,)
        ).fetchall()
        for r in rows:
            ids.extend(self._all_ids_resolving_to(r["device_id"]))
        return ids

    # --- edges -----------------------------------------------------------------

    def add_edge(self, src_kind: str, src_id: str, dst_kind: str, dst_id: str,
                  relation: str, timestamp: Optional[float] = None,
                  metadata: Optional[Dict[str, Any]] = None) -> None:
        import json
        ts = timestamp if timestamp is not None else time.time()
        self._conn.execute(
            "INSERT INTO edges (src_kind, src_id, dst_kind, dst_id, relation, timestamp, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (src_kind, src_id, dst_kind, dst_id, relation, ts, json.dumps(metadata or {})),
        )
        self._conn.commit()

    def get_device_destinations_since(self, since: float) -> List[Any]:
        """Distinct (device_id, destination_id) pairs observed since `since` --
        used by retro_hunter.py (Phase 6) to re-scan historical destinations
        against freshly-updated threat intel, replacing v-current's
        load_historical_domains()'s flat-file JSONL scan with a direct graph query."""
        rows = self._conn.execute(
            "SELECT DISTINCT device_id, destination_id FROM evidence "
            "WHERE timestamp >= ? AND destination_id != '(none)'",
            (since,),
        ).fetchall()
        return [(r["device_id"], r["destination_id"]) for r in rows]

    def get_edges(self, relation: Optional[str] = None, src_kind: Optional[str] = None,
                   src_id: Optional[str] = None, dst_kind: Optional[str] = None,
                   dst_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generic edge query -- kept here (not a relation-specific method) so
        GraphStore stays a plain graph CRUD layer; relation-specific semantics (e.g.
        CL-AFPE's 'trusts' edge TTL/scoping rules, Phase 4) live in their own module,
        not here."""
        import json
        clauses, params = [], []
        for col, val in (("relation", relation), ("src_kind", src_kind), ("src_id", src_id),
                          ("dst_kind", dst_kind), ("dst_id", dst_id)):
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(f"SELECT * FROM edges {where} ORDER BY timestamp ASC", params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            except Exception:
                d["metadata"] = {}
            out.append(d)
        return out

    def delete_edge(self, edge_id: int) -> None:
        self._conn.execute("DELETE FROM edges WHERE edge_id = ?", (edge_id,))
        self._conn.commit()

    # --- retention (schema.sql's own documented policy) -------------------------

    def prune_evidence(self, older_than_days: float = DEFAULT_EVIDENCE_RETENTION_DAYS,
                         now: Optional[float] = None) -> int:
        """Deletes evidence older than the cutoff UNLESS referenced by a decision
        newer than the cutoff (decisions are the audit trail; keep what they point
        to) -- matches schema.sql's documented policy exactly, not a simplified
        version of it. Returns the number of rows deleted."""
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        cur = self._conn.execute(
            "DELETE FROM evidence WHERE timestamp < ? AND evidence_id NOT IN ("
            "  SELECT src_id FROM edges WHERE src_kind = 'evidence' AND dst_kind = 'decision' "
            "  AND EXISTS (SELECT 1 FROM decisions d WHERE d.decision_id = edges.dst_id AND d.timestamp >= ?)"
            ")",
            (cutoff, cutoff),
        )
        self._conn.commit()
        return cur.rowcount


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
