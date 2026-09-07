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
import contextlib
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from v13.evidence.model import Evidence, NO_DESTINATION

_SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

# Matches schema.sql's own documented policy (comment at the bottom of that file).
# v13 full-architecture plan, Phase 10b: evidence retention itself is now
# hardware_profile-driven too -- see live_prune.py's own _RETENTION_DAYS_BY_PROFILE
# (this constant stays the fallback for the "custom"/unrecognized-profile case and
# for any caller that doesn't go through that wiring, e.g. direct GraphStore use in
# tests).
DEFAULT_EVIDENCE_RETENTION_DAYS = 90

# v13 full-architecture plan, Phase 10b: SQLite PRAGMA cache_size (negative = KB,
# per SQLite's own docs), sized against config/trust_anchors.py's own
# VALID_HARDWARE_PROFILES. A first-pass judgment call (this project's own
# established convention for a not-yet-empirically-tuned number, matching
# INDEPENDENCE_FAMILY_MAP's own "honest status" framing) -- SQLite's own default is
# -2000 (2MB); pi_8gb gets a modest bump given this box also runs Zeek/Suricata/
# Ollama concurrently (see this file's own "Hardware topology" section in
# V13_ARCHITECTURE_DEPENDENCY_MAP.md), x86_16gb/custom get more headroom to spend on
# graph query performance since nothing else on that box is as resource-constrained.
_HARDWARE_PROFILE_CACHE_SIZE_KB: Dict[str, int] = {
    "pi_8gb": 4_000,
    "x86_16gb": 16_000,
    "custom": 16_000,
}


class GraphStore:
    def __init__(self, db_path: str, hardware_profile: Optional[str] = None):
        self.db_path = db_path
        is_new = not Path(db_path).exists()
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        # Phase 10b: optional -- omitting hardware_profile (every pre-existing
        # caller, including every test) leaves SQLite's own default cache_size
        # untouched, identical to this class's behavior before this param existed.
        cache_kb = _HARDWARE_PROFILE_CACHE_SIZE_KB.get(hardware_profile or "")
        if cache_kb is not None:
            self._conn.execute(f"PRAGMA cache_size = -{cache_kb}")
        self._in_transaction = False
        if is_new:
            self._apply_schema()

    def _apply_schema(self) -> None:
        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            self._conn.executescript(f.read())
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _maybe_commit(self) -> None:
        """Every mutating method calls this instead of self._conn.commit() directly.
        Outside a transaction() block, behavior is unchanged (commits immediately,
        same as before this existed). Inside one, defers to the transaction's own
        single commit at the end -- this is what lets a whole poll cycle's writes
        (many insert_evidence() calls + one insert_decision()) cost one commit
        instead of the ~4-per-item cost each of those methods used to pay alone."""
        if not self._in_transaction:
            self._conn.commit()

    @contextlib.contextmanager
    def transaction(self):
        """Groups every write made inside the `with` block into a single commit
        (or a single rollback if the block raises) -- callers writing a whole
        cycle's worth of evidence + a decision should wrap that in one of these
        rather than let each insert_evidence()/insert_decision() call commit on
        its own. Nested `with store.transaction():` blocks are a no-op pass-through
        (only the outermost one actually commits/rolls back)."""
        if self._in_transaction:
            yield
            return
        self._in_transaction = True
        try:
            yield
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            self._in_transaction = False

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
        self._maybe_commit()

    def update_device_metadata(self, device_id: str, updates: Dict[str, Any],
                                 timestamp: Optional[float] = None) -> None:
        """Merges `updates` into a device's metadata_json (shallow -- top-level keys in
        `updates` overwrite the same key in the existing dict, everything else is left
        alone). Auto-upserts the device row first, so this is safe to call for a
        device_id that hasn't been seen via insert_evidence()/insert_decision() yet
        (v13 full-architecture plan, Phase 3 -- used to persist a trust anchor's
        learned MAC, surviving restarts, unlike v-current's own single in-memory
        `_gateway_mac` field)."""
        self.upsert_device(device_id, timestamp=timestamp)
        row = self._conn.execute(
            "SELECT metadata_json FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        try:
            current = json.loads(row["metadata_json"]) if row and row["metadata_json"] else {}
        except (TypeError, ValueError):
            current = {}
        current.update(updates)
        self._conn.execute(
            "UPDATE devices SET metadata_json = ? WHERE device_id = ?",
            (json.dumps(current), device_id),
        )
        self._maybe_commit()

    def get_device_metadata(self, device_id: str) -> Dict[str, Any]:
        """Returns the device's metadata_json as a dict, or {} if the device doesn't
        exist yet or its metadata is malformed -- never raises."""
        row = self._conn.execute(
            "SELECT metadata_json FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        if row is None or not row["metadata_json"]:
            return {}
        try:
            return json.loads(row["metadata_json"])
        except (TypeError, ValueError):
            return {}

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
        self._maybe_commit()

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
        self._maybe_commit()

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
        self._maybe_commit()

    def insert_decision(self, device_id: str, timestamp: float, state: str,
                          decision_path: str, confidence: float, risk_score: float,
                          winning_hypothesis_id: Optional[str] = None,
                          mechanism_flags: Optional[Dict[str, str]] = None,
                          raw_payload: Optional[Dict[str, Any]] = None,
                          evidence_ids: Optional[List[str]] = None) -> str:
        # winning_hypothesis_id references the `hypotheses` table's own versioned
        # registry (schema.sql) -- not yet populated by any v13 module (a
        # separate, not-yet-built concern: registering/versioning hypothesis
        # definitions as graph rows). Left None here deliberately rather than
        # inventing a fake row to satisfy the FK; the winning hypothesis NAME is
        # still fully recoverable from raw_payload_json's own "hypotheses" key.
        """Writes one row to schema.sql's `decisions` table -- the audit trail
        Phase 7's divergence comparator reads (raw_payload_json carries the full
        DecisionEngine.evaluate() return dict for that purpose, per schema.sql's
        own column comment). mechanism_flags records which mechanisms were
        shadow vs. live AT DECISION TIME, so a later divergence found while a
        mechanism was still shadow-only is distinguishable from one found after
        it flipped live -- schema.sql's own stated reason for this column,
        confirmed via direct read, not guessed.

        evidence_ids (Phase 1 fix, v13 full-architecture plan): the evidence_id of
        every Evidence item that contributed to this decision -- creates an
        evidence->decision 'supports' edge for each. Without this, prune_evidence()'s
        own "don't delete evidence a decision still references" exception (see that
        method's docstring) checks for edges that nothing ever created, silently
        pruning evidence a decision's raw_payload_json still points to. Callers pass
        the SAME evidence list they gave the decision engine, by evidence_id.

        Returns the generated decision_id."""
        decision_id = uuid.uuid4().hex
        self.upsert_device(device_id, timestamp=timestamp)
        self._conn.execute(
            "INSERT INTO decisions (decision_id, device_id, timestamp, winning_hypothesis_id, "
            "state, decision_path, confidence, risk_score, mechanism_flags_json, raw_payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (decision_id, device_id, timestamp, winning_hypothesis_id, state, decision_path,
             confidence, risk_score, json.dumps(mechanism_flags or {}), json.dumps(raw_payload or {})),
        )
        for eid in (evidence_ids or []):
            self.add_edge("evidence", eid, "decision", decision_id, "supports", timestamp)
        self._maybe_commit()
        return decision_id

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

    def get_evidence_by_ids(self, evidence_ids: List[str]) -> List[Evidence]:
        """Batch fetch by evidence_id -- added for the console API's graph-view
        endpoint, which resolves the evidence linked to several decisions at once via
        get_edges() and would otherwise pay one query per evidence_id (N+1)."""
        if not evidence_ids:
            return []
        placeholders = ",".join("?" * len(evidence_ids))
        rows = self._conn.execute(
            f"SELECT * FROM evidence WHERE evidence_id IN ({placeholders})", evidence_ids,
        ).fetchall()
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
        self._maybe_commit()

    def get_devices_targeting(self, destination_id: str, since: float) -> List[str]:
        """Distinct CANONICAL device_ids that have touched this destination since
        `since` -- v13 full-architecture plan, Phase 1a: the real, cheap
        cross-device query `idx_evidence_destination` exists to support ("which
        devices have an edge targeting destination X in the last N minutes,"
        schema.sql's own stated reason for that index). Canonicalizes each raw
        device_id via resolve_canonical_device_id() and dedupes -- without this, a
        device that fragmented across an old orphan id and its current canonical id
        could be miscounted as two independent devices touching the same
        destination, when it's really one physical device."""
        rows = self._conn.execute(
            "SELECT DISTINCT device_id FROM evidence WHERE destination_id = ? AND timestamp >= ?",
            (destination_id, since),
        ).fetchall()
        canonical_ids = {self.resolve_canonical_device_id(r["device_id"]) for r in rows}
        return sorted(canonical_ids)

    def get_devices_sharing_provenance(self, evidence_type: str, provenance: str, since: float) -> List[str]:
        """Release 14, net-new capability N4 (multi-signal campaign detection):
        the SAME cross-device query get_devices_targeting() answers for a shared
        DESTINATION, generalized to a shared PROVENANCE string -- e.g. a JA3/JA4
        fingerprint hash, encoded into provenance at the detector (see
        intelligence/detectors/zeek_network.py), matching this codebase's own
        established "provenance is the free-text discriminator slot" convention
        (already used for zeek_notice's note_type). An exact string match is
        correct here (two devices sharing the literal SAME TLS fingerprint hash
        is unambiguous), unlike DGA-seed correlation below, which needs a
        COMPUTED similarity key instead of an exact stored value. Canonicalizes
        each device_id, same reasoning as get_devices_targeting()."""
        rows = self._conn.execute(
            "SELECT DISTINCT device_id FROM evidence WHERE evidence_type = ? AND provenance = ? AND timestamp >= ?",
            (evidence_type, provenance, since),
        ).fetchall()
        canonical_ids = {self.resolve_canonical_device_id(r["device_id"]) for r in rows}
        return sorted(canonical_ids)

    def get_evidence_by_type_since(self, evidence_type: str, since: float) -> List[Evidence]:
        """All evidence of one type across EVERY device since `since` -- unlike
        get_evidence_for_device(), deliberately not scoped to one device. DGA-seed
        correlation (Release 14, N4) needs this raw cross-device fetch because it
        groups by a COMPUTED shape key (live_engine.py's own _dga_shape_key()),
        not a single stored value get_devices_sharing_provenance() could match on
        directly -- the grouping happens in Python after this fetch."""
        rows = self._conn.execute(
            "SELECT * FROM evidence WHERE evidence_type = ? AND timestamp >= ?",
            (evidence_type, since),
        ).fetchall()
        return [Evidence.from_row(dict(r)) for r in rows]

    def get_devices_with_metadata_value(self, key: str, value: Any) -> List[str]:
        """Release 14, N2 (peer-cohort behavioral baselining): all device_ids
        whose metadata_json[key] == value -- a full table scan, parsed in
        Python rather than a SQLite json_extract() query, deliberately, so this
        doesn't depend on the JSON1 extension being available in every
        deployment's SQLite build (the same reasoning every other v13 metadata
        read in this module already applies). Device counts are small (tens,
        not thousands) on any real deployment this project targets, so a full
        scan is cheap -- this is a peer-cohort lookup run once per decision
        cycle per device, not a hot inner loop."""
        rows = self._conn.execute("SELECT device_id, metadata_json FROM devices").fetchall()
        out = []
        for r in rows:
            try:
                meta = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
            except (TypeError, ValueError):
                continue
            if meta.get(key) == value:
                out.append(r["device_id"])
        return out

    def get_distinct_destination_count(self, device_id: str, since: float) -> int:
        """Release 14, N2: the behavioral metric peer-cohort baselining compares
        a device against its cohort on -- how many DISTINCT destinations this
        device has touched since `since`. Chosen because it's cheap (one
        indexed COUNT DISTINCT), needs no new evidence field, and is a
        genuinely meaningful anomaly axis for many device classes (e.g. most
        IoT devices talk to a small, stable set of cloud endpoints; a sudden
        jump in destination diversity is a real behavioral change worth a
        peer comparison, independent of whether any single destination looks
        suspicious on its own)."""
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT destination_id) as c FROM evidence WHERE device_id = ? AND timestamp >= ?",
            (device_id, since),
        ).fetchone()
        return int(row["c"]) if row and row["c"] is not None else 0

    def set_destination_reputation(self, destination_id: str, tier: int,
                                     timestamp: Optional[float] = None) -> None:
        """Writes a live reputation-tier cache onto the shared `destinations` row
        (v13 full-architecture plan, Phase 1a: network-wide reputation
        propagation) -- schema.sql's own `reputation_tier_cache`/`reputation_cached_at`
        columns, confirmed unused by anything before this. Once one device's
        evidence confirms a destination as malicious (see retro_hunter.py's own
        call site), any OTHER device touching the same destination can inherit
        that verdict immediately via get_destination_reputation(), instead of each
        device re-earning its own corroboration from zero. Auto-upserts the
        destination row first, so this is safe to call for a destination not yet
        seen via insert_evidence()."""
        ts = timestamp if timestamp is not None else time.time()
        dest_kind = "ip" if _looks_like_ip(destination_id) else "domain"
        self.upsert_destination(destination_id, dest_kind, timestamp=ts)
        self._conn.execute(
            "UPDATE destinations SET reputation_tier_cache = ?, reputation_cached_at = ? "
            "WHERE destination_id = ?",
            (tier, ts, destination_id),
        )
        self._maybe_commit()

    def get_destination(self, destination_id: str) -> Optional[Dict[str, Any]]:
        """One row from `destinations` (kind/first_seen/last_seen/reputation fields),
        or None if it doesn't exist. Added for the console API's graph-view endpoint,
        which needs a destination's own kind/label rather than just its reputation
        cache (get_destination_reputation() below only returns the latter)."""
        row = self._conn.execute(
            "SELECT * FROM destinations WHERE destination_id = ?", (destination_id,)
        ).fetchone()
        return dict(row) if row is not None else None

    def get_destinations_matching(self, query: str) -> List[str]:
        """destination_ids containing `query` as a case-insensitive substring --
        get_devices_targeting() itself needs an EXACT destination_id, so a free-text
        search UI (the console's "devices touching X" hunt query) composes this first
        to resolve what the user typed into the exact id(s) to then look up."""
        rows = self._conn.execute(
            "SELECT destination_id FROM destinations WHERE destination_id LIKE ? ESCAPE '\\'",
            ("%" + query.replace("%", "\\%").replace("_", "\\_") + "%",),
        ).fetchall()
        return [r["destination_id"] for r in rows]

    def get_destination_reputation(self, destination_id: str) -> Optional[Dict[str, Any]]:
        """Returns {"tier": int, "cached_at": float} if this destination has a live
        reputation cache, or None if it was never set (including a destination
        that doesn't exist yet at all) -- never raises. Callers own their own
        staleness policy; this method never expires anything itself (see
        live_engine.py's own TTL constant for the actual policy applied to reads)."""
        row = self._conn.execute(
            "SELECT reputation_tier_cache, reputation_cached_at FROM destinations WHERE destination_id = ?",
            (destination_id,),
        ).fetchone()
        if row is None or row["reputation_tier_cache"] is None:
            return None
        return {"tier": row["reputation_tier_cache"], "cached_at": row["reputation_cached_at"]}

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

    def get_decisions_since(self, since: float, until: Optional[float] = None) -> List[Dict[str, Any]]:
        """Real decisions (A7) in [since, until) -- the divergence comparator's
        (A8) own read side. raw_payload is parsed back into a dict (stored as
        JSON text, per insert_decision()); mechanism_flags likewise."""
        if until is not None:
            rows = self._conn.execute(
                "SELECT * FROM decisions WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp",
                (since, until),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM decisions WHERE timestamp >= ? ORDER BY timestamp",
                (since,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["raw_payload"] = json.loads(d.pop("raw_payload_json") or "{}")
            d["mechanism_flags"] = json.loads(d.pop("mechanism_flags_json") or "{}")
            out.append(d)
        return out

    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """Release 14, N1 (threat_hunt.py's decision-timeline lookup): one
        decision by id, same raw_payload/mechanism_flags parsing as
        get_decisions_since(). Returns None if no such decision exists (a
        typo'd or already-archived id is a real, expected case for a manual
        lookup tool, not an error)."""
        row = self._conn.execute("SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["raw_payload"] = json.loads(d.pop("raw_payload_json") or "{}")
        d["mechanism_flags"] = json.loads(d.pop("mechanism_flags_json") or "{}")
        return d

    def get_devices_with_latest_decision(self) -> List[Dict[str, Any]]:
        """Every non-merged-away device, LEFT JOINed to its own most recent decision
        (by MAX(timestamp) per device_id) -- added for the console API's device-list
        endpoint. There is no per-device "current state/risk" persisted anywhere
        (DeviceState/ids_state.json has none -- confirmed by direct inspection); the
        latest decision IS that value, matching how the existing Grafana "Master
        Threat Ledger" panel already sources it (home_ids_decision_state /
        home_ids_threat_confidence gauges, themselves populated from this same
        per-cycle decision). Devices with no decision yet return NULL for every
        decision_* column -- a real, expected case (a device seen by the pipeline but
        never yet evaluated), not an error.

        Excludes merged_into_device_id IS NOT NULL rows -- an orphaned identity that
        was merged into a canonical device_id shouldn't double-list alongside it."""
        rows = self._conn.execute(
            """
            SELECT d.device_id, d.display_label, d.device_type, d.first_seen, d.last_seen,
                   dec.decision_id, dec.state, dec.risk_score, dec.confidence,
                   dec.timestamp AS decision_timestamp
            FROM devices d
            LEFT JOIN decisions dec ON dec.decision_id = (
                SELECT decision_id FROM decisions WHERE device_id = d.device_id
                ORDER BY timestamp DESC LIMIT 1
            )
            WHERE d.merged_into_device_id IS NULL
            ORDER BY dec.timestamp DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def get_edges(self, relation: Optional[str] = None, src_kind: Optional[str] = None,
                   src_id: Optional[str] = None, dst_kind: Optional[str] = None,
                   dst_id: Optional[str] = None, limit_most_recent: Optional[int] = None) -> List[Dict[str, Any]]:
        """Generic edge query -- kept here (not a relation-specific method) so
        GraphStore stays a plain graph CRUD layer; relation-specific semantics (e.g.
        CL-AFPE's 'trusts' edge TTL/scoping rules, Phase 4) live in their own module,
        not here.

        limit_most_recent (added for the console API's graph-view endpoint): pushes
        `ORDER BY timestamp DESC LIMIT N` down into SQL instead of the caller fetching
        every matching row and truncating in Python. Real, not hypothetical: one
        production decision has 56,073 edges pointing at it (one device alone accounts
        for ~79% of all evidence in the whole database) -- fetching all of those into
        Python just to keep the newest 15 cost ~3s per call; with idx_edges_dst already
        covering (dst_kind, dst_id), SQLite can satisfy ORDER BY ... LIMIT without
        scanning past what it needs. Returned order is DESC (newest first) when this is
        set, ASC otherwise -- unchanged default behavior for every existing caller."""
        import json
        clauses, params = [], []
        for col, val in (("relation", relation), ("src_kind", src_kind), ("src_id", src_id),
                          ("dst_kind", dst_kind), ("dst_id", dst_id)):
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        if limit_most_recent is not None:
            query = f"SELECT * FROM edges {where} ORDER BY timestamp DESC LIMIT ?"
            params = params + [limit_most_recent]
        else:
            query = f"SELECT * FROM edges {where} ORDER BY timestamp ASC"
        rows = self._conn.execute(query, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            except Exception:
                d["metadata"] = {}
            out.append(d)
        return out

    def count_edges(self, relation: Optional[str] = None, src_kind: Optional[str] = None,
                      src_id: Optional[str] = None, dst_kind: Optional[str] = None,
                      dst_id: Optional[str] = None) -> int:
        """COUNT(*) counterpart to get_edges(), same filter columns -- lets a caller
        using limit_most_recent still report "N of TOTAL" without fetching TOTAL rows
        just to len() them (the console API's graph-view endpoint's own
        evidence_total/evidence_truncated fields)."""
        clauses, params = [], []
        for col, val in (("relation", relation), ("src_kind", src_kind), ("src_id", src_id),
                          ("dst_kind", dst_kind), ("dst_id", dst_id)):
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        row = self._conn.execute(f"SELECT COUNT(*) c FROM edges {where}", params).fetchone()
        return int(row["c"])

    def delete_edge(self, edge_id: int) -> None:
        self._conn.execute("DELETE FROM edges WHERE edge_id = ?", (edge_id,))
        self._maybe_commit()

    # --- retention (schema.sql's own documented policy) -------------------------

    def prune_evidence(self, older_than_days: float = DEFAULT_EVIDENCE_RETENTION_DAYS,
                         now: Optional[float] = None) -> int:
        """Deletes evidence older than the cutoff UNLESS referenced by a decision
        newer than the cutoff (decisions are the audit trail; keep what they point
        to) -- matches schema.sql's documented policy exactly, not a simplified
        version of it. Returns the number of rows deleted.

        BUGFIX (2026-09-07, live audit): this used to delete ONLY from the
        `evidence` table -- every evidence row's own 'observed' edge (device->
        evidence) and 'targets' edge (evidence->destination), plus any 'supports'
        edge from a decision OLDER than this cutoff but still inside the
        separate, much longer 1-year decision-retention window (schema.sql's own
        two DIFFERENT retention windows for evidence vs. decisions -- a decision
        can and does legitimately outlive its own supporting evidence by design),
        were left behind pointing at an evidence_id that no longer existed --
        genuinely dangling, not just stale. Left unbounded, this also meant the
        `edges` table itself never shrank even as `evidence` did, undermining the
        actual reason retention/pruning exists at all (A14's real runaway-growth
        incident). Now selects the evidence_ids being deleted FIRST, deletes
        every edge referencing any of them (either direction), then deletes the
        evidence rows themselves -- all inside one transaction, so a mid-failure
        can never leave edges half-cleaned relative to what evidence survived."""
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        with self.transaction():
            rows = self._conn.execute(
                "SELECT evidence_id FROM evidence WHERE timestamp < ? AND evidence_id NOT IN ("
                "  SELECT src_id FROM edges WHERE src_kind = 'evidence' AND dst_kind = 'decision' "
                "  AND EXISTS (SELECT 1 FROM decisions d WHERE d.decision_id = edges.dst_id AND d.timestamp >= ?)"
                ")",
                (cutoff, cutoff),
            ).fetchall()
            evidence_ids = [r["evidence_id"] for r in rows]
            if not evidence_ids:
                return 0
            placeholders = ",".join("?" * len(evidence_ids))
            self._conn.execute(
                f"DELETE FROM edges WHERE "
                f"(src_kind = 'evidence' AND src_id IN ({placeholders})) OR "
                f"(dst_kind = 'evidence' AND dst_id IN ({placeholders}))",
                evidence_ids + evidence_ids,
            )
            cur = self._conn.execute(
                f"DELETE FROM evidence WHERE evidence_id IN ({placeholders})", evidence_ids,
            )
            return cur.rowcount

    # --- decision archival (v13 full-architecture plan, Phase 10a) -------------

    def get_decisions_older_than(self, days: float, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Read-only: decisions older than the cutoff, same parsed shape as
        get_decisions_since(). Matches schema.sql's own documented policy
        ("decisions: kept 1 year, then archived (exported, not deleted)").
        Deliberately kept as a SEPARATE step from delete_decisions() below
        (not one atomic archive-and-delete method) -- live_decision_archive.py's
        own export-then-delete ordering means nothing is ever removed from the
        live graph until the export write to disk has actually succeeded, so a
        failed export can never silently lose a decision."""
        cutoff = (now if now is not None else time.time()) - days * 86400
        rows = self._conn.execute(
            "SELECT * FROM decisions WHERE timestamp < ? ORDER BY timestamp", (cutoff,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["raw_payload"] = json.loads(d.pop("raw_payload_json") or "{}")
            d["mechanism_flags"] = json.loads(d.pop("mechanism_flags_json") or "{}")
            out.append(d)
        return out

    def delete_decisions(self, decision_ids: List[str]) -> int:
        """Deletes the given decisions AND their own 'supports' edges (so
        nothing is left dangling at a decision_id that no longer exists).
        Callers MUST have already durably exported these rows first -- this
        method has no knowledge of whether that happened, by design; the
        export-then-delete ordering is the caller's own responsibility (see
        get_decisions_older_than()'s own docstring)."""
        if not decision_ids:
            return 0
        placeholders = ",".join("?" * len(decision_ids))
        self._conn.execute(
            f"DELETE FROM edges WHERE dst_kind = 'decision' AND dst_id IN ({placeholders})", decision_ids,
        )
        cur = self._conn.execute(
            f"DELETE FROM decisions WHERE decision_id IN ({placeholders})", decision_ids,
        )
        self._maybe_commit()
        return cur.rowcount


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
