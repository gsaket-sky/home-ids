"""
live_engine.py - the engine's decision path: pipeline.py calls evaluate() for every device cycle and
evaluate_cl_afpe_live() for every alert.

evaluate() converts the cycle's Evidence/features into graph Evidence (the detectors' destination gap for
zeek_exfiltration/zeek_beaconing is filled from features), merges it with the device's recent graph history, adds
graph-derived evidence (coordinated targeting, peer deviation, ...) and baseline evidence, and calls the argus
DecisionEngine.

IF THE ENGINE RAISES, the cycle is not decided by anything else: evaluate() returns a "not evaluated" decision
(BENIGN, no action, decision_path "engine_error") and evaluate_cl_afpe_live() returns UNCERTAIN (the alert is
published normally, never suppressed). The evidence stays in the graph for the next cycle, and engine_error_status()
lets the health manager report the failure. A fallback to a different engine would decide that cycle under
different rules -- a predictable no-action result is safer.

GRAPH WRITE + WINDOWED READ: when `device_id` is
supplied, every call also (a) queries `RollingWindowView.evidence_in_window()` for that
device's persisted history and merges it with this cycle's fresh evidence before
deciding, and (b) writes this cycle's fresh evidence + the resulting decision into the
same GraphStore. Both are best-effort -- a graph failure never affects the returned
decision, only means this cycle is missing from the durable trail (logged loudly, not
silent). `device_id=None` (the default) skips both entirely, unchanged from before this
existed -- so existing callers that don't pass it keep working exactly as they do today.
The decision row is deduped by (state, decision_path) per device (`_last_decision_key`,
mirroring `src/argus/ingest/daemon.py`'s own `only_persist_if_changed_from` pattern) -- a
real fix found live on `.94`'s first restart with this wiring: without it, every device
writes a new decisions-table row every ~2s poll cycle regardless of whether the verdict
actually changed (611 rows observed in well under a minute of real runtime before this
was added). Evidence itself is never deduped this way -- every fresh item is a real
observation worth recording.

WHY QUERY UP TO THE LONGEST TTL, NOT A SHORTER "ROLLING WINDOW": confirmed by reading
`src/argus/hypotheses/engine.py`'s own `compute_freshness()` -- it already discards
anything older than 600s (default) / 86400s (reputation family) per item, matching
the detector `EvidenceStore` TTLs exactly. Querying a shorter window than that would only
ever return a SUBSET of what scoring already considers fresh; querying up to the longest
TTL and letting `compute_freshness()` do the real trimming is simpler and strictly
correct. The actual new capability this unlocks is NOT "see further back in time than a
single cycle already could" (a single cycle's `EvidenceStore`-backed `active_evidence`
already covers the same TTL window) -- it's that this survives a `soc.service` restart,
which wipes `EvidenceStore` completely (100% in-memory, no persistence at all) but not
the graph. A device mid-way through building up a slow pattern doesn't lose that history
just because the service restarted for an unrelated reason.
"""
import ipaddress
import json
import logging
import time
from pathlib import Path
import dataclasses
from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple

from argus.autotune.engine import AutotuneEngine
from argus.baseline.engine import BaselineEngine
from argus.evidence.ingest import convert_list
from argus.evidence.model import Evidence, NO_DESTINATION
from argus.hypotheses.independence import INDEPENDENCE_FAMILY_MAP
from argus.decision.engine import DecisionEngine as V13DecisionEngine
from argus.graph.store import (
    _looks_like_ip,
    GraphStore, DEFAULT_EVIDENCE_RETENTION_DAYS,
    _MAX_EVIDENCE_PER_TYPE_IN_WINDOW_BY_PROFILE, _DEFAULT_MAX_EVIDENCE_PER_TYPE_IN_WINDOW,
)
from argus.graph.merge_consistency import MergeReport, check_merges, repair_merges
from argus.graph.window import RollingWindowView
from argus.cl_afpe.engine import ClAfpeEngine
from argus.cl_afpe.ml_scoring import MLScorer
from config import CONFIG
from extractors.pihole_codes import ratio_metric_key
from intelligence.local_intel import LocalConfirmedIntel
from intelligence.device_familiarity import DeviceFamiliarity
from intelligence.reputation.classifier import ReputationClassifier
from utils import is_cloud_cdn_provider_org

LOGGER = logging.getLogger("home_ids.v13_live_engine")


# The longest TTL argus/hypotheses/engine.py's own compute_freshness() honors (the
# "reputation" independence_family, 86400s) -- see the module docstring above for why
# querying up to this bound, not a shorter one, is the correct design.
_GRAPH_QUERY_WINDOW_SECONDS = 86400

_v13_engine = V13DecisionEngine()

_GRAPH_DB_PATH = "state/v13_graph.db"
_graph_store: Optional[GraphStore] = None

# Mirrors src/argus/ingest/daemon.py's own _last_decision_key dict + compute_decision()'s
# only_persist_if_changed_from param exactly (see that docstring) -- without this, every
# device gets a NEW decisions-table row every single ~2s poll cycle regardless of
# whether the verdict actually changed (confirmed live: 611 decision rows after well
# under a minute of real runtime on .94's first restart with this wiring). Evidence
# itself is NOT deduped this way -- every fresh item is a real observation worth
# recording; it's specifically the DERIVED verdict that shouldn't be re-written when
# nothing about it changed.
_last_decision_key: Dict[str, Tuple[str, str]] = {}

# alert/decision unification (Phase 2): the most
# recently WRITTEN decision_id per device, regardless of which cycle wrote it.
# pipeline.py's alert-worthy gate (300s/60s+risk-delta re-alert cadence) fires on
# many cycles where decision["state"]/decision_path haven't themselves "changed"
# (a persistent HIGH re-notifying), so _last_decision_key's own dedup means most
# alert-worthy cycles do NOT write a fresh decision row -- but the alert built that
# cycle should still enrich the MOST RECENT real decision row for this device, not
# require a same-cycle write. evaluate() attaches this onto decision["_graph_decision_id"]
# on every call (whether or not this cycle itself wrote a new row) so pipeline.py's
# later update_decision_payload() call always has a real target.
_last_decision_id: Dict[str, str] = {}

# the graph-engine migration, Phase 1a -- the new graph-only-possible capabilities'
# tuning constants. Each mirrors a value already established elsewhere in this codebase
# rather than inventing a new number: the coordinated-targeting window matches
# RollingWindowView's own SHORT_WINDOW_SECONDS ("within a short window," the plan's own
# phrasing); the reputation-propagation TTL matches argus/hypotheses/engine.py's own
# _REPUTATION_TTL_SECONDS (the same 86400s bound compute_freshness() already applies to
# every other "reputation" family item, so a propagated verdict ages out on the same
# schedule a directly-observed one would); the first-contact lookback matches
# GraphStore's own DEFAULT_EVIDENCE_RETENTION_DAYS ("seen before" can only mean "within
# what the graph actually still retains" -- claiming first-contact status against data
# that's already been pruned would be a false signal, not a stronger one).
_COORDINATED_TARGETING_WINDOW_SECONDS = RollingWindowView.SHORT_WINDOW_SECONDS
# RAISED (third-party architecture review + live audit, 2026-09-09): was 1 ("2+
# distinct devices" total = 1+ OTHER device). Confirmed live, twice, post-fix: an
# ordinary pair of devices sharing an unclassified private destination (a second
# device independently touching a household IP, another touching the FIRST
# device's own IP) cleared this bar and reached HIGH from essentially nothing --
# neither multicast, shared-infra, nor recognized-CDN, just two devices being
# two devices. "Two coincide" isn't "coordinated"; three independently reaching
# the same otherwise-unclassified signal is a meaningfully harder coincidence.
_COORDINATED_TARGETING_MIN_OTHER_DEVICES = 2  # "3+ distinct devices" total = 2+ OTHER devices

# Release 14, net-new capability N4 (multi-signal campaign detection): widens the
# SAME cross-device-correlation concept above to two more shared signals a real
# campaign can share instead of (or alongside) a literal destination -- same
# window/threshold constants reused, not re-derived, since this is the identical
# underlying question ("is another device independently corroborating this").
_FINGERPRINT_EVIDENCE_TYPES = ("malicious_ja3", "malicious_ja4")
_DGA_EVIDENCE_TYPE = "dns_dga_burst"
_REPUTATION_PROPAGATION_MIN_TIER = 5  # only a fully "corroborated" cached tier propagates
_REPUTATION_PROPAGATION_TTL_SECONDS = 86400
_FIRST_CONTACT_LOOKBACK_SECONDS = DEFAULT_EVIDENCE_RETENTION_DAYS * 86400

# device_id -> set of content keys already written to the graph. A MUCH more serious
# bug than the decision-dedup above, found the same minute on the same restart:
# EvidenceStore.get_for_device() returns the SAME still-fresh detector item on EVERY cycle
# for up to its full TTL (600s default, 86400s reputation -- ~300 cycles at the 2s poll
# interval for a behavioral item alone), and evidence/ingest.py's convert() assigns a
# FRESH, non-deterministic evidence_id on every call with no content-based dedup. Naive
# per-cycle insertion of "this cycle's fresh_v2" therefore re-writes the SAME real
# observation as a brand-new graph row every single cycle it remains in EvidenceStore --
# confirmed live: 12,766 evidence rows / 28.7MB after 9 minutes of real runtime, ~2
# orders of magnitude more than the real observation rate. Detector Evidence has no id field
# of its own, so (device, type, source, timestamp) is used as a stable content key --
# EvidenceStore never mutates an item's timestamp after creation, so the SAME real
# observation produces the SAME key every cycle it's returned. Pruned against each
# cycle's own active-evidence key set, so memory never grows past what EvidenceStore
# itself is currently holding for that device -- when EvidenceStore lets an item expire,
# this forgets it too.
_written_evidence_keys: Dict[str, set] = {}


def _content_key(ev) -> tuple:
    """Same stable identity for both detector Evidence (.type/.device) and v2 Evidence
    (.evidence_type/.device_id) -- needed to recognize a v2 item (already converted)
    against the SAME real observation converted again in a later cycle."""
    device = getattr(ev, "device_id", None) or getattr(ev, "device", None)
    etype = getattr(ev, "evidence_type", None) or getattr(ev, "type", None)
    return (device, etype, ev.source, ev.timestamp)


_GRAPH_HARDWARE_PROFILE: Optional[str] = None


def configure(graph_db_path: str, hardware_profile: Optional[str] = None) -> None:
    """Optional: call once at startup to point the live graph store somewhere other
    than the default 'state/v13_graph.db' (relative to the process's CWD, matching
    every other argus ops file's own state_dir convention). Safe to call before any
    real evaluate() call; if never called, the default path is opened lazily on
    first use with a device_id.

    hardware_profile: passed
    straight through to GraphStore's own PRAGMA cache_size tuning -- this is the
    ONE long-lived GraphStore singleton actually serving the live per-cycle path,
    so it's the one place hardware-driven query-performance tuning actually
    matters (every other argus ops job's own GraphStore is a short-lived,
    once-per-run construction where cache_size has far less to work with).
    Omitting it (the default) leaves SQLite's own default cache_size untouched,
    identical to this function's behavior before this param existed."""
    global _GRAPH_DB_PATH, _GRAPH_HARDWARE_PROFILE, _graph_store
    global _peer_cohort_cache, _peer_cohort_cache_refreshed_at
    _GRAPH_DB_PATH = graph_db_path
    _GRAPH_HARDWARE_PROFILE = hardware_profile
    _graph_store = None  # force re-init against the new path/profile on next use
    _peer_cohort_cache = {}  # stale cohort data from the OLD store would otherwise survive the swap
    _peer_cohort_cache_refreshed_at = 0.0


def _get_graph_store() -> GraphStore:
    global _graph_store
    if _graph_store is None:
        _graph_store = GraphStore(_GRAPH_DB_PATH, hardware_profile=_GRAPH_HARDWARE_PROFILE)
    return _graph_store


# Restart-cadence investigation follow-up (2026-09-28, open item #1 of
# Documentation/MEMORY_RESTART_ROOT_CAUSE_AND_CAPACITY_PLAN.md): device_type ->
# [device_ids], the same shape _gather_peer_stats() below used to
# ask GraphStore.get_devices_with_metadata_value() to recompute via a full
# `devices` table scan EVERY call -- one scan per device evaluated per cycle,
# for a cycle that visits every device. Cached here instead, TTL-refreshed
# (matching ShadowEvaluator._refresh_if_stale()'s own pattern in
# shadow/sandbox.py) as a defensive backstop, PLUS patched incrementally on
# every write (see _record_own_device_type_in_cache() below) since this
# module's own update_device_metadata() call is the ONLY writer of device_type
# metadata anywhere in this codebase (confirmed by grep before this change) --
# every real device patches itself in on its own turn, so by the end of one
# full cycle the cache is exactly as complete as an uncached scan would have
# been, just without N redundant table scans to get there. 60s TTL is well
# above one full main-loop pass (~2-4s measured live on .94), so the backstop
# rebuild only matters for the rare case device_type metadata changes some
# OTHER way (e.g. a future merge/tombstone path) that the incremental patch
# wouldn't see.
_PEER_COHORT_CACHE_REFRESH_SECONDS = 60.0
_peer_cohort_cache: Dict[str, List[str]] = {}
_peer_cohort_cache_refreshed_at: float = 0.0


def _refresh_peer_cohort_cache_if_stale(now: float) -> None:
    global _peer_cohort_cache, _peer_cohort_cache_refreshed_at
    if now - _peer_cohort_cache_refreshed_at >= _PEER_COHORT_CACHE_REFRESH_SECONDS:
        _peer_cohort_cache = _get_graph_store().get_device_type_cohorts()
        _peer_cohort_cache_refreshed_at = now


def _record_own_device_type_in_cache(device_id: str, device_type: str) -> None:
    """Keeps the cache in sync with the one write path that can change a
    device's device_type (the update_device_metadata() call in
    _gather_peer_stats() immediately above this function's own
    call site), without waiting for the next periodic rebuild."""
    for existing_type, ids in _peer_cohort_cache.items():
        if existing_type != device_type and device_id in ids:
            ids.remove(device_id)
            break
    bucket = _peer_cohort_cache.setdefault(device_type, [])
    if device_id not in bucket:
        bucket.append(device_id)


# BUGFIX (2026-09-16, third-party audit finding P0 -- unbounded WAL growth):
# this module's _graph_store singleton is the ONE GraphStore connection in the
# whole codebase that stays open for the life of the process (every other
# caller, e.g. the console API's middleware/graph_client.py, opens a fresh
# connection per request and closes it). SQLite's own automatic WAL checkpoint
# already handles the common case, so this is a periodic, rate-limited
# backstop, not a fix for a confirmed live problem -- see checkpoint_wal()'s
# own docstring for why. 600s: frequent enough to bound worst-case WAL size
# without adding meaningful per-cycle overhead (PASSIVE never blocks).
_WAL_CHECKPOINT_INTERVAL_SECONDS = 600.0
_last_wal_checkpoint_ts: float = 0.0


def _maybe_checkpoint_wal(now: float) -> None:
    global _last_wal_checkpoint_ts
    if now - _last_wal_checkpoint_ts < _WAL_CHECKPOINT_INTERVAL_SECONDS:
        return
    _last_wal_checkpoint_ts = now
    try:
        _get_graph_store().checkpoint_wal()
    except Exception as e:
        LOGGER.warning("Periodic WAL checkpoint failed (non-fatal): %s", e)


def merge_device_in_own_connection(orphan_id: str, canonical_id: str) -> None:
    """GraphStore.merge_device() for callers on a thread OTHER than the main loop (the identity-reconcile
    worker). The singleton's connection is single-thread by design (sqlite3's check_same_thread), so such a caller
    opens a short-lived store on the same database file; the merge runs in one transaction there and SQLite's file
    locking orders it against the main loop's writes."""
    store = GraphStore(_GRAPH_DB_PATH)
    try:
        store.merge_device(orphan_id, canonical_id)
    finally:
        store._conn.close()
    try:   # the singleton caches canonical-id lookups; drop them so the main loop sees the merge at once
        if _graph_store is not None:
            _graph_store._invalidate_merge_caches()
    except Exception:
        pass


def reconcile_graph_splits_in_own_connection(splits: Dict[str, Any]) -> List[str]:
    """Un-merges in the graph every id the engine split (StateManager.get_identity_splits()) that the graph still has
    merged -- a split's own graph mirror is best-effort, like a merge's (LiveIdentityManager._on_identity_split). For
    the identity-reconcile worker thread: a short-lived store of its own. Returns the ids un-merged."""
    if not splits:
        return []
    store = GraphStore(_GRAPH_DB_PATH)
    done: List[str] = []
    try:
        pointers = store.get_merge_pointers()
        for device_id in splits:
            if pointers.get(device_id) and store.unmerge_device(device_id):
                done.append(device_id)
    finally:
        store.close()
    if done:
        try:
            if _graph_store is not None:
                _graph_store._invalidate_merge_caches()
        except Exception:
            pass
    return done


def reconcile_graph_merges_in_own_connection(redirects: Dict[str, str], repair: bool = True) -> MergeReport:
    """Compares the engine's merge redirects with the graph and, with `repair`, replays the merges the graph is
    missing (argus/graph/merge_consistency.py). For the identity-reconcile worker thread: a short-lived store of its
    own, like merge_device_in_own_connection()."""
    store = GraphStore(_GRAPH_DB_PATH)
    try:
        report = repair_merges(store, redirects) if repair else check_merges(redirects, store.get_merge_pointers())
    finally:
        store.close()
    if report.repaired:
        try:
            if _graph_store is not None:
                _graph_store._invalidate_merge_caches()
        except Exception:
            pass
    return report


def get_graph_store() -> GraphStore:
    """Public accessor for the SAME lazily-initialized GraphStore singleton this
    module's own evaluate() uses -- 
    LiveIdentityManager needs the same graph (one file, one source of truth per
    process) for its own anchor-MAC persistence, rather than opening a second,
    independent connection to the same db file."""
    return _get_graph_store()


# Release 15 Sheet 03a live-wiring follow-up: the three autotuner-tunable
# parameters decision/engine.py itself doesn't (and per its own docstring,
# shouldn't) know how to read live -- resolved HERE, the one caller that
# already owns the GraphStore singleton, and passed into evaluate() below as
# plain values. `_reputation_classifier` is a second instance from pipeline.py's
# own `self.rep_classifier` -- classify() is a pure, stateless function
# (confirmed via direct read), so a second instance is not a second source of
# truth, just avoids this module reaching into pipeline.py's own object.
_autotune_engine: Optional[AutotuneEngine] = None
_reputation_classifier = ReputationClassifier()


def _get_autotune_engine() -> AutotuneEngine:
    global _autotune_engine
    if _autotune_engine is None or _autotune_engine.store is not _get_graph_store():
        _autotune_engine = AutotuneEngine(_get_graph_store())
    return _autotune_engine


# Routine baseline updates are persisted at most this often per (device, metric, hour); changepoints save at once.
_BASELINE_SAVE_MIN_INTERVAL_SECONDS = 300.0   # 2026-10-02: was 30 s; saves now batched in one transaction (flash wear)
_baseline_engine: Optional[BaselineEngine] = None


def _get_baseline_engine() -> BaselineEngine:
    global _baseline_engine
    if _baseline_engine is None or _baseline_engine.store is not _get_graph_store():
        _baseline_engine = BaselineEngine(_get_graph_store(), save_min_interval=_BASELINE_SAVE_MIN_INTERVAL_SECONDS)
    return _baseline_engine


def _tuned_rep_vector(rep_vector, params: "DecisionParameters"):
    """Re-classifies `rep_vector` from the SAME raw inputs it was built from (vt/ti/abuse scores, asn_owner -- all on
    the ReputationVector) with the two reputation floors in `params` -- pure: no autotuner read, no state. Both floors
    None (no device scope, the pre-autotune contract) returns `rep_vector` unchanged; one given and the other None uses
    classify()'s own default (2.0 / 4.0) for the missing one. Never mutates `rep_vector`: pipeline.py's alert text
    keeps reading the untouched original."""
    if rep_vector is None:
        return rep_vector
    if params.reputation_tier_suspicious_floor is None and params.reputation_tier_high_floor is None:
        return rep_vector
    suspicious_floor = params.reputation_tier_suspicious_floor
    high_floor = params.reputation_tier_high_floor
    return _reputation_classifier.classify(
        rep_vector.domain, vt_score=rep_vector.vt_detection_ratio,
        afpe_score=rep_vector.cl_afpe_similarity, is_new=rep_vector.first_seen,
        ti_score=rep_vector.ti_risk, abuse_score=rep_vector.abuse_risk,
        asn_owner=rep_vector.asn_owner,
        confirmed_vt_ti_floor=2.0 if suspicious_floor is None else suspicious_floor,
        confirmed_abuse_floor=4.0 if high_floor is None else high_floor,
    )


def record_device_traffic(device_id: str, destination_ids, now: Optional[float] = None,
                          seen: bool = False) -> None:
    """Public entry point for pipeline.py to record THIS cycle's real destinations
    (e.g. its own zeek_fx.get_dest_ips() output) into GraphStore.
    device_destinations -- external architecture review, 2026-09-09: closes the
    self-reinforcing false-positive loop where PeerDeviationHypothesis's own
    "distinct destination count" was being read from the `evidence` table (a
    detector-biased proxy: only destinations that ALSO triggered some other
    evidence show up at all), not real traffic. See GraphStore.
    get_distinct_destination_count()'s own BUGFIX comment for the full incident.

    Best-effort, same "never blocks the real decision" contract as every other
    graph write in this module -- a failure here degrades to today's behavior for
    THIS cycle (peer-cohort baselining simply doesn't see this cycle's traffic
    yet, not a crash), never raises.

    `seen`: the device had DNS or Zeek activity this cycle. Advances the graph's
    devices.last_seen even with no destination to record (a WiFi device the wired
    sensor only sees through its DNS queries). This and record_device_destinations()
    are the only writers that move last_seen; every other graph write only ensures
    the row exists (GraphStore.ensure_device)."""
    if not device_id:
        return
    try:
        if destination_ids:
            _get_graph_store().record_device_destinations(device_id, destination_ids, timestamp=now)
        elif seen:
            _get_graph_store().upsert_device(device_id, timestamp=now)
    except Exception as e:
        LOGGER.warning(
            "Failed to record device traffic for %r into device_destinations "
            "(non-fatal, peer-cohort baselining degrades to not seeing this "
            "cycle's traffic): %s", device_id, e,
        )


def _convert_active_evidence(v1_evidence_list, features: dict):
    """Converts this cycle's detector evidence as-is. P0 (architecture review 2026-10-02): there is no longer a
    last_dest_ip fallback for destination-less zeek_exfiltration/zeek_beaconing evidence -- it stamped the device's
    most recent connection onto every such item in the batch, so one IP collected evidence from unrelated traffic
    and false corroboration followed. The detectors now attribute to what actually fired (the dominant byte
    receiver, the periodic domain); evidence without one keeps NO_DESTINATION."""
    return convert_list(list(v1_evidence_list), INDEPENDENCE_FAMILY_MAP) if v1_evidence_list else []


def _query_graph_window(device_id: str, now: float) -> List:
    """Best-effort: returns [] on any failure rather than raising, so a graph
    problem degrades to "decide on this cycle's fresh evidence only" (exactly
    today's pre-Phase-1 behavior), never blocks a real decision.

    BUGFIX (2026-09-20, restart-cadence investigation): cap_per_type is now
    passed here, hardware-profile-driven -- a real device found live on .94
    generated 41,509 evidence rows in this SAME 24h window (39,551 of them
    zeek_notice_weak, ~1 every 2.2s non-stop), and constructing+iterating that
    many Evidence objects every 2s cycle for one device was blowing the
    pipeline_main_loop's 60s heartbeat deadline, self-restarting every
    ~12-14 minutes -- worse than Root Causes #1/#2 ever were. See
    GraphStore._MAX_EVIDENCE_PER_TYPE_IN_WINDOW_BY_PROFILE's own comment for
    why this bounds the pathological-volume case without losing genuine
    signal (most-recent-first, and confirmed the specific case that motivated
    this -- zeek_notice_weak's fixed per-tier confidence -- is mathematically
    unaffected by which subset survives the cap)."""
    try:
        store = _get_graph_store()
        window = RollingWindowView(store)
        cap = _MAX_EVIDENCE_PER_TYPE_IN_WINDOW_BY_PROFILE.get(
            _GRAPH_HARDWARE_PROFILE or "", _DEFAULT_MAX_EVIDENCE_PER_TYPE_IN_WINDOW)
        return window.evidence_in_window(device_id, _GRAPH_QUERY_WINDOW_SECONDS, now=now, cap_per_type=cap)
    except Exception as e:
        LOGGER.warning(
            "Failed to query GraphStore window for device %r, deciding on this "
            "cycle's fresh evidence only: %s", device_id, e,
        )
        return []


def _write_graph(device_id: str, timestamp: float, fresh_v2: List, merged_v2: List,
                   decision: Dict[str, Any]) -> None:
    """Best-effort: never raises out to the caller. A failure here means this
    cycle is missing from the durable audit trail -- it must never affect the
    live decision, which has already been computed and returned by the time
    this runs.

    Evidence is only inserted the FIRST cycle it's seen (see _written_evidence_keys'
    own module-level comment for why this matters -- without it, the same real
    observation gets re-written every cycle it remains in EvidenceStore). The
    decision row is separately deduped by (state, decision_path) via
    _last_decision_key, matching src/argus/ingest/daemon.py's own
    only_persist_if_changed_from pattern. Skips the graph entirely (no transaction
    opened at all) when there's neither new evidence nor a changed decision."""
    written = _written_evidence_keys.setdefault(device_id, set())
    current_fresh_keys = {_content_key(ev) for ev in fresh_v2}
    written &= current_fresh_keys  # forget anything EvidenceStore itself has let expire
    new_v2 = [ev for ev in fresh_v2 if _content_key(ev) not in written]

    try:
        current_key = (decision["state"], decision["decision_path"])
        decision_changed = _last_decision_key.get(device_id) != current_key
        if not new_v2 and not decision_changed:
            return
        try:
            store = _get_graph_store()
            with store.transaction():
                for ev in new_v2:
                    store.insert_evidence(ev)
                if decision_changed:
                    # Phase 1a: merged_v2 also carries synthetic, graph-DERIVED evidence
                    # (_gather_graph_derived()) that is deliberately never passed
                    # to insert_evidence() above -- an evidence->decision 'supports' edge
                    # for an evidence_id that was never actually persisted would be a
                    # dangling reference. All three synthetic evidence types share the
                    # "v13_live_engine:" provenance prefix, so filtering on that (rather
                    # than threading a separate is-synthetic flag through several layers)
                    # is enough to exclude them here.
                    real_evidence_ids = [
                        ev.evidence_id for ev in merged_v2
                        if not ev.provenance.startswith("v13_live_engine:")
                    ]
                    new_decision_id = store.insert_decision(
                        device_id=device_id, timestamp=timestamp,
                        state=decision["state"], decision_path=decision["decision_path"],
                        confidence=float(decision.get("threat_confidence", 0.0) or 0.0),
                        risk_score=float(decision.get("hypotheses", {}).get("attack", {}).get("score", 0.0) or 0.0),
                        raw_payload=decision,
                        evidence_ids=real_evidence_ids,
                    )
                    # Alert-trace graph (Documentation/ALERT_TRACE_GRAPH_PLAN.md,
                    # 2026-09-22): the hypothesis layer insert_decision() alone never
                    # populates (winning_hypothesis_id confirmed 0/45,650 rows on .94's
                    # real graph) -- best-effort, same convention as every other graph
                    # enrichment call in this module (a failure here must never affect
                    # the already-returned live decision).
                    try:
                        store.add_hypothesis_edges(
                            new_decision_id, decision.get("hypotheses", {}),
                            decision.get("explanation"), real_evidence_ids, timestamp,
                        )
                    except Exception as e:
                        LOGGER.warning(
                            "Failed to write hypothesis edges for decision %r, device %r "
                            "-- the live decision itself is already made and unaffected: %s",
                            new_decision_id, device_id, e,
                        )
                    _last_decision_key[device_id] = current_key
                    _last_decision_id[device_id] = new_decision_id
            # Only mark as written AFTER a successful commit -- a failed write leaves
            # these keys untracked, so they're correctly retried next cycle instead of
            # being silently lost from the graph forever.
            written.update(_content_key(ev) for ev in new_v2)
        except Exception as e:
            LOGGER.error(
                "Failed to write evidence/decision to GraphStore for device %r -- the live "
                "decision itself is already made and unaffected by this: %s",
                device_id, e, exc_info=True,
            )
    finally:
        # BUGFIX (2026-09-16, third-party audit finding P1 -- unbounded memory
        # growth): the prune above (`written &= current_fresh_keys`) empties
        # `written` once EvidenceStore lets every item for this device expire,
        # but never removed the now-empty set's OWN top-level device_id entry --
        # mobile devices routinely rotate MAC addresses, so over weeks/months
        # this dict accumulates one permanent empty-set entry per ephemeral MAC
        # ever seen. Checked here, in `finally`, AFTER every write attempt above
        # (written.update() may have just repopulated it this same call) so an
        # in-flight write's own dedup bookkeeping is never discarded out from
        # under it -- only a device_id whose set is STILL empty once this call
        # is entirely done gets dropped. Re-created via setdefault() above the
        # moment this device_id is active again, identical to a device seen for
        # the first time.
        if device_id in _written_evidence_keys and not _written_evidence_keys[device_id]:
            del _written_evidence_keys[device_id]


def write_supplementary_decision(device_id: str, timestamp: float, new_evidence_v1: List,
                                   decision: Dict[str, Any]) -> Optional[str]:
    """For a decision computed OUTSIDE the main per-cycle evaluate() call above --
    currently only pipeline.py's geofencing hard-stop re-decision (redecide_with_evidence(),
    the pure decide() on the cycle's own gathered facts: it gathers nothing and writes
    nothing, so a second evaluate() -- whose baseline learners would have observed the
    cycle twice -- is never needed). This function does ONLY the plain graph write (new
    evidence + one decision row + hypothesis edges).

    Found live 2026-09-22: a real geofencing HIGH alert (document-server/device-hash,
    Russia-blocklisted destination) fired correctly to Telegram but was completely
    absent from the graph/console/Evidence-Graph/alert narrative, because the
    original re-evaluation path never set decision["_graph_decision_id"] at all
    (evaluate() only sets it when device_id is passed) -- so pipeline.py's whole
    downstream alert_event/plain_explanation block silently no-op'd for every
    geofencing-triggered alert. Caller is expected to set
    decision["_graph_decision_id"] itself from this function's return value.

    Same best-effort, content-key dedup (_written_evidence_keys, shared with
    _write_graph() above) and "never raises, never affects the already-made
    decision" contract as everywhere else in this module. Returns the new
    decision_id, or None if there was nothing new to write."""
    try:
        fresh_v2 = _convert_active_evidence(new_evidence_v1, {})
        written = _written_evidence_keys.setdefault(device_id, set())
        new_v2 = [ev for ev in fresh_v2 if _content_key(ev) not in written]
        if not new_v2:
            return None
        store = _get_graph_store()
        with store.transaction():
            for ev in new_v2:
                store.insert_evidence(ev)
            new_evidence_ids = [ev.evidence_id for ev in new_v2]
            new_decision_id = store.insert_decision(
                device_id=device_id, timestamp=timestamp,
                state=decision["state"], decision_path=decision["decision_path"],
                confidence=float(decision.get("threat_confidence", 0.0) or 0.0),
                risk_score=float(decision.get("hypotheses", {}).get("attack", {}).get("score", 0.0) or 0.0),
                raw_payload=decision,
                evidence_ids=new_evidence_ids,
            )
            try:
                store.add_hypothesis_edges(
                    new_decision_id, decision.get("hypotheses", {}),
                    decision.get("explanation"), new_evidence_ids, timestamp,
                )
            except Exception as e:
                LOGGER.warning(
                    "Failed to write hypothesis edges for supplementary decision %r, "
                    "device %r -- the live decision itself is already made and "
                    "unaffected by this: %s", new_decision_id, device_id, e,
                )
        written.update(_content_key(ev) for ev in new_v2)
        _last_decision_key[device_id] = (decision["state"], decision["decision_path"])
        _last_decision_id[device_id] = new_decision_id
        return new_decision_id
    except Exception as e:
        LOGGER.error(
            "Failed to write supplementary decision to GraphStore for device %r -- "
            "the live decision itself is already made and unaffected by this: %s",
            device_id, e, exc_info=True,
        )
        return None


def _dga_shape_key(domain: str) -> str:
    """Release 14, N4: normalizes a DGA-shaped domain into a coarse "generation
    shape" fingerprint -- the first label's length, its TLD, and its character-
    class composition (hex-only / alphanumeric-with-digits / alpha-only). Real
    DGA families commonly produce a highly consistent SHAPE across every domain
    they generate (fixed length, fixed charset, fixed TLD), even though the
    literal string differs per date/seed input -- an established DGA-clustering
    heuristic, not invented for this feature. First-pass, not empirically tuned
    against this network's own real DGA traffic (same honest-status framing this
    project's own INDEPENDENCE_FAMILY_MAP already uses for a similarly
    unvalidated number) -- the divergence data this correlation itself produces
    is what should validate or refute it over time, not a claim made up front.
    Returns "" for anything that isn't a real two-label-or-more domain (an IP,
    NO_DESTINATION, or a malformed value) -- deliberately not a match key at all,
    never grouped with another empty key."""
    if not domain or domain == NO_DESTINATION or "." not in domain:
        return ""
    try:
        ipaddress.ip_address(domain)
        return ""  # a bare IP is not a DGA-generated hostname, never a match key
    except ValueError:
        pass
    parts = domain.split(".")
    label, tld = parts[0], parts[-1]
    if not label:
        return ""
    is_hex = all(c in "0123456789abcdefABCDEF" for c in label)
    has_digit = any(c.isdigit() for c in label)
    charset_class = "hex" if is_hex else ("alnum_digit" if has_digit else "alpha")
    return f"{len(label)}:{tld}:{charset_class}"


_LAN_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "224.0.0.0/4", "fc00::/7", "fe80::/10", "ff00::/8", "::1/128"))


def _is_lan_destination(dest: str) -> bool:
    """True for a literal RFC1918/loopback/link-local/multicast/ULA IP. Several
    devices reaching one LAN host (a speaker, hub, router) is ordinary local
    chatter, not a coordinated campaign against a shared external target -- so
    coordinated_targeting skips these. Deliberately NOT ip.is_private, which also
    covers documentation/reserved ranges. Non-IP values (domains) return False."""
    try:
        ip = ipaddress.ip_address(dest)
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in _LAN_NETWORKS)


def _gather_graph_derived(device_id: str, destinations: set, ts: float,
                          fresh_evidence: Optional[List[Evidence]] = None,
                          geoip_engine=None) -> List[Any]:
    """GATHER stage (U7, 2026-10-14): the graph reads behind the derived signals below, done once per cycle. Returns
    Evidence items plus `_ReputationCandidate` placeholders, in scoring order; a placeholder becomes `reputation`
    evidence in decide() only when within `reputation_propagation_ttl_seconds` (a decide-stage parameter, so a shadow
    evaluates a candidate TTL on the same facts without a second graph read).

    computes the three new graph-only-possible
    signals for THIS cycle's decision -- cross-device correlation, reputation
    propagation, and genuine first-contact scoring (see graph/window.py's
    devices_targeting()/domain_seen_before() and graph/store.py's
    get_destination_reputation(), all built for exactly this). Release 14, N4:
    ALSO widens cross-device correlation to two more shared signals besides a
    literal destination -- a shared JA3/JA4 TLS fingerprint (devices_sharing_
    fingerprint(), an exact provenance match) and a shared DGA "generation
    shape" (_dga_shape_key(), a computed similarity key) -- fed into the SAME
    CoordinatedTargetingHypothesis, which now scores on any of the three.
    `fresh_evidence` (optional, default None/[] for any existing caller that
    hasn't been updated) is THIS cycle's own fresh v2 evidence list -- needed
    for N4 because fingerprint/DGA correlation keys off evidence_type/provenance,
    not destination_id alone.

    CRITICAL: the returned items are added ONLY to merged_v2 (this cycle's scoring
    input) by the caller, NEVER to fresh_v2 (the graph-write path). A synthetic item
    re-created fresh every cycle would look "new" by _content_key() every single time
    (its own timestamp is `ts`, which changes every call) -- writing it to the graph
    would re-create the exact evidence-duplication bug Phase 1's own incident already
    found and fixed (see this module's own _written_evidence_keys docstring). These
    items are graph-DERIVED context for scoring, not a sensor observation to persist.

    Best-effort, matching every other graph read in this module: any failure degrades
    to 'no synthetic evidence this cycle' and returns [], never blocks the real
    decision.

    BUGFIX (live audit, 2026-09-08): `geoip_engine` (optional -- callers without one
    keep today's behavior unchanged) gates `coordinated_targeting` specifically, not
    the reputation-propagation/first-contact signals below it. Root cause: the
    decision engine's `rep_vector.tier in (1,2)` contradicting-evidence check (the
    ONLY thing that would otherwise suppress this hypothesis on a trusted
    destination) is computed ONCE per cycle for `reputation_target` -- whichever
    domain earned the highest TI/VT/abuse risk score that cycle -- and reused
    across every hypothesis regardless of relevance. `coordinated_targeting`'s own
    evidence is about a DIFFERENT destination entirely (confirmed live: multiple
    devices independently streaming Netflix, `45.57.x.x`, scored as "coordinated
    targeting" while `rep_vector` that cycle described an unrelated domain with zero
    real touching devices) -- the tier check was never evaluating the actual
    destination this hypothesis's evidence is about. A cheap, local ASN-owner
    lookup against THIS destination specifically (matching the same
    `is_cloud_cdn_provider_org()` keyword list `ReputationClassifier.classify()`
    already trusts elsewhere, `.94`'s existing GeoLite2 ASN db, no network call)
    closes that gap at the one place this hypothesis's own evidence is created,
    without restructuring how `rep_vector` flows through every other hypothesis."""
    synthetic: List[Evidence] = []
    fresh_evidence = fresh_evidence or []
    real_destinations = {d for d in destinations if d and d != NO_DESTINATION}
    if not real_destinations and not fresh_evidence:
        return synthetic
    try:
        store = _get_graph_store()
        window = RollingWindowView(store)
        for dest in real_destinations:
            others = window.devices_targeting(
                dest, _COORDINATED_TARGETING_WINDOW_SECONDS, now=ts, exclude_device_id=device_id,
            )
            if others and _is_lan_destination(dest):
                others = []
            if others and geoip_engine is not None:
                try:
                    asn_info = geoip_engine.lookup_asn(dest)
                    owner = asn_info.autonomous_system_organization if asn_info else ""
                except Exception:
                    owner = ""
                if owner and is_cloud_cdn_provider_org(owner):
                    others = []
            if len(others) >= _COORDINATED_TARGETING_MIN_OTHER_DEVICES:
                synthetic.append(Evidence(
                    device_id=device_id, destination_id=dest, evidence_type="coordinated_targeting",
                    independence_family="cross_device_correlation", timestamp=ts,
                    source="v13_live_engine", confidence=1.0, value=float(len(others) + 1),
                    provenance="v13_live_engine:coordinated_targeting",
                    features={"other_devices": others},
                ))

            rep = store.get_destination_reputation(dest)
            # The propagation TTL (reputation_propagation_ttl_seconds) is applied in decide(), see the docstring.
            if rep and rep["tier"] >= _REPUTATION_PROPAGATION_MIN_TIER:
                synthetic.append(_ReputationCandidate(dest, float(rep["tier"]), float(rep["cached_at"])))

            if not window.domain_seen_before(
                device_id, dest, _FIRST_CONTACT_LOOKBACK_SECONDS, now=ts,
                exclude_window_seconds=RollingWindowView.SHORT_WINDOW_SECONDS,
            ):
                synthetic.append(Evidence(
                    device_id=device_id, destination_id=dest, evidence_type="first_contact",
                    independence_family="novelty_context", timestamp=ts,
                    source="v13_live_engine", confidence=1.0, value=1.0,
                    provenance="v13_live_engine:first_contact",
                ))

        # Release 14, N4a: shared JA3/JA4 fingerprint correlation -- an exact
        # provenance match (the real hash, encoded at the detector), same
        # cross-device-corroboration shape as coordinated_targeting above.
        for ev in fresh_evidence:
            if ev.evidence_type not in _FINGERPRINT_EVIDENCE_TYPES or not ev.provenance:
                continue
            others = window.devices_sharing_fingerprint(
                ev.evidence_type, ev.provenance, _COORDINATED_TARGETING_WINDOW_SECONDS,
                now=ts, exclude_device_id=device_id,
            )
            if len(others) >= _COORDINATED_TARGETING_MIN_OTHER_DEVICES:
                synthetic.append(Evidence(
                    device_id=device_id, destination_id=ev.destination_id, evidence_type="fingerprint_campaign",
                    independence_family="cross_device_correlation", timestamp=ts,
                    source="v13_live_engine", confidence=1.0, value=float(len(others) + 1),
                    provenance="v13_live_engine:fingerprint_campaign",
                    features={"other_devices": others, "shared_evidence_type": ev.evidence_type},
                ))

        # Release 14, N4b: shared DGA "generation shape" correlation -- a COMPUTED
        # similarity key (_dga_shape_key()), not an exact stored value, so this
        # needs its own cross-device scan rather than devices_sharing_fingerprint()'s
        # exact-match query. Lower confidence than the fingerprint/destination
        # signals (0.7, not 1.0) -- an honest reflection that shape-matching is a
        # real but approximate heuristic, not a definitional match.
        my_dga_shapes = {_dga_shape_key(ev.destination_id) for ev in fresh_evidence
                          if ev.evidence_type == _DGA_EVIDENCE_TYPE}
        my_dga_shapes.discard("")
        if my_dga_shapes:
            # BUGFIX (2026-09-20, restart-cadence investigation follow-up): flagged at
            # the time as the same bug class as Root Cause #3 (a system-wide, fully
            # unbounded fetch, re-run once per device per cycle) but lower priority
            # since there was no live evidence it was actually large -- capped now
            # defensively. Per-DEVICE, not a flat total: see
            # GraphStore.get_evidence_by_type_since()'s own comment for why a flat cap
            # would be actively wrong here (it would let one flooding device crowd out
            # every other genuinely-distinct device from this cross-device correlation).
            dga_cap = _MAX_EVIDENCE_PER_TYPE_IN_WINDOW_BY_PROFILE.get(
                _GRAPH_HARDWARE_PROFILE or "", _DEFAULT_MAX_EVIDENCE_PER_TYPE_IN_WINDOW)
            all_dga_evidence = store.get_evidence_by_type_since(
                _DGA_EVIDENCE_TYPE, since=ts - _COORDINATED_TARGETING_WINDOW_SECONDS,
                cap_per_device=dga_cap,
            )
            for shape_key in my_dga_shapes:
                others = sorted({
                    store.resolve_canonical_device_id(e.device_id) for e in all_dga_evidence
                    if store.resolve_canonical_device_id(e.device_id) != device_id
                    and _dga_shape_key(e.destination_id) == shape_key
                })
                if len(others) >= _COORDINATED_TARGETING_MIN_OTHER_DEVICES:
                    synthetic.append(Evidence(
                        device_id=device_id, destination_id=NO_DESTINATION, evidence_type="dga_seed_campaign",
                        independence_family="cross_device_correlation", timestamp=ts,
                        source="v13_live_engine", confidence=0.7, value=float(len(others) + 1),
                        provenance=f"v13_live_engine:dga_seed_campaign:{shape_key}",
                        features={"other_devices": others, "shape_key": shape_key},
                    ))
    except Exception as e:
        LOGGER.warning(
            "Failed to compute Phase 1a graph-derived signals for device %r, deciding "
            "without them this cycle: %s", device_id, e,
        )
        return []
    return synthetic


# Release 14, N2 tuning constants -- FIRST-PASS, NOT EMPIRICALLY TUNED against
# this network's own real peer variance (same honest-status framing this
# project's own INDEPENDENCE_FAMILY_MAP already uses for a similarly
# unvalidated number). The divergence/false-positive data this signal itself
# produces once live is what should validate or refute these, not a claim made
# up front.
_PEER_DEVIATION_WINDOW_SECONDS = 7 * 86400  # a week -- stable enough for a baseline, current enough to matter
# P2 FOLLOW-UP (third-party review, 2026-09-28): raised from 2 -- a 2-peer cohort's
# "average" is one outlier away from being meaningless (either peer alone swings it
# 50%), and this heuristic is already flagged above as a genuinely new, unvalidated
# one with no live tuning data. 3 is the smallest cohort where a single unusual peer
# can no longer dominate the average outright. Below this, _inject_peer_deviation_
# evidence() returns [] entirely (an automatic disable, not a confidence penalty --
# there's no real signal to discount when the "cohort" itself isn't statistically
# meaningful yet).
_PEER_DEVIATION_MIN_PEERS = 3
_PEER_DEVIATION_MULTIPLIER = 3.0  # this device's own count must be >= 3x its cohort's average
_PEER_DEVIATION_MIN_ABSOLUTE_COUNT = 5  # avoid flagging trivial small-number swings (e.g. 1 -> 4 is "4x" but meaningless)

# A2 (2026-10-01): every device's evaluation used to re-query the 7-day distinct-destination count of EVERY peer in
# its cohort -- O(devices x peers) COUNT(DISTINCT) queries per cycle, a steady share of the engine's CPU on .94. A
# count over a 7-day window does not move in a few minutes, so each device's count is reused for this long.
_DISTINCT_DEST_CACHE_TTL_SECONDS = 300.0
_distinct_dest_cache: Dict[str, Tuple[float, int]] = {}


def _cached_distinct_destination_count(store, device_id: str, ts: float) -> int:
    hit = _distinct_dest_cache.get(device_id)
    if hit is not None and 0.0 <= ts - hit[0] < _DISTINCT_DEST_CACHE_TTL_SECONDS:
        return hit[1]
    count = store.get_distinct_destination_count(device_id, ts - _PEER_DEVIATION_WINDOW_SECONDS)
    if len(_distinct_dest_cache) > 10000:
        _distinct_dest_cache.clear()
    _distinct_dest_cache[device_id] = (ts, count)
    return count


def _gather_peer_stats(device_id: str, device_type: str, ts: float) -> Optional["PeerStats"]:
    """Release 14, net-new capability N2: "does this device deviate from
    similar devices" -- groups devices by device_type (already computed by
    core/identity.py and pipeline.py, passed straight through here) and
    compares THIS device's own distinct-destination count (the last 7 days)
    against its cohort's average. Persists device_type onto this device's own
    graph metadata as a side effect (best-effort, mirrors how trust-anchor MAC
    learning already persists onto device_metadata), also patching the module-
    level _peer_cohort_cache (see that cache's own comment above) so it has
    something to group on -- the cohort naturally gets more complete as more
    devices are evaluated over time, no separate backfill job needed.

    HONEST STATUS, not hidden: this is a genuinely NEW anomaly heuristic, unlike
    coordinated_targeting/fingerprint_campaign/dga_seed_campaign (all reuse
    well-established, low-false-positive correlation concepts) -- real cohort
    variance (two very different real-world usage patterns sharing one
    device_type) could produce a real false positive with no live tuning data
    yet. PeerDeviationHypothesis (argus/hypotheses/engine.py) is deliberately capped
    at a SUSPICIOUS ceiling on its own, never independently reaching HIGH,
    reflecting that lower confidence explicitly rather than silently trusting
    an unvalidated number the way an established signal would be.

    Best-effort, matching every other graph read in this module: any failure
    degrades to 'no synthetic evidence this cycle' and returns [], never blocks
    the real decision.

    BUGFIX (live audit, 2026-09-08): "unknown" (the literal string
    `getattr(state, "device_type", "unknown")` falls back to across this codebase,
    pipeline.py's own convention) is truthy, so it slipped past the guard below and
    pooled every unidentified device on the network into one fake "unknown" cohort
    -- physically unrelated devices (a smart plug, a laptop, a phone that hasn't
    finished fingerprinting yet) compared against each other as if they were peers.
    Confirmed live: 13 such devices, one genuine high-traffic outlier among them
    skewed the "peer average" enough to flag an otherwise near-idle, still-
    unidentified device at HIGH with zero real evidence behind it. "unknown" means
    exactly the same thing an empty device_type does here -- no real classification
    to compare against -- so it gets the same treatment."""
    # GATHER stage (U7, 2026-10-14): only the counts are gathered here; the two thresholds
    # (peer_deviation_min_absolute_count / peer_deviation_multiplier) are applied in decide() by
    # _peer_deviation_evidence(), so a shadow evaluates a candidate threshold on the same counts.
    if not device_type or device_type == "unknown":
        return None
    try:
        store = _get_graph_store()
        store.update_device_metadata(device_id, {"device_type": device_type}, timestamp=ts)
        _refresh_peer_cohort_cache_if_stale(ts)
        _record_own_device_type_in_cache(device_id, device_type)
        peers = [d for d in _peer_cohort_cache.get(device_type, []) if d != device_id]
        if len(peers) < _PEER_DEVIATION_MIN_PEERS:
            return None
        my_count = _cached_distinct_destination_count(store, device_id, ts)
        peer_counts = [_cached_distinct_destination_count(store, p, ts) for p in peers]
        return PeerStats(device_type=device_type, my_count=my_count,
                         peer_avg=sum(peer_counts) / len(peer_counts), peer_count=len(peers))
    except Exception as e:
        LOGGER.warning(
            "Failed to compute peer-cohort deviation for device %r (type=%r), deciding "
            "without it this cycle: %s", device_id, device_type, e,
        )
    return None


def _peer_deviation_evidence(device_id: str, stats: Optional["PeerStats"], params: "DecisionParameters",
                             ts: float) -> List[Evidence]:
    """DECIDE stage, pure: the peer-deviation evidence for gathered `stats` under `params`."""
    if stats is None or stats.my_count < params.peer_deviation_min_absolute_count:
        return []
    if stats.peer_avg > 0 and stats.my_count >= stats.peer_avg * params.peer_deviation_multiplier:
        return [Evidence(
            device_id=device_id, destination_id=NO_DESTINATION, evidence_type="peer_deviation",
            independence_family="peer_cohort_deviation", timestamp=ts,
            source="v13_live_engine", confidence=0.6, value=float(stats.my_count),
            provenance=f"v13_live_engine:peer_deviation:{stats.device_type}",
            features={"device_type": stats.device_type, "my_count": stats.my_count,
                      "peer_avg": round(stats.peer_avg, 1), "peer_count": stats.peer_count,
                      "multiplier": params.peer_deviation_multiplier,
                      "min_absolute_count": params.peer_deviation_min_absolute_count},
        )]
    return []


_GAUSSIAN_INPUT_KEYS = {
    "query_rate": "query_rate", "entropy_avg": "entropy_avg", "unique_domains": "unique_domains",
    "outbound_bytes": "zeek_outbound_bytes",
}
# Stored under versioned keys (extractors/pihole_codes.ratio_metric_key): a change in how the two ratios are measured
# starts fresh trackers instead of the old ones reading it as a changepoint.
_BETA_INPUT_KEYS = {ratio_metric_key("nxdomain_ratio"): "nxdomain_ratio",
                    ratio_metric_key("blocked_ratio"): "blocked_ratio"}

# device_id -> the attack hypothesis score `_v13_engine.evaluate()` computed on the
# device's PREVIOUS cycle -- daemon.py's own documented trade-off, ported unchanged:
# `risk` (the 5th Gaussian baseline metric) depends on THIS cycle's own decision, which
# doesn't exist yet at the point baseline evidence needs to be injected into merged_v2
# (before _v13_engine.evaluate() runs) -- scoring it live would force a circular
# dependency. A one-poll-interval lag is the honest trade-off daemon.py already made
# and ships with; this file makes the identical trade-off, not a different one.
_last_risk_score: Dict[str, float] = {}


# Domain age (MASTER_TODO M2, opt-in): the popularity ledger whose is_young() reads the stored RDAP registration
# dates. Bound by pipeline.py (configure_domain_age); None -> no domain-age evidence, the behaviour before it existed.
_domain_age_source = None


def configure_domain_age(source) -> None:
    global _domain_age_source
    _domain_age_source = source


def _inject_domain_age_evidence(device_id: str, fresh_v2: List, ts: float) -> List[Evidence]:
    """Context evidence `domain_age_young` for each of THIS cycle's domain destinations whose registrable domain was
    registered shortly before this network first used it. Family `registration_age` is non-attack (independence.py),
    so it never counts as a source; decision/engine.py only uses it to lift a score that another detector already
    earned on the same destination. Derived context: added to merged_v2 only, never written to the graph. Reads the
    stored dates only (no lookup). Best-effort: any failure means no such evidence this cycle."""
    source = _domain_age_source
    if source is None:
        return []
    out: List[Evidence] = []
    try:
        for dest in sorted({ev.destination_id for ev in fresh_v2}):
            if not dest or dest == NO_DESTINATION or "." not in dest or _looks_like_ip(dest):
                continue
            if source.is_young(dest):
                out.append(Evidence(
                    device_id=device_id, destination_id=dest, evidence_type="domain_age_young",
                    independence_family="registration_age", timestamp=ts, source="v13_live_engine",
                    confidence=0.5, value=1.0, provenance="v13_live_engine:domain_age",
                    features={"note": "registered shortly before first use on this network"},
                ))
    except Exception as e:
        LOGGER.debug("domain-age evidence skipped for %r this cycle: %s", device_id, e)
    return out


def _inject_baseline_evidence(device_id: str, features: dict, fresh_v2: List, ts: float) -> List[Evidence]:
    """Sheet 00 baseline/BOCPD scoring, now live on `.94` -- see the module comment
    above this function for the full porting rationale. Best-effort, matching every
    other graph-touching injection in this module: any failure degrades to 'no
    baseline evidence this cycle', never blocks the real decision.

    Config-gated (`baseline_scoring_enabled`, default True) -- a plain rollback switch
    for a genuinely new, first-time-live subsystem, matching this codebase's own
    standing precedent for every other newly-cut-over subsystem (engine/
    cl_afpe_engine/reactive_capture_*/health_manager_enabled all ship with one)."""
    if not CONFIG.get("baseline_scoring_enabled", True):
        return []
    try:
        engine = _get_baseline_engine()
        hour = time.localtime(ts).tm_hour
        new_evidence: List[Evidence] = []

        # 2026-09-23 (live incident, py-spy-confirmed): each score_metric()/
        # score_activity_transition() call below persists via _save_tracker(),
        # which -- outside a transaction() block -- commits (fsyncs) on its
        # own. Up to 7+ of these ran per device, every single cycle, each
        # paying its own commit cost on the main detection loop's own thread;
        # one device's stall inside this block's own json.dumps() blew the
        # heartbeat watchdog's deadline. GraphStore.transaction() (already
        # used elsewhere in this module for the same reason -- see its own
        # docstring) batches the whole cycle's worth of trackers for this
        # device into ONE commit instead. As a side benefit this also makes
        # the block atomic with the try/except below: previously a mid-loop
        # failure could leave some trackers committed to disk with no
        # Evidence actually returned (this function degrades to [] on any
        # exception) -- now either everything this cycle commits or nothing
        # does, matching what's actually returned.
        with engine.store.transaction():
            gaussian_inputs = {metric: features.get(feature_key) for metric, feature_key in _GAUSSIAN_INPUT_KEYS.items()}
            gaussian_inputs["risk"] = _last_risk_score.get(device_id)
            for metric, value in gaussian_inputs.items():
                if value is None:
                    continue
                ev = engine.score_metric(device_id, metric, "gaussian", (float(value),), hour, now=ts)
                if ev is not None:
                    new_evidence.append(ev)

            # Beta-Binomial metrics need the real per-cycle trial count, not a fixed
            # trials=1.0 -- skipped outright when this cycle had no DNS activity at all
            # (an empty window carries no real Binomial observation to update on), same
            # gate daemon.py's own _score_baselines() uses.
            trials = float(features.get("total", 0.0) or 0.0)
            if trials > 0:
                for metric, feature_key in _BETA_INPUT_KEYS.items():
                    ratio = features.get(feature_key)
                    if ratio is None:
                        continue
                    successes = float(ratio) * trials
                    ev = engine.score_metric(device_id, metric, "beta", (successes, trials), hour, now=ts)
                    if ev is not None:
                        new_evidence.append(ev)

            # fresh_v2, not merged_v2 -- this cycle's OWN real detector output, matching
            # daemon.py's own evidence_items (this cycle's fresh items only, never the
            # graph-window history merged_v2 also carries).
            dga_count = sum(1 for ev in fresh_v2 if ev.evidence_type == "dns_dga_burst")
            honeypot_count = sum(1 for ev in fresh_v2 if ev.evidence_type == "honeypot_access")
            for metric, count in (("dga_hits", dga_count), ("honeypot_touches", honeypot_count)):
                ev = engine.score_metric(device_id, metric, "poisson", (float(count),), hour, now=ts)
                if ev is not None:
                    new_evidence.append(ev)

            activity_types = [ev.evidence_type for ev in fresh_v2]
            markov_ev = engine.score_activity_transition(device_id, activity_types, now=ts)
            if markov_ev is not None:
                new_evidence.append(markov_ev)

        return new_evidence
    except Exception as e:
        LOGGER.warning(
            "Baseline/BOCPD scoring failed for device %r (non-fatal, deciding without "
            "it this cycle): %s", device_id, e,
        )
        return []


# --- gather / decide / commit (U7, 2026-10-14; DETECTION_CORE_REWORK section I) -------------------------------------
#
# One cycle is three stages. GATHER (impure, exactly once per cycle): converts the detector evidence, reads the graph
# window and the facts behind the derived signals, and runs the stateful learners (BOCPD baselines, Markov activity
# model) -- they observe each cycle once, with the champion parameters. DECIDE (pure): turns the gathered facts plus a
# DecisionParameters value into a decision -- no graph access, no autotuner read, no module state; the same gathered
# cycle decided twice with the same parameters gives the same decision. COMMIT (impure): graph writes and the
# per-device bookkeeping (_last_risk_score, _last_decision_key/_id). A shadow evaluation of an autotune candidate is
# decide() on the real cycle's GatheredCycle with one parameter replaced: it cannot touch the learners, the graph or
# the bookkeeping. Before, the shadow re-ran the whole evaluate() and rolled the graph back, which left the in-memory
# learners having observed the cycle again and the bookkeeping pointing at rolled-back rows.


class _ReputationCandidate(NamedTuple):
    """A cached high-tier reputation for one of this cycle's destinations; becomes `reputation` evidence in decide()
    when `ts - cached_at <= reputation_propagation_ttl_seconds`."""
    destination: str
    tier: float
    cached_at: float


class PeerStats(NamedTuple):
    device_type: str
    my_count: int
    peer_avg: float
    peer_count: int


@dataclass(frozen=True)
class DecisionParameters:
    """Every tunable value decide() reads. Floors None = the reputation vector is used as classified (no device
    scope: the contract for calls without a device_id). `resolved` is True when the values came from the autotuner
    for a device; only then are they recorded on the decision as `_autotune_state`."""
    reputation_tier_suspicious_floor: Optional[float] = None
    reputation_tier_high_floor: Optional[float] = None
    hard_stop_candidate_sensitivity: Optional[float] = None
    familiarity_trust_bar: float = 0.6       # DeviceProfileBenignHypothesis's own default
    reputation_propagation_ttl_seconds: float = float(_REPUTATION_PROPAGATION_TTL_SECONDS)
    peer_deviation_multiplier: float = _PEER_DEVIATION_MULTIPLIER
    peer_deviation_min_absolute_count: float = float(_PEER_DEVIATION_MIN_ABSOLUTE_COUNT)
    resolved: bool = False


# The autotune parameters decide() reads -- the ones a per-cycle shadow can evaluate. Every other tunable acts in a
# stateful learner (bocpd_hazard_rate, pool_*), a detector (arp_sweep_unique_targets_threshold) or the false-positive
# engine (fp_combined_suppress_threshold, combined_uncertain_threshold, trust_cache_ttl_seconds); re-deciding a cycle
# says nothing about them (their old shadow rows were trivially "agree"), so the shadow records nothing for them.
DECIDE_PARAMETERS = frozenset(f.name for f in fields(DecisionParameters) if f.name != "resolved")

# What resolve_decision_parameters() returns for a device with no promoted autotune change (the champion before any
# tuning). The golden guard (argus/golden/guard.py) decides its cases with these values.
CHAMPION_DEFAULTS = DecisionParameters(
    reputation_tier_suspicious_floor=2.0, reputation_tier_high_floor=4.0, hard_stop_candidate_sensitivity=None,
    familiarity_trust_bar=0.6, reputation_propagation_ttl_seconds=float(_REPUTATION_PROPAGATION_TTL_SECONDS),
    peer_deviation_multiplier=_PEER_DEVIATION_MULTIPLIER,
    peer_deviation_min_absolute_count=float(_PEER_DEVIATION_MIN_ABSOLUTE_COUNT), resolved=True,
)


@dataclass(frozen=True)
class GatheredCycle:
    """Everything decide() needs for one device cycle, read once. Immutable: `features` is a read-only copy (the
    pipeline's dict is shared and mutated by later consumers), the evidence collections are tuples."""
    device_id: Optional[str]
    ts: float
    device_type: str
    is_safe: bool
    baseline_familiarity: float
    features: Optional[Mapping[str, Any]]
    rep_vector: Any
    fresh_v2: Tuple[Evidence, ...]
    windowed_v2: Tuple[Evidence, ...] = ()
    graph_derived: Tuple[Any, ...] = ()           # Evidence and _ReputationCandidate, in scoring order
    peer_stats: Optional[PeerStats] = None
    baseline_v2: Tuple[Evidence, ...] = ()
    domain_age_v2: Tuple[Evidence, ...] = ()
    # which evidence sources were available when this cycle was gathered ({source: ok|degraded|unavailable|disabled},
    # core/source_availability.py); recorded on the decision as `_sources`. Empty = not recorded (callers without a registry).
    sources: Mapping[str, str] = MappingProxyType({})


class EvaluatedCycle(NamedTuple):
    """A decided cycle: its gathered facts and the champion parameters the real decision used -- what a shadow
    evaluation re-decides with one parameter replaced."""
    gathered: GatheredCycle
    params: DecisionParameters


def resolve_decision_parameters(device_id: Optional[str]) -> DecisionParameters:
    """The champion parameters for `device_id` (device -> device_type -> global, AutotuneEngine.get_active_value()).
    No device id: the defaults (no autotuner read, rep vector untouched). A failing autotuner read degrades to the
    defaults for this cycle, logged -- never blocks the decision."""
    if not device_id:
        return DecisionParameters()
    try:
        autotune = _get_autotune_engine()
        return DecisionParameters(
            **{name: autotune.get_active_value(name, device_id, default=getattr(CHAMPION_DEFAULTS, name))
               for name in sorted(DECIDE_PARAMETERS)},
            resolved=True,
        )
    except Exception as e:
        LOGGER.warning(
            "Failed to resolve live-tunable autotuner parameters for device %r, "
            "deciding with defaults this cycle: %s", device_id, e,
        )
        return DecisionParameters()


def gather_cycle(active_evidence_v1: List, rep_vector, device_type: str = "", baseline_familiarity: float = 0.0,
                 features: Optional[dict] = None, is_safe: bool = False, device_id: Optional[str] = None,
                 now: Optional[float] = None, geoip_engine=None,
                 sources: Optional[Mapping[str, str]] = None) -> GatheredCycle:
    """GATHER: the impure half of a cycle, run exactly once (see the stage comment above). Each graph read and learner
    degrades to "nothing from it this cycle" on its own; only an unexpected programming error raises."""
    fresh_v2 = _convert_active_evidence(active_evidence_v1, features or {})
    ts = now if now is not None else time.time()
    frozen_features = MappingProxyType(dict(features)) if features is not None else None
    frozen_sources = MappingProxyType(dict(sources or {}))
    if not device_id:
        return GatheredCycle(device_id=None, ts=ts, device_type=device_type, is_safe=is_safe,
                             baseline_familiarity=baseline_familiarity, features=frozen_features,
                             rep_vector=rep_vector, fresh_v2=tuple(fresh_v2), sources=frozen_sources)
    windowed_v2 = _query_graph_window(device_id, ts)
    # Phase 1a: cross-device correlation / reputation propagation / first contact -- from THIS cycle's destinations
    # only; scoring context, never written to the graph (see _gather_graph_derived()).
    fresh_destinations = {ev.destination_id for ev in fresh_v2}
    graph_derived = _gather_graph_derived(device_id, fresh_destinations, ts, fresh_v2, geoip_engine=geoip_engine)
    # Release 14, N2: peer-cohort deviation (see _gather_peer_stats()).
    peer_stats = _gather_peer_stats(device_id, device_type, ts)
    # Release 15 Sheet 00: Bayesian Gaussian/Beta/Poisson/Markov + BOCPD -- the stateful learners observe this cycle
    # here, once (see _inject_baseline_evidence()).
    baseline_v2 = _inject_baseline_evidence(device_id, features or {}, fresh_v2, ts)
    # Domain age (opt-in): supporting context only -- see _inject_domain_age_evidence().
    domain_age_v2 = _inject_domain_age_evidence(device_id, fresh_v2, ts)
    return GatheredCycle(device_id=device_id, ts=ts, device_type=device_type, is_safe=is_safe,
                         baseline_familiarity=baseline_familiarity, features=frozen_features, rep_vector=rep_vector,
                         fresh_v2=tuple(fresh_v2), windowed_v2=tuple(windowed_v2),
                         graph_derived=tuple(graph_derived), peer_stats=peer_stats,
                         baseline_v2=tuple(baseline_v2), domain_age_v2=tuple(domain_age_v2), sources=frozen_sources)


def _autotune_state(gathered: GatheredCycle, params: DecisionParameters) -> Dict[str, Any]:
    """Autonomous-behaviour traceability (Documentation/ALERT_TRACE_GRAPH_PLAN.md, 2026-09-22): the tunable values this
    decision used, persisted onto the matching alert_event's autotune_state_json by pipeline.py. Values only (not
    which threshold_history.change_id produced each). Includes the raw inputs judged against the bars (familiarity
    score, reputation scores) so a retroactive calibration can tell whether another value would have changed it."""
    if not params.resolved:
        return {}
    state: Dict[str, Any] = {
        "hard_stop_candidate_sensitivity": params.hard_stop_candidate_sensitivity,
        "reputation_tier_suspicious_floor": params.reputation_tier_suspicious_floor,
        "reputation_tier_high_floor": params.reputation_tier_high_floor,
        "familiarity_trust_bar": params.familiarity_trust_bar,
        "baseline_familiarity": gathered.baseline_familiarity,
    }
    rep_vector = gathered.rep_vector
    if rep_vector is not None:
        state["reputation_vt_score"] = rep_vector.vt_detection_ratio
        state["reputation_ti_score"] = rep_vector.ti_risk
        state["reputation_abuse_score"] = rep_vector.abuse_risk
    return state


def decide(gathered: GatheredCycle, params: DecisionParameters) -> Tuple[Dict[str, Any], List[Evidence]]:
    """DECIDE: pure -- the decision for `gathered` under `params`, and the merged evidence it was made on. No graph
    access, no autotuner read, no module state written; `gathered` is not modified (the decision engine gets its own
    copy of the features)."""
    ts = gathered.ts
    fresh_v2 = list(gathered.fresh_v2)
    merged_v2: List[Evidence] = fresh_v2
    if gathered.device_id:
        # Dedup by CONTENT, not evidence_id -- convert() assigns a fresh, random evidence_id on every call, so the
        # same observation converted fresh this cycle and read back from the graph would never match on id alone.
        fresh_keys = {_content_key(ev) for ev in fresh_v2}
        merged_v2 = [ev for ev in gathered.windowed_v2 if _content_key(ev) not in fresh_keys] + fresh_v2
        for item in gathered.graph_derived:
            if isinstance(item, _ReputationCandidate):
                if ts - item.cached_at <= params.reputation_propagation_ttl_seconds:
                    merged_v2.append(Evidence(
                        device_id=gathered.device_id, destination_id=item.destination, evidence_type="reputation",
                        independence_family="reputation", timestamp=ts,
                        source="v13_live_engine", confidence=1.0, value=item.tier,
                        provenance="v13_live_engine:reputation_propagation",
                    ))
            else:
                merged_v2.append(item)
        merged_v2 += _peer_deviation_evidence(gathered.device_id, gathered.peer_stats, params, ts)
        merged_v2 += list(gathered.baseline_v2)
        merged_v2 += list(gathered.domain_age_v2)
    decision = _v13_engine.evaluate(
        merged_v2, _tuned_rep_vector(gathered.rep_vector, params), device_type=gathered.device_type,
        baseline_familiarity=gathered.baseline_familiarity,
        features=dict(gathered.features) if gathered.features is not None else None, is_safe=gathered.is_safe,
        now=ts, hard_stop_candidate_sensitivity=params.hard_stop_candidate_sensitivity,
        familiarity_trust_bar=params.familiarity_trust_bar,
    )
    decision["_autotune_state"] = _autotune_state(gathered, params)
    decision["_sources"] = dict(gathered.sources)     # what was available when this was decided
    return decision, merged_v2


def commit_cycle(gathered: GatheredCycle, decision: Dict[str, Any], merged_v2: List[Evidence]) -> None:
    """COMMIT: the real decision's writes -- graph rows and per-device bookkeeping. Only ever for the champion."""
    device_id = gathered.device_id
    if not device_id:
        return
    # Feeds the NEXT cycle's `risk` baseline metric (one-cycle-lagged, see _inject_baseline_evidence()).
    _last_risk_score[device_id] = float(
        decision.get("hypotheses", {}).get("attack", {}).get("score", 0.0) or 0.0)
    _write_graph(device_id, gathered.ts, list(gathered.fresh_v2), merged_v2, decision)
    # alert/decision unification (Phase 2): the most recently written decision_id for this device, whether or not
    # THIS cycle wrote a new row -- the target pipeline.py enriches with alert_payload/fp_verdict/outcome fields.
    decision["_graph_decision_id"] = _last_decision_id.get(device_id)
    _maybe_checkpoint_wal(gathered.ts)


def evaluate_cycle(active_evidence_v1: List, rep_vector, device_type: str = "",
                   baseline_familiarity: float = 0.0, features: Optional[dict] = None,
                   is_safe: bool = False, device_id: Optional[str] = None, now: Optional[float] = None,
                   geoip_engine=None, sources: Optional[Mapping[str, str]] = None
                   ) -> Tuple[Dict[str, Any], Optional[EvaluatedCycle]]:
    """evaluate() plus the EvaluatedCycle it decided (None when the cycle could not be evaluated) -- what
    maybe_shadow_evaluate() needs to evaluate a canary on exactly this cycle and these champion parameters."""
    try:
        gathered = gather_cycle(active_evidence_v1, rep_vector, device_type=device_type,
                                baseline_familiarity=baseline_familiarity, features=features, is_safe=is_safe,
                                device_id=device_id, now=now, geoip_engine=geoip_engine, sources=sources)
        params = resolve_decision_parameters(gathered.device_id)
        decision, merged_v2 = decide(gathered, params)
        commit_cycle(gathered, decision, merged_v2)
        return decision, EvaluatedCycle(gathered, params)
    except Exception as e:
        LOGGER.error(
            "Decision engine raised %s -- this cycle is not evaluated (no action); the evidence stays for the "
            "next cycle. This should never happen in normal operation; investigate.", e, exc_info=True,
        )
        _note_engine_error("decision", e)
        return not_evaluated_decision(str(e)), None


def redecide_with_evidence(cycle: Optional[EvaluatedCycle], new_evidence_v1: List) -> Optional[Dict[str, Any]]:
    """The decision for an already-decided cycle plus evidence that arrived after it (pipeline.py's GeoIP step adds a
    geofencing hard-stop item). Same context as the main decision -- the cycle's gathered facts (graph history, derived
    signals, baselines, features, familiarity) and champion parameters -- through the pure decide(): nothing is gathered
    again, nothing is written. The caller persists the result with write_supplementary_decision() (which also writes
    the new evidence). None when the cycle was not evaluated (no EvaluatedCycle): that cycle stays "not evaluated, no
    action" -- a decision under another path would use different rules (module docstring)."""
    if cycle is None:
        return None
    extra = tuple(_convert_active_evidence(new_evidence_v1, dict(cycle.gathered.features or {})))
    gathered = dataclasses.replace(cycle.gathered, fresh_v2=cycle.gathered.fresh_v2 + extra)
    try:
        decision, _merged = decide(gathered, cycle.params)
        return decision
    except Exception as e:
        LOGGER.error(
            "Re-decision with new evidence raised %s -- keeping the cycle's earlier decision; investigate.", e,
            exc_info=True,
        )
        _note_engine_error("decision", e)
        return None


def evaluate(active_evidence_v1: List, rep_vector, device_type: str = "",
             baseline_familiarity: float = 0.0, features: Optional[dict] = None,
             is_safe: bool = False,
             device_id: Optional[str] = None, now: Optional[float] = None,
             geoip_engine=None) -> Dict[str, Any]:
    """The live call site `pipeline.py` uses in place of
    `argus/decision/engine.py`'s `DecisionEngine.evaluate()`. Same positional/keyword
    shape as the earlier engine's own `evaluate()` (plus the new, optional `device_id`/`now`)
    so the original call site swap in pipeline.py stayed a one-line change; passing
    `device_id` is what opts a call into the graph read/write behavior described in
    this module's own docstring above -- omitting it (the default) is unaffected by
    any of that, identical to this function's pre-Phase-1 behavior.

    `geoip_engine` (optional, live audit 2026-09-08): pipeline.py's own already-
    constructed `GeoIPEngine` instance, reused as-is rather than this module
    opening a second mmdb reader -- see `_gather_graph_derived()`'s own
    docstring for what it gates. Omitting it degrades to today's behavior
    unchanged, same graceful-degradation contract as every other optional
    dependency in this module."""
    return evaluate_cycle(active_evidence_v1, rep_vector, device_type=device_type,
                          baseline_familiarity=baseline_familiarity, features=features, is_safe=is_safe,
                          device_id=device_id, now=now, geoip_engine=geoip_engine)[0]


# --- engine errors (read by the health manager) --------------------------------------------------------------------

_engine_errors: Dict[str, Dict[str, Any]] = {}


def _note_engine_error(engine: str, exc: Exception) -> None:
    entry = _engine_errors.setdefault(engine, {"count": 0})
    entry["count"] += 1
    entry["last_error_at"] = time.time()
    entry["last_error"] = f"{type(exc).__name__}: {exc}"[:300]


def engine_error_status() -> Dict[str, Dict[str, Any]]:
    """{"decision"|"cl_afpe": {"count", "last_error_at", "last_error"}} since this process started."""
    return {k: dict(v) for k, v in _engine_errors.items()}


def not_evaluated_decision(reason: str) -> Dict[str, Any]:
    """The result of a cycle the decision engine could not evaluate: no alert, no action."""
    return {
        "state": "BENIGN", "action": "none", "threat_confidence": 0.0,
        "explanation": "Not evaluated (decision engine error)", "decision_path": "engine_error",
        "independent_sources": 0, "evidence_families": [], "evidence_types": [], "winning_evidence": [],
        "attack_evidence": [], "hypotheses": {}, "hypothesis_destination_ids": [], "hypothesis_weight": 0.0,
        "evidence_verification_required": False,
        "reasoning_trail": [f"Decision engine error: {reason}"], "_engine_error": True,
    }


# ==============================================================================
# CL-AFPE (the false-positive engine) wiring
#
# The engine's verdict is computed at a later point in pipeline.py's per-cycle flow than the decision above, so it
# has its own entry point here, evaluate_cl_afpe_live(), with the same no-fallback error handling as evaluate().
#
# Shared threat memory: the local confirmed-intel store (intelligence/local_intel.py) is ONE store,
# state/local_confirmed_intel.json, used by this engine's Stage-1 check, by pipeline.py's HIGH/CRITICAL feed, by the
# retro-hunt and by the maintenance tools. pipeline.py injects its instance through configure_cl_afpe(local_intel=),
# so a destination confirmed for one device is checked for every other device. A store left over from the period
# when this engine ran in shadow (state/v13_cl_afpe/) is merged into it once, then renamed.
#
# ML models: MLScorer reads the trained fp_classifier.onnx / fastembed_cache under the model dir read-only;
# train_fp_classifier.py remains their only producer.
# ==============================================================================

LOGGER_CL_AFPE = logging.getLogger("home_ids.cl_afpe")

# Matches config.yaml's `model_path: models/ids_model.pkl` -> parent dir `models/`, where fp_classifier.onnx and
# fastembed_cache/ live. Relative to the process's CWD, like every other ops file's state dir.
_CL_AFPE_MODEL_DIR = "models"

# Directory of the shared state/local_confirmed_intel.json (used when no instance is injected, e.g. in tests).
_CL_AFPE_LOCAL_INTEL_DIR = "state"
_RETIRED_LOCAL_INTEL_SUBDIR = "v13_cl_afpe"

_cl_afpe_engine: Optional[ClAfpeEngine] = None
_shared_local_intel: Optional[LocalConfirmedIntel] = None
_shared_familiarity: Optional[DeviceFamiliarity] = None


class _ConfiguredSafeIps:
    """config.yaml's safe_ips (router, NAS, this host, ...), read live: never recorded as confirmed threats."""
    def __contains__(self, ip) -> bool:
        return ip in set(CONFIG.get("safe_ips", []) or [])


def configure_cl_afpe(model_dir: Optional[str] = None, local_intel_dir: Optional[str] = None,
                      local_intel: Optional[LocalConfirmedIntel] = None,
                      familiarity: Optional[DeviceFamiliarity] = None) -> None:
    """Call once at startup. `local_intel` / `familiarity` share the caller's instances (one store, one in-memory
    copy per process); `local_intel_dir` points a fresh confirmed-intel store at another directory. Forces re-init
    of the lazy singleton."""
    global _CL_AFPE_MODEL_DIR, _CL_AFPE_LOCAL_INTEL_DIR, _cl_afpe_engine, _shared_local_intel, _shared_familiarity
    if model_dir is not None:
        _CL_AFPE_MODEL_DIR = model_dir
    if local_intel_dir is not None:
        _CL_AFPE_LOCAL_INTEL_DIR = local_intel_dir
    if local_intel is not None:
        _shared_local_intel = local_intel
    if familiarity is not None:
        _shared_familiarity = familiarity
    _cl_afpe_engine = None


def merge_retired_local_intel(local_intel: LocalConfirmedIntel, state_dir) -> int:
    """Folds the store this engine kept while it ran in shadow (state/v13_cl_afpe/local_confirmed_intel.json)
    into the shared one, once, then renames the old file so it is not merged again."""
    old = Path(state_dir) / _RETIRED_LOCAL_INTEL_SUBDIR / "local_confirmed_intel.json"
    if not old.exists():
        return 0
    merged = local_intel.merge_from(old)
    try:
        old.rename(old.with_name(old.name + ".merged"))
    except OSError as e:
        LOGGER_CL_AFPE.warning("Could not rename merged confirmed-intel store %s: %s", old, e)
    LOGGER_CL_AFPE.info("Merged %d confirmed indicator(s) from %s into the shared store", merged, old)
    return merged


def get_cl_afpe_engine() -> ClAfpeEngine:
    """The process's false-positive engine (lazy singleton on the configured graph store)."""
    global _cl_afpe_engine
    if _cl_afpe_engine is None:
        store = _get_graph_store()
        local_intel = _shared_local_intel or LocalConfirmedIntel(_CL_AFPE_LOCAL_INTEL_DIR)
        ml_scorer = MLScorer(_CL_AFPE_MODEL_DIR)
        _cl_afpe_engine = ClAfpeEngine(
            store, local_intel=local_intel, ml_scorer=ml_scorer, familiarity=_shared_familiarity,
            safe_ips=_ConfiguredSafeIps(),
            lateral_targets_threshold=lambda: int(CONFIG.get("lateral_movement_unique_targets_threshold", 2)),
            config_get=CONFIG.get)
    return _cl_afpe_engine


_get_cl_afpe_engine = get_cl_afpe_engine   # older name, kept for callers and tests


def get_device_sigma_shift(device_id: str) -> float:
    """The device's cumulative sensitivity shift, as the false-positive engine maintains it (graph metadata)."""
    try:
        return get_cl_afpe_engine().get_sigma_shift(device_id)
    except Exception as e:
        LOGGER_CL_AFPE.warning("sigma shift lookup failed for %s: %s", device_id, e)
        return 0.0


def get_device_profile_threshold(device_id: str, key: str, default: float) -> Optional[float]:
    """A per-device threshold the false-positive engine raised after corrections (graph metadata `fp_profile`), or
    None when it has none for this device -- the caller then falls back to older stores / its own default."""
    try:
        engine = get_cl_afpe_engine()
        sentinel = object()
        value = engine._get_device_profile_value(device_id, key, sentinel)
        return None if value is sentinel else float(value)
    except Exception as e:
        LOGGER_CL_AFPE.warning("profile threshold lookup failed for %s/%s: %s", device_id, key, e)
        return None


def evaluate_cl_afpe_live(alert_payload: dict, features: dict, decision: Optional[dict] = None,
                          asn_owner: str = "", now: Optional[float] = None) -> Dict[str, Any]:
    """The false-positive engine's verdict for one alert -- the value pipeline.py acts on (suppress/publish,
    ML-registry learn/reject, alerts.json's fp_verdict). If the engine raises, the alert is published normally as
    UNCERTAIN (never suppressed) and the failure is reported to the health manager."""
    ts = now if now is not None else time.time()
    try:
        return get_cl_afpe_engine().evaluate(alert_payload, features, decision=decision, asn_owner=asn_owner, now=ts)
    except Exception as e:
        LOGGER_CL_AFPE.error("CL-AFPE evaluation raised %s -- alert published unsuppressed (UNCERTAIN). "
                             "This should never happen in normal operation; investigate.", e, exc_info=True)
        _note_engine_error("cl_afpe", e)
        return {"verdict": "UNCERTAIN", "confidence": 0.5, "calibrated_confidence": None, "stage": "ENGINE_ERROR",
                "reasons": [f"False-positive engine error: {e}"], "suppress": False}


_shadow_evaluator = None


def _get_shadow_evaluator():
    """Lazy singleton, same shape as _get_cl_afpe_engine() above -- one
    ShadowEvaluator per process, sharing this module's own GraphStore
    singleton so canary reads/shadow_decisions writes land in the same db
    file every other call site in this module already uses."""
    global _shadow_evaluator
    if _shadow_evaluator is None:
        from argus.shadow.sandbox import ShadowEvaluator
        _shadow_evaluator = ShadowEvaluator(_get_graph_store())
    return _shadow_evaluator


def maybe_shadow_evaluate(cycle: Optional[EvaluatedCycle], real_state: str, now: Optional[float] = None) -> None:
    """The pipeline.py call site for Phase 7 (16-parameter autonomy plan): called right after evaluate_cycle() with
    the EvaluatedCycle that real decision was made on and its state. Fire-and-forget, compute-only: the shadow is
    decide() on that same cycle with one candidate parameter -- no learner, graph or bookkeeping is touched (U7).
    Returns nothing, never raises. A no-op when the cycle was not evaluated, no canary applies, or resource pressure
    is high."""
    if cycle is None:
        return
    ts = now if now is not None else cycle.gathered.ts
    try:
        _get_shadow_evaluator().maybe_shadow_evaluate(cycle, real_state=real_state, now=ts)
    except Exception as e:
        LOGGER.error(
            "Shadow-evaluation sandbox failed (compute-only -- the real decision this "
            "cycle is already decided and unaffected by this): %s", e, exc_info=True,
        )
