"""
live_engine.py - the actual swap-in adapter `pipeline.py` calls instead of
`core/decision_engine.py`'s `DecisionEngine.evaluate()`, per the v13 fast-cutover plan
(Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md, the entry recording this cutover).

Converts v-current's real per-cycle Evidence/features into v13 Evidence v2 (mirroring
`src/v13/ingest/sources.py`'s own `fallback_context` split exactly, since pipeline.py's
real detectors have the same `zeek_exfiltration`/`zeek_beaconing` destination gap
`sources.py` already works around -- see that file's own A2 comment) and calls v13's
own `DecisionEngine.evaluate()`, now the LIVE decision path, not a shadow comparison.

Dependency direction stays one-way (core -> v13, never v13 -> core): this module never
imports `core.decision_engine` itself. The caller (`pipeline.py`) passes its own
v-current `evaluate` as `fallback_evaluate`, used ONLY if v13's engine raises. This is
the one piece of the old per-mechanism-flip caution machinery kept from the superseded
plan -- a fail-safe costs nothing and this project always keeps an escape hatch. Any
fallback firing is logged loudly (never silent) since it should never happen in normal
operation and would mean something needs investigating.

GRAPH WRITE + WINDOWED READ (v13 full-architecture plan, Phase 1): when `device_id` is
supplied, every call also (a) queries `RollingWindowView.evidence_in_window()` for that
device's persisted history and merges it with this cycle's fresh evidence before
deciding, and (b) writes this cycle's fresh evidence + the resulting decision into the
same GraphStore. Both are best-effort -- a graph failure never affects the returned
decision, only means this cycle is missing from the durable trail (logged loudly, not
silent). `device_id=None` (the default) skips both entirely, unchanged from before this
existed -- so existing callers that don't pass it keep working exactly as they do today.
The decision row is deduped by (state, decision_path) per device (`_last_decision_key`,
mirroring `src/v13/ingest/daemon.py`'s own `only_persist_if_changed_from` pattern) -- a
real fix found live on `.94`'s first restart with this wiring: without it, every device
writes a new decisions-table row every ~2s poll cycle regardless of whether the verdict
actually changed (611 rows observed in well under a minute of real runtime before this
was added). Evidence itself is never deduped this way -- every fresh item is a real
observation worth recording.

WHY QUERY UP TO THE LONGEST TTL, NOT A SHORTER "ROLLING WINDOW": confirmed by reading
`src/v13/hypotheses/engine.py`'s own `compute_freshness()` -- it already discards
anything older than 600s (default) / 86400s (reputation family) per item, matching
v-current's `EvidenceStore` TTLs exactly. Querying a shorter window than that would only
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
from typing import Any, Dict, List, Optional, Tuple

from v13.evidence.ingest import convert_list
from v13.evidence.model import Evidence, NO_DESTINATION
from v13.hypotheses.independence import INDEPENDENCE_FAMILY_MAP
from v13.decision.engine import DecisionEngine as V13DecisionEngine
from v13.graph.store import GraphStore, DEFAULT_EVIDENCE_RETENTION_DAYS
from v13.graph.window import RollingWindowView
from v13.cl_afpe.engine import ClAfpeEngine
from v13.cl_afpe.ml_scoring import MLScorer
from intelligence.local_intel import LocalConfirmedIntel

LOGGER = logging.getLogger("home_ids.v13_live_engine")

# Mirrors src/v13/ingest/sources.py's _NEEDS_LAST_DEST_IP_FALLBACK / _NO_DEST_SENTINEL
# exactly -- these two v-current detectors (threat_signals.py:247-274) never set
# Evidence.domain themselves; everyone else either sets it directly or has no domain
# concept at all, so a fallback would be misleading, not helpful.
_NEEDS_LAST_DEST_IP_FALLBACK = frozenset({"zeek_exfiltration", "zeek_beaconing"})
_NO_DEST_SENTINEL = "unknown"  # ZeekFeatureExtractor._last_connection_meta's own "no data yet" sentinel

# The longest TTL hypotheses/engine.py's own compute_freshness() honors (the
# "reputation" independence_family, 86400s) -- see the module docstring above for why
# querying up to this bound, not a shorter one, is the correct design.
_GRAPH_QUERY_WINDOW_SECONDS = 86400

_v13_engine = V13DecisionEngine()

_GRAPH_DB_PATH = "state/v13_graph.db"
_graph_store: Optional[GraphStore] = None

# Mirrors src/v13/ingest/daemon.py's own _last_decision_key dict + compute_decision()'s
# only_persist_if_changed_from param exactly (see that docstring) -- without this, every
# device gets a NEW decisions-table row every single ~2s poll cycle regardless of
# whether the verdict actually changed (confirmed live: 611 decision rows after well
# under a minute of real runtime on .94's first restart with this wiring). Evidence
# itself is NOT deduped this way -- every fresh item is a real observation worth
# recording; it's specifically the DERIVED verdict that shouldn't be re-written when
# nothing about it changed.
_last_decision_key: Dict[str, Tuple[str, str]] = {}

# v13 full-architecture plan, alert/decision unification (Phase 2): the most
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

# v13 full-architecture plan, Phase 1a -- the new graph-only-possible capabilities'
# tuning constants. Each mirrors a value already established elsewhere in this codebase
# rather than inventing a new number: the coordinated-targeting window matches
# RollingWindowView's own SHORT_WINDOW_SECONDS ("within a short window," the plan's own
# phrasing); the reputation-propagation TTL matches hypotheses/engine.py's own
# _REPUTATION_TTL_SECONDS (the same 86400s bound compute_freshness() already applies to
# every other "reputation" family item, so a propagated verdict ages out on the same
# schedule a directly-observed one would); the first-contact lookback matches
# GraphStore's own DEFAULT_EVIDENCE_RETENTION_DAYS ("seen before" can only mean "within
# what the graph actually still retains" -- claiming first-contact status against data
# that's already been pruned would be a false signal, not a stronger one).
_COORDINATED_TARGETING_WINDOW_SECONDS = RollingWindowView.SHORT_WINDOW_SECONDS
_COORDINATED_TARGETING_MIN_OTHER_DEVICES = 1  # "2+ distinct devices" total = 1+ OTHER device

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
# EvidenceStore.get_for_device() returns the SAME still-fresh v1 item on EVERY cycle
# for up to its full TTL (600s default, 86400s reputation -- ~300 cycles at the 2s poll
# interval for a behavioral item alone), and evidence/ingest.py's convert() assigns a
# FRESH, non-deterministic evidence_id on every call with no content-based dedup. Naive
# per-cycle insertion of "this cycle's fresh_v2" therefore re-writes the SAME real
# observation as a brand-new graph row every single cycle it remains in EvidenceStore --
# confirmed live: 12,766 evidence rows / 28.7MB after 9 minutes of real runtime, ~2
# orders of magnitude more than the real observation rate. v1 Evidence has no id field
# of its own, so (device, type, source, timestamp) is used as a stable content key --
# EvidenceStore never mutates an item's timestamp after creation, so the SAME real
# observation produces the SAME key every cycle it's returned. Pruned against each
# cycle's own active-evidence key set, so memory never grows past what EvidenceStore
# itself is currently holding for that device -- when EvidenceStore lets an item expire,
# this forgets it too.
_written_evidence_keys: Dict[str, set] = {}


def _content_key(ev) -> tuple:
    """Same stable identity for both v1 Evidence (.type/.device) and v2 Evidence
    (.evidence_type/.device_id) -- needed to recognize a v2 item (already converted)
    against the SAME real observation converted again in a later cycle."""
    device = getattr(ev, "device_id", None) or getattr(ev, "device", None)
    etype = getattr(ev, "evidence_type", None) or getattr(ev, "type", None)
    return (device, etype, ev.source, ev.timestamp)


_GRAPH_HARDWARE_PROFILE: Optional[str] = None


def configure(graph_db_path: str, hardware_profile: Optional[str] = None) -> None:
    """Optional: call once at startup to point the live graph store somewhere other
    than the default 'state/v13_graph.db' (relative to the process's CWD, matching
    every other v13 ops file's own state_dir convention). Safe to call before any
    real evaluate() call; if never called, the default path is opened lazily on
    first use with a device_id.

    hardware_profile (v13 full-architecture plan, Phase 10b, optional): passed
    straight through to GraphStore's own PRAGMA cache_size tuning -- this is the
    ONE long-lived GraphStore singleton actually serving the live per-cycle path,
    so it's the one place hardware-driven query-performance tuning actually
    matters (every other v13 ops job's own GraphStore is a short-lived,
    once-per-run construction where cache_size has far less to work with).
    Omitting it (the default) leaves SQLite's own default cache_size untouched,
    identical to this function's behavior before this param existed."""
    global _GRAPH_DB_PATH, _GRAPH_HARDWARE_PROFILE, _graph_store
    _GRAPH_DB_PATH = graph_db_path
    _GRAPH_HARDWARE_PROFILE = hardware_profile
    _graph_store = None  # force re-init against the new path/profile on next use


def _get_graph_store() -> GraphStore:
    global _graph_store
    if _graph_store is None:
        _graph_store = GraphStore(_GRAPH_DB_PATH, hardware_profile=_GRAPH_HARDWARE_PROFILE)
    return _graph_store


def get_graph_store() -> GraphStore:
    """Public accessor for the SAME lazily-initialized GraphStore singleton this
    module's own evaluate() uses -- v13 full-architecture plan, Phase 3:
    LiveIdentityManager needs the same graph (one file, one source of truth per
    process) for its own anchor-MAC persistence, rather than opening a second,
    independent connection to the same db file."""
    return _get_graph_store()


def _build_fallback_context(features: dict) -> Optional[Dict[str, str]]:
    dest_ip = str((features or {}).get("last_dest_ip", "") or "")
    if not dest_ip or dest_ip == _NO_DEST_SENTINEL:
        return None
    return {"dest_ip": dest_ip}


def _convert_active_evidence(v1_evidence_list, features: dict):
    """Same split as run_detection_cycle(): only the two known-gap types get a
    fallback_context, so a zeek_notice/malicious_ja3/etc. item never gets a misleading
    destination attached just because it happened to share a batch with one that does."""
    needs_fallback = [ev for ev in v1_evidence_list if ev.type in _NEEDS_LAST_DEST_IP_FALLBACK]
    no_fallback_needed = [ev for ev in v1_evidence_list if ev.type not in _NEEDS_LAST_DEST_IP_FALLBACK]

    out = []
    if no_fallback_needed:
        out.extend(convert_list(no_fallback_needed, INDEPENDENCE_FAMILY_MAP))
    if needs_fallback:
        fallback_context = _build_fallback_context(features)
        out.extend(convert_list(needs_fallback, INDEPENDENCE_FAMILY_MAP, fallback_context=fallback_context))
    return out


def _query_graph_window(device_id: str, now: float) -> List:
    """Best-effort: returns [] on any failure rather than raising, so a graph
    problem degrades to "decide on this cycle's fresh evidence only" (exactly
    today's pre-Phase-1 behavior), never blocks a real decision."""
    try:
        store = _get_graph_store()
        window = RollingWindowView(store)
        return window.evidence_in_window(device_id, _GRAPH_QUERY_WINDOW_SECONDS, now=now)
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
    _last_decision_key, matching src/v13/ingest/daemon.py's own
    only_persist_if_changed_from pattern. Skips the graph entirely (no transaction
    opened at all) when there's neither new evidence nor a changed decision."""
    written = _written_evidence_keys.setdefault(device_id, set())
    current_fresh_keys = {_content_key(ev) for ev in fresh_v2}
    written &= current_fresh_keys  # forget anything EvidenceStore itself has let expire
    new_v2 = [ev for ev in fresh_v2 if _content_key(ev) not in written]

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
                new_decision_id = store.insert_decision(
                    device_id=device_id, timestamp=timestamp,
                    state=decision["state"], decision_path=decision["decision_path"],
                    confidence=float(decision.get("threat_confidence", 0.0) or 0.0),
                    risk_score=float(decision.get("hypotheses", {}).get("attack", {}).get("score", 0.0) or 0.0),
                    raw_payload=decision,
                    # Phase 1a: merged_v2 also carries synthetic, graph-DERIVED evidence
                    # (_inject_graph_derived_evidence()) that is deliberately never passed
                    # to insert_evidence() above -- an evidence->decision 'supports' edge
                    # for an evidence_id that was never actually persisted would be a
                    # dangling reference. All three synthetic evidence types share the
                    # "v13_live_engine:" provenance prefix, so filtering on that (rather
                    # than threading a separate is-synthetic flag through several layers)
                    # is enough to exclude them here.
                    evidence_ids=[
                        ev.evidence_id for ev in merged_v2
                        if not ev.provenance.startswith("v13_live_engine:")
                    ],
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


def _inject_graph_derived_evidence(device_id: str, destinations: set, ts: float,
                                      fresh_evidence: Optional[List[Evidence]] = None) -> List[Evidence]:
    """v13 full-architecture plan, Phase 1a: computes the three new graph-only-possible
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
    decision."""
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
            if len(others) >= _COORDINATED_TARGETING_MIN_OTHER_DEVICES:
                synthetic.append(Evidence(
                    device_id=device_id, destination_id=dest, evidence_type="coordinated_targeting",
                    independence_family="cross_device_correlation", timestamp=ts,
                    source="v13_live_engine", confidence=1.0, value=float(len(others) + 1),
                    provenance="v13_live_engine:coordinated_targeting",
                    features={"other_devices": others},
                ))

            rep = store.get_destination_reputation(dest)
            if (rep and rep["tier"] >= _REPUTATION_PROPAGATION_MIN_TIER
                    and (ts - rep["cached_at"]) <= _REPUTATION_PROPAGATION_TTL_SECONDS):
                synthetic.append(Evidence(
                    device_id=device_id, destination_id=dest, evidence_type="reputation",
                    independence_family="reputation", timestamp=ts,
                    source="v13_live_engine", confidence=1.0, value=float(rep["tier"]),
                    provenance="v13_live_engine:reputation_propagation",
                ))

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
            all_dga_evidence = store.get_evidence_by_type_since(
                _DGA_EVIDENCE_TYPE, since=ts - _COORDINATED_TARGETING_WINDOW_SECONDS,
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
_PEER_DEVIATION_MIN_PEERS = 2  # need at least 2 OTHER same-type devices for a statistically meaningful average
_PEER_DEVIATION_MULTIPLIER = 3.0  # this device's own count must be >= 3x its cohort's average
_PEER_DEVIATION_MIN_ABSOLUTE_COUNT = 5  # avoid flagging trivial small-number swings (e.g. 1 -> 4 is "4x" but meaningless)


def _inject_peer_deviation_evidence(device_id: str, device_type: str, ts: float) -> List[Evidence]:
    """Release 14, net-new capability N2: "does this device deviate from
    similar devices" -- groups devices by device_type (already computed by
    v-current's own identity/pipeline code, passed straight through here) and
    compares THIS device's own distinct-destination count (the last 7 days)
    against its cohort's average. Persists device_type onto this device's own
    graph metadata as a side effect (best-effort, mirrors how trust-anchor MAC
    learning already persists onto device_metadata) so get_devices_with_
    metadata_value() has something to group on -- the cohort naturally gets
    more complete as more devices are evaluated over time, no separate backfill
    job needed.

    HONEST STATUS, not hidden: this is a genuinely NEW anomaly heuristic, unlike
    coordinated_targeting/fingerprint_campaign/dga_seed_campaign (all reuse
    well-established, low-false-positive correlation concepts) -- real cohort
    variance (two very different real-world usage patterns sharing one
    device_type) could produce a real false positive with no live tuning data
    yet. PeerDeviationHypothesis (hypotheses/engine.py) is deliberately capped
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
    if not device_type or device_type == "unknown":
        return []
    try:
        store = _get_graph_store()
        store.update_device_metadata(device_id, {"device_type": device_type}, timestamp=ts)
        peers = [d for d in store.get_devices_with_metadata_value("device_type", device_type) if d != device_id]
        if len(peers) < _PEER_DEVIATION_MIN_PEERS:
            return []
        since = ts - _PEER_DEVIATION_WINDOW_SECONDS
        my_count = store.get_distinct_destination_count(device_id, since)
        if my_count < _PEER_DEVIATION_MIN_ABSOLUTE_COUNT:
            return []
        peer_counts = [store.get_distinct_destination_count(p, since) for p in peers]
        peer_avg = sum(peer_counts) / len(peer_counts)
        if peer_avg > 0 and my_count >= peer_avg * _PEER_DEVIATION_MULTIPLIER:
            return [Evidence(
                device_id=device_id, destination_id=NO_DESTINATION, evidence_type="peer_deviation",
                independence_family="peer_cohort_deviation", timestamp=ts,
                source="v13_live_engine", confidence=0.6, value=float(my_count),
                provenance=f"v13_live_engine:peer_deviation:{device_type}",
                features={"device_type": device_type, "my_count": my_count,
                          "peer_avg": round(peer_avg, 1), "peer_count": len(peers)},
            )]
    except Exception as e:
        LOGGER.warning(
            "Failed to compute peer-cohort deviation for device %r (type=%r), deciding "
            "without it this cycle: %s", device_id, device_type, e,
        )
    return []


def evaluate(active_evidence_v1: List, rep_vector, device_type: str = "",
             baseline_familiarity: float = 0.0, features: Optional[dict] = None,
             is_safe: bool = False, fallback_evaluate=None,
             device_id: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """The live call site `pipeline.py` uses in place of
    `core/decision_engine.py`'s `DecisionEngine.evaluate()`. Same positional/keyword
    shape as v-current's own `evaluate()` (plus the new, optional `device_id`/`now`)
    so the original call site swap in pipeline.py stayed a one-line change; passing
    `device_id` is what opts a call into the graph read/write behavior described in
    this module's own docstring above -- omitting it (the default) is unaffected by
    any of that, identical to this function's pre-Phase-1 behavior."""
    try:
        fresh_v2 = _convert_active_evidence(active_evidence_v1, features or {})
        ts = now if now is not None else time.time()

        merged_v2 = fresh_v2
        if device_id:
            windowed_v2 = _query_graph_window(device_id, ts)
            # Dedup by CONTENT, not evidence_id -- convert() assigns a fresh, random
            # evidence_id on every call, so the same real observation converted fresh
            # this cycle and the same observation read back from the graph (written on
            # an earlier cycle) would never match on evidence_id alone, double-counting
            # it in the merged list handed to the decision engine.
            fresh_keys = {_content_key(ev) for ev in fresh_v2}
            merged_v2 = [ev for ev in windowed_v2 if _content_key(ev) not in fresh_keys] + fresh_v2

            # Phase 1a: cross-device correlation / reputation propagation / genuine
            # first-contact scoring -- computed from THIS cycle's real destinations
            # only (not the whole windowed history), added to merged_v2 alone. See
            # _inject_graph_derived_evidence()'s own docstring for why these must
            # never reach fresh_v2 (the graph-write path).
            fresh_destinations = {ev.destination_id for ev in fresh_v2}
            merged_v2 = merged_v2 + _inject_graph_derived_evidence(device_id, fresh_destinations, ts, fresh_v2)

            # Release 14, N2: peer-cohort behavioral baselining -- a genuinely NEW,
            # unvalidated heuristic (unlike coordinated_targeting/fingerprint_campaign/
            # dga_seed_campaign, which all reuse well-established, low-false-positive
            # correlation concepts), so kept as its own separate injection call rather
            # than folded into _inject_graph_derived_evidence() above. See
            # _inject_peer_deviation_evidence()'s own docstring for the honest-status
            # framing and why PeerDeviationHypothesis is deliberately capped low.
            merged_v2 = merged_v2 + _inject_peer_deviation_evidence(device_id, device_type, ts)

        decision = _v13_engine.evaluate(
            merged_v2, rep_vector, device_type=device_type,
            baseline_familiarity=baseline_familiarity, features=features, is_safe=is_safe,
            now=ts,
        )

        if device_id:
            _write_graph(device_id, ts, fresh_v2, merged_v2, decision)
            # v13 full-architecture plan, alert/decision unification (Phase 2): the
            # most recently written decision_id for this device, whether or not
            # THIS cycle itself wrote a new row (see _last_decision_id's own
            # module-level comment) -- gives pipeline.py a real target for later
            # enriching this decision with alert_payload/fp_verdict/incident-outcome
            # fields via GraphStore.update_decision_payload(). None (never set) if
            # the graph write itself has never succeeded for this device yet.
            decision["_graph_decision_id"] = _last_decision_id.get(device_id)

        return decision
    except Exception as e:
        LOGGER.error(
            "v13 live engine raised %s -- falling back to v-current's decision engine "
            "for this cycle. This should never happen in normal operation; investigate.",
            e, exc_info=True,
        )
        if fallback_evaluate is not None:
            return fallback_evaluate(
                active_evidence_v1, rep_vector, device_type, baseline_familiarity,
                features=features, is_safe=is_safe,
            )
        raise


# ==============================================================================
# CL-AFPE shadow-mode wiring (v13 full-architecture plan, Phase 6e)
#
# This module is "the actual swap-in adapter pipeline.py calls" for the DECISION
# path (see the module docstring above) -- but v-current's real CL-AFPE verdict
# (self.fp_engine.evaluate(), intelligence/fp_engine.py) is computed at a LATER,
# separate point in pipeline.py's own per-cycle flow (~line 1812, well after the
# `decision` this module's own evaluate() returns at ~line 1298). A genuine
# shadow comparison therefore needs its OWN call site in pipeline.py, immediately
# alongside that real fp_engine.evaluate() call -- not a repurposing of this
# module's own decision-path evaluate() above. This mirrors the SAME "one new
# call site, mirroring an existing precedent" shape the original v13 decision
# cutover itself used (this module's own docstring calls that "a one-line
# change") -- the new pipeline.py line calls evaluate_cl_afpe_shadow() below,
# which does 100% of the real work here, in live_engine.py, matching the plan's
# own wording as closely as is architecturally honest.
#
# "Compute-only, never suppresses" (the plan's own verification section) means:
# this function's return value is never used by pipeline.py to change what
# actually gets suppressed/contained -- it's fire-and-forget, logging a
# divergence record for later comparison. It does NOT mean CL-AFPE's own writes
# (trust edges, per-device fp_profile/sigma_shift, its own local-intel store) are
# skipped -- see cl_afpe/engine.py's own Phase 6e docstring paragraph for why
# accumulating that experience for real is the point of running this in shadow
# at all. What IS carefully kept separate: local-intel poisoning-protection state
# writes into a v13-ONLY LocalConfirmedIntel store (_CL_AFPE_LOCAL_INTEL_DIR,
# never intelligence/local_intel.py's real state/local_confirmed_intel.json) --
# sharing that file would let a shadow-only ML verdict actually hard-stop v1's
# own real Stage-1 Check 7 on a later alert, a real live-behavior side effect
# through a shared file, which is exactly what "never suppresses" rules out.
#
# ML models are the one deliberate EXCEPTION to that separation: MLScorer reads
# v-current's REAL, already-trained fp_classifier.onnx/fastembed_cache under
# _CL_AFPE_MODEL_DIR read-only (see cl_afpe/ml_scoring.py's own module docstring
# for the reuse-not-retrain design) -- reading them changes nothing about how
# train_fp_classifier.py's weekly retrain produces or consumes those same files.
# ==============================================================================

LOGGER_CL_AFPE = logging.getLogger("home_ids.v13_cl_afpe_shadow")

# Matches config.yaml's real `model_path: models/ids_model.pkl` -> parent dir
# `models/`, where fp_classifier.onnx and fastembed_cache/ actually live (see
# fp_engine.py:2532/2671's own Path(...).parent resolution). Relative to the
# process's CWD, matching every other v13 ops file's own state_dir convention.
_CL_AFPE_MODEL_DIR = "models"

# Deliberately v13-only -- never intelligence/local_intel.py's real
# state/local_confirmed_intel.json. See this section's own docstring above.
_CL_AFPE_LOCAL_INTEL_DIR = "state/v13_cl_afpe"

_CL_AFPE_DIVERGENCE_LOG_PATH = "state/cl_afpe_divergence_v13.jsonl"

_cl_afpe_engine: Optional[ClAfpeEngine] = None


def configure_cl_afpe(model_dir: Optional[str] = None, local_intel_dir: Optional[str] = None) -> None:
    """Optional: call once at startup to point CL-AFPE's shadow engine somewhere
    other than the defaults above -- same override shape as this module's own
    configure() for the graph db path. Safe to call before any real
    evaluate_cl_afpe_shadow() call; forces re-init of the lazy singleton."""
    global _CL_AFPE_MODEL_DIR, _CL_AFPE_LOCAL_INTEL_DIR, _cl_afpe_engine
    if model_dir is not None:
        _CL_AFPE_MODEL_DIR = model_dir
    if local_intel_dir is not None:
        _CL_AFPE_LOCAL_INTEL_DIR = local_intel_dir
    _cl_afpe_engine = None


def _get_cl_afpe_engine() -> ClAfpeEngine:
    global _cl_afpe_engine
    if _cl_afpe_engine is None:
        store = _get_graph_store()
        local_intel = LocalConfirmedIntel(_CL_AFPE_LOCAL_INTEL_DIR)
        ml_scorer = MLScorer(_CL_AFPE_MODEL_DIR)
        _cl_afpe_engine = ClAfpeEngine(store, local_intel=local_intel, ml_scorer=ml_scorer)
    return _cl_afpe_engine


def _log_cl_afpe_divergence(alert_payload: dict, v13_verdict: dict,
                              fp_verdict_v1: Optional[dict], now: float) -> None:
    """Best-effort append-only log, matching Phase 5's own separate-file
    convention (state/cl_afpe_divergence_v13.jsonl, mirroring
    ollama_analysis_v13.jsonl's own shape) -- never raises out to the caller.
    Logs EVERY comparison, not just divergences, so the log also carries a true
    agreement rate rather than only ever showing disagreements."""
    try:
        v1_verdict = (fp_verdict_v1 or {}).get("verdict")
        v13_verdict_str = v13_verdict.get("verdict")
        record = {
            "timestamp": now,
            "device_id": alert_payload.get("device", {}).get("id", "unknown"),
            "hostname": alert_payload.get("device", {}).get("hostname", ""),
            "signature": alert_payload.get("signature", ""),
            "v1_verdict": v1_verdict,
            "v1_confidence": (fp_verdict_v1 or {}).get("confidence"),
            "v1_stage": (fp_verdict_v1 or {}).get("stage"),
            "v13_verdict": v13_verdict_str,
            "v13_confidence": v13_verdict.get("confidence"),
            "v13_stage": v13_verdict.get("stage"),
            "agree": (v1_verdict == v13_verdict_str) if (v1_verdict and v13_verdict_str) else None,
        }
        path = Path(_CL_AFPE_DIVERGENCE_LOG_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        LOGGER_CL_AFPE.error("Failed to write CL-AFPE divergence log entry: %s", e, exc_info=True)


def evaluate_cl_afpe_live(alert_payload: dict, features: dict, risk_score: float = 0.0,
                            ti_engine=None, decision: Optional[dict] = None, asn_owner: str = "",
                            fallback_evaluate=None, now: Optional[float] = None) -> Dict[str, Any]:
    """v13 full-architecture plan, Workstream 2 -- the pipeline.py call site once
    config.yaml's `cl_afpe_engine` is flipped from "v_current" to "v13" (see
    cl_afpe_flip_monitor.py for how/when that flip happens). Unlike
    evaluate_cl_afpe_shadow() above, this function's RETURN VALUE is what pipeline.py
    actually acts on -- suppress/publish, ML-registry learn/reject, alerts.json's
    fp_verdict field -- exactly the same "one new call site, fail-safe fallback" shape
    A13's own decision-path evaluate() above already established for the main engine
    cutover. `risk_score`/`ti_engine` are accepted ONLY to pass through to
    fallback_evaluate on failure (ClAfpeEngine.evaluate() itself needs neither) --
    kept as real parameters rather than **kwargs so a caller passing the wrong shape
    fails loudly at the call site, not inside the except block.

    Once flipped, v-current's own fp_engine.evaluate() is no longer called at all for
    this cycle -- its flat-file state (device_fp_profiles.json/fp_sigma_shifts.json/
    fp_trust_cache.json/local_confirmed_intel.json) stops being updated, matching
    exactly how the main engine cutover (A13) made decision_engine.py's own shadow
    experiment permanently frozen. This is the intended, one-way consequence of a
    whole-engine swap (the granularity explicitly chosen over a per-mechanism flip),
    not a bug."""
    ts = now if now is not None else time.time()
    try:
        engine = _get_cl_afpe_engine()
        return engine.evaluate(alert_payload, features, decision=decision, asn_owner=asn_owner, now=ts)
    except Exception as e:
        LOGGER_CL_AFPE.error(
            "CL-AFPE LIVE evaluation raised %s -- falling back to v-current's real "
            "AutonomousFPEngine for this cycle. This should never happen in normal "
            "operation; investigate.", e, exc_info=True,
        )
        if fallback_evaluate is not None:
            return fallback_evaluate(
                alert_payload=alert_payload, features=features, risk_score=risk_score,
                ti_engine=ti_engine, decision=decision, asn_owner=asn_owner,
            )
        raise


def evaluate_cl_afpe_shadow(alert_payload: dict, features: dict, decision: Optional[dict] = None,
                              asn_owner: str = "", fp_verdict_v1: Optional[dict] = None,
                              now: Optional[float] = None) -> None:
    """The pipeline.py call site for Phase 6e -- called immediately alongside the
    real self.fp_engine.evaluate() (fp_verdict_v1 is that call's own return
    value, passed straight through for the divergence comparison). Returns
    nothing: this is fire-and-forget, compute-only shadow evaluation. Never
    raises -- a CL-AFPE shadow failure must never affect the real alert this
    cycle is publishing, matching every other best-effort graph operation in
    this module."""
    ts = now if now is not None else time.time()
    try:
        engine = _get_cl_afpe_engine()
        v13_verdict = engine.evaluate(alert_payload, features, decision=decision, asn_owner=asn_owner, now=ts)
        _log_cl_afpe_divergence(alert_payload, v13_verdict, fp_verdict_v1, ts)
    except Exception as e:
        LOGGER_CL_AFPE.error(
            "CL-AFPE shadow evaluation failed (compute-only -- the real fp_verdict this "
            "cycle is already decided and unaffected by this): %s", e, exc_info=True,
        )
