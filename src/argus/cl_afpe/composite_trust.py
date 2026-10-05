"""
argus/cl_afpe/composite_trust.py -- Release 15 Sheet 03b: CL-AFPE's
six-dimensional composite trust key (device x behavior_fingerprint x
destination_class x hypothesis x evidence_family x regime), persisted in
cl_afpe_trust (already migrated).

ADDITIVE, not a replacement: this package's engine.py (ClAfpeEngine) already
scopes trust by (device, destination_id, hypothesis) via is_trust_cached()/
get_dynamic_trust_cache() -- three of these six dimensions. This module adds
the remaining three (behavior_fingerprint instead of raw evidence_type,
destination_class instead of a literal destination_id, evidence_family, and
regime) as a SEPARATE, MORE CONSERVATIVE gate.

WIRED 2026-09-15 (write-side live, read-side shadow-logged, not yet hard-gating):
record_corroborating_signal() is called for real on every genuine STAGE_3_COMBINED
suppression in ClAfpeEngine.evaluate(), so the table starts accumulating real data
now. permits_suppression() is also computed there and logged, but deliberately NOT
yet AND-ed onto the existing is_trust_cached() fast path as a hard gate -- since
this table starts completely empty, hard-gating immediately would strip away every
currently-working trust-cache suppression until real corroboration re-accumulates
(days, possibly longer), a significant live behavior change with zero real data
behind it on day one. Promote to a hard gate once shadow data shows
permits_suppression() agreeing with real outcomes, the same shadow-then-promote
shape CL-AFPE itself already went through (argus is the default engine since 2026-10-02). When
promoted, the intended integration is AND, not OR: a suppression decision requires
BOTH is_trust_cached() AND permits_suppression() below to agree, so this module can
only ever TIGHTEN what already exists, never loosen it.

Two of the six dimensions are first-pass simplifications, not the schema's original
full intent -- see classify_destination() below and engine.py's call site for what
behavior_fingerprint/regime_id actually resolve to today and why.

THE QUESTION THIS CLOSES: "how do we know CL-AFPE isn't just learning to
trust bad behavior." A plain (device, destination) key reproduces a softer
version of the old device-wide `immunize` button -- trust earned ruling out
one evidence shape/hypothesis/regime silently applies to a different one it
was never actually validated against. All six dimensions already exist
elsewhere in this codebase or this plan's own schema; this module doesn't
invent new taxonomy, it uses them as the actual trust key.

THE ANTI-GAMING FIX SPECIFICALLY: the classic FP-engine poisoning move is
repeatedly tripping the SAME single weak signal, just under the
corroboration threshold, until it gets trusted. Fixed here structurally:
trust for a given (device, fingerprint, destination_class, hypothesis,
regime) tuple only rises once at least _MIN_DISTINCT_FAMILIES_TO_BUILD_TRUST
DISTINCT evidence_family values have each independently corroborated it --
never from N repeats of one family.
"""
import ipaddress
import time
import uuid
from typing import Optional

from argus.graph.store import GraphStore
from utils import is_cloud_cdn_provider_org, is_telemetry_domain

# First-pass, not-yet-empirically-tuned constants (this codebase's own
# established honesty framing).
_TRUST_INCREMENT = 0.15         # bounded step per confirming observation -- same discipline as the autotuner
_TRUST_DECAY_PER_DAY = 0.05     # trust decays if not reinforced -- never permanent from one confirmation
_SUPPRESSION_TRUST_FLOOR = 0.6  # minimum per-family trust before that family counts as "corroborating"
_MIN_DISTINCT_FAMILIES_TO_BUILD_TRUST = 2

# Release 15 Sheet 03b wiring (2026-09-15): no destination_class producer existed
# anywhere in the codebase before this. Deliberately reuses this codebase's existing
# private/multicast/CDN/telemetry classification (utils.is_cloud_cdn_provider_org/
# is_telemetry_domain, stdlib ipaddress) rather than inventing a second taxonomy that
# could quietly disagree with the first -- same reasoning as this module's own
# docstring for why it uses existing dimensions instead of new ones.


def classify_destination(dest_ip: str = "", base_domain: str = "", asn_owner: str = "") -> str:
    """First-pass destination_class classifier. Checks IP-shape first (cheap,
    always available when dest_ip is a real address), then domain/ASN-based
    classification, falling back to "public" when nothing more specific matches."""
    if dest_ip:
        try:
            addr = ipaddress.ip_address(dest_ip)
            if addr.is_multicast:
                return "multicast"
            if addr.is_loopback:
                return "loopback"
            if addr.is_private or addr.is_link_local or addr.is_reserved:
                return "private"
        except ValueError:
            pass
    if base_domain and is_telemetry_domain(base_domain):
        return "telemetry"
    if asn_owner and is_cloud_cdn_provider_org(asn_owner):
        return "cdn"
    return "public"


def record_corroborating_signal(store: GraphStore, device_id: str, behavior_fingerprint: str,
                                   destination_class: str, hypothesis_id: str, evidence_family: str,
                                   regime_id: int, eligible_to_contribute: bool = True,
                                   now: Optional[float] = None) -> None:
    """Records ONE observation supporting benign classification for this
    exact six-dimensional tuple, scoped to ONE evidence_family (the row's
    own primary key includes evidence_family -- see cross-family counting
    in permits_suppression()). `eligible_to_contribute` is the caller's own
    determination (Sheet 00's incident-gate / regime-probation state, kept
    decoupled from this module rather than reached into directly) -- an
    ineligible call is a documented no-op, not an error, matching the
    self-review fix that excludes probationary/incident-window devices from
    CONTRIBUTING to shared trust the same way they're excluded from
    contributing to population priors."""
    if not eligible_to_contribute:
        return
    now = now if now is not None else time.time()
    device_id = _canonical(store, device_id)
    # BUGFIX (2026-09-15, found live on .94 minutes after deploying the "3
    # automated-learning gaps" fix): cl_afpe_trust.hypothesis_id is a real FK
    # against the hypotheses catalog table (GraphStore's PRAGMA foreign_keys=ON
    # is real enforcement, not advisory) -- but nothing ever seeded that table on
    # a live production deployment, so EVERY insert below has always failed with
    # sqlite3.IntegrityError on .94, caught non-fatally by evaluate()'s own
    # try/except and silently logged, since this function was first wired
    # (composite trust's hard-gate went live earlier the same day). This means
    # composite-trust corroboration has likely never successfully written a row
    # in production before now, for ANY caller (the original Stage 2/3 path
    # included), not just the new Stage 1b path that happened to be the first to
    # exercise it heavily enough to surface the error in the journal. Ensuring
    # the FK row exists here -- once, cheaply, via INSERT OR IGNORE -- fixes this
    # for every current and future caller in one place, rather than requiring
    # every caller to remember to seed it themselves (this module's own tests
    # were doing exactly that seeding manually, masking the gap).
    store._conn.execute(
        "INSERT OR IGNORE INTO hypotheses (hypothesis_id, kind) VALUES (?, 'attack')",
        (hypothesis_id,),
    )
    # Rows of this tuple under every id of the device: an id merged into it keeps contributing, so the new value
    # builds on the highest (decayed) trust the device already has, whichever id it was earned under.
    ids = _device_ids(store, device_id)
    rows = store._conn.execute(
        f"SELECT device_id, trust_value, n, last_updated FROM cl_afpe_trust WHERE device_id IN "
        f"({','.join('?' * len(ids))}) AND behavior_fingerprint=? AND destination_class=? AND hypothesis_id=? "
        f"AND evidence_family=? AND regime_id=?",
        (*ids, behavior_fingerprint, destination_class, hypothesis_id, evidence_family, regime_id),
    ).fetchall()
    row = next((r for r in rows if r["device_id"] == device_id), None)
    prior = max((_apply_decay(float(r["trust_value"]), float(r["n"]), now, r) for r in rows), default=None)
    if row is None:
        new_trust = min(1.0, (prior or 0.0) + _TRUST_INCREMENT)
        store._conn.execute(
            "INSERT INTO cl_afpe_trust (device_id, behavior_fingerprint, destination_class, hypothesis_id, "
            "evidence_family, regime_id, trust_value, n, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (device_id, behavior_fingerprint, destination_class, hypothesis_id, evidence_family, regime_id,
             new_trust, now),
        )
    else:
        new_trust = min(1.0, prior + _TRUST_INCREMENT)
        store._conn.execute(
            "UPDATE cl_afpe_trust SET trust_value=?, n=n+1, last_updated=? WHERE device_id=? AND "
            "behavior_fingerprint=? AND destination_class=? AND hypothesis_id=? AND evidence_family=? AND regime_id=?",
            (new_trust, now, device_id, behavior_fingerprint, destination_class, hypothesis_id,
             evidence_family, regime_id),
        )
    store._maybe_commit()


def _apply_decay(trust_value: float, n: float, now: float, row) -> float:
    last_updated = float(row["last_updated"] or now)
    days_elapsed = max(0.0, (now - last_updated) / 86400.0)
    return max(0.0, trust_value - _TRUST_DECAY_PER_DAY * days_elapsed)


def _canonical(store: GraphStore, device_id: str) -> str:
    """Trust belongs to the physical device: written under its canonical id (an id merged away since resolves to the
    device it was merged into)."""
    try:
        return store.resolve_canonical_device_id(device_id) if device_id else device_id
    except RuntimeError:
        return device_id


def _device_ids(store: GraphStore, device_id: str):
    return store.device_ids_for(device_id) if device_id else [device_id]


def _family_trusts(store: GraphStore, device_id: str, behavior_fingerprint: str,
                     destination_class: str, hypothesis_id: str, regime_id: int, now: float):
    """(evidence_family, decayed trust) for this tuple, across every id of the device (trust earned under an id since
    merged into it still counts). Several ids with the same family: the highest trust, one entry per family."""
    ids = _device_ids(store, device_id)
    rows = store._conn.execute(
        f"SELECT evidence_family, trust_value, n, last_updated FROM cl_afpe_trust WHERE device_id IN "
        f"({','.join('?' * len(ids))}) AND behavior_fingerprint=? AND destination_class=? AND hypothesis_id=? "
        f"AND regime_id=?",
        (*ids, behavior_fingerprint, destination_class, hypothesis_id, regime_id),
    ).fetchall()
    best = {}
    for r in rows:
        trust = _apply_decay(float(r["trust_value"]), float(r["n"]), now, r)
        best[r["evidence_family"]] = max(trust, best.get(r["evidence_family"], 0.0))
    return list(best.items())


def permits_suppression(store: GraphStore, device_id: str, behavior_fingerprint: str,
                           destination_class: str, hypothesis_id: str, regime_id: int,
                           now: Optional[float] = None) -> bool:
    """The actual gate: True only if at least _MIN_DISTINCT_FAMILIES_TO_
    BUILD_TRUST distinct evidence families have EACH independently
    corroborated this exact tuple past _SUPPRESSION_TRUST_FLOOR (after
    decay). A single family sitting at trust_value=1.0 from repeated
    self-corroboration never passes this on its own -- the direct
    structural fix for the anti-gaming concern in this module's own
    docstring. regime_id is part of the key, not just the lookup filter:
    trust earned under an OLDER regime_id never satisfies a lookup for a
    NEWER one, so a firmware/OS-update-driven regime change re-requires
    fresh corroboration rather than silently inheriting stale trust."""
    now = now if now is not None else time.time()
    trusts = _family_trusts(store, device_id, behavior_fingerprint, destination_class, hypothesis_id,
                              regime_id, now)
    qualifying_families = {family for family, trust in trusts if trust >= _SUPPRESSION_TRUST_FLOOR}
    return len(qualifying_families) >= _MIN_DISTINCT_FAMILIES_TO_BUILD_TRUST


def reset_tuple(store: GraphStore, device_id: str, behavior_fingerprint: str,
                  destination_class: str, hypothesis_id: str, regime_id: int) -> int:
    """Operator-invoked reset (Sheet 04's reset/undo, not yet built) -- wipes
    every family's accumulated trust for this exact tuple. Returns the
    number of rows removed. A normal admin capability, not an autonomous
    decision -- see Sheet 04's own design for why this is deliberately
    manual, not automatic. Covers every id of the device, like the reads."""
    ids = _device_ids(store, device_id)
    cur = store._conn.execute(
        f"DELETE FROM cl_afpe_trust WHERE device_id IN ({','.join('?' * len(ids))}) AND behavior_fingerprint=? "
        f"AND destination_class=? AND hypothesis_id=? AND regime_id=?",
        (*ids, behavior_fingerprint, destination_class, hypothesis_id, regime_id),
    )
    store._maybe_commit()
    return cur.rowcount
