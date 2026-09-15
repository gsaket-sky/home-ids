"""
v13/cl_afpe/composite_trust.py -- Release 15 Sheet 03b: CL-AFPE's
six-dimensional composite trust key (device x behavior_fingerprint x
destination_class x hypothesis x evidence_family x regime), persisted in
cl_afpe_trust (already migrated).

ADDITIVE, not a replacement: this package's engine.py (ClAfpeEngine) already
scopes trust by (device, destination_id, hypothesis) via is_trust_cached()/
get_dynamic_trust_cache() -- three of these six dimensions. This module adds
the remaining three (behavior_fingerprint instead of raw evidence_type,
destination_class instead of a literal destination_id, evidence_family, and
regime) as a SEPARATE, MORE CONSERVATIVE gate. NOT YET WIRED into
ClAfpeEngine.evaluate() itself -- real, separate follow-up work, matching
Sheet 00/02/03a's honest-gap pattern. When wired, the intended integration
is AND, not OR: a suppression decision should require BOTH is_trust_cached()
AND permits_suppression() below to agree, so this module can only ever
TIGHTEN what already exists, never loosen it.

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
import time
import uuid
from typing import Optional

from argus.graph.store import GraphStore

# First-pass, not-yet-empirically-tuned constants (this codebase's own
# established honesty framing).
_TRUST_INCREMENT = 0.15         # bounded step per confirming observation -- same discipline as the autotuner
_TRUST_DECAY_PER_DAY = 0.05     # trust decays if not reinforced -- never permanent from one confirmation
_SUPPRESSION_TRUST_FLOOR = 0.6  # minimum per-family trust before that family counts as "corroborating"
_MIN_DISTINCT_FAMILIES_TO_BUILD_TRUST = 2


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
    row = store._conn.execute(
        "SELECT trust_value, n, last_updated FROM cl_afpe_trust WHERE device_id=? AND behavior_fingerprint=? AND "
        "destination_class=? AND hypothesis_id=? AND evidence_family=? AND regime_id=?",
        (device_id, behavior_fingerprint, destination_class, hypothesis_id, evidence_family, regime_id),
    ).fetchone()
    if row is None:
        new_trust = min(1.0, _TRUST_INCREMENT)
        store._conn.execute(
            "INSERT INTO cl_afpe_trust (device_id, behavior_fingerprint, destination_class, hypothesis_id, "
            "evidence_family, regime_id, trust_value, n, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (device_id, behavior_fingerprint, destination_class, hypothesis_id, evidence_family, regime_id,
             new_trust, now),
        )
    else:
        decayed = _apply_decay(float(row["trust_value"]), float(row["n"]), now, row)
        new_trust = min(1.0, decayed + _TRUST_INCREMENT)
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


def _family_trusts(store: GraphStore, device_id: str, behavior_fingerprint: str,
                     destination_class: str, hypothesis_id: str, regime_id: int, now: float):
    rows = store._conn.execute(
        "SELECT evidence_family, trust_value, n, last_updated FROM cl_afpe_trust WHERE device_id=? AND "
        "behavior_fingerprint=? AND destination_class=? AND hypothesis_id=? AND regime_id=?",
        (device_id, behavior_fingerprint, destination_class, hypothesis_id, regime_id),
    ).fetchall()
    return [(r["evidence_family"], _apply_decay(float(r["trust_value"]), float(r["n"]), now, r)) for r in rows]


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
    manual, not automatic."""
    cur = store._conn.execute(
        "DELETE FROM cl_afpe_trust WHERE device_id=? AND behavior_fingerprint=? AND destination_class=? "
        "AND hypothesis_id=? AND regime_id=?",
        (device_id, behavior_fingerprint, destination_class, hypothesis_id, regime_id),
    )
    store._maybe_commit()
    return cur.rowcount
