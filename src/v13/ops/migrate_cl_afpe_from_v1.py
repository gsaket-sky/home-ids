"""
migrate_cl_afpe_from_v1.py - v13 full-architecture plan, CL-AFPE flip prerequisite:
ONE-TIME, one-directional seed of v13's own ClAfpeEngine state (its
LocalConfirmedIntel store + its graph 'trusts' edges) from v-current's real,
long-established equivalents (state/local_confirmed_intel.json,
state/fp_trust_cache.json).

WHY THIS EXISTS (found this session, not guessed): .94's real
state/cl_afpe_divergence_v13.jsonl showed the flip monitor's hard veto correctly
firing -- 112 of 2259 eligible comparisons were false-negative-shaped (v13 would
have silently suppressed a real alert v-current correctly flagged). Root-caused
directly against live data: v13's ClAfpeEngine.evaluate() is a faithful, correct
port of fp_engine.py's real evaluate() (verified line-by-line against a real
divergence record for device a4544eb6d2ca) -- the divergence isn't a code bug.
It's that state/v13_cl_afpe/ on .94 was found completely EMPTY, while
v-current's real state/local_confirmed_intel.json has 1,130 lines of genuine,
cross-device-accumulated confirmed-threat history and state/fp_trust_cache.json
has 129 real trust-cache entries. v13 has been evaluating every shadow-mode
alert with ZERO cross-device corroboration/trust history available to it,
which plausibly explains most or all of the 112 divergences, not just the one
device this session traced in detail.

DELIBERATELY ONE-DIRECTIONAL, ONE-TIME -- does not create an ongoing shared-file
coupling. live_engine.py's own module docstring (search "_CL_AFPE_LOCAL_INTEL_DIR")
explains why v13's shadow-mode writes were deliberately kept OUT of v-current's
real files: an ONGOING shared file would let a shadow-only, unproven v13 verdict
actually hard-stop v-current's own real Stage-1 Check 7 on a later alert -- a
genuine live-behavior side effect through a shared file, exactly what "compute-
only, never suppresses" rules out. That concern is about v13 WRITING into
v-current's real files on an ongoing basis. This script does the opposite,
once: READS v-current's real files (never modifies them) and imports a snapshot
into v13's own, separate, already-isolated store. v-current's real files and
real live behavior are completely unaffected by running this.

Real production trust data -- run with --dry-run first and read its report
before running for real. Safe to re-run (idempotent): local-intel entries are
merged by kind+value taking whichever side has the newer last_confirmed;
trust-cache entries go through ClAfpeEngine.immunize()'s own real refresh
semantics (an existing 'trusts' edge to the same destination is replaced, not
duplicated).
"""
import argparse
import json
import logging
import time
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402
from v13.config.trust_anchors import load_hardware_profile  # noqa: E402
from v13.ops import live_engine as v13_live_engine  # noqa: E402

LOGGER = logging.getLogger("migrate_cl_afpe_from_v1")

# Matches fp_engine.py's own TRUST_CACHE_TTL_SECONDS (14 days) -- used only as a
# fallback for a legacy bare-float entry with no per-entry TTL recorded, same
# convention _trust_entry_ttl() (fp_engine.py) and immunize()'s own TTL clamping
# (cl_afpe/engine.py) already use.
_V1_TRUST_CACHE_DEFAULT_TTL_SECONDS = 14 * 24 * 3600


def _migrate_local_intel(state_dir: Path, dry_run: bool) -> dict:
    """Merges v-current's real LocalConfirmedIntel store into v13's own, by
    kind+value, taking whichever side's entry has the newer last_confirmed.
    Reads both through the SAME LocalConfirmedIntel class (both stores use the
    identical file format -- this class is reused unmodified by v13, not
    reimplemented, confirmed via direct read of v13/ops/live_engine.py's own
    _get_cl_afpe_engine()) -- accessing ._store directly is a deliberate,
    documented exception for this one-time migration tool: there is no public
    merge API on the class, and the on-disk format it reads/writes is simple and
    stable (see LocalConfirmedIntel._load()/_save())."""
    v1_store = LocalConfirmedIntel(str(state_dir))  # real, live state dir
    v13_store = LocalConfirmedIntel(str(state_dir / "v13_cl_afpe"))

    stats = {"kinds": {}}
    changed = False
    for kind in ("ip", "domain"):
        v1_bucket = v1_store._store.get(kind, {})
        v13_bucket = v13_store._store.setdefault(kind, {})
        v13_total_before = len(v13_bucket)
        added, refreshed, kept = 0, 0, 0
        for value, v1_entry in v1_bucket.items():
            existing = v13_bucket.get(value)
            if existing is None:
                if not dry_run:
                    v13_bucket[value] = dict(v1_entry)
                added += 1
                changed = True
            elif v1_entry.get("last_confirmed", 0) > existing.get("last_confirmed", 0):
                if not dry_run:
                    v13_bucket[value] = dict(v1_entry)
                refreshed += 1
                changed = True
            else:
                kept += 1
        stats["kinds"][kind] = {
            "v1_total": len(v1_bucket), "v13_total_before": v13_total_before,
            "added": added, "refreshed_with_newer_v1_data": refreshed, "kept_v13_own": kept,
        }

    if changed and not dry_run:
        v13_store._save()

    return stats


def _migrate_trust_cache(state_dir: Path, dry_run: bool) -> dict:
    """Reads v-current's real fp_trust_cache.json (never modifies it) and
    imports each entry via ClAfpeEngine.immunize() -- the real method, not a
    reimplementation, so validation/TTL-clamping/edge-shape stay exactly
    correct. `now` is passed as the entry's ORIGINAL confirmation timestamp
    (not migration time) so the edge's own TTL expiry is judged against real
    elapsed time going forward -- an entry 13 of its 14 real days old stays 1
    day from expiring after migration, it doesn't get a fresh 14-day clock."""
    trust_cache_path = state_dir / "fp_trust_cache.json"
    stats = {"v1_total": 0, "migrated": 0, "skipped_already_expired": 0, "skipped_invalid": 0}
    if not trust_cache_path.exists():
        stats["skipped_reason"] = "state/fp_trust_cache.json does not exist"
        return stats

    try:
        raw = json.loads(trust_cache_path.read_text(encoding="utf-8"))
    except Exception as exc:
        stats["skipped_reason"] = f"failed to parse fp_trust_cache.json: {exc}"
        return stats

    stats["v1_total"] = len(raw)
    if dry_run:
        now = time.time()
        for domain, entry in raw.items():
            if isinstance(entry, dict):
                ts = entry.get("ts", 0.0)
                ttl = entry.get("ttl_seconds") or _V1_TRUST_CACHE_DEFAULT_TTL_SECONDS
            else:
                ts, ttl = entry, _V1_TRUST_CACHE_DEFAULT_TTL_SECONDS
            if not domain or (now - float(ts)) >= float(ttl):
                stats["skipped_already_expired"] += 1
            else:
                stats["migrated"] += 1
        return stats

    engine = v13_live_engine._get_cl_afpe_engine()
    now = time.time()
    for domain, entry in raw.items():
        if isinstance(entry, dict):
            ts = float(entry.get("ts", 0.0) or 0.0)
            ttl = float(entry.get("ttl_seconds") or _V1_TRUST_CACHE_DEFAULT_TTL_SECONDS)
            device_id = entry.get("device_id")
            hypothesis = entry.get("hypothesis")
        else:
            ts = float(entry or 0.0)
            ttl = _V1_TRUST_CACHE_DEFAULT_TTL_SECONDS
            device_id = None
            hypothesis = None

        if not domain or (now - ts) >= ttl:
            stats["skipped_already_expired"] += 1
            continue

        try:
            engine.immunize(
                destination_id=domain, device_id=device_id, hypothesis=hypothesis,
                source="migrated_from_v1", ttl_seconds=ttl, now=ts,
            )
            stats["migrated"] += 1
        except Exception as exc:
            LOGGER.warning("Failed to migrate trust-cache entry for %r: %s", domain, exc)
            stats["skipped_invalid"] += 1

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                         help="Report what would be migrated without writing anything.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    db_path = state_dir / "v13_graph.db"
    if not db_path.exists() and not args.dry_run:
        LOGGER.error("state/v13_graph.db does not exist yet -- nothing to seed CL-AFPE state "
                      "against. Run this after v13's live decision path has run at least once.")
        return

    v13_live_engine.configure(str(db_path), hardware_profile=load_hardware_profile(CONFIG))

    LOGGER.info("=== Local confirmed-intel merge (%s) ===", "DRY RUN" if args.dry_run else "LIVE")
    local_intel_stats = _migrate_local_intel(state_dir, args.dry_run)
    LOGGER.info(json.dumps(local_intel_stats, indent=2))

    LOGGER.info("=== Trust cache -> graph 'trusts' edges (%s) ===", "DRY RUN" if args.dry_run else "LIVE")
    trust_cache_stats = _migrate_trust_cache(state_dir, args.dry_run)
    LOGGER.info(json.dumps(trust_cache_stats, indent=2))

    if args.dry_run:
        LOGGER.info("Dry run complete -- nothing was written. Re-run without --dry-run to apply.")
    else:
        LOGGER.info("Migration complete.")


if __name__ == "__main__":
    main()
