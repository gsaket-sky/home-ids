"""
live_retro_hunter.py - schedules argus's RetroHunter (src/argus/retro_hunter.py) against
`.94`'s own live graph.

Registered as its own scheduled job (config.yaml's scheduled_jobs.scheduler.live_retro_hunter,
same mechanism as live_prune.py). v16: the sole retro-hunt job -- the earlier engine's own
scripts/retro_hunter.py was retired the same release once its findings/local-intel-store
activity stayed flat across multiple live checks while this job (which by then had reached
full feature parity: local-intel cross-reference, Telegram notification, and the
sensitivity-tuning loop-closing action below) kept running as the sole
engine. This job re-scans Argus's OWN graph-backed destination history (state/v13_graph.db,
Phase 1) against fresh threat intel and writes any newly-confirmed-malicious destination back
as a real `reputation` Evidence item for the device that touched it -- picked up by that
device's very next live decision cycle through the same HypothesisEngine/DecisionEngine path
any other evidence goes through (this exact feedback loop is already proven end-to-end by
tests/test_argus_integration.py's own Step 8, against a test store).


cross-device local-intel correlation and Telegram notification, both now wired in here
-- see retro_hunter.py's own module docstring item #4 for check_local_intel_history()'s
design, and this module's own _notify_external_ti_findings()/_notify_local_intel_matches()
below for the notification shape (a direct port of scripts/retro_hunter.py's own
run_retro_hunt() notification text, using the shared argus/ops/telegram.py helper).

Release 14, Workstream 5 (2026-09-07): both items A25/A26 deliberately deferred are
now wired in. (1) Per-device job-health breakdown (the earlier engine's own
_count_findings_by_device() equivalent) -- see _count_by_device() below. (2) The
loop-closing action: when check_local_intel_history() finds a NEWLY-implicated
device (one that touched an IOC before it was confirmed by a different device),
this job now ALSO calls ClAfpeEngine.record_confirmed_threat() +
_apply_sigma_shift(TUNE_UP) for that device -- the same "close the loop" mutation
the earlier engine's own run_retro_hunt() performs, previously named as deferred because it needed
a ClAfpeEngine instance threaded in, which this phase does. This has a real,
useful side effect beyond the immediate device: it adds the device to the IOC's own
confirmed `sources` list, so the SAME match correctly stops re-firing on the next
run (check_local_intel_history()'s own exclusion rule already treats an
already-a-source device as "not a new finding") -- without this, the identical
match would otherwise be reported again every single day, forever.
"""
import ipaddress
import logging
import time
from datetime import datetime
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402
from intelligence.geoip import GeoIPEngine  # noqa: E402
from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402
from argus.config.trust_anchors import load_hardware_profile  # noqa: E402
from argus.graph.store import GraphStore, DEFAULT_EVIDENCE_RETENTION_DAYS  # noqa: E402
from argus.retro_hunter import RetroHunter, real_threat_intel_lookups_factory, format_findings_message, \
    days_back_for_profile  # noqa: E402
from intelligence.local_popularity import LocalPopularity  # noqa: E402
from argus.ops.telegram import send_telegram  # noqa: E402

LOGGER = logging.getLogger("live_retro_hunter")

# the earlier engine's own scripts/retro_hunter.py's _REASON_PHRASES, ported exactly -- only the
# reasons this argus job's own local-intel store can actually carry are included
# (STAGE_1_HARD_STOP/TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP from CL-AFPE's shadow
# mode, Phase 6b/6e); reasons only the retired script had (LLM_VALIDATED_MALICIOUS,
# HIGH_CRITICAL_DECISION) are omitted since nothing in argus writes those yet.
_REASON_PHRASES = {
    "STAGE_1_HARD_STOP": "a hard-stop match against known-bad intel",
    "TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP": "a hard-stop that overrode an existing trust-cache entry",
}


def _geo_note(geoip_engine: GeoIPEngine, ip: str) -> str:
    """Matches scripts/retro_hunter.py's own _geo_note() exactly: ' (Org,
    Country)' for a raw IP via local mmdb lookups, or '' if unavailable/not an
    IP. A small local copy, matching that script's own established convention
    of not importing another script's private helper across module boundaries."""
    if not ip or ip == "unknown" or not geoip_engine:
        return ""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ""
    try:
        asn_res = geoip_engine.lookup_asn(ip)
        city_res = geoip_engine.lookup(ip)
        geo_org = getattr(asn_res, "autonomous_system_organization", None) if asn_res else None
        geo_country = getattr(getattr(city_res, "country", None), "name", None) if city_res else None
        geo_parts = [p for p in (geo_org, geo_country) if p]
        return f" ({', '.join(geo_parts)})" if geo_parts else ""
    except Exception:
        return ""


def _count_by_device(items: list, device_id_getter) -> dict:
    """argus-native equivalent of scripts/retro_hunter.py's own
    _count_findings_by_device() -- a simple {device_id: count} tally, generic over
    both `findings` (Evidence objects, device_id via attribute) and `local_matches`
    (dicts, device_id via key) via the caller-supplied getter."""
    counts: dict = {}
    for item in items:
        dev_id = device_id_getter(item)
        if dev_id:
            counts[dev_id] = counts.get(dev_id, 0) + 1
    return counts


def _close_local_intel_loop(cl_afpe: ClAfpeEngine, matches: list) -> int:
    """The loop-closing action A25/A26 named as deferred: the earlier engine's own run_retro_hunt()
    doesn't just NOTIFY about a newly-implicated device, it also confirms the
    threat against that device's own CL-AFPE state (record_confirmed_threat() +
    a TUNE_UP sigma-shift, tightening its sensitivity the same way a direct
    Stage-1 hard-stop would). Returns the number of devices actually closed.
    Best-effort per-match: one failure must not block closing the loop for every
    OTHER match in the same run."""
    closed = 0
    for m in matches:
        device_id = m.get("device_id")
        if not device_id:
            continue
        try:
            matched_kind = m.get("matched_kind")
            base_domain = m.get("matched_value") if matched_kind == "domain" else None
            dest_ip = m.get("matched_value") if matched_kind == "ip" else None
            cl_afpe.record_confirmed_threat(
                device_id, base_domain, dest_ip,
                # Matches scripts/retro_hunter.py's own real reason string exactly
                # (line 389) -- NOT the ORIGINAL confirmer's own reason (m["reason"],
                # e.g. STAGE_1_HARD_STOP) -- this call is about why THIS device is
                # being newly confirmed (a retro-hunt cross-reference), a genuinely
                # different fact than how the FIRST device was originally confirmed.
                reason="RETRO_HUNT_LOCAL_INTEL_MATCH",
            )
            cl_afpe._apply_sigma_shift(device_id, direction="TUNE_UP", source="autonomous")
            closed += 1
        except Exception as e:
            LOGGER.warning("Failed to close the local-intel loop for device %r: %s", device_id, e)
    return closed


def _notify_external_ti_findings(findings: list, days_back: float) -> None:
    """Matches run_retro_hunt()'s own external-ThreatIntel notification shape
    (scripts/retro_hunter.py lines 308-343) -- a genuine zero-day retroactive
    match deserves the same real-time channel every other finding in this
    codebase gets, not just a log line. No-op (send_telegram itself no-ops)
    when telegram_token/telegram_chat_id aren't configured."""
    if not findings:
        return
    send_telegram(CONFIG, format_findings_message(findings, days_back))


def _notify_local_intel_matches(matches: list, geoip_engine: GeoIPEngine, days_back: float) -> None:
    """Matches run_retro_hunt()'s own local-intel cross-reference notification
    shape (scripts/retro_hunter.py lines 405-434), GeoIP-enriched for any IP
    match. device_id is used directly as the display label (argus's devices table
    has a display_label column, but nothing populates it yet -- a real, minor,
    tracked simplification versus the earlier engine's hostname/display-name map, not a
    correctness gap)."""
    if not matches:
        return
    top = matches[:10]
    lines = [f"\U0001f310 <b>Retroactive Local-Intel Cross-Reference: {len(matches)} match(es)</b>",
             f"Devices that touched a since-confirmed-malicious IP/domain in the past {int(days_back)}d:", ""]
    for m in top:
        ip_note = _geo_note(geoip_engine, m["matched_value"]) if m["matched_kind"] == "ip" else ""
        reason_phrase = _REASON_PHRASES.get(m.get("reason", ""), m.get("reason") or "unknown")
        first_confirmed_human = (
            datetime.fromtimestamp(m["first_confirmed"]).strftime("%Y-%m-%d")
            if m.get("first_confirmed") else "unknown"
        )
        count_str = f"{m['count']}x" if m.get("count") else "an unknown number of times"
        confirmed_by = ", ".join(m.get("confirmed_by", [])) or "no one else yet"
        lines.append(
            f"• <code>{m['device_id']}</code> → {m['matched_kind']} <code>{m['matched_value']}</code>{ip_note}\n"
            f"  confirmed {count_str} since {first_confirmed_human} ({reason_phrase}); "
            f"also confirmed by: {confirmed_by}"
        )
    if len(matches) > len(top):
        lines.append(f"...and {len(matches) - len(top)} more")
    send_telegram(CONFIG, "\n".join(lines)[:4000])

# Phase 1a's item 5: "retro-hunter against the FULL
# retained history, not just recent days" -- now that live_prune.py actually enforces
# GraphStore's 90-day evidence retention (Phase 1's own follow-up fix), a newly
# confirmed-malicious destination can be checked against everything any device
# touched in the WHOLE retained window, not an arbitrary shorter slice. Was 14
# (matching RetroHunter.hunt()'s own default / scripts/retro_hunter.py's --days
# default) when this file was first written in Phase 4, before retention was
# actually being enforced on `.94` -- deliberately widened here, now that it is,
# rather than leaving an artificially narrow lookback that ignores 76 days of
# history the graph is already paying to retain.
#
# BUGFIX (2026-09-20, data-lifecycle retuning): this was a flat 90 regardless of
# hardware_profile, but evidence/device_destinations retention is only 30 days on
# pi_8gb -- meaning a pi_8gb deployment was requesting 60 days of history that its
# OWN retention policy had already deleted, silently getting a shorter effective
# scan than intended with no indication anything was truncated. Now scaled the
# same way live_prune.py's own retention_days is, so this job's lookback can never
# exceed what the graph actually still retains, on any profile.
# The table itself lives in retro_hunter.py (days_back_for_profile), shared with the learning-period sweep.
def _default_days_back() -> float:
    return days_back_for_profile(load_hardware_profile(CONFIG))


def _ledger_pairs(state_dir: Path, days_back: float) -> list:
    """(device, name) pairs from the learned-popularity ledger (state/popularity.db): every non-blocked name a device
    asked for, whether or not any detector flagged it. Empty when there is no ledger yet or it cannot be read."""
    path = state_dir / "popularity.db"
    if not path.exists():
        return []
    try:
        return LocalPopularity(path).device_name_pairs_since(time.time() - days_back * 86400)
    except Exception as e:
        LOGGER.warning("Could not read the popularity ledger %s (hunting without it): %s", path, e)
        return []


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    db_path = state_dir / "v13_graph.db"

    if not db_path.exists():
        # Nothing to hunt yet -- matches live_prune.py's own no-op path, same reason
        # (a box where engine="v_current", or live_engine.py has never run with a
        # device_id yet). Not an error.
        write_job_health(state_dir, "live_retro_hunter", time.time() - run_start,
                          extra={"findings_count": 0, "skipped": "no_db_yet"})
        return

    try:
        days_back = _default_days_back()
        store = GraphStore(str(db_path))
        lookup, ip_lookup = real_threat_intel_lookups_factory(CONFIG, str(state_dir), refresh=True)
        hunter = RetroHunter(store, lookup, ip_lookup=ip_lookup)
        ledger_pairs = _ledger_pairs(state_dir, days_back)
        findings = hunter.hunt(days_back=days_back, extra_pairs=ledger_pairs)
        LOGGER.info(
            "Retro-hunt complete: %d new finding(s) against the last %d days of graph history.",
            len(findings), days_back,
        )
        _notify_external_ti_findings(findings, days_back)

        # Cross-device local-intel correlation against the shared confirmed-intel store
        # (state/local_confirmed_intel.json) -- the same one the engine's CL-AFPE checks and records into.
        local_intel = LocalConfirmedIntel(str(state_dir))
        local_matches = hunter.check_local_intel_history(local_intel, days_back=days_back, extra_pairs=ledger_pairs)
        LOGGER.info(
            "Local-intel cross-reference complete: %d match(es) against the last %d days.",
            len(local_matches), days_back,
        )

        # Release 14, Workstream 5 (item 2): close the loop for each newly-implicated
        # device -- record_confirmed_threat() + a sigma TUNE_UP, the same real
        # mutation the earlier engine's own run_retro_hunt() performs, previously deferred pending a
        # ClAfpeEngine instance being threaded in here. Uses the SAME store/
        # local_intel this run already has open (still open -- store.close() moved
        # below this block).
        closed_count = 0
        if local_matches:
            cl_afpe = ClAfpeEngine(store, local_intel=local_intel)
            closed_count = _close_local_intel_loop(cl_afpe, local_matches)
            LOGGER.info("Closed the local-intel loop for %d/%d newly-implicated device(s).",
                        closed_count, len(local_matches))
        store.close()

        if local_matches:
            # Built lazily -- only when there's something to report, matching
            # scripts/retro_hunter.py's own laziness for the exact same reason
            # (GeoIPEngine is a cheap local mmdb read either way, but no reason to
            # even try on a quiet run).
            geoip_engine = GeoIPEngine(
                db_path=CONFIG.get("geoip_db", str(state_dir / "GeoLite2-City.mmdb")),
                asn_db_path=CONFIG.get("geoip_asn_db", ""),
            )
            _notify_local_intel_matches(local_matches, geoip_engine, days_back)

        write_job_health(state_dir, "live_retro_hunter", time.time() - run_start,
                          extra={
                              "findings_count": len(findings),
                              "local_intel_matches_count": len(local_matches),
                              "local_intel_loop_closed_count": closed_count,
                              # Release 14, Workstream 5 (item 1): per-device breakdown,
                              # the earlier engine's own _count_findings_by_device() equivalent.
                              "findings_by_device": _count_by_device(findings, lambda e: e.device_id),
                              "local_intel_matches_by_device": _count_by_device(local_matches, lambda m: m.get("device_id")),
                          })
    except Exception as e:
        LOGGER.error("live_retro_hunter failed: %s", e, exc_info=True)
        write_job_health(state_dir, "live_retro_hunter", time.time() - run_start, extra={"error": str(e)})


if __name__ == "__main__":
    main()
