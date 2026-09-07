"""
live_retro_hunter.py - schedules v13's RetroHunter (src/v13/retro_hunter.py) against
`.94`'s own live graph (v13 full-architecture plan, Phase 4).

Registered as its own scheduled job (config.yaml's scheduled_jobs.scheduler.live_retro_hunter,
same mechanism as live_prune.py/retro_hunter.py) -- NOT a replacement for v-current's own
scripts/retro_hunter.py job (config key "retro_hunter", still enabled, still does its own
local-intel cross-reference, Telegram notification, and fp_engine sigma-tuning, none of
which v13's RetroHunter has -- see retro_hunter.py's own module docstring for the documented
scope cut). This job re-scans v13's OWN graph-backed destination history (state/v13_graph.db,
Phase 1) against fresh threat intel and writes any newly-confirmed-malicious destination back
as a real `reputation` Evidence item for the device that touched it -- picked up by that
device's very next live decision cycle through the same HypothesisEngine/DecisionEngine path
any other evidence goes through (this exact feedback loop is already proven end-to-end by
tests/test_v13_integration.py's own Step 8, against a test store).

v13 full-architecture plan, Phase 7 (added after this module's initial Phase 4 build):
cross-device local-intel correlation and Telegram notification, both now wired in here
-- see retro_hunter.py's own module docstring item #4 for check_local_intel_history()'s
design, and this module's own _notify_external_ti_findings()/_notify_local_intel_matches()
below for the notification shape (a direct port of scripts/retro_hunter.py's own
run_retro_hunt() notification text, using the shared v13/ops/telegram.py helper).

Still deliberately deferred: per-device job-health breakdown (v1's own
_count_findings_by_device()) -- a small, independently addable follow-up, not blocking.
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
from v13.graph.store import GraphStore, DEFAULT_EVIDENCE_RETENTION_DAYS  # noqa: E402
from v13.retro_hunter import RetroHunter, real_threat_intel_lookup_factory  # noqa: E402
from v13.ops.telegram import send_telegram  # noqa: E402
from v13.ops.live_engine import _CL_AFPE_LOCAL_INTEL_DIR  # noqa: E402

LOGGER = logging.getLogger("live_retro_hunter")

# v1's own scripts/retro_hunter.py's _REASON_PHRASES, ported exactly -- only the
# reasons this v13 job's own local-intel store can actually carry are included
# (STAGE_1_HARD_STOP/TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP from CL-AFPE's shadow
# mode, Phase 6b/6e); v1-only reasons (LLM_VALIDATED_MALICIOUS,
# HIGH_CRITICAL_DECISION) are omitted since nothing in v13 writes those yet.
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


def _notify_external_ti_findings(findings: list, days_back: float) -> None:
    """Matches run_retro_hunt()'s own external-ThreatIntel notification shape
    (scripts/retro_hunter.py lines 308-343) -- a genuine zero-day retroactive
    match deserves the same real-time channel every other finding in this
    codebase gets, not just a log line. No-op (send_telegram itself no-ops)
    when telegram_token/telegram_chat_id aren't configured."""
    if not findings:
        return
    top = findings[:10]
    lines = [f"\U0001f6a8 <b>v13 Retroactive Threat Hunt: {len(findings)} match(es)</b>",
             f"Destinations queried in the past {int(days_back)}d, now classified malicious by fresh intel:", ""]
    for f in top:
        lines.append(f"• <code>{f.destination_id}</code> — {f.source}, confidence {f.confidence:.2f}")
    if len(findings) > len(top):
        lines.append(f"...and {len(findings) - len(top)} more (see state/v13_graph.db decisions/evidence)")
    send_telegram(CONFIG, "\n".join(lines)[:4000])


def _notify_local_intel_matches(matches: list, geoip_engine: GeoIPEngine, days_back: float) -> None:
    """Matches run_retro_hunt()'s own local-intel cross-reference notification
    shape (scripts/retro_hunter.py lines 405-434), GeoIP-enriched for any IP
    match. device_id is used directly as the display label (v13's devices table
    has a display_label column, but nothing populates it yet -- a real, minor,
    tracked simplification versus v1's hostname/display-name map, not a
    correctness gap)."""
    if not matches:
        return
    top = matches[:10]
    lines = [f"\U0001f310 <b>v13 Retroactive Local-Intel Cross-Reference: {len(matches)} match(es)</b>",
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

# v13 full-architecture plan, Phase 1a's item 5: "retro-hunter against the FULL
# retained history, not just recent days" -- now that live_prune.py actually enforces
# GraphStore's 90-day evidence retention (Phase 1's own follow-up fix), a newly
# confirmed-malicious destination can be checked against everything any device
# touched in the WHOLE retained window, not an arbitrary shorter slice. Was 14
# (matching RetroHunter.hunt()'s own default / scripts/retro_hunter.py's --days
# default) when this file was first written in Phase 4, before retention was
# actually being enforced on `.94` -- deliberately widened here, now that it is,
# rather than leaving an artificially narrow lookback that ignores 76 days of
# history the graph is already paying to retain.
DEFAULT_DAYS_BACK = DEFAULT_EVIDENCE_RETENTION_DAYS


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
        store = GraphStore(str(db_path))
        lookup = real_threat_intel_lookup_factory(CONFIG, str(state_dir), refresh=True)
        hunter = RetroHunter(store, lookup)
        findings = hunter.hunt(days_back=DEFAULT_DAYS_BACK)
        LOGGER.info(
            "Retro-hunt complete: %d finding(s) against the last %d days of graph history.",
            len(findings), DEFAULT_DAYS_BACK,
        )
        _notify_external_ti_findings(findings, DEFAULT_DAYS_BACK)

        # Phase 7: cross-device local-intel correlation, against the SAME v13-only
        # LocalConfirmedIntel store CL-AFPE's own shadow mode writes into (Phase 6e)
        # -- see retro_hunter.py's own module docstring item #4 for why this is
        # deliberately never v1's real local_confirmed_intel.json.
        local_intel = LocalConfirmedIntel(_CL_AFPE_LOCAL_INTEL_DIR)
        local_matches = hunter.check_local_intel_history(local_intel, days_back=DEFAULT_DAYS_BACK)
        store.close()
        LOGGER.info(
            "Local-intel cross-reference complete: %d match(es) against the last %d days.",
            len(local_matches), DEFAULT_DAYS_BACK,
        )
        if local_matches:
            # Built lazily -- only when there's something to report, matching
            # scripts/retro_hunter.py's own laziness for the exact same reason
            # (GeoIPEngine is a cheap local mmdb read either way, but no reason to
            # even try on a quiet run).
            geoip_engine = GeoIPEngine(
                db_path=CONFIG.get("geoip_db", str(state_dir / "GeoLite2-City.mmdb")),
                asn_db_path=CONFIG.get("geoip_asn_db", ""),
            )
            _notify_local_intel_matches(local_matches, geoip_engine, DEFAULT_DAYS_BACK)

        write_job_health(state_dir, "live_retro_hunter", time.time() - run_start,
                          extra={"findings_count": len(findings), "local_intel_matches_count": len(local_matches)})
    except Exception as e:
        LOGGER.error("live_retro_hunter failed: %s", e, exc_info=True)
        write_job_health(state_dir, "live_retro_hunter", time.time() - run_start, extra={"error": str(e)})


if __name__ == "__main__":
    main()
