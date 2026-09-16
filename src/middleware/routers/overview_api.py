"""
overview_api.py -- the console's "at a glance" security-posture summary.

Origin: home_ids also ships 5 Grafana dashboards (~150 panels) covering deep
per-device forensics, threat-landscape/geo, and autotune-history -- genuinely
valuable for the operator/tuner, but too heavy a dependency (Prometheus +
Loki + Promtail + Grafana, ~460MB RAM / ~1.9GB disk measured live on .94) to
require for a consumer product. This endpoint pulls the small, highest-signal
subset into the console instead: security/self-healing counters and a short
alert-volume trend. It is NOT trying to replace the Grafana dashboards' depth
(per-device DNS z-scores, autotune threshold history, geo maps, CL-AFPE funnel
stay Grafana-only) -- just cover "is my network okay" without requiring the
observability stack at all.

Three data sources:
1. A local self-scrape of this box's own /metrics endpoint (prometheus_client's
   start_http_server(), unconditionally started in core/pipeline.py's run()
   regardless of whether a Prometheus SERVICE is installed). Still used for
   pihole_blocks/router_isolations/tarpit_activations/ips_errors/
   domains_immunized/sigma_shifts -- in-process Counter objects, reset to 0 on
   every engine restart, labeled as such rather than overclaiming a lifetime
   total.
2. state/alerts.json, the same 170MB+ append-only NDJSON log suricata_api.py
   already reads, via the SAME bounded backward-scan helper
   (_alert_log_utils.iter_lines_reverse()), never a full-file read. Used for
   BOTH the alert-volume trend AND alerts_triaged/fp_evaluations/fp_suppressed/
   fp_confirmed_threats -- see _alert_stats()'s own docstring for why these
   moved off Prometheus entirely.
3. 2026-09-16 (user request: "include the overview of per device tuning in
   console") -- a single cheap COUNT query against the graph's own
   threshold_history table (the SAME table /api/autonomy/devices already
   surfaces in full detail) for a one-line "how many devices/categories are
   currently tuned away from global" summary, deliberately NOT the full
   per-device/category breakdown that endpoint already provides -- Overview
   stays "at a glance," the Autonomy tab stays the place for real detail. This
   revises the module's own earlier "autotune history stays Grafana-only"
   framing above -- true when originally written, superseded once the
   console got its own Autonomy tab.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import requests
from fastapi import APIRouter, Depends
from prometheus_client.parser import text_string_to_metric_families

from middleware.auth import verify_token, CONFIG
from middleware.graph_client import open_store
from middleware.routers._alert_log_utils import iter_lines_reverse

LOGGER = logging.getLogger("home_ids.overview_api")
router = APIRouter()

# home_ids_alerts_total/fp_evaluations_total/fp_suppressed_total/
# fp_confirmed_threats_total deliberately NOT scraped from here anymore -- see
# _alert_stats()'s docstring. Only counters unaffected by the v1/v13 CL-AFPE
# split are scraped: IPS actions happen downstream of whichever engine chose
# the verdict, and domains_immunized/sigma_shifts fire from
# AutonomousFPEngine's mark_false_positive()/_apply_sigma_shift(), which v13's
# ClAfpeEngine.evaluate() still calls directly (confirmed against
# v13/cl_afpe/engine.py's own module docstring) even though it bypasses
# AutonomousFPEngine.evaluate() itself.
_SECURITY_COUNTER_NAMES = {
    "home_ids_ips_pihole_blocks_total": "pihole_blocks",
    "home_ids_ips_router_isolations_total": "router_isolations",
    "home_ids_ips_tarpit_activations_total": "tarpit_activations",
    "home_ids_ips_errors_total": "ips_errors",
}
_SELF_HEALING_COUNTER_NAMES = {
    "home_ids_fp_domains_immunized_total": "domains_immunized",
    "home_ids_fp_sigma_shifts_total": "sigma_shifts",
}
_ALL_COUNTER_NAMES = dict(_SECURITY_COUNTER_NAMES, **_SELF_HEALING_COUNTER_NAMES)

# Bounded -- alerts.json is 170MB+ on the real deployment. 40MB covers roughly
# a week at .94's real measured alert rate (~6MB/day); a quieter network
# covers proportionally more days, a noisier one fewer -- the response's own
# `note` says which, rather than silently promising a fixed window.
_ALERT_VOLUME_MAX_SCAN_BYTES = 40 * 1024 * 1024
_ALERT_VOLUME_MAX_DAYS = 14


def _scrape_counters() -> "tuple[Dict[str, float], bool]":
    """Returns (totals, scrape_ok). scrape_ok is True whenever the HTTP GET
    and parsing both succeeded -- deliberately NOT the same thing as "totals
    is non-empty".

    BUGFIX (found live, 2026-09-14, right after the fp_verdict fix's own
    deploy): every metric this function reads (pihole_blocks/
    router_isolations/tarpit_activations/ips_errors/domains_immunized/
    sigma_shifts) is a LABELED prometheus_client Counter (e.g. Counter(...,
    ["device", "hostname"])). A labeled counter with no observations yet
    exports ZERO sample lines at all -- not even a 0 -- until its first
    .labels(...).inc() call (confirmed: reproduced `_scrape_counters()`
    returning {} on .94 shortly after a restart, then proved BOTH the raw
    HTTP GET and the parsing succeed fine in isolation against the exact
    same real 359KB response -- the function's old bool(totals) return was
    conflating "the scrape genuinely failed" with "nothing in this specific
    set of six rare-ish events has happened yet," which right after a
    restart is the common case, not a fault. The console's "could not reach
    the metrics endpoint" warning was firing for a false reason."""
    port = int(CONFIG.get("metrics_port", 9105))
    try:
        resp = requests.get(f"http://127.0.0.1:{port}/metrics", timeout=3)
        resp.raise_for_status()
    except Exception as exc:
        LOGGER.debug("Failed to scrape local /metrics: %s", exc)
        return {}, False
    totals: Dict[str, float] = {}
    try:
        for family in text_string_to_metric_families(resp.text):
            # BUGFIX (found while writing tests): prometheus_client's parser
            # strips the "_total" suffix from family.name (Prometheus's own
            # naming convention treats it as part of the counter type-suffix,
            # not the metric's identity) -- family.name for
            # "home_ids_alerts_total" comes back as "home_ids_alerts", while
            # the full "_total"-suffixed name only survives on each
            # individual sample. Matching against family.name here always
            # missed every counter. Match per-sample instead.
            for sample in family.samples:
                if sample.name not in _ALL_COUNTER_NAMES:
                    continue
                # Summed across every label combination (device/hostname/
                # reason/etc.) -- this view wants totals, not per-device
                # breakdown; the console's Devices/Blocking/Suricata tabs
                # already cover per-device detail.
                totals[sample.name] = totals.get(sample.name, 0.0) + sample.value
    except Exception as exc:
        LOGGER.debug("Failed to parse /metrics response: %s", exc)
        return {}, False
    return totals, True


def _alert_stats(alerts_path: Path) -> Dict[str, Any]:
    """Single bounded backward-scan over alerts.json computing the
    alert-volume-by-day trend AND real FP-engine verdict tallies together
    (one read of each line, not two separate scans).

    BUGFIX (found live, 2026-09-14, user report: "1149 alerts today but zero
    evaluation/suppressed/confirmed-threat counters, and no Telegram alerts"):
    those counters used to come from Prometheus's home_ids_alerts_total/
    fp_evaluations_total/fp_suppressed_total/fp_confirmed_threats_total.
    home_ids_alerts_total is fine on its own, but it was being compared
    against the OTHER three, which only ever increment inside the LEGACY
    AutonomousFPEngine.evaluate() (src/intelligence/fp_engine.py) -- and
    .94's live config has `cl_afpe_engine: v13` set, which routes every real
    verdict through v13_live_engine.evaluate_cl_afpe_live() ->
    ClAfpeEngine.evaluate() instead, a completely separate code path with NO
    Prometheus instrumentation of its own (confirmed: zero Counter/inc() calls
    anywhere in src/v13/cl_afpe/engine.py). AutonomousFPEngine.evaluate() is
    only reached as an error-path fallback on that route -- confirmed live: 8
    real alerts triaged in a 5-minute window, 0 recorded FP evaluations, not
    because nothing happened but because that counter structurally cannot
    increment under this deployment's actual configuration.

    The fix isn't new instrumentation -- pipeline.py already writes the REAL
    verdict (whichever engine produced it, v1 or v13, unconditionally) onto
    every alert record as alert_payload["fp_verdict"]["verdict"] before it's
    appended to alerts.json. Reading that back here is accurate regardless of
    which engine is active, and as a side effect is NOT reset by a restart
    the way the Prometheus counters were -- also fixing the separate
    "still inconsistent" complaint (alerts_triaged, previously Prometheus-
    since-restart, and the volume trend, always file-based-today, could
    disagree after any recent deploy restart; both now come from this same
    scan of the same file, so they can't disagree with each other again)."""
    empty = {
        "by_day": {}, "fp_evaluations": 0, "fp_suppressed": 0, "fp_confirmed_threats": 0,
        "fp_evaluations_by_day": {}, "fp_suppressed_by_day": {}, "fp_confirmed_threats_by_day": {},
    }
    if not alerts_path.exists():
        return dict(empty, note=f"No alert log found at {alerts_path}.")
    by_day: Dict[str, int] = {}
    # 2026-09-16 (user request: "i want the dates to be clickable so that only
    # values for those days are shown" -- Overview's alert-volume chart). These
    # three mirror by_day's own shape -- same source scan, same day key --
    # so the console can show a click-selected day's real fp_evaluations/
    # fp_suppressed/fp_confirmed_threats instead of the whole scanned window's
    # totals. Deliberately NOT extended to the 6 Prometheus-sourced counters in
    # _SECURITY_COUNTER_NAMES/_SELF_HEALING_COUNTER_NAMES (pihole_blocks,
    # router_isolations, tarpit_activations, ips_errors, domains_immunized,
    # sigma_shifts) -- those are in-process Counter objects with no historical
    # per-day series at all (reset to 0 on every restart), so there is no
    # honest per-day number to show for them; the console marks those as
    # unavailable when a day is selected rather than silently showing the
    # same restart-scoped total under a day label that would misleadingly
    # imply it's day-scoped.
    fp_evaluations_by_day: Dict[str, int] = {}
    fp_suppressed_by_day: Dict[str, int] = {}
    fp_confirmed_threats_by_day: Dict[str, int] = {}
    fp_evaluations = 0
    fp_suppressed = 0
    fp_confirmed_threats = 0
    scanned_lines = 0
    try:
        for line in iter_lines_reverse(alerts_path, _ALERT_VOLUME_MAX_SCAN_BYTES):
            scanned_lines += 1
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(rec, dict):
                continue

            ts = rec.get("timestamp")
            day = None
            if ts is not None:
                day = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
                by_day[day] = by_day.get(day, 0) + 1

            verdict = (rec.get("fp_verdict") or {}).get("verdict")
            if verdict is not None:
                fp_evaluations += 1
                if day is not None:
                    fp_evaluations_by_day[day] = fp_evaluations_by_day.get(day, 0) + 1
                if verdict == "FALSE_POSITIVE":
                    fp_suppressed += 1
                    if day is not None:
                        fp_suppressed_by_day[day] = fp_suppressed_by_day.get(day, 0) + 1
                elif verdict == "CONFIRMED_THREAT":
                    fp_confirmed_threats += 1
                    if day is not None:
                        fp_confirmed_threats_by_day[day] = fp_confirmed_threats_by_day.get(day, 0) + 1

            if len(by_day) > _ALERT_VOLUME_MAX_DAYS:
                break
    except Exception as exc:
        LOGGER.error("Failed reading %s: %s", alerts_path, exc)
        return dict(empty, note=f"Failed reading the alert log: {exc}")
    return {
        "by_day": by_day,
        "fp_evaluations": fp_evaluations,
        "fp_suppressed": fp_suppressed,
        "fp_confirmed_threats": fp_confirmed_threats,
        "fp_evaluations_by_day": fp_evaluations_by_day,
        "fp_suppressed_by_day": fp_suppressed_by_day,
        "fp_confirmed_threats_by_day": fp_confirmed_threats_by_day,
        "scanned_lines": scanned_lines,
        "note": (
            f"Computed from the most recent ~{_ALERT_VOLUME_MAX_SCAN_BYTES // (1024 * 1024)}MB "
            f"of the alert log (a bounded tail-scan, not a full read of what can be a "
            f"100MB+ file on a real deployment) -- may cover fewer days than requested on "
            f"a high-alert-volume network. fp_evaluations may be lower than the alert "
            f"count for the same reason, or if an older alert predates fp_verdict being "
            f"recorded at all."
        ),
    }


def _per_device_tuning_summary() -> Dict[str, Any]:
    """2026-09-16 (user request: "include the overview of per device tuning in
    console"). One cheap COUNT(DISTINCT ...) query against threshold_history
    for how many devices/categories currently have an ACTIVE (promoted, not
    rolled back) scoped autotuner override -- i.e. genuinely tuned away from
    the global default right now, not merely proposed-and-canary or
    since-rolled-back. Deliberately NOT the full per-device/category
    breakdown -- that's /api/autonomy/devices's job; this is Overview's own
    "at a glance" framing, same spirit as the rest of this endpoint.

    Returns zeros (not an error) when the graph db doesn't exist yet, same
    degradation shape open_store()'s own docstring already documents for
    every other console endpoint that reads it."""
    with open_store() as store:
        if store is None:
            return {"devices_tuned": 0, "categories_tuned": 0, "last_activity_at": None}
        row = store._conn.execute(
            "SELECT COUNT(DISTINCT device_id) AS devices_tuned, "
            "COUNT(DISTINCT device_type) AS categories_tuned, "
            "MAX(promoted_at) AS last_activity_at "
            "FROM threshold_history WHERE promoted_at IS NOT NULL AND rolled_back_at IS NULL "
            "AND (device_id IS NOT NULL OR device_type IS NOT NULL)"
        ).fetchone()
    return {
        "devices_tuned": row["devices_tuned"] or 0,
        "categories_tuned": row["categories_tuned"] or 0,
        "last_activity_at": row["last_activity_at"],
    }


@router.get("/api/overview/summary")
def get_overview_summary(token: str = Depends(verify_token)) -> dict:
    counters_raw, scrape_ok = _scrape_counters()
    security = {label: counters_raw.get(metric, 0.0) for metric, label in _SECURITY_COUNTER_NAMES.items()}
    self_healing = {label: counters_raw.get(metric, 0.0) for metric, label in _SELF_HEALING_COUNTER_NAMES.items()}

    alerts_path = Path(CONFIG.get("alert_json_path", "state/alerts.json"))
    stats = _alert_stats(alerts_path)

    # alerts_triaged lives in `security` alongside the Prometheus-sourced
    # counters for display purposes, but comes from the SAME alert-log scan as
    # alert_volume_by_day below -- see _alert_stats()'s own docstring for why.
    security["alerts_triaged"] = sum(stats["by_day"].values())
    self_healing["fp_evaluations"] = stats["fp_evaluations"]
    self_healing["fp_suppressed"] = stats["fp_suppressed"]
    self_healing["fp_confirmed_threats"] = stats["fp_confirmed_threats"]

    return {
        "counters_available": scrape_ok,
        "counters_since": (
            "pihole_blocks/router_isolations/tarpit_activations/ips_errors/domains_immunized/"
            "sigma_shifts are since last engine restart (in-process counters, not a database "
            "-- not a lifetime total). alerts_triaged/fp_evaluations/fp_suppressed/"
            "fp_confirmed_threats are computed from the alert log instead (same scanned "
            "window as the trend below) and are NOT reset by a restart."
        ),
        "security": security,
        "self_healing": self_healing,
        "alert_volume_by_day": stats["by_day"],
        "alert_volume_note": stats.get("note", ""),
        # 2026-09-16: per-day breakdowns for the console's clickable date filter.
        # alerts_triaged's own per-day numbers ARE alert_volume_by_day (identical
        # source, no separate field needed). day_filterable_metrics tells the
        # console exactly which `security`/`self_healing` keys have real
        # per-day data behind them -- pihole_blocks/router_isolations/
        # tarpit_activations/ips_errors/domains_immunized/sigma_shifts are
        # deliberately absent (Prometheus since-restart counters, no per-day
        # history exists to show) rather than the console having to guess or
        # hardcode that list itself.
        "fp_evaluations_by_day": stats["fp_evaluations_by_day"],
        "fp_suppressed_by_day": stats["fp_suppressed_by_day"],
        "fp_confirmed_threats_by_day": stats["fp_confirmed_threats_by_day"],
        "day_filterable_metrics": ["alerts_triaged", "fp_evaluations", "fp_suppressed", "fp_confirmed_threats"],
        "per_device_tuning": _per_device_tuning_summary(),
    }
