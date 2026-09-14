"""
overview_api.py -- the console's "at a glance" security-posture summary.

Origin: home_ids also ships 5 Grafana dashboards (~150 panels) covering deep
per-device forensics, threat-landscape/geo, and autotune-history -- genuinely
valuable for the operator/tuner, but too heavy a dependency (Prometheus +
Loki + Promtail + Grafana, ~460MB RAM / ~1.9GB disk measured live on .94) to
require for a consumer product. This endpoint pulls the small, highest-signal
subset into the console instead: cumulative security/self-healing counters
and a short alert-volume trend. It is NOT trying to replace the Grafana
dashboards' depth (per-device DNS z-scores, autotune threshold history, geo
maps, CL-AFPE funnel stay Grafana-only) -- just cover "is my network okay"
without requiring the observability stack at all.

Two data sources, both already running, zero new services:
1. A local self-scrape of this box's own /metrics endpoint
   (prometheus_client's start_http_server(), unconditionally started in
   core/pipeline.py's run() regardless of whether a Prometheus SERVICE is
   installed). These are in-process Counter objects -- they reset to 0 on
   every engine restart, so this is explicitly NOT a lifetime/all-time total;
   labeled as such in the response rather than overclaiming.
2. state/alerts.json, the same 170MB+ append-only NDJSON log suricata_api.py
   already reads -- via the SAME bounded backward-scan helper
   (_alert_log_utils.iter_lines_reverse()), never a full-file read.
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
from middleware.routers._alert_log_utils import iter_lines_reverse

LOGGER = logging.getLogger("home_ids.overview_api")
router = APIRouter()

_SECURITY_COUNTER_NAMES = {
    "home_ids_alerts_total": "alerts_triaged",
    "home_ids_ips_pihole_blocks_total": "pihole_blocks",
    "home_ids_ips_router_isolations_total": "router_isolations",
    "home_ids_ips_tarpit_activations_total": "tarpit_activations",
    "home_ids_ips_errors_total": "ips_errors",
}
_SELF_HEALING_COUNTER_NAMES = {
    "home_ids_fp_evaluations_total": "fp_evaluations",
    "home_ids_fp_suppressed_total": "fp_suppressed",
    "home_ids_fp_confirmed_threats_total": "fp_confirmed_threats",
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


def _scrape_counters() -> Dict[str, float]:
    port = int(CONFIG.get("metrics_port", 9105))
    try:
        resp = requests.get(f"http://127.0.0.1:{port}/metrics", timeout=3)
        resp.raise_for_status()
    except Exception as exc:
        LOGGER.debug("Failed to scrape local /metrics: %s", exc)
        return {}
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
        return {}
    return totals


def _alert_volume_by_day(alerts_path: Path) -> Dict[str, Any]:
    if not alerts_path.exists():
        return {"by_day": {}, "note": f"No alert log found at {alerts_path}."}
    by_day: Dict[str, int] = {}
    scanned_lines = 0
    try:
        for line in iter_lines_reverse(alerts_path, _ALERT_VOLUME_MAX_SCAN_BYTES):
            scanned_lines += 1
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            ts = rec.get("timestamp") if isinstance(rec, dict) else None
            if ts is None:
                continue
            day = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
            by_day[day] = by_day.get(day, 0) + 1
            if len(by_day) > _ALERT_VOLUME_MAX_DAYS:
                break
    except Exception as exc:
        LOGGER.error("Failed reading %s: %s", alerts_path, exc)
        return {"by_day": {}, "note": f"Failed reading the alert log: {exc}"}
    return {
        "by_day": by_day,
        "scanned_lines": scanned_lines,
        "note": (
            f"Computed from the most recent ~{_ALERT_VOLUME_MAX_SCAN_BYTES // (1024 * 1024)}MB "
            f"of the alert log (a bounded tail-scan, not a full read of what can be a "
            f"100MB+ file on a real deployment) -- may cover fewer days than requested on "
            f"a high-alert-volume network."
        ),
    }


@router.get("/api/overview/summary")
def get_overview_summary(token: str = Depends(verify_token)) -> dict:
    counters_raw = _scrape_counters()
    security = {label: counters_raw.get(metric, 0.0) for metric, label in _SECURITY_COUNTER_NAMES.items()}
    self_healing = {label: counters_raw.get(metric, 0.0) for metric, label in _SELF_HEALING_COUNTER_NAMES.items()}

    alerts_path = Path(CONFIG.get("alert_json_path", "state/alerts.json"))
    volume = _alert_volume_by_day(alerts_path)

    return {
        "counters_available": bool(counters_raw),
        "counters_since": "last engine restart (in-process counters, not a database -- not a lifetime total)",
        "security": security,
        "self_healing": self_healing,
        "alert_volume_by_day": volume["by_day"],
        "alert_volume_note": volume.get("note", ""),
    }
