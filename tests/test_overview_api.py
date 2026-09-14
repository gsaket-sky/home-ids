"""
Tests for src/middleware/routers/overview_api.py -- the console's "Overview"
tab: security/self-healing counters and a bounded alert-volume-by-day trend
(via the same _alert_log_utils.iter_lines_reverse() suricata_api.py already
uses). Direct-call style, same convention as the other middleware tests in
this suite -- requests.get is monkeypatched, never a real network call.
"""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from middleware.routers import overview_api  # noqa: E402


def _write_jsonl(path, records):
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def _day_ts(days_ago, hour=12):
    dt = datetime.now(tz=timezone.utc).replace(hour=hour, minute=0, second=0, microsecond=0)
    return dt.timestamp() - days_ago * 86400


# --- _alert_stats: volume-by-day (unchanged behavior) ---------------------------

def test_alert_stats_buckets_by_calendar_day(tmp_path):
    path = tmp_path / "alerts.json"
    _write_jsonl(path, [
        {"timestamp": _day_ts(0)}, {"timestamp": _day_ts(0)}, {"timestamp": _day_ts(1)},
    ])
    result = overview_api._alert_stats(path)
    assert sum(result["by_day"].values()) == 3
    assert len(result["by_day"]) == 2


def test_alert_stats_missing_file_returns_empty_with_note(tmp_path):
    result = overview_api._alert_stats(tmp_path / "does_not_exist.json")
    assert result["by_day"] == {}
    assert "No alert log found" in result["note"]


def test_alert_stats_skips_corrupt_lines_and_missing_timestamps(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text(
        "{not valid json\n"
        + json.dumps({"no_timestamp_field": True}) + "\n"
        + json.dumps({"timestamp": _day_ts(0)}) + "\n",
        encoding="utf-8",
    )
    result = overview_api._alert_stats(path)
    assert sum(result["by_day"].values()) == 1


def test_alert_stats_respects_max_days_cutoff(tmp_path, monkeypatch):
    monkeypatch.setattr(overview_api, "_ALERT_VOLUME_MAX_DAYS", 2)
    path = tmp_path / "alerts.json"
    _write_jsonl(path, [{"timestamp": _day_ts(d)} for d in range(10)])
    result = overview_api._alert_stats(path)
    assert len(result["by_day"]) <= 4


def test_alert_stats_note_mentions_bounded_scan(tmp_path):
    path = tmp_path / "alerts.json"
    _write_jsonl(path, [{"timestamp": _day_ts(0)}])
    result = overview_api._alert_stats(path)
    assert "bounded" in result["note"].lower()


# --- _alert_stats: fp_verdict tallies (the actual bug fix) -----------------------
# BUGFIX regression: found live that Prometheus's fp_evaluations_total/
# fp_suppressed_total/fp_confirmed_threats_total never increment when
# cl_afpe_engine=="v13" (.94's real live config) -- the v13 CL-AFPE engine has
# zero Prometheus instrumentation of its own, and only falls back to the
# legacy AutonomousFPEngine.evaluate() (where those counters live) on error.
# pipeline.py writes the REAL verdict onto every alert record regardless of
# which engine produced it -- these tests assert that source is read
# correctly instead.

def test_alert_stats_counts_fp_verdicts(tmp_path):
    path = tmp_path / "alerts.json"
    _write_jsonl(path, [
        {"timestamp": _day_ts(0), "fp_verdict": {"verdict": "FALSE_POSITIVE"}},
        {"timestamp": _day_ts(0), "fp_verdict": {"verdict": "FALSE_POSITIVE"}},
        {"timestamp": _day_ts(0), "fp_verdict": {"verdict": "CONFIRMED_THREAT"}},
        {"timestamp": _day_ts(0), "fp_verdict": {"verdict": "UNCERTAIN"}},
    ])
    result = overview_api._alert_stats(path)
    assert result["fp_evaluations"] == 4
    assert result["fp_suppressed"] == 2
    assert result["fp_confirmed_threats"] == 1


def test_alert_stats_alerts_without_fp_verdict_do_not_count_as_evaluations(tmp_path):
    """An alert record predating this field, or one from a code path that
    never reached FP evaluation, must not be silently counted as evaluated."""
    path = tmp_path / "alerts.json"
    _write_jsonl(path, [
        {"timestamp": _day_ts(0)},  # no fp_verdict key at all
        {"timestamp": _day_ts(0), "fp_verdict": {"verdict": "FALSE_POSITIVE"}},
    ])
    result = overview_api._alert_stats(path)
    assert result["fp_evaluations"] == 1
    assert result["fp_suppressed"] == 1


def test_alert_stats_fp_evaluations_can_be_lower_than_total_alert_count(tmp_path):
    """The exact real-world shape this bug produced: real alert volume high,
    but only a subset (or none) carry a usable fp_verdict -- must not crash
    or silently inflate fp_evaluations to match alert count."""
    path = tmp_path / "alerts.json"
    _write_jsonl(path, [{"timestamp": _day_ts(0)} for _ in range(20)])  # zero fp_verdict anywhere
    result = overview_api._alert_stats(path)
    assert sum(result["by_day"].values()) == 20
    assert result["fp_evaluations"] == 0


# --- _scrape_counters ------------------------------------------------------------
# Only pihole_blocks/router_isolations/tarpit_activations/ips_errors/
# domains_immunized/sigma_shifts are scraped now -- alerts_total/
# fp_evaluations_total/fp_suppressed_total/fp_confirmed_threats_total were
# removed from the scraped set entirely (see overview_api.py's own docstring).

_SAMPLE_METRICS_TEXT = """
# HELP home_ids_ips_pihole_blocks_total Total automated domain blocks executed
# TYPE home_ids_ips_pihole_blocks_total counter
home_ids_ips_pihole_blocks_total{device="a",hostname="h1"} 12.0
home_ids_ips_pihole_blocks_total{device="b",hostname="h2"} 3.0
# HELP home_ids_fp_domains_immunized_total Total unique eTLD+1 base domains added to the trust cache
# TYPE home_ids_fp_domains_immunized_total counter
home_ids_fp_domains_immunized_total{source="autonomous"} 45.0
# HELP home_ids_alerts_total IDS alerts triggered
# TYPE home_ids_alerts_total counter
home_ids_alerts_total{device="a"} 999.0
# HELP home_ids_unrelated_metric Something this endpoint doesn't care about
# TYPE home_ids_unrelated_metric counter
home_ids_unrelated_metric 999.0
"""


def test_scrape_counters_sums_across_label_combinations(monkeypatch):
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text=_SAMPLE_METRICS_TEXT, raise_for_status=lambda: None,
    ))
    result, scrape_ok = overview_api._scrape_counters()
    assert scrape_ok is True
    assert result["home_ids_ips_pihole_blocks_total"] == 15.0  # 12 + 3, summed across devices
    assert result["home_ids_fp_domains_immunized_total"] == 45.0


def test_scrape_counters_ignores_metrics_not_in_our_list(monkeypatch):
    """alerts_total is deliberately no longer in the scraped set (moved to
    the alert-log scan instead) -- must not appear even though it's present
    in the raw /metrics text."""
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text=_SAMPLE_METRICS_TEXT, raise_for_status=lambda: None,
    ))
    result, _ = overview_api._scrape_counters()
    assert "home_ids_unrelated_metric" not in result
    assert "home_ids_alerts_total" not in result


def test_scrape_counters_connection_failure_returns_empty_and_not_ok(monkeypatch):
    def _raise(*a, **kw):
        raise ConnectionError("nope")
    monkeypatch.setattr(overview_api.requests, "get", _raise)
    assert overview_api._scrape_counters() == ({}, False)


def test_scrape_counters_http_error_status_returns_empty_and_not_ok(monkeypatch):
    def _bad_status():
        raise Exception("500")
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text="", raise_for_status=_bad_status,
    ))
    assert overview_api._scrape_counters() == ({}, False)


def test_scrape_counters_succeeds_but_finds_nothing_is_still_ok(monkeypatch):
    """BUGFIX regression (found live, 2026-09-14, right after the fp_verdict
    fix's own deploy): every scraped metric is a LABELED counter -- one with
    no observations yet exports ZERO sample lines at all, not even a 0. This
    is the common case right after a restart (no pihole blocks/router
    isolations/etc. have happened yet), not a scrape failure -- must report
    scrape_ok=True with empty totals, not conflate the two."""
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text="# a real response with none of our metric names present\n",
        raise_for_status=lambda: None,
    ))
    result, scrape_ok = overview_api._scrape_counters()
    assert result == {}
    assert scrape_ok is True


# --- get_overview_summary (end to end) ------------------------------------------

def test_get_overview_summary_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text=_SAMPLE_METRICS_TEXT, raise_for_status=lambda: None,
    ))
    alerts_path = tmp_path / "alerts.json"
    _write_jsonl(alerts_path, [
        {"timestamp": _day_ts(0), "fp_verdict": {"verdict": "FALSE_POSITIVE"}},
        {"timestamp": _day_ts(0), "fp_verdict": {"verdict": "CONFIRMED_THREAT"}},
    ])
    monkeypatch.setattr(overview_api.CONFIG, "get", lambda key, default=None: {
        "metrics_port": 9105, "alert_json_path": str(alerts_path),
    }.get(key, default))

    result = overview_api.get_overview_summary(token="test")
    assert result["counters_available"] is True
    # alerts_triaged now comes from the alert log, not the (no-longer-scraped)
    # Prometheus counter (999.0 in the sample text) -- must be the real count.
    assert result["security"]["alerts_triaged"] == 2
    assert result["security"]["pihole_blocks"] == 15.0
    assert result["self_healing"]["fp_suppressed"] == 1
    assert result["self_healing"]["fp_confirmed_threats"] == 1
    assert result["self_healing"]["domains_immunized"] == 45.0
    assert result["security"]["router_isolations"] == 0.0  # not in the sample text -- must default to 0, not KeyError


def test_get_overview_summary_survives_scrape_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(overview_api.requests, "get", lambda *a, **kw: (_ for _ in ()).throw(ConnectionError()))
    monkeypatch.setattr(overview_api.CONFIG, "get", lambda key, default=None: {
        "metrics_port": 9105, "alert_json_path": str(tmp_path / "alerts.json"),
    }.get(key, default))
    result = overview_api.get_overview_summary(token="test")  # must not raise
    assert result["counters_available"] is False
    assert result["security"]["pihole_blocks"] == 0.0


def test_get_overview_summary_alerts_triaged_matches_volume_trend_sum(tmp_path, monkeypatch):
    """BUGFIX regression: alerts_triaged and alert_volume_by_day used to come
    from two different sources (Prometheus since-restart vs. the alert log)
    and could silently disagree. They must now always be internally
    consistent -- same scan, same window."""
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text="", raise_for_status=lambda: None,
    ))
    alerts_path = tmp_path / "alerts.json"
    _write_jsonl(alerts_path, [{"timestamp": _day_ts(d % 3)} for d in range(9)])
    monkeypatch.setattr(overview_api.CONFIG, "get", lambda key, default=None: {
        "metrics_port": 9105, "alert_json_path": str(alerts_path),
    }.get(key, default))

    result = overview_api.get_overview_summary(token="test")
    assert result["security"]["alerts_triaged"] == sum(result["alert_volume_by_day"].values())


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
