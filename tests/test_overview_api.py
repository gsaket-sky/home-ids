"""
Tests for src/middleware/routers/overview_api.py -- the console's "Overview"
tab: cumulative security/self-healing counters (via a local self-scrape of
/metrics) and a bounded alert-volume-by-day trend (via the same
_alert_log_utils.iter_lines_reverse() suricata_api.py already uses). Direct-
call style, same convention as the other middleware tests in this suite --
requests.get is monkeypatched, never a real network call.
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


# --- _alert_volume_by_day -----------------------------------------------------

def test_alert_volume_buckets_by_calendar_day(tmp_path):
    path = tmp_path / "alerts.json"
    _write_jsonl(path, [
        {"timestamp": _day_ts(0)}, {"timestamp": _day_ts(0)}, {"timestamp": _day_ts(1)},
    ])
    result = overview_api._alert_volume_by_day(path)
    assert sum(result["by_day"].values()) == 3
    assert len(result["by_day"]) == 2


def test_alert_volume_missing_file_returns_empty_with_note(tmp_path):
    result = overview_api._alert_volume_by_day(tmp_path / "does_not_exist.json")
    assert result["by_day"] == {}
    assert "No alert log found" in result["note"]


def test_alert_volume_skips_corrupt_lines_and_missing_timestamps(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text(
        "{not valid json\n"
        + json.dumps({"no_timestamp_field": True}) + "\n"
        + json.dumps({"timestamp": _day_ts(0)}) + "\n",
        encoding="utf-8",
    )
    result = overview_api._alert_volume_by_day(path)
    assert sum(result["by_day"].values()) == 1


def test_alert_volume_respects_max_days_cutoff(tmp_path, monkeypatch):
    monkeypatch.setattr(overview_api, "_ALERT_VOLUME_MAX_DAYS", 2)
    path = tmp_path / "alerts.json"
    _write_jsonl(path, [{"timestamp": _day_ts(d)} for d in range(10)])  # 10 distinct days, newest first on disk order doesn't matter -- reverse-scanned
    result = overview_api._alert_volume_by_day(path)
    # stops shortly after exceeding max_days, not necessarily exactly max_days+1 -- just must not silently scan all 10
    assert len(result["by_day"]) <= 4


def test_alert_volume_note_mentions_bounded_scan(tmp_path):
    path = tmp_path / "alerts.json"
    _write_jsonl(path, [{"timestamp": _day_ts(0)}])
    result = overview_api._alert_volume_by_day(path)
    assert "bounded" in result["note"].lower()


# --- _scrape_counters ----------------------------------------------------------

_SAMPLE_METRICS_TEXT = """
# HELP home_ids_alerts_total IDS alerts triggered
# TYPE home_ids_alerts_total counter
home_ids_alerts_total{device="a",hostname="h1",device_type="laptop"} 12.0
home_ids_alerts_total{device="b",hostname="h2",device_type="phone"} 3.0
# HELP home_ids_fp_suppressed_total Total alerts autonomously classified as False Positive
# TYPE home_ids_fp_suppressed_total counter
home_ids_fp_suppressed_total 45.0
# HELP home_ids_unrelated_metric Something this endpoint doesn't care about
# TYPE home_ids_unrelated_metric counter
home_ids_unrelated_metric 999.0
"""


def test_scrape_counters_sums_across_label_combinations(monkeypatch):
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text=_SAMPLE_METRICS_TEXT, raise_for_status=lambda: None,
    ))
    result = overview_api._scrape_counters()
    assert result["home_ids_alerts_total"] == 15.0  # 12 + 3, summed across devices
    assert result["home_ids_fp_suppressed_total"] == 45.0


def test_scrape_counters_ignores_metrics_not_in_our_list(monkeypatch):
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text=_SAMPLE_METRICS_TEXT, raise_for_status=lambda: None,
    ))
    result = overview_api._scrape_counters()
    assert "home_ids_unrelated_metric" not in result


def test_scrape_counters_connection_failure_returns_empty(monkeypatch):
    def _raise(*a, **kw):
        raise ConnectionError("nope")
    monkeypatch.setattr(overview_api.requests, "get", _raise)
    assert overview_api._scrape_counters() == {}


def test_scrape_counters_http_error_status_returns_empty(monkeypatch):
    def _bad_status():
        raise Exception("500")
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text="", raise_for_status=_bad_status,
    ))
    assert overview_api._scrape_counters() == {}


# --- get_overview_summary (end to end) ------------------------------------------

def test_get_overview_summary_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(overview_api.requests, "get", lambda url, timeout: SimpleNamespace(
        text=_SAMPLE_METRICS_TEXT, raise_for_status=lambda: None,
    ))
    alerts_path = tmp_path / "alerts.json"
    _write_jsonl(alerts_path, [{"timestamp": _day_ts(0)}])
    monkeypatch.setattr(overview_api.CONFIG, "get", lambda key, default=None: {
        "metrics_port": 9105, "alert_json_path": str(alerts_path),
    }.get(key, default))

    result = overview_api.get_overview_summary(token="test")
    assert result["counters_available"] is True
    assert result["security"]["alerts_triaged"] == 15.0
    assert result["self_healing"]["fp_suppressed"] == 45.0
    assert result["security"]["router_isolations"] == 0.0  # not in the sample text -- must default to 0, not KeyError
    assert sum(result["alert_volume_by_day"].values()) == 1


def test_get_overview_summary_survives_scrape_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(overview_api.requests, "get", lambda *a, **kw: (_ for _ in ()).throw(ConnectionError()))
    monkeypatch.setattr(overview_api.CONFIG, "get", lambda key, default=None: {
        "metrics_port": 9105, "alert_json_path": str(tmp_path / "alerts.json"),
    }.get(key, default))
    result = overview_api.get_overview_summary(token="test")  # must not raise
    assert result["counters_available"] is False
    assert result["security"]["alerts_triaged"] == 0.0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
