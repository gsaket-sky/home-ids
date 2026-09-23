"""
Tests for the 2026-09-23 Argus observability work (Documentation/ARGUS_OBSERVABILITY_PLAN.md):
core/argus_metrics.py (evidence-graph exporter), core/job_result_channel.py (job -> scheduler
result pipe), core/scheduler_metrics.py (scheduler's own /metrics), pipeline.py's
record_cl_afpe_verdict(), and metrics_sync.py's decision-path codes.

The autotune tests don't re-derive "what should be active" by hand: they compare the
exporter against AutotuneEngine's own scope lookup on the same database, so the dashboard
can never drift from what the engine really uses.
"""
import json
import os
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from argus.autotune.engine import AutotuneEngine  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from core import argus_metrics, job_result_channel, scheduler_metrics  # noqa: E402
import metrics  # noqa: E402

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="pass_fds result pipe is POSIX-only (.94 is Linux)")
NOW = 1_800_000_000.0


def _value(gauge, **labels):
    for sample in gauge.collect()[0].samples:
        if all(sample.labels.get(k) == v for k, v in labels.items()):
            return sample.value
    return None


def _th(store, change_id, parameter, new_value, *, device_id=None, device_type=None, proposed_at=NOW - 5000,
        canary_until=None, promoted_at=None, rolled_back_at=None):
    store._conn.execute(
        "INSERT INTO threshold_history (change_id, device_id, parameter, old_value, new_value, proposed_at, "
        "canary_until, promoted_at, rolled_back_at, device_type) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (change_id, device_id, parameter, 0.0, new_value, proposed_at, canary_until, promoted_at,
         rolled_back_at, device_type))


@pytest.fixture
def graph(tmp_path):
    db = tmp_path / "graph.db"
    store = GraphStore(str(db))
    for dev, lbl, typ in [("devA", "laptop-a", "laptop"), ("devB", "tv-b", "smart_tv"), ("orphan", "old-a", "laptop")]:
        store.upsert_device(dev, display_label=lbl, device_type=typ, timestamp=NOW - 9000)
    store.merge_device("orphan", "devA", timestamp=NOW - 8000)
    store.update_device_metadata("devB", {"sigma_shift": 0.75}, timestamp=NOW - 100)

    # autotune: global promoted then superseded, category promoted, device promoted on the
    # ORPHAN id (must resolve to devA), one rolled back, one live canary.
    p = "fp_combined_suppress_threshold"
    _th(store, "g1", p, 0.80, promoted_at=NOW - 4000)
    _th(store, "g2", p, 0.78, promoted_at=NOW - 3000)
    _th(store, "c1", p, 0.70, device_type="smart_tv", promoted_at=NOW - 2000)
    _th(store, "d1", p, 0.65, device_id="orphan", promoted_at=NOW - 1000)
    _th(store, "d2", p, 0.60, device_id="devB", promoted_at=NOW - 900, rolled_back_at=NOW - 800)
    _th(store, "d3", p, 0.62, device_id="devB", canary_until=NOW + 3600)

    # alert outcomes: 2 fired + 1 suppressed for devA in the last day, 1 fired 3 days ago
    for i, (status, ts) in enumerate([("FIRED", NOW - 60), ("FIRED", NOW - 120), ("SUPPRESSED_AUTONOMOUS", NOW - 180),
                                      ("FIRED", NOW - 3 * 86400)]):
        dec = store.insert_decision("devA", ts, "HIGH", "hypothesis_high", 0.85, 7.0)
        store._conn.execute(
            "INSERT INTO alert_events (alert_event_id, decision_id, device_id, timestamp, status, "
            "autotune_state_json, alert_payload_json, backfilled) VALUES (?,?,?,?,?,?,?,0)",
            (f"ae{i}", dec, "devA", ts, status, "{}", "{}"))
    store._conn.execute("INSERT OR IGNORE INTO hypotheses (hypothesis_id, kind) VALUES ('BENIGN_X', 'benign')")
    for dev, fp, trust in [("devA", "f1", 0.2), ("orphan", "f2", 0.6), ("devB", "f3", 0.9)]:
        store._conn.execute(
            "INSERT INTO cl_afpe_trust (device_id, behavior_fingerprint, destination_class, hypothesis_id, "
            "evidence_family, trust_value, n, last_updated) VALUES (?,?,?,?,?,?,?,?)",
            (dev, fp, "cdn", "BENIGN_X", "dns", trust, 3, NOW))
    for dev, regime in [("devA", 0), ("devA", 2), ("devB", 1)]:
        store._conn.execute(
            "INSERT INTO device_baselines (device_id, metric, hour, regime_id, model_kind, n, updated_at) "
            "VALUES (?,?,?,?,?,?,?)", (dev, f"m{regime}", 1, regime, "gaussian", 10, NOW))
    store._maybe_commit()
    store._conn.commit()
    yield store, db
    store.close()


def test_canonical_device_map_follows_merges_and_survives_cycles():
    m = argus_metrics.canonical_device_map([("a", "b"), ("b", "c"), ("c", None), ("x", "y"), ("y", "x")])
    assert m["a"] == "c" and m["b"] == "c" and m["c"] == "c"
    assert m["x"] in ("x", "y") and m["y"] in ("x", "y")  # cycle: terminates, no exception


def test_exported_autotune_values_match_the_engines_own_lookup(graph):
    store, db = graph
    exp = argus_metrics.ArgusMetricsExporter(db, {"fp_combined_suppress_threshold": 0.8})
    assert exp.run_once(now=NOW) is True
    engine = AutotuneEngine(store)
    p = "fp_combined_suppress_threshold"
    cases = [("global", "", "", engine._promoted_value_at_scope(p, None, None)),
             ("category", "smart_tv", "", engine._promoted_value_at_scope(p, None, "smart_tv")),
             ("device", "devA", "laptop-a", engine._promoted_value_at_scope(p, "devA", None))]
    for scope, target, host, engine_value in cases:
        assert engine_value is not None
        assert _value(metrics.autotune_value, parameter=p, scope=scope, target=target, hostname=host) == pytest.approx(engine_value)
    # devB's only promotion was rolled back -> the engine has nothing at device scope, nor may the exporter
    assert engine._promoted_value_at_scope(p, "devB", None) is None
    assert _value(metrics.autotune_value, parameter=p, scope="device", target="devB") is None
    assert _value(metrics.autotune_canary_value, parameter=p, scope="device", target="devB") == pytest.approx(0.62)
    assert _value(metrics.autotune_config_value, parameter=p) == pytest.approx(0.8)
    assert _value(metrics.autotune_changes, parameter=p, scope="global", status="superseded") == 1
    assert _value(metrics.autotune_changes, parameter=p, scope="device", status="rolled_back") == 1


def test_alert_outcomes_trust_regimes_and_sigma_per_canonical_device(graph):
    _, db = graph
    argus_metrics.ArgusMetricsExporter(db, {}).run_once(now=NOW)
    assert _value(metrics.argus_alert_events_24h, status="FIRED") == 2
    assert _value(metrics.argus_alert_events_retained, status="FIRED") == 3
    assert _value(metrics.device_alerts_fired_24h, device="devA", hostname="laptop-a") == 2
    assert _value(metrics.device_alerts_suppressed_24h, device="devA", hostname="laptop-a") == 1
    # orphan's trust row is folded into its canonical device: mean(0.2, 0.6)
    assert _value(metrics.device_learned_trust, device="devA", hostname="laptop-a") == pytest.approx(0.4)
    assert _value(metrics.device_learned_trust, device="orphan") is None
    assert _value(metrics.device_baseline_regime_shifts, device="devA", hostname="laptop-a") == 2
    assert _value(metrics.device_sigma_shift, device="devB", hostname="tv-b") == pytest.approx(0.75)
    assert _value(metrics.cl_afpe_trust_entries, destination_class="cdn") == 3


def test_vanished_label_sets_are_removed_not_left_stale(graph):
    store, db = graph
    exp = argus_metrics.ArgusMetricsExporter(db, {})
    exp.run_once(now=NOW)
    assert _value(metrics.device_alerts_suppressed_24h, device="devA", hostname="laptop-a") == 1
    exp.run_once(now=NOW + 2 * 86400)  # a day later nothing is inside the 24h window any more
    assert _value(metrics.device_alerts_suppressed_24h, device="devA", hostname="laptop-a") is None


def test_pass_timeout_abandons_cleanly_and_keeps_previous_values(graph):
    _, db = graph
    exp = argus_metrics.ArgusMetricsExporter(db, {})
    exp.run_once(now=NOW)
    before = _value(metrics.argus_alert_events_24h, status="FIRED")
    slow = argus_metrics.ArgusMetricsExporter(db, {}, pass_timeout_seconds=-1.0)  # deadline already passed
    assert slow.run_once(now=NOW) is False
    assert _value(metrics.argus_alert_events_24h, status="FIRED") == before


def test_exporter_never_writes(graph):
    _, db = graph
    mtime = db.stat().st_mtime_ns
    argus_metrics.ArgusMetricsExporter(db, {}).run_once(now=NOW)
    assert db.stat().st_mtime_ns == mtime


# ------------------------------------------------------------------ result channel / scheduler metrics

def test_numeric_and_per_device_field_flattening():
    extra = {"reviewed": 96, "stopped_for_deadline": True, "note": "x",
             "budget_gb": {"graph_db": 9.0, "zeek_logs": 3.0},
             "findings_by_device": {"d1": 2, "d2": 0}}
    assert job_result_channel.numeric_fields(extra) == {
        "reviewed": 96.0, "stopped_for_deadline": 1.0, "budget_gb.graph_db": 9.0, "budget_gb.zeek_logs": 3.0}
    assert job_result_channel.per_device_fields(extra) == {"findings_by_device": {"d1": 2.0, "d2": 0.0}}


def test_publish_is_a_noop_without_a_channel(monkeypatch):
    monkeypatch.delenv(job_result_channel.RESULT_FD_ENV, raising=False)
    assert job_result_channel.publish("x", 1.0, {"a": 1}) is False


@POSIX_ONLY
def test_result_pipe_round_trip_through_a_real_child_process():
    import subprocess
    read_fd, write_fd = job_result_channel.open_channel()
    code = ("import sys; sys.path.insert(0, %r); from utils import write_job_health; import tempfile; "
            "write_job_health(tempfile.mkdtemp(), 'demo_task', 12.5, extra={'reviewed': 3, 'findings_by_device': {'d1': 4}})"
            % str(SRC_DIR))
    proc = subprocess.Popen([sys.executable, "-c", code], pass_fds=(write_fd,), env=job_result_channel.child_env(write_fd))
    os.close(write_fd)
    proc.wait(timeout=60)
    result = job_result_channel.collect(read_fd)
    assert result["job"] == "demo_task" and result["status"] == "success"
    assert result["duration_seconds"] == pytest.approx(12.5)
    assert result["extra"]["findings_by_device"] == {"d1": 4}


def test_scheduler_exit_accounting_and_last_run_semantics():
    now = time.time()
    scheduler_metrics.record_exit("t_obs", 0, {"status": "success", "duration_seconds": 7.0,
                                               "extra": {"reviewed": 5, "findings_by_device": {"d1": 1, "d2": 2}}}, now)
    assert _value(scheduler_metrics.task_result, task="t_obs", field="reviewed") == 5
    assert _value(scheduler_metrics.task_last_success, task="t_obs") == pytest.approx(now)
    scheduler_metrics.record_exit("t_obs", 0, {"status": "error", "duration_seconds": 1.0,
                                               "extra": {"error": "boom", "findings_by_device": {"d1": 1}}}, now + 5)
    assert _value(scheduler_metrics.task_last_success, task="t_obs") == pytest.approx(now)  # an error is not a success
    assert _value(scheduler_metrics.task_result_by_device, task="t_obs", field="findings_by_device", device="d2") is None
    assert _value(scheduler_metrics.task_runs_total, task="t_obs", outcome="error") == 1


def test_scheduler_kill_is_counted_once_not_also_as_a_failure():
    scheduler_metrics.record_kill({"job": "t_kill", "pid": 1, "active_minutes": 31.0, "budget_minutes": 30})
    scheduler_metrics.record_exit("t_kill", -9, None, time.time(), killed=True)
    assert _value(scheduler_metrics.task_kills_total, task="t_kill") == 1
    assert _value(scheduler_metrics.task_runs_total, task="t_kill", outcome="killed") == 1
    assert _value(scheduler_metrics.task_runs_total, task="t_kill", outcome="failed") is None


def test_disabled_tasks_drop_out_of_the_enabled_gauge():
    scheduler_metrics.sync_enabled_tasks({"t_a": 30.0, "t_b": 10.0})
    assert _value(scheduler_metrics.task_enabled, task="t_b") == 1
    scheduler_metrics.sync_enabled_tasks({"t_a": 30.0})
    assert _value(scheduler_metrics.task_enabled, task="t_b") is None


def test_job_result_status_from_extra():
    from utils import job_result_status
    assert job_result_status(None) == "success"
    assert job_result_status({"error": "x"}) == "error"
    assert job_result_status({"skipped": "disabled"}) == "skipped"


# ------------------------------------------------------------------ CL-AFPE + decision paths

def test_cl_afpe_verdict_accounting():
    from core.pipeline import record_cl_afpe_verdict
    ev0 = metrics.fp_engine_evaluations_total._value.get()
    sup0 = metrics.fp_engine_suppressed_total._value.get()
    hs0 = metrics.fp_engine_confirmed_threats_total._value.get()
    payload = {"device": {"id": "devT", "hostname": "host-t"}}
    record_cl_afpe_verdict({"verdict": "FALSE_POSITIVE", "stage": "TRUST_CACHE", "confidence": 1.0, "suppress": True}, payload)
    record_cl_afpe_verdict({"verdict": "CONFIRMED_THREAT", "stage": "STAGE_1_HARD_STOP", "confidence": 0.0, "suppress": False}, payload)
    assert metrics.fp_engine_evaluations_total._value.get() == ev0 + 2
    assert metrics.fp_engine_suppressed_total._value.get() == sup0 + 1
    assert metrics.fp_engine_confirmed_threats_total._value.get() == hs0 + 1
    assert _value(metrics.fp_engine_confidence_score, device="devT", hostname="host-t") == 0.0


def test_every_real_decision_path_has_a_stable_code():
    import re
    from core.metrics_sync import DECISION_PATH_CODES
    src = (SRC_DIR / "argus" / "decision" / "engine.py").read_text(encoding="utf-8")
    paths = set(re.findall(r'decision_path\s*=\s*"([a-z0-9_]+)"', src))
    assert paths, "no decision paths found -- engine.py layout changed, update this test"
    assert paths <= set(DECISION_PATH_CODES), sorted(paths - set(DECISION_PATH_CODES))
    assert len(set(DECISION_PATH_CODES.values())) == len(DECISION_PATH_CODES)
