"""
Scheduler resilience (MASTER_TODO 0c Step 2, 2026-10-12). On .94 the 1 GB scheduler container was OOM-killed three times
in two days; a killed job recorded nothing, so the backtest showed "last success 10-07" with no reason.

- a job that ends without reporting (killed, crashed) is recorded as a failure with its reason -- signal, out of memory
  (the cgroup's oom_kill counter rose), or overrun budget -- and every run lands in state/scheduler_runs.jsonl;
- a job that died together with the scheduler or its container is recorded at the next start;
- the scheduler applies live overrides (state/config_overrides.json) like the engine: never to static keys;
- the health manager reports a failed last run at once, with its reason, and the backtest gate after 36 h.
"""
import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(SRC / "scripts"))

import scheduler  # noqa: E402
from core import job_coordinator  # noqa: E402


@pytest.mark.parametrize("args,expected", [
    ((-9, False, 3, 4, 40), "killed: out of memory"),
    ((-9, False, 3, 3, 40), "killed by signal 9"),
    ((-9, False, None, None, 40), "killed by signal 9"),
    ((1, False, 0, 0, 40), "exited with code 1 without reporting a result"),
    ((-9, True, 0, 1, 40), "stopped: ran past its time budget (40 min)"),
])
def test_failure_reason(args, expected):
    assert scheduler.failure_reason(*args) == expected


def test_live_overrides_apply_except_static_keys_and_respect_the_master_switch(tmp_path):
    from config import _STATIC_KEYS
    static_key = sorted(_STATIC_KEYS)[0]
    path = tmp_path / "config_overrides.json"
    path.write_text(json.dumps({
        "autotune_enabled": {"value": False, "baseline": True},
        static_key: {"value": "changed", "baseline": "x"},
        "ips_enabled": {"value": False, "baseline": True},
        "not_an_entry": 5}), encoding="utf-8")
    cfg = scheduler._apply_live_overrides({"autotune_enabled": True, static_key: "orig", "ips_tarpit_enabled": True},
                                          path)
    assert cfg["autotune_enabled"] is False                                    # reaches the scheduler now
    assert cfg[static_key] == "orig"                                           # never a static key
    assert cfg["ips_tarpit_enabled"] is False                                  # master switch enforced
    assert "not_an_entry" not in cfg
    assert scheduler._apply_live_overrides({"a": 1}, tmp_path / "missing.json") == {"a": 1}


def test_record_run_appends_one_line_per_run(tmp_path):
    scheduler.record_run(tmp_path, {"job": "backtest_job", "outcome": "failed", "reason": "killed: out of memory"})
    scheduler.record_run(tmp_path, {"job": "live_prune", "outcome": "success", "reason": None})
    lines = (tmp_path / "scheduler_runs.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(x)["job"] for x in lines] == ["backtest_job", "live_prune"]


def test_oom_counter_is_none_where_there_is_no_cgroup(monkeypatch):
    monkeypatch.setattr(scheduler, "Path", lambda p: Path("/nonexistent-cgroup-path"))
    assert scheduler._oom_kills() is None


def test_dead_occupant_is_read_without_clearing(tmp_path, monkeypatch):
    slot = {"job": "backtest_job", "pid": 999999, "started_at": 1000.0, "priority": 2}
    path = job_coordinator._lock_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(slot), encoding="utf-8")
    monkeypatch.setattr(job_coordinator, "is_pid_alive", lambda pid: False)
    assert job_coordinator.dead_occupant(tmp_path)["job"] == "backtest_job"
    assert path.exists()                                                       # still there for _read_slot to heal
    monkeypatch.setattr(job_coordinator, "is_pid_alive", lambda pid: True)
    assert job_coordinator.dead_occupant(tmp_path) is None


def test_shipped_night_schedule_runs_in_logical_order_without_overlap():
    """The night jobs share one slot: cleanup, then the backtest, then autotune, which needs that night's backtest
    (four jobs used to start between 03:00 and 03:30, autotune before the backtest)."""
    import yaml
    path = Path(__file__).resolve().parent.parent / "docker" / "config" / "ids" / "config.yaml.example"
    flat = scheduler._flatten_config_categories(yaml.safe_load(path.read_text(encoding="utf-8")))

    def minute_of_day(cron):
        m, h = cron.split()[:2]
        return int(h) * 60 + int(m)
    jobs = flat["scheduler"]
    t = {name: minute_of_day(jobs[name]["cron"]) for name in ("live_prune", "disk_budget_governor", "backtest_job")}
    t["autotune"] = minute_of_day(flat["autotune_schedule_cron"])
    assert t["live_prune"] < t["disk_budget_governor"] < t["backtest_job"] < t["autotune"]
    assert t["backtest_job"] + int(jobs["backtest_job"]["max_runtime_minutes"]) <= t["autotune"]   # done before


def test_backtest_streams_decision_payloads(tmp_path):
    """The nightly backtest read every decision payload of a scope into memory at once (fetchall), "every later
    decision" of a device for each near miss -- the 1 GB scheduler container was OOM-killed during the nights. The
    reads are now cursors iterated once: peak memory stays at about one payload, not the window."""
    import tracemalloc
    from argus.graph.store import GraphStore
    from argus.ops import backtest_job
    store = GraphStore(str(tmp_path / "g.db"))
    blob = "x" * 20_000
    for i in range(1500):                                                       # ~30 MB of payloads
        store.insert_decision("d1", 1000.0 + i, "BENIGN", "benign", 0.0, 0.0, raw_payload={"pad": blob, "i": i})
    store._maybe_commit()
    rows = backtest_job._decision_rows(store, "decision_id, raw_payload_json", "d1", "AND timestamp > ?", (0.0,))
    assert not isinstance(rows, list)                                          # a cursor, not the whole window
    tracemalloc.start()
    n = sum(1 for _ in rows)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert n == 1500 and peak < 5_000_000, peak                                 # one payload at a time


def test_llm_review_reads_only_reviewable_decisions_and_ranks_them(tmp_path):
    from argus.graph.store import GraphStore
    from argus.ops.live_llm_review import review_priority, _REVIEWABLE_STATES
    store = GraphStore(str(tmp_path / "g.db"))
    for i, (state, srcs) in enumerate([("SUSPICIOUS", 1), ("BENIGN", 0), ("HIGH", 2), ("SUSPICIOUS", 3),
                                       ("CRITICAL", 1), ("BENIGN", 0), ("HIGH", 3)]):
        store.insert_decision("d1", 1000.0 + i, state, "p", 0.5, 5.0, raw_payload={"independent_sources": srcs})
    store._maybe_commit()
    got = store.get_decisions_since(0.0, states=_REVIEWABLE_STATES)
    assert sorted(d["state"] for d in got) == ["CRITICAL", "HIGH", "HIGH", "SUSPICIOUS", "SUSPICIOUS"]   # no BENIGN
    assert len(store.get_decisions_since(0.0)) == 7                            # unchanged without `states`
    order = [(d["state"], d["raw_payload"]["independent_sources"]) for d in sorted(got, key=review_priority)]
    assert order == [("CRITICAL", 1), ("HIGH", 3), ("HIGH", 2), ("SUSPICIOUS", 3), ("SUSPICIOUS", 1)]


# ------------------------------------------------------------------------------------------------ health manager

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_health_manager_state_machine import FakeConfig, FakeAlertManager  # noqa: E402
from core.health_manager import HealthManager, HEALTHY, DEGRADED  # noqa: E402

NOW = 1_000_000_000.0


@pytest.fixture
def hm(tmp_path):
    return HealthManager(config=FakeConfig(), alert_manager=FakeAlertManager(), state_dir=str(tmp_path))


def _jobs(hm, data):
    (Path(hm.state_dir) / "job_health.json").write_text(json.dumps(data), encoding="utf-8")
    hm._evaluate_job_health_components(NOW)


def test_a_failed_last_run_is_degraded_at_once_with_its_reason(hm):
    hm.config = FakeConfig(scheduler={"backtest_job": {"enabled": True, "cron": "30 3 * * *"}})
    _jobs(hm, {"backtest_job": {"last_success": NOW - 2 * 3600, "last_failure": NOW - 600,
                                "error": "killed: out of memory"}})
    rec = hm._component_state["job:backtest_job"]
    assert rec["state"] == DEGRADED and "killed: out of memory" in rec["detail"]


def test_the_backtest_gate_is_degraded_after_36_hours(hm):
    hm.config = FakeConfig(scheduler={"backtest_job": {"enabled": True, "cron": "30 3 * * *"}},
                           health_manager_job_max_age_hours={"backtest_job": 36})
    _jobs(hm, {"backtest_job": {"last_success": NOW - 40 * 3600}})         # inside 2x daily (48 h), past 36 h
    assert hm._component_state["job:backtest_job"]["state"] == DEGRADED
    hm.config = FakeConfig(scheduler={"backtest_job": {"enabled": True, "cron": "30 3 * * *"}},
                           health_manager_job_max_age_hours={"backtest_job": 36})
    _jobs(hm, {"backtest_job": {"last_success": NOW - 30 * 3600}})
    assert hm._component_state["job:backtest_job"]["state"] == HEALTHY


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
