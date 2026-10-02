"""CPU-reduction caches must not change behaviour: merge-chain cache, pause cache, tracker-save throttle,
shadow-eval throttle. Offline; pytest."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from argus.baseline.engine import BaselineEngine  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.shadow import sandbox  # noqa: E402


def _decision(store, dev, ts, state):
    store.insert_decision(dev, ts, state, "path", 0.9, 0.5)


def test_merge_invalidates_canonical_cache():
    s = GraphStore(":memory:")
    s.upsert_device("a", device_type="x", timestamp=1.0)
    s.upsert_device("b", device_type="x", timestamp=1.0)
    assert s.resolve_canonical_device_id("a") == "a"       # primes the cache
    s.merge_device("a", "b", timestamp=2.0)
    assert s.resolve_canonical_device_id("a") == "b"
    assert "a" in s._all_ids_resolving_to("b")


def test_all_ids_resolving_returns_copy():
    s = GraphStore(":memory:")
    s.upsert_device("a", device_type="x", timestamp=1.0)
    s._all_ids_resolving_to("a").append("junk")
    assert "junk" not in s._all_ids_resolving_to("a")


def test_pause_cache_sees_new_decision_immediately():
    s = GraphStore(":memory:")
    e = BaselineEngine(s)
    s.upsert_device("d", device_type="x", timestamp=1.0)
    assert e.is_learning_paused("d", now=100.0) is False
    _decision(s, "d", 100.0, "HIGH")
    assert e.is_learning_paused("d", now=101.0) is True        # decision write busts the cache
    _decision(s, "d", 102.0, "BENIGN")
    assert e.is_learning_paused("d", now=103.0) is True        # still inside the cooldown
    assert e.is_learning_paused("d", now=103.0 + 1900) is False


def _saved_n(s, dev):
    return s._conn.execute("SELECT COUNT(*) FROM device_baselines WHERE device_id=?", (dev,)).fetchone()[0] \
        if hasattr(s, "_conn") else None


def test_save_throttle_and_flush():
    s = GraphStore(":memory:")
    e = BaselineEngine(s, save_min_interval=30.0)
    s.upsert_device("d", device_type="x", timestamp=1.0)
    e.score_metric("d", "query_rate", "gaussian", (5.0,), 3, now=1000.0)
    assert len(e._dirty_trackers) == 0
    e.score_metric("d", "query_rate", "gaussian", (5.1,), 3, now=1001.0)
    assert len(e._dirty_trackers) == 1                          # skipped, held for flush
    assert e.flush() == 1
    assert len(e._dirty_trackers) == 0


def test_default_engine_saves_every_time():
    s = GraphStore(":memory:")
    e = BaselineEngine(s)
    s.upsert_device("d", device_type="x", timestamp=1.0)
    for i in range(3):
        e.score_metric("d", "query_rate", "gaussian", (5.0 + i,), 3, now=1000.0 + i)
    assert e._dirty_trackers == {}


def test_shadow_throttle_per_device(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox, "evaluate_candidate_shadow", lambda *a, **k: calls.append(a[4]))
    monkeypatch.setattr(sandbox, "is_resource_pressure_active_in_process", lambda: False)
    ev = sandbox.ShadowEvaluator(GraphStore(":memory:"))
    ev._active_canaries = [{"change_id": "c", "parameter": "p", "new_value": 1, "device_id": None, "device_type": None}]
    ev._cache_refreshed_at = 10 ** 12
    for now in (1000.0, 1001.0, 1059.0):
        ev.maybe_shadow_evaluate("d1", "t", [], None, None, True, 0.5, "BENIGN", now=now)
    ev.maybe_shadow_evaluate("d2", "t", [], None, None, True, 0.5, "BENIGN", now=1002.0)
    ev.maybe_shadow_evaluate("d1", "t", [], None, None, True, 0.5, "BENIGN", now=1061.0)
    assert calls == ["d1", "d2", "d1"]


def test_label_purge_runs_only_when_host_or_domains_change():
    from core import metrics_sync
    ex = metrics_sync.MetricsExporter.__new__(metrics_sync.MetricsExporter)
    ex._metric_keys_cache = {}
    ex._last_purge_sig = {}
    calls = []
    ex._purge_stale_device_labels = lambda d, h: calls.append(("dev", d, h))
    ex._purge_stale_domain_labels = lambda d, h, doms: calls.append(("dom", d, h))

    class St:
        device_id = "d1"; hostname = "h1"; client_ip = "1.2.3.4"; device_type = "t"
    try:
        for _ in range(3):
            ex.export_device_telemetry(St(), {"current_hour": 1}, 0, 0, 0, 0, 0, 0, True, False, 1.0)
    except Exception:
        pass   # the gauge writes after the purge are not under test
    assert [c[0] for c in calls] == ["dev", "dom"]


def test_zeek_dns_tailer_thins_mdns(tmp_path):
    import json
    from extractors.zeek_features import ZeekLogTailer
    log = tmp_path / "dns.log"
    rows = [{"id.orig_h": "192.168.1.2", "id.resp_h": "224.0.0.251", "query": "x.local"}] * 100
    rows += [{"id.orig_h": "192.168.1.2", "id.resp_h": "192.168.1.1", "query": "example.com"}] * 10
    log.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))
    got = []
    t = ZeekLogTailer(log, "dns", lambda et, ev: got.append(ev), tmp_path)
    t._pos = 0
    t._inode = None
    t.poll()
    assert sum(1 for e in got if e["id.resp_h"] == "224.0.0.251") == 2      # 100 / 50
    assert sum(1 for e in got if e["id.resp_h"] == "192.168.1.1") == 10     # real DNS untouched


def test_overview_summary_cache_reuses_then_expires(monkeypatch):
    from middleware.routers import overview_api
    monkeypatch.setattr(overview_api, "_SUMMARY_CACHE_TTL_SECONDS", 30.0)
    overview_api._summary_cache.clear()
    n = []
    f = lambda: n.append(1) or len(n)
    assert overview_api._cached("k", f) == 1
    assert overview_api._cached("k", f) == 1
    monkeypatch.setattr(overview_api, "_SUMMARY_CACHE_TTL_SECONDS", 0.0)
    assert overview_api._cached("k", f) == 2
    overview_api._summary_cache.clear()
