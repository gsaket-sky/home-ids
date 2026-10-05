"""
Graph vs engine merge consistency (argus/graph/merge_consistency.py), found on .94 2026-10-05: the graph disagreed
with the engine on 33 of 113 device merges because the identity-reconcile worker's graph mirror had failed on every
call before 2026-10-02, and nothing replayed old merges. One phone showed up as three ids: the graph had
A -> B, the engine A -> C and B -> C, and the graph never got B -> C.

Run: python -m pytest tests/test_graph_merge_consistency.py   (or python tests/test_graph_merge_consistency.py)
"""
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from argus.graph.merge_consistency import check_merges, classify, repair_merges  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402


# -- classification (pure) ---------------------------------------------------------------------------------------------

def _kind(orphan, canonical, redirects, pointers):
    return classify(orphan, canonical, redirects, pointers).kind


def test_ok_when_graph_resolves_both_to_the_same_device():
    assert _kind("a", "c", {"a": "c"}, {"a": "c", "c": None}) == "ok"


def test_ok_through_a_graph_chain():
    assert _kind("a", "c", {"a": "c"}, {"a": "b", "b": "c", "c": None}) == "ok"


def test_absent_when_the_graph_never_saw_the_orphan():
    assert _kind("a", "c", {"a": "c"}, {"c": None}) == "absent"


def test_missing_when_the_orphan_is_still_live_in_the_graph():
    item = classify("a", "c", {"a": "c"}, {"a": None, "c": None})
    assert (item.kind, item.repair_from) == ("missing", "a")


def test_missing_when_the_graph_stops_one_step_short():
    # The phone: graph A -> B; engine (flat) A -> C and B -> C. Repair is B -> C, which fixes A too.
    redirects = {"A": "C", "B": "C"}
    pointers = {"A": "B", "B": None, "C": None}
    item = classify("A", "C", redirects, pointers)
    assert (item.kind, item.graph_root, item.repair_from) == ("missing", "B", "B")


def test_diverged_when_the_graph_has_the_orphan_under_a_live_engine_device():
    item = classify("a", "c", {"a": "c"}, {"a": "x", "x": None, "c": None})
    assert (item.kind, item.graph_root, item.repair_from) == ("diverged", "x", "a")


def test_unresolved_when_the_graph_merged_the_engine_canonical_away():
    item = classify("a", "c", {"a": "c"}, {"a": None, "c": "z", "z": None})
    assert item.kind == "unresolved" and item.repair_from is None


def test_unresolved_on_a_cycle():
    assert _kind("a", "c", {"a": "c"}, {"a": "b", "b": "a", "c": None}) == "unresolved"


def test_check_skips_self_and_empty_redirects():
    report = check_merges({"a": "a", "": "c", "b": ""}, {"a": None})
    assert report.items == []


# -- repair against a real store ---------------------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    s = GraphStore(str(tmp_path / "graph.db"))
    yield s
    s.close()


def _seed(store, ids, ts=1000.0):
    for d in ids:
        store.upsert_device(d, timestamp=ts)


def test_repair_makes_every_engine_merge_agree(store):
    _seed(store, ["A", "B", "C", "ghost", "canon2", "o3", "x", "canon3"])
    store.merge_device("A", "B", timestamp=1100.0)          # the old mirror got this far
    store.merge_device("o3", "x", timestamp=1100.0)         # an older merge the engine later replaced
    redirects = {"A": "C", "B": "C", "ghost": "canon2", "o3": "canon3", "never_seen": "C"}

    before = check_merges(redirects, store.get_merge_pointers()).counts()
    assert before == {"ok": 0, "absent": 1, "missing": 3, "diverged": 1, "unresolved": 0}

    report = repair_merges(store, redirects)
    assert report.counts() == {"ok": 4, "absent": 1, "missing": 0, "diverged": 0, "unresolved": 0}
    assert report.repaired == 3          # B -> C (fixes A as well), ghost -> canon2, o3 -> canon3
    assert report.repair_failures == 0
    for orphan, canonical in redirects.items():
        if orphan != "never_seen":
            assert store.resolve_canonical_device_id(orphan) == canonical
    assert "never_seen" not in store.get_merge_pointers()   # no rows made up for ids the graph never saw
    assert store.resolve_canonical_device_id("x") == "x"    # the live device the old merge pointed at stays live


def test_repair_is_idempotent(store):
    _seed(store, ["a", "c"])
    assert repair_merges(store, {"a": "c"}).repaired == 1
    again = repair_merges(store, {"a": "c"})
    assert again.repaired == 0 and again.counts()["ok"] == 1


def test_repair_leaves_unresolved_alone(store):
    _seed(store, ["a", "c", "z"])
    store.merge_device("c", "z", timestamp=1100.0)
    report = repair_merges(store, {"a": "c"})
    assert report.repaired == 0 and report.counts()["unresolved"] == 1
    assert store.resolve_canonical_device_id("a") == "a"


def test_a_merge_does_not_move_last_seen(store):
    # 2026-10-05: graph last_seen jumped to "now" for a device idle for days; a merge (and so every replay) did that.
    _seed(store, ["orphan", "canon"], ts=1000.0)
    store.merge_device("orphan", "canon", timestamp=999_999.0)
    rows = {r["device_id"]: r["last_seen"] for r in store._conn.execute("SELECT device_id, last_seen FROM devices")}
    assert rows == {"orphan": 1000.0, "canon": 1000.0}
    store.merge_device("new_orphan", "canon", timestamp=2000.0)   # a row the graph lacked is still created
    assert store.resolve_canonical_device_id("new_orphan") == "canon"


# -- engine side and the live wiring ---------------------------------------------------------------------------------

def test_state_manager_returns_a_copy_of_its_redirects(tmp_path):
    from core.state_guard import StateManager
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"), max_devices=10)
    sm.get_or_create(device_id="orph", client_ip="10.0.0.2", hostname="unknown")
    sm.get_or_create(device_id="canon", client_ip="10.0.0.3", hostname="unknown")
    assert sm.merge_into_canonical("orph", "canon")
    redirects = sm.get_merge_redirects()
    assert redirects == {"orph": "canon"}
    redirects["x"] = "y"
    assert sm.get_merge_redirects() == {"orph": "canon"}


@pytest.fixture
def live_engine_db(tmp_path):
    from argus.ops import live_engine
    old_path, old_store = live_engine._GRAPH_DB_PATH, live_engine._graph_store
    db = str(tmp_path / "live.db")
    live_engine._GRAPH_DB_PATH = db
    live_engine._graph_store = GraphStore(db)
    yield live_engine
    live_engine._graph_store.close()
    live_engine._GRAPH_DB_PATH, live_engine._graph_store = old_path, old_store


def test_worker_thread_repair_is_seen_by_the_main_loop_singleton(live_engine_db):
    singleton = live_engine_db._graph_store
    _seed(singleton, ["a", "c"])
    assert singleton.resolve_canonical_device_id("a") == "a"   # now cached for 15 s
    out = []
    t = threading.Thread(target=lambda: out.append(
        live_engine_db.reconcile_graph_merges_in_own_connection({"a": "c"})))
    t.start()
    t.join(timeout=30)
    assert out and out[0].repaired == 1
    assert singleton.resolve_canonical_device_id("a") == "c"


def test_check_only_mode_writes_nothing(live_engine_db):
    _seed(live_engine_db._graph_store, ["a", "c"])
    report = live_engine_db.reconcile_graph_merges_in_own_connection({"a": "c"}, repair=False)
    assert report.repaired == 0 and report.counts()["missing"] == 1
    assert live_engine_db._graph_store.get_merge_pointers()["a"] is None


def _sample(name, labels=None):
    from prometheus_client import REGISTRY
    return REGISTRY.get_sample_value(name, labels or {})


def test_pipeline_pass_publishes_counts_and_repairs(live_engine_db, tmp_path):
    from core.pipeline import EnginePipeline
    from core.state_guard import StateManager
    _seed(live_engine_db._graph_store, ["orph", "canon"])
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"), max_devices=10)
    sm.get_or_create(device_id="orph", client_ip="10.0.0.2", hostname="unknown")
    sm.get_or_create(device_id="canon", client_ip="10.0.0.3", hostname="unknown")
    sm.merge_into_canonical("orph", "canon")          # engine merged; the graph mirror "failed"

    fake_self = SimpleNamespace(state_manager=sm, config={"graph_merge_repair_enabled": False})
    report = EnginePipeline._graph_merge_check_pass(fake_self)
    assert report.repaired == 0
    assert _sample("home_ids_graph_merge_disagreements", {"kind": "missing"}) == 1.0

    repairs_before = _sample("home_ids_graph_merge_repairs_total") or 0.0
    fake_self.config["graph_merge_repair_enabled"] = True
    report = EnginePipeline._graph_merge_check_pass(fake_self)
    assert report.repaired == 1
    assert _sample("home_ids_graph_merge_disagreements", {"kind": "missing"}) == 0.0
    assert _sample("home_ids_graph_merge_disagreements", {"kind": "ok"}) == 1.0
    assert _sample("home_ids_graph_merge_repairs_total") == repairs_before + 1
    assert fake_self._graph_merge_last_disagreements == []


def test_pipeline_pass_never_raises():
    from core.pipeline import EnginePipeline

    class _Broken:
        def get_merge_redirects(self):
            raise RuntimeError("boom")

    assert EnginePipeline._graph_merge_check_pass(SimpleNamespace(state_manager=_Broken(), config={})) is None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
