"""
What a device merge carries over, and which per-device reads cover a device's earlier ids (2026-10-05).

A graph merge tombstones the orphan id and leaves its rows in place; each per-device reader has to cover every id
merged into the device. Evidence, decisions, containment and tuned thresholds already did. These did not: CL-AFPE
learned trust (composite and device-scoped trust cache), alerts per device, the peer-cohort destination count, the
retro-hunter's (device, destination) pairs and the popularity ledger's "unproven name" check. On the engine side the
orphan's learning days (DeviceFamiliarity) were thrown away, and the graph never combined device metadata.

Run: python -m pytest tests/test_device_merge_carryover.py   (or python tests/test_device_merge_carryover.py)
"""
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from argus.graph.store import GraphStore, combine_merged_metadata  # noqa: E402
from argus.evidence.model import Evidence  # noqa: E402
from intelligence.device_familiarity import ACTIVE_DAYS_KIND, MAX_ENTRIES_PER_KIND, DeviceFamiliarity  # noqa: E402

DAY = 86400.0


@pytest.fixture
def store(tmp_path):
    s = GraphStore(str(tmp_path / "graph.db"))
    yield s
    s.close()


# -- 3: device metadata ------------------------------------------------------------------------------------------------

def test_combine_unites_histories_and_adds_signature_counts():
    canonical = {"mac_history": {"aa": 200.0, "bb": 300.0}, "known_ips_history": {"10.0.0.2": 100.0},
                 "confirmed_threat_counts": {"_total": 2, "sig_a": 2},
                 "sigma_shift": 0.5, "fp_profile": {"k": {"value": 1}}, "hostname": "unknown", "device_type": "phone"}
    orphan = {"mac_history": {"aa": 150.0, "cc": 50.0}, "known_ips_history": {"10.0.0.9": 80.0},
              "confirmed_threat_counts": {"_total": 1, "sig_b": 1},
              "sigma_shift": 2.0, "fp_profile": {"k": {"value": 9}}, "hostname": "real-name", "device_type": "laptop",
              "fp_count": 4}
    out = combine_merged_metadata(canonical, orphan)
    assert out["mac_history"] == {"aa": 150.0, "bb": 300.0, "cc": 50.0}       # earliest first-seen kept
    assert out["known_ips_history"] == {"10.0.0.2": 100.0, "10.0.0.9": 80.0}
    assert out["confirmed_threat_counts"] == {"_total": 3, "sig_a": 2, "sig_b": 1}
    assert out["sigma_shift"] == 0.5 and out["fp_profile"] == {"k": {"value": 1}}   # calibration stays the canonical's
    assert out["device_type"] == "phone"
    assert out["hostname"] == "real-name"     # the canonical had none
    assert out["fp_count"] == 4               # gap filled, not added: the engine's mirror owns this count
    assert canonical["mac_history"] == {"aa": 200.0, "bb": 300.0}              # inputs untouched


def test_combine_keeps_the_writers_bound():
    canonical = {"mac_history": {f"m{i}": float(100 + i) for i in range(15)}}
    orphan = {"mac_history": {f"o{i}": float(i) for i in range(15)}}
    out = combine_merged_metadata(canonical, orphan)["mac_history"]
    assert len(out) == 20 and "o0" not in out and "m14" in out                # oldest dropped first


def test_combine_skips_a_malformed_field():
    out = combine_merged_metadata({"confirmed_threat_counts": {"_total": 1}},
                                  {"confirmed_threat_counts": {"_total": "x"}, "hostname": "h"})
    assert out == {"confirmed_threat_counts": {"_total": 1}, "hostname": "h"}


def test_merge_device_combines_metadata_once(store):
    store.update_device_metadata("orph", {"mac_history": {"aa": 10.0}, "confirmed_threat_counts": {"_total": 1}},
                                 timestamp=1000.0)
    store.update_device_metadata("canon", {"mac_history": {"bb": 20.0}, "confirmed_threat_counts": {"_total": 2}},
                                 timestamp=1000.0)
    store.merge_device("orph", "canon", timestamp=2000.0)
    meta = store.get_device_metadata("canon")
    assert meta["mac_history"] == {"aa": 10.0, "bb": 20.0}
    assert meta["confirmed_threat_counts"] == {"_total": 3}
    assert store.get_device_metadata("orph")["confirmed_threat_counts"] == {"_total": 1}   # audit copy kept
    store.merge_device("orph", "canon", timestamp=2001.0)                    # a repeated call adds nothing
    assert store.get_device_metadata("canon")["confirmed_threat_counts"] == {"_total": 3}


# -- 2: learning progress ---------------------------------------------------------------------------------------------

def _observe(fam, device_id, day, hour, port=None):
    fam.record_device_baseline_observation(device_id, dest_port=port, now=day * DAY + hour * 3600 + 1)


def test_familiarity_merge_carries_learning_days_and_destinations():
    fam = DeviceFamiliarity()
    for day in (1, 2, 3):
        _observe(fam, "orph", day, 8, port=443)
    _observe(fam, "orph", 4, 9)
    for day in (4, 5):
        _observe(fam, "canon", day, 10, port=53)
    assert fam.learned_activity("canon") == (2, 2)
    fam.merge_device_profile("orph", "canon")
    assert fam.learned_activity("canon") == (5, 6)          # days 1-5; day 4 has hours 9 and 10
    assert fam.learned_activity("orph") == (0, 0)           # forgotten
    assert fam.get_baseline_familiarity("canon", dest_port=443) == pytest.approx(3 / 5)
    assert fam.get_baseline_familiarity("canon", dest_port=53) == pytest.approx(2 / 5)


def test_familiarity_merge_keeps_the_bound():
    fam = DeviceFamiliarity()
    for day in range(MAX_ENTRIES_PER_KIND):
        _observe(fam, "canon", 1000 + day, 1)
    for day in range(10):
        _observe(fam, "orph", day, 1)
    fam.merge_device_profile("orph", "canon")
    assert fam.learned_activity("canon")[0] == MAX_ENTRIES_PER_KIND


def test_engine_merge_carries_learning_days(tmp_path):
    from core.state_guard import StateManager
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"), max_devices=10)
    sm.get_or_create(device_id="orph", client_ip="10.0.0.2", hostname="unknown")
    sm.get_or_create(device_id="canon", client_ip="10.0.0.3", hostname="unknown")
    fam = DeviceFamiliarity()
    for day in (1, 2, 3):
        _observe(fam, "orph", day, 8)
    _observe(fam, "canon", 4, 8)
    assert sm.merge_into_canonical("orph", "canon", familiarity=fam)
    assert fam.learned_activity("canon") == (4, 4)


def test_engine_merge_still_works_with_a_familiarity_that_can_only_discard(tmp_path):
    from core.state_guard import StateManager

    class _Old:
        discarded = []

        def discard_device_profile(self, device_id, reason=""):
            self.discarded.append((device_id, reason))

    sm = StateManager(state_path=str(tmp_path / "ids_state.json"), max_devices=10)
    sm.get_or_create(device_id="orph", client_ip="10.0.0.2", hostname="unknown")
    sm.get_or_create(device_id="canon", client_ip="10.0.0.3", hostname="unknown")
    old = _Old()
    assert sm.merge_into_canonical("orph", "canon", familiarity=old)
    assert old.discarded == [("orph", "merge")]


# -- 1: readers that now cover every id of a device -------------------------------------------------------------------

def test_composite_trust_earned_under_an_earlier_id_counts(store):
    from argus.cl_afpe import composite_trust as ct
    key = dict(behavior_fingerprint="fp", destination_class="public", hypothesis_id="h1", regime_id=0)
    store.upsert_device("orph", timestamp=1.0)
    store.upsert_device("canon", timestamp=1.0)
    now = 10_000.0
    for family in ("dns_behavior", "tls_fingerprint"):
        for _ in range(5):
            ct.record_corroborating_signal(store, "orph", evidence_family=family, now=now, **key)
    assert not ct.permits_suppression(store, "canon", now=now, **key)
    store.merge_device("orph", "canon", timestamp=now)
    assert ct.permits_suppression(store, "canon", now=now, **key)

    # A new observation builds on the device's existing trust (not from zero) and is written under the canonical id.
    ct.record_corroborating_signal(store, "orph", evidence_family="dns_behavior", now=now, **key)
    rows = store._conn.execute("SELECT device_id, trust_value FROM cl_afpe_trust WHERE evidence_family='dns_behavior'"
                               ).fetchall()
    by_id = {r["device_id"]: r["trust_value"] for r in rows}
    assert by_id["canon"] == pytest.approx(0.75 + 0.15)    # 5 x 0.15 earned under "orph", plus this one
    assert ct.reset_tuple(store, "canon", **key) == 3       # both ids' rows of the tuple
    assert not ct.permits_suppression(store, "canon", now=now, **key)


def test_device_scoped_trust_cache_follows_a_merge(store):
    from argus.cl_afpe.engine import ClAfpeEngine
    engine = ClAfpeEngine(store)
    now = 50_000.0
    engine.immunize("example.test", device_id="orph", hypothesis="h1", device_scoped=True, now=now)
    assert not engine.is_trust_cached("example.test", device_id="canon", hypothesis="h1", now=now)
    store.upsert_device("canon", timestamp=now)
    store.merge_device("orph", "canon", timestamp=now)
    assert engine.is_trust_cached("example.test", device_id="canon", hypothesis="h1", now=now)
    assert not engine.is_trust_cached("example.test", device_id="other", hypothesis="h1", now=now)


def test_alert_events_per_device_include_earlier_ids(store):
    for dev, ts in (("orph", 100.0), ("canon", 200.0), ("other", 300.0)):
        decision_id = store.insert_decision(dev, ts, "SUSPICIOUS", "test", 0.5, 0.5)
        store.insert_alert_event(decision_id, dev, ts, "FIRED")
    store.merge_device("orph", "canon", timestamp=400.0)
    assert [a["device_id"] for a in store.get_alert_events(device_id="canon")] == ["canon", "orph"]
    assert [a["device_id"] for a in store.get_alert_events(device_id="orph")] == ["canon", "orph"]
    assert [a["device_id"] for a in store.get_alert_events(device_id="canon", resolve_merges=False)] == ["canon"]


def test_destination_count_and_pairs_cover_earlier_ids(store):
    store.record_device_destinations("orph", ["1.1.1.1", "2.2.2.2"], timestamp=100.0)
    store.record_device_destinations("canon", ["2.2.2.2", "3.3.3.3"], timestamp=100.0)
    store.insert_evidence(Evidence(device_id="orph", destination_id="4.4.4.4", evidence_type="t",
                                   independence_family="f", timestamp=100.0, source="test"))
    store.merge_device("orph", "canon", timestamp=200.0)
    assert store.get_distinct_destination_count("canon", since=0.0) == 3
    assert sorted(store.get_traffic_destinations_since(0.0)) == [
        ("canon", "1.1.1.1"), ("canon", "2.2.2.2"), ("canon", "3.3.3.3")]
    assert store.get_device_destinations_since(0.0) == [("canon", "4.4.4.4")]


def test_canonical_id_map_follows_chains_and_survives_a_cycle(store):
    for d in ("a", "b", "c", "x", "y"):
        store.upsert_device(d, timestamp=1.0)
    store.merge_device("a", "b", timestamp=2.0)
    store.merge_device("b", "c", timestamp=3.0)
    store._conn.execute("UPDATE devices SET merged_into_device_id='y' WHERE device_id='x'")
    store._conn.execute("UPDATE devices SET merged_into_device_id='x' WHERE device_id='y'")
    store._conn.commit()
    m = store.canonical_id_map()
    assert m["a"] == "c" and m["b"] == "c" and "c" not in m
    assert m["x"] == "x" and m["y"] == "y"
    assert store.device_ids_for("x") == ["x"]


def test_retro_hunter_maps_ledger_pairs_to_the_canonical_device(store):
    from argus.retro_hunter import RetroHunter
    store.upsert_device("orph", timestamp=1.0)
    store.upsert_device("canon", timestamp=1.0)
    store.merge_device("orph", "canon", timestamp=2.0)
    hunter = RetroHunter(store, lambda d: None)
    pairs = hunter._window_pairs(0.0, [("orph", "name.test"), ("canon", "name.test"), ("third", "x.test")])
    assert pairs == [("canon", "name.test"), ("third", "x.test")]


def test_popularity_unproven_check_treats_earlier_ids_as_the_same_device(tmp_path):
    from intelligence.local_popularity import LocalPopularity
    pop = LocalPopularity(tmp_path / "popularity.db", learning_fn=lambda d: False)
    # The name was only ever used by "orph" during its learning period; "orph" is now part of "canon".
    devices, learning = frozenset({"orph"}), frozenset({"orph"})
    assert pop._unproven_for("canon", devices, learning) is True        # before: looked like another device's name
    pop.resolve_fn = lambda d: {"orph": "canon"}.get(d, d)
    assert pop._unproven_for("canon", devices, learning) is False       # its own learning-period name
    # A genuinely different device that used it only while learning still makes it unproven for a baselined "canon".
    assert pop._unproven_for("canon", frozenset({"orph", "cam"}), frozenset({"cam"})) is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
