"""
Merge sweep follow-ups (2026-10-05): places where a device-identity merge still used the old id.

- Containment: a merge used to RELEASE the orphan's tarpit/router isolation (the MAC-rotation release path), although
  the orphan's address now belongs to the same physical device. Now it is kept, relabelled and extended.
- Operator corrections and the nightly calibration on alerts raised before a merge.
- Device labels, console hostname lookups, the device list's latest decision, decision history, purge, backtest.

Run: python -m pytest tests/test_merge_followups.py   (or python tests/test_merge_followups.py)
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from argus.graph.store import GraphStore  # noqa: E402
from core.state_guard import StateManager  # noqa: E402

ORPHAN_MAC, ORPHAN_IP = "aa:aa:aa:aa:aa:01", "10.0.0.20"
CANON_MAC, CANON_IP = "bb:bb:bb:bb:bb:02", "10.0.0.30"


def _two_devices(tmp_path):
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"), max_devices=20)
    orphan = sm.get_or_create(device_id="orph", client_ip=ORPHAN_IP, hostname="unknown")
    orphan.mac_address = ORPHAN_MAC
    canon = sm.get_or_create(device_id="canon", client_ip=CANON_IP, hostname="phone")
    canon.mac_address = CANON_MAC
    return sm


@pytest.fixture
def store(tmp_path):
    s = GraphStore(str(tmp_path / "graph.db"))
    yield s
    s.close()


# -- containment -------------------------------------------------------------------------------------------------------

def test_merge_keeps_and_relabels_containment(tmp_path):
    sm = _two_devices(tmp_path)
    sm.update_ips_state_atomic({
        "tarpit_targets": {ORPHAN_IP: {"mac": ORPHAN_MAC, "hostname": "unknown", "dev_id": "orph"}},
        "router_isolated_devices": {ORPHAN_MAC: {"ip": ORPHAN_IP, "hostname": "unknown", "dev_id": "orph"}},
        "operator_released_devices": {"orph": 123.0},
    })
    assert sm.merge_into_canonical("orph", "canon")
    ips_state = sm.get_ips_state()
    assert ips_state["tarpit_targets"][ORPHAN_IP]["dev_id"] == "canon"
    assert ips_state["router_isolated_devices"][ORPHAN_MAC]["dev_id"] == "canon"
    assert ips_state["router_isolated_devices"][ORPHAN_MAC]["hostname"] == "phone"
    assert ips_state["operator_released_devices"]["canon"] == 123.0   # a person's release is not undone by a merge
    assert sm.pop_last_migrated_isolation_target() is None             # nothing handed to the release path
    carry = sm.pop_last_merged_containment()
    assert carry == {"orphan_mac": ORPHAN_MAC, "orphan_ip": ORPHAN_IP, "canonical_id": "canon",
                     "canonical_mac": CANON_MAC, "canonical_ip": CANON_IP, "hostname": "phone"}


def _mitigator(tmp_path, sm, armed=True):
    from mitigation.ips import IPSMitigator
    config = {"ips_router_enabled": True, "ips_tarpit_enabled": True, "onboarding_mode_days": 0,
              "state_path": str(tmp_path / "ids_state.json")}
    m = IPSMitigator(config=config, state_manager=sm, start_workers=False)
    m.tarpit_armed = armed
    m._isolate_device_router = lambda **kw: True
    return m


def test_contained_orphan_extends_containment_to_the_canonical(tmp_path):
    sm = _two_devices(tmp_path)
    m = _mitigator(tmp_path, sm)
    m._router_isolated_devices[ORPHAN_MAC] = {"ip": ORPHAN_IP, "hostname": "unknown", "dev_id": "orph"}
    m._tarpit_active_targets[ORPHAN_IP] = {"mac": ORPHAN_MAC, "hostname": "unknown", "dev_id": "orph"}
    added = m.carry_containment_after_merge(ORPHAN_MAC, ORPHAN_IP, "canon", CANON_MAC, CANON_IP, "phone")
    assert set(added) == {"router", "tarpit"}
    assert m._router_isolated_devices[CANON_MAC]["dev_id"] == "canon"
    assert m._tarpit_active_targets[CANON_IP]["dev_id"] == "canon"
    assert ORPHAN_MAC in m._router_isolated_devices and ORPHAN_IP in m._tarpit_active_targets   # never released


def test_uncontained_orphan_adds_nothing(tmp_path):
    sm = _two_devices(tmp_path)
    m = _mitigator(tmp_path, sm)
    assert m.carry_containment_after_merge(ORPHAN_MAC, ORPHAN_IP, "canon", CANON_MAC, CANON_IP, "phone") == []
    assert m._router_isolated_devices == {} and m._tarpit_active_targets == {}


def test_reconcile_pass_carries_containment_instead_of_releasing(tmp_path):
    from core.identity import DeviceIdentityManager
    sm = _two_devices(tmp_path)
    calls = []
    fake_ips = SimpleNamespace(unisolate_all=lambda **kw: calls.append(("release", kw)),
                               carry_containment_after_merge=lambda **kw: calls.append(("carry", kw)))
    idm = DeviceIdentityManager(sm, {})
    assert sm.merge_into_canonical("orph", "canon")
    idm._release_stale_isolation_if_merged(fake_ips)
    assert [c[0] for c in calls] == ["carry"]
    assert calls[0][1]["canonical_id"] == "canon"


# -- corrections and calibration on alerts from before a merge --------------------------------------------------------

def test_operator_correction_on_an_old_alert_calibrates_the_current_device(store):
    from argus.cl_afpe.engine import ClAfpeEngine
    now = 1_000_000.0
    store.upsert_device("orph", timestamp=now)
    store.upsert_device("canon", timestamp=now)
    store.merge_device("orph", "canon", timestamp=now)
    engine = ClAfpeEngine(store)
    result = engine.mark_false_positive(
        {"signature": "NETWORK_INTRUSION", "device": {"id": "orph"},
         "network_context": {"queried_domain": "corrected.example.com"}}, now=now)
    assert not result.refused
    assert engine.get_sigma_shift("canon") > 0.0
    assert engine.get_sigma_shift("orph") == 0.0


def test_calibration_evidence_is_grouped_by_device():
    from scripts.train_fp_classifier import _by_canonical_device
    canonical = {"orph": "canon"}
    assert _by_canonical_device({"orph": [0.9, 0.8], "canon": [0.7], "other": [0.5]}, canonical) == {
        "canon": [0.9, 0.8, 0.7], "other": [0.5]}
    assert _by_canonical_device({"orph": 2, "canon": 3}, canonical) == {"canon": 5}
    assert _by_canonical_device({"orph": [1]}, {}) == {"orph": [1]}


# -- labels, names, console readers -----------------------------------------------------------------------------------

def test_device_label_follows_the_merge(tmp_path):
    from core.device_labels import all_labels, set_label
    sm = _two_devices(tmp_path)
    set_label("orph", "phone", str(tmp_path))
    assert sm.merge_into_canonical("orph", "canon")
    labels = all_labels(str(tmp_path))
    assert labels["canon"]["device_type"] == "phone" and "orph" not in labels


def test_newer_label_wins_on_merge(tmp_path):
    from core import device_labels
    device_labels._write_all({"orph": {"device_type": "tablet", "labeled_at": 10.0},
                              "canon": {"device_type": "phone", "labeled_at": 20.0}}, str(tmp_path))
    assert device_labels.transfer_label("orph", "canon", str(tmp_path)) is False
    assert device_labels.all_labels(str(tmp_path)) == {"canon": {"device_type": "phone", "labeled_at": 20.0}}


def test_hostname_lookup_follows_merges(tmp_path):
    from middleware.humanize import resolve_device_hostname, resolve_device_identity
    sm = _two_devices(tmp_path)
    sm.merge_into_canonical("orph", "canon")
    assert resolve_device_hostname("orph", sm) == "phone"
    ident = resolve_device_identity("orph", sm)
    assert ident["hostname"] == "phone" and ident["ip"] == CANON_IP and ident["device_id"] == "orph"
    assert resolve_device_hostname("never-seen", sm) == "never-seen"


def test_recent_decisions_latest_decision_and_history_cover_earlier_ids(store):
    from argus.ops.threat_hunt import device_history
    store.insert_decision("orph", 300.0, "SUSPICIOUS", "test", 0.5, 0.5)
    store.insert_decision("canon", 200.0, "BENIGN", "test", 0.1, 0.1)
    store.insert_decision("other", 250.0, "BENIGN", "test", 0.1, 0.1)
    store.merge_device("orph", "canon", timestamp=400.0)
    assert [d["device_id"] for d in store.get_recent_decisions(10, device_id="canon")] == ["orph", "canon"]
    rows = {r["device_id"]: r for r in store.get_devices_with_latest_decision()}
    assert rows["canon"]["state"] == "SUSPICIOUS" and rows["canon"]["decision_timestamp"] == 300.0
    assert [r["device_id"] for r in store.get_devices_with_latest_decision()] == ["canon", "other"]
    hist = device_history(store, "canon")
    assert sorted(d["device_id"] for d in hist["decisions"]) == ["canon", "orph"]


def test_purge_forgets_learned_values_under_every_id(store):
    from argus.cl_afpe import composite_trust as ct
    key = dict(behavior_fingerprint="fp", destination_class="public", hypothesis_id="h1", regime_id=0)
    store.upsert_device("orph", timestamp=1.0)
    store.upsert_device("canon", timestamp=1.0)
    ct.record_corroborating_signal(store, "orph", evidence_family="dns", now=10.0, **key)
    store.update_device_metadata("orph", {"sigma_shift": 1.5, "mac_history": {"aa": 1.0}}, timestamp=1.0)
    store.merge_device("orph", "canon", timestamp=20.0)
    ct.record_corroborating_signal(store, "canon", evidence_family="tls", now=30.0, **key)
    assert store.clear_learned_device_values("canon") == 2
    assert store._conn.execute("SELECT COUNT(*) FROM cl_afpe_trust").fetchone()[0] == 0
    meta = store.get_device_metadata("orph")
    assert meta["sigma_shift"] == 0.0 and meta["mac_history"] == {"aa": 1.0}   # identity history kept


# -- backtest --------------------------------------------------------------------------------------------------------

def test_backtest_decision_lookups_cover_earlier_ids(store):
    from argus.ops.backtest_job import _decision_rows, _with_merged_ids
    store.insert_decision("canon", 500.0, "SUSPICIOUS", "test", 0.5, 0.5)
    store.upsert_device("orph", timestamp=1.0)
    store.merge_device("orph", "canon", timestamp=10.0)
    rows = _decision_rows(store, "decision_id", "orph", "AND timestamp > ?", (100.0,))
    assert len(rows) == 1                       # evidence under the old id finds the decision under the new one
    assert sorted(_with_merged_ids(store, ["canon"])) == ["canon", "orph"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
