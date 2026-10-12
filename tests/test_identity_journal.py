"""The identity journal (core/identity_journal.py; Documentation/internal/IDENTITY_MODEL.md, P1): time-bounded bindings
of identifiers to devices and an exact record of every identity change, written to the graph (identity_bindings /
identity_events). P1 is shadow -- nothing reads it to decide identity -- so it must never fail the caller and never
lose a record it was given."""
import sys
import threading
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from argus.graph.store import GraphStore  # noqa: E402
from core.identity_journal import IdentityJournal  # noqa: E402


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def graph(tmp_path):
    g = GraphStore(str(tmp_path / "g.db"))
    yield g
    g.close()


def _bindings(g, **where):
    rows = [dict(r) for r in g._conn.execute("SELECT * FROM identity_bindings ORDER BY binding_id")]
    return [r for r in rows if all(r.get(k) == v for k, v in where.items())]


def _events(g):
    return [dict(r) for r in g._conn.execute("SELECT * FROM identity_events ORDER BY event_id")]


def test_a_binding_opens_extends_and_is_written(graph):
    j = IdentityJournal(clock=_Clock())
    j.observe("phone", "10.0.0.39", "aa:00:00:00:00:01", True, ts=100.0)
    j.observe("phone", "10.0.0.39", "aa:00:00:00:00:01", True, ts=160.0)
    assert j.flush(graph) > 0
    mac, addr = _bindings(graph, id_kind="mac")[0], _bindings(graph, id_kind="address")[0]
    assert (mac["device_id"], mac["valid_from"], mac["last_seen"], mac["valid_to"]) == ("phone", 100.0, 160.0, None)
    assert (addr["evidence"], addr["last_seen"]) == ("mac_observed", 160.0)
    assert [e["kind"] for e in _events(graph)] == ["mac_observed", "address_attributed"]
    j.observe("phone", "10.0.0.39", "aa:00:00:00:00:01", True, ts=220.0)     # later extension: an UPDATE, no new row
    j.flush(graph)
    assert len(_bindings(graph)) == 2 and _bindings(graph, id_kind="mac")[0]["last_seen"] == 220.0


def test_an_address_that_changes_hands_closes_one_tenure_and_opens_the_next(graph):
    j = IdentityJournal(clock=_Clock())
    j.observe("laptop", "10.0.0.59", "70:00:00:00:00:02", True, ts=100.0)
    j.flush(graph)
    j.observe("printer", "10.0.0.59", "70:00:00:00:00:09", True, ts=500.0)
    j.flush(graph)
    a = _bindings(graph, id_kind="address")
    assert [(b["device_id"], b["valid_from"], b["valid_to"]) for b in a] == [("laptop", 100.0, 500.0),
                                                                             ("printer", 500.0, None)]
    hand = [e for e in _events(graph) if e["kind"] == "handed_over"]
    assert hand and (hand[0]["device_id"], hand[0]["other_device_id"], hand[0]["id_value"]) == \
        ("laptop", "printer", "10.0.0.59")


def test_without_an_observed_mac_only_the_address_is_recorded_as_a_guess(graph):
    j = IdentityJournal(clock=_Clock())
    j.observe("phone", "10.0.0.59", "70:00:00:00:00:02", False, ts=100.0)    # MAC from the router table: not evidence
    j.flush(graph)
    assert _bindings(graph, id_kind="mac") == []
    assert _bindings(graph, id_kind="address")[0]["evidence"] == "no_mac"


def test_release_and_retraction_are_recorded_and_rows_are_kept(graph):
    j = IdentityJournal(clock=_Clock())
    j.bind("legacy_id", "9989de06dc0f", "phone", ts=100.0, evidence="merge")
    j.bind("address", "10.0.0.40", "tv", ts=100.0)
    j.flush(graph)
    j.unbind("legacy_id", "9989de06dc0f", "phone", ts=300.0, reason="split: traffic from another MAC", retract=True)
    j.unbind("address", "10.0.0.40", "someone-else", ts=300.0)              # not that device's: ignored
    j.unbind("address", "10.0.0.40", "tv", ts=310.0, reason="history pruned")
    j.flush(graph)
    leg = _bindings(graph, id_kind="legacy_id")[0]
    assert (leg["valid_to"], leg["retracted_at"]) == (300.0, 300.0) and "split" in leg["retracted_by"]
    assert _bindings(graph, id_kind="address")[0]["valid_to"] == 310.0
    kinds = [e["kind"] for e in _events(graph)]
    assert "retracted" in kinds and "released" in kinds
    assert len(_bindings(graph)) == 2                                         # nothing deleted


def test_open_bindings_survive_a_restart(graph):
    j = IdentityJournal(clock=_Clock())
    j.observe("phone", "10.0.0.39", "aa:00:00:00:00:01", True, ts=100.0)
    j.flush(graph)
    j2 = IdentityJournal(clock=_Clock())
    j2.load_open(graph.load_open_identity_bindings())
    assert j2.current() == {("mac", "aa:00:00:00:00:01"): "phone", ("address", "10.0.0.39"): "phone"}
    j2.observe("laptop", "10.0.0.39", "70:00:00:00:00:02", True, ts=900.0)   # the restarted journal closes the old row
    j2.flush(graph)
    assert [(b["device_id"], b["valid_to"]) for b in _bindings(graph, id_kind="address")] == [("phone", 900.0),
                                                                                                ("laptop", None)]


def test_a_failed_write_is_kept_for_the_next_flush(graph):
    j = IdentityJournal(clock=_Clock())
    j.observe("phone", "10.0.0.39", "aa:00:00:00:00:01", True, ts=100.0)
    j.event("name_changed", ts=101.0, device_id="phone", detail={"old": "a", "new": "b"})

    class _Broken:
        def write_identity_journal(self, *a):
            raise RuntimeError("database is locked")
    assert j.flush(_Broken()) == 0 and j.pending() > 0
    assert j.flush(graph) > 0 and j.pending() == 0
    assert {e["kind"] for e in _events(graph)} == {"mac_observed", "address_attributed", "name_changed"}


def test_a_close_racing_a_flush_is_not_lost(graph):
    j = IdentityJournal(clock=_Clock())
    j.observe("phone", "10.0.0.39", "aa:00:00:00:00:01", True, ts=100.0)

    class _Racing:
        def write_identity_journal(self, events, opened, updates):
            # the reconcile thread hands the address over while this batch (with its insert) is being written
            t = threading.Thread(target=j.observe, args=("laptop", "10.0.0.39", "70:00:00:00:00:02", True, 200.0))
            t.start(); t.join()
            return graph.write_identity_journal(events, opened, updates)
    j.flush(_Racing())
    j.flush(graph)
    a = _bindings(graph, id_kind="address")
    assert [(b["device_id"], b["valid_to"]) for b in a] == [("phone", 200.0), ("laptop", None)]


def test_the_journal_never_raises_into_the_caller():
    j = IdentityJournal()
    j.bind("not-a-kind", "x", "d")                       # ignored
    j.bind("mac", "", "d"); j.bind("mac", "aa", "")      # ignored
    j.event("anything", device_id=object())             # odd input still does not raise
    assert j.flush(None) == 0


# --- wiring: the state manager, the resolver and the tools record into / read from the journal -------------------------

import time  # noqa: E402

from core.state_guard import StateManager  # noqa: E402
from core.identity import DeviceIdentityManager, stable_device_id  # noqa: E402


class _Zeek:
    def __init__(self, macs, names=None):
        self.macs, self.names = macs, names or {}

    def get_mac(self, ip):
        return self.macs.get(ip)

    def get_hostname(self, ip):
        return self.names.get(ip, "unknown")

    def get_dhcp_fingerprint(self, ip):
        return None

    def get_ja4_set(self, ip):
        return set()


@pytest.fixture
def wired(tmp_path, graph):
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    mgr = DeviceIdentityManager(sm, {})
    j = IdentityJournal()
    sm.journal = mgr.journal = j
    return sm, mgr, j, graph


def test_the_state_manager_records_creation_merge_split_and_release(wired):
    sm, mgr, j, graph = wired
    sm.get_or_create(device_id="frag", client_ip="fe80::77", hostname="unknown")
    canon = sm.get_or_create(device_id="dev", client_ip="10.0.0.77", hostname="unknown")
    canon.mac_address = "aa:00:00:00:00:77"
    sm.bind_mac("aa:00:00:00:00:77", "dev")
    assert sm.merge_into_canonical("frag", "dev", reason="fragment: fe80::77 observed with MAC aa:00:00:00:00:77")
    sm.split_merged_id("frag", "bb:00:00:00:00:01")
    sm.release_address("dev", "10.0.0.77", reason="changed hands: now device x")
    j.flush(graph)
    kinds = [e["kind"] for e in _events(graph)]
    for k in ("device_created", "id_bound", "merge", "retracted", "split"):
        assert k in kinds, (k, kinds)
    merge = next(e for e in _events(graph) if e["kind"] == "merge")
    assert (merge["device_id"], merge["other_device_id"]) == ("dev", "frag") and "observed with MAC" in merge["reason"]
    leg = _bindings(graph, id_kind="legacy_id")[0]
    assert leg["retracted_at"] is not None and "split" in leg["retracted_by"]


def test_the_resolver_records_attributions_names_and_hand_overs(wired):
    sm, mgr, j, graph = wired
    mgr.process_zeek_identities([{"id.orig_h": "10.0.0.5"}], _Zeek({"10.0.0.5": "aa:00:00:00:00:05"},
                                                                    {"10.0.0.5": "kitchen-tablet"}))
    dev = sm.get_device_id_for_mac("aa:00:00:00:00:05")
    mgr.process_dns_identities([{"client_ip": "10.0.0.5", "hostname": "den-tablet", "domain": "example.org"}],
                               _Zeek({"10.0.0.5": "aa:00:00:00:00:05"}))
    # the address goes to another device: observed with another MAC
    mgr.process_zeek_identities([{"id.orig_h": "10.0.0.5"}], _Zeek({"10.0.0.5": "aa:00:00:00:00:06"}))
    j.flush(graph)
    kinds = [e["kind"] for e in _events(graph)]
    assert "mac_observed" in kinds and "address_attributed" in kinds and "name_changed" in kinds
    a = _bindings(graph, id_kind="address", id_value="10.0.0.5")
    assert [b["device_id"] for b in a][0] == dev and a[0]["valid_to"] is not None and a[-1]["valid_to"] is None
    assert any(e["kind"] in ("released", "handed_over") and e["id_value"] == "10.0.0.5" for e in _events(graph))


def test_identify_device_shows_the_timeline(wired):
    import sqlite3
    import identify_device
    sm, mgr, j, graph = wired
    mgr.process_zeek_identities([{"id.orig_h": "10.0.0.8"}], _Zeek({"10.0.0.8": "aa:00:00:00:00:08"}))
    j.flush(graph)
    conn = sqlite3.connect(graph.db_path if hasattr(graph, "db_path") else graph._conn.execute(
        "PRAGMA database_list").fetchone()[2])
    r = identify_device.identify(sm, "aa:00:00:00:00:08", conn)
    assert r["timeline"]["bindings"][0]["device_id"] == sm.get_device_id_for_mac("aa:00:00:00:00:08")
    assert any(e["kind"] == "mac_observed" for e in r["timeline"]["events"])


def test_shadow_report_agrees_and_flags_a_disagreement(wired):
    import sqlite3
    import identity_shadow_report
    sm, mgr, j, graph = wired
    mgr.process_zeek_identities([{"id.orig_h": "10.0.0.9"}], _Zeek({"10.0.0.9": "aa:00:00:00:00:09"}))
    j.flush(graph)
    conn = sqlite3.connect(graph._conn.execute("PRAGMA database_list").fetchone()[2])
    assert identity_shadow_report.compare(sm, conn)["disagreements"] == []
    dev = sm.get_device_id_for_mac("aa:00:00:00:00:09")
    with sm.lock_device(dev) as st:
        st.client_ip = "10.0.0.99"                           # the engine believes something the ledger never saw
    d = identity_shadow_report.compare(sm, conn)["disagreements"]
    assert d == [{"kind": "address", "identifier": "10.0.0.99", "engine": dev, "ledger": None, "ledger_evidence": None}]


def test_both_tools_run_from_the_command_line(tmp_path, monkeypatch, capsys):
    import config as config_module
    import identify_device
    import identity_shadow_report
    state_path = tmp_path / "ids_state.json"
    sm = StateManager(state_path=str(state_path))
    mgr = DeviceIdentityManager(sm, {})
    j = IdentityJournal()
    sm.journal = mgr.journal = j
    mgr.process_zeek_identities([{"id.orig_h": "10.0.0.12"}], _Zeek({"10.0.0.12": "aa:00:00:00:00:12"}))
    sm.flush_to_disk()
    g = GraphStore(str(tmp_path / "v13_graph.db"))
    j.flush(g)
    g.close()
    monkeypatch.setattr(config_module, "CONFIG", {"state_path": str(state_path)})

    monkeypatch.setattr(sys, "argv", ["identity_shadow_report.py"])
    assert identity_shadow_report.main() == 0 and "agree" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["identity_shadow_report.py", "--json"])
    assert identity_shadow_report.main() == 0
    import json as _json
    assert _json.loads(capsys.readouterr().out)["checked"]["mac"] == 1

    monkeypatch.setattr(sys, "argv", ["identify_device.py", "10.0.0.12"])
    assert identify_device.main() == 0
    out = capsys.readouterr().out
    assert "bindings (who held it when" in out and "identity events" in out and "address_attributed" in out


def test_shadow_report_without_a_ledger_or_a_graph(tmp_path, monkeypatch, capsys):
    import sqlite3
    import config as config_module
    import identity_shadow_report
    state_path = tmp_path / "ids_state.json"
    StateManager(state_path=str(state_path)).flush_to_disk()
    monkeypatch.setattr(config_module, "CONFIG", {"state_path": str(state_path)})
    monkeypatch.setattr(sys, "argv", ["identity_shadow_report.py"])
    assert identity_shadow_report.main() == 2 and "No graph" in capsys.readouterr().out
    sqlite3.connect(str(tmp_path / "v13_graph.db")).execute("CREATE TABLE devices (device_id TEXT)").connection.commit()
    assert identity_shadow_report.main() == 2 and "no identity ledger" in capsys.readouterr().out
