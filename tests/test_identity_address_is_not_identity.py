"""
An address is a lease, not an identity (2026-10-12). Found on .94: a laptop's whole identity (the addresses of both its
NICs) had been folded into a phone's, because device identity treated a shared address as proof of one device:
- the periodic reconcile linked any two devices whose address HISTORIES overlapped (DHCP reuse makes that normal),
  transitively, and every merge grew the history behind the next one;
- the real-time path folded the device an address was last tracked under into the device it now resolves to, even
  when that device had its own, different MAC;
- the router's host table (which lists inactive hosts with the address they LAST had) overrode the MAC Zeek observed;
- the address index was never rebuilt at load, so a long-running engine kept every address a merge pointed elsewhere.

Now a device is the MAC its traffic was observed from: an address joins two identities only when one of them never
had a MAC (an address-only fragment) and the MAC was observed; two real MACs are one device only as a MAC rotation
(name or fingerprint, never active at the same time); an address that changed hands leaves the old device; operator
containment acts only on a device identified exactly; src/identify_device.py tells which device anything belongs to.
"""
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import ADDRESS_HOLD_WINDOW_SECONDS, StateManager  # noqa: E402
from core.identity import DeviceIdentityManager, router_host_caches, stable_device_id  # noqa: E402
import identify_device  # noqa: E402
from merge_fragmented_devices import find_fragmented_groups  # noqa: E402

PHONE_MAC, LAPTOP_MAC, OTHER_MAC = "a2:00:00:00:00:01", "70:00:00:00:00:02", "58:00:00:00:00:03"
PHONE_IP, LAPTOP_IP, LAPTOP_LL = "10.20.0.39", "10.20.0.59", "fe80::7200:ff:fe00:2"


@pytest.fixture
def sm(tmp_path):
    return StateManager(state_path=str(tmp_path / "ids_state.json"))


def _dev(sm, dev_id, ip, mac="unknown", host="unknown", seen=None, history=()):
    st = sm.get_or_create(device_id=dev_id, client_ip=ip, hostname=host)
    st.mac_address = mac
    st.known_ips.add(ip)
    for h in history:
        st.known_ips.add(h)
    if seen is not None:
        st.last_seen = seen
    if mac != "unknown":
        sm.bind_mac(mac, dev_id)
    return st


class _Zeek:
    """What process_*_identities reads from Zeek: the MAC each address's traffic was observed from."""
    def __init__(self, macs):
        self.macs = macs

    def get_mac(self, ip):
        return self.macs.get(ip)

    def get_hostname(self, ip):
        return "unknown"

    def get_dhcp_fingerprint(self, ip):
        return None

    def get_ja4_set(self, ip):
        return set()


@pytest.fixture
def mgr(sm):
    return DeviceIdentityManager(sm, {})


# --- router table and caches ------------------------------------------------------------------------------------------

def test_router_table_uses_only_active_entries_for_addresses():
    by_ip, by_mac = router_host_caches([
        {"ip": "10.20.0.5", "mac": "AA:00:00:00:00:0A", "name": "printer", "active": True},
        {"ip": "10.20.0.5", "mac": "aa:00:00:00:00:0b", "name": "old-phone", "active": False},   # stale lease
        {"ip": "10.20.0.6", "mac": "aa:00:00:00:00:0c", "name": "nas"},                          # cannot tell
    ])
    assert by_ip["10.20.0.5"] == {"mac": "aa:00:00:00:00:0a", "name": "printer"}
    assert by_mac["aa:00:00:00:00:0b"] == {"ip": "unknown", "name": "old-phone"}                # name kept, no address
    assert by_ip["10.20.0.6"]["mac"] == "aa:00:00:00:00:0c"


def test_the_observed_mac_wins_over_the_router_table(mgr):
    mgr._fritz_cache = {"10.20.0.5": {"mac": OTHER_MAC, "name": "old-phone"}}
    # observed from another MAC: the router's entry is about another device -- neither its MAC nor its name applies
    assert mgr._enrich_from_cache("10.20.0.5", LAPTOP_MAC, "unknown") == (LAPTOP_MAC, "unknown")
    # nothing observed: the router fills in
    assert mgr._enrich_from_cache("10.20.0.5", "unknown", "unknown") == (OTHER_MAC, "old-phone")
    assert mgr._enrich_from_cache("10.20.0.5", OTHER_MAC, "unknown") == (OTHER_MAC, "old-phone")


def test_the_address_cache_forgets_the_previous_holders_name(mgr):
    mgr._enrich_from_cache("10.20.0.7", OTHER_MAC, "old-phone")
    assert mgr._enrich_from_cache("10.20.0.7", LAPTOP_MAC, "unknown") == (LAPTOP_MAC, "unknown")


# --- the real-time merge decision -----------------------------------------------------------------------------------

def _merge(mgr, ip, dev_id, mac, observed):
    return mgr._merge_orphan_if_fragmented(ip, dev_id, None, None, None, None, None, event_mac=mac, mac_observed=observed)


def test_an_address_that_changed_hands_is_released_not_merged(sm, mgr):
    _dev(sm, "phone", PHONE_IP, PHONE_MAC, history=[LAPTOP_IP])
    sm._ip_to_device_id[LAPTOP_IP] = "phone"            # as a long-running engine had it after the wrong merge
    _dev(sm, "laptop", "10.20.0.60", LAPTOP_MAC)
    assert _merge(mgr, LAPTOP_IP, "laptop", LAPTOP_MAC, observed=True) is None
    assert sm.has_device("phone") and sm.has_device("laptop")
    with sm.lock_device("phone") as p:
        assert LAPTOP_IP not in p.known_ips and p.mac_address == PHONE_MAC
    assert sm.get_device_id_for_ip(LAPTOP_IP) != "phone"


def test_without_an_observed_mac_nothing_is_merged(sm, mgr):
    _dev(sm, "fragment", "10.20.0.70")
    _dev(sm, "device", "10.20.0.71", LAPTOP_MAC)
    assert _merge(mgr, "10.20.0.70", "device", LAPTOP_MAC, observed=False) is None   # MAC from the router / a cache
    assert sm.has_device("fragment")


@pytest.mark.parametrize("orphan_mac", ["unknown", LAPTOP_MAC])
def test_a_fragment_or_the_same_mac_is_merged_on_an_observed_mac(sm, mgr, orphan_mac):
    _dev(sm, "fragment", "10.20.0.70", orphan_mac)
    _dev(sm, "device", "10.20.0.71", LAPTOP_MAC)
    assert _merge(mgr, "10.20.0.70", "device", LAPTOP_MAC, observed=True) == "fragment"
    assert not sm.has_device("fragment")


def test_replay_of_the_94_incident_the_laptop_is_seen_again(sm, mgr):
    """The phone carries the laptop's addresses from the old wrong merge; the laptop's next DNS query is observed from
    its own MAC. Before: the laptop's address resolved to a new address-anchored id, the index named the phone as the
    address's previous holder, and the PHONE was folded into it. Now nothing is merged and the address goes home."""
    _dev(sm, "phone", PHONE_IP, PHONE_MAC, history=[LAPTOP_IP, LAPTOP_LL])
    sm._ip_to_device_id[LAPTOP_IP] = "phone"
    sm._ip_to_device_id[LAPTOP_LL] = "phone"
    zeek = _Zeek({LAPTOP_IP: LAPTOP_MAC, LAPTOP_LL: LAPTOP_MAC, PHONE_IP: PHONE_MAC})
    mgr.process_dns_identities([{"client_ip": LAPTOP_IP, "hostname": "unknown", "domain": "example.org"},
                                {"client_ip": LAPTOP_LL, "hostname": "unknown", "domain": "example.org"}], zeek)
    laptop = sm.get_device_id_for_mac(LAPTOP_MAC)
    assert sm.has_device("phone") and laptop and laptop != "phone"
    assert sorted(sm.get_all_device_ids()) == sorted(["phone", laptop])
    with sm.lock_device("phone") as p:
        assert p.mac_address == PHONE_MAC and p.client_ip == PHONE_IP
        assert LAPTOP_IP not in p.known_ips and LAPTOP_LL not in p.known_ips
    with sm.lock_device(laptop) as l:
        assert {LAPTOP_IP, LAPTOP_LL} <= set(l.known_ips)
    assert identify_device.identify(sm, LAPTOP_MAC)["current"][0]["device_id"] == laptop


# --- state: index at load, self-healing history, exact identity -----------------------------------------------------

def test_the_address_index_is_rebuilt_from_current_addresses_at_load(tmp_path):
    path = str(tmp_path / "ids_state.json")
    sm = StateManager(state_path=path)
    now = time.time()
    _dev(sm, "d1", "10.20.0.10", "aa:00:00:00:00:01", seen=now - 100, history=["10.20.0.11"])
    _dev(sm, "d2", "10.20.0.11", "aa:00:00:00:00:02", seen=now - 50)
    _dev(sm, "old", "10.20.0.12", "aa:00:00:00:00:03", seen=now - 9000)
    _dev(sm, "new", "10.20.0.12", "aa:00:00:00:00:04", seen=now)
    sm.flush_to_disk()
    fresh = StateManager(state_path=path)
    fresh.load_from_disk()
    assert fresh.get_device_id_for_ip("10.20.0.10") == "d1"
    assert fresh.get_device_id_for_ip("10.20.0.11") == "d2"                  # current holder, not d1's history
    assert fresh.get_device_id_for_ip("10.20.0.12") == "new"                 # the most recently seen claimant


def test_a_reassigned_address_leaves_the_old_devices_history(sm):
    now = time.time()
    _dev(sm, "old", "10.20.0.21", "aa:00:00:00:00:01", seen=now - 600, history=["10.20.0.20"])
    _dev(sm, "new", "10.20.0.20", "aa:00:00:00:00:02", seen=now)
    _dev(sm, "fragment", "10.20.0.22", history=["10.20.0.20"])                # no MAC: left to the reconcile
    _dev(sm, "same", "10.20.0.23", "aa:00:00:00:00:02", history=["10.20.0.20"])   # same MAC as the holder
    removed = sm.prune_reassigned_addresses()
    assert removed == [{"device_id": "old", "address": "10.20.0.20", "now_owned_by": "new"}]
    for dev, kept in (("fragment", True), ("same", True), ("new", True)):
        with sm.lock_device(dev) as st:
            assert ("10.20.0.20" in st.known_ips) is kept
    assert sm.prune_reassigned_addresses() == []                              # idempotent


def test_identity_check(sm):
    now = time.time()
    _dev(sm, "exact", "10.20.0.30", "aa:00:00:00:00:01", seen=now)
    _dev(sm, "no-mac", "10.20.0.31")
    _dev(sm, "dup1", "10.20.0.32", "aa:00:00:00:00:02", seen=now)
    _dev(sm, "dup2", "10.20.0.33", "aa:00:00:00:00:02", seen=now)
    _dev(sm, "shared1", "10.20.0.34", "aa:00:00:00:00:03", seen=now)
    _dev(sm, "shared2", "10.20.0.34", "aa:00:00:00:00:04", seen=now - 60)
    _dev(sm, "stale", "10.20.0.35", "aa:00:00:00:00:05", seen=now - ADDRESS_HOLD_WINDOW_SECONDS - 600)
    _dev(sm, "holder", "10.20.0.35", "aa:00:00:00:00:06", seen=now)
    assert sm.identity_check("exact") == {"exact": True, "reason": ""}
    assert not sm.identity_check("no-mac")["exact"] and "No MAC" in sm.identity_check("no-mac")["reason"]
    assert not sm.identity_check("dup1")["exact"] and "dup2" in sm.identity_check("dup1")["reason"]
    assert not sm.identity_check("shared1")["exact"] and not sm.identity_check("shared2")["exact"]
    assert sm.identity_check("holder")["exact"]                    # the stale claimant handed the address on
    assert not sm.identity_check("stale")["exact"]                 # its address is now someone else's
    assert not sm.identity_check("missing")["exact"]


# --- the periodic reconcile -------------------------------------------------------------------------------------------

def _groups(sm, ambiguous=None):
    return [sorted(m["device_id"] for m in g) for g in find_fragmented_groups(sm, ambiguous=ambiguous)]


def test_reconcile_never_links_two_macs_by_an_address(sm):
    now = time.time()
    _dev(sm, "phone", PHONE_IP, PHONE_MAC, seen=now, history=[LAPTOP_IP])
    _dev(sm, "laptop", LAPTOP_IP, LAPTOP_MAC, seen=now)
    assert _groups(sm) == []


def test_reconcile_two_macs_with_one_name_active_together_are_two_devices(sm):
    now = time.time()
    _dev(sm, "wired", "10.20.0.40", LAPTOP_MAC, host="office-laptop", seen=now)
    _dev(sm, "wifi", "10.20.0.41", OTHER_MAC, host="office-laptop", seen=now - 30)        # two NICs, both active
    assert _groups(sm) == []


def test_reconcile_a_mac_rotation_is_still_merged(sm):
    now = time.time()
    _dev(sm, "before", "10.20.0.42", "a6:00:00:00:00:01", host="den-tablet", seen=now - ADDRESS_HOLD_WINDOW_SECONDS - 60)
    _dev(sm, "after", "10.20.0.43", "a6:00:00:00:00:02", host="den-tablet", seen=now)
    groups = find_fragmented_groups(sm)
    assert [sorted(m["device_id"] for m in g) for g in groups] == [["after", "before"]]
    assert any("MAC rotation" in r for m in groups[0] for r in m["linked_by"])


def test_reconcile_a_fragment_shared_by_two_devices_is_ambiguous_not_merged(sm):
    now = time.time()
    _dev(sm, "a", "10.20.0.50", "aa:00:00:00:00:0a", seen=now, history=["10.20.0.52"])
    _dev(sm, "b", "10.20.0.51", "aa:00:00:00:00:0b", seen=now, history=["10.20.0.52"])
    _dev(sm, "fragment", "10.20.0.52", seen=now - 60)
    ambiguous = []
    assert _groups(sm, ambiguous) == []
    assert sorted(m["device_id"] for m in ambiguous[0]["members"]) == ["a", "b", "fragment"]
    assert "not linked as a MAC rotation" in ambiguous[0]["reason"]


def test_reconcile_a_fragment_seen_after_the_device_left_its_address_is_not_folded_in(sm):
    now = time.time()
    _dev(sm, "device", "10.20.0.61", LAPTOP_MAC, seen=now - 3 * ADDRESS_HOLD_WINDOW_SECONDS, history=["10.20.0.60"])
    _dev(sm, "newcomer", "10.20.0.60", seen=now)          # more likely a new device that got the address
    assert _groups(sm) == []


def test_reconcile_pass_on_the_94_shape_merges_nothing_and_heals_the_history(sm):
    from core.pipeline import EnginePipeline
    now = time.time()
    _dev(sm, "phone", PHONE_IP, PHONE_MAC, seen=now, history=[LAPTOP_IP, LAPTOP_LL])
    _dev(sm, "laptop", LAPTOP_IP, LAPTOP_MAC, seen=now - 30)
    fake = SimpleNamespace(state_manager=sm, config={}, ml_registry=None, familiarity=None,
                           identity_manager=None, ips_mitigator=None, evidence_store=None, metrics_exporter=None,
                           alert_manager=None)
    assert EnginePipeline._identity_reconcile_pass(fake) == 0
    assert sorted(sm.get_all_device_ids()) == ["laptop", "phone"]
    with sm.lock_device("phone") as p:
        assert LAPTOP_IP not in p.known_ips and LAPTOP_LL in p.known_ips   # .LL: its owner is not seen there yet


# --- splits: a wrong merge is undone when the merged-away id's own traffic proves it -----------------------------------
# A merge redirect is permanent: on .94 the laptop's address-anchored ids (hash of its address) all redirected to the
# phone, so every later sighting of the laptop -- with all of the above in place -- would still have landed on the phone.

def _graph(tmp_path, name="g"):
    from argus.graph.store import GraphStore
    return GraphStore(str(tmp_path / f"{name}.db"))


def test_replay_94_with_the_redirect_map_and_the_graph(tmp_path):
    from argus.identity.live_manager import LiveIdentityManager
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    graph = _graph(tmp_path)
    laptop_id = stable_device_id(LAPTOP_IP)                 # what the laptop's address hashes to
    _dev(sm, "phone", PHONE_IP, PHONE_MAC, history=[LAPTOP_IP])
    _dev(sm, laptop_id, LAPTOP_IP, LAPTOP_MAC)
    sm.merge_into_canonical(laptop_id, "phone")             # the old wrong merge
    graph.merge_device(laptop_id, "phone")
    with sm.lock_device("phone") as p:
        p.mac_address = PHONE_MAC                           # the phone's own MAC (as on .94)
    sm._mac_to_device_id.pop(LAPTOP_MAC, None)              # the index after a restart: current MACs only
    assert sm.resolve_merge_redirect(laptop_id) == "phone" and graph.resolve_canonical_device_id(laptop_id) == "phone"

    mgr = LiveIdentityManager(sm, {}, graph, {})
    mgr.process_dns_identities([{"client_ip": LAPTOP_IP, "hostname": "unknown", "domain": "example.org"}],
                               _Zeek({LAPTOP_IP: LAPTOP_MAC}))
    assert sm.resolve_merge_redirect(laptop_id) == laptop_id and sm.has_device(laptop_id)
    assert sm.get_device_id_for_mac(LAPTOP_MAC) == laptop_id
    assert sm.get_identity_splits()[laptop_id]["from"] == "phone"
    with sm.lock_device("phone") as p:
        assert p.mac_address == PHONE_MAC and LAPTOP_IP not in p.known_ips
    assert graph.resolve_canonical_device_id(laptop_id) == laptop_id         # the graph un-merged it too
    assert laptop_id not in graph._all_ids_resolving_to("phone")             # e.g. autotune's device thresholds
    assert identify_device.identify(sm, laptop_id)["split_from"]["from"] == "phone"


@pytest.mark.parametrize("observed, target_mac, event_mac", [
    (False, PHONE_MAC, LAPTOP_MAC),          # a MAC from the router / a cache decides nothing
    (True, "unknown", LAPTOP_MAC),           # the target never had a MAC of its own: an address-only fragment
    (True, PHONE_MAC, PHONE_MAC),            # the same MAC: the merge was right
])
def test_a_redirect_is_followed_unless_an_observed_mac_proves_it_wrong(sm, mgr, observed, target_mac, event_mac):
    _dev(sm, "target", PHONE_IP, target_mac)
    sm._merge_redirects["gone"] = "target"
    assert mgr._follow_merge_redirect("gone", event_mac, observed) == "target"
    assert sm.get_identity_splits() == {}


def test_a_split_survives_a_restart_and_ends_with_a_later_legitimate_merge(tmp_path):
    path = str(tmp_path / "ids_state.json")
    sm = StateManager(state_path=path)
    _dev(sm, "phone", PHONE_IP, PHONE_MAC)
    sm._merge_redirects["gone"] = "phone"
    assert sm.split_merged_id("gone", LAPTOP_MAC) == "phone"
    assert sm.split_merged_id("never-merged", LAPTOP_MAC) is None
    sm.flush_to_disk()
    fresh = StateManager(state_path=path)
    fresh.load_from_disk()
    assert "gone" in fresh.get_identity_splits() and fresh.resolve_merge_redirect("gone") == "gone"
    _dev(fresh, "gone", "10.20.0.88")                                       # seen again, address-only ...
    assert fresh.merge_into_canonical("gone", "phone")                       # ... and merged for a real reason
    assert "gone" not in fresh.get_identity_splits()


def test_the_reconcile_worker_replays_a_split_the_graph_missed(tmp_path, monkeypatch):
    import argus.ops.live_engine as live_engine
    path = tmp_path / "graph.db"
    monkeypatch.setattr(live_engine, "_GRAPH_DB_PATH", str(path))
    from argus.graph.store import GraphStore
    g = GraphStore(str(path))
    g.merge_device("laptop-id", "phone")
    g.close()
    assert live_engine.reconcile_graph_splits_in_own_connection({"laptop-id": {"from": "phone"}}) == ["laptop-id"]
    assert live_engine.reconcile_graph_splits_in_own_connection({"laptop-id": {"from": "phone"}}) == []   # done once
    g = GraphStore(str(path))
    assert g.resolve_canonical_device_id("laptop-id") == "laptop-id"
    assert g.get_edges(relation="merged_into") == []
    g.close()


# --- identify_device.py -----------------------------------------------------------------------------------------------

def test_identify_device_verdicts(sm):
    now = time.time()
    _dev(sm, "phone", PHONE_IP, PHONE_MAC, seen=now, history=["10.20.0.80"])
    _dev(sm, "fragment", "10.20.0.81")
    _dev(sm, "x", "10.20.0.82", "aa:00:00:00:00:0c", seen=now)
    _dev(sm, "y", "10.20.0.82", "aa:00:00:00:00:0d", seen=now)
    assert identify_device.identify(sm, PHONE_IP)["verdict"] == "EXACT"
    assert identify_device.identify(sm, PHONE_MAC.upper())["current"][0]["device_id"] == "phone"
    assert identify_device.identify(sm, "phone")["verdict"] == "EXACT"
    r = identify_device.identify(sm, "10.20.0.80")
    assert r["verdict"] == "UNKNOWN" and [s["device_id"] for s in r["history"]] == ["phone"]
    assert identify_device.identify(sm, "10.20.0.81")["verdict"] == "NOT EXACT"
    assert identify_device.identify(sm, "10.20.0.82")["verdict"] == "AMBIGUOUS"
    sm._merge_redirects["gone"] = "phone"
    r = identify_device.identify(sm, "gone")
    assert r["merged_into"] == "phone" and r["verdict"] == "EXACT"


# --- operator containment waits for an exact identity -------------------------------------------------------------------

def test_console_tarpit_and_isolate_refuse_a_device_not_identified_exactly(tmp_path, monkeypatch):
    from middleware.routers import mitigation_api
    from mitigation.ips import IPSMitigator
    path = tmp_path / "ids_state.json"
    sm = StateManager(state_path=str(path))
    _dev(sm, "dup1", "10.20.0.90", "aa:00:00:00:00:0e")
    _dev(sm, "dup2", "10.20.0.91", "aa:00:00:00:00:0e")
    sm.flush_to_disk()
    monkeypatch.setattr(mitigation_api, "CONFIG", {"state_path": str(path), "ips_tarpit_enabled": True,
                                                   "ips_router_enabled": True})
    engine = StateManager(state_path=str(path))
    engine.load_from_disk()
    armed = IPSMitigator(config={"state_path": str(path)}, state_manager=engine, start_workers=False)
    armed.tarpit_armed = True
    armed._publish_engine_tarpit_state()
    engine.flush_to_disk()
    for call in (mitigation_api.tarpit_device, mitigation_api.isolate_device_router):
        with pytest.raises(HTTPException) as exc:
            call("dup1", mitigation_api.ReasonPayload(), token="test")
        assert exc.value.status_code == 409 and "not identified exactly" in exc.value.detail and "dup2" in exc.value.detail
    check = StateManager(state_path=str(path))
    check.load_from_disk()
    assert check.get_ips_state().get("tarpit_targets", {}) == {}


def test_block_refuses_an_address_claimed_by_two_devices(tmp_path, monkeypatch):
    from middleware.routers import fritzbox_api
    path = tmp_path / "ids_state.json"
    sm = StateManager(state_path=str(path))
    _dev(sm, "x", "10.20.0.95", "aa:00:00:00:00:0f")
    _dev(sm, "y", "10.20.0.95", "aa:00:00:00:00:10")
    sm.flush_to_disk()
    monkeypatch.setattr(fritzbox_api, "CONFIG", {"state_path": str(path)})
    with pytest.raises(HTTPException) as exc:
        fritzbox_api._ipc_block_logic("10.20.0.95")
    assert exc.value.status_code == 409 and "claimed by 2 devices" in exc.value.detail


def test_identify_device_command_line(tmp_path, monkeypatch, capsys):
    import config as config_module
    path = tmp_path / "ids_state.json"
    sm = StateManager(state_path=str(path))
    now = time.time()
    _dev(sm, "phone", PHONE_IP, PHONE_MAC, seen=now - 30, history=["10.20.0.80"])
    _dev(sm, "fragment", "10.20.0.81", seen=now - 3 * 86400)
    sm._merge_redirects["gone"] = "phone"
    sm.split_merged_id("gone", LAPTOP_MAC)
    sm.flush_to_disk()
    monkeypatch.setattr(config_module, "CONFIG", {"state_path": str(path)})

    monkeypatch.setattr(sys, "argv", ["identify_device.py", PHONE_IP])
    assert identify_device.main() == 0
    out = capsys.readouterr().out
    assert "EXACT" in out and "phone" in out and "address history" in out and "min ago" in out

    monkeypatch.setattr(sys, "argv", ["identify_device.py", "10.20.0.81"])
    assert identify_device.main() == 1                                     # not exact: no MAC
    out = capsys.readouterr().out
    assert "NOT EXACT" in out and "not exact:" in out and "d ago" in out

    monkeypatch.setattr(sys, "argv", ["identify_device.py", "gone"])
    assert identify_device.main() == 1                                     # split, not seen since
    assert "split again" in capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", ["identify_device.py", "10.20.0.80", "--json"])
    assert identify_device.main() == 1
    import json
    assert json.loads(capsys.readouterr().out)["history"][0]["device_id"] == "phone"

    monkeypatch.setattr(sys, "argv", ["identify_device.py"])
    assert identify_device.main() == 2 and "Usage" in capsys.readouterr().out
    assert identify_device._age(0) == "never" and identify_device._age(time.time() - 7200).endswith("h ago")


def test_router_adapter_contract_and_fritz_active_flag(monkeypatch):
    from mitigation import router_adapter
    with pytest.raises(NotImplementedError):
        router_adapter.RouterAdapter.get_hosts(object())
    import middleware.routers.fritzbox_api as fritzbox_api

    class _Hosts:
        def get_hosts_info(self):
            return [{"ip": "10.20.0.5", "mac": "AA:00:00:00:00:0A", "name": "printer", "status": True},
                    {"ip": "10.20.0.6", "mac": "aa:00:00:00:00:0b", "name": "old-phone", "status": False}]
    monkeypatch.setattr(fritzbox_api, "_get_fritz_hosts", lambda *a, **k: _Hosts())
    adapter = router_adapter.FritzBoxAdapter({"fritz_password": "x"})
    assert [(h["ip"], h["active"]) for h in adapter.get_hosts()] == [("10.20.0.5", True), ("10.20.0.6", False)]


def test_block_refuses_a_single_device_not_identified_exactly(tmp_path, monkeypatch):
    from middleware.routers import fritzbox_api
    path = tmp_path / "ids_state.json"
    sm = StateManager(state_path=str(path))
    _dev(sm, "no-mac", "10.20.0.96")
    sm.flush_to_disk()
    monkeypatch.setattr(fritzbox_api, "CONFIG", {"state_path": str(path)})
    with pytest.raises(HTTPException) as exc:
        fritzbox_api._ipc_block_logic("10.20.0.96")
    assert exc.value.status_code == 409 and "No MAC address" in exc.value.detail


# --- MAC-less events (live on .94 after the deploy, 2026-10-12) ---------------------------------------------------------
# After a restart a laptop's DNS queries reached the engine before Zeek had seen its traffic again (no MAC). The old
# wrong redirect was followed and the record's MAC was reset to "unknown": the phone's record took the laptop's
# address and name and lost the very MAC the split needs.

def _phone_with_laptop_redirect(sm, host="pocket-phone"):
    laptop_id = stable_device_id(LAPTOP_IP)
    _dev(sm, "phone", PHONE_IP, PHONE_MAC, host=host, history=[LAPTOP_IP])
    sm._merge_redirects[laptop_id] = "phone"                      # the old wrong merge
    return laptop_id


def test_an_event_without_a_mac_never_wipes_a_known_mac(sm, mgr):
    st = _dev(sm, "d", "10.20.0.10", LAPTOP_MAC)
    with sm.lock_device("d") as locked:
        mgr._refresh_identity_signals(locked, "unknown", "10.20.0.10", "unknown", None)
        assert locked.mac_address == LAPTOP_MAC
        mgr._refresh_identity_signals(locked, None, "10.20.0.10", "unknown", None)
        assert locked.mac_address == LAPTOP_MAC


def test_live_sequence_macless_dns_first_then_the_laptop_is_observed(sm, mgr):
    laptop_id = _phone_with_laptop_redirect(sm)
    # 1. the laptop's DNS query, no MAC yet (Zeek has not seen .59 since the restart)
    mgr.process_dns_identities([{"client_ip": LAPTOP_IP, "hostname": "laptop-host", "domain": "example.org"}], _Zeek({}))
    with sm.lock_device("phone") as p:          # the redirect is followed, but a MAC-less event changes no identity
        assert (p.mac_address, p.client_ip, p.hostname) == (PHONE_MAC, PHONE_IP, "pocket-phone")
    assert not sm.has_device(laptop_id) and sm.get_identity_splits() == {}
    # 2. Zeek has seen the laptop's traffic: its MAC is observed
    mgr.process_dns_identities([{"client_ip": LAPTOP_IP, "hostname": "laptop-host", "domain": "example.org"}],
                               _Zeek({LAPTOP_IP: LAPTOP_MAC}))
    assert sm.get_device_id_for_mac(LAPTOP_MAC) == laptop_id
    assert sorted(sm.get_all_device_ids()) == sorted(["phone", laptop_id])
    with sm.lock_device("phone") as p:
        assert (p.mac_address, p.client_ip) == (PHONE_MAC, PHONE_IP)
    assert identify_device.identify(sm, LAPTOP_IP)["verdict"] == "EXACT"
    assert identify_device.identify(sm, PHONE_IP)["verdict"] == "EXACT"


def test_live_sequence_on_an_already_damaged_record(sm, mgr):
    """The record as found on .94: MAC wiped, the laptop's address and name -- but the MAC index still binds the
    phone's MAC to it. The laptop's observed MAC must still split it off."""
    laptop_id = _phone_with_laptop_redirect(sm)
    with sm.lock_device("phone") as p:
        p.mac_address, p.client_ip, p.hostname = "unknown", LAPTOP_IP, "laptop-host"
    sm._ip_to_device_id[LAPTOP_IP] = "phone"
    mgr.process_dns_identities([{"client_ip": LAPTOP_IP, "hostname": "laptop-host", "domain": "example.org"}],
                               _Zeek({LAPTOP_IP: LAPTOP_MAC}))
    assert sm.get_device_id_for_mac(LAPTOP_MAC) == laptop_id and sm.get_device_id_for_mac(PHONE_MAC) == "phone"
    assert sm.get_identity_splits()[laptop_id]["mac"] == LAPTOP_MAC
    # the phone's own traffic repairs its record
    mgr.process_zeek_identities([{"id.orig_h": PHONE_IP}], _Zeek({PHONE_IP: PHONE_MAC}))
    with sm.lock_device("phone") as p:
        assert (p.mac_address, p.client_ip) == (PHONE_MAC, PHONE_IP) and LAPTOP_IP not in p.known_ips


def test_a_new_mac_on_an_address_anchored_record_is_a_new_device(sm, mgr):
    old_id = stable_device_id("10.20.0.70")
    _dev(sm, old_id, "10.20.0.70", "aa:00:00:00:00:71")             # the address's previous owner
    mgr.process_zeek_identities([{"id.orig_h": "10.20.0.70"}], _Zeek({"10.20.0.70": "aa:00:00:00:00:72"}))
    new_id = sm.get_device_id_for_mac("aa:00:00:00:00:72")
    assert new_id == stable_device_id("aa:00:00:00:00:72") and new_id != old_id
    with sm.lock_device(old_id) as old:
        assert old.mac_address == "aa:00:00:00:00:71" and "10.20.0.70" not in old.known_ips


def test_a_macless_event_follows_the_redirect_while_the_target_still_uses_the_address(sm, mgr):
    frag_id = stable_device_id("10.20.0.75")
    _dev(sm, "device", "10.20.0.75", LAPTOP_MAC)
    sm._merge_redirects[frag_id] = "device"                       # an old, correct fragment merge
    assert mgr.resolve_device_id("10.20.0.75", None, "unknown") == "device"
    assert sm.get_identity_splits() == {}


def test_reconcile_never_takes_a_damaged_record_for_an_address_only_fragment(sm):
    now = time.time()
    _dev(sm, "phone", LAPTOP_IP, PHONE_MAC, seen=now - 60)          # bound in the MAC index ...
    with sm.lock_device("phone") as p:
        p.mac_address = "unknown"                                     # ... but its field was wiped
    _dev(sm, "laptop", LAPTOP_IP, LAPTOP_MAC, seen=now)
    assert _groups(sm) == []
