"""
Containment T1 (Documentation/internal/CONTAINMENT_MODEL.md, 2026-10-12): containment is a state of the DEVICE.

- tarpit entries are keyed "dev:<id>" and act on every MAC the device is known by now; older address-keyed entries are
  re-keyed without loss (mitigation/containment.py);
- every reader decides "contained" by device id or MAC, never by address (the next holder of an address is another
  device); release, the release cooldown and the Pi-hole blocks released with a device go by device too;
- mitigate() no longer fabricates a MAC from a device id;
- the status (holding / not reaching / unconfirmed / offline) comes from the device's frames the box actually sees, and
  "not reaching" is queued once for the engine to alert on.
"""
import struct
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import StateManager  # noqa: E402
from mitigation import containment as ct  # noqa: E402
from mitigation import l2_raw  # noqa: E402
from mitigation.ips import IPSMitigator  # noqa: E402
from mitigation.containment_gate import MONITOR_ONLY, ContainmentAuthorization  # noqa: E402

M1, M2, M3 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"
BOGUS, GW = "00:11:22:33:44:55", "02:aa:bb:cc:dd:01"


# ------------------------------------------------------------------------------------------------ containment.py

def test_normalize_rekeys_by_device_merges_and_is_idempotent():
    raw = {"10.0.0.5": {"mac": "AA:BB:CC:00:00:01", "dev_id": "d1", "hostname": "h", "since": 20.0},
           "fe80::1": {"mac": M2, "dev_id": "d1", "arp_ip": "10.0.0.6", "since": 10.0},
           "mac:" + M3: {"mac": M3, "dev_id": "d2"},
           "10.0.0.9": {"mac": "unknown", "hostname": "x"}}                    # no device id: kept as is
    out = ct.normalize_tarpit_targets(raw)
    assert set(out) == {"dev:d1", "dev:d2", "10.0.0.9"}
    d1 = out["dev:d1"]
    assert d1["macs"] == [M1, M2] and d1["registered_ip"] == "10.0.0.5" and d1["since"] == 10.0
    assert d1["arp_ips"] == {M1: "10.0.0.5", M2: "10.0.0.6"} and "arp_ip" not in d1
    assert ct.normalize_tarpit_targets(out) == out
    assert raw["10.0.0.5"]["mac"] == "AA:BB:CC:00:00:01"                        # input not mutated


def test_containment_of_by_id_or_mac_never_by_address():
    state = {"tarpit_targets": {"dev:d1": {"dev_id": "d1", "macs": [M1], "registered_ip": "10.0.0.5",
                                           "status": "holding"}},
             "router_isolated_devices": {M2: {"dev_id": "d2", "ip": "10.0.0.6"}},
             "blocked_domains": {"bad.example": {"device_id": "d1", "device_ip": "10.0.0.7"},
                                 "other.example": {"device_id": "d9", "device_ip": "10.0.0.7"}}}
    c = ct.containment_of(state, "d1")
    assert c["tarpitted"] and not c["router_isolated"] and c["status_text"] == "Holding"
    assert c["blocked_domain_count"] == 1                                       # its own block, not by address
    assert ct.containment_of(state, "dx", [M1.upper()])["tarpitted"]            # by MAC
    assert ct.containment_of(state, "dx", [M2])["router_isolated"]
    assert not ct.containment_of(state, "new-holder-of-10.0.0.5", ["aa:bb:cc:00:00:09"])["contained"]


def test_released_recently_by_id_or_mac_only():
    rel = {"d1": 1000.0, M2: 1000.0, "10.0.0.5": 1000.0, "android-1": 1000.0}
    assert ct.released_recently(rel, "d1", (), 3600, now=2000.0)
    assert ct.released_recently(rel, "dx", [M2.upper()], 3600, now=2000.0)
    assert not ct.released_recently(rel, "d9", (), 3600, now=2000.0)          # address / name keys name no device
    assert not ct.released_recently(rel, "d1", (), 600, now=2000.0)                         # cooldown over
    assert not ct.released_recently({"operator_released_devices": rel}, "dy", ["aa:bb:cc:00:00:09"], 3600, now=2000.0)


# ------------------------------------------------------------------------------------------------ kernel filter

def _run_bpf(prog, frame):
    """Tiny classic-BPF interpreter for the opcodes src_mac_filter_program uses."""
    pc, acc = 0, 0
    while True:
        code, jt, jf, k = prog[pc]
        if code == 0x20:
            acc = struct.unpack("!I", frame[k:k + 4])[0]
        elif code == 0x28:
            acc = struct.unpack("!H", frame[k:k + 2])[0]
        elif code == 0x15:
            pc += jt if acc == k else jf
        elif code == 0x06:
            return k
        pc += 1


def _frame(src, dst=BOGUS):
    return l2_raw.mac_bytes(dst) + l2_raw.mac_bytes(src) + b"\x08\x00" + b"\x00" * 46


@pytest.mark.parametrize("n", [0, 1, 3, 60])
def test_src_mac_filter_accepts_exactly_the_listed_sources(n):
    macs = [f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}" for i in range(1, n + 1)]
    prog = l2_raw.src_mac_filter_program(macs)
    for m in macs:
        assert _run_bpf(prog, _frame(m)) > 0
    assert _run_bpf(prog, _frame("aa:bb:cc:00:ff:ff")) == 0
    assert _run_bpf(prog, _frame("02:00:00:00:00:01", dst=macs[0] if macs else BOGUS)) == 0   # dst never matches
    assert all(0 <= jt <= 255 for _c, jt, _jf, _k in prog)


# ------------------------------------------------------------------------------------------------ IPSMitigator

@pytest.fixture
def sm(tmp_path):
    s = StateManager(state_path=str(tmp_path / "ids_state.json"))
    for dev, ip, mac in (("d1", "10.0.0.5", M1), ("d2", "10.0.0.6", M2)):
        s.get_or_create(dev, ip, f"host-{dev}")
        with s.lock_device(dev) as st:
            st.mac_address = mac
        s.bind_mac(mac, dev)
    return s


@pytest.fixture
def mit(sm, tmp_path):
    m = IPSMitigator(config={"ips_router_enabled": False, "ips_tarpit_enabled": True, "onboarding_mode_days": 0,
                             "state_path": str(tmp_path / "ids_state.json"), "simulation_mode": True},
                     state_manager=sm, start_workers=False)
    m.tarpit_armed = True
    return m


def test_a_device_with_two_macs_is_one_entry_acting_on_both(mit, sm):
    sm.bind_mac(M3, "d1")                                                      # e.g. its second network adapter
    ok, _ = mit.operator_tarpit("d1", "10.0.0.5", M1, "host-d1")
    assert ok and mit._tarpit_active_targets["dev:d1"]["macs"] == [M1, M3]


def test_refresh_follows_the_device_state(mit, sm):
    mit.operator_tarpit("d1", "10.0.0.5", M1, "host-d1")
    sm.bind_mac(M3, "d1")
    with sm.lock_device("d1") as st:
        st.client_ip = "10.0.0.50"                                             # new DHCP lease
    mit._refresh_targets_from_state()
    e = mit._tarpit_active_targets["dev:d1"]
    assert e["macs"] == [M1, M3] and e["arp_ips"][M1] == "10.0.0.50"


def test_release_by_address_names_the_current_holder_only(mit, sm):
    mit.operator_tarpit("d1", "10.0.0.5", M1, "host-d1")
    with sm.lock_device("d1") as st:                                           # d1 moved on; d2 holds .5 now
        st.client_ip = "10.0.0.51"
    sm._ip_to_device_id["10.0.0.5"] = "d2"                                     # (the index the engine keeps)
    assert sm.get_device_id_for_ip("10.0.0.5") == "d2"
    assert mit.release_device("10.0.0.5") is False                             # d2 holds it and is not contained
    assert "dev:d1" in mit._tarpit_active_targets                              # the address no longer names d1
    assert mit.release_device(M1.upper()) is True and mit._tarpit_active_targets == {}


def test_release_unblocks_this_devices_domains_only_and_cools_down_by_device(mit, sm, monkeypatch):
    unblocked = []
    monkeypatch.setattr(mit, "unblock_domain", lambda dom, reason="manual": unblocked.append(dom) or True)
    sm.update_ips_state_atomic({"blocked_domains": {
        "bad.example": {"device_id": "d1", "device_ip": "10.0.0.5", "hostname": "shared-name"},
        "other.example": {"device_id": "d2", "device_ip": "10.0.0.5", "hostname": "shared-name"}}})
    mit.operator_tarpit("d1", "10.0.0.5", M1, "shared-name")
    assert mit.release_device("d1") is True
    assert unblocked == ["bad.example"]                                        # not d2's, though same address/name
    rel = mit._operator_released_devices
    assert "d1" in rel and M1 in rel and "10.0.0.5" not in rel and "shared-name" not in rel


def test_cooldown_does_not_protect_the_next_holder_of_an_address(mit, sm):
    mit.operator_tarpit("d1", "10.0.0.5", M1, "host-d1")
    mit.release_device("d1")
    st_d2 = SimpleNamespace(client_ip="10.0.0.5", hostname="host-d1", device_id="d2", mac_address=M2,
                            device_type="unknown", known_ips=["10.0.0.5"])
    mit.mitigate(st_d2, target_domain="unknown", risk_score=9.5, authorization=ContainmentAuthorization("corroborated"), is_safe=False)
    assert "dev:d2" in mit._tarpit_active_targets                              # d2 is not in d1's cooldown
    st_d1 = SimpleNamespace(client_ip="10.0.0.51", hostname="host-d1", device_id="d1", mac_address=M1,
                            device_type="unknown", known_ips=[])
    mit.mitigate(st_d1, target_domain="unknown", risk_score=9.5, authorization=ContainmentAuthorization("corroborated"), is_safe=False)
    assert "dev:d1" not in mit._tarpit_active_targets                          # d1 is, by id and MAC


def test_mitigate_never_fabricates_a_mac_from_the_device_id(mit):
    st = SimpleNamespace(client_ip="10.0.0.77", hostname="h", device_id="0a1b2c3d4e5f", mac_address="unknown",
                         device_type="unknown", known_ips=[])
    mit.mitigate(st, target_domain="unknown", risk_score=9.5, authorization=ContainmentAuthorization("corroborated"), is_safe=False)
    assert mit._tarpit_active_targets == {}                                    # was: "0a:1b:2c:3d:4e:5f"


# ------------------------------------------------------------------------------------------------ status from frames

def _obs(mit, mac, **kw):
    mit._observed[mac] = dict(kw)


def test_status_from_observed_frames(mit):
    now = 10_000.0
    meta = {"dev_id": "d1", "macs": [M1], "since": now - 5}
    assert mit._status_for(meta, now) == ct.REQUESTED
    meta["since"] = now - 300
    assert mit._status_for(meta, now) == ct.OFFLINE                           # nothing seen: no claim
    _obs(mit, M1, frame=now - 3)
    assert mit._status_for(meta, now) == ct.UNCONFIRMED
    _obs(mit, M1, frame=now - 3, to_tarpit=now - 3)
    assert mit._status_for(meta, now) == ct.HOLDING
    _obs(mit, M1, frame=now - 1, to_tarpit=now - 30, to_gateway=now - 1)
    assert mit._status_for(meta, now) == ct.NOT_REACHING
    _obs(mit, M1, frame=now - 1, to_tarpit=now - 1, to_gateway=now - 30)     # obeys again after a stale route
    assert mit._status_for(meta, now) == ct.HOLDING
    _obs(mit, M1, frame=now - 1, to_gateway=meta["since"] + 2)                 # before the grace period ended
    assert mit._status_for(meta, now) == ct.UNCONFIRMED


def test_observer_classifies_frames_of_contained_macs_only(mit):
    mit._gateway_cache = (time.monotonic(), "10.0.0.1", GW)
    wanted = {M1}
    mit._observe_frame(_frame(M1, BOGUS), wanted, BOGUS)
    mit._observe_frame(_frame(M1, GW), wanted, BOGUS)
    mit._observe_frame(_frame(M2, BOGUS), wanted, BOGUS)                       # not contained: ignored
    assert set(mit._observed) == {M1} and {"frame", "to_tarpit", "to_gateway"} <= set(mit._observed[M1])


def test_not_reaching_is_queued_once(mit):
    mit.operator_tarpit("d1", "10.0.0.5", M1, "host-d1")
    e = mit._tarpit_active_targets["dev:d1"]
    e["since"] = time.time() - 300
    _obs(mit, M1, frame=time.time(), to_gateway=time.time())
    mit._update_statuses(time.time())
    mit._update_statuses(time.time())
    events = mit.pop_containment_events()
    assert [ev["type"] for ev in events] == ["tarpit_not_reaching"] and events[0]["dev_id"] == "d1"
    assert e["status"] == ct.NOT_REACHING and mit.pop_containment_events() == []


# ------------------------------------------------------------------------------------------------ Telegram buttons

def test_approve_button_by_device_id_still_requires_an_exact_identity(tmp_path, monkeypatch):
    # The Telegram buttons name the device by id now (the alert-time address may belong to another device later);
    # the block handler must run the same exact-identity check on that path as on the address path.
    from fastapi import HTTPException
    from middleware.routers import fritzbox_api
    path = tmp_path / "ids_state.json"
    s = StateManager(state_path=str(path))
    s.get_or_create("nomac", "10.0.0.40", "h")                                  # no MAC: not identified exactly
    s.flush_to_disk()
    monkeypatch.setattr(fritzbox_api, "CONFIG", {"state_path": str(path)})
    with pytest.raises(HTTPException) as exc:
        fritzbox_api._ipc_block_logic("nomac")
    assert exc.value.status_code == 409


# ------------------------------------------------------------------------------------------------ cleanup script

def test_clear_stale_isolation_matches_device_mac_or_registered_ip_not_a_name(tmp_path, monkeypatch, capsys):
    import clear_stale_isolation as tool
    path = tmp_path / "ids_state.json"
    s = StateManager(state_path=str(path))
    s.update_ips_state_atomic({"tarpit_targets": {
        "dev:d1": {"dev_id": "d1", "macs": [M1], "hostname": "shared", "registered_ip": "10.0.0.5"},
        "dev:d2": {"dev_id": "d2", "macs": [M2], "hostname": "shared"}}})
    s.flush_to_disk()
    monkeypatch.setattr(tool, "CONFIG", {"state_path": str(path)})

    def run(arg):
        monkeypatch.setattr(sys, "argv", ["clear_stale_isolation.py", arg])
        tool.main()
        c = StateManager(state_path=str(path))
        c.load_from_disk()
        return set(c.get_ips_state()["tarpit_targets"])
    assert run("shared") == {"dev:d1", "dev:d2"}                                # a name clears nothing
    assert run(M2.upper()) == {"dev:d1"}                                        # by MAC
    assert run("10.0.0.5") == set()                                             # by the registered address

# ------------------------------------------------------------------------------------------------ fake_scope (T2)

def test_fake_scope_tarpit_is_peers_plus_gateways_minus_self():
    peers = {"10.0.0.5": "aa:bb:cc:00:00:05", "10.0.0.6": "aa:bb:cc:00:00:06", "10.0.0.9": "de:ad:be:ef:00:09"}
    gw = {"10.0.0.1": "gw00", "fe80::1": ""}
    scope = ct.fake_scope(ct.TARPIT_MODE, peers, gw, device_macs=["DE:AD:BE:EF:00:09"])
    assert set(scope) == {"10.0.0.5", "10.0.0.6", "10.0.0.1", "fe80::1"}   # own MAC's address excluded
    assert scope["10.0.0.1"] == "gw00"


def test_fake_scope_block_internet_is_gateways_only():
    peers = {"10.0.0.5": "aa:bb:cc:00:00:05"}
    gw = {"10.0.0.1": "gw00", "fe80::1": "r6"}
    assert ct.fake_scope(ct.BLOCK_INTERNET_MODE, peers, gw) == {"10.0.0.1": "gw00", "fe80::1": "r6"}


def test_fake_scope_a_gateway_also_a_peer_keeps_the_gateway_real_mac():
    peers = {"10.0.0.1": "aa:bb:cc:00:00:01"}
    gw = {"10.0.0.1": "realgw"}
    assert ct.fake_scope(ct.TARPIT_MODE, peers, gw) == {"10.0.0.1": "realgw"}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
