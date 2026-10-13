"""
Containment T2 wiring (Documentation/internal/CONTAINMENT_MODEL.md section 5, 2026-10-13): the same-segment cores
(peer_table + l2_enforcer + nftables_fw) wired into mitigation/ips.py. Proves, with fake L2 sockets and a fake nft
runner (no network, no root):
  - a Tarpit fakes every observed PEER as well as the gateway; Block internet fakes only the gateway;
  - a contained device's own ARP request for an in-scope address is answered reactively;
  - a peer re-announcing itself is counter-faked to the devices whose scope covers it;
  - the segment receiver observes peers from ARP and learns IPv6 routers from RAs;
  - owner decision 1: a Tarpit box-drops the device's MACs (and undrops on release); Block internet never does;
  - operator_tarpit is TARPIT mode, the router-isolation dual-stack coverage is BLOCK_INTERNET mode.
Network-agnostic throughout (addresses discovered/observed, never assumed).
"""
import ipaddress
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import StateManager  # noqa: E402
import mitigation.ips as ips_module  # noqa: E402
from mitigation import l2_raw  # noqa: E402
from mitigation import containment as ct  # noqa: E402
from mitigation.ips import IPSMitigator  # noqa: E402
from mitigation.nftables_fw import NftContainment  # noqa: E402

BOGUS = "00:11:22:33:44:55"
GW_IP, GW_MAC = "10.20.0.1", "02:aa:bb:cc:dd:01"
DEV_MAC = "aa:bb:cc:dd:ee:01"
PEER_IP, PEER_MAC = "10.20.0.7", "aa:bb:cc:00:00:07"


class _StopLoop(BaseException):   # BaseException so the loops' `except Exception` never swallows the stop signal
    pass


@pytest.fixture
def mit(tmp_path):
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    config = {"ips_router_enabled": False, "ips_tarpit_enabled": True, "onboarding_mode_days": 0,
              "state_path": str(tmp_path / "ids_state.json")}
    m = IPSMitigator(config=config, state_manager=sm, start_workers=False)
    m.tarpit_armed = True
    return m


@pytest.fixture
def wire(monkeypatch):
    """Fake L2: frames captured as (eth_dst, sender_mac, sender_ip, target_ip) for ARP."""
    sent = []
    monkeypatch.setattr(l2_raw, "open_raw", lambda proto=None: object())
    monkeypatch.setattr(l2_raw, "interface_for", lambda ip: "eth0")
    monkeypatch.setattr(l2_raw, "interface_mac", lambda ifname: "02:00:00:00:00:fe")
    monkeypatch.setattr(l2_raw, "ipv4_for_mac", lambda mac, arp_table=None: None)
    monkeypatch.setattr(l2_raw, "neighbor_mac", lambda ip, timeout=2.0: GW_MAC if ip == GW_IP else None)
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: GW_IP)
    monkeypatch.setattr(l2_raw, "send_frame", lambda sock, ifname, frame: sent.append((
        frame[0:6].hex(":"), frame[22:28].hex(":"), str(ipaddress.IPv4Address(frame[28:32])),
        str(ipaddress.IPv4Address(frame[38:42])))))
    return sent


def _run_rounds(monkeypatch, mit, rounds):
    n = []

    def sleep(seconds):
        n.append(seconds)
        if len(n) >= rounds:
            raise _StopLoop
    monkeypatch.setattr(ips_module.time, "sleep", sleep)
    with pytest.raises(_StopLoop):
        mit._arp_tarpit_loop()


def _entry(dev_id, macs, mode, arp_ip):
    return {"dev_id": dev_id, "hostname": "h", "macs": list(macs), "mac": macs[0], "mode": mode,
            "arp_ips": {macs[0]: arp_ip}}


# --- refresh: peers + gateway (Tarpit) vs gateway only (Block internet) --------------------------------------------

def test_tarpit_refresh_fakes_the_observed_peer_and_the_gateway(mit, wire, monkeypatch):
    mit._peer_table.observe(PEER_IP, PEER_MAC)
    mit._tarpit_active_targets["dev:d1"] = _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")
    _run_rounds(monkeypatch, mit, 1)
    faked = {f[2] for f in wire if f[1] == BOGUS}
    assert faked == {GW_IP, PEER_IP}                       # both the gateway and the peer were poisoned
    assert all(f[0] == DEV_MAC and f[3] == "10.20.0.50" for f in wire)


def test_block_internet_refresh_fakes_only_the_gateway(mit, wire, monkeypatch):
    mit._peer_table.observe(PEER_IP, PEER_MAC)
    mit._tarpit_active_targets["dev:d1"] = _entry("d1", [DEV_MAC], ct.BLOCK_INTERNET_MODE, "10.20.0.50")
    _run_rounds(monkeypatch, mit, 1)
    assert {f[2] for f in wire} == {GW_IP}                 # the peer is left reachable (LAN stays open)


def test_a_peer_that_went_silent_drops_out_of_the_refresh(mit, wire, monkeypatch):
    mit._peer_table.observe(PEER_IP, PEER_MAC, now=time.time() - 10_000)   # older than the TTL
    mit._tarpit_active_targets["dev:d1"] = _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")
    _run_rounds(monkeypatch, mit, 1)
    assert {f[2] for f in wire} == {GW_IP}                 # only the gateway; the stale peer is gone


# --- reactive answer -----------------------------------------------------------------------------------------------

def test_reactive_answers_a_contained_devices_arp_request(mit, wire, monkeypatch):
    mit._tarpit_active_targets["dev:d1"] = _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")
    mit._reactive_answer("arp_request", DEV_MAC, "10.20.0.99", object(), "eth0")
    assert wire == [(DEV_MAC, BOGUS, "10.20.0.99", "10.20.0.50")]


def test_reactive_ignores_a_request_from_a_device_not_contained(mit, wire):
    mit._tarpit_active_targets["dev:d1"] = _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")
    mit._reactive_answer("arp_request", "de:ad:be:ef:00:09", "10.20.0.99", object(), "eth0")
    assert wire == []


# --- counter-fake --------------------------------------------------------------------------------------------------

def test_counter_fake_re_poisons_the_device_for_an_announced_peer(mit, wire):
    mit._peer_table.observe(PEER_IP, PEER_MAC)
    mit._tarpit_active_targets["dev:d1"] = _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")
    mit._counter_fake(PEER_IP, object(), "eth0")
    assert wire == [(DEV_MAC, BOGUS, PEER_IP, "10.20.0.50")]


def test_counter_fake_for_a_peer_does_not_touch_a_block_internet_device(mit, wire):
    mit._peer_table.observe(PEER_IP, PEER_MAC)
    mit._tarpit_active_targets["dev:d1"] = _entry("d1", [DEV_MAC], ct.BLOCK_INTERNET_MODE, "10.20.0.50")
    mit._counter_fake(PEER_IP, object(), "eth0")           # a peer, not a gateway -> left open for block_internet
    assert wire == []


# --- segment receiver: peer + router learning ----------------------------------------------------------------------

def test_segment_loop_observes_peers_and_learns_routers(mit, monkeypatch):
    arp = l2_raw.build_arp_reply(eth_src=PEER_MAC, eth_dst="ff:ff:ff:ff:ff:ff", sender_mac=PEER_MAC,
                                 sender_ip=PEER_IP, target_mac="00:00:00:00:00:00", target_ip=PEER_IP)
    ra_icmp = struct.pack("!BBHI", l2_raw.ICMPV6_RA, 0, 0, 0) + b"\x00" * 12
    ra = l2_raw.mac_bytes("33:33:00:00:00:01") + l2_raw.mac_bytes("02:aa:bb:cc:dd:06") \
        + struct.pack("!H", l2_raw.ETH_P_IPV6) \
        + struct.pack("!IHBB", 0x60000000, len(ra_icmp), l2_raw.IPPROTO_ICMPV6, 255) \
        + ipaddress.IPv6Address("fe80::1").packed + ipaddress.IPv6Address("ff02::1").packed + ra_icmp
    frames = iter([(arp, "eth0"), (ra, "eth0")])

    def recv(sock, bufsize=2048):
        try:
            return next(frames)
        except StopIteration:
            raise _StopLoop
    monkeypatch.setattr(l2_raw, "open_raw", lambda proto=None: type("S", (), {"settimeout": lambda self, t: None})())
    monkeypatch.setattr(l2_raw, "attach_filter", lambda sock, prog: True)
    monkeypatch.setattr(l2_raw, "recv_frame", recv)
    monkeypatch.setattr(l2_raw, "send_frame", lambda *a, **k: None)
    with pytest.raises(_StopLoop):
        mit._segment_loop()
    assert mit._peer_table.mac_for(PEER_IP) == PEER_MAC
    assert mit._ipv6_routers.get("fe80::1") == "02:aa:bb:cc:dd:06"


# --- box firewall reconcile (owner decision 1) ---------------------------------------------------------------------

class _FakeNft:
    """Records every set element add/delete. `added`/`deleted` are flat MAC lists (any set); `added_sets` keys them by
    set name. `inpath_ok=False` makes in-path element adds fail, to drive the fail-closed path."""
    def __init__(self, inpath_ok=True):
        self.added, self.deleted = [], []
        self.added_sets, self.deleted_sets = {}, {}
        self.inpath_ok = inpath_ok

    def __call__(self, args):
        if args[:1] == ["--version"]:
            return 0, "nftables v1.0"
        if args[:2] == ["list", "table"]:
            return 1, "No such file or directory"
        if args[:1] == ["-f"]:
            for line in args[-1].splitlines():
                verb = line.split()[:1]
                if verb == ["add"] and line.startswith("add element"):
                    set_name, mac = line.split()[4], line.split("{")[1].strip(" }")
                    if set_name in ("inpath_blocked", "inpath_internet") and not self.inpath_ok:
                        return 1, "permission denied"
                    self.added.append(mac)
                    self.added_sets.setdefault(set_name, []).append(mac)
                elif line.startswith("delete element"):
                    set_name, mac = line.split()[4], line.split("{")[1].strip(" }")
                    self.deleted.append(mac)
                    self.deleted_sets.setdefault(set_name, []).append(mac)
        return 0, ""


def _fw_mit(mit, inpath_ok=True, in_path=False):
    mit._state_only = False                       # a box with the firewall (the engine's own instance)
    mit._fw = NftContainment(run=_FakeNft(inpath_ok=inpath_ok), uplink="eth0")
    mit._fw_avail = None
    # force the detection result (real OS reads would say "same segment" on the test host)
    mit._path.method_for = lambda mac, ip, uplink: ("in_path" if in_path else "same_segment")
    return mit._fw._run


def test_tarpit_box_drops_macs_and_undrops_on_release(mit):
    runner = _fw_mit(mit)
    tarpit = {"dev:d1": _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")}
    mit._reconcile_firewall(tarpit)
    assert DEV_MAC in runner.added
    mit._reconcile_firewall({})               # device released
    assert DEV_MAC in runner.deleted


def test_block_internet_is_never_box_dropped(mit):
    runner = _fw_mit(mit)
    mit._reconcile_firewall({"dev:d1": _entry("d1", [DEV_MAC], ct.BLOCK_INTERNET_MODE, "10.20.0.50")})
    assert runner.added == []


def test_state_only_instance_never_touches_the_firewall(mit):
    # the API-process (W-01) instance must leave no side effects
    assert mit._state_only is True
    mit._fw = NftContainment(run=_FakeNft(), uplink="eth0")
    mit._reconcile_firewall({"dev:d1": _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")})
    assert mit._fw._run.added == []


# --- T3 in-path reconcile (method detection -> bridge-family drop) -------------------------------------------------

def test_in_path_tarpit_device_gets_an_inpath_drop_both_sets_name(mit):
    runner = _fw_mit(mit, in_path=True)
    mit._reconcile_firewall({"dev:d1": _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")})
    assert DEV_MAC in runner.added_sets.get("inpath_blocked", [])
    mit._reconcile_firewall({})                         # released
    assert DEV_MAC in runner.deleted_sets.get("inpath_blocked", [])


def test_in_path_block_internet_uses_the_internet_set(mit):
    runner = _fw_mit(mit, in_path=True)
    mit._reconcile_firewall({"dev:d1": _entry("d1", [DEV_MAC], ct.BLOCK_INTERNET_MODE, "10.20.0.50")})
    assert DEV_MAC in runner.added_sets.get("inpath_internet", [])
    assert runner.added_sets.get("box_blocked") is None   # block-internet is never box-dropped


def test_same_segment_device_gets_no_inpath_drop(mit):
    runner = _fw_mit(mit, in_path=False)
    mit._reconcile_firewall({"dev:d1": _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")})
    assert "inpath_blocked" not in runner.added_sets    # only box-drop applies on a same-segment box
    assert DEV_MAC in runner.added_sets.get("box_blocked", [])


def test_fail_closed_surfaces_a_containment_event_when_the_inpath_drop_fails(mit):
    _fw_mit(mit, inpath_ok=False, in_path=True)
    mit._reconcile_firewall({"dev:d1": _entry("d1", [DEV_MAC], ct.TARPIT_MODE, "10.20.0.50")})
    events = mit.pop_containment_events()
    assert any(e["type"] == "inpath_enforcement_failed" and e["mac"] == DEV_MAC for e in events)


# --- mode is set correctly at the two entry points -----------------------------------------------------------------

def test_operator_tarpit_is_tarpit_mode(mit):
    mit.state_manager.get_or_create("d1", "10.20.0.60", "h")
    with mit.state_manager.lock_device("d1") as st:
        st.mac_address = DEV_MAC
    mit.state_manager.bind_mac(DEV_MAC, "d1")
    ok, _ = mit.operator_tarpit("d1", "10.20.0.60", DEV_MAC, "h")
    assert ok and mit._tarpit_active_targets["dev:d1"]["mode"] == ct.TARPIT_MODE


def test_dual_stack_coverage_is_block_internet_mode(mit):
    mit.config["simulation_mode"] = True
    mit.state_manager.get_or_create("d2", "10.20.0.61", "h")
    with mit.state_manager.lock_device("d2") as st:
        st.mac_address = "aa:bb:cc:dd:ee:02"
    mit.state_manager.bind_mac("aa:bb:cc:dd:ee:02", "d2")
    armed = mit._arm_tarpit_for_dual_stack_coverage("10.20.0.61", "aa:bb:cc:dd:ee:02", "h", "d2", reason="router")
    assert armed and mit._tarpit_active_targets["dev:d2"]["mode"] == ct.BLOCK_INTERNET_MODE


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
