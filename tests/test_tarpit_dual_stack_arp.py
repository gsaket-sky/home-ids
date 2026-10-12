"""
Dual-stack ARP tarpit (2026-10-07, found on .94 while preparing a live tarpit test): a device whose client_ip is an
IPv6 address (fe80::/ULA) was registered under that address, and the ARP half of the tarpit forged its reply with it
-- build_arp_reply() only takes IPv4, so the ARP half never acted on that device, and the exception aborted the ARP
round for every target after it. Only the NDP half (which matches by MAC) covered it.

The fix keeps the target registry keyed exactly as before (every lookup by client_ip -- release, the safe-device
auto-release, merge carry-over, status -- is unchanged) and resolves the IPv4 when the ARP frame is built: the kernel's
neighbour table for the MAC, else the "arp_ip" hint stored at registration from the device's known_ips.
"""
import ipaddress
import logging
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state import BoundedSet  # noqa: E402
from core.state_guard import StateManager  # noqa: E402
import mitigation.ips as ips_module  # noqa: E402
from mitigation import l2_raw  # noqa: E402
from mitigation.ips import IPSMitigator  # noqa: E402
from middleware.routers import mitigation_api  # noqa: E402

V6 = "fe80::1c2d:3e4f:5a6b:7c8d"
MAC = "aa:bb:cc:dd:ee:01"

ARP_TABLE = """IP address       HW type     Flags       HW address            Mask     Device
10.0.0.21        0x1         0x2         AA:BB:CC:DD:EE:01     *        eth0
10.0.0.22        0x1         0x0         aa:bb:cc:dd:ee:02     *        eth0
"""


@pytest.fixture
def no_neighbours(monkeypatch):
    """The neighbour table has no entry (CI's real /proc/net/arp must not decide the result)."""
    monkeypatch.setattr(l2_raw, "ipv4_for_mac", lambda mac, arp_table="/proc/net/arp": None)


@pytest.fixture
def mitigator(tmp_path):
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    config = {"ips_router_enabled": False, "ips_tarpit_enabled": True, "onboarding_mode_days": 0,
              "state_path": str(tmp_path / "ids_state.json"), "fritz_ip": "10.0.0.1"}
    m = IPSMitigator(config=config, state_manager=sm, start_workers=False)
    m.tarpit_armed = True
    return m


# --- l2_raw.ipv4_for_mac -----------------------------------------------------------------------------------------

def test_ipv4_for_mac_reads_complete_entries_case_insensitively(tmp_path):
    table = tmp_path / "arp"
    table.write_text(ARP_TABLE)
    assert l2_raw.ipv4_for_mac("aa:bb:cc:dd:ee:01", arp_table=str(table)) == "10.0.0.21"
    assert l2_raw.ipv4_for_mac("AA:BB:CC:DD:EE:01", arp_table=str(table)) == "10.0.0.21"


def test_ipv4_for_mac_skips_incomplete_unknown_and_missing(tmp_path):
    table = tmp_path / "arp"
    table.write_text(ARP_TABLE)
    assert l2_raw.ipv4_for_mac("aa:bb:cc:dd:ee:02", arp_table=str(table)) is None   # flags 0x0: incomplete
    assert l2_raw.ipv4_for_mac("aa:bb:cc:dd:ee:99", arp_table=str(table)) is None
    assert l2_raw.ipv4_for_mac("", arp_table=str(table)) is None
    assert l2_raw.ipv4_for_mac(MAC, arp_table=str(tmp_path / "missing")) is None


# --- IPSMitigator._arp_target_ip / _arp_ip_hint ---------------------------------------------------------------------

def test_ipv4_target_passes_through_without_a_lookup(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("an IPv4 target needs no neighbour lookup")
    monkeypatch.setattr(l2_raw, "ipv4_for_mac", boom)
    assert IPSMitigator._arp_target_ip("10.0.0.5", MAC) == "10.0.0.5"
    assert IPSMitigator._arp_ip_hint("10.0.0.5", MAC, ["10.0.0.9"]) is None


def test_ipv6_target_uses_the_neighbour_table_first(monkeypatch):
    monkeypatch.setattr(l2_raw, "ipv4_for_mac", lambda mac: "10.0.0.21" if mac == MAC else None)
    assert IPSMitigator._arp_target_ip(V6, MAC, ["10.0.0.9"]) == "10.0.0.21"


def test_ipv6_target_falls_back_to_the_newest_usable_known_ip(no_neighbours):
    assert IPSMitigator._arp_target_ip(V6, MAC, ["10.0.0.3", "10.0.0.4"]) == "10.0.0.4"           # newest last
    assert IPSMitigator._arp_target_ip(V6, MAC, ["10.0.0.4", "fe80::9", "169.254.3.3"]) == "10.0.0.4"
    known = BoundedSet(max_size=8, initial=[V6, "10.0.0.7"])                                       # a device's live set
    assert IPSMitigator._arp_target_ip(V6, MAC, known) == "10.0.0.7"


def test_ipv6_target_without_any_ipv4_is_returned_unchanged(no_neighbours):
    assert IPSMitigator._arp_target_ip(V6, MAC, ["fe80::9"]) == V6
    assert IPSMitigator._arp_ip_hint(V6, MAC, ["fe80::9"]) is None


# --- registration keeps the key, adds the hint ----------------------------------------------------------------------

def test_operator_tarpit_keeps_the_ipv6_key_and_stores_the_ipv4_hint(mitigator, no_neighbours):
    ok, _ = mitigator.operator_tarpit("dev1", V6, MAC, "host1", ipv4_candidates=[V6, "10.0.0.21"])
    assert ok
    assert mitigator._tarpit_active_targets[V6]["arp_ip"] == "10.0.0.21"
    assert "10.0.0.21" not in mitigator._tarpit_active_targets


def test_operator_tarpit_ipv4_target_gets_no_hint(mitigator, no_neighbours):
    mitigator.operator_tarpit("dev1", "10.0.0.5", MAC, "host1", ipv4_candidates=["10.0.0.5"])
    assert "arp_ip" not in mitigator._tarpit_active_targets["10.0.0.5"]


def test_mitigate_autonomous_tarpit_stores_the_hint_from_known_ips(mitigator, no_neighbours):
    mitigator.config["simulation_mode"] = True
    st = SimpleNamespace(client_ip=V6, hostname="host1", device_id="dev1", mac_address=MAC,
                         known_ips=BoundedSet(max_size=8, initial=[V6, "10.0.0.21"]))
    mitigator.mitigate(st, target_domain="unknown", risk_score=9.5, lateral_threat=False, is_safe=False,
                       decision_state="HIGH")
    assert mitigator._tarpit_active_targets[V6]["arp_ip"] == "10.0.0.21"


# --- the lookups by client_ip still find the target (why the key was NOT changed to the IPv4) ------------------------

def test_lookups_by_the_ipv6_client_ip_still_find_the_target(mitigator, no_neighbours):
    mitigator.operator_tarpit("dev1", V6, MAC, "host1", ipv4_candidates=["10.0.0.21"])
    assert "TARPITTED" in mitigator.get_containment_status(client_ip=V6)            # no dev_id fallback needed
    assert mitigator.release_device(V6) is True
    assert V6 not in mitigator._tarpit_active_targets


def test_safe_device_auto_release_still_finds_the_ipv6_target(mitigator, no_neighbours):
    mitigator.operator_tarpit("dev1", V6, MAC, "host1", ipv4_candidates=["10.0.0.21"])
    st = SimpleNamespace(client_ip=V6, hostname="host1", device_id="dev1", mac_address=MAC)
    assert V6 in mitigator._tarpit_active_targets
    mitigator.mitigate(st, target_domain="unknown", risk_score=0.0, lateral_threat=False, is_safe=True)
    assert mitigator._tarpit_active_targets == {}                    # released, not left behind under another key


def test_merge_carry_over_still_sees_the_ipv6_tarpit(mitigator, no_neighbours):
    mitigator.operator_tarpit("dev_orphan", V6, MAC, "host1", ipv4_candidates=["10.0.0.21"])
    added = mitigator.carry_containment_after_merge(
        orphan_mac=MAC, orphan_ip=V6, canonical_id="dev1", canonical_mac="aa:bb:cc:dd:ee:02",
        canonical_ip="10.0.0.22", hostname="host1")
    assert added == ["tarpit"]


# --- the ARP loop resolves per target and one bad target no longer aborts the round ---------------------------------

class _StopLoop(Exception):
    pass


def test_arp_loop_sends_ipv4_frames_for_ipv6_targets_and_survives_a_bad_target(mitigator, monkeypatch, caplog):
    neighbours = {MAC: "10.0.0.21"}
    monkeypatch.setattr(l2_raw, "ipv4_for_mac", lambda mac: neighbours.get(mac))
    monkeypatch.setattr(l2_raw, "open_raw", lambda proto=None: object())
    looked_up, sent = [], []
    monkeypatch.setattr(l2_raw, "interface_for", lambda ip: looked_up.append(ip) or "eth0")
    monkeypatch.setattr(l2_raw, "interface_mac", lambda ifname: "02:00:00:00:00:01")
    monkeypatch.setattr(l2_raw, "send_frame", lambda sock, ifname, frame: sent.append(frame))
    real_sleep, rounds = time.sleep, []

    def sleep(seconds):                     # two rounds, then stop (other threads keep the real sleep)
        if threading.current_thread() is not threading.main_thread():
            return real_sleep(seconds)
        rounds.append(seconds)
        if len(rounds) == 2:
            raise _StopLoop
    monkeypatch.setattr(ips_module.time, "sleep", sleep)

    mitigator._tarpit_active_targets.update({
        "fe80::bad": {"hostname": "broken"},                                                   # no "mac": raises
        V6: {"mac": MAC, "hostname": "h1", "dev_id": "d1"},                                    # neighbour table
        "fe80::2": {"mac": "aa:bb:cc:dd:ee:02", "hostname": "h2", "dev_id": "d2", "arp_ip": "10.0.0.22"},  # hint
        "10.0.0.23": {"mac": "aa:bb:cc:dd:ee:03", "hostname": "h3", "dev_id": "d3"},          # plain IPv4
        "fe80::4": {"mac": "aa:bb:cc:dd:ee:04", "hostname": "h4", "dev_id": "d4"},            # no IPv4 at all
    })
    with caplog.at_level(logging.INFO, logger=ips_module.LOGGER.name), pytest.raises(_StopLoop):
        mitigator._arp_tarpit_loop()

    assert len(sent) == 6                                                    # 3 resolvable targets x 2 rounds
    got = {(frame[0:6].hex(":"), str(ipaddress.IPv4Address(frame[-4:]))) for frame in sent}
    assert got == {(MAC, "10.0.0.21"), ("aa:bb:cc:dd:ee:02", "10.0.0.22"), ("aa:bb:cc:dd:ee:03", "10.0.0.23")}
    assert all(":" not in ip for ip in looked_up)                            # interfaces looked up by IPv4 only
    for frame in sent:                                                       # still "the gateway is at a bogus MAC"
        assert str(ipaddress.IPv4Address(frame[28:32])) == "10.0.0.1"
    no_ipv4 = [r for r in caplog.records if "no IPv4 address known for fe80::4" in r.getMessage()]
    assert len(no_ipv4) == 1                                                 # logged once, not every 2 s


# --- the console endpoint passes the device's known_ips --------------------------------------------------------------

def test_console_tarpit_for_an_ipv6_device_stores_the_ipv4_hint(tmp_path, monkeypatch, no_neighbours):
    path = tmp_path / "ids_state.json"
    sm = StateManager(state_path=str(path))
    sm.get_or_create("dev_v6", V6, "workstation-2")
    with sm.lock_device("dev_v6") as st:
        st.mac_address = MAC
        st.known_ips.add("192.168.1.60")
    sm.flush_to_disk()
    monkeypatch.setattr(mitigation_api, "CONFIG", {"state_path": str(path), "ips_tarpit_enabled": True})
    engine = StateManager(state_path=str(path))
    engine.load_from_disk()
    engine_side = IPSMitigator(config={"state_path": str(path)}, state_manager=engine, start_workers=False)
    engine_side.tarpit_armed = True
    engine_side._publish_engine_tarpit_state()
    engine.flush_to_disk()

    result = mitigation_api.tarpit_device("dev_v6", mitigation_api.ReasonPayload(), token="test")
    assert result["status"] == "success"
    check = StateManager(state_path=str(path))
    check.load_from_disk()
    target = check.get_ips_state()["tarpit_targets"][V6]
    assert target["dev_id"] == "dev_v6" and target["arp_ip"] == "192.168.1.60"
