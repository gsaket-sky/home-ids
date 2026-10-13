"""
Containment T0 (Documentation/internal/CONTAINMENT_MODEL.md, 2026-10-12):
- the ARP half of the tarpit fakes the DISCOVERED default gateway (kernel routing table), never config `fritz_ip`,
  whose default (192.168.1.1) is wrong on every other network;
- without a discovered gateway the ARP half is idle (logged once), not faking a guessed address;
- after a release -- by any path, including another process's change synced in -- the device gets the gateway's real
  MAC for a few rounds, so its access returns at once instead of after its cache expires (~1 min, live test on .19);
- a target re-keyed to "mac:<mac>" (its address changed hands) is still held, not "released".
"""
import ipaddress
import logging
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
from mitigation.ips import IPSMitigator  # noqa: E402

BOGUS = "00:11:22:33:44:55"
GW_MAC = "02:aa:bb:cc:dd:01"
MAC1, MAC2 = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"


class _StopLoop(Exception):
    pass


@pytest.fixture
def mitigator(tmp_path):
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    # fritz_ip is deliberately a different address: it must never be what the tarpit fakes.
    config = {"ips_router_enabled": False, "ips_tarpit_enabled": True, "onboarding_mode_days": 0,
              "state_path": str(tmp_path / "ids_state.json"), "fritz_ip": "192.168.1.1"}
    m = IPSMitigator(config=config, state_manager=sm, start_workers=False)
    m.tarpit_armed = True
    return m


@pytest.fixture
def wire(monkeypatch):
    """Fake L2: one interface, frames captured as (eth_dst, sender_mac, sender_ip, target_ip)."""
    sent = []
    monkeypatch.setattr(l2_raw, "open_raw", lambda proto=None: object())
    monkeypatch.setattr(l2_raw, "interface_for", lambda ip: "eth0")
    monkeypatch.setattr(l2_raw, "interface_mac", lambda ifname: "02:00:00:00:00:01")
    monkeypatch.setattr(l2_raw, "ipv4_for_mac", lambda mac, arp_table=None: None)
    monkeypatch.setattr(l2_raw, "neighbor_mac", lambda ip, timeout=2.0: GW_MAC if ip == "10.20.0.254" else None)
    monkeypatch.setattr(l2_raw, "send_frame", lambda sock, ifname, frame: sent.append((
        frame[0:6].hex(":"), frame[22:28].hex(":"), str(ipaddress.IPv4Address(frame[28:32])),
        str(ipaddress.IPv4Address(frame[38:42])))))
    return sent


def _run_rounds(monkeypatch, mitigator, rounds, between=None):
    """Runs the ARP loop for `rounds` rounds; `between(i)` runs after round i (0-based)."""
    real_sleep, n = time.sleep, []

    def sleep(seconds):
        if threading.current_thread() is not threading.main_thread():
            return real_sleep(seconds)
        if between:
            between(len(n))
        n.append(seconds)
        if len(n) == rounds:
            raise _StopLoop
    monkeypatch.setattr(ips_module.time, "sleep", sleep)
    with pytest.raises(_StopLoop):
        mitigator._arp_tarpit_loop()


def test_fakes_the_discovered_gateway_not_the_configured_router_address(mitigator, wire, monkeypatch):
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: "10.20.0.254")
    mitigator._tarpit_active_targets["dev:d1"] = {"mac": MAC1, "macs": [MAC1], "hostname": "h1", "dev_id": "d1", "arp_ips": {MAC1: "10.20.0.7"}}
    _run_rounds(monkeypatch, mitigator, 1)
    assert wire == [(MAC1, BOGUS, "10.20.0.254", "10.20.0.7")]


def test_no_discovered_gateway_means_the_arp_half_is_idle_and_says_so_once(mitigator, wire, monkeypatch, caplog):
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: None)
    mitigator._tarpit_active_targets["dev:d1"] = {"mac": MAC1, "macs": [MAC1], "hostname": "h1", "dev_id": "d1", "arp_ips": {MAC1: "10.20.0.7"}}
    mitigator._GATEWAY_REFRESH_SECONDS = 0.0
    with caplog.at_level(logging.WARNING, logger=ips_module.LOGGER.name):
        _run_rounds(monkeypatch, mitigator, 3)
    assert wire == []
    assert len([r for r in caplog.records if "no IPv4 default gateway discovered" in r.getMessage()]) == 1


@pytest.mark.parametrize("gw", ["fe80::1", "not-an-address", "169.254.0.1"])
def test_a_non_ipv4_gateway_is_not_used(mitigator, wire, monkeypatch, gw):
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: gw)
    mitigator._tarpit_active_targets["dev:d1"] = {"mac": MAC1, "macs": [MAC1], "hostname": "h1", "dev_id": "d1", "arp_ips": {MAC1: "10.20.0.7"}}
    _run_rounds(monkeypatch, mitigator, 1)
    assert wire == []


def test_a_changed_gateway_is_followed(mitigator, wire, monkeypatch):
    gws = iter(["10.20.0.254", "10.30.0.1"])
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: next(gws))
    mitigator._GATEWAY_REFRESH_SECONDS = 0.0
    mitigator._tarpit_active_targets["dev:d1"] = {"mac": MAC1, "macs": [MAC1], "hostname": "h1", "dev_id": "d1", "arp_ips": {MAC1: "10.20.0.7"}}
    _run_rounds(monkeypatch, mitigator, 2)
    assert [f[2] for f in wire] == ["10.20.0.254", "10.30.0.1"]


def test_release_sends_the_real_gateway_mac_for_three_rounds_then_stops(mitigator, wire, monkeypatch):
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: "10.20.0.254")
    mitigator._tarpit_active_targets.update({
        "dev:d1": {"mac": MAC1, "macs": [MAC1], "hostname": "h1", "dev_id": "d1", "arp_ips": {MAC1: "10.20.0.7"}},
        "dev:d2": {"mac": MAC2, "macs": [MAC2], "hostname": "h2", "dev_id": "d2", "arp_ips": {MAC2: "10.20.0.8"}},
    })

    def between(i):
        if i == 0:      # released after the first round, the way the console/web UI does it
            assert mitigator.release_device("d1")
    _run_rounds(monkeypatch, mitigator, 6, between)
    to_d1 = [f for f in wire if f[0] == MAC1]
    assert to_d1[0][1] == BOGUS                                   # round 1: still held
    assert [f[1] for f in to_d1[1:]] == [GW_MAC] * 3              # rounds 2-4: the real MAC, then nothing
    assert all(f[2] == "10.20.0.254" and f[3] == "10.20.0.7" for f in to_d1)
    assert [f[1] for f in wire if f[0] == MAC2] == [BOGUS] * 6    # the other device stays held


def test_a_release_synced_from_another_process_is_restored_too(mitigator, wire, monkeypatch):
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: "10.20.0.254")
    mitigator._tarpit_active_targets["dev:d1"] = {"mac": MAC1, "macs": [MAC1], "hostname": "h1", "dev_id": "d1", "arp_ips": {MAC1: "10.20.0.7"}}

    def between(i):
        if i == 0:      # the API process released it; the engine reloads the IPS state (no release_device here)
            with mitigator._lock:
                mitigator._tarpit_active_targets.pop("dev:d1")
    _run_rounds(monkeypatch, mitigator, 3, between)
    assert [f[1] for f in wire] == [BOGUS, GW_MAC, GW_MAC]


def test_an_address_handed_to_another_device_leaves_the_contained_device_held(mitigator, wire, monkeypatch):
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: "10.20.0.254")
    mitigator._tarpit_active_targets["dev:d1"] = {"mac": MAC1, "macs": [MAC1], "hostname": "h1", "dev_id": "d1",
                                                  "arp_ips": {MAC1: "10.20.0.7"}}

    def between(i):
        if i == 0:      # its address went to another device, which is contained too (keys are devices, T1)
            mitigator.operator_tarpit("d2", "10.20.0.7", MAC2, "h2")
    _run_rounds(monkeypatch, mitigator, 3, between)
    assert [f[1] for f in wire if f[0] == MAC1] == [BOGUS, BOGUS, BOGUS]     # never "released"


def test_contained_again_during_restore_is_held_again(mitigator, wire, monkeypatch):
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: "10.20.0.254")
    meta = {"mac": MAC1, "macs": [MAC1], "hostname": "h1", "dev_id": "d1", "arp_ips": {MAC1: "10.20.0.7"}}
    mitigator._tarpit_active_targets["dev:d1"] = dict(meta)

    def between(i):
        with mitigator._lock:
            if i == 0:
                mitigator._tarpit_active_targets.pop("dev:d1")
            elif i == 1:
                mitigator._tarpit_active_targets["dev:d1"] = dict(meta)
    _run_rounds(monkeypatch, mitigator, 4, between)
    assert [f[1] for f in wire] == [BOGUS, GW_MAC, BOGUS, BOGUS]


def test_release_without_a_known_gateway_mac_does_not_fake_anything(mitigator, wire, monkeypatch, caplog):
    monkeypatch.setattr(ips_module, "_discover_gateway_ipv4", lambda: "10.20.0.254")
    monkeypatch.setattr(l2_raw, "neighbor_mac", lambda ip, timeout=2.0: None)
    mitigator._tarpit_active_targets["dev:d1"] = {"mac": MAC1, "macs": [MAC1], "hostname": "h1", "dev_id": "d1", "arp_ips": {MAC1: "10.20.0.7"}}

    def between(i):
        if i == 0:
            with mitigator._lock:
                mitigator._tarpit_active_targets.pop("dev:d1")
    with caplog.at_level(logging.INFO, logger=ips_module.LOGGER.name):
        _run_rounds(monkeypatch, mitigator, 4, between)
    assert [f[1] for f in wire] == [BOGUS]
    assert any("real MAC is unknown" in r.getMessage() for r in caplog.records)


def test_the_gateway_hook_reads_discovery_not_config(monkeypatch):
    from argus.identity import discovery
    monkeypatch.setattr(discovery, "default_gateway_ip", lambda: "10.40.0.1")
    assert ips_module._discover_gateway_ipv4() == "10.40.0.1"


def test_the_tarpit_never_reads_fritz_ip():
    src = (SRC_DIR / "mitigation" / "ips.py").read_text(encoding="utf-8")
    loop = src.split("def _arp_tarpit_loop", 1)[1].split("\n    def ", 1)[0]
    assert "fritz_ip" not in loop and "192.168." not in loop


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
