"""mitigation/l2_enforcer.py -- the socket-free decision core of same-segment containment (T2, 2026-10-13): which
forged frames to send on refresh, as a reactive answer, as a counter-fake, and to restore on release. Proves the
"devices coming and going" behaviour without a network."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mitigation import l2_enforcer as E  # noqa: E402
from mitigation import containment as ct  # noqa: E402

DEV_MAC = "aa:bb:cc:00:00:01"
P5, P6 = "aa:bb:cc:00:00:05", "aa:bb:cc:00:00:06"
GW_MAC = "02:aa:bb:cc:dd:01"
BOGUS = E.BOGUS_MAC


def tarpit(macs=(DEV_MAC,)):
    return {"dev_id": "d1", "macs": list(macs), "mode": ct.TARPIT_MODE}


def blocknet(macs=(DEV_MAC,)):
    return {"dev_id": "d2", "macs": list(macs), "mode": ct.BLOCK_INTERNET_MODE}


def specset(specs):
    return {(s.family, s.dst_mac, s.ip, s.sender_mac) for s in specs}


# --- refresh --------------------------------------------------------------------------------------------------------

def test_tarpit_refresh_fakes_every_peer_and_the_gateway():
    peers = {"10.0.0.5": P5, "10.0.0.6": P6}
    gw = {"10.0.0.1": GW_MAC, "fe80::1": "02:aa:bb:cc:dd:06"}
    specs = E.refresh_specs(tarpit(), peers, gw)
    assert specset(specs) == {
        (4, DEV_MAC, "10.0.0.5", BOGUS), (4, DEV_MAC, "10.0.0.6", BOGUS),
        (4, DEV_MAC, "10.0.0.1", BOGUS), (6, DEV_MAC, "fe80::1", BOGUS)}


def test_block_internet_refresh_fakes_only_the_gateways():
    peers = {"10.0.0.5": P5}
    gw = {"10.0.0.1": GW_MAC}
    assert specset(E.refresh_specs(blocknet(), peers, gw)) == {(4, DEV_MAC, "10.0.0.1", BOGUS)}


def test_refresh_with_no_peers_is_gateway_only_like_today():
    assert specset(E.refresh_specs(tarpit(), {}, {"10.0.0.1": GW_MAC})) == {(4, DEV_MAC, "10.0.0.1", BOGUS)}


def test_refresh_covers_every_mac_of_a_multi_nic_device():
    specs = E.refresh_specs(tarpit([DEV_MAC, "aa:bb:cc:00:00:02"]), {"10.0.0.5": P5}, {})
    assert specset(specs) == {(4, DEV_MAC, "10.0.0.5", BOGUS), (4, "aa:bb:cc:00:00:02", "10.0.0.5", BOGUS)}


def test_refresh_never_fakes_the_device_to_itself():
    # a peer whose MAC IS the device's own MAC (its own address seen as a peer) is excluded
    specs = E.refresh_specs(tarpit(), {"10.0.0.9": DEV_MAC}, {"10.0.0.1": GW_MAC})
    assert specset(specs) == {(4, DEV_MAC, "10.0.0.1", BOGUS)}


# --- reactive -------------------------------------------------------------------------------------------------------

def test_reactive_answers_the_device_arp_request_for_an_in_scope_address():
    s = E.reactive_spec("arp_request", DEV_MAC, "10.0.0.7", tarpit(), {}, {"10.0.0.1": GW_MAC})
    assert s == E.SendSpec(4, DEV_MAC, "10.0.0.7", BOGUS)      # tarpit: any address is in scope


def test_reactive_ignores_a_request_from_a_non_contained_mac():
    assert E.reactive_spec("arp_request", "de:ad:be:ef:00:09", "10.0.0.7", tarpit(), {}, {}) is None


def test_reactive_block_internet_only_answers_for_a_gateway():
    e, gw = blocknet(), {"10.0.0.1": GW_MAC}
    assert E.reactive_spec("arp_request", DEV_MAC, "10.0.0.7", e, {}, gw) is None   # a peer: left open
    assert E.reactive_spec("arp_request", DEV_MAC, "10.0.0.1", e, {}, gw) == E.SendSpec(4, DEV_MAC, "10.0.0.1", BOGUS)


def test_reactive_ns_is_ipv6():
    s = E.reactive_spec("ns", DEV_MAC, "fe80::9", tarpit(), {}, {})
    assert s == E.SendSpec(6, DEV_MAC, "fe80::9", BOGUS)


# --- counter-fake ---------------------------------------------------------------------------------------------------

def test_counter_fake_reposions_every_device_that_covers_the_announced_peer():
    peers = {"10.0.0.5": P5}
    targets = [tarpit([DEV_MAC]), blocknet(["aa:bb:cc:00:00:03"])]
    # a peer (10.0.0.5) announced: only the tarpit device covers a plain peer
    specs = E.counter_fake_specs("10.0.0.5", targets, peers, {"10.0.0.1": GW_MAC})
    assert specset(specs) == {(4, DEV_MAC, "10.0.0.5", BOGUS)}
    # the gateway announced: both devices cover it
    specs = E.counter_fake_specs("10.0.0.1", targets, peers, {"10.0.0.1": GW_MAC})
    assert specset(specs) == {(4, DEV_MAC, "10.0.0.1", BOGUS), (4, "aa:bb:cc:00:00:03", "10.0.0.1", BOGUS)}


def test_counter_fake_skips_when_the_announced_host_is_the_contained_device_itself():
    # the "peer" announcing is the device's own MAC -> never fake the device to itself
    assert E.counter_fake_specs("10.0.0.9", [tarpit()], {"10.0.0.9": DEV_MAC}, {}) == []


# --- restore --------------------------------------------------------------------------------------------------------

def test_restore_sends_real_macs_back():
    peers = {"10.0.0.5": P5}
    gw = {"10.0.0.1": GW_MAC}
    assert specset(E.restore_specs(tarpit(), peers, gw)) == {
        (4, DEV_MAC, "10.0.0.5", P5), (4, DEV_MAC, "10.0.0.1", GW_MAC)}


def test_restore_skips_an_address_whose_real_mac_is_unknown():
    assert E.restore_specs(blocknet(), {}, {"10.0.0.1": ""}) == []   # gateway real MAC unknown -> nothing to send


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
