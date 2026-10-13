"""mitigation/path_detect.py (T3, 2026-10-13): per-device containment method detection -- is this box in the forwarding
path for the device (router between NICs / bridge / AP -> nftables forward drop) or only on its segment (-> ARP/NDP
deception)? The decision is pure; the OS readers are driven by a fake `bridge`/`ip` runner and a fake /proc reader, so
the routed, bridged and plain-segment topologies are all proven without root or netns. Fails safe to 'same segment'."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mitigation import path_detect as pd  # noqa: E402

DEV_MAC, UP = "aa:bb:cc:00:00:01", "eth0"


# --- the pure decision ---------------------------------------------------------------------------------------------

def test_no_forwarding_is_always_same_segment():
    assert pd.decide(False, "eth1", "eth0", False) == pd.SAME_SEGMENT


def test_device_not_located_is_same_segment():
    assert pd.decide(True, None, "eth0", False) == pd.SAME_SEGMENT


def test_routed_between_two_nics_is_in_path():
    assert pd.decide(True, "eth1", "eth0", False) == pd.IN_PATH


def test_same_single_nic_as_uplink_is_same_segment():
    # the box is a peer on the segment, not between the device and the gateway
    assert pd.decide(True, "eth0", "eth0", False) == pd.SAME_SEGMENT


def test_same_bridge_is_in_path_even_on_one_bridge_interface():
    assert pd.decide(True, "wlan0", "eth0", True) == pd.IN_PATH


# --- the OS readers, via a fake runner + fake /proc ----------------------------------------------------------------

class FakeOS:
    def __init__(self, forwarding="0", fdb="", neigh="", brif=None, master=None):
        self.v4 = forwarding
        self.fdb = fdb
        self.neigh = neigh
        self.brif = brif or {}        # bridge -> "port1 port2"
        self.master = master or {}    # port -> bridge

    def run(self, args):
        if args[:2] == ["bridge", "fdb"]:
            return (0, self.fdb)
        if args[:2] == ["ip", "neigh"]:
            return (0, self.neigh)
        return (1, "")

    def read_proc(self, path):
        if path == "/proc/sys/net/ipv4/ip_forward":
            return self.v4
        if path == "/proc/sys/net/ipv6/conf/all/forwarding":
            return "0"
        if path.startswith("/sys/class/net/") and path.endswith("/brif"):
            return self.brif.get(path.split("/")[-2], "")
        if path.startswith("/sys/class/net/") and path.endswith("/master"):
            return self.master.get(path.split("/")[-2], "")
        return ""


def _detector(os_):
    return pd.PathDetector(run=os_.run, read_proc=os_.read_proc)


def test_forwarding_off_short_circuits_to_same_segment():
    os_ = FakeOS(forwarding="0", neigh=f"{'10.0.0.9'} dev eth1 lladdr {DEV_MAC} REACHABLE")
    assert _detector(os_).method_for(DEV_MAC, "10.0.0.9", UP) == pd.SAME_SEGMENT


def test_routed_device_on_another_nic_is_in_path():
    os_ = FakeOS(forwarding="1", neigh=f"10.0.0.9 dev eth1 lladdr {DEV_MAC} REACHABLE")
    assert _detector(os_).method_for(DEV_MAC, "10.0.0.9", UP) == pd.IN_PATH


def test_bridged_device_behind_a_port_of_the_uplinks_bridge_is_in_path():
    os_ = FakeOS(forwarding="1",
                 fdb=f"{DEV_MAC} dev wlan0 master br0\n33:33:00:00:00:01 dev eth0 self permanent",
                 brif={"br0": "wlan0 eth0"},
                 master={"wlan0": "br0", "eth0": "br0"})
    # mac is on wlan0, which is a port of br0; the uplink eth0 is also a port of br0 -> the box bridges them
    assert _detector(os_).method_for(DEV_MAC, "10.0.0.9", UP) == pd.IN_PATH


def test_bridge_not_carrying_the_uplink_still_routes_to_it_so_in_path():
    os_ = FakeOS(forwarding="1",
                 fdb=f"{DEV_MAC} dev wlan0 master br1",
                 brif={"br1": "wlan0"},           # the uplink eth0 is NOT a port of br1
                 master={"wlan0": "br1"})
    # device bridged on br1 (seen on wlan0), the uplink reached on a different NIC (eth0): the box forwards between
    # them, so it is still in the path (the routed rule applies).
    assert _detector(os_).method_for(DEV_MAC, "10.0.0.9", UP) == pd.IN_PATH


def test_plain_single_segment_box_is_same_segment():
    # one NIC: the device and the gateway are both reached on eth0, nothing is forwarded between them
    os_ = FakeOS(forwarding="1", neigh=f"10.0.0.9 dev eth0 lladdr {DEV_MAC} REACHABLE")
    assert _detector(os_).method_for(DEV_MAC, "10.0.0.9", UP) == pd.SAME_SEGMENT


def test_readers_fail_safe_to_same_segment_on_error():
    def boom(args):
        raise OSError("no such tool")

    def boom_proc(path):
        if "ip_forward" in path:
            return "1"
        raise OSError("denied")
    assert pd.PathDetector(run=boom, read_proc=boom_proc).method_for(DEV_MAC, "10.0.0.9", UP) == pd.SAME_SEGMENT


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
