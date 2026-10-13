"""mitigation/peer_table.py: the per-segment IP<->MAC table that drives same-segment containment (T2, 2026-10-13).
Records only real host addresses + unicast MACs, expires silent peers, is size-capped, and flags a new/changed binding
(which the enforcer counter-fakes)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mitigation.peer_table import PeerTable, usable_mac, host_ip  # noqa: E402

M1, M2 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"


@pytest.mark.parametrize("mac,ok", [
    (M1, True), ("AA:BB:CC:00:00:01", True), ("ff:ff:ff:ff:ff:ff", False), ("00:00:00:00:00:00", False),
    ("01:00:5e:00:00:fb", False), ("33:33:00:00:00:01", False), ("", False), ("aa:bb", False)])
def test_usable_mac(mac, ok):
    assert usable_mac(mac) is ok


@pytest.mark.parametrize("ip,ok", [
    ("10.0.0.5", "10.0.0.5"), ("192.168.1.255", None), ("224.0.0.1", None), ("255.255.255.255", None),
    ("0.0.0.0", None), ("127.0.0.1", None), ("fe80::1", "fe80::1"), ("fe80::1%eth0", "fe80::1"),
    ("ff02::1", None), ("2001:db8::5", "2001:db8::5"), ("not-an-ip", None)])
def test_host_ip(ip, ok):
    assert host_ip(ip) == ok


def test_observe_active_and_binding_change():
    t = PeerTable(ttl_seconds=100)
    assert t.observe("10.0.0.5", M1, now=1000) is True        # new binding
    assert t.observe("10.0.0.5", M1, now=1010) is False       # unchanged
    assert t.observe("10.0.0.5", M2, now=1020) is True        # changed -> announcement
    assert t.observe("10.0.0.99", "ff:ff:ff:ff:ff:ff", now=1020) is False   # unusable, not recorded
    assert t.active(now=1030) == {"10.0.0.5": M2}
    assert t.mac_for("10.0.0.5", now=1030) == M2


def test_expiry_drops_silent_peers():
    t = PeerTable(ttl_seconds=100)
    t.observe("10.0.0.5", M1, now=1000)
    t.observe("10.0.0.6", M2, now=1050)
    assert t.active(now=1060) == {"10.0.0.5": M1, "10.0.0.6": M2}
    assert t.active(now=1120) == {"10.0.0.6": M2}             # .5 silent > ttl, not active
    assert t.mac_for("10.0.0.5", now=1120) is None
    assert t.expire(now=1120) == 1 and len(t) == 1
    assert t.observe("10.0.0.5", M1, now=1121) is True        # returns -> announcement again


def test_families_filter():
    t = PeerTable(ttl_seconds=100)
    t.observe("10.0.0.5", M1, now=1000)
    t.observe("fe80::1", M2, now=1000)
    assert set(t.active(now=1001, families=(4,))) == {"10.0.0.5"}
    assert set(t.active(now=1001, families=(6,))) == {"fe80::1"}
    assert set(t.active(now=1001)) == {"10.0.0.5", "fe80::1"}


def test_size_cap_evicts_oldest():
    t = PeerTable(ttl_seconds=10_000, max_entries=3)
    for i in range(5):
        t.observe(f"10.0.0.{i}", f"aa:bb:cc:00:00:0{i}", now=1000 + i)
    assert len(t) == 3
    assert set(t.active(now=1005)) == {"10.0.0.2", "10.0.0.3", "10.0.0.4"}   # oldest two evicted


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
