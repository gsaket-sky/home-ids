"""mitigation/l2_raw.py parsers for same-segment containment (T2, 2026-10-13): ARP, Neighbor Advertisement, Router
Advertisement, and the ARP+ICMPv6 capture filter. Round-trips against the builders where they exist, and a BPF
interpreter proves the filter admits ARP/ICMPv6 and drops the rest."""
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mitigation import l2_raw  # noqa: E402

DEV = "aa:bb:cc:00:00:01"
BOX = "02:00:00:00:00:01"
BOGUS = "00:11:22:33:44:55"


def test_parse_arp_request_and_reply_roundtrip():
    reply = l2_raw.build_arp_reply(eth_src=BOX, eth_dst=DEV, sender_mac=BOGUS, sender_ip="10.0.0.1",
                                   target_mac=DEV, target_ip="10.0.0.9")
    p = l2_raw.parse_arp(reply)
    assert p["op"] == "reply" and p["sender_ip"] == "10.0.0.1" and p["sender_mac"] == BOGUS
    assert p["target_ip"] == "10.0.0.9" and p["eth_dst"] == DEV
    # a hand-built request (op 1): device asks who-has 10.0.0.7
    eth = l2_raw.mac_bytes("ff:ff:ff:ff:ff:ff") + l2_raw.mac_bytes(DEV) + struct.pack("!H", l2_raw.ETH_P_ARP)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + l2_raw.mac_bytes(DEV) + bytes([10, 0, 0, 5]) \
        + l2_raw.mac_bytes("00:00:00:00:00:00") + bytes([10, 0, 0, 7])
    q = l2_raw.parse_arp(eth + arp)
    assert q["op"] == "request" and q["sender_ip"] == "10.0.0.5" and q["target_ip"] == "10.0.0.7"


def test_parse_arp_rejects_non_arp():
    assert l2_raw.parse_arp(b"\x00" * 42) is None
    assert l2_raw.parse_arp(b"\x00" * 10) is None


def test_parse_neighbor_advertisement_roundtrip():
    na = l2_raw.build_neighbor_advertisement(eth_src=BOX, eth_dst=DEV, ip_src="fe80::1", ip_dst="fe80::9",
                                             target="fe80::1", lladdr=BOGUS)
    p = l2_raw.parse_neighbor_advertisement(na)
    assert p and p["target"] == "fe80::1" and p["lladdr"] == BOGUS and p["eth_src"] == BOX
    # an NS must not parse as an NA
    ns = _build_ns(src_mac=DEV, ip_src="fe80::9", target="fe80::1")
    assert l2_raw.parse_neighbor_advertisement(ns) is None
    assert l2_raw.parse_neighbor_solicitation(ns)["target"] == "fe80::1"


def _build_ns(src_mac, ip_src, target):
    icmp = struct.pack("!BBHI", l2_raw.ICMPV6_NS, 0, 0, 0) + __import__("ipaddress").IPv6Address(target).packed
    ip6 = struct.pack("!IHBB", 0x60000000, len(icmp), l2_raw.IPPROTO_ICMPV6, 255) \
        + __import__("ipaddress").IPv6Address(ip_src).packed + __import__("ipaddress").IPv6Address("ff02::1").packed
    eth = l2_raw.mac_bytes("33:33:00:00:00:01") + l2_raw.mac_bytes(src_mac) + struct.pack("!H", l2_raw.ETH_P_IPV6)
    return eth + ip6 + icmp


def test_parse_router_advertisement():
    icmp = struct.pack("!BBHI", l2_raw.ICMPV6_RA, 0, 0, 0) + b"\x00" * 12   # RA header (rest unused by the parser)
    import ipaddress
    ip6 = struct.pack("!IHBB", 0x60000000, len(icmp), l2_raw.IPPROTO_ICMPV6, 255) \
        + ipaddress.IPv6Address("fe80::abcd").packed + ipaddress.IPv6Address("ff02::1").packed
    eth = l2_raw.mac_bytes("33:33:00:00:00:01") + l2_raw.mac_bytes("02:aa:bb:cc:dd:ee") + struct.pack("!H", l2_raw.ETH_P_IPV6)
    p = l2_raw.parse_router_advertisement(eth + ip6 + icmp)
    assert p == {"eth_src": "02:aa:bb:cc:dd:ee", "ip_src": "fe80::abcd"}
    assert l2_raw.parse_router_advertisement(_build_ns(DEV, "fe80::9", "fe80::1")) is None   # NS is not an RA


# --- the ARP+ICMPv6 BPF filter, via a tiny interpreter ----------------------------------------------------------

def _run_bpf(prog, frame):
    pc, acc = 0, 0
    while True:
        code, jt, jf, k = prog[pc]
        if code == 0x28:
            acc = struct.unpack_from("!H", frame, k)[0]
        elif code == 0x30:
            acc = frame[k]
        elif code == 0x15:
            pc += (jt if acc == k else jf) + 1
            continue
        elif code == 0x06:
            return k
        pc += 1


def test_arp_and_icmp6_filter_admits_the_right_frames():
    prog = l2_raw.arp_and_icmp6_filter_program()
    arp = l2_raw.build_arp_reply(eth_src=BOX, eth_dst=DEV, sender_mac=BOGUS, sender_ip="10.0.0.1",
                                 target_mac=DEV, target_ip="10.0.0.9")
    na = l2_raw.build_neighbor_advertisement(eth_src=BOX, eth_dst=DEV, ip_src="fe80::1", ip_dst="fe80::9",
                                             target="fe80::1", lladdr=BOGUS)
    ipv4_other = l2_raw.mac_bytes(DEV) + l2_raw.mac_bytes(BOX) + struct.pack("!H", 0x0800) + b"\x45" + b"\x00" * 40
    assert _run_bpf(prog, arp) > 0
    assert _run_bpf(prog, na) > 0
    assert _run_bpf(prog, ipv4_other) == 0        # plain IPv4 dropped
    assert all(0 <= jt <= 255 and 0 <= jf <= 255 for _c, jt, jf, _k in prog)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
