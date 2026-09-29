"""Standalone test (run directly): mitigation/l2_raw.py packet builders/parsers (no privileges, no network).

When scapy happens to be installed in the dev environment it is used ONLY here, as an independent decoder
to cross-check the hand-built frames (checksums, flags, options). The product itself no longer imports it."""
import struct
import sys
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))
from mitigation import l2_raw as L

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


IFACE_MAC, BOGUS, VICTIM = "02:00:00:00:00:01", "00:11:22:33:44:55", "02:aa:bb:cc:dd:ee"

arp = L.build_arp_reply(eth_src=IFACE_MAC, eth_dst=VICTIM, sender_mac=BOGUS, sender_ip="192.168.77.1",
                        target_mac=VICTIM, target_ip="192.168.77.40")
check("ARP frame is 42 bytes", len(arp) == 42, str(len(arp)))
check("ARP ethertype + op=2", arp[12:14] == b"\x08\x06" and struct.unpack("!H", arp[20:22])[0] == 2)
check("ARP sender MAC is the bogus one", arp[22:28] == L.mac_bytes(BOGUS))

# NS as a victim would send it: fe80::victim asks for the gateway's address
def build_ns(src_mac, ip_src, target):
    src = L.ipaddress.IPv6Address(ip_src).packed
    dst = L.ipaddress.IPv6Address("ff02::1:ff00:1").packed
    icmp = struct.pack("!BBHI", 135, 0, 0, 0) + L.ipaddress.IPv6Address(target).packed + bytes([1, 1]) + L.mac_bytes(src_mac)
    c = L.icmpv6_checksum(src, dst, icmp)
    icmp = icmp[:2] + struct.pack("!H", c) + icmp[4:]
    return (L.mac_bytes("33:33:ff:00:00:01") + L.mac_bytes(src_mac) + b"\x86\xdd"
            + struct.pack("!IHBB", 0x60000000, len(icmp), 58, 255) + src + dst + icmp)

ns = build_ns(VICTIM, "fe80::aa", "fe80::1")
p = L.parse_neighbor_solicitation(ns)
check("NS parsed", p == {"eth_src": VICTIM, "ip_src": "fe80::aa", "target": "fe80::1"}, str(p))
check("non-NS ICMPv6 ignored", L.parse_neighbor_solicitation(ns[:54] + b"\x88" + ns[55:]) is None)
check("IPv4 frame ignored", L.parse_neighbor_solicitation(arp + b"\x00" * 40) is None)
check("truncated frame ignored", L.parse_neighbor_solicitation(ns[:60]) is None)

na = L.build_neighbor_advertisement(eth_src=BOGUS, eth_dst=VICTIM, ip_src="fe80::1", ip_dst="fe80::aa",
                                    target="fe80::1", lladdr=BOGUS)
check("NA frame length 14+40+32", len(na) == 86, str(len(na)))
icmp = na[54:]
src, dst = na[22:38], na[38:54]
check("NA checksum verifies", L._checksum(src + dst + struct.pack("!I", len(icmp)) + b"\x00\x00\x00\x3a" + icmp) == 0)
check("NA flags R|S|O", struct.unpack("!I", icmp[4:8])[0] == 0xE0000000)
check("NA hop limit 255", na[21] == 255)
check("filter program has 8 instructions", len(L._NS_FILTER) == 8)
check("mac helpers round-trip", L.mac_str(L.mac_bytes("AA-BB-CC-DD-EE-FF")) == "aa:bb:cc:dd:ee:ff")

try:
    from scapy.all import Ether, ARP, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr  # dev-only cross-check
    s = Ether(arp)
    check("scapy decodes ARP: op/psrc/hwsrc/pdst",
          s[ARP].op == 2 and s[ARP].psrc == "192.168.77.1" and s[ARP].hwsrc == BOGUS and s[ARP].pdst == "192.168.77.40")
    n = Ether(na)
    orig = n[ICMPv6ND_NA].cksum
    del n[ICMPv6ND_NA].cksum
    recomputed = Ether(bytes(n))[ICMPv6ND_NA].cksum
    check("scapy agrees on the NA checksum", orig == recomputed, f"{orig:#x} vs {recomputed:#x}")
    check("scapy decodes NA target + R/S/O + lladdr",
          n[ICMPv6ND_NA].tgt == "fe80::1" and n[ICMPv6ND_NA].R == 1 and n[ICMPv6ND_NA].S == 1
          and n[ICMPv6ND_NA].O == 1 and n[ICMPv6NDOptDstLLAddr].lladdr == BOGUS)
except ImportError:
    print("[SKIP] scapy not installed -- cross-decode skipped")

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED: {FAILURES}")
    sys.exit(1)
print("ALL PASSED")
