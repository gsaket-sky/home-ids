"""
l2_raw.py - Layer-2 primitives for the ARP/NDP tarpit, built on the standard library only.

Replaces scapy (GPL-2.0) for the three things this codebase used it for:
  - build + send a forged ARP reply ("the gateway is at <bogus MAC>") to a contained device;
  - receive IPv6 Neighbor Solicitations and answer a contained device's with a forged
    Neighbor Advertisement;
  - (discovery) look up a neighbour's MAC -- done via the kernel's neighbour table instead
    of a raw ARP request, see neighbor_mac().

Linux only (AF_PACKET), same as the tarpit always was. Needs root or CAP_NET_RAW, exactly like
the scapy version. Packet builders/parsers are pure functions (bytes in, bytes out) so they can
be tested without privileges or a network.
"""
import ctypes
import ipaddress
import logging
import re
import socket
import struct
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

LOGGER = logging.getLogger("home_ids.l2_raw")

ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
ICMPV6_NS = 135
ICMPV6_NA = 136
IPPROTO_ICMPV6 = 58
SO_ATTACH_FILTER = 26

# Frame offsets for an untagged Ethernet + IPv6 (no extension headers) + ICMPv6 packet.
_OFF_IPV6 = 14
_OFF_IPV6_NH = _OFF_IPV6 + 6
_OFF_IPV6_SRC = _OFF_IPV6 + 8
_OFF_IPV6_DST = _OFF_IPV6 + 24
_OFF_ICMP = _OFF_IPV6 + 40
_OFF_NS_TARGET = _OFF_ICMP + 8


# ---- addresses --------------------------------------------------------------------------------
def mac_bytes(mac: str) -> bytes:
    b = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(b) != 6:
        raise ValueError(f"bad MAC {mac!r}")
    return b


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


# ---- ARP --------------------------------------------------------------------------------------
def build_arp_reply(*, eth_src: str, eth_dst: str, sender_mac: str, sender_ip: str,
                    target_mac: str, target_ip: str) -> bytes:
    """Ethernet + ARP reply (op 2): 'sender_ip is at sender_mac', addressed to target."""
    eth = mac_bytes(eth_dst) + mac_bytes(eth_src) + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    arp += mac_bytes(sender_mac) + ipaddress.IPv4Address(sender_ip).packed
    arp += mac_bytes(target_mac) + ipaddress.IPv4Address(target_ip).packed
    return eth + arp


# ---- IPv6 / NDP -------------------------------------------------------------------------------
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def icmpv6_checksum(src: bytes, dst: bytes, icmp: bytes) -> int:
    pseudo = src + dst + struct.pack("!I", len(icmp)) + b"\x00\x00\x00" + bytes([IPPROTO_ICMPV6])
    return _checksum(pseudo + icmp)


def parse_neighbor_solicitation(frame: bytes) -> Optional[Dict[str, str]]:
    """Return {eth_src, ip_src, target} for an untagged Ethernet/IPv6/ICMPv6 NS frame, else None.
    Frames with IPv6 extension headers are ignored (NS never carries them in practice)."""
    if len(frame) < _OFF_NS_TARGET + 16:
        return None
    if struct.unpack_from("!H", frame, 12)[0] != ETH_P_IPV6:
        return None
    if frame[_OFF_IPV6] >> 4 != 6 or frame[_OFF_IPV6_NH] != IPPROTO_ICMPV6 or frame[_OFF_ICMP] != ICMPV6_NS:
        return None
    return {
        "eth_src": mac_str(frame[6:12]),
        "ip_src": str(ipaddress.IPv6Address(frame[_OFF_IPV6_SRC:_OFF_IPV6_SRC + 16])),
        "target": str(ipaddress.IPv6Address(frame[_OFF_NS_TARGET:_OFF_NS_TARGET + 16])),
    }


def build_neighbor_advertisement(*, eth_src: str, eth_dst: str, ip_src: str, ip_dst: str,
                                 target: str, lladdr: str) -> bytes:
    """Ethernet + IPv6 + ICMPv6 NA (Router|Solicited|Override) with a Target Link-Layer option."""
    src = ipaddress.IPv6Address(ip_src).packed
    dst = ipaddress.IPv6Address(ip_dst).packed
    icmp = struct.pack("!BBHI", ICMPV6_NA, 0, 0, 0xE0000000) + ipaddress.IPv6Address(target).packed
    icmp += bytes([2, 1]) + mac_bytes(lladdr)                       # option 2 = target LL address, len 1 (8 bytes)
    csum = icmpv6_checksum(src, dst, icmp)
    icmp = icmp[:2] + struct.pack("!H", csum) + icmp[4:]
    ip6 = struct.pack("!IHBB", 0x60000000, len(icmp), IPPROTO_ICMPV6, 255) + src + dst
    eth = mac_bytes(eth_dst) + mac_bytes(eth_src) + struct.pack("!H", ETH_P_IPV6)
    return eth + ip6 + icmp


# Classic BPF: accept only IPv6 / ICMPv6 / type 135 (NS), so the kernel drops every other frame
# before Python sees it (the old scapy sniff decoded every ICMPv6 packet in Python).
_NS_FILTER = [
    (0x28, 0, 0, 12),           # ldh [12]            ethertype
    (0x15, 0, 5, ETH_P_IPV6),   # jeq 0x86dd  else -> drop
    (0x30, 0, 0, _OFF_IPV6_NH), # ldb [20]            next header
    (0x15, 0, 3, IPPROTO_ICMPV6),
    (0x30, 0, 0, _OFF_ICMP),    # ldb [54]            ICMPv6 type
    (0x15, 0, 1, ICMPV6_NS),
    (0x06, 0, 0, 0x40000),      # accept
    (0x06, 0, 0, 0),            # drop
]


def attach_ns_filter(sock: socket.socket) -> bool:
    """Best effort: attach the NS-only BPF program. Returns False (caller still filters in Python)."""
    try:
        prog = b"".join(struct.pack("HBBI", *ins) for ins in _NS_FILTER)
        buf = ctypes.create_string_buffer(prog)
        fprog = struct.pack("HL", len(_NS_FILTER), ctypes.addressof(buf))
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        sock._ns_filter_buf = buf  # keep the program alive as long as the socket
        return True
    except (OSError, AttributeError, ValueError) as exc:
        LOGGER.debug("NS BPF filter not attached (%s); filtering in Python", exc)
        return False


# ---- sockets / interfaces ---------------------------------------------------------------------
def open_raw(proto: int = ETH_P_ALL) -> socket.socket:
    return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))


def send_frame(sock: socket.socket, ifname: str, frame: bytes) -> None:
    sock.sendto(frame, (ifname, 0))


def interface_mac(ifname: str) -> Optional[str]:
    try:
        return Path(f"/sys/class/net/{ifname}/address").read_text().strip() or None
    except OSError:
        return None


_ROUTE_DEV_RE = re.compile(r"\bdev\s+(\S+)")
_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B


def _iface_ipv4_network(ifname: str):
    """(IPv4Address, IPv4Network) for `ifname` via ioctl -- no `ip` binary needed. None if it has no v4."""
    import fcntl
    ifr = struct.pack("16sH14s", ifname.encode()[:15], socket.AF_INET, b"\x00" * 14)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), _SIOCGIFADDR, ifr)[20:24])
        mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), _SIOCGIFNETMASK, ifr)[20:24])
    except OSError:
        return None
    finally:
        s.close()
    return ipaddress.IPv4Address(addr), ipaddress.ip_network(f"{addr}/{mask}", strict=False)


def interface_for(ip: str) -> Optional[str]:
    """The interface whose subnet contains `ip` (IPv4). Pure stdlib (ioctl over the interface list) so it
    works in a container without iproute2; falls back to `ip route get` only if the ioctl scan finds nothing."""
    try:
        target = ipaddress.IPv4Address(ip)
        for _, ifname in socket.if_nameindex():
            info = _iface_ipv4_network(ifname)
            if info and target in info[1]:
                return ifname
    except (OSError, ValueError):
        pass
    try:
        out = subprocess.run(["ip", "route", "get", ip], capture_output=True, text=True, timeout=3).stdout
        m = _ROUTE_DEV_RE.search(out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


_NEIGH_MAC_RE = re.compile(r"\blladdr\s+([0-9a-fA-F:]{17})")


def _read_neighbor(ip: str) -> Optional[str]:
    try:
        out = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=3).stdout
        m = _NEIGH_MAC_RE.search(out)
        if m:
            return m.group(1).lower()
    except (OSError, subprocess.SubprocessError):
        pass
    try:  # IPv4 fallback without iproute2
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                return parts[3].lower()
    except OSError:
        pass
    return None


def neighbor_mac(ip: str, timeout: float = 2.0) -> Optional[str]:
    """MAC of a LAN neighbour from the kernel's neighbour table. If the entry is missing, send one
    harmless UDP datagram (discard port 9) so the kernel resolves it, then read again. No raw
    socket or privileges needed."""
    mac = _read_neighbor(ip)
    if mac:
        return mac
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.sendto(b"", (ip, 9))
    except OSError:
        pass
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.2)
        mac = _read_neighbor(ip)
        if mac:
            return mac
    return None


def recv_frame(sock: socket.socket, bufsize: int = 2048) -> Tuple[bytes, str]:
    data, addr = sock.recvfrom(bufsize)
    return data, addr[0]
