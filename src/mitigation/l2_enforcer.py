"""
Same-segment containment enforcement -- the socket-free core (CONTAINMENT_MODEL.md section 5, T2 2026-10-13).

A contained device is cut off by faking, to it, the link-layer address of the hosts in its scope (every peer + the
gateways for a Tarpit; the gateways / IPv6 RA routers only for Block internet -- mitigation/containment.fake_scope).
This module decides WHICH frames to emit; mitigation/ips.py owns the sockets and sends them. Keeping the decision pure
makes "devices coming and going" testable without a network:

  - refresh_specs(): every ~2 s, one forged frame per scope entry per contained MAC (the box answers "that host is at
    the bogus MAC"); peers that went silent have already dropped out of the peer table, so they drop out here.
  - reactive_spec(): a contained device's own ARP request / NS for an address in its scope is answered at once.
  - counter_fake_specs(): when a peer announces itself (a changed binding), the fake for that peer is re-sent to every
    contained device whose scope covers it.
  - restore_specs(): on release, the REAL address is sent back a few times so the device recovers at once.

A "spec" is a SendSpec(family, dst_mac, ip, sender_mac): fake it to `dst_mac` by saying `ip` is at `sender_mac`
(the bogus MAC while contained, the real MAC on release). ips.py turns each into an ARP reply (IPv4) or a Neighbor
Advertisement (IPv6) on the interface that reaches the device, and sends it.

Network-agnostic: nothing about any particular network/vendor/address; the gateways are discovered, the peers observed.
No identity code.
"""
import ipaddress
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from mitigation import containment as ct
from mitigation.peer_table import PeerTable, host_ip, usable_mac

BOGUS_MAC = "00:11:22:33:44:55"


@dataclass(frozen=True)
class SendSpec:
    family: int          # 4 (ARP) or 6 (Neighbor Advertisement)
    dst_mac: str         # the contained device's MAC the frame is addressed to
    ip: str              # the address being (un)faked
    sender_mac: str      # who `ip` is claimed to be at: BOGUS_MAC while contained, the real MAC on release


def _fam(ip: str) -> int:
    return ipaddress.ip_address(str(ip).split("%", 1)[0]).version


def _entry_macs(entry: dict) -> List[str]:
    return ct.entry_macs(entry)


def refresh_specs(entry: dict, peers: Dict[str, str], gateways: Dict[str, str],
                  bogus: str = BOGUS_MAC) -> List[SendSpec]:
    """Every forged frame to re-send to this contained device this refresh: its scope (peers+gateways for tarpit,
    gateways only for block_internet) faked to each of its MACs."""
    macs = _entry_macs(entry)
    if not macs:
        return []
    scope = ct.fake_scope(entry.get("mode", ct.TARPIT_MODE), peers, gateways, macs)
    out = []
    for ip in sorted(scope):
        for dst in macs:
            out.append(SendSpec(_fam(ip), dst, ip, bogus))
    return out


def reactive_spec(parsed_kind: str, src_mac: str, wanted_ip: str, entry: dict,
                  peers: Dict[str, str], gateways: Dict[str, str], bogus: str = BOGUS_MAC) -> Optional[SendSpec]:
    """The immediate answer to a contained device's own ARP request / NS: if `src_mac` is one of the device's MACs and
    `wanted_ip` is in its scope, fake it at once. `parsed_kind` is "arp_request" or "ns" (just for the family)."""
    macs = _entry_macs(entry)
    if ct.norm_mac(src_mac) not in macs:
        return None
    h = host_ip(wanted_ip)
    if h is None or ct.norm_mac(peers.get(h) or gateways.get(h) or "") in macs:
        return None          # never fake the device's own address to itself
    # Tarpit answers for ANY address the device asks for (cut all traffic, even peers not yet in the table);
    # Block internet answers only for a gateway/router (home traffic stays open).
    if entry.get("mode", ct.TARPIT_MODE) != ct.TARPIT_MODE and h not in (gateways or {}):
        return None
    return SendSpec(_fam(h), ct.norm_mac(src_mac), h, bogus)


def counter_fake_specs(announced_ip: str, targets: Iterable[dict], peers: Dict[str, str], gateways: Dict[str, str],
                       bogus: str = BOGUS_MAC) -> List[SendSpec]:
    """When a peer at `announced_ip` announces itself (new/changed binding, or a router RA), re-send the fake for it to
    every contained device whose scope covers it -- so a device that just saw the real peer is immediately re-poisoned."""
    h = host_ip(announced_ip)
    if h is None:
        return []
    out = []
    for entry in targets:
        macs = _entry_macs(entry)
        if not macs:
            continue
        scope = ct.fake_scope(entry.get("mode", ct.TARPIT_MODE), peers, gateways, macs)
        if h in scope and ct.norm_mac(peers.get(h) or gateways.get(h) or "") not in macs:
            for dst in macs:
                out.append(SendSpec(_fam(h), dst, h, bogus))
    return out


def restore_specs(entry: dict, peers: Dict[str, str], gateways: Dict[str, str]) -> List[SendSpec]:
    """On release: send each scope address's REAL MAC back to the device, so it recovers at once. Skips any whose real
    MAC is unknown (the device's cache expires on its own in about a minute)."""
    macs = _entry_macs(entry)
    if not macs:
        return []
    scope = ct.fake_scope(entry.get("mode", ct.TARPIT_MODE), peers, gateways, macs)
    out = []
    for ip in sorted(scope):
        real = ct.norm_mac(scope.get(ip) or peers.get(ip) or gateways.get(ip) or "")
        if usable_mac(real):
            for dst in macs:
                out.append(SendSpec(_fam(ip), dst, ip, real))
    return out
