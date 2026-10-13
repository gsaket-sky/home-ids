"""
Per-segment peer table for same-segment containment (CONTAINMENT_MODEL.md section 5, T2 2026-10-13).

A contained device is cut off by faking, to it, the link-layer address of the hosts it would otherwise reach -- for a
Tarpit, every active peer and the gateway(s); for Block internet, only the gateways/routers. To fake "every active
peer" the box needs to know who the peers are right now, so this table records IP -> MAC from what the box passively
observes (ARP request/reply/gratuitous, NDP NS/NA/RA, plus the engine's own device list). Entries expire when a host
goes quiet (so a peer that left is dropped from the refresh) and the table is size-capped. Returning peers are picked
up again by their next announcement.

Pure data structure: no sockets, no I/O; the enforcer feeds it observations and reads the active set. Network-agnostic
-- nothing about any particular network, vendor or address is assumed; non-host addresses (broadcast, multicast,
unspecified) and unusable MACs are never recorded.
"""
import ipaddress
import time
from typing import Dict, Optional, Tuple

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
DEFAULT_TTL_SECONDS = 300.0          # a host silent this long drops out of the refresh (order of minutes, section 5)
DEFAULT_MAX_ENTRIES = 4096           # size cap; a home/small-company segment is tens to low hundreds


def _norm_mac(mac) -> str:
    return str(mac or "").strip().lower()


def usable_mac(mac) -> bool:
    m = _norm_mac(mac)
    if len(m.split(":")) != 6 or m in ("", ZERO_MAC, BROADCAST_MAC):
        return False
    try:
        first = int(m.split(":")[0], 16)
    except ValueError:
        return False
    return not (first & 0x01)          # a multicast/broadcast group MAC is never a real host


def host_ip(ip) -> Optional[str]:
    """The address as a plain host address string, or None when it is not one the box should ever fake to a device:
    broadcast, multicast, unspecified, or loopback. Link-local IPv6 (fe80::) IS a host address (NDP uses it)."""
    s = str(ip or "").split("%", 1)[0].strip()
    if not s:
        return None
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.is_multicast or a.is_unspecified or a.is_loopback:
        return None
    if a.version == 4 and (a.is_reserved or str(a).endswith(".255")):
        return None
    return str(a)


class PeerTable:
    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS, max_entries: int = DEFAULT_MAX_ENTRIES):
        self.ttl = float(ttl_seconds)
        self.max_entries = int(max_entries)
        self._peers: Dict[str, Tuple[str, float]] = {}      # ip -> (mac, last_seen)

    def observe(self, ip, mac, now: Optional[float] = None) -> bool:
        """Record that `ip` is at `mac`, seen now. Returns True when the (ip, mac) binding is new or changed (the
        enforcer counter-fakes such an announcement to contained devices). Ignores non-host addresses / unusable MACs."""
        now = time.time() if now is None else now
        h = host_ip(ip)
        m = _norm_mac(mac)
        if h is None or not usable_mac(m):
            return False
        prev = self._peers.get(h)
        self._peers[h] = (m, now)
        if len(self._peers) > self.max_entries:
            self._evict_oldest()
        return prev is None or prev[0] != m

    def forget(self, ip) -> None:
        self._peers.pop(host_ip(ip) or "", None)

    def mac_for(self, ip, now: Optional[float] = None) -> Optional[str]:
        now = time.time() if now is None else now
        hit = self._peers.get(host_ip(ip) or "")
        if hit is None or now - hit[1] >= self.ttl:
            return None
        return hit[0]

    def active(self, now: Optional[float] = None, families=(4, 6)) -> Dict[str, str]:
        """{ip: mac} for every peer seen within the TTL, limited to the given address families."""
        now = time.time() if now is None else now
        fams = set(families)
        out = {}
        for ip, (mac, seen) in self._peers.items():
            if now - seen < self.ttl and ipaddress.ip_address(ip.split("%", 1)[0]).version in fams:
                out[ip] = mac
        return out

    def expire(self, now: Optional[float] = None) -> int:
        """Drop silent entries; returns how many were removed. Called periodically by the enforcer."""
        now = time.time() if now is None else now
        stale = [ip for ip, (_m, seen) in self._peers.items() if now - seen >= self.ttl]
        for ip in stale:
            del self._peers[ip]
        return len(stale)

    def _evict_oldest(self) -> None:
        drop = sorted(self._peers.items(), key=lambda kv: kv[1][1])[: max(1, len(self._peers) - self.max_entries)]
        for ip, _ in drop:
            del self._peers[ip]

    def __len__(self) -> int:
        return len(self._peers)
