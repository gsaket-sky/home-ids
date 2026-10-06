"""
argus/identity/discovery.py -- Zero-site bootstrap B (autonomy-completion effort,
Phase 10): auto-discovers this network's `trust_anchors` instead of requiring
hand-edited YAML.

NETWORK-AGNOSTIC BY CONSTRUCTION ([[feedback_network_agnostic_design]]): every
anchor found here comes from generic OS/network primitives -- psutil's own
interface table, the kernel's own neighbour table (ARP/NDP), the kernel's own default-route
table -- never a household-specific rule, hardcoded IP range, or vendor name. This
module has been run and verified against exactly one real network (this project's
own test bed) but contains nothing specific to it; every constant here is a generic
mechanism choice (which OS primitive to read), not a fact about any particular LAN.

Two roles are discovered:
  - "this_host": this machine's own LAN-facing IPv4 address + MAC, selected (when
    more than one non-loopback interface exists) as whichever interface's subnet
    actually contains the discovered gateway IP -- the generic "which NIC talks to
    the LAN" signal, not a guessed interface name (`eth0`/`ath0`/etc. vary by
    hardware and are never assumed).
  - "gateway": the LAN's default-route next-hop IP (read via the kernel's own
    routing table, `ip route show default` -- Linux-only, matching this project's
    Pi/x86-Linux-only deployment target), resolved to a MAC from the
    kernel's neighbour table (`mitigation/l2_raw.py`'s neighbor_mac(), which nudges the
    kernel to resolve the address if needed) -- no raw socket, no extra dependency, and
    not a routing-table MAC guess.

`discover()` NEVER writes to config.yaml or any live config path itself -- Phase 13
(the actual cutover) is what makes its output authoritative. This phase ships the
discovery mechanism itself, verified once against real `.94` output over SSH, so it
exists and is trustworthy before anything is wired to depend on it. It always logs a
diff against whatever `trust_anchors` config.yaml currently has (or an empty list, if
this network hasn't opted in yet) -- a PERMANENT feature that runs every call, not a
one-time dry-run gate, per this effort's own "fix forward with live data, no staged
soak periods" standing instruction.
"""
import ipaddress
import logging
import socket
import subprocess
from typing import Any, Dict, List, Optional

import psutil

LOGGER = logging.getLogger("argus.identity.discovery")

_ARP_TIMEOUT_SECONDS = 2.0
_ROUTE_COMMAND_TIMEOUT_SECONDS = 5.0


def _candidate_this_host_interfaces() -> List[Dict[str, Any]]:
    """Every non-loopback IPv4 interface this machine owns, with its own MAC and
    netmask where available -- psutil.net_if_addrs() only, no network I/O."""
    candidates: List[Dict[str, Any]] = []
    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        ip = None
        netmask = None
        mac = None
        for a in iface_addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                ip = a.address
                netmask = a.netmask
            elif a.family == psutil.AF_LINK and a.address and a.address != "00:00:00:00:00:00":
                mac = a.address
        if ip:
            candidates.append({"iface": iface_name, "ip": ip, "netmask": netmask, "mac": mac})
    return candidates


def _gateway_from_proc_route(path: str = "/proc/net/route") -> Optional[str]:
    """The IPv4 default gateway from the kernel's routing table file: no `ip` binary needed (the engine image has
    none, so trust-anchor discovery always fell through on .94). Columns: Iface Destination Gateway Flags ...; the
    default route has Destination 00000000 and the RTF_GATEWAY flag (0x2); addresses are little-endian hex."""
    try:
        with open(path, "r", encoding="ascii") as fh:
            next(fh, None)   # header
            for line in fh:
                parts = line.split()
                if len(parts) < 4 or parts[1] != "00000000" or not (int(parts[3], 16) & 0x2):
                    continue
                gw = int(parts[2], 16)
                if gw:
                    return ".".join(str((gw >> shift) & 0xFF) for shift in (0, 8, 16, 24))
    except (OSError, ValueError):
        pass
    return None


def default_gateway_ip() -> Optional[str]:
    """This network's default gateway (normally the router), discovered -- never assumed."""
    return _default_gateway_ip()


def _default_gateway_ip() -> Optional[str]:
    """Reads the real default-route gateway IP from the kernel's own routing
    table: /proc/net/route first (stdlib, works in the containers, which share
    the host network), then `ip route`. Linux-only -- matches this project's own
    Pi 8GB/x86_16gb deployment targets, no cross-platform fallback needed."""
    gw = _gateway_from_proc_route()
    if gw:
        return gw
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=_ROUTE_COMMAND_TIMEOUT_SECONDS, check=False,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        LOGGER.exception("[DISCOVERY] failed to read the default gateway via 'ip route'")
    return None


def _arp_resolve_mac(ip: str, timeout: float = _ARP_TIMEOUT_SECONDS) -> Optional[str]:
    """MAC for `ip` from the kernel's neighbour table (resolved on demand). Same name and signature as the
    old scapy ARP round-trip so callers and tests keep working; needs no raw-socket privileges."""
    try:
        from mitigation import l2_raw
        return l2_raw.neighbor_mac(ip, timeout=timeout)
    except Exception:
        LOGGER.exception("[DISCOVERY] neighbour lookup failed for %s", ip)
    return None


def _select_this_host_interface(candidates: List[Dict[str, Any]], gateway_ip: Optional[str]) -> Optional[Dict[str, Any]]:
    """Picks the ONE interface that's actually this network's LAN-facing NIC --
    load_trust_anchors() keeps only the FIRST occurrence of a duplicate role, so
    emitting more than one 'this_host' candidate would silently drop every one
    but the first with no signal about which was right. Preferred: whichever
    interface's own subnet (ip/netmask) actually contains the discovered gateway
    IP -- the generic 'which NIC talks to the LAN' signal. Falls back to the
    first candidate (logged loudly) if none match or the gateway is unknown,
    rather than emitting zero anchors."""
    if not candidates:
        return None
    if gateway_ip:
        for c in candidates:
            if not c.get("netmask"):
                continue
            try:
                network = ipaddress.ip_network(f"{c['ip']}/{c['netmask']}", strict=False)
                if ipaddress.ip_address(gateway_ip) in network:
                    return c
            except ValueError:
                continue
        LOGGER.warning(
            "[DISCOVERY] no candidate interface's subnet contains the discovered "
            "gateway %s -- falling back to the first non-loopback interface (%s). "
            "Multi-NIC hosts may need a manual trust_anchors entry.",
            gateway_ip, candidates[0]["iface"],
        )
    return candidates[0]


def _log_diff(previous: List[Dict[str, Any]], current: List[Dict[str, Any]]) -> None:
    prev_keys = {(a.get("role"), a.get("ip")) for a in previous if isinstance(a, dict)}
    curr_keys = {(a.get("role"), a.get("ip")) for a in current if isinstance(a, dict)}
    added = sorted(curr_keys - prev_keys)
    removed = sorted(prev_keys - curr_keys)
    if added or removed:
        LOGGER.warning(
            "[DISCOVERY] trust_anchors drift detected: added=%s removed=%s "
            "(previously configured: %d anchor(s), freshly discovered: %d anchor(s)).",
            added, removed, len(previous), len(current),
        )
    else:
        LOGGER.info(
            "[DISCOVERY] freshly discovered trust_anchors match the currently "
            "configured set exactly (%d anchor(s)) -- no drift.", len(current),
        )


def discover(previous_trust_anchors: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Produces a fresh trust_anchors list (the same [{role, ip, mac}, ...] shape
    config.yaml's network.trust_anchors already uses, directly consumable by
    argus.config.trust_anchors.load_trust_anchors()) from live OS/network state.
    Never raises -- a discovery failure returns whatever anchors it did manage to
    find (possibly none), always logging the diff against `previous_trust_anchors`
    (pass config.yaml's current value, or omit/None for a deployment that hasn't
    opted in yet)."""
    anchors: List[Dict[str, Any]] = []
    try:
        gateway_ip = _default_gateway_ip()
        candidates = _candidate_this_host_interfaces()
        this_host = _select_this_host_interface(candidates, gateway_ip)
        if this_host is not None:
            anchors.append({"role": "this_host", "ip": this_host["ip"], "mac": this_host.get("mac")})
        else:
            LOGGER.warning("[DISCOVERY] no non-loopback IPv4 interface found on this host at all.")

        if gateway_ip:
            gateway_mac = _arp_resolve_mac(gateway_ip)
            anchors.append({"role": "gateway", "ip": gateway_ip, "mac": gateway_mac})
        else:
            LOGGER.warning("[DISCOVERY] could not determine a default gateway -- no 'gateway' anchor this run.")
    except Exception:
        LOGGER.exception("[DISCOVERY] discover() failed partway through -- returning whatever anchors were found so far")

    _log_diff(previous_trust_anchors or [], anchors)
    return anchors
