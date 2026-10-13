"""
Containment method detection (CONTAINMENT_MODEL.md section 6, T3, 2026-10-13).

Per device, decide whether THIS box is in the forwarding path for the device's traffic -- a router between two NICs, or
a bridge / Wi-Fi AP the device sits behind -- or merely another host on the same Layer-2 segment:

  - **in path**: the box forwards the device's frames, so the kernel can drop them by MAC in the nftables `forward`
    hook (`nftables_fw.inpath_drop`). Reliable: the device cannot bypass it by ignoring ARP/NDP.
  - **same segment**: the box only shares the segment, so containment is the ARP/NDP deception (T2, l2_enforcer).

The two are not exclusive -- the same-segment deception is harmless when also in path, so containment runs it always and
ADDS the in-path drop when this box is in the path. This module only answers "is the box in the path for this device?".

Network-agnostic: it reads the kernel's own forwarding flag, neighbour table and bridge fdb; it assumes nothing about
addresses, subnets or vendors. The decision (`decide`) is a pure function of injected facts, so it is unit-testable
without root or a particular topology; the OS readers are separated and fail safe (on any error -> "same segment", the
conservative answer: never claim an in-path drop the kernel is not actually positioned to make).

Owner decision 2 (CONTAINMENT_MODEL section 9): **fail closed in path** -- when the box IS in the path and the in-path
drop cannot be installed, that is surfaced (CRITICAL + a containment event), never silently treated as contained. That
handling lives in ips.py where the firewall result is known; this module supplies the detection it keys on.
"""
import logging
import shutil
import subprocess
from typing import Callable, List, Optional, Set, Tuple

LOGGER = logging.getLogger("home_ids.path_detect")

IN_PATH = "in_path"
SAME_SEGMENT = "same_segment"


def decide(forwarding: bool, device_iface: Optional[str], uplink_iface: Optional[str], same_bridge: bool) -> str:
    """Pure decision. `forwarding` is whether this box forwards at all; `device_iface` the interface the device is
    reached on (bridge port or routed NIC); `uplink_iface` the interface the default gateway is reached on;
    `same_bridge` whether the device's MAC and the uplink are ports of one bridge this box owns.

      - the box forwards nothing  -> same segment (it cannot be in any path)
      - the device cannot be located -> same segment (never claim a drop we cannot place)
      - device and uplink on one bridge -> in path (the box bridges the device's frames: a Pi AP / transparent bridge)
      - device reached on a different NIC than the uplink -> in path (the box routes between the two)
      - otherwise (same single NIC as the uplink, no bridge) -> same segment (a peer on the segment, not between it
        and the gateway)."""
    if not forwarding:
        return SAME_SEGMENT
    if not device_iface:
        return SAME_SEGMENT
    if same_bridge:
        return IN_PATH
    if uplink_iface and device_iface != uplink_iface:
        return IN_PATH
    return SAME_SEGMENT


def _default_run(args: List[str]) -> Tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return p.returncode, (p.stdout or "")
    except Exception as exc:  # noqa: BLE001 -- any failure becomes the conservative "unknown"
        return 1, str(exc)


class PathDetector:
    """OS-reading wrapper around `decide`. The command runner and the /proc reader are injected so the whole thing is
    unit-testable without root, netns or a particular box. Every reader fails safe to the conservative answer."""

    def __init__(self, run: Optional[Callable[[List[str]], Tuple[int, str]]] = None,
                 read_proc: Optional[Callable[[str], str]] = None):
        self._run = run or _default_run
        self._read_proc = read_proc or self._default_read_proc

    @staticmethod
    def _default_read_proc(path: str) -> str:
        try:
            with open(path, "r", encoding="ascii", errors="replace") as fh:
                return fh.read()
        except Exception:
            return ""

    def forwarding(self) -> bool:
        """True when the box forwards IPv4 or IPv6 -- the precondition for being in any path."""
        v4 = self._read_proc("/proc/sys/net/ipv4/ip_forward").strip()
        v6 = self._read_proc("/proc/sys/net/ipv6/conf/all/forwarding").strip()
        return v4 == "1" or v6 == "1"

    def _fdb_port(self, mac: str) -> Optional[str]:
        """The bridge port a MAC sits behind, from `bridge fdb show` (e.g. a device on the Pi's wlan0). None if the MAC
        is not in any fdb or the `bridge` tool is absent."""
        if self._run is _default_run and shutil.which("bridge") is None:
            return None
        rc, out = self._run(["bridge", "fdb", "show"])
        if rc != 0:
            return None
        mac = mac.lower()
        for line in out.splitlines():
            parts = line.split()
            # "<mac> dev <port> ..." -- skip "self"/"permanent" local entries without a learned port
            if parts and parts[0].lower() == mac and "dev" in parts:
                return parts[parts.index("dev") + 1]
        return None

    def _neigh_iface(self, ip: str) -> Optional[str]:
        """The interface an IP's neighbour entry is on, from `ip neigh` -- the routed-device case (the box reaches the
        device on one NIC and the gateway on another)."""
        rc, out = self._run(["ip", "neigh", "show", ip])
        if rc != 0:
            return None
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        return None

    def _bridge_ports(self, bridge: str) -> Set[str]:
        """The member ports of a bridge, from `ls /sys/class/net/<bridge>/brif`."""
        listing = self._read_proc(f"/sys/class/net/{bridge}/brif")
        return {p for p in listing.split() if p}

    def _bridge_of_port(self, port: str) -> Optional[str]:
        """The bridge a port belongs to, from `/sys/class/net/<port>/master` (a symlink to the bridge)."""
        master = self._read_proc(f"/sys/class/net/{port}/master").strip()
        return master.rsplit("/", 1)[-1] if master else None

    def method_for(self, mac: str, ip: Optional[str], uplink_iface: Optional[str]) -> str:
        """IN_PATH / SAME_SEGMENT for the device at (`mac`, `ip`), given the uplink interface (where the gateway is
        reached). Fails safe to SAME_SEGMENT on any error."""
        try:
            if not self.forwarding():
                return SAME_SEGMENT
            fdb_port = self._fdb_port(mac) if mac else None
            same_bridge = False
            device_iface = fdb_port
            if fdb_port:
                bridge = self._bridge_of_port(fdb_port)
                if bridge and uplink_iface:
                    ports = self._bridge_ports(bridge)
                    same_bridge = uplink_iface in ports or self._bridge_of_port(uplink_iface) == bridge
            else:
                device_iface = self._neigh_iface(ip) if ip else None
            return decide(True, device_iface, uplink_iface, same_bridge)
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("path detection for %s/%s failed -> same segment: %s", mac, ip, exc)
            return SAME_SEGMENT
