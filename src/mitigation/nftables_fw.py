"""
nftables firewall for containment (CONTAINMENT_MODEL.md section 4, T2 box-drop + T3 in-path, 2026-10-13).

Two uses, both "drop this device's frames by MAC":
  - **box drop** (T2, owner decision 1 = yes): a Tarpitted device must not reach the box itself (Pi-hole DNS, web UI).
    A rule in the `input` hook drops frames whose Ethernet source is the device.
  - **in-path** (T3): when the box forwards the device's traffic (Pi as AP, bridge, router), drop in the `forward`
    hook -- a Tarpit drops both directions; Block internet drops only forwarding out the uplink.

All of it lives in one dedicated `inet homeids_containment` table so it never touches the operator's own firewall and
is removed cleanly. Per-device state is held in nftables SETS of MAC addresses (one static rule per set), so
containing/releasing a device is a single add/delete-element -- no rule-handle bookkeeping. Network-agnostic (no
address/vendor assumptions); when `nft` is absent (not Linux, or iptables-only) every call is a logged no-op, so the
same-segment ARP/NDP method still works on its own.

The command runner is injected so the decisions are unit-testable without root or a kernel.
"""
import logging
import shutil
import subprocess
from typing import Callable, Iterable, List, Optional, Tuple

LOGGER = logging.getLogger("home_ids.nftables_fw")
TABLE = "homeids_containment"
_SET_BOX = "box_blocked"            # Tarpit: drop the device's frames to the box (input)
_SET_INPATH_ALL = "inpath_blocked"  # Tarpit in-path: drop both directions (forward)
_SET_INPATH_NET = "inpath_internet"  # Block internet in-path: drop forwarding out the uplink (forward)


def _default_run(args: List[str]) -> Tuple[int, str]:
    try:
        p = subprocess.run(["nft", *args], capture_output=True, text=True, timeout=5)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001 -- availability/permission errors become a clean no-op
        return 1, str(exc)


def _norm(mac) -> str:
    return str(mac or "").strip().lower()


class NftContainment:
    def __init__(self, run: Optional[Callable[[List[str]], Tuple[int, str]]] = None, uplink: Optional[str] = None):
        self._run = run or _default_run
        self.uplink = uplink
        self._ensured = False

    def available(self) -> bool:
        if self._run is _default_run and shutil.which("nft") is None:
            return False
        rc, _ = self._run(["--version"])
        return rc == 0

    def ensure(self) -> bool:
        """Create the table / sets / chains / static rules once (idempotent via a presence check; the per-device sets
        survive, so this never duplicates rules). Returns True when the table is present afterwards."""
        if self._ensured:
            return True
        if not self.available():
            return False
        if self._run(["list", "table", "inet", TABLE])[0] == 0:
            self._ensured = True
            return True
        net = f"ether saddr @{_SET_INPATH_NET} oifname \"{self.uplink}\" drop" if self.uplink else None
        script = [
            f"add table inet {TABLE}",
            f"add set inet {TABLE} {_SET_BOX} {{ type ether_addr; }}",
            f"add set inet {TABLE} {_SET_INPATH_ALL} {{ type ether_addr; }}",
            f"add set inet {TABLE} {_SET_INPATH_NET} {{ type ether_addr; }}",
            f"add chain inet {TABLE} input {{ type filter hook input priority -150; policy accept; }}",
            f"add chain inet {TABLE} forward {{ type filter hook forward priority -150; policy accept; }}",
            f"add rule inet {TABLE} input ether saddr @{_SET_BOX} drop",
            f"add rule inet {TABLE} forward ether saddr @{_SET_INPATH_ALL} drop",
            f"add rule inet {TABLE} forward ether daddr @{_SET_INPATH_ALL} drop",
        ]
        if net:
            script.append(f"add rule inet {TABLE} forward {net}")
        rc, out = self._run_script(script)
        if rc != 0:
            LOGGER.warning("nft containment table setup failed (containment falls back to same-segment only): %s", out)
            return False
        self._ensured = True
        return True

    def _run_script(self, lines: List[str]) -> Tuple[int, str]:
        # one atomic `nft -f` so a partial failure leaves nothing behind
        return self._run(["-f", "-", "\n".join(lines) + "\n"])

    def _set_elems(self, set_name: str, macs: Iterable[str], add: bool) -> bool:
        wanted = sorted({_norm(m) for m in macs if _norm(m) and len(_norm(m).split(":")) == 6})
        if not wanted or not self.ensure():
            return False
        verb = "add" if add else "delete"
        lines = [f"{verb} element inet {TABLE} {set_name} {{ {m} }}" for m in wanted]
        rc, out = self._run_script(lines)
        if rc != 0 and add:          # a delete of an absent element is a harmless miss
            LOGGER.warning("nft %s element %s failed: %s", verb, set_name, out)
        return rc == 0

    # -- T2: the box itself --
    def box_drop(self, macs: Iterable[str]) -> bool:
        return self._set_elems(_SET_BOX, macs, add=True)

    def box_undrop(self, macs: Iterable[str]) -> bool:
        return self._set_elems(_SET_BOX, macs, add=False)

    # -- T3: in path --
    def inpath_drop(self, macs: Iterable[str], mode: str) -> bool:
        from mitigation.containment import TARPIT_MODE
        return self._set_elems(_SET_INPATH_ALL if mode == TARPIT_MODE else _SET_INPATH_NET, macs, add=True)

    def inpath_undrop(self, macs: Iterable[str], mode: str) -> bool:
        from mitigation.containment import TARPIT_MODE
        return self._set_elems(_SET_INPATH_ALL if mode == TARPIT_MODE else _SET_INPATH_NET, macs, add=False)

    def teardown(self) -> bool:
        """Remove the whole table (e.g. on a clean shutdown). Safe when it was never created."""
        if not self.available():
            return False
        self._ensured = False
        return self._run(["delete", "table", "inet", TABLE])[0] == 0
