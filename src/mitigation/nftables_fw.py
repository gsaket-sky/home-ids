"""
nftables firewall for containment (CONTAINMENT_MODEL.md sections 4 + 6, T2 box-drop + T3 in-path, 2026-10-13).

Two uses, both "drop this device's frames by MAC", in the family that actually sees those frames:

  - **box drop** (T2, owner decision 1 = yes): a Tarpitted device must not reach the box itself (Pi-hole DNS, web UI).
    Frames addressed to the box go up its `input` hook, so this is an `inet` table with a rule in `input` dropping
    frames whose Ethernet source is the device.
  - **in path** (T3): when the box forwards the device's frames (Pi as Wi-Fi AP / transparent bridge / wired bridge),
    the frames cross the bridge with their original MACs intact in BOTH directions. The `bridge` family's `forward`
    hook sees exactly those, so this is a `bridge` table: a Tarpit drops the device's frames as source AND as
    destination (cut both ways); Block internet drops only the device's frames egressing the uplink port. The bridge
    family needs no `br_netfilter`, which is why the netns CI test can prove it with a plain bridge.

Each family lives in its own dedicated table (`homeids_containment` / `homeids_containment_br`) so it never touches the
operator's own firewall and is removed cleanly. Per-device state is held in nftables SETS of MAC addresses (one static
rule per set), so containing/releasing a device is a single add/delete-element -- no rule-handle bookkeeping.
Network-agnostic (no address/vendor assumptions); when `nft` is absent (not Linux, or iptables-only) every call is a
logged no-op, so the same-segment ARP/NDP method still works on its own. The command runner is injected so the emitted
rules are unit-testable without root or a kernel.
"""
import logging
import shutil
import subprocess
from typing import Callable, Iterable, List, Optional, Tuple

LOGGER = logging.getLogger("home_ids.nftables_fw")

TABLE = "homeids_containment"          # inet: box-drop (input hook)
BR_TABLE = "homeids_containment_br"    # bridge: in-path (forward hook)
_SET_BOX = "box_blocked"               # Tarpit: drop the device's frames to the box (inet input)
_SET_INPATH_ALL = "inpath_blocked"     # Tarpit in-path: drop both directions (bridge forward)
_SET_INPATH_NET = "inpath_internet"    # Block internet in-path: drop frames egressing the uplink (bridge forward)


def _default_run(args: List[str]) -> Tuple[int, str]:
    try:
        # `nft -f -` reads the ruleset from stdin; _run_script passes it as args[2], so feed it on stdin here (not as
        # an argv filename). Any other form is passed straight through.
        if len(args) == 3 and args[0] == "-f" and args[1] == "-":
            p = subprocess.run(["nft", "-f", "-"], input=args[2], capture_output=True, text=True, timeout=5)
        else:
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
        self._ensured_inet = False
        self._ensured_br = False

    def available(self) -> bool:
        if self._run is _default_run and shutil.which("nft") is None:
            return False
        rc, _ = self._run(["--version"])
        return rc == 0

    # -- table setup (idempotent; the per-device sets survive, so this never duplicates rules) --
    def _ensure_inet(self) -> bool:
        if self._ensured_inet:
            return True
        if not self.available():
            return False
        if self._run(["list", "table", "inet", TABLE])[0] == 0:
            self._ensured_inet = True
            return True
        script = [
            f"add table inet {TABLE}",
            f"add set inet {TABLE} {_SET_BOX} {{ type ether_addr; }}",
            f"add chain inet {TABLE} input {{ type filter hook input priority -150; policy accept; }}",
            f"add rule inet {TABLE} input ether saddr @{_SET_BOX} drop",
        ]
        rc, out = self._run_script(script)
        if rc != 0:
            LOGGER.warning("nft inet containment table setup failed (box-drop off; same-segment unaffected): %s", out)
            return False
        self._ensured_inet = True
        return True

    def _ensure_bridge(self) -> bool:
        if self._ensured_br:
            return True
        if not self.available():
            return False
        if self._run(["list", "table", "bridge", BR_TABLE])[0] == 0:
            self._ensured_br = True
            return True
        net = (f"ether saddr @{_SET_INPATH_NET} oifname \"{self.uplink}\" drop") if self.uplink else None
        script = [
            f"add table bridge {BR_TABLE}",
            f"add set bridge {BR_TABLE} {_SET_INPATH_ALL} {{ type ether_addr; }}",
            f"add set bridge {BR_TABLE} {_SET_INPATH_NET} {{ type ether_addr; }}",
            f"add chain bridge {BR_TABLE} forward {{ type filter hook forward priority -150; policy accept; }}",
            # Tarpit: the device cut both ways -- as source and as destination of a forwarded frame.
            f"add rule bridge {BR_TABLE} forward ether saddr @{_SET_INPATH_ALL} drop",
            f"add rule bridge {BR_TABLE} forward ether daddr @{_SET_INPATH_ALL} drop",
        ]
        if net:
            # Block internet: only the device's frames leaving by the uplink port (LAN forwarding stays).
            script.append(f"add rule bridge {BR_TABLE} forward {net}")
        rc, out = self._run_script(script)
        if rc != 0:
            LOGGER.warning("nft bridge containment table setup failed (in-path off; same-segment unaffected): %s", out)
            return False
        self._ensured_br = True
        return True

    def ensure(self) -> bool:
        """Create both tables (used at start / by tests). True when both are present afterwards."""
        return self._ensure_inet() & self._ensure_bridge()

    def _run_script(self, lines: List[str]) -> Tuple[int, str]:
        # one atomic `nft -f` so a partial failure leaves nothing behind
        return self._run(["-f", "-", "\n".join(lines) + "\n"])

    def _set_elems(self, family: str, table: str, set_name: str, macs: Iterable[str], add: bool) -> bool:
        wanted = sorted({_norm(m) for m in macs if _norm(m) and len(_norm(m).split(":")) == 6})
        if not wanted:
            return False
        ensured = self._ensure_inet() if family == "inet" else self._ensure_bridge()
        if not ensured:
            return False
        verb = "add" if add else "delete"
        lines = [f"{verb} element {family} {table} {set_name} {{ {m} }}" for m in wanted]
        rc, out = self._run_script(lines)
        if rc != 0 and add:          # a delete of an absent element is a harmless miss
            LOGGER.warning("nft %s element %s failed: %s", verb, set_name, out)
        return rc == 0

    # -- T2: the box itself (inet input) --
    def box_drop(self, macs: Iterable[str]) -> bool:
        return self._set_elems("inet", TABLE, _SET_BOX, macs, add=True)

    def box_undrop(self, macs: Iterable[str]) -> bool:
        return self._set_elems("inet", TABLE, _SET_BOX, macs, add=False)

    # -- T3: in path (bridge forward) --
    def inpath_drop(self, macs: Iterable[str], mode: str) -> bool:
        from mitigation.containment import TARPIT_MODE
        s = _SET_INPATH_ALL if mode == TARPIT_MODE else _SET_INPATH_NET
        return self._set_elems("bridge", BR_TABLE, s, macs, add=True)

    def inpath_undrop(self, macs: Iterable[str], mode: str) -> bool:
        from mitigation.containment import TARPIT_MODE
        s = _SET_INPATH_ALL if mode == TARPIT_MODE else _SET_INPATH_NET
        return self._set_elems("bridge", BR_TABLE, s, macs, add=False)

    def teardown(self) -> bool:
        """Remove both tables (e.g. on a clean shutdown). Safe when they were never created."""
        if not self.available():
            return False
        self._ensured_inet = self._ensured_br = False
        rc1 = self._run(["delete", "table", "inet", TABLE])[0]
        rc2 = self._run(["delete", "table", "bridge", BR_TABLE])[0]
        return rc1 == 0 and rc2 == 0
