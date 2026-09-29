"""
hardware_capabilities.py - Shared hardware-capability-detection layer.

The product's tier ladder (Starter/Standard/Advanced -- see
PRODUCTIZATION_ROADMAP.md section 3) is one universal software image gated by
DETECTED hardware, not by SKU or license key. This module is the one shared
component behind every gate: capture-NIC presence for the bundled tap kit
(Phase 5), the Fritzbox reactive-capture wizard's own capture validation
(Phase 5), and RAM sizing for the optional local-LLM add-on (Phase 6).

Two rules this module exists to enforce everywhere it's used, per the
roadmap's own "Software architecture: one image, capability-gated" section:

1. VALIDATE, DON'T JUST CHECK PRESENCE. "A second NIC exists" proves nothing
   about whether a mirror switch is actually feeding it traffic -- the same
   gap the reactive-capture wizard closes by parsing an actual pcap instead
   of trusting a 200 response. Every check in this module either confirms
   real activity/capacity or says plainly that it couldn't.
2. BIDIRECTIONAL. Auto-enabling a feature when its hardware appears and
   gracefully degrading when it disappears (the capture-NIC-dies case) are
   the same mechanism running both ways. CapabilityRegistry persists each
   check's last result specifically so callers get an "appeared"/
   "disappeared" transition, not just a snapshot -- "customer hasn't bought
   the kit" and "the kit's NIC just failed" become one code path, not two.

Degrade-gracefully contract: every check function here returns a
CapabilityResult, never raises, on any platform -- including this project's
own Windows dev environment, which can validate nothing hardware-specific but
must not crash importing or running this module.
"""

import json
import logging
import socket
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Dict, List, Optional

LOGGER = logging.getLogger(__name__)

DEFAULT_STATE_PATH = Path("state/hardware_capabilities.json")

# Interfaces never worth treating as a mirror/capture candidate -- loopback
# and virtual/container plumbing, not physical NICs a tap kit could feed.
_EXCLUDED_INTERFACE_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "tun", "tap")

# A "8GB" Pi reports somewhat less than 8192MiB total once reserved memory is
# subtracted -- an exact >= 8.0 floor would false-negative on the exact
# hardware this check exists to detect.
_DEFAULT_LLM_RAM_FLOOR_GB = 7.0


@dataclass
class CapabilityResult:
    name: str
    present: bool
    validated: bool
    detail: str
    checked_at: float

    def to_dict(self) -> dict:
        return asdict(self)


def list_network_interfaces() -> List[str]:
    """Enumerates real network interfaces via /sys/class/net (Linux -- the
    only platform this appliance ships on). Returns [] on any platform
    without it (e.g. local Windows dev) rather than raising -- callers treat
    that identically to "no candidate interfaces found"."""
    net_dir = Path("/sys/class/net")
    if not net_dir.is_dir():
        return []
    try:
        return sorted(p.name for p in net_dir.iterdir())
    except OSError:
        return []


def candidate_capture_interfaces(exclude: Optional[List[str]] = None) -> List[str]:
    """Interfaces worth validating as a mirror/tap capture source: everything
    except loopback, virtual/container interfaces, and any explicitly
    excluded name (typically the box's own management/uplink interface)."""
    exclude_set = set(exclude or [])
    return [
        name for name in list_network_interfaces()
        if name not in exclude_set and not name.startswith(_EXCLUDED_INTERFACE_PREFIXES)
    ]


def validate_mirror_traffic(interface: str, sample_seconds: float = 5.0,
                             min_packets: int = 1) -> CapabilityResult:
    """The presence-vs-validated test for a capture NIC: opens a raw AF_PACKET
    socket on `interface` and confirms it actually receives frames within
    `sample_seconds`. An interface that merely exists (shows up in `ip link`,
    no cable pulled) says nothing about whether a mirror switch is really
    feeding it traffic.

    Linux-only (AF_PACKET doesn't exist elsewhere) and needs CAP_NET_RAW/root
    -- both cases degrade to a clear unvalidated result, never an exception.
    """
    now = time.time()
    if not hasattr(socket, "AF_PACKET"):
        return CapabilityResult(
            name=f"capture_nic:{interface}", present=True, validated=False,
            detail="AF_PACKET not available on this platform -- can only validate on Linux",
            checked_at=now,
        )
    eth_p_all = 0x0003
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(eth_p_all)) as s:
            s.bind((interface, 0))
            s.settimeout(sample_seconds)
            seen = 0
            deadline = time.time() + sample_seconds
            while time.time() < deadline and seen < min_packets:
                try:
                    s.recv(2048)
                    seen += 1
                except socket.timeout:
                    break
        if seen >= min_packets:
            return CapabilityResult(
                name=f"capture_nic:{interface}", present=True, validated=True,
                detail=f"received {seen} frame(s) in {sample_seconds}s",
                checked_at=now,
            )
        return CapabilityResult(
            name=f"capture_nic:{interface}", present=True, validated=False,
            detail=f"interface exists but no frames observed in {sample_seconds}s -- likely not mirrored",
            checked_at=now,
        )
    except PermissionError:
        return CapabilityResult(
            name=f"capture_nic:{interface}", present=True, validated=False,
            detail="permission denied opening raw socket -- needs CAP_NET_RAW/root to validate",
            checked_at=now,
        )
    except OSError as exc:
        return CapabilityResult(
            name=f"capture_nic:{interface}", present=False, validated=False,
            detail=f"interface unavailable: {exc}",
            checked_at=now,
        )


def detect_total_ram_gb() -> Optional[float]:
    """Reads real installed RAM in GiB from /proc/meminfo (Linux only).
    Returns None on unsupported platforms so callers can distinguish
    "checked, this box doesn't qualify" from "couldn't check at all"."""
    meminfo_path = Path("/proc/meminfo")
    if not meminfo_path.is_file():
        return None
    try:
        for line in meminfo_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                return round(kb / (1024 * 1024), 2)
    except (OSError, ValueError, IndexError):
        return None
    return None


def check_llm_eligible(min_gb: float = _DEFAULT_LLM_RAM_FLOOR_GB) -> CapabilityResult:
    """Local-LLM add-on sizing check (Phase 6): gigabyte-scale model weights
    (gemma3:1b/llama3.2:1b) only make sense once RAM detection confirms a
    Pi 5 8GB+ board -- never pre-load them onto hardware that could never
    run them."""
    now = time.time()
    total_gb = detect_total_ram_gb()
    if total_gb is None:
        return CapabilityResult(
            name="llm_ram", present=False, validated=False,
            detail="couldn't read total RAM on this platform",
            checked_at=now,
        )
    eligible = total_gb >= min_gb
    return CapabilityResult(
        name="llm_ram", present=eligible, validated=True,
        detail=f"{total_gb} GiB total RAM ({'meets' if eligible else 'below'} {min_gb} GiB floor)",
        checked_at=now,
    )


class CapabilityRegistry:
    """Runs named capability checks and persists each one's last result so
    callers can react to a transition (appeared / disappeared) instead of
    just a snapshot -- the one shared mechanism the reactive-capture wizard,
    tap-kit detection, and LLM sizing all need, built once instead of three
    times (see this module's docstring, rule 2).
    """

    def __init__(self, state_path: Path = DEFAULT_STATE_PATH):
        self.state_path = Path(state_path)
        self._checks: Dict[str, Callable[[], CapabilityResult]] = {}

    def register(self, name: str, check_fn: Callable[[], CapabilityResult]) -> None:
        self._checks[name] = check_fn

    def _load_previous(self) -> Dict[str, dict]:
        if not self.state_path.is_file():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, snapshot: Dict[str, dict]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.state_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        tmp_path.replace(self.state_path)

    def evaluate(self) -> Dict[str, dict]:
        """Runs every registered check once, diffs each result's `validated`
        flag against its last-persisted value, and returns
        {name: {...CapabilityResult fields..., "transition": "appeared"|"disappeared"|"unchanged"}}.
        Persists the new snapshot so the next call has something to diff against.
        """
        previous = self._load_previous()
        results: Dict[str, dict] = {}
        for name, check_fn in self._checks.items():
            try:
                result = check_fn()
            except Exception as exc:
                LOGGER.error("Capability check %r raised: %s", name, exc)
                result = CapabilityResult(
                    name=name, present=False, validated=False,
                    detail=f"check raised: {exc}", checked_at=time.time(),
                )
            was_validated = bool(previous.get(name, {}).get("validated"))
            is_validated = result.validated
            if is_validated and not was_validated:
                transition = "appeared"
            elif was_validated and not is_validated:
                transition = "disappeared"
            else:
                transition = "unchanged"
            entry = result.to_dict()
            entry["transition"] = transition
            results[name] = entry
            if transition in ("appeared", "disappeared"):
                LOGGER.info("Hardware capability %r %s (%s)", name, transition, result.detail)
        self._save(results)
        return results


def default_registry(management_interface: Optional[str] = None) -> CapabilityRegistry:
    """Convenience factory wiring up the two Phase-0-scoped checks (capture
    NICs + LLM RAM). Phase 5/6 add their own checks via `.register()` on top
    of this rather than rebuilding the registry."""
    registry = CapabilityRegistry()
    for interface in candidate_capture_interfaces(exclude=[management_interface] if management_interface else None):
        registry.register(f"capture_nic:{interface}", lambda i=interface: validate_mirror_traffic(i))
    registry.register("llm_ram", check_llm_eligible)
    return registry


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    results = default_registry().evaluate()
    if not results:
        print("No capability checks ran (no candidate interfaces found on this host).")
    for name, entry in results.items():
        status = "VALIDATED" if entry["validated"] else ("present" if entry["present"] else "absent")
        print(f"{name}: {status} [{entry['transition']}] -- {entry['detail']}")
