"""
Device containment, read and keyed by DEVICE (CONTAINMENT_MODEL.md T1, 2026-10-12).

Containment is a state of a device: its tarpit entry is keyed "dev:<device id>" and carries every MAC the device is
known by now; router isolation stays keyed by MAC (the router acts on a MAC) and carries the device id. Readers decide
"is this device contained" here, by device id or by one of its MACs -- never by an address. An address changes hands
(DHCP reuse): with address matching, the next holder of a contained device's old address read as tarpitted, and
releasing by that address released or kept the wrong device's domain blocks.

Pure functions over the IPS state dict (state_guard's ips_state): no I/O, no IPSMitigator (whose constructor starts
threads), safe for the web UI and API processes.
"""
import ipaddress
import time
from typing import Any, Dict, Iterable, List, Optional

TARPIT_KEY_PREFIX = "dev:"

# Per-device enforcement state (T1), from what the box actually observes of the device's frames (IPSMitigator's
# observer) -- never inferred:
#   requested    registered; the first seconds after the engine starts acting
#   holding      the device's frames are seen going to the tarpit's fake address (it obeys)
#   not_reaching after the grace period the device's frames are seen going to the real gateway -- containment does
#                not reach it (e.g. a Wi-Fi client its access point answers for); reported and alerted
#   unconfirmed  the device is active (its frames are seen) but none of them go out of the network: no evidence yet
#                either way
#   offline      no frame from the device in the observation window
REQUESTED, HOLDING, NOT_REACHING, UNCONFIRMED, OFFLINE = "requested", "holding", "not_reaching", "unconfirmed", "offline"
STATUS_TEXT = {
    REQUESTED: "Starting",
    HOLDING: "Holding",
    NOT_REACHING: "Not reaching this device",
    UNCONFIRMED: "Active, no outgoing traffic seen yet",
    OFFLINE: "Not seen (offline or idle)",
}


def _arp_ipv4(v) -> bool:
    try:
        return not ipaddress.IPv4Address(str(v)).is_link_local
    except ValueError:
        return False


def _is_address(v) -> bool:
    try:
        ipaddress.ip_address(str(v).split("%", 1)[0])
        return True
    except ValueError:
        return False


def tarpit_key(dev_id: str) -> str:
    return f"{TARPIT_KEY_PREFIX}{dev_id}"


def _usable(v) -> bool:
    return bool(v) and str(v).lower() not in ("unknown", "none", "")


def norm_mac(mac) -> str:
    return str(mac or "").strip().lower()


def entry_macs(meta: Dict[str, Any]) -> List[str]:
    """Every MAC a tarpit/isolation entry acts on: "macs" (T1), else the single "mac" of older entries."""
    if not isinstance(meta, dict):
        return []
    out = [norm_mac(m) for m in (meta.get("macs") or []) if _usable(m)]
    one = norm_mac(meta.get("mac"))
    if _usable(one) and one not in out:
        out.append(one)
    return out


def normalize_tarpit_targets(targets: Dict[str, Any]) -> Dict[str, Any]:
    """Re-keys tarpit entries by device ("dev:<id>"), merging entries of one device (union of MACs, earliest start).
    Entries without a device id keep their key (nothing to key them by). Idempotent; returns a new dict."""
    out: Dict[str, Any] = {}
    for key, meta in (targets or {}).items():
        if not isinstance(meta, dict):
            continue
        dev_id = meta.get("dev_id")
        if not _usable(dev_id):
            out[key] = dict(meta)
            continue
        new_key = tarpit_key(dev_id)
        cur = out.get(new_key)
        merged = dict(meta) if cur is None else cur
        if cur is not None:
            for k, v in meta.items():
                merged.setdefault(k, v)
        macs = entry_macs(cur or {}) + [m for m in entry_macs(meta) if m not in entry_macs(cur or {})]
        merged["macs"] = macs
        merged["mac"] = macs[0] if macs else "unknown"
        # An older entry was keyed by the address it was registered under: kept as "registered_ip" (what
        # IPSMitigator.unisolate_all() matches, unchanged behaviour) and, when IPv4, as the ARP half's hint for the MAC it
        # was registered with -- never as an identity.
        if _is_address(key):
            merged.setdefault("registered_ip", key)
            if _arp_ipv4(key) and entry_macs(meta):
                merged.setdefault("arp_ips", {}).setdefault(entry_macs(meta)[0], key)
        hint = meta.get("arp_ip")
        if _arp_ipv4(hint) and entry_macs(meta):
            merged.setdefault("arp_ips", {}).setdefault(entry_macs(meta)[0], hint)
        merged.pop("arp_ip", None)
        if cur is not None and cur.get("since") and meta.get("since"):
            merged["since"] = min(cur["since"], meta["since"])
        out[new_key] = merged
    return out


def tarpitted(ips_state: Dict[str, Any], dev_id: str, macs: Iterable[str] = ()) -> Optional[Dict[str, Any]]:
    """The device's tarpit entry (by id, else by one of its MACs), or None."""
    targets = (ips_state or {}).get("tarpit_targets", {}) or {}
    if _usable(dev_id):
        hit = targets.get(tarpit_key(dev_id))
        if isinstance(hit, dict):
            return hit
        for meta in targets.values():
            if isinstance(meta, dict) and meta.get("dev_id") == dev_id:
                return meta
    wanted = {norm_mac(m) for m in macs if _usable(m)}
    if wanted:
        for meta in targets.values():
            if wanted & set(entry_macs(meta)):
                return meta
    return None


def router_isolated(ips_state: Dict[str, Any], dev_id: str, macs: Iterable[str] = ()) -> Optional[Dict[str, Any]]:
    """The device's router-isolation entry (keyed by MAC; by id, else by one of its MACs), or None."""
    isolated = (ips_state or {}).get("router_isolated_devices", {}) or {}
    wanted = {norm_mac(m) for m in macs if _usable(m)}
    for mac, meta in isolated.items():
        if not isinstance(meta, dict):
            continue
        if (_usable(dev_id) and meta.get("dev_id") == dev_id) or norm_mac(mac) in wanted:
            return meta
    legacy = {norm_mac(m) for m in ((ips_state or {}).get("isolated_macs") or [])}
    if wanted & legacy:
        return {"mac": next(iter(wanted & legacy))}
    return None


def blocked_domains_of(ips_state: Dict[str, Any], dev_id: str) -> List[str]:
    """Pi-hole domains blocked because of THIS device (by its id; an entry without an id belongs to no device)."""
    blocked = (ips_state or {}).get("blocked_domains", {}) or {}
    return sorted(d for d, m in blocked.items() if isinstance(m, dict) and _usable(dev_id) and m.get("device_id") == dev_id)


def containment_of(ips_state: Dict[str, Any], dev_id: str, macs: Iterable[str] = ()) -> Dict[str, Any]:
    """{"tarpitted", "router_isolated", "contained", "status", "status_text", "blocked_domain_count"} for one device."""
    macs = list(macs or ())
    tp = tarpitted(ips_state, dev_id, macs)
    ri = router_isolated(ips_state, dev_id, macs)
    status = (tp or {}).get("status") or (REQUESTED if tp else "")
    return {
        "tarpitted": tp is not None,
        "router_isolated": ri is not None,
        "contained": tp is not None or ri is not None,
        "status": status,
        "status_text": STATUS_TEXT.get(status, ""),
        "blocked_domain_count": len(blocked_domains_of(ips_state, dev_id)),
    }


def released_recently(ips_state_or_released: Dict[str, Any], dev_id: str, macs: Iterable[str] = (),
                      cooldown_seconds: float = 3600.0, now: Optional[float] = None) -> bool:
    """Whether an operator released this device within the cooldown -- by device id or one of its MACs, never by an
    address or a name (both are shared or reused)."""
    released = ips_state_or_released.get("operator_released_devices", ips_state_or_released) \
        if isinstance(ips_state_or_released, dict) else {}
    now = time.time() if now is None else now
    for key in [dev_id] + [norm_mac(m) for m in macs]:
        if _usable(key) and key in released:
            try:
                if now - float(released[key]) < cooldown_seconds:
                    return True
            except (TypeError, ValueError):
                continue
    return False
