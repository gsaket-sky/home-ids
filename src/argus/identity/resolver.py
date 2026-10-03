"""
Identity resolver.
Generalizes core/identity.py's resolve_device_id() from one hardcoded
gateway_ip/gateway_mac special case to an arbitrary list of `trust_anchors`
(config.yaml.example's `network.trust_anchors`) -- an IDS product needs to
recognize "this is a well-known infrastructure device" for however many such
devices a given deployment has (gateway, NAS, a second AP, ...), not just one.

Priority chain matches core/identity.py's own (confirmed via direct read this
session, not guessed), generalized over anchors:
  1. client_ip exactly matches a trust_anchor -> fixed canonical id for that anchor
  2. client MAC matches a trust_anchor's LEARNED mac on a different ip (the
     anchor's other interface, e.g. a router's WLAN vs LAN MAC) -> same anchor id
  3. client MAC found in an existing mac->device_id binding -> that device_id
  4. private/trackable IP -> stable_device_id(ip)
  5. non-generic hostname -> stable_device_id(f"host:{hostname}")
  6. MAC fallback -> stable_device_id(mac)
  7. raw IP fallback -> stable_device_id(ip)

Deliberately pure/stateless (no hidden mutable state) -- learned_anchor_macs and
mac_bindings are passed in and read-only here; the CALLER (Phase 3+ wiring) owns
updating them, e.g. via GraphStore, matching this module's own testability goal.
"""
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, Optional

# Matches core/identity.py's own _GENERIC_HOSTNAMES exactly (confirmed via direct
# read) -- kept here rather than imported, since argus is meant to eventually stand
# alone from core/identity.py, not share a live import dependency on it.
_GENERIC_HOSTNAMES = frozenset({
    "android", "iphone", "ipad", "ipod", "macbook", "macbook-pro", "macbook-air",
    "imac", "apple-tv", "desktop", "laptop", "pc", "workstation", "unknown",
    "localhost", "galaxy", "samsung", "pixel", "amazon-device", "chromecast",
    "windows", "linux", "debian", "ubuntu", "raspberrypi", "router", "gateway",
    "switch", "ap", "access-point", "wlan", "wifi", "host", "device", "none",
})


@dataclass(frozen=True)
class TrustAnchor:
    role: str                     # e.g. "gateway", "nas", "this_host" -- config-driven, not hardcoded
    ip: Optional[str] = None
    mac: Optional[str] = None     # the anchor's OWN primary-interface MAC, if known


def stable_device_id(raw_client: str) -> str:
    """Matches core/identity.py's stable_device_id() exactly."""
    if not raw_client:
        return "000000000000"
    cleaned = str(raw_client).strip().lower()
    return hashlib.sha256(cleaned.encode("utf-8", errors="ignore")).hexdigest()[:12]


def is_locally_administered_mac(mac: Optional[str]) -> bool:
    """real MAC-randomization detection --
    confirmed via direct investigation that NO such check existed anywhere in this
    codebase before this function (the only prior "signal" was OUI-lookup failure in
    utils.get_mac_vendor(), an indirect side effect, not a deliberate flag). The
    locally-administered bit is the second-least-significant bit of a MAC's first
    octet (IEEE 802-2014 sec 8.2.2) -- set on every privacy-randomized MAC modern
    iOS/Android devices generate per-network or per-session, and essentially never
    set on a real burned-in vendor MAC. A True result means "this MAC is expected to
    change again later" -- anchoring a device_id to it via the raw-MAC-fallback
    branch (resolve_device_id()'s own last resort) is actively counterproductive for
    such a MAC, unlike for the vast majority of real, stable vendor MACs."""
    if not mac or mac == "unknown":
        return False
    try:
        first_octet_str = mac.split(":")[0].split("-")[0]
        first_octet = int(first_octet_str, 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0x02)


def is_generic_hostname(hostname: Optional[str]) -> bool:
    """Matches core/identity.py's _is_generic_hostname() exactly."""
    if not hostname or hostname == "unknown":
        return True
    clean = hostname.lower().strip()
    if clean in _GENERIC_HOSTNAMES:
        return True
    if re.match(r"^\d+$", clean):
        return True
    return False


def _is_trackable_ip(ip: str) -> bool:
    """JUDGMENT CALL (not a confirmed line-for-line match of core/identity.py -- the excerpt
    read this session didn't show this specific gate): treats any parseable IP as
    trackable except loopback/unspecified. Private-range RFC1918 addresses are the
    common case on a LAN, but a argus deployment may reasonably see other private
    ranges too (ULA IPv6, etc.) -- this doesn't hard-restrict to IPv4 RFC1918 the
    way that might over-narrow a generalized product's actual deployments."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (parsed.is_loopback or parsed.is_unspecified)


def _anchor_device_id(anchor: TrustAnchor) -> str:
    """Continuity-safe by construction (2026-09-27, Phase 11 of the autonomy-
    completion effort). An anchor WITH a configured ip resolves via
    stable_device_id(anchor.ip) directly -- the same formula pre-argus code always
    used for its one anchor (gateway_ip) -- so a newly-configured trust anchor
    resolves to the SAME device_id its history already lives under, not a fresh
    role-based hash that would silently reset it. A role-only anchor (no ip
    configured, a real but rare case) has no continuity to preserve, so it falls
    back to the role-based hash -- there's nothing to be compatible WITH in that
    case.

    BUGFIX: this function previously used the role-based hash unconditionally,
    even when anchor.ip was set. argus/identity/live_manager.py's
    LiveIdentityManager already found this breaks gateway continuity in
    production and worked around it at its own call site (never delegating
    trust_anchors into resolve_device_id() below at all, and inlining
    v13_stable_device_id(anchor.ip) itself) -- but this pure function itself
    was still broken for any OTHER caller. Confirmed via grep at fix time:
    LiveIdentityManager is resolver.py's only real caller, and its own
    resolve_device_id() never passes trust_anchors through to the delegate
    call below, so branches 1/2 of resolve_device_id() (which are the only
    callers of this function) are dead code in production today -- this fix
    has zero live behavior change, it closes the landmine for any future
    caller (e.g. Phase 10's discovery diff logic, if it ever calls this
    directly) before one exists."""
    if anchor.ip:
        return stable_device_id(anchor.ip)
    return stable_device_id(f"anchor:{anchor.role}")


def resolve_device_id(
    client_ip: str,
    trust_anchors: Optional[Dict[str, TrustAnchor]] = None,   # keyed by role
    client_mac: Optional[str] = None,
    hostname: Optional[str] = None,
    learned_anchor_macs: Optional[Dict[str, str]] = None,      # role -> learned mac
    mac_bindings: Optional[Dict[str, str]] = None,              # mac -> existing device_id
) -> str:
    trust_anchors = trust_anchors or {}
    learned_anchor_macs = learned_anchor_macs or {}
    mac_bindings = mac_bindings or {}

    # 1. exact IP match on a configured trust anchor
    for anchor in trust_anchors.values():
        if anchor.ip and anchor.ip == client_ip:
            return _anchor_device_id(anchor)

    # 2. MAC matches a trust anchor's LEARNED mac, seen on a different IP (that
    #    anchor's other interface -- e.g. a router's WLAN address presenting the
    #    same MAC family learned at its LAN address).
    if client_mac and client_mac != "unknown":
        for role, anchor in trust_anchors.items():
            learned = learned_anchor_macs.get(role) or anchor.mac
            if learned and learned == client_mac:
                return _anchor_device_id(anchor)

    # 3. MAC-first anchor via an existing binding
    if client_mac and client_mac != "unknown" and client_mac in mac_bindings:
        return mac_bindings[client_mac]

    # 4. private/trackable IP anchor
    if _is_trackable_ip(client_ip):
        return stable_device_id(client_ip)

    # 5. non-generic hostname anchor
    if hostname and not is_generic_hostname(hostname):
        return stable_device_id(f"host:{hostname.lower()}")

    # 6. MAC fallback
    if client_mac and client_mac != "unknown":
        return stable_device_id(client_mac)

    # 7. raw IP fallback (reached only for a non-trackable, e.g. loopback/unspecified, IP)
    return stable_device_id(client_ip)
