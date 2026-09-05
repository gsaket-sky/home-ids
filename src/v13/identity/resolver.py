"""
v13 identity resolver (Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).
Generalizes v-current's resolve_device_id() (core/identity.py) from one hardcoded
gateway_ip/gateway_mac special case to an arbitrary list of `trust_anchors`
(v13/config_v13.example.yaml's `network.trust_anchors`) -- an IDS product needs to
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
# read) -- kept here rather than imported, since v13 is meant to eventually stand
# alone from v-current, not share a live import dependency on it.
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
    """JUDGMENT CALL (not a confirmed line-for-line match of v-current -- the excerpt
    read this session didn't show this specific gate): treats any parseable IP as
    trackable except loopback/unspecified. Private-range RFC1918 addresses are the
    common case on a LAN, but a v13 deployment may reasonably see other private
    ranges too (ULA IPv6, etc.) -- this doesn't hard-restrict to IPv4 RFC1918 the
    way that might over-narrow a generalized product's actual deployments."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (parsed.is_loopback or parsed.is_unspecified)


def _anchor_device_id(anchor: TrustAnchor) -> str:
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
