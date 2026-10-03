"""
argus config loader: network.trust_anchors -> Dict[str, TrustAnchor], plus
hardware_profile validation.

Bridges the YAML list shape config.yaml.example's `network:` block documents
(`network.trust_anchors: [{role, ip, mac}, ...]`) into the `Dict[str, TrustAnchor]`
keyed-by-role shape `src/argus/identity/resolver.py`'s `resolve_device_id()` already
expects. Confirmed 100% unbuilt before this file: nothing anywhere read
`trust_anchors`/`hardware_profile` from a real config into that shape.

Purely additive: reads NEW config keys, doesn't touch or replace `.94`'s existing
`gateway_ip`/`home_subnet` keys at all -- Phase 3 is what actually switches the live
identity-resolution call site over to use this. `hardware_profile` is validated here
but not yet consumed by any behavior (CL-AFPE pruning aggressiveness, LLM-review's
local-vs-remote default) -- those are later phases' concern; this just makes the
config value readable and validated in one place instead of each future consumer
re-parsing/re-validating it independently.
"""
import logging
from typing import Any, Dict, List, Optional

from argus.identity.resolver import TrustAnchor
from argus.identity.discovery import discover

LOGGER = logging.getLogger("v13_config_trust_anchors")

VALID_HARDWARE_PROFILES = frozenset({"pi_8gb", "x86_16gb", "custom"})
DEFAULT_HARDWARE_PROFILE = "x86_16gb"


def load_trust_anchors(raw_entries: Optional[List[Dict[str, Any]]]) -> Dict[str, TrustAnchor]:
    """Converts the network.trust_anchors list shape into the Dict[str, TrustAnchor]
    resolve_device_id() expects, keyed by role. A malformed entry (missing role,
    wrong type, non-string ip/mac) is skipped and logged, never raises -- one bad
    entry in a product config shouldn't crash identity resolution. A duplicate role
    keeps the FIRST occurrence and warns about the rest, rather than silently letting
    a later entry overwrite an earlier one with no record of the conflict."""
    result: Dict[str, TrustAnchor] = {}
    for i, entry in enumerate(raw_entries or []):
        try:
            if not isinstance(entry, dict):
                raise TypeError(f"entry is not a mapping: {entry!r}")
            role = entry.get("role")
            if not role or not isinstance(role, str):
                raise ValueError(f"no valid 'role' string: {entry!r}")
            if role in result:
                LOGGER.warning(
                    "Duplicate trust_anchor role %r at entry %d -- keeping the "
                    "first occurrence, ignoring this one.", role, i,
                )
                continue
            ip = entry.get("ip")
            mac = entry.get("mac")
            if ip is not None and not isinstance(ip, str):
                raise TypeError(f"role {role!r} has a non-string ip: {ip!r}")
            if mac is not None and not isinstance(mac, str):
                raise TypeError(f"role {role!r} has a non-string mac: {mac!r}")
            result[role] = TrustAnchor(role=role, ip=ip, mac=mac)
        except Exception as e:
            LOGGER.warning("Skipping malformed trust_anchor entry %d: %s", i, e)
            continue
    return result


def load_trust_anchors_from_config(config: Dict[str, Any]) -> Dict[str, TrustAnchor]:
    """Convenience wrapper reading directly off a flat config dict's 'network' key
    (matching config.yaml.example's top-level `network:` block). Returns an empty dict, not an
    error, when the key is absent entirely -- a deployment that hasn't opted into
    this yet behaves identically to one with zero configured anchors."""
    network_cfg = config.get("network") or {}
    if not isinstance(network_cfg, dict):
        LOGGER.warning(
            "config's 'network' key is not a mapping (got %s) -- ignoring, no "
            "trust anchors loaded.", type(network_cfg).__name__,
        )
        return {}
    return load_trust_anchors(network_cfg.get("trust_anchors"))


def bootstrap_trust_anchors(config: Dict[str, Any]) -> Dict[str, TrustAnchor]:
    """Zero-site bootstrap E (Phase 13, autonomy-completion effort, 2026-09-27):
    trust_anchors is now AUTHORITATIVE, auto-populated by
    argus.identity.discovery.discover(), replacing config.yaml's hand-maintained
    network.trust_anchors as the primary source. The hand-configured value (if
    any) is used only as (a) discover()'s own diff-logging baseline and (b) the
    gateway-continuity safety guard's comparison baseline below -- never itself
    returned unmodified once a discovery run has actually succeeded.

    THE SAFETY GUARD (the one built-in mechanism the zero-site bootstrap plan
    calls for -- a code-level guard that does the real safety work, not a human
    approval gate or a staged rollout): the discovered gateway anchor's IP must
    be VERIFIED EQUAL to the current/last-known-good gateway IP (network.
    trust_anchors's own configured gateway entry if present, else the legacy
    gateway_ip key, else "no prior value -- first-ever adoption, nothing to
    conflict with") before being adopted. On a mismatch, this warns LOUDLY and
    refuses to auto-adopt the newly discovered gateway, keeping the last-known-
    good one instead -- turning "this network's gateway IP silently changed"
    into a loud logged event an operator will see, instead of a silent identity
    reset for every device this system tracks (every device's OWN identity
    resolution can depend on the gateway anchor's stability, per resolver.py's
    own continuity-safety fix, Phase 11).

    this_host has no continuity risk of this kind (it's never used as a merge
    anchor for OTHER devices, only to mark this one host as infrastructure) and
    is always adopted fresh from discovery. Any OTHER hand-configured role
    (e.g. a manually-added household anchor discover() has no way to find, like
    a NAS) is preserved untouched -- this function only ever touches the
    'gateway'/'this_host' roles discover() actually produces.

    Never raises: a discover() failure of any kind degrades to the existing
    hand-configured trust_anchors unchanged -- the exact same behavior as
    before this function existed."""
    hand_configured_raw = (config.get("network") or {}).get("trust_anchors") or []
    hand_configured = load_trust_anchors(hand_configured_raw)

    try:
        discovered_raw = discover(previous_trust_anchors=hand_configured_raw)
    except Exception:
        LOGGER.exception(
            "[BOOTSTRAP] discover() failed -- falling back to the hand-configured "
            "trust_anchors unchanged, exactly as if this phase didn't exist."
        )
        return hand_configured

    discovered = load_trust_anchors(discovered_raw)

    last_known_good_gateway_ip: Optional[str] = None
    if "gateway" in hand_configured and hand_configured["gateway"].ip:
        last_known_good_gateway_ip = hand_configured["gateway"].ip
    elif config.get("gateway_ip"):
        last_known_good_gateway_ip = config.get("gateway_ip")

    result: Dict[str, TrustAnchor] = dict(hand_configured)

    discovered_gateway = discovered.get("gateway")
    if discovered_gateway is not None:
        if last_known_good_gateway_ip and discovered_gateway.ip != last_known_good_gateway_ip:
            LOGGER.warning(
                "[BOOTSTRAP] discovered gateway ip %r does NOT match the last-known-good "
                "gateway %r -- REFUSING to auto-adopt it. Keeping the last-known-good "
                "gateway anchor. If this network's gateway genuinely changed, update "
                "network.trust_anchors (or the legacy gateway_ip key) by hand to accept it.",
                discovered_gateway.ip, last_known_good_gateway_ip,
            )
            if "gateway" not in result and last_known_good_gateway_ip:
                # Legacy gateway_ip was the only prior source (network.trust_anchors was
                # never configured at all) -- preserve continuity with it directly rather
                # than silently dropping gateway anchoring altogether.
                result["gateway"] = TrustAnchor(role="gateway", ip=last_known_good_gateway_ip)
        else:
            result["gateway"] = discovered_gateway

    this_host_discovered = discovered.get("this_host")
    if this_host_discovered is not None:
        result["this_host"] = this_host_discovered

    return result


def load_hardware_profile(config: Dict[str, Any]) -> str:
    """Returns a validated hardware_profile string, defaulting to
    DEFAULT_HARDWARE_PROFILE when the key is absent OR set to something not in
    VALID_HARDWARE_PROFILES -- fails safe to the known-working default rather than
    handing an unvalidated string to whatever future phase consumes this."""
    raw = config.get("hardware_profile")
    if raw in VALID_HARDWARE_PROFILES:
        return raw
    if raw is not None:
        LOGGER.warning(
            "Unrecognized hardware_profile %r (valid: %s) -- falling back to %r.",
            raw, sorted(VALID_HARDWARE_PROFILES), DEFAULT_HARDWARE_PROFILE,
        )
    return DEFAULT_HARDWARE_PROFILE
