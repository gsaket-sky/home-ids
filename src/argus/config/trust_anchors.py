"""
v13 config loader: network.trust_anchors -> Dict[str, TrustAnchor], plus
hardware_profile validation (v13 full-architecture plan, Phase 2).

Bridges the YAML list shape `src/v13/config_v13.example.yaml` documents
(`network.trust_anchors: [{role, ip, mac}, ...]`) into the `Dict[str, TrustAnchor]`
keyed-by-role shape `src/v13/identity/resolver.py`'s `resolve_device_id()` already
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
    (matching config_v13.example.yaml's nesting). Returns an empty dict, not an
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
