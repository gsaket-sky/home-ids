"""
device_matching.py – Fingerprint-based device re-identification for MAC-rotation resilience.

Pure, dependency-free comparison functions used by StateManager to decide whether a
newly-observed device (new IP/MAC after a DHCP client-identifier rotation, e.g. iOS/Android
"private Wi-Fi address") is very likely the same physical device as a recently-active one
that just went quiet — so its history (baselines, alert state, killchain, confirmed-threat
counters) can be migrated forward via `StateManager.migrate_device_id()` instead of the
device cold-starting under a brand-new identity with zero history.

Deliberately conservative, on purpose:
- DHCP Option 55/60/77 fingerprints (vendor_class, param_list, user_class) are a
  *device-class* signal, not a unique-device signal. Two ESP32 units on the same firmware
  present an IDENTICAL fingerprint (confirmed on this network — see the audit). So a DHCP
  fingerprint match alone is capped well below the auto-merge bar; it only clears that bar
  once corroborated by a second, independent signal.
- The two corroborating signals are: JA4 TLS-fingerprint set overlap (a real behavioral
  signal — which apps/services a device's TLS stack actually talks to over time), and an
  exact match on a non-generic hostname (generic names like "iphone" prove nothing, since
  many distinct physical iPhones share it).
- Wrong merges are worse than missed merges: a wrong merge silently blends two different
  devices' security history. Until Phase 3 (closed-loop revocable actions) is wired up, a
  bad merge here has no one-tap undo — so the AUTO_MERGE_CONFIDENCE bar stays high by
  default and every candidate (even below the bar) is logged, so the operator can tune the
  threshold from real observed scores instead of guessing.
"""
from typing import Any, Dict, Optional, Set

# Below this, don't even log it as a candidate — pure noise.
MIN_CANDIDATE_CONFIDENCE = 0.45

# At/above this (with corroboration baked into the scoring itself), auto-merge fires.
AUTO_MERGE_CONFIDENCE = 0.75

# Minimum Jaccard overlap on JA4 hash sets to count as "corroborating" at all.
_JA4_CORROBORATION_FLOOR = 0.34

# Duplicated from core/identity.py's _GENERIC_HOSTNAMES on purpose: state_guard.py (which
# calls into this module) is imported BY identity.py, so importing identity.py from here
# would create a circular import. Keep this list in sync with identity.py's copy if edited.
_GENERIC_HOSTNAMES = frozenset({
    "android", "iphone", "ipad", "ipod", "macbook", "macbook-pro", "macbook-air",
    "imac", "apple-tv", "desktop", "laptop", "pc", "workstation", "unknown",
    "localhost", "galaxy", "samsung", "pixel", "amazon-device", "chromecast",
    "windows", "linux", "debian", "ubuntu", "raspberrypi", "router", "gateway",
    "switch", "ap", "access-point", "wlan", "wifi", "host", "device", "none"
})


def is_generic_hostname(hostname: str) -> bool:
    if not hostname or hostname == "unknown":
        return True
    return hostname.lower().strip() in _GENERIC_HOSTNAMES


def dhcp_fingerprint_match(fp_a: Optional[Dict[str, Any]], fp_b: Optional[Dict[str, Any]]) -> float:
    """1.0 if both DHCP fingerprints are present and identical on vendor_class, param_list,
    and user_class; 0.0 otherwise (including when either side is missing/empty). This is
    intentionally exact-match, not fuzzy — a "close" param_list order/content is not
    meaningfully different from an unrelated one for fingerprinting purposes."""
    if not fp_a or not fp_b:
        return 0.0

    vendor_a, vendor_b = fp_a.get("vendor_class") or "", fp_b.get("vendor_class") or ""
    params_a, params_b = list(fp_a.get("param_list") or []), list(fp_b.get("param_list") or [])
    user_a, user_b = fp_a.get("user_class") or "", fp_b.get("user_class") or ""

    if not params_a and not vendor_a and not user_a:
        return 0.0  # nothing usable to compare on this side

    if params_a != params_b or vendor_a != vendor_b or user_a != user_b:
        return 0.0
    return 1.0


def ja4_overlap(set_a: Set[str], set_b: Set[str]) -> float:
    """Jaccard similarity of two benign JA4-hash sets. Requires both sides to have at
    least one entry — an empty set is "no data", not "definitely different"."""
    if not set_a or not set_b:
        return 0.0
    inter = len(set_a & set_b)
    union = len(set_a | set_b)
    return inter / union if union else 0.0


def hostname_corroborates(host_a: str, host_b: str) -> bool:
    """True only if both hostnames are identical (case-insensitive) AND non-generic."""
    if not host_a or not host_b:
        return False
    if host_a.lower().strip() != host_b.lower().strip():
        return False
    return not is_generic_hostname(host_a)


def match_confidence(dhcp_score: float, ja4_sim: float, hostname_ok: bool) -> float:
    """Combine the three independent signals into one 0.0-1.0 confidence score.

    A DHCP fingerprint match alone tops out at 0.40 (below both thresholds) because it's a
    device-*class* signal on this network (identical across same-model ESP32s etc). It only
    climbs into merge territory once corroborated by decent JA4 overlap or a matching
    non-generic hostname. Strong JA4 overlap alone can also carry a match (useful for
    devices that don't send fresh DHCP traffic during the observation window).
    """
    if dhcp_score <= 0.0 and ja4_sim <= 0.0 and not hostname_ok:
        return 0.0

    corroborated = (ja4_sim >= _JA4_CORROBORATION_FLOOR) or hostname_ok

    if dhcp_score >= 1.0 and corroborated:
        base = 0.55 + (0.35 * min(1.0, ja4_sim)) + (0.10 if hostname_ok else 0.0)
        return min(1.0, base)
    if dhcp_score >= 1.0:
        # Device-class match only (e.g. "some ESP32 with stock firmware") — not enough alone.
        return 0.40
    if ja4_sim >= 0.5:
        base = 0.45 + (0.35 * ja4_sim) + (0.10 if hostname_ok else 0.0)
        return min(1.0, base)
    if hostname_ok:
        return 0.50
    return 0.0
