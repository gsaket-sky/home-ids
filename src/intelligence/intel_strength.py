"""
How much one threat-intel match may count for. Shared by the live engine, the nightly retro-hunt and the
learning-period sweep, so the three never disagree.

Strong vs weak: ThreatIntel turns a match's confidence into risk as confidence * 4.0, and the false-positive engine
hard-stops at risk >= 2.0, so a single match at confidence >= 0.5 can confirm a threat on its own. Everything below is
context by design (local_ioc_index.py: Tor relays 0.25, the CINS "poor reputation" list 0.35, Spamhaus DROP 0.45,
ET misc/adware domains 0.40): weak corroboration that needs a second independent evidence family. Found on .94
(2026-10-05): the learning-period sweep reported all such weak matches as findings ("now classified malicious") and
gave each destination network-wide tier-5 reputation -- 15 first-sweep findings (9 NTP-pool servers on the Tor list,
6 ordinary app domains on ET misc lists) and 33 tier-5 destinations, among them api.telegram.org and
cloudflare-dns.com. A weak match is now never a retro finding and never propagates.

Tor listings: Tor relays speak TCP only. A Tor-list entry says nothing about a UDP contact with the same address --
NTP-pool volunteers often run a Tor relay on the same server, so a device syncing its clock (UDP 123) touched a "Tor
node" -- and nothing about an address a device only resolved (WiFi devices are invisible to the wired sensor, so their
destination address often comes from the DNS answer, not an observed connection).
"""
from typing import Any, Optional

STRONG_MATCH_CONFIDENCE = 0.5

_TOR_TAGS = frozenset({"et_tor", "tor", "tor_exit", "tor_relay"})


def match_confidence(match: Any) -> float:
    if not isinstance(match, dict):
        return 0.0
    try:
        return float(match.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def is_strong_match(match: Any) -> bool:
    """True when this one match could confirm a threat on its own."""
    return match_confidence(match) >= STRONG_MATCH_CONFIDENCE


def is_tor_listing(match: Any) -> bool:
    if not isinstance(match, dict):
        return False
    return any(str(t).lower() in _TOR_TAGS for t in (match.get("tags") or []))


def tor_listing_applies(match: Any, observed_on_wire: bool, protocol: Optional[str]) -> bool:
    """False for a Tor-list match that cannot mean Tor use: the contact was not seen on the wire, or was not TCP.
    Any other match always applies."""
    if not is_tor_listing(match):
        return True
    return bool(observed_on_wire) and str(protocol or "").upper() == "TCP"
