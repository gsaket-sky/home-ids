"""
VERSION 10 (incident aggregation): canonical "same ongoing incident" identity, shared
between pipeline.py's real-time Telegram-volume gate (IncidentTracker, incident_tracker.py)
and ollama_soc.py's offline batch grouping. Previously this key concept existed only
inside ollama_soc.py (as `_cache_key`/`_target_for_key`), duplicated nowhere else --
this module is the single source of truth both call sites now import, so "same incident"
means the same thing whether it's being decided in real time or reconstructed after the
fact from alerts.json.
"""
from typing import Optional


def target_for_key(destination_ip: Optional[str], queried_domain: Optional[str]) -> str:
    """Best available identifier for 'what was this alert about' -- prefers the
    resolved domain, falls back to the raw destination IP for connections with no DNS
    resolution (e.g. the 149.154.166.110/Telegram case), matching the same fallback
    pipeline.py's own alert-message target_display logic already uses."""
    domain = (queried_domain or "").strip()
    if domain and domain != "unknown":
        return domain
    dest_ip = (destination_ip or "").strip()
    return dest_ip or "unknown"


def signature_base(signature: str) -> str:
    """Strips the cross-cycle persistence-escalation suffix (' (persisted Ns)', see
    pipeline.py's primary_sig_base) so an incident that escalates mid-episode still
    keys to the SAME incident, not a new one every time the persisted-seconds count
    grows. Kept as a small independent duplication of pipeline.py's identical inline
    split (rather than a shared import) since pipeline.py's copy is already tested and
    source-guarded by existing tests against its exact inline form -- not worth the risk
    of touching stable, verified code to de-duplicate one line."""
    return (signature or "unknown").split(" (persisted ", 1)[0]


def incident_key(device_id: str, destination_ip: Optional[str], queried_domain: Optional[str], signature: str) -> str:
    """Canonical 'same ongoing incident' identity: same device, same target, same
    underlying signature (persistence-suffix stripped). Deliberately coarser than a
    per-event key (e.g. it ignores the exact timestamp) -- the whole point is that
    repeat firings of the identical pattern collapse to one key."""
    dev = device_id or "unknown"
    return f"{dev}|{target_for_key(destination_ip, queried_domain)}|{signature_base(signature)}"
