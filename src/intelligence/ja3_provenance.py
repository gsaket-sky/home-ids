"""Where each known-bad JA3 hash came from, so an alert can say so.

A JA3 hash only identifies a TLS client stack. When an alert says "malicious TLS client fingerprint" the reader needs
to see which list claims it, and what that list says (an ET Open rule id, an abuse.ch listing), to judge whether it
is plausible -- the alert used to show neither (a stock-Windows-11 hash was reported as "matched a known-bad
signature directly", 2026-10-01). Loaders register their hashes here; the alert formatter only reads.
"""
import threading
from typing import Dict, Iterable, Mapping, Optional

_lock = threading.Lock()
_BY_SOURCE: Dict[str, Dict[str, str]] = {}
_ORDER = ("et_open", "sslbl", "builtin")   # first listed source wins when a hash is in several


def set_source(source: str, labels: Mapping[str, str]) -> None:
    """Replace everything registered for `source` (a feed refresh is a full replacement)."""
    with _lock:
        _BY_SOURCE[source] = {h.lower(): str(label) for h, label in labels.items()}


def describe(ja3_hash: Optional[str]) -> str:
    """Human-readable source of a hash, or '' when none is registered."""
    h = (ja3_hash or "").lower()
    if not h:
        return ""
    with _lock:
        for source in _ORDER:
            label = _BY_SOURCE.get(source, {}).get(h)
            if label:
                return label
    return ""


def clear() -> None:
    with _lock:
        _BY_SOURCE.clear()
