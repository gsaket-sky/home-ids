"""
v13 rolling-window-as-query (Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).
Replaces core/state.py's RollingWindow (deques + Counters kept in memory per
device, never persisted -- state.py:110-127,165-173 confirms this is intentional
in v-current, lost on every restart) with plain time-bounded SQL queries against
GraphStore's evidence table. "Recent window" becomes a query parameter, not a
separate struct that has to be kept in sync with the evidence store by hand.

This also directly answers one of HEE_ROADMAP.md item 4's own cited benefits for
a graph-backed store: "has this device seen this destination before via a
different evidence family" becomes a real query (domain_seen_before) instead of
needing a bespoke mechanism the way _is_campaign_corroborated()/
get_baseline_familiarity() are today.
"""
import time
from collections import Counter
from typing import Dict, List, Optional

from argus.graph.store import GraphStore
from argus.evidence.model import Evidence, NO_DESTINATION


class RollingWindowView:
    """A thin, stateless view over GraphStore -- every method re-queries fresh each
    call. Matches core/state.py's own two window sizes (events ~5min, long_events
    ~1hr) as named presets, but any window length is really just a `since=` value."""

    SHORT_WINDOW_SECONDS = 300     # matches RollingWindow.events' documented ~5-min window
    LONG_WINDOW_SECONDS = 3600     # matches RollingWindow.long_events' documented ~1-hour window

    def __init__(self, store: GraphStore):
        self.store = store

    def evidence_in_window(self, device_id: str, window_seconds: float,
                             now: Optional[float] = None) -> List[Evidence]:
        now = now if now is not None else time.time()
        return self.store.get_evidence_for_device(device_id, since=now - window_seconds)

    def domain_counts(self, device_id: str, window_seconds: float = LONG_WINDOW_SECONDS,
                        now: Optional[float] = None) -> Counter:
        """Replaces RollingWindow.domains (an in-memory Counter, unbounded until
        Phase 64's reset-on-suppress fix, state.py:110-127) with a query -- there is
        nothing to reset or leak, since nothing accumulates in memory between calls."""
        evidence = self.evidence_in_window(device_id, window_seconds, now=now)
        counts = Counter(
            ev.destination_id for ev in evidence if ev.destination_id != NO_DESTINATION
        )
        return counts

    def domain_seen_before(self, device_id: str, destination_id: str,
                             lookback_seconds: float, now: Optional[float] = None,
                             exclude_window_seconds: float = 0.0) -> bool:
        """Answers "has this device contacted this destination before, outside the
        current incident window" -- the cross-cycle question HEE_ROADMAP.md item 4
        named as a real benefit of a graph-backed store, not achievable as a plain
        query against v-current's in-memory-only RollingWindow.

        exclude_window_seconds lets a caller ask "seen before the CURRENT alert's
        own window" by excluding the most recent slice -- e.g. lookback_seconds=90days,
        exclude_window_seconds=SHORT_WINDOW_SECONDS asks "was this destination
        familiar before this specific incident started," not just "ever.\""""
        now = now if now is not None else time.time()
        evidence = self.store.get_evidence_for_device(device_id, since=now - lookback_seconds)
        cutoff = now - exclude_window_seconds
        return any(
            ev.destination_id == destination_id and ev.timestamp < cutoff
            for ev in evidence
        )

    def evidence_type_counts(self, device_id: str, window_seconds: float = LONG_WINDOW_SECONDS,
                               now: Optional[float] = None) -> Dict[str, int]:
        evidence = self.evidence_in_window(device_id, window_seconds, now=now)
        return dict(Counter(ev.evidence_type for ev in evidence))

    def devices_targeting(self, destination_id: str, window_seconds: float,
                            now: Optional[float] = None,
                            exclude_device_id: Optional[str] = None) -> List[str]:
        """Answers "which OTHER devices have touched this destination in the last
        N seconds" -- v13 full-architecture plan, Phase 1a: cross-device
        correlation / coordinated-campaign detection, a real capability v-current's
        per-device, in-memory-only RollingWindow structurally cannot answer (it has
        no view across devices at all). exclude_device_id is typically the calling
        device itself, since the point of this query is "who ELSE is touching this
        destination right now," not a self-count."""
        now = now if now is not None else time.time()
        devices = self.store.get_devices_targeting(destination_id, since=now - window_seconds)
        if exclude_device_id:
            devices = [d for d in devices if d != exclude_device_id]
        return devices

    def devices_sharing_fingerprint(self, evidence_type: str, provenance: str, window_seconds: float,
                                       now: Optional[float] = None,
                                       exclude_device_id: Optional[str] = None) -> List[str]:
        """Release 14, N4: the fingerprint-correlation analogue of
        devices_targeting() above -- "which OTHER devices have evidence of this
        exact type carrying this exact provenance (e.g. the same JA3/JA4 hash) in
        the last N seconds." Thin wrapper, same shape as devices_targeting(), for
        the same reason: keep GraphStore a plain CRUD layer, relation-specific
        semantics live here."""
        now = now if now is not None else time.time()
        devices = self.store.get_devices_sharing_provenance(evidence_type, provenance, since=now - window_seconds)
        if exclude_device_id:
            devices = [d for d in devices if d != exclude_device_id]
        return devices
