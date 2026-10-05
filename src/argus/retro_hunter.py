"""
Retro-hunter.

Faithful port of scripts/retro_hunter.py's CORE loop (451 lines, read in full
before writing anything): re-scan historical destinations against freshly-updated
threat intel to catch zero-day compromises that were invisible at the time the
traffic occurred. Two deliberate structural differences, both scope-consistent
with Phases 4/5's own honest cuts, not accidents:

1. THREAT-INTEL LOOKUP IS AN INJECTED DEPENDENCY, not a reimplementation of
   intelligence/threat_intel.py's ThreatIntel class (URLHaus/FeodoTracker/
   ThreatFox/OTX feed integration -- its own substantial, unresearched subsystem).
   Callers pass a `lookup: Callable[[str], Optional[dict]]` -- the live
   ThreatIntel.lookup_domain() has exactly this shape (domain -> {confidence,
   tags, source} or None), so wiring the real one in later is a one-line change,
   not a redesign.

2. A FINDING BECOMES A NEW GRAPH EVIDENCE ITEM, not a side-channel
   CL-AFPE record_confirmed_threat()+_apply_sigma_shift() call (the CL-AFPE
   deliberately doesn't have either -- Phase 4's own scope cut). A retroactively-
   confirmed malicious destination is written back as a real `reputation`
   Evidence item for the device that touched it, timestamped now with
   provenance="retro_hunter" -- the NEXT evaluation cycle for that device picks
   it up through the exact same HypothesisEngine/DecisionEngine path any other
   reputation evidence goes through, rather than a separate mechanism.

NOT PORTED HERE (a deliberate module-boundary choice, not a scope cut): Telegram
notification and GeoIP-enriched reporting stay OUT of this module -- an
orchestration concern, kept out for testability. Callers (argus/ops/live_retro_hunter.py)
get the finding/match lists back and decide how to notify, the same "hand data
back, let the caller act" shape CL-AFPE's MarkFalsePositiveResult already uses.
See that ops module for Phase 7's Telegram/GeoIP wiring.

3. NETWORK-WIDE REPUTATION PROPAGATION (the graph-engine migration, Phase 1a,
   added after this module's initial Phase 6 build): every confirmed destination
   also gets `store.set_destination_reputation(dest, tier=5, ...)` called once,
   writing onto the shared `destinations` row so ANY other device touching that
   destination inherits the verdict immediately (live_engine.py's own
   get_destination_reputation() read), not just the specific device(s) this hunt
   happened to already know about. A genuinely different mechanism from #2 above
   (a per-device Evidence write-back) -- this one is destination-scoped, not
   device-scoped, closing the gap check_local_intel_history() addresses for
   the shared LocalConfirmedIntel store.

4. LOCAL-INTEL CROSS-DEVICE CORRELATION:
   check_local_intel_history() below is the "not yet ported" item #1 named at the
   top of this docstring, now built. Graph-native port of
   scripts/retro_hunter.py's own check_local_intel_history() (lines 197-258) --
   same exclusion rule (a device already among an IOC's own confirmed `sources`
   is not a new finding), same {device_id, matched_kind, matched_value,
   confirmed_by, first_confirmed, count, reason} shape -- but reads argus's OWN
   graph-derived destination history (get_device_destinations_since(), the SAME
   query hunt() itself already uses) instead of the earlier engine's flat alerts.json log, and
   classifies each destination_id as "ip"/"domain" via the same _looks_like_ip()
   GraphStore's own insert_evidence() already uses (argus Evidence has one
   destination_id field, not the earlier engine's separate queried_domain/destination_ip pair).

   Checked against the shared confirmed-intel store (state/local_confirmed_intel.json),
   the one the live CL-AFPE records into when its Stage-1 hard stop confirms a threat for
   one device: this finds every OTHER device that touched the SAME IOC earlier -- the
   "device B also touched this before it was confirmed by device A" point of the mechanism.
"""
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from argus.graph.store import GraphStore, _looks_like_ip
from argus.evidence.model import Evidence
from intelligence.local_intel import LocalConfirmedIntel


def real_threat_intel_lookup_factory(config: Dict[str, Any], state_dir: str,
                                       refresh: bool = True) -> Callable[[str], Optional[Dict[str, Any]]]:
    """Wires in the live ThreatIntel (intelligence/threat_intel.py,
    URLHaus/FeodoTracker/ThreatFox/OTX) as RetroHunter's injected lookup --
    confirmed via direct read that ThreatIntel.lookup_domain(domain) already
    returns exactly the Optional[dict] shape ({confidence, tags, source} or
    None) RetroHunter expects, so this is a genuine one-line wiring, not a
    reimplementation (the whole point of the injected-dependency design, Phase 6).

    refresh=True (the real-usage default) calls ThreatIntel._refresh_all() once
    up front -- a real network call against external feeds, matching
    the earlier engine's own run_retro_hunt() -- so this factory itself is NOT called
    from any test (tests use a plain fake callable instead, see
    tests/test_argus_retro_hunter.py). Set refresh=False only when reusing an
    already-warm on-disk cache from a prior run without paying for a fresh
    network round-trip."""
    return real_threat_intel_lookups_factory(config, state_dir, refresh=refresh)[0]


def real_threat_intel_lookups_factory(config: Dict[str, Any], state_dir: str, refresh: bool = True):
    """(lookup_domain, lookup_ip) of one live ThreatIntel. A name must go to lookup_domain() and an address to
    lookup_ip(): lookup_domain() never consults the IP lists, so an address looked up there can never match."""
    from intelligence.threat_intel import ThreatIntel
    ti = ThreatIntel(
        cache_dir=str(Path(state_dir) / "ti_cache"),
        otx_api_key=config.get("otx_api_key", ""),
        advanced_feeds=bool(config.get("advanced_keyed_feeds", False)),
        refresh_interval=3600,
    )
    if refresh:
        ti._refresh_all()
    return ti.lookup_domain, ti.lookup_ip


# Evidence written by the retro-hunter carries this source; it is what the next run reads to skip a finding it has
# already reported for a (device, destination) pair.
RETRO_HUNTER_SOURCE = "retro_hunter"


@dataclass
class RetroHuntFinding:
    device_id: str
    destination_id: str
    confidence: float
    tags: List[str] = field(default_factory=list)
    source: str = "unknown"


class RetroHunter:
    def __init__(self, store: GraphStore, threat_intel_lookup: Callable[[str], Optional[Dict[str, Any]]],
                 ip_lookup: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None):
        """`threat_intel_lookup` answers for names. `ip_lookup`, when given, answers for raw addresses; without it
        every destination goes to `threat_intel_lookup` (the behaviour before it existed)."""
        self.store = store
        self.threat_intel_lookup = threat_intel_lookup
        self.ip_lookup = ip_lookup

    def _lookup(self, dest: str) -> Optional[Dict[str, Any]]:
        if self.ip_lookup is not None and _looks_like_ip(dest):
            return self.ip_lookup(dest)
        return self.threat_intel_lookup(dest)

    def _window_pairs(self, since: float, extra_pairs: Optional[Iterable[Tuple[str, str]]]) -> List[Tuple[str, str]]:
        """Every (device, destination) pair in the window, from three sources: flagged destinations (evidence),
        real traffic (device_destinations: includes the quiet ones no detector flagged) and the caller's own pairs
        (the live job passes the learned-popularity ledger's names). De-duplicated, order kept."""
        seen: Dict[Tuple[str, str], None] = {}
        for pair in self.store.get_device_destinations_since(since):
            seen[(pair[0], pair[1])] = None
        for pair in self.store.get_traffic_destinations_since(since):
            seen[(pair[0], pair[1])] = None
        for device_id, dest in (extra_pairs or ()):
            if device_id and dest:
                seen[(device_id, dest)] = None
        return list(seen)

    def hunt(self, days_back: float = 14, now: Optional[float] = None,
             extra_pairs: Optional[Iterable[Tuple[str, str]]] = None) -> List[RetroHuntFinding]:
        """Matches run_retro_hunt()'s core loop exactly in spirit: pull every
        destination touched in the lookback window, look each up against
        (injected) fresh threat intel, and for a match, both record a finding AND
        write it back as real evidence for the device that touched it."""
        now = now if now is not None else time.time()
        since = now - days_back * 86400
        pairs = self._window_pairs(since, extra_pairs)
        # A pair already reported inside this window is not reported or written again: the evidence it left is the
        # record, and re-writing it nightly would also re-notify forever.
        already_reported = self.store.get_pairs_written_by_source_since(RETRO_HUNTER_SOURCE, since)

        # Matches load_historical_domains()'s own dedup-by-domain behavior: a
        # domain looked up once here, even if multiple devices touched it, still
        # only calls threat_intel_lookup() once per distinct destination -- but
        # unlike the earlier engine (which discards per-device attribution entirely once
        # deduped), each match is still written back per-DEVICE below, since argus
        # evidence is inherently device-attributed and losing that would be a
        # real regression, not a neutral simplification.
        destinations = {dest for _, dest in pairs}
        intel_by_destination: Dict[str, Dict[str, Any]] = {}
        for dest in destinations:
            result = self._lookup(dest)
            if result:
                intel_by_destination[dest] = result

        # Phase 1a: network-wide reputation propagation.
        # A retro-hunt confirmation IS exactly a "one device's evidence confirms a
        # destination as malicious" moment (ReputationVector's own tier-5 docstring:
        # "corroborated (TI/VT match...) can justify auto-block") -- write it once per
        # distinct destination (not per device-destination pair, since this is a fact
        # about the DESTINATION, not about any one device) onto the shared graph row so
        # any OTHER device touching it inherits the verdict immediately via
        # live_engine.py's own get_destination_reputation() read, rather than waiting
        # for its own turn in a future retro-hunt cycle.
        for dest in intel_by_destination:
            self.store.set_destination_reputation(dest, tier=5, timestamp=now)

        findings: List[RetroHuntFinding] = []
        for device_id, dest in pairs:
            intel = intel_by_destination.get(dest)
            if not intel or (device_id, dest) in already_reported:
                continue
            confidence = float(intel.get("confidence", 0.0) or 0.0)
            finding = RetroHuntFinding(
                device_id=device_id, destination_id=dest, confidence=confidence,
                tags=list(intel.get("tags", []) or []), source=intel.get("source", "unknown"),
            )
            findings.append(finding)

            # Write-back: a real reputation Evidence item, timestamped NOW (this is
            # when the compromise was DISCOVERED, not when the original traffic
            # happened -- the original evidence for that connection, if any, still
            # carries its own original timestamp separately).
            self.store.insert_evidence(Evidence(
                device_id=device_id, destination_id=dest, evidence_type="reputation",
                independence_family="reputation", timestamp=now, source=RETRO_HUNTER_SOURCE,
                value=confidence, confidence=min(1.0, max(0.0, confidence)),
                provenance="retro_hunter:historical_rescan",
                features={"tags": finding.tags, "retro_hunt_source": finding.source},
            ))

        findings.sort(key=lambda f: f.confidence, reverse=True)
        return findings

    def check_local_intel_history(self, local_intel: LocalConfirmedIntel, days_back: float = 14,
                                     now: Optional[float] = None,
                                     extra_pairs: Optional[Iterable[Tuple[str, str]]] = None) -> List[Dict[str, Any]]:
        """the graph-engine migration, Phase 7 -- see this module's own top-of-file
        docstring item #4 for the full design rationale. Matches
        scripts/retro_hunter.py's real check_local_intel_history() exclusion rule
        exactly: a device already among an IOC's own confirmed `sources` is not a
        new finding (it already triggered its own confirmation at the time)."""
        now = now if now is not None else time.time()
        since = now - days_back * 86400
        pairs = self._window_pairs(since, extra_pairs)

        matches: List[Dict[str, Any]] = []
        for device_id, dest in pairs:
            kind = "ip" if _looks_like_ip(dest) else "domain"
            entry = local_intel.check(kind, dest)
            if not entry:
                continue
            if device_id in entry.get("sources", []):
                continue
            matches.append({
                "device_id": device_id, "matched_kind": kind, "matched_value": dest,
                "confirmed_by": list(entry.get("sources", []) or []),
                "first_confirmed": entry.get("first_confirmed"),
                "count": entry.get("count"),
                "reason": entry.get("reason", "unknown"),
            })
        return matches
