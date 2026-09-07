"""
v13 retro-hunter (Phase 6 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Faithful port of scripts/retro_hunter.py's CORE loop (451 lines, read in full
before writing anything): re-scan historical destinations against freshly-updated
threat intel to catch zero-day compromises that were invisible at the time the
traffic occurred. Two deliberate structural differences, both scope-consistent
with Phases 4/5's own honest cuts, not accidents:

1. THREAT-INTEL LOOKUP IS AN INJECTED DEPENDENCY, not a reimplementation of
   intelligence/threat_intel.py's ThreatIntel class (URLHaus/FeodoTracker/
   ThreatFox/OTX feed integration -- its own substantial, unresearched subsystem).
   Callers pass a `lookup: Callable[[str], Optional[dict]]` -- v-current's real
   ThreatIntel.lookup_domain() has exactly this shape (domain -> {confidence,
   tags, source} or None), so wiring the real one in later is a one-line change,
   not a redesign.

2. A FINDING BECOMES A NEW GRAPH EVIDENCE ITEM, not a side-channel
   fp_engine.record_confirmed_threat()+_apply_sigma_shift() call (v13's CL-AFPE
   deliberately doesn't have either -- Phase 4's own scope cut). A retroactively-
   confirmed malicious destination is written back as a real `reputation`
   Evidence item for the device that touched it, timestamped now with
   provenance="retro_hunter" -- the NEXT evaluation cycle for that device picks
   it up through the exact same HypothesisEngine/DecisionEngine path any other
   reputation evidence goes through, rather than a separate mechanism.

NOT PORTED (tracked as real, separate future work, consistent with Phase 4's
local_intel deferral): check_local_intel_history()'s cross-device "device B also
touched this IOC before it was confirmed by device A" cross-reference -- it
depends on the LocalConfirmedIntel store, which v13 doesn't have yet (deliberately
deferred in Phase 4 alongside the rest of local-intel poisoning protection). Also
not ported: Telegram notification (an orchestration concern, kept out of this
module for testability -- callers get the finding list back and decide how to
notify, the same "hand data back, let the caller act" shape CL-AFPE's
MarkFalsePositiveResult already uses) and job-health/GeoIP-enrichment reporting.

3. NETWORK-WIDE REPUTATION PROPAGATION (v13 full-architecture plan, Phase 1a,
   added after this module's initial Phase 6 build): every confirmed destination
   also gets `store.set_destination_reputation(dest, tier=5, ...)` called once,
   writing onto the shared `destinations` row so ANY other device touching that
   destination inherits the verdict immediately (live_engine.py's own
   get_destination_reputation() read), not just the specific device(s) this hunt
   happened to already know about. A genuinely different mechanism from #2 above
   (a per-device Evidence write-back) -- this one is destination-scoped, not
   device-scoped, closing the gap check_local_intel_history() addresses for
   v-current's own separate LocalConfirmedIntel store.
"""
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from v13.graph.store import GraphStore
from v13.evidence.model import Evidence


def real_threat_intel_lookup_factory(config: Dict[str, Any], state_dir: str,
                                       refresh: bool = True) -> Callable[[str], Optional[Dict[str, Any]]]:
    """Wires in v-current's REAL ThreatIntel (intelligence/threat_intel.py,
    URLHaus/FeodoTracker/ThreatFox/OTX) as RetroHunter's injected lookup --
    confirmed via direct read that ThreatIntel.lookup_domain(domain) already
    returns exactly the Optional[dict] shape ({confidence, tags, source} or
    None) RetroHunter expects, so this is a genuine one-line wiring, not a
    reimplementation (the whole point of the injected-dependency design, Phase 6).

    refresh=True (the real-usage default) calls ThreatIntel._refresh_all() once
    up front -- a real network call against external feeds, matching
    v-current's own run_retro_hunt() -- so this factory itself is NOT called
    from any test (tests use a plain fake callable instead, see
    tests/test_v13_retro_hunter.py). Set refresh=False only when reusing an
    already-warm on-disk cache from a prior run without paying for a fresh
    network round-trip."""
    from intelligence.threat_intel import ThreatIntel
    ti = ThreatIntel(
        cache_dir=str(Path(state_dir) / "ti_cache"),
        otx_api_key=config.get("otx_api_key", ""),
        refresh_interval=3600,
    )
    if refresh:
        ti._refresh_all()
    return ti.lookup_domain


@dataclass
class RetroHuntFinding:
    device_id: str
    destination_id: str
    confidence: float
    tags: List[str] = field(default_factory=list)
    source: str = "unknown"


class RetroHunter:
    def __init__(self, store: GraphStore, threat_intel_lookup: Callable[[str], Optional[Dict[str, Any]]]):
        self.store = store
        self.threat_intel_lookup = threat_intel_lookup

    def hunt(self, days_back: float = 14, now: Optional[float] = None) -> List[RetroHuntFinding]:
        """Matches run_retro_hunt()'s core loop exactly in spirit: pull every
        destination touched in the lookback window, look each up against
        (injected) fresh threat intel, and for a match, both record a finding AND
        write it back as real evidence for the device that touched it."""
        now = now if now is not None else time.time()
        since = now - days_back * 86400
        pairs = self.store.get_device_destinations_since(since)

        # Matches load_historical_domains()'s own dedup-by-domain behavior: a
        # domain looked up once here, even if multiple devices touched it, still
        # only calls threat_intel_lookup() once per distinct destination -- but
        # unlike v1 (which discards per-device attribution entirely once
        # deduped), each match is still written back per-DEVICE below, since v13
        # evidence is inherently device-attributed and losing that would be a
        # real regression, not a neutral simplification.
        destinations = {dest for _, dest in pairs}
        intel_by_destination: Dict[str, Dict[str, Any]] = {}
        for dest in destinations:
            result = self.threat_intel_lookup(dest)
            if result:
                intel_by_destination[dest] = result

        # Phase 1a (v13 full-architecture plan): network-wide reputation propagation.
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
            if not intel:
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
                independence_family="reputation", timestamp=now, source="retro_hunter",
                value=confidence, confidence=min(1.0, max(0.0, confidence)),
                provenance="retro_hunter:historical_rescan",
                features={"tags": finding.tags, "retro_hunt_source": finding.source},
            ))

        findings.sort(key=lambda f: f.confidence, reverse=True)
        return findings
