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
"""
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from v13.graph.store import GraphStore
from v13.evidence.model import Evidence


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
