import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import time

from utils import ZEEK_NOTICE_ATTACK_SHAPED_EVIDENCE_TYPES
from argus.hypotheses.independence import family_for

@dataclass
class Evidence:
    type: str               # e.g., "dns_entropy", "reputation_tier"
    source: str             # e.g., "pihole", "zeek", "ml_engine"
    timestamp: float        
    device: str
    value: float            # raw observation value
    baseline: Optional[float] = None
    confidence: float = 1.0 # detector confidence 0.0-1.0
    freshness: float = 1.0  # multiplier that can decay over time
    provenance: str = ""    # e.g., "detector:dns_entropy"
    domain: Optional[str] = None
    # Scan-shaped evidence (arp_sweep, zeek_conn_abuse, zeek_lateral_scan) touches a SET of hosts: `domain` holds one
    # example for older readers, `targets` a short sorted sample and `target_count` the distinct count, so the alert
    # can name the set instead of one arbitrary member (core/alert_attribution.py).
    targets: Tuple[str, ...] = ()
    target_count: int = 0

    def effective_weight(self) -> float:
        return self.confidence * self.freshness

    @property
    def family(self) -> str:
        """The evidence family -- from the one registry (argus/hypotheses/independence.py), never from the detector
        that produced the item (W-13, 2026-10-14: the free-form `independence_group` string is gone)."""
        return family_for(self.type)


# W-13 (2026-10-14): the evidence-family model has ONE registry, argus/hypotheses/independence.py's
# INDEPENDENCE_FAMILY_MAP (evidence type -> family; NON_ATTACK_FAMILIES = the context-only families that never count
# toward an attack verdict). This module used to keep a second, coarser vocabulary (EVIDENCE_FAMILIES, set by each
# detector as a free-form `independence_group` string); it drove the evidence expiry, the safe-device noise filter and
# the family names saved on alerts while the decision engine counted by the other model. Both are re-stated on types
# and registry families below.
#
# Evidence types the behavioural noise filter drops for a safe-listed device (operator-verified address): the device's
# own routine behaviour -- resolver traffic, mesh/repeater and router ARP/flow noise, ML score -- is not evidence of
# compromise there, while threat-intel, honeypot, ARP-spoof, geofence and signature evidence is always kept. Exactly what
# the old group assignments dropped (zeek_network, lan_recon, the named dns types, ml_anomaly); pinned by
# tests/test_evidence_single_family_registry.py.
SAFE_DEVICE_DAMPENED_TYPES = frozenset({
    "ml_anomaly", "dns_rate", "dns_entropy", "dns_unique_ratio", "dns_evasion_anomaly",
    "malicious_ja3", "malicious_ja4",
    "zeek_lateral_scan", "zeek_exfiltration", "zeek_beaconing", "zeek_conn_abuse", "zeek_long_conn",
    "arp_spoof_pending", "arp_sweep",
}) | frozenset(f"zeek_notice_{tier}" for tier in ("weak", "medium", "strong", "highly_deterministic"))

# Families whose evidence outlives the 10-minute behavioural default (a reputation verdict is a property of the
# destination, not of this minute's traffic).
LONG_LIVED_FAMILIES = frozenset({"reputation"})

# PHASE 58 (hoisted from argus/hypotheses/engine.py's DeviceProfileBenignHypothesis, which
# originally defined this as a private class attribute): Evidence `type` values that are
# NEVER ambiguous/routine-telemetry-explainable -- a device-type label (Gap 6, Documentation/
# DECISION_LOGIC_DEPENDENCY_MAP.md) can never rescue a "benign" verdict when any of these
# are present, regardless of which HYPOTHESIS actually fired. Single source of truth,
# imported both by DeviceProfileBenignHypothesis (`argus/hypotheses/engine.py`, competing
# against an attack hypothesis at alert-creation time) and by ai_soc.py's
# DeterministicValidator (checking an LLM's free-text re-review of an already-published
# alert, hours later, in a different process) -- previously only the FIRST of those two
# consumers had this guard; the second could still be talked into "benign, suppress" by
# a device-type explanation that never engaged with the actual attack-shaped evidence at
# all (confirmed live: both example_smarttv_fritz_box immunizations in the 2026-09-03 SOC
# report justified suppressing NETWORK_INTRUSION using DNS-hygiene language -- query rate,
# unique domains, entropy -- none of which NetworkIntrusionHypothesis.evaluate() actually
# reads; see argus/hypotheses/engine.py:104-120). Deliberately excludes dns_rate/dns_entropy/
# dns_unique_ratio (and by extension the "dns_behavior" family as a whole) --
# those genuinely are ambiguous signals a device-profile hypothesis is allowed to explain
# as routine telemetry, not attack-specific on their own -- see
# DeviceProfileBenignHypothesis's own docstring.
# BUGFIX (explicit user request, 2026-09-09): "zeek_notice" fragmented into 4
# evidence_type values by tier (utils.py's ZEEK_NOTICE_EVIDENCE_TYPES) -- weak
# (routine TCP-framing/capture-timing noise, not attacker behavior) deliberately
# excluded here too, matching argus's own DeviceProfileBenignHypothesis treatment,
# so the two engines don't silently diverge on this exact question again.
ATTACK_SHAPED_EVIDENCE_TYPES = frozenset({
    "dns_dga_burst", "dns_tunnel_v2", "zeek_lateral_scan", "malicious_ja3",
    "malicious_ja4", "zeek_exfiltration", "zeek_beaconing",
    "zeek_conn_abuse", "zeek_long_conn", "arp_sweep", "dns_evasion_anomaly",
    "arp_spoof_pending",
}) | ZEEK_NOTICE_ATTACK_SHAPED_EVIDENCE_TYPES

class EvidenceStore:
    def __init__(self):
        self._evidence_by_device: Dict[str, List[Evidence]] = {}
        self._lock = threading.RLock()

    def add(self, ev: Evidence):
        with self._lock:
            if ev.device not in self._evidence_by_device:
                self._evidence_by_device[ev.device] = []
            self._evidence_by_device[ev.device].append(ev)

    def get_for_device(self, device: str) -> List[Evidence]:
        # Filter out stale evidence (e.g. > 10 minutes old) unless it's long-lived
        now = time.time()
        active_evidence = []
        with self._lock:
            for e in self._evidence_by_device.get(device, []):
                age = now - e.timestamp
                ttl = 600 # 10 minutes default for behavioral
                if e.family in LONG_LIVED_FAMILIES:
                    ttl = 86400 # 24 hours
                if age < ttl:
                    # decay freshness linearly
                    e.freshness = max(0.0, 1.0 - (age / ttl))
                    active_evidence.append(e)
                
            self._evidence_by_device[device] = active_evidence
        return active_evidence
        
    def clear_device(self, device: str):
        if device in self._evidence_by_device:
            del self._evidence_by_device[device]
