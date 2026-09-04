import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time

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
    independence_group: str = "general" # e.g., "dns_behavior", "reputation" -- see EVIDENCE_FAMILIES below
    provenance: str = ""    # e.g., "detector:dns_entropy"
    domain: Optional[str] = None
    
    def effective_weight(self) -> float:
        return self.confidence * self.freshness


# VERSION 10 (evidence families): canonical registry of every `independence_group`
# value actually used anywhere in the codebase. Before this existed, independence_group
# was just an ad-hoc string literal scattered across each detector file with no central
# list -- decision_engine.py's "how many independent evidence sources" count read a
# hand-maintained hybrid type-prefix-or-group-membership filter that had silently never
# been updated when threat_signals.py added "lan_recon" (arp_sweep) evidence, so a real
# ARP-sweep + corroborating signal never counted toward the 2-independent-sources bar a
# HIGH-severity verdict requires. This registry is the single source of truth
# decision_engine.py's filter now reads from, so a new detector inventing a fragmenting
# or colliding group name is at least visible in one place instead of silently
# fragmenting corroboration counting further.
#
# This is a DIFFERENT, coarser question than the per-hypothesis `subtag` value some
# detectors also encode into `provenance` (see threat_signals.py's `add()` helper) --
# e.g. multiple dns_tunnel_v2 evidence items share independence_group="dns_tunnel_v2"
# but differ by subtag ("encoded_labels" vs "txt_null_abuse" vs "subdomain_fanout"),
# deliberately, so ONE hypothesis (DNSTunnelingV2Hypothesis) can still tell two
# different tunneling signal *categories* apart for its own internal "2+ corroborating
# categories" bonus. independence_group answers "how many independent evidence FAMILIES
# does this device have, across every hypothesis" (decision_engine.py's cross-hypothesis
# question); subtag answers "how many distinct signal categories does THIS ONE
# hypothesis have" (a single Hypothesis subclass's own, finer-grained question). These
# are intentionally separate mechanisms at different granularities -- merging them would
# lose the within-hypothesis distinction subtag exists specifically to preserve.
EVIDENCE_FAMILIES = frozenset({
    "dns_behavior",     # dns_rate, dns_entropy, dns_unique_ratio, dns_dga_burst
    "dns_tunnel_v2",    # encoded labels, subdomain fanout, txt/null abuse, suspicious TLD
    "zeek_network",     # malicious_ja3/ja4, zeek_notice, lateral_scan, exfiltration, beaconing, conn_abuse, long_conn
    "lan_recon",        # arp_sweep (host-discovery sweep)
    "blindspot_audit",  # dns_evasion_anomaly (reactive-capture blind-spot audit)
    "honeypot",         # honeypot_access
    "ml_anomaly",       # ml_anomaly
    "local_context",    # local_device_discovery -- benign-context only, see below
    "reputation",       # reputation
    "suricata",         # suricata_signature_match (suricata_scan.py, VERSION 11) --
                         # real signature/rule matches from a batch-mode Suricata scan
                         # of a reactive-capture burst pcap. Genuinely independent of
                         # every other family here: it's the only detector that does
                         # byte-pattern/exploit-signature matching rather than
                         # flow/behavioral analysis.
})

# Families whose evidence can corroborate an ATTACK hypothesis toward decision_engine.py's
# "N independent evidence sources" count. Deliberately excludes "local_context" -- that
# family is benign-context-only (e.g. UPnP/SSDP local device discovery) and must never
# count toward independent sources for an attack verdict, the same way it's already
# excluded from pipeline.py's attack-side noisy_types dampening.
ATTACK_EVIDENCE_FAMILIES = EVIDENCE_FAMILIES - {"local_context"}

# PHASE 58 (hoisted from hypotheses/engine.py's DeviceProfileBenignHypothesis, which
# originally defined this as a private class attribute): Evidence `type` values that are
# NEVER ambiguous/routine-telemetry-explainable -- a device-type label (Gap 6, Documentation/
# DECISION_LOGIC_DEPENDENCY_MAP.md) can never rescue a "benign" verdict when any of these
# are present, regardless of which HYPOTHESIS actually fired. Single source of truth,
# imported both by DeviceProfileBenignHypothesis (`hypotheses/engine.py`, competing
# against an attack hypothesis at alert-creation time) and by ai_soc.py's
# DeterministicValidator (checking an LLM's free-text re-review of an already-published
# alert, hours later, in a different process) -- previously only the FIRST of those two
# consumers had this guard; the second could still be talked into "benign, suppress" by
# a device-type explanation that never engaged with the actual attack-shaped evidence at
# all (confirmed live: both example_smarttv_fritz_box immunizations in the 2026-09-03 SOC
# report justified suppressing NETWORK_INTRUSION using DNS-hygiene language -- query rate,
# unique domains, entropy -- none of which NetworkIntrusionHypothesis.evaluate() actually
# reads; see hypotheses/engine.py:104-120). Deliberately excludes dns_rate/dns_entropy/
# dns_unique_ratio (and by extension the "dns_behavior" independence_group as a whole) --
# those genuinely are ambiguous signals a device-profile hypothesis is allowed to explain
# as routine telemetry, not attack-specific on their own -- see
# DeviceProfileBenignHypothesis's own docstring.
ATTACK_SHAPED_EVIDENCE_TYPES = frozenset({
    "dns_dga_burst", "dns_tunnel_v2", "zeek_lateral_scan", "malicious_ja3",
    "malicious_ja4", "zeek_notice", "zeek_exfiltration", "zeek_beaconing",
    "zeek_conn_abuse", "zeek_long_conn", "arp_sweep", "dns_evasion_anomaly",
    "arp_spoof_pending",
})

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
                if e.independence_group == "reputation":
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
