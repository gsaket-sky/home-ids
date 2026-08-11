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
    independence_group: str = "general" # e.g., "dns_behavior", "reputation"
    provenance: str = ""    # e.g., "detector:dns_entropy"
    domain: Optional[str] = None
    
    def effective_weight(self) -> float:
        return self.confidence * self.freshness

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
