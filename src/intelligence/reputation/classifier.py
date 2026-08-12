from dataclasses import dataclass
from typing import Dict, Any, Optional

@dataclass
class ReputationVector:
    domain: str
    tier: int
    asn_owner: str = "Unknown"
    vt_detection_ratio: float = 0.0
    ti_risk: float = 0.0
    abuse_risk: float = 0.0
    cl_afpe_similarity: float = 0.0
    first_seen: bool = False
    source_confidence: str = "medium"

class ReputationClassifier:
    def __init__(self):
        self._TIER_0 = {".box", ".local", "fritz.box"}
        self._TIER_1 = {"apple.com", "microsoft.com", "google.com", "icloud.com", "windowsupdate.com"}
        self._TIER_2 = {"doubleclick.net", "cloudflare.com", "amazonaws.com", "azure.com", "akamaiedge.net", "googlesyndication.com"}
        
    def classify(self, domain: str, vt_score: float = 0.0, afpe_score: float = 0.0, is_new: bool = False, ti_score: float = 0.0, abuse_score: float = 0.0) -> ReputationVector:
        domain = (domain or "").lower().strip(".")
        tier = 3 # Unknown by default
        
        # Check explicit tiers (simplified matching for prototype)
        for t0 in self._TIER_0:
            if domain.endswith(t0) or domain == t0:
                tier = 0
                break
        if tier == 3:
            for t1 in self._TIER_1:
                if domain.endswith(t1) or domain == t1:
                    tier = 1
                    break
        if tier == 3:
            for t2 in self._TIER_2:
                if domain.endswith(t2) or domain == t2:
                    tier = 2
                    break
                    
        # Check malicious thresholds
        confirmed_ioc = vt_score > 2.0 or ti_score > 2.0 or abuse_score > 2.0
        weak_signal = vt_score > 0.0 or ti_score > 0.0 or abuse_score > 0.0
        if confirmed_ioc:
            tier = 5
        elif weak_signal:
            tier = 4 # Weak detection is suspicious, not confirmed malware
            
        return ReputationVector(
            domain=domain,
            tier=tier,
            vt_detection_ratio=vt_score,
            ti_risk=ti_score,
            abuse_risk=abuse_score,
            cl_afpe_similarity=afpe_score,
            first_seen=is_new,
            source_confidence="high" if tier in (0,1,5) else "medium"
        )
