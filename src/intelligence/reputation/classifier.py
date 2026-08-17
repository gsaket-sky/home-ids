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

def _suffix_or_domain_match(domain: str, pattern: str) -> bool:
    """PHASE 0 FIX: boundary-safe tier matching. The old `domain.endswith(pattern)` check
    matched on raw substrings, so 'notgoogle.com'.endswith('google.com') was True — any
    domain that happened to END with a trusted domain's characters (not just a real
    subdomain of it) got silently promoted to a trusted tier. Patterns starting with '.'
    are true suffix patterns (e.g. '.local') where the leading dot already enforces a
    boundary; bare domain patterns (e.g. 'google.com') now require an exact match or a
    real subdomain relationship ('.' + pattern)."""
    if pattern.startswith("."):
        return domain.endswith(pattern)
    return domain == pattern or domain.endswith("." + pattern)


class ReputationClassifier:
    def __init__(self):
        self._TIER_0 = {".box", ".local", "fritz.box"}
        self._TIER_1 = {"apple.com", "microsoft.com", "google.com", "icloud.com", "windowsupdate.com"}
        self._TIER_2 = {"doubleclick.net", "cloudflare.com", "amazonaws.com", "azure.com", "akamaiedge.net", "googlesyndication.com"}

    def classify(self, domain: str, vt_score: float = 0.0, afpe_score: float = 0.0, is_new: bool = False, ti_score: float = 0.0, abuse_score: float = 0.0) -> ReputationVector:
        domain = (domain or "").lower().strip(".")
        tier = 3 # Unknown by default

        # Check explicit tiers (boundary-safe matching — see _suffix_or_domain_match)
        for t0 in self._TIER_0:
            if _suffix_or_domain_match(domain, t0):
                tier = 0
                break
        if tier == 3:
            for t1 in self._TIER_1:
                if _suffix_or_domain_match(domain, t1):
                    tier = 1
                    break
        if tier == 3:
            for t2 in self._TIER_2:
                if _suffix_or_domain_match(domain, t2):
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
