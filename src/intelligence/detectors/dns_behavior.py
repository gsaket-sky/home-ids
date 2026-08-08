from typing import List, Dict, Any
from intelligence.hypotheses.evidence import Evidence
import time

class DNSBehaviorDetector:
    def __init__(self):
        pass

    def detect(self, device: str, features: Dict[str, Any]) -> List[Evidence]:
        ev_list = []
        now = time.time()
        
        # Rate evidence
        rate = features.get("dns_rate_last_60s", 0)
        if rate > 100:
            ev_list.append(Evidence(
                type="dns_rate",
                source="pihole",
                timestamp=now,
                device=device,
                value=rate,
                confidence=min(1.0, rate / 500.0), # Caps at 500 qps for 1.0 confidence
                independence_group="dns_behavior",
                provenance="detector:dns_behavior:rate"
            ))
            
        # Entropy evidence
        entropy = features.get("max_entropy", 0.0)
        if entropy > 4.0:
            ev_list.append(Evidence(
                type="dns_entropy",
                source="pihole",
                timestamp=now,
                device=device,
                value=entropy,
                confidence=min(1.0, (entropy - 4.0) / 1.5),
                independence_group="dns_behavior",
                provenance="detector:dns_behavior:entropy"
            ))
            
        # Unique domains
        unique_ratio = features.get("unique_subdomain_ratio", 0.0)
        if unique_ratio > 0.8:
            ev_list.append(Evidence(
                type="dns_unique_ratio",
                source="pihole",
                timestamp=now,
                device=device,
                value=unique_ratio,
                confidence=unique_ratio,
                independence_group="dns_behavior",
                provenance="detector:dns_behavior:unique_ratio"
            ))
            
        return ev_list
