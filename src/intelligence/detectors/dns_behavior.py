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
        # W-04: read "dns_rate_last_60s" first, which nothing ever produced. Deliberately not produced: this fixed
        # 100/min bar applied to a raw 60-s count would fire on ordinary page loads. The 5-min average is the signal.
        rate = features.get("query_rate", 0)
        if rate > 100:
            ev_list.append(Evidence(
                type="dns_rate",
                source="pihole",
                timestamp=now,
                device=device,
                value=rate,
                confidence=min(1.0, rate / 500.0), # Caps at 500 qps for 1.0 confidence
                independence_group="dns_behavior",
                provenance="detector:dns_behavior:rate",
                # P2 FIX (third-party review, 2026-09-28): domain=... attaches the
                # real domain actually driving this rate burst (dns_features.py's
                # new top_rate_domain), the same "real evidence-linked domain, not
                # an unrelated fallback" fix already applied to dns_entropy above --
                # see argus/hypotheses/engine.py's AdvertisingBurstHypothesis for why a
                # dns_rate Evidence with no .domain made its own rep_vector.tier
                # gate a structural no-op.
                domain=features.get("top_rate_domain") or None,
            ))
            
        # Entropy evidence
        # SECURITY FIX (P0-1, third-party architecture review, 2026-09-28): "max_entropy"
        # was a dead feature key -- dns_features.py never populated it, so this .get()
        # always silently fell through to entropy_avg anyway. Reads entropy_avg directly
        # now; domain=... attaches the real domain whose label actually drove that
        # average up (dns_features.py's new top_entropy_domain), so pipeline.py's alert
        # attribution has a genuine evidence-linked domain to prefer instead of always
        # falling back to "unknown" for a DNS_TUNNELING verdict.
        entropy = features.get("entropy_avg", 0.0)
        if entropy > 4.0:
            ev_list.append(Evidence(
                type="dns_entropy",
                source="pihole",
                timestamp=now,
                device=device,
                value=entropy,
                confidence=min(1.0, (entropy - 4.0) / 1.5),
                independence_group="dns_behavior",
                provenance="detector:dns_behavior:entropy",
                domain=features.get("top_entropy_domain") or None,
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
                provenance="detector:dns_behavior:unique_ratio",
                # W-04: the parent domain the ratio was measured under (dns_features._unique_subdomain_ratio).
                domain=features.get("unique_subdomain_ratio_domain") or None,
            ))
            
        return ev_list
