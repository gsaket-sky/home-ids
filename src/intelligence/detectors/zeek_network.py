from typing import List, Dict, Any
from intelligence.hypotheses.evidence import Evidence
import time

class ZeekNetworkDetector:
    def detect(self, device: str, zeek_events: List[Dict[str, Any]]) -> List[Evidence]:
        ev_list = []
        now = time.time()
        
        for evt in zeek_events:
            evt_type = evt.get("type")
            if evt_type in ("malicious_ja3", "malicious_ja4"):
                ev_list.append(Evidence(
                    type=evt_type,
                    source="zeek",
                    timestamp=now,
                    device=device,
                    value=1.0,
                    confidence=evt.get("confidence", 0.95),
                    independence_group="zeek_network",
                    provenance=f"detector:zeek:{evt_type}"
                ))
            elif evt_type == "zeek_notice":
                ev_list.append(Evidence(
                    type="zeek_notice",
                    source="zeek",
                    timestamp=now,
                    device=device,
                    value=1.0,
                    confidence=evt.get("confidence", 0.75),
                    independence_group="zeek_network",
                    provenance="detector:zeek:notice"
                ))
                
        return ev_list
