from typing import List, Dict, Any
from intelligence.hypotheses.evidence import Evidence
import time

class ZeekNetworkDetector:
    def detect(self, device: str, zeek_events: List[Dict[str, Any]]) -> List[Evidence]:
        ev_list = []
        now = time.time()
        
        for evt in zeek_events:
            # Check for lateral movement (port scans, etc)
            if evt.get("type") == "lateral_movement":
                ev_list.append(Evidence(
                    type="zeek_lateral_scan",
                    source="zeek",
                    timestamp=now,
                    device=device,
                    value=1.0,
                    confidence=0.9,
                    independence_group="zeek_network",
                    provenance="detector:zeek:lateral_scan"
                ))
            # Check for general zeek notices
            elif evt.get("type") == "notice":
                ev_list.append(Evidence(
                    type="zeek_notice",
                    source="zeek",
                    timestamp=now,
                    device=device,
                    value=1.0,
                    confidence=0.5,
                    independence_group="zeek_network",
                    provenance="detector:zeek:notice"
                ))
                
        return ev_list
