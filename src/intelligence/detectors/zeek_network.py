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
                # BUGFIX (reviewer suggestion, implemented): the alert's WHY line only
                # ever said "Zeek policy notice fired for this connection" with no way to
                # tell a genuinely alarming notice type (e.g. SSL::Invalid_Server_Cert)
                # apart from a routine one -- get_alerts() already carries the real
                # note/msg text (zeek_features.py's _process_notice()), it just never
                # made it past this detector. provenance is the established free-text
                # slot other detectors already use for this exact purpose (see
                # threat_signals.py's add() helper).
                note_type = evt.get("note", "") or "unknown"
                ev_list.append(Evidence(
                    type="zeek_notice",
                    source="zeek",
                    timestamp=now,
                    device=device,
                    value=1.0,
                    confidence=evt.get("confidence", 0.75),
                    independence_group="zeek_network",
                    provenance=f"detector:zeek:notice:{note_type}"
                ))
                
        return ev_list
