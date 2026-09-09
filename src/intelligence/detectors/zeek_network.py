from typing import List, Dict, Any
from intelligence.hypotheses.evidence import Evidence
from utils import classify_zeek_notice, ZEEK_NOTICE_TIER_CONFIDENCE
import time

class ZeekNetworkDetector:
    def detect(self, device: str, zeek_events: List[Dict[str, Any]]) -> List[Evidence]:
        ev_list = []
        now = time.time()
        
        for evt in zeek_events:
            evt_type = evt.get("type")
            if evt_type in ("malicious_ja3", "malicious_ja4"):
                # BUGFIX (live audit): attach a real attribution target -- prefer the TLS
                # SNI server_name (a real hostname, more useful to a reader than a bare
                # IP) and fall back to dest_ip when SNI wasn't present on the wire.
                evidence_target = evt.get("server") or evt.get("dest_ip") or None
                # Release 14, N4 (multi-signal campaign detection): the real fingerprint
                # hash, encoded into provenance -- this codebase's own established
                # "free-text discriminator slot" convention (see zeek_notice's note_type
                # below). Previously this was just f"detector:zeek:{evt_type}" with no
                # way to tell WHICH ja3/ja4 hash fired, so nothing downstream could ever
                # answer "did another device see this SAME fingerprint" -- the hash
                # itself was computed by Zeek and available on `evt`, just never
                # propagated past this detector. v13/graph/store.py's
                # get_devices_sharing_provenance() is the new consumer.
                fingerprint_hash = evt.get("ja3") if evt_type == "malicious_ja3" else evt.get("ja4")
                ev_list.append(Evidence(
                    type=evt_type,
                    source="zeek",
                    timestamp=now,
                    device=device,
                    value=1.0,
                    confidence=evt.get("confidence", 0.95),
                    independence_group="zeek_network",
                    provenance=f"detector:zeek:{evt_type}:{fingerprint_hash or 'unknown'}",
                    domain=evidence_target,
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
                # BUGFIX (live audit, 2026-09-09): confidence used to be a flat 0.75 for
                # EVERY notice type, regardless of which one fired -- utils.py's
                # classify_zeek_notice() (see its own docstring for the full incident,
                # grounded in .94's real notice.log/weird.log distribution) now sets it
                # per-tier instead. The tier is also embedded as a provenance subtag
                # ("detector:zeek:notice:{tier}:{note_type}"), the SAME
                # "detector:...:{subtag}:{note}" convention DNSTunnelingV2Hypothesis/
                # BeaconingHypothesis/DNSEvasionHypothesis's own subtag parsing already
                # uses (split(":", 4)[3]) -- so v13/hypotheses/engine.py's
                # NetworkIntrusionHypothesis/DeviceProfileBenignHypothesis can weight a
                # notice by its actual tier instead of treating any zeek_notice's mere
                # PRESENCE as equally notable.
                tier = classify_zeek_notice(note_type)
                ev_list.append(Evidence(
                    type="zeek_notice",
                    source="zeek",
                    timestamp=now,
                    device=device,
                    value=1.0,
                    confidence=ZEEK_NOTICE_TIER_CONFIDENCE[tier],
                    independence_group="zeek_network",
                    provenance=f"detector:zeek:notice:{tier}:{note_type}",
                    domain=evt.get("dest_ip") or None,
                ))
                
        return ev_list
