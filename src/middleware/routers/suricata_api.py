"""
suricata_api.py -- surfaces Suricata's real signature-match findings in the console for
the first time. Confirmed directly against the codebase and .94's live data before
building this (not assumed):

- Suricata never got wired into the argus evidence graph at all (Documentation/
  CONSOLE_DATA_API.md already documents this -- it only runs as a subprocess against
  reactive-capture pcap bursts, not a continuous log stream). So this reads
  state/alerts.json directly instead of GraphStore, and is explicitly NOT an attempt at
  the bigger "wire Suricata into the argus graph" migration that doc flags as separate,
  larger work.
- state/alerts.json is a 113MB append-only JSONL log on the real deployment (checked over
  SSH). Reading it forward from the start would mean parsing the whole thing on every
  request -- this tails it BACKWARD from the end in bounded chunks instead, stopping once
  `limit` matching records are found or a hard byte cap is hit, per the Pi-8GB-target
  bounded-I/O rule.
- Records span a real schema migration on the live box: older ones (schema
  "home_ids_alerts_v3") carry the hypothesis name as a top-level "signature" field with
  no "hee_evidence_types" at all; newer ones carry "hee_evidence_types"/"hee_hypotheses".
  Both are checked. core/pipeline.py's own "suricata_matches" field (added alongside this
  endpoint, same change) only exists on records written from deploy time onward --
  historical matches show an honest "not recorded for this alert" note instead of guessing.
"""
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query

from middleware.auth import verify_token, CONFIG, LOGGER
from middleware.routers._alert_log_utils import iter_lines_reverse

router = APIRouter()

_MAX_TAIL_BYTES = 20 * 1024 * 1024  # bounded scan -- see _alert_log_utils.py's module docstring
_CHUNK_BYTES = 1 * 1024 * 1024


def _iter_lines_reverse(path: Path, max_bytes: int = _MAX_TAIL_BYTES):
    # _CHUNK_BYTES looked up as a module global (not a default-arg snapshot) so
    # tests/test_suricata_api.py's monkeypatch.setattr(suricata_api, "_CHUNK_BYTES", ...)
    # -- forcing tiny chunks to exercise the partial-line-carry boundary logic --
    # still works after this function became a thin wrapper around the shared
    # _alert_log_utils.iter_lines_reverse().
    return iter_lines_reverse(path, max_bytes, chunk_bytes=_CHUNK_BYTES)


def _is_suricata_record(rec: Dict[str, Any]) -> bool:
    if "suricata_signature_match" in (rec.get("hee_evidence_types") or []):
        return True
    if rec.get("signature") == "SIGNATURE_MATCHED_THREAT":
        return True
    hyps = rec.get("hee_hypotheses") or {}
    if (hyps.get("attack") or {}).get("name") == "SIGNATURE_MATCHED_THREAT":
        return True
    return False


def _summarize(rec: Dict[str, Any]) -> Dict[str, Any]:
    device = rec.get("device") or {}
    net = rec.get("network_context") or {}
    matches = rec.get("suricata_matches") or []
    return {
        "timestamp": rec.get("timestamp"),
        "device_id": device.get("id", "unknown"),
        "hostname": device.get("hostname", "unknown"),
        "device_ip": device.get("ip", "unknown"),
        "target": net.get("destination_ip") or net.get("queried_domain") or "unknown",
        "risk": rec.get("risk"),
        "state": rec.get("state"),
        "matches": matches,
        "detail_recorded": bool(matches),
    }


@router.get("/api/suricata/recent")
def get_recent_suricata(limit: int = Query(50, ge=1, le=500), token: str = Depends(verify_token)):
    alerts_path = Path(CONFIG.get("alert_json_path", "state/alerts.json"))
    if not alerts_path.exists():
        return {"detections": [], "note": f"No alert log found at {alerts_path}."}

    detections: List[Dict[str, Any]] = []
    scanned_lines = 0
    try:
        for line in _iter_lines_reverse(alerts_path):
            scanned_lines += 1
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if _is_suricata_record(rec):
                detections.append(_summarize(rec))
                if len(detections) >= limit:
                    break
    except Exception as exc:
        LOGGER.error("suricata_api: failed reading %s: %s", alerts_path, exc)
        return {"detections": [], "note": f"Failed reading the alert log: {exc}"}

    return {
        "detections": detections,
        "scanned_lines": scanned_lines,
        "note": (
            "Suricata's own signature/rule text is only recorded for alerts generated "
            "after this feature shipped -- older matches show that a Suricata signature "
            "fired, without which rule."
        ),
    }
