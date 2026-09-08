"""
suricata_api.py -- surfaces Suricata's real signature-match findings in the console for
the first time. Confirmed directly against the codebase and .94's live data before
building this (not assumed):

- Suricata never got wired into the v13 evidence graph at all (Documentation/
  CONSOLE_DATA_API.md already documents this -- it only runs as a subprocess against
  reactive-capture pcap bursts, not a continuous log stream). So this reads
  state/alerts.json directly instead of GraphStore, and is explicitly NOT an attempt at
  the bigger "wire Suricata into the v13 graph" migration that doc flags as separate,
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

router = APIRouter()

_MAX_TAIL_BYTES = 20 * 1024 * 1024  # bounded scan -- see module docstring
_CHUNK_BYTES = 1 * 1024 * 1024


def _iter_lines_reverse(path: Path, max_bytes: int = _MAX_TAIL_BYTES):
    """Yields complete lines from `path`, most-recent-first, reading backward in
    `_CHUNK_BYTES` chunks and stopping once `max_bytes` has been scanned. The very first
    (oldest, leftmost) fragment of the scanned window is dropped -- it may be a partial
    line whose real start lies further back than we read."""
    size = path.stat().st_size
    if size == 0:
        return
    scanned = 0
    pos = size
    buf = b""
    with path.open("rb") as f:
        while pos > 0 and scanned < max_bytes:
            read_size = min(_CHUNK_BYTES, pos)
            pos -= read_size
            f.seek(pos)
            buf = f.read(read_size) + buf
            scanned += read_size
            # Yield every complete line we can from the front of buf, keeping the
            # leading (possibly-partial) fragment for the next chunk.
            parts = buf.split(b"\n")
            buf = parts[0]
            for line in reversed(parts[1:]):
                if line.strip():
                    yield line
    # Whatever's left in buf at pos==0 is the true first line of the scanned window --
    # only safe to yield if we actually reached the start of the file (pos == 0 means
    # we did), otherwise it's a partial line from mid-file and must be dropped.
    if pos == 0 and buf.strip():
        yield buf


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
