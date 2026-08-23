"""
incident_report.py - VERSION 11 (P1, review #7/#8: "Alert != Observation != Incident").

alerts.json is deliberately append-only, one line per qualifying cycle -- that's
correct for CL-AFPE training data (scripts/train_fp_classifier.py) and must not
change. But a human auditing the system by reading raw alerts.json (exactly what a
third-party review of this file had to do by hand) sees "event / event / event /
event" where the system's own model is really "ONE INCIDENT, N observations" --
incident_key.py's incident_key() already exists and is already written into every
alert as alert_payload["incident_id"] (pipeline.py), it just has no human-readable
view. This script is that view: purely a read-only rollup over the existing training
log, never writes to it, never feeds back into the pipeline.

Usage:
    python3 src/scripts/incident_report.py [--hours 24] [--top 30] [--min-occurrences 1]
"""
import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))
from config import CONFIG
from incident_key import incident_key as compute_incident_key, signature_base

# Coarsest-to-finest, matching incident_tracker.py's own severity ranking -- used here
# only to report "highest state this incident ever reached," not to gate anything.
_SEVERITY_RANK = {"BENIGN": 0, "ANOMALOUS": 0, "SUSPICIOUS": 1, "HIGH": 2, "CRITICAL": 3}


def _resolve_alerts_path() -> Path:
    configured = CONFIG.get("alert_json_path", "state/alerts.json")
    p = Path(configured)
    if not p.is_absolute():
        # Matches config.yaml's own documented convention: relative paths resolve
        # against the repo root (this file lives at src/scripts/, repo root is two
        # levels up), same as every other relative state path in config.yaml.
        p = Path(__file__).resolve().parent.parent.parent / configured
    return p


def _iter_alert_records(path: Path, since_ts: float):
    """Streams alerts.json line by line rather than loading the whole (often 10s of
    MB, growing forever) file into memory at once. A malformed line (partial write,
    mid-append truncation) is skipped, not fatal -- this is a best-effort read-only
    report over a live-appended file, not a strict schema validator."""
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = rec.get("timestamp")
            if ts is not None and float(ts) < since_ts:
                continue
            yield rec


def _record_incident_key(rec: dict) -> str:
    """Prefers the incident_id already stamped onto the record at write time
    (VERSION 10, pipeline.py) -- falls back to recomputing it from the record's own
    fields for older records written before that existed, so this report works over
    a file spanning both eras without a gap."""
    existing = rec.get("incident_id")
    if existing:
        return str(existing)
    device_id = rec.get("device", {}).get("id", "unknown")
    net_ctx = rec.get("network_context", {}) or {}
    return compute_incident_key(
        device_id, net_ctx.get("destination_ip"), net_ctx.get("queried_domain"),
        rec.get("signature", "unknown"),
    )


def build_incidents(path: Path, since_ts: float) -> dict:
    incidents: dict = {}
    for rec in _iter_alert_records(path, since_ts):
        key = _record_incident_key(rec)
        entry = incidents.get(key)
        ts = float(rec.get("timestamp", 0.0) or 0.0)
        state = str(rec.get("decision_state") or rec.get("state") or "").upper()
        # VERSION 11: alerts.json doesn't carry a bare "state" field directly on every
        # schema version -- reasoning_trail's last line ("Verdict: STATE / action --
        # ...") is the reliable source across versions when present.
        if not state:
            trail = rec.get("reasoning_trail") or []
            if trail:
                last = trail[-1]
                if last.startswith("Verdict: "):
                    state = last.split("Verdict: ", 1)[1].split(" /", 1)[0].strip()
        fp_verdict = (rec.get("fp_verdict") or {}).get("verdict", "")
        net_ctx = rec.get("network_context", {}) or {}
        device = rec.get("device", {}) or {}

        if entry is None:
            entry = {
                "first_seen": ts, "last_seen": ts, "occurrences": 0,
                "device_id": device.get("id", "unknown"),
                "hostname": device.get("hostname", "unknown"),
                "target": net_ctx.get("queried_domain") or net_ctx.get("destination_ip") or "unknown",
                "signature": signature_base(rec.get("signature", "unknown")),
                "max_severity_rank": -1, "max_severity_state": "",
                "confirmed_threat_count": 0, "suppressed_count": 0,
            }
            incidents[key] = entry

        entry["occurrences"] += 1
        entry["first_seen"] = min(entry["first_seen"], ts) if entry["first_seen"] else ts
        entry["last_seen"] = max(entry["last_seen"], ts)
        rank = _SEVERITY_RANK.get(state, -1)
        if rank > entry["max_severity_rank"]:
            entry["max_severity_rank"] = rank
            entry["max_severity_state"] = state or "unknown"
        if fp_verdict == "CONFIRMED_THREAT":
            entry["confirmed_threat_count"] += 1
        if rec.get("suppressed"):
            entry["suppressed_count"] += 1

    return incidents


def format_report(incidents: dict, top_n: int, min_occurrences: int) -> str:
    rows = [e for e in incidents.values() if e["occurrences"] >= min_occurrences]
    rows.sort(key=lambda e: (e["max_severity_rank"], e["occurrences"]), reverse=True)

    lines = [
        "# Incident Report",
        f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"{len(incidents)} distinct incident(s) found, showing top {min(top_n, len(rows))} "
        f"(min {min_occurrences} occurrence(s) each).",
        "",
        "| Severity | Occurrences | Device | Target | Signature | First Seen | Last Seen | Confirmed | Suppressed |",
        "|----------|-------------|--------|--------|-----------|------------|-----------|-----------|------------|",
    ]
    for e in rows[:top_n]:
        first = datetime.fromtimestamp(e["first_seen"]).strftime("%Y-%m-%d %H:%M") if e["first_seen"] else "?"
        last = datetime.fromtimestamp(e["last_seen"]).strftime("%Y-%m-%d %H:%M") if e["last_seen"] else "?"
        lines.append(
            f"| {e['max_severity_state'] or '?'} | {e['occurrences']} | {e['hostname']} | "
            f"{e['target']} | {e['signature']} | {first} | {last} | "
            f"{e['confirmed_threat_count']} | {e['suppressed_count']} |"
        )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=float, default=24.0, help="Only include alerts from the last N hours (default: 24)")
    parser.add_argument("--top", type=int, default=30, help="Max incidents to display, sorted by severity then occurrence count (default: 30)")
    parser.add_argument("--min-occurrences", type=int, default=1, help="Only show incidents with at least this many occurrences (default: 1)")
    args = parser.parse_args()

    path = _resolve_alerts_path()
    since_ts = time.time() - args.hours * 3600.0
    incidents = build_incidents(path, since_ts)
    print(format_report(incidents, args.top, args.min_occurrences))


if __name__ == "__main__":
    main()
