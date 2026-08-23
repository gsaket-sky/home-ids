"""
suricata_scan.py - VERSION 11 (P2, review Suricata follow-up): real signature/exploit
detection, run in BATCH mode against reactive-capture burst pcaps -- never
continuously against live traffic.

Why batch mode: this codebase already has a reactive-capture mechanism
(fritzbox_capture.py) that captures a short pcap burst (rate-limited to a handful of
times per hour) and reprocesses it through Zeek. Suricata's actual value here is its
mature protocol parsers and its signature/rule engine (known-exploit and malware-C2
byte-pattern matching) -- neither of which this codebase has today. Running Suricata
CONTINUOUSLY inline against live traffic is the expensive, Raspberry-Pi-hostile way to
get that; running it once, for a few seconds, against an already-captured bounded pcap
file is not -- idle cost is exactly zero (no process running at all between bursts),
and "a few seconds of batch analysis on a short pcap" is a completely different
resource profile than continuous full-rate inline inspection. See config.yaml's
reactive_capture_suricata_* keys.

Deliberately does NOT ship or author Suricata rules -- re-curating threat
intelligence Suricata/Emerging Threats already maintains would be exactly the kind of
low-value reinvention this project should avoid. Point
reactive_capture_suricata_rules_path at a ruleset you manage with the standard
`suricata-update` tool (e.g. `suricata-update --etopen` with a trimmed/"security"
policy, not the full noisy feed) -- this module only runs whatever rules that file
contains and turns real MATCHES into Evidence.

Deliberately evidence-based like every other detector here (see
SuricataSignatureHypothesis in hypotheses/engine.py) -- EXCEPT for a genuinely
high-severity match (Suricata's own severity=1/"high"), which decision_engine.py
treats as an explicit hard-stop (has_confirmed_exploit), matching the review's own
"known malware signature" / "confirmed exploit" hard-stop categories. A real rule
match against a curated ruleset is close to definitional, not a fuzzy heuristic --
unlike everything fp_engine.py's Stage-1 used to independently re-derive from raw
features (VERSION 11's earlier fix), this is genuinely new information no other
detector here can produce.
"""
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from intelligence.hypotheses.evidence import Evidence

LOGGER = logging.getLogger("home_ids.suricata_scan")

# Suricata's own severity convention (alert.severity in eve.json): 1 = high priority
# (most severe), 2 = medium, 3 = low. Mapped to Evidence.confidence -- 0.9+ is what
# decision_engine.py's has_confirmed_exploit hard-stop requires, so only a genuine
# severity=1 match reaches that bar; 2/3 are real evidence, not a hard-stop.
_SEVERITY_TO_CONFIDENCE = {1: 0.95, 2: 0.70, 3: 0.45}
_DEFAULT_CONFIDENCE = 0.5


def run_suricata_on_pcap(pcap_path: Path, scratch_dir: Path, suricata_bin: str,
                          rules_path: Optional[str], timeout: float = 60.0) -> List[dict]:
    """Runs `suricata -r <pcap> -l <scratch_dir> -S <rules_path>` (batch/offline mode
    -- reads a file, exits, does not touch a live interface) and returns the parsed
    `event_type: alert` records from the resulting eve.json. Never raises -- a
    missing binary, a missing/empty rules file, or a timeout all just mean "no
    Suricata findings this burst," logged, not fatal to the rest of the capture
    pipeline (matching reprocess_with_zeek's own non-fatal-failure style)."""
    if not suricata_bin:
        return []
    if not rules_path or not Path(rules_path).exists():
        LOGGER.debug("Suricata rules_path not configured or missing -- skipping scan (%s).", rules_path)
        return []

    scratch_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        suricata_bin, "-r", str(pcap_path), "-l", str(scratch_dir),
        "-S", str(rules_path), "-k", "none", "--runmode=single",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode != 0:
            LOGGER.warning(
                "Suricata batch scan exited %d for %s -- treating as no findings. stderr=%s",
                result.returncode, pcap_path, (result.stderr or "")[-500:],
            )
    except FileNotFoundError:
        LOGGER.error("Suricata binary not found at '%s' -- reactive_capture_suricata_bin needs to "
                     "point at a real install. Skipping.", suricata_bin)
        return []
    except subprocess.TimeoutExpired:
        LOGGER.warning("Suricata batch scan timed out after %.0fs for %s -- skipping.", timeout, pcap_path)
        return []
    except Exception as exc:
        LOGGER.error("Suricata batch scan failed for %s: %s", pcap_path, exc)
        return []

    return _parse_eve_json_alerts(scratch_dir / "eve.json")


def _parse_eve_json_alerts(eve_path: Path) -> List[dict]:
    if not eve_path.exists():
        return []
    alerts: List[dict] = []
    try:
        with eve_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("event_type") == "alert":
                    alerts.append(rec)
    except Exception as exc:
        LOGGER.error("Failed reading Suricata eve.json at %s: %s", eve_path, exc)
    return alerts


def build_ip_to_device_map(state_manager) -> Dict[str, str]:
    """O(N) over tracked devices, same shape as fritzbox_capture.py's
    run_dns_evasion_audit's own device scan -- N is small (dozens, not millions) and
    this only runs on the same rate-limited reactive-capture budget."""
    mapping: Dict[str, str] = {}
    if state_manager is None:
        return mapping
    for dev_id in state_manager.get_all_device_ids():
        try:
            with state_manager.lock_device(dev_id) as state:
                ip = getattr(state, "client_ip", "")
                if ip:
                    mapping[ip] = dev_id
        except KeyError:
            continue  # device pruned between get_all_device_ids() and lock_device()
    return mapping


def suricata_alerts_to_evidence(alerts: List[dict], ip_to_device: Dict[str, str],
                                 capture_ts: float) -> Dict[str, List[Evidence]]:
    """Attributes each Suricata alert to a tracked device via whichever side
    (src_ip/dest_ip) is a known LAN client, and turns it into Evidence. An alert
    matching neither side to a tracked device is dropped -- nothing to attach it to.
    Returns {device_id: [Evidence]} for only devices with a real finding."""
    out: Dict[str, List[Evidence]] = {}
    for rec in alerts:
        src_ip = str(rec.get("src_ip", "") or "")
        dest_ip = str(rec.get("dest_ip", "") or "")
        device_id = ip_to_device.get(src_ip) or ip_to_device.get(dest_ip)
        if not device_id:
            continue
        # The OTHER side (not the tracked LAN device) is the real external target --
        # falls back to whichever IP isn't the matched device's own if both happen to
        # resolve (unusual, e.g. two tracked devices talking to each other).
        target_ip = dest_ip if ip_to_device.get(src_ip) == device_id else src_ip

        alert_meta = rec.get("alert", {}) or {}
        severity = alert_meta.get("severity")
        confidence = _SEVERITY_TO_CONFIDENCE.get(severity, _DEFAULT_CONFIDENCE)
        signature = alert_meta.get("signature", "unknown signature")
        signature_id = alert_meta.get("signature_id", "0")
        category = alert_meta.get("category", "unknown")

        ev = Evidence(
            type="suricata_signature_match",
            source="suricata",
            timestamp=capture_ts,
            device=device_id,
            value=1.0,
            confidence=confidence,
            independence_group="suricata",
            provenance=f"detector:suricata:{signature_id}:{category}:{signature}",
            domain=target_ip or None,
        )
        out.setdefault(device_id, []).append(ev)
    return out


def run_and_attribute(pcap_path: Path, scratch_dir: Path, suricata_bin: str,
                       rules_path: Optional[str], state_manager, capture_ts: float,
                       timeout: float = 60.0) -> Dict[str, List[Evidence]]:
    """Convenience wrapper: run_suricata_on_pcap() + build_ip_to_device_map() +
    suricata_alerts_to_evidence() in one call -- what fritzbox_capture.py's
    capture_and_ingest() actually calls per burst."""
    alerts = run_suricata_on_pcap(pcap_path, scratch_dir, suricata_bin, rules_path, timeout=timeout)
    if not alerts:
        return {}
    ip_map = build_ip_to_device_map(state_manager)
    return suricata_alerts_to_evidence(alerts, ip_map, capture_ts)
