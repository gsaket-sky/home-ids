"""
retro_hunter.py - Retroactive Threat Hunting Engine (Zero-Day Sweeper).

Scans historical DNS transaction logs against freshly updated OSINT and Threat Intelligence IOCs. 
Detects Zero-Day compromises that were completely unknown to the global security community 
at the time the traffic actually occurred.

RECENT FIXES:
- Modified sys.path logic to enable execution within the modular structure.
- FIXED (CRITICAL): Replaced targeted `_refresh_otx()` with global `_refresh_all()` 
  to safely synchronize URLHaus, FeodoTracker, ThreatFox, and OTX IOCs concurrently.
"""
import sys
import json
import time
import logging
import argparse
import urllib.request
from pathlib import Path
from datetime import datetime, timedelta

# Ensures the script can resolve modules from the src directory
sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import CONFIG
from intelligence.threat_intel import ThreatIntel
from intelligence.local_intel import LocalConfirmedIntel
from intelligence.fp_engine import AutonomousFPEngine
from utils import write_job_health

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [RETRO-HUNTER] %(message)s")
LOGGER = logging.getLogger("retro_hunter")


def _send_telegram(msg: str) -> None:
    """PHASE 9 FIX: run_retro_hunt() previously had exactly one output channel —
    LOGGER.critical() — for its single most important finding: a domain your network
    already talked to that's now known to be malicious. Between scripts/scheduler.py
    launching this as a subprocess.Popen with no stdout/stderr override, and main.py (see
    the scheduler_proc fix a few commits up) formerly piping THAT subprocess's own
    stdout/stderr to DEVNULL, every one of those log lines was unrecoverable — no
    journalctl entry, no file, no notification, nothing. Even with that now fixed, a
    genuine zero-day retroactive match deserves the same real-time channel every other
    finding in this codebase gets, not just a log line an operator has to think to go
    read. Mirrors scripts/top_domains_report.py's own send_telegram() helper."""
    token = CONFIG.get("telegram_token", "")
    chat_id = CONFIG.get("telegram_chat_id", "")
    if not token or not chat_id:
        return
    try:
        data = json.dumps({"chat_id": chat_id, "text": msg, "parse_mode": "HTML"}).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        LOGGER.error("Failed to send Telegram retro-hunt alert: %s", e)

def _count_findings_by_device(state_dir: Path) -> dict:
    """Per-device breakdown of retro-hunt findings, for the dashboard-redesign per-device
    metric. Scoped to "local_intel_retro_match" records ONLY -- the other record type
    ("retro_hunt_match", the external-ThreatIntel historical-domain re-scan) is
    genuinely device-agnostic by construction: load_historical_domains() extracts a
    fleet-wide SET of unique domains with no per-device attribution retained at all, so
    there is no device to attribute those findings to. Returns {device_id: {"hostname":
    str, "count": int}}."""
    findings_path = state_dir / "retro_hunt_findings.jsonl"
    if not findings_path.exists():
        return {}
    by_device: dict = {}
    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                if entry.get("type") != "local_intel_retro_match":
                    continue
                dev_id = entry.get("device_id")
                if not dev_id or dev_id == "unknown":
                    continue
                bucket = by_device.setdefault(dev_id, {"hostname": entry.get("hostname") or "unknown", "count": 0})
                bucket["count"] += 1
    except Exception:
        return {}
    return by_device

def _count_findings(state_dir: Path) -> int:
    """Cumulative retro-hunt match count, read straight from the append-only findings
    file itself rather than a separately-maintained running counter -- avoids any
    chance of the relay stat drifting out of sync with the actual source of truth."""
    findings_path = state_dir / "retro_hunt_findings.jsonl"
    if not findings_path.exists():
        return 0
    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def load_historical_domains(log_path: Path, days_back: int) -> set:
    """Parses massive JSONL log streams efficiently to extract unique queried domains."""
    cutoff_time = (datetime.now() - timedelta(days=days_back)).timestamp()
    unique_domains = set()
    
    if not log_path.exists():
        LOGGER.error("Historical log path %s does not exist. Aborting hunt.", log_path)
        return unique_domains

    LOGGER.info("Scanning history in %s looking back %d days...", log_path.name, days_back)
    
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    record = json.loads(line)
                    ts = float(record.get("timestamp", 0) or 0)
                    if ts < cutoff_time:
                        continue
                    domain = (
                        record.get("domain")
                        or record.get("network_context", {}).get("queried_domain")
                        or record.get("target_domain")
                    )
                    if domain:
                        unique_domains.add(str(domain).lower().strip("."))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        LOGGER.error("Failed to parse historical stream: %s", e)
        
    return unique_domains


def check_local_intel_history(log_path: Path, local_intel: LocalConfirmedIntel, days_back: int) -> list:
    """PHASE 21D3: retroactive cross-device check against the LOCAL confirmed-intel
    store (local_intel.py), not the external ThreatIntel feeds load_historical_domains()
    /the rest of this module checks against. When any device gets confirmed touching a
    malicious IP/domain (fp_engine.py's Stage-1 hard-stop, or pipeline.py's HIGH/
    CRITICAL bar), that IOC only hard-stops FUTURE connections from other devices --
    this catches "device B also touched this IOC three days ago but wasn't over its own
    detection threshold at the time," using intel the network only just learned.

    Returns a list of {device_id, hostname, matched_kind, matched_value, ts,
    confirmed_by} dicts -- one per historical alert whose domain/destination_ip matches
    a confirmed IOC, EXCLUDING alerts from a device that's already one of that IOC's own
    confirmed sources (that device already triggered its own hard-stop at the time; the
    genuinely new finding here is a DIFFERENT, not-yet-flagged device)."""
    cutoff_time = (datetime.now() - timedelta(days=days_back)).timestamp()
    matches = []

    if not log_path.exists():
        return matches

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = float(record.get("timestamp", 0) or 0)
                if ts < cutoff_time:
                    continue
                device_id = record.get("device", {}).get("id", "unknown")
                hostname = record.get("device", {}).get("hostname", "unknown")
                network_context = record.get("network_context", {}) or {}
                domain = str(network_context.get("queried_domain") or "").lower().strip(".")
                dest_ip = str(network_context.get("destination_ip") or "")

                for kind, value in (("domain", domain), ("ip", dest_ip)):
                    if not value or value == "unknown":
                        continue
                    entry = local_intel.check(kind, value)
                    if not entry:
                        continue
                    if device_id in entry.get("sources", []):
                        continue  # this device already confirmed it itself -- not a new finding
                    matches.append({
                        "device_id": device_id, "hostname": hostname,
                        "matched_kind": kind, "matched_value": value, "ts": ts,
                        "confirmed_by": entry.get("sources", []),
                    })
    except Exception as e:
        LOGGER.error("Failed to parse historical stream for local-intel cross-reference: %s", e)

    return matches


def run_retro_hunt(days: int = 14) -> None:
    """Executes the retroactive threat hunt for a given number of days."""
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    # Load Active Intelligence Engine (Updated for Modular Architecture)
    ti = ThreatIntel(
        # Same stale "/app/state/..." Docker-era fallback as main.py's ti_cache --
        # inconsistent with this very function's OWN state_dir line just above, which
        # already uses the correct "state/ids_state.json" default.
        cache_dir        = str(Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "ti_cache"),
        otx_api_key      = CONFIG.get("otx_api_key", ""),
        refresh_interval = 3600
    )
    
    LOGGER.info("Warming up active Threat Intelligence databases...")
    # FIXED: Replaced targeted refresh with global refresh payload
    ti._refresh_all() 
    
    # PHASE 9 FIX: the default value here (/app/state/alerts_stream.jsonl) is a leftover
    # from an earlier Docker-based layout this project no longer uses (see the v3.0.0
    # changelog: "removes hardcoded Docker dependencies"), and the fallback filename
    # ("alerts_stream.jsonl") is a file GEMINI.md explicitly says must never be referenced
    # — "the current architecture strictly expects alerts.json for Promtail/Loki
    # scraping." Both were dead in practice (alert_json_path is correctly "alerts.json" in
    # the live config, so the primary branch always won), but if it were ever briefly
    # unset or the file briefly missing, this would have silently hunted the wrong,
    # nonexistent file forever instead of erroring. Mirrors ollama_soc.py's own
    # already-correct fallback-to-the-real-filename pattern.
    alert_path_cfg = Path(CONFIG.get("alert_json_path", "state/alerts.json"))
    log_path = alert_path_cfg if alert_path_cfg.exists() else alert_path_cfg.with_name("alerts.json")
    historical_domains = load_historical_domains(log_path, days)

    matches = []
    if not historical_domains:
        LOGGER.info("No historical domains found to scan against external Threat Intel.")
    else:
        LOGGER.info("Extracted %d unique historical domains. Commencing Threat Intel detonation...", len(historical_domains))
        for domain in historical_domains:
            ti_result = ti.lookup_domain(domain)
            if ti_result:
                matches.append({
                    "domain": domain,
                    "confidence": ti_result.get("confidence", 0.0),
                    "tags": ti_result.get("tags", []),
                    "source": ti_result.get("source", "unknown")
                })

    if matches:
        matches_sorted = sorted(matches, key=lambda x: x["confidence"], reverse=True)
        LOGGER.critical("🚨 RETROACTIVE THREATS DISCOVERED 🚨")
        LOGGER.critical("The following domains were accessed in the past %d days and have recently been classified as malicious:", days)
        for match in matches_sorted:
            LOGGER.critical(" -> [MATCH] Domain: %s | Source: %s | Confidence: %.2f | Tags: %s", 
                            match["domain"], match["source"], match["confidence"], match["tags"])

        # PHASE 9 FIX: durable record, separate from alerts.json on purpose — that file
        # feeds train_fp_classifier.py's label=0 threat set and ollama_soc.py's 24h
        # analysis window, both of which expect the live pipeline's real alert schema
        # (device/network_context/features). A retro-hunt match has none of that (no
        # active device state, no computed features at the time of the original
        # connection) — forcing it into that schema would either crash extraction or, worse,
        # get silently reinterpreted as something it isn't. A dedicated JSONL append,
        # same pattern as state/autonomous_muted.jsonl, avoids that class of bug entirely.
        try:
            findings_path = Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "retro_hunt_findings.jsonl"
            with open(findings_path, "a", encoding="utf-8") as f:
                for match in matches_sorted:
                    f.write(json.dumps({
                        "type": "retro_hunt_match", "ts_unix": time.time(),
                        "ts_human": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "lookback_days": days, **match,
                    }) + "\n")
        except Exception as e:
            LOGGER.error("Failed to write retro_hunt_findings.jsonl: %s", e)

        top = matches_sorted[:10]
        lines = [f"🚨 <b>Retroactive Threat Hunt: {len(matches)} match(es)</b>",
                 f"Domains queried in the past {days}d, now classified malicious by fresh intel:", ""]
        for match in top:
            lines.append(f"• <code>{match['domain']}</code> — {match['source']}, confidence {match['confidence']:.2f}")
        if len(matches) > len(top):
            lines.append(f"...and {len(matches) - len(top)} more (see retro_hunt_findings.jsonl)")
        _send_telegram("\n".join(lines)[:4000])
    else:
        LOGGER.info("✅ Retroactive hunt complete. Zero historical compromises detected against fresh intel.")

    # PHASE 21D3: separate cross-reference against the LOCAL confirmed-intel store --
    # catches "device B also touched this IOC three days ago but wasn't over ITS OWN
    # detection threshold at the time," using intel the network only just learned from
    # a DIFFERENT device's confirmed threat. See check_local_intel_history()'s
    # docstring. Independent of the external-ThreatIntel pass above -- runs even when
    # historical_domains was empty, since it also checks destination_ip, not just domain.
    local_intel = LocalConfirmedIntel(state_dir)
    local_matches = check_local_intel_history(log_path, local_intel, days)
    if local_matches:
        LOGGER.critical("🌐 RETROACTIVE LOCAL-INTEL MATCHES: %d historical connection(s) from a "
                         "device match an IOC confirmed by a DIFFERENT device since then.", len(local_matches))

        # BUGFIX (2026-08-27, third-party review): this pass used to be notify-only --
        # check_local_intel_history() found the match, but nothing ever fed it back into
        # fp_engine's own confirmed-threat bookkeeping (local_intel record/count, sigma
        # tune-up) for the NEWLY-implicated device, unlike every other confirmation path
        # in this codebase. Now closes that loop the same way: record_confirmed_threat()
        # (re-confirms/refreshes the existing local_intel entry rather than duplicating
        # it -- record() is idempotent per value) + a sigma tune-up for this device.
        # asn_owner isn't available from historical alert records here, so the
        # cloud/CDN-org protection layer doesn't apply on this path specifically -- the
        # entry being matched against already passed through record_confirmed_threat()'s
        # other guards (safe_ips/private/multicast/telemetry-domain) when it was first
        # confirmed, so this isn't a new poisoning vector, just missing an extra layer.
        # CONFIG (config.py's LiveConfig) exposes .get() directly -- confirmed via this
        # file's own pre-existing _send_telegram() already calling CONFIG.get(...) --
        # AutonomousFPEngine only ever calls .get() on its config param, so it's passed
        # through as-is rather than guessing at LiveConfig's internal storage attribute.
        fp_engine = AutonomousFPEngine(config=CONFIG, state_dir=str(state_dir))
        for m in local_matches:
            base_domain = m["matched_value"] if m["matched_kind"] == "domain" else None
            dest_ip = m["matched_value"] if m["matched_kind"] == "ip" else None
            fp_engine.record_confirmed_threat(
                m["device_id"], base_domain, dest_ip, reason="RETRO_HUNT_LOCAL_INTEL_MATCH",
            )
            fp_engine._apply_sigma_shift(m["device_id"], m["hostname"], direction="TUNE_UP", source="autonomous")

        try:
            findings_path = Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "retro_hunt_findings.jsonl"
            with open(findings_path, "a", encoding="utf-8") as f:
                for m in local_matches:
                    f.write(json.dumps({
                        "type": "local_intel_retro_match", "ts_unix": time.time(),
                        "ts_human": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "lookback_days": days, **m,
                    }) + "\n")
        except Exception as e:
            LOGGER.error("Failed to write local-intel retro findings: %s", e)

        top_local = local_matches[:10]
        lines = [f"🌐 <b>Retroactive Local-Intel Cross-Reference: {len(local_matches)} match(es)</b>",
                 f"Devices that touched a since-confirmed-malicious IP/domain in the past {days}d:", ""]
        for m in top_local:
            lines.append(f"• <code>{m['hostname']}</code> ({m['device_id']}) → {m['matched_kind']} "
                          f"<code>{m['matched_value']}</code>, confirmed by {m['confirmed_by']}")
        if len(local_matches) > len(top_local):
            lines.append(f"...and {len(local_matches) - len(top_local)} more (see retro_hunt_findings.jsonl)")
        _send_telegram("\n".join(lines)[:4000])
    else:
        LOGGER.info("✅ No historical connections match the local confirmed-intel store.")
    local_intel.prune_expired()

    write_job_health(state_dir, "retro_hunter", time.time() - run_start, extra={
        "findings_count": _count_findings(state_dir),
        "findings_by_device": _count_findings_by_device(state_dir),
    })

def main():
    parser = argparse.ArgumentParser(description="Retroactive Zero-Day Threat Hunter")
    parser.add_argument("--days", type=int, default=14, help="Number of days of history to scan.")
    args = parser.parse_args()
    
    run_retro_hunt(days=args.days)

if __name__ == "__main__":
    main()