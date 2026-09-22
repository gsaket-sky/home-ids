import os
import sys
import time
import json
import sqlite3
import logging
import urllib.request
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# Setup Path
sys.path.append(str(Path(__file__).parent.parent))
from config import CONFIG
from intelligence.threat_intel import ThreatIntel
from utils import write_job_health

LOGGER = logging.getLogger("home_ids.top_domains")

def send_telegram(msg: str):
    token = CONFIG.get("telegram_token")
    chat_id = CONFIG.get("telegram_chat_id")
    if not token or not chat_id:
        return
        
    try:
        data = json.dumps({"chat_id": chat_id, "text": msg, "parse_mode": "HTML"}).encode('utf-8')
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data, headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        LOGGER.error(f"Failed to send Telegram report: {e}")

def get_device_names():
    state_path = CONFIG.get("state_path")
    mapping = {}
    if state_path and Path(state_path).exists():
        try:
            with open(state_path, "r") as f:
                data = json.load(f)
                for ip, d in data.get("devices", {}).items():
                    hostname = d.get("hostname")
                    if hostname and hostname != "unknown":
                        mapping[ip] = hostname
        except Exception:
            pass
    return mapping

def generate_report():
    LOGGER.info("Generating Top Domains per Device Report...")
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    db_path = CONFIG.get("pihole_db", "/etc/pihole/pihole-FTL.db")
    if not os.path.exists(db_path):
        LOGGER.error(f"Pi-hole database not found at {db_path}")
        return

    # Look back 24 hours
    ts_24h_ago = int(time.time() - 86400)
    
    # Query Pi-hole for top domains per device
    device_domains = defaultdict(lambda: defaultdict(int))
    
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            # Query all domains in the last 24h
            cur = conn.execute("SELECT client, domain FROM queries WHERE timestamp > ? AND type = 1", (ts_24h_ago,))
            for client, domain in cur:
                device_domains[client][domain] += 1
    except Exception as e:
        LOGGER.error(f"Failed to query Pi-hole database: {e}")
        return

    if not device_domains:
        LOGGER.info("No DNS queries found in the last 24 hours.")
        write_job_health(state_dir, "top_domains_report", time.time() - run_start)
        return

    # Initialize Threat Intel engine (it will load cache from disk)
    ti_engine = ThreatIntel(
        cache_dir=str(Path(CONFIG.get("state_path")).parent / "ti_cache"),
        otx_api_key=CONFIG.get("otx_api_key", "")
    )
    device_names = get_device_names()
    safe_ips = set(CONFIG.get("safe_ips", []))
    
    report_lines = []
    report_lines.append("# 📊 Top Domains per Device (Last 24 Hours)")
    report_lines.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("")
    
    telegram_summary = ["<b>📊 Top Domains Report (24h)</b>\n"]
    malicious_found = 0

    for client_ip, domains in sorted(device_domains.items()):
        if client_ip in safe_ips or client_ip.startswith("127."):
            continue
            
        hostname = device_names.get(client_ip, "Unknown")
        report_lines.append(f"## Device: {hostname} (`{client_ip}`)")
        report_lines.append("| Count | Domain | Threat Level |")
        report_lines.append("|-------|--------|--------------|")
        
        # Sort domains by count descending, take top 10
        top_10 = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]
        
        device_malicious = 0
        for domain, count in top_10:
            threat_level = "🟢 Safe"
            
            # Simple heuristic / TI check
            if ti_engine.check_domain(domain):
                threat_level = "🔴 Malicious"
                device_malicious += 1
                malicious_found += 1
            elif domain.endswith(".local") or domain.endswith(".lan"):
                threat_level = "🔵 Local"
            
            report_lines.append(f"| {count} | {domain} | {threat_level} |")
            
        report_lines.append("")
        
        # Add to telegram summary
        telegram_summary.append(f"🖥️ <b>{hostname}</b> ({client_ip})")
        telegram_summary.append(f"Top: <code>{top_10[0][0]}</code> ({top_10[0][1]} reqs)")
        if device_malicious > 0:
            telegram_summary.append(f"⚠️ {device_malicious} malicious domains detected!")
        telegram_summary.append("")

    # Save Markdown Report
    state_path = Path(CONFIG.get("state_path"))
    if state_path.name == "ids_state.json":
        # Ensure we are saving relative to the state dir properly
        reports_dir = state_path.parent.parent / "reports"
    else:
        reports_dir = state_path.parent / "reports"
        
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / f"top_domains_{datetime.now().strftime('%Y%m%d')}.md"
    
    try:
        # Atomic write (temp file + os.replace()) -- a kill mid-write (OOM, a forced
        # restart, or a SIGKILL of this job while resource-aware scheduling has it
        # SIGSTOP-paused) can then never leave a truncated report at the final path.
        tmp_report_file = report_file.with_name(report_file.name + ".tmp")
        tmp_report_file.write_text("\n".join(report_lines))
        os.replace(tmp_report_file, report_file)
        LOGGER.info(f"Report saved to {report_file}")
    except Exception as e:
        LOGGER.error(f"Failed to write report file: {e}")

    # Send Telegram Summary
    if malicious_found > 0:
        telegram_summary.insert(1, f"🚨 <b>Warning:</b> {malicious_found} malicious/flagged domains queried across the network!\n")
        
    telegram_text = "\n".join(telegram_summary)[:4000] # Telegram limit
    send_telegram(telegram_text)

    write_job_health(state_dir, "top_domains_report", time.time() - run_start)

if __name__ == "__main__":
    # Configure basic logging if run directly
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    generate_report()
