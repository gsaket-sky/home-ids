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
import logging
import argparse
from pathlib import Path
from datetime import datetime, timedelta

# Ensures the script can resolve modules from the src directory
sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import CONFIG
from intelligence.threat_intel import ThreatIntel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [RETRO-HUNTER] %(message)s")
LOGGER = logging.getLogger("retro_hunter")

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
                    if record.get("timestamp", 0) >= cutoff_time:
                        domain = record.get("domain")
                        if domain:
                            unique_domains.add(domain)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        LOGGER.error("Failed to parse historical stream: %s", e)
        
    return unique_domains

def main():
    parser = argparse.ArgumentParser(description="Retroactive Zero-Day Threat Hunter")
    parser.add_argument("--days", type=int, default=14, help="Number of days of history to scan.")
    args = parser.parse_args()

    # Load Active Intelligence Engine (Updated for Modular Architecture)
    ti = ThreatIntel(
        cache_dir        = str(Path(CONFIG.get("state_path", "/app/state/ids_state.json")).parent / "ti_cache"),
        otx_api_key      = CONFIG.get("otx_api_key", ""),
        refresh_interval = 3600
    )
    
    LOGGER.info("Warming up active Threat Intelligence databases...")
    # FIXED: Replaced targeted refresh with global refresh payload
    ti._refresh_all() 
    
    log_path = Path(CONFIG.get("alert_json_path", "/app/state/alerts.json")).with_name("alerts_stream.jsonl")
    historical_domains = load_historical_domains(log_path, args.days)
    
    if not historical_domains:
        LOGGER.info("No historical domains found to scan. Exiting.")
        return
        
    LOGGER.info("Extracted %d unique historical domains. Commencing Threat Intel detonation...", len(historical_domains))
    
    matches = []
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
        LOGGER.critical("🚨 RETROACTIVE THREATS DISCOVERED 🚨")
        LOGGER.critical("The following domains were accessed in the past %d days and have recently been classified as malicious:", args.days)
        for match in sorted(matches, key=lambda x: x["confidence"], reverse=True):
            LOGGER.critical(" -> [MATCH] Domain: %s | Source: %s | Confidence: %.2f | Tags: %s", 
                            match["domain"], match["source"], match["confidence"], match["tags"])
    else:
        LOGGER.info("✅ Retroactive hunt complete. Zero historical compromises detected against fresh intel.")

if __name__ == "__main__":
    main()