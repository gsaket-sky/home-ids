import os
import sys
import json
import time
import logging
import requests
from pathlib import Path
from datetime import datetime, timedelta

# Ensures the script can resolve modules from the src directory
sys.path.append(str(Path(__file__).resolve().parent.parent))
def load_config():
    config_path = Path(__file__).resolve().parent.parent.parent / "config.json"
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        LOGGER.error(f"Failed to load config: {e}")
        return {}
from intelligence.ai_soc import DeterministicValidator
from intelligence.hypotheses.evidence import Evidence

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [OLLAMA-SOC] %(message)s")
LOGGER = logging.getLogger("ollama_soc")

def save_config(config, config_path):
    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        LOGGER.info(f"Updated {config_path}")
    except Exception as e:
        LOGGER.error(f"Failed to update config.json: {e}")

def main():
    LOGGER.info("Starting Daily Ollama SOC Batch Analysis...")
    
    root_dir = Path(__file__).resolve().parent.parent.parent
    config_path = root_dir / "config.json"
    
    config = load_config()
    static_cfg = config.get("static_requires_restart", {})
    dyn_cfg = config.get("dynamic_live_reload", {})
    
    ollama_url = dyn_cfg.get("ollama_url", "http://127.0.0.1:11434").rstrip("/")
    ollama_model = dyn_cfg.get("ollama_model", "llama3.1")
    
    alerts_path = root_dir / static_cfg.get("alert_json_path", "state/alerts.json")
    if not alerts_path.exists():
        alerts_path = root_dir / "alerts.json"
    
    if not alerts_path.exists():
        LOGGER.error(f"Alerts file not found at {alerts_path}")
        return
        
    # 1. Parse last 24 hours of alerts
    yesterday = time.time() - (24 * 3600)
    alerts_to_analyze = []
    
    try:
        with open(alerts_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): continue
                try:
                    payload = json.loads(line)
                    if payload.get("timestamp", 0) > yesterday:
                        alerts_to_analyze.append(payload)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        LOGGER.error(f"Failed to read alerts.json: {e}")
        return
        
    if not alerts_to_analyze:
        LOGGER.info("No recent alerts found for analysis.")
        return
        
    LOGGER.info(f"Found {len(alerts_to_analyze)} alerts from the past 24 hours. Querying {ollama_model}...")
    
    # 2. Analyze each alert
    new_transparency_logs = []
    validator = DeterministicValidator()
    
    report_lines = [
        f"# 🛡️ Home-IDS Daily SOC Report",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Model:** {ollama_model}",
        "",
        "## Analyzed Threats",
        ""
    ]
    
    safe_host_patterns = dyn_cfg.get("safe_host_patterns", [])
    config_modified = False
    
    for payload in alerts_to_analyze:
        device_ip = payload.get("device", {}).get("ip", "unknown")
        risk = payload.get("risk", 0.0)
        
        system_prompt = (
            "You are an autonomous Tier 2 SOC Analyst for a Home Intrusion Detection System. "
            "Analyze the provided JSON alert payload. "
            "Your job is to analyze the evidence and determine if the activity is benign (e.g. telemetry, ads) or malicious. "
            "You must respond ONLY with a valid JSON object matching this schema: "
            "{\"classification\": \"benign|malicious\", \"confidence\": 0.0-1.0, \"reason\": \"<short executive summary>\", \"recommended_action\": \"suppress|block|none\"}"
        )
        prompt_text = f"Alert Payload:\n{json.dumps(payload, indent=2)}"
        
        # Build evidence objects for validation
        ev_store = []
        for ev_dict in payload.get("active_evidence", []):
            try:
                ev = Evidence(
                    type=ev_dict.get("type", "unknown"),
                    source=ev_dict.get("source", "unknown"),
                    timestamp=ev_dict.get("timestamp", 0.0),
                    device=device_ip,
                    value=ev_dict.get("value", 0.0),
                    confidence=ev_dict.get("confidence", 1.0),
                    independence_group=ev_dict.get("independence_group", "general")
                )
                ev_store.append(ev)
            except Exception: pass
            
        try:
            resp = requests.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": ollama_model, 
                    "system": system_prompt,
                    "prompt": prompt_text, 
                    "format": "json",
                    "stream": False
                },
                timeout=900.0
            )
            if resp.status_code == 200:
                response_text = resp.json().get("response", "").strip()
                try:
                    response_json = json.loads(response_text)
                except json.JSONDecodeError:
                    LOGGER.error(f"Failed to parse Ollama JSON: {response_text}")
                    continue
                    
                is_valid = validator.validate(response_json, ev_store)
                
                transparency_log = {
                    "type": "ollama_transparency",
                    "component": "batch_analyzer",
                    "device": {"ip": device_ip},
                    "timestamp": time.time(),
                    "original_alert_ts": payload.get("timestamp"),
                    "risk": risk,
                    "model": ollama_model,
                    "prompt": prompt_text,
                    "response": response_json,
                    "validator_passed": is_valid
                }
                new_transparency_logs.append(transparency_log)
                
                report_lines.append(f"### Target IP: `{device_ip}` (Risk: {risk})")
                report_lines.append(f"- **Classification:** `{response_json.get('classification', 'unknown').upper()}` (Confidence: {response_json.get('confidence', 0.0)})")
                report_lines.append(f"- **Summary:** {response_json.get('reason', 'N/A')}")
                report_lines.append(f"- **Recommended Action:** `{response_json.get('recommended_action', 'none')}`")
                report_lines.append(f"- **Validator Passed:** `{'YES' if is_valid else 'NO'}`")
                
                # Autonomous Action
                if is_valid and response_json.get('classification') == 'benign' and response_json.get('recommended_action') == 'suppress':
                    # Extract target domain from alert payload if available
                    target_domain = None
                    for hyp in payload.get("hypotheses", []):
                        if hyp.get("type") == "Malicious DNS":
                            target_domain = hyp.get("details", {}).get("domain")
                            break
                    if target_domain and target_domain not in safe_host_patterns:
                        safe_host_patterns.append(target_domain)
                        config_modified = True
                        report_lines.append(f"- **Autonomous Action Taken:** 🤖 Injected `{target_domain}` into `safe_host_patterns` to suppress future false positives.")
                        
                report_lines.append("")
                LOGGER.info(f"Analyzed {device_ip} (Risk {risk}): {response_json.get('reason')}")
            else:
                LOGGER.error(f"Ollama returned HTTP {resp.status_code}")
        except Exception as e:
            LOGGER.error(f"Failed to query Ollama for {device_ip}: {e}")
            
    # 3. Append transparency logs to alerts.json
    if new_transparency_logs:
        try:
            with open(alerts_path, "a", encoding="utf-8") as f:
                for log in new_transparency_logs:
                    f.write(json.dumps(log) + "\n")
        except Exception as e:
            LOGGER.error(f"Failed to write to alerts.json: {e}")
            
    # 4. Save Config if modified
    if config_modified:
        dyn_cfg["safe_host_patterns"] = safe_host_patterns
        save_config(config, config_path)
        
    # 5. Write Markdown Report
    reports_dir = root_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"soc_daily_report_{datetime.now().strftime('%Y%m%d')}.md"
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    LOGGER.info(f"Generated SOC Daily Report: {report_path}")

if __name__ == "__main__":
    main()
