import os
import sys
import json
import time
import logging
import requests
import yaml
from pathlib import Path
from datetime import datetime, timedelta

# Ensures the script can resolve modules from the src directory
sys.path.append(str(Path(__file__).resolve().parent.parent))


def _flatten_config_categories(raw: dict) -> dict:
    """Mirror config.py's LiveConfig._load() flattening rule: merge every top-level
    mapping whose name doesn't start with "_"/"#" into one flat key->value namespace.
    Category names in config.yaml are purely organizational -- this script reads the
    same flat keys regardless of which category they're grouped under."""
    flattened = {}
    for section_name, section_val in (raw or {}).items():
        if str(section_name).startswith("_") or str(section_name).startswith("#"):
            continue
        if isinstance(section_val, dict):
            flattened.update(section_val)
        else:
            flattened[section_name] = section_val
    return flattened


def load_config():
    """Returns the FLAT config namespace (already merged across every category)."""
    config_path = Path(__file__).resolve().parent.parent.parent / "config.yaml"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return _flatten_config_categories(raw)
    except Exception as e:
        LOGGER.error(f"Failed to load config: {e}")
        return {}
from intelligence.ai_soc import DeterministicValidator
from intelligence.hypotheses.evidence import Evidence

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [OLLAMA-SOC] %(message)s")
LOGGER = logging.getLogger("ollama_soc")

def save_config_key(config_path: Path, key: str, value) -> None:
    """Surgically update ONE key's value in config.yaml, preserving every existing
    comment, category grouping, and formatting -- unlike a plain yaml.safe_dump()
    (or the old json.dump() this replaces), which would silently blow away all of
    config.yaml's hand-written documentation the first time this ran. Uses
    ruamel.yaml's round-trip mode specifically for this. Locates whichever top-level
    category currently contains `key` and updates it there, so this keeps working
    even if you reorganize/rename categories later; falls back to a top-level write
    if the key isn't found under any category (shouldn't normally happen).

    KNOWN RUAMEL QUIRK, HANDLED: when a config.yaml key's comment describes the NEXT
    key (this file's style -- a blank line + comment sits between the end of one
    key's value and the start of the next), and that PRECEDING value is a list,
    ruamel attaches that comment internally to the list's *last item index*, not to
    the key itself. Naively replacing the list (`section_val[key] = new_list`) or
    even slice-assigning into it therefore silently drops that trailing comment the
    moment the new list's length changes the "last index" — verified empirically
    (adding a 7th item to safe_host_patterns dropped the entire device_type_overrides
    doc-comment on a naive implementation). Fixed below by explicitly relocating the
    comment from the old last-index to the new one before dumping, instead of relying
    on ruamel to carry it over automatically."""
    from ruamel.yaml import YAML
    yaml_rt = YAML()
    yaml_rt.preserve_quotes = True
    yaml_rt.width = 4096
    yaml_rt.indent(mapping=2, sequence=4, offset=2)
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            doc = yaml_rt.load(f)
        updated = False
        for section_val in doc.values():
            if isinstance(section_val, dict) and key in section_val:
                old_val = section_val[key]
                trailing_comment = None
                if isinstance(value, list) and hasattr(old_val, "ca") and old_val.ca and old_val.ca.items:
                    old_last_idx = len(old_val) - 1
                    trailing_comment = old_val.ca.items.pop(old_last_idx, None)
                if isinstance(value, list) and hasattr(old_val, "ca"):
                    # Mutate the SAME sequence object in place (not a rebind to a
                    # plain new list) so its .ca comment-attachment structure, and
                    # thus any comments NOT on the last index, survive untouched.
                    old_val[:] = value
                    if trailing_comment is not None:
                        new_last_idx = len(old_val) - 1
                        if new_last_idx >= 0:
                            old_val.ca.items[new_last_idx] = trailing_comment
                else:
                    section_val[key] = value
                updated = True
                break
        if not updated:
            doc[key] = value
        with open(config_path, "w", encoding="utf-8") as f:
            yaml_rt.dump(doc, f)
        LOGGER.info(f"Updated {key} in {config_path}")
    except Exception as e:
        LOGGER.error(f"Failed to update {config_path}: {e}")

def main():
    LOGGER.info("Starting Daily Ollama SOC Batch Analysis...")

    root_dir = Path(__file__).resolve().parent.parent.parent
    config_path = root_dir / "config.yaml"

    config = load_config()  # already flat -- merged across every config.yaml category

    ollama_url = config.get("ollama_url", "http://127.0.0.1:11434").rstrip("/")
    ollama_model = config.get("ollama_model", "llama3.1")

    alerts_path = root_dir / config.get("alert_json_path", "state/alerts.json")
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
    
    safe_host_patterns = config.get("safe_host_patterns", [])
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
        save_config_key(config_path, "safe_host_patterns", safe_host_patterns)
        
    # 5. Write Markdown Report
    reports_dir = root_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"soc_daily_report_{datetime.now().strftime('%Y%m%d')}.md"
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    LOGGER.info(f"Generated SOC Daily Report: {report_path}")

if __name__ == "__main__":
    main()
