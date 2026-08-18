import os
import sys
import json
import time
import logging
import requests
import yaml
from pathlib import Path
from collections import defaultdict
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
from intelligence.fp_engine import AutonomousFPEngine
from mitigation.ips import IPSMitigator
from core.state_guard import StateManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [OLLAMA-SOC] %(message)s")
LOGGER = logging.getLogger("ollama_soc")

# PHASE 11 FIX: a live diagnostic run on the actual server showed a single trivial
# "say hello" /api/generate call taking 849s total_duration while the model's own
# reported load+eval durations summed to only ~13s — ~836s of that was pure CPU-
# contention queueing (the server was observed at 300%+ CPU). With no dedup, this
# script was calling Ollama once per alert in the last 24h — and a single noisy
# threat pattern (confirmed in a live alerts.json: one device/destination pair firing
# 54 times in 11 hours) meant one recurring pattern alone could cost 50+ multi-minute
# calls in a single run. That's the real reason no soc_daily_report has ever had
# content: any run either took far longer than the 4h gap to its next scheduled
# invocation, or individual calls timed out against the 900s request timeout. Per
# explicit direction: "use ollama sparingly and only when absolutely needed", "save
# every redundant call to it with no repeat query on same threat". The fix has three
# parts, all below: (1) group alerts by device+target+signature and query ONCE per
# group, not once per alert — collapses the 54-alert case to 1 call; (2) persist
# verdicts to a cache file with a TTL so the SAME pattern recurring across separate
# scheduled runs (every 4h) doesn't re-query either; (3) a hard cap on fresh queries
# per run so one unusually noisy day can't turn into an hours-long run regardless.
DEFAULT_CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days -- matches this codebase's other
                                            # weekly cadence (fp_engine's own retrain loop)
DEFAULT_MAX_QUERIES_PER_RUN = 5             # 5 x up to ~15min worst-case (900s request
                                            # timeout) = 75min worst case, well inside the
                                            # 4h gap between scheduled runs


def _target_for_key(payload: dict) -> str:
    """Best available identifier for 'what was this alert about' -- prefers the resolved
    domain, falls back to the raw destination IP for connections with no DNS resolution
    (e.g. the 149.154.166.110/Telegram case), matching the same fallback pipeline.py's
    own alert-message target_display logic already uses."""
    nc = payload.get("network_context", {}) or {}
    domain = nc.get("queried_domain", "") or ""
    if domain and domain != "unknown":
        return domain
    dest_ip = nc.get("destination_ip", "") or ""
    return dest_ip or "unknown"


def _cache_key(payload: dict) -> str:
    """Canonical 'same threat' identity: same device, same target, same signature. This is
    deliberately coarser than a per-event key (e.g. it ignores the exact timestamp) --
    the whole point is that repeat firings of the identical pattern collapse to one key."""
    device_id = payload.get("device", {}).get("id", "unknown")
    signature = payload.get("signature", "unknown")
    return f"{device_id}|{_target_for_key(payload)}|{signature}"


def _load_cache(cache_path: Path, ttl_seconds: float) -> dict:
    if not cache_path.exists():
        return {}
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception as e:
        LOGGER.warning(f"Could not read ollama analysis cache ({e}) -- starting fresh.")
        return {}
    now = time.time()
    fresh = {k: v for k, v in raw.items() if isinstance(v, dict) and (now - float(v.get("ts", 0.0))) < ttl_seconds}
    pruned = len(raw) - len(fresh)
    if pruned:
        LOGGER.info(f"Pruned {pruned} expired entries from ollama analysis cache.")
    return fresh


def _save_cache(cache_path: Path, cache: dict) -> None:
    try:
        cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception as e:
        LOGGER.error(f"Failed to save ollama analysis cache: {e}")


def _query_ollama(ollama_url: str, ollama_model: str, prompt_text: str, system_prompt: str) -> dict:
    """Single /api/generate call. Returns the parsed response JSON, or None on any
    failure (HTTP error, timeout, malformed JSON) -- caller decides how to log/handle."""
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
    if resp.status_code != 200:
        LOGGER.error(f"Ollama returned HTTP {resp.status_code}")
        return None
    response_text = resp.json().get("response", "").strip()
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        LOGGER.error(f"Failed to parse Ollama JSON: {response_text}")
        return None


def main():
    LOGGER.info("Starting Daily Ollama SOC Batch Analysis...")

    root_dir = Path(__file__).resolve().parent.parent.parent

    config = load_config()  # already flat -- merged across every config.yaml category

    ollama_url = config.get("ollama_url", "http://127.0.0.1:11434").rstrip("/")
    ollama_model = config.get("ollama_model", "llama3.1")
    cache_ttl_seconds = float(config.get("ollama_cache_ttl_seconds", DEFAULT_CACHE_TTL_SECONDS))
    max_queries_per_run = int(config.get("ollama_max_queries_per_run", DEFAULT_MAX_QUERIES_PER_RUN))

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
                    # PHASE 9 FIX: this file is also where THIS SCRIPT appends its own
                    # "ollama_transparency" entries a few dozen lines down. Without a type
                    # filter, tomorrow's run would read today's transparency logs back in as
                    # if they were fresh alerts and re-query the LLM about them.
                    if payload.get("type") != "ids_alert":
                        continue
                    # PHASE 11 FIX: fp_engine already runs a fast, cheap 3-stage check on
                    # EVERY alert before it's published; entries with suppressed=True were
                    # already confidently resolved as false positives by that pipeline. Ollama
                    # is the expensive, scarce resource here -- spend it only on alerts that
                    # actually needed a human/LLM judgment call because CL-AFPE didn't
                    # resolve them with confidence, not on ones already closed out.
                    if payload.get("suppressed"):
                        continue
                    if payload.get("timestamp", 0) > yesterday:
                        alerts_to_analyze.append(payload)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        LOGGER.error(f"Failed to read alerts.json: {e}")
        return

    if not alerts_to_analyze:
        LOGGER.info("No recent (published, non-suppressed) alerts found for analysis.")
        return

    # 2. Group into "same threat" buckets -- one Ollama call per bucket, not per alert.
    groups: dict = defaultdict(list)
    for payload in alerts_to_analyze:
        groups[_cache_key(payload)].append(payload)
    # Largest/noisiest patterns first, so if the per-run cap is hit, the highest-impact
    # patterns are the ones that actually got analyzed this run.
    ordered_keys = sorted(groups.keys(), key=lambda k: len(groups[k]), reverse=True)

    LOGGER.info(
        f"{len(alerts_to_analyze)} alert(s) collapsed into {len(groups)} distinct threat "
        f"pattern(s) (device+target+signature). Cache TTL={cache_ttl_seconds/3600:.1f}h, "
        f"max {max_queries_per_run} fresh Ollama call(s) this run."
    )

    cache_path = Path(config.get("state_path", "state/ids_state.json")).parent / "ollama_analysis_cache.json"
    cache = _load_cache(cache_path, cache_ttl_seconds)

    validator = DeterministicValidator()
    fp_engine = AutonomousFPEngine(config=config, state_dir=str(root_dir / "state"))

    # PHASE 14: mirrors middleware/routers/pihole_api.py's _ipc_immunize_logic() pattern --
    # a fresh StateManager + IPSMitigator per run, used only to release a Pi-hole block for
    # a domain this run just immunized. unblock_domain() makes a real Pi-hole API call
    # regardless of which process instantiated the client, so this has the same real-world
    # effect as the live pipeline calling it directly. Per explicit direction: an
    # autonomous correction should also undo containment that's no longer warranted, not
    # just stop future alerts -- block only what's absolutely necessary.
    state_manager = StateManager(state_path=str(Path(config.get("state_path", "state/ids_state.json"))))
    state_manager.load_from_disk()
    ips_mitigator = IPSMitigator(config=config, state_manager=state_manager)

    report_lines = [
        f"# 🛡️ Home-IDS Daily SOC Report",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Model:** {ollama_model}",
        f"**Alerts seen:** {len(alerts_to_analyze)} → **{len(groups)} distinct threat pattern(s)**",
        "",
        "## Analyzed Threats",
        ""
    ]

    new_transparency_logs = []
    queries_made = 0
    cache_hits = 0
    deferred = 0

    system_prompt = (
        "You are an autonomous Tier 2 SOC Analyst for a Home Intrusion Detection System. "
        "Analyze the provided JSON alert payload. "
        "Your job is to analyze the evidence and determine if the activity is benign (e.g. telemetry, ads) or malicious. "
        "You must respond ONLY with a valid JSON object matching this schema: "
        "{\"classification\": \"benign|malicious\", \"confidence\": 0.0-1.0, \"reason\": \"<short executive summary>\", \"recommended_action\": \"suppress|block|none\"}"
    )

    for key in ordered_keys:
        members = groups[key]
        representative = members[0]  # most recent structure is representative enough for a pattern-level verdict
        device_ip = representative.get("device", {}).get("ip", "unknown")
        risk = representative.get("risk", 0.0)
        target = _target_for_key(representative)

        cached = cache.get(key)
        if cached:
            response_json = {
                "classification": cached.get("classification", "unknown"),
                "confidence": cached.get("confidence", 0.0),
                "reason": cached.get("reason", ""),
                "recommended_action": cached.get("recommended_action", "none"),
            }
            is_valid = bool(cached.get("validator_passed", False))
            cache_hits += 1
            cache_age_h = (time.time() - float(cached.get("ts", time.time()))) / 3600.0
            LOGGER.info(f"[CACHE HIT] {device_ip} -> {target} ({len(members)} alert(s), cached {cache_age_h:.1f}h ago) -- skipping Ollama call.")
        elif queries_made >= max_queries_per_run:
            deferred += 1
            LOGGER.info(f"[DEFERRED] {device_ip} -> {target} ({len(members)} alert(s)) -- per-run query cap ({max_queries_per_run}) reached, will retry next run.")
            report_lines.append(f"### Target: `{target}` (Device: `{device_ip}`, {len(members)} alert(s))")
            report_lines.append("- **Status:** `DEFERRED` -- per-run Ollama query cap reached, will retry on the next scheduled run.")
            report_lines.append("")
            continue
        else:
            prompt_text = f"Alert Payload:\n{json.dumps(representative, indent=2)}"
            feats = representative.get("features", {}) or {}
            rep_value = max(
                float(feats.get("ti_risk", 0.0) or 0.0),
                float(feats.get("abuseipdb_risk", 0.0) or 0.0),
                float(feats.get("vt_risk", 0.0) or 0.0),
            )
            ev_store = []
            if rep_value > 0.0:
                ev_store.append(Evidence(
                    type="reputation", source="threat_intel", timestamp=representative.get("timestamp", time.time()),
                    device=device_ip, value=rep_value, confidence=0.95 if rep_value >= 4.0 else 0.8,
                    independence_group="reputation", provenance="ollama_soc:reconstructed_from_features",
                ))

            try:
                queries_made += 1
                LOGGER.info(f"[QUERY {queries_made}/{max_queries_per_run}] {device_ip} -> {target} ({len(members)} alert(s) collapsed into this one call)...")
                response_json = _query_ollama(ollama_url, ollama_model, prompt_text, system_prompt)
            except Exception as e:
                LOGGER.error(f"Failed to query Ollama for {device_ip} -> {target}: {e}")
                response_json = None

            if response_json is None:
                continue

            is_valid = validator.validate(response_json, ev_store)
            cache[key] = {
                "classification": response_json.get("classification", "unknown"),
                "confidence": response_json.get("confidence", 0.0),
                "reason": response_json.get("reason", ""),
                "recommended_action": response_json.get("recommended_action", "none"),
                "validator_passed": is_valid,
                "model": ollama_model,
                "ts": time.time(),
                "action_taken": False,
            }

        # PHASE 9/11: one transparency log per PATTERN, not per repeat alert -- keeps
        # alerts.json growth bounded to the number of distinct threats, not the number of
        # times a noisy one happened to fire.
        new_transparency_logs.append({
            "type": "ollama_transparency",
            "component": "batch_analyzer",
            "device": {"ip": device_ip},
            "timestamp": time.time(),
            "original_alert_ts": representative.get("timestamp"),
            "risk": risk,
            "model": ollama_model,
            "cache_key": key,
            "alerts_covered": len(members),
            "response": response_json,
            "validator_passed": is_valid,
        })

        report_lines.append(f"### Target: `{target}` (Device: `{device_ip}`, {len(members)} alert(s) covered by this analysis)")
        report_lines.append(f"- **Classification:** `{response_json.get('classification', 'unknown').upper()}` (Confidence: {response_json.get('confidence', 0.0)})")
        report_lines.append(f"- **Summary:** {response_json.get('reason', 'N/A')}")
        report_lines.append(f"- **Recommended Action:** `{response_json.get('recommended_action', 'none')}`")
        report_lines.append(f"- **Validator Passed:** `{'YES' if is_valid else 'NO'}`")

        # PHASE 9 FIX (autonomous action): calls fp_engine.mark_false_positive() -- the same
        # mechanism the "🛡️ Mark False Positive" Telegram button uses -- instead of writing
        # to safe_host_patterns (a device-hostname key, not a domain-suppression one; see the
        # Phase 9 history below for why that was always a no-op).
        # PHASE 11 FIX: only take this action ONCE per pattern (action_taken flag in the
        # cache entry), not on every cache-hit re-run of the same still-recurring pattern --
        # re-immunizing an already-immunized domain and re-widening an already-widened sigma
        # every 4 hours for the identical verdict is exactly the kind of redundant repeat
        # work this whole rewrite exists to eliminate.
        already_actioned = bool(cache.get(key, {}).get("action_taken"))
        if is_valid and response_json.get('classification') == 'benign' and response_json.get('recommended_action') == 'suppress' and not already_actioned:
            target_domain = representative.get("network_context", {}).get("queried_domain", "") or ""
            if target_domain and target_domain != "unknown":
                alert_hostname = representative.get("device", {}).get("hostname", "unknown")
                # PHASE 13: tagged distinctly from a real Telegram operator tap, so
                # train_fp_classifier.py's threshold self-calibration can tell "the LLM
                # validated this, autonomously, every 4h" apart from "a human confirmed
                # this" — the former is now the PRIMARY, human-independent calibration
                # signal; the latter remains valid and optional on top.
                mark_result = fp_engine.mark_false_positive(representative, alert_hostname, target_domain, source="llm_validated")
                base_domain = mark_result.get("base_domain", "")
                if key in cache:
                    cache[key]["action_taken"] = True
                if base_domain:
                    # PHASE 14: an earlier cycle may have already blocked this domain in
                    # Pi-hole before the LLM had a chance to validate it as benign -- an
                    # immunization alone only stops FUTURE alerts, it doesn't undo an
                    # existing block. Check local state first (no network call) so this
                    # doesn't fire a wasted Pi-hole API call on every immunization.
                    was_blocked = base_domain in state_manager.get_ips_state().get("blocked_domains", {})
                    unblocked_note = ""
                    if was_blocked and ips_mitigator.unblock_domain(domain=base_domain):
                        unblocked_note = " Released its existing Pi-hole block."
                        LOGGER.info(f"🔓 [OLLAMA-SOC] '{base_domain}' was immunized -- released its existing Pi-hole block.")
                    report_lines.append(
                        f"- **Autonomous Action Taken:** 🤖 Immunized `{base_domain}` in the FP trust "
                        f"cache and logged an operator-equivalent training correction "
                        f"(takes effect on soc.service's next restart).{unblocked_note}"
                    )
                else:
                    report_lines.append(
                        f"- **Autonomous Action Skipped:** could not safely extract a base domain "
                        f"from `{target_domain}` — no immunization applied."
                    )
        elif already_actioned:
            report_lines.append("- **Autonomous Action:** already applied for this pattern on a previous run — not repeated.")

        report_lines.append("")
        LOGGER.info(f"Analyzed {device_ip} -> {target} (Risk {risk}, {len(members)} alert(s)): {response_json.get('reason')}")

    report_lines.insert(
        6,
        f"**Ollama calls this run:** {queries_made} fresh, {cache_hits} served from cache, {deferred} deferred to next run.\n"
    )

    # 3. Persist the analysis cache
    _save_cache(cache_path, cache)

    # 4. Append transparency logs to alerts.json
    if new_transparency_logs:
        try:
            with open(alerts_path, "a", encoding="utf-8") as f:
                for log in new_transparency_logs:
                    f.write(json.dumps(log) + "\n")
        except Exception as e:
            LOGGER.error(f"Failed to write to alerts.json: {e}")

    # 5. Write Markdown Report
    reports_dir = root_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"soc_daily_report_{datetime.now().strftime('%Y%m%d')}.md"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    LOGGER.info(
        f"Generated SOC Daily Report: {report_path} "
        f"({queries_made} fresh Ollama calls, {cache_hits} cache hits, {deferred} deferred)"
    )

if __name__ == "__main__":
    main()
