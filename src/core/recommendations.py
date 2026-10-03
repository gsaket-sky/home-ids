"""
recommendations.py - rule-based "next best action" suggestions for the WebUI
dashboard (PRODUCTIZATION_ROADMAP.md Phase 4).

Reads the JSON files the pipeline/scheduled scripts already write --
state/job_health.json, state/device_labels.json, state/ids_state.json,
onboarding.json -- and turns them into a small set of canned suggestion cards.
Deliberately informational-only for anything that would need to WRITE a config
change (e.g. "raise strictness"): safely validating and applying an arbitrary
config edit is Phase 6's job (the full config.yaml editor), not this panel's --
see this module's cards for the exact line the roadmap draws between "suggest"
and "act." A suggestion always either links to a page with a REAL existing
action (device labeling, onboarding activation) or is read-only text.
"""
import json
import math
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.onboarding import get_onboarding_status

# Expected cadence per scheduled job, in hours -- used only to flag a job that
# looks overdue, not to enforce/replace the real schedule in config.yaml's
# `scheduler` block (which is the actual source of truth for when a job runs).
# Names are the ones the jobs write to state/job_health.json (utils.write_job_health()).
_EXPECTED_CADENCE_HOURS = {
    "live_llm_review": 8.0,          # every 4h -- 2x margin before flagging (a skip without Ollama counts as a run)
    "live_prune_weak_notices": 8.0,  # every 4h
    "live_retro_hunter": 48.0,       # nightly -- 2x margin
    "live_prune": 48.0,
    "disk_budget_governor": 48.0,
    "zeek_log_prune": 48.0,
    "top_domains_report": 48.0,
    "train_fp_classifier": 48.0,     # nightly retrain + calibration (autotune_schedule_cron)
    "live_decision_archive": 62 * 24.0,  # monthly
}


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _card(text: str, severity: str = "info", action_url: Optional[str] = None,
          action_label: Optional[str] = None) -> Dict[str, Any]:
    return {"text": text, "severity": severity, "action_url": action_url, "action_label": action_label}


def build_recommendations(config, state_dir: str = "state") -> List[Dict[str, Any]]:
    state_dir_path = Path(state_dir)
    cards: List[Dict[str, Any]] = []

    # -- Onboarding status --------------------------------------------------
    onboarding = get_onboarding_status(config, state_dir)
    if onboarding["active"]:
        days = max(1, math.ceil(onboarding["days_remaining"]))
        card = _card(
            f"The IDS is still learning your network -- automatic blocking starts in {days} "
            f"day{'' if days == 1 else 's'}. Look through your alerts, then turn protection on early if "
            "you're ready.",
            severity="warning", action_url="/", action_label="Activate Protection Now",
        )
        card["kind"] = "onboarding"     # Home shows this as its main button already
        cards.append(card)

    # -- Unlabeled devices ----------------------------------------------------
    from core import state_store
    ids_state = state_store.read_snapshot(state_dir_path / "ids_state.json", ledger=False) or {}
    devices = ids_state.get("devices", {}) or {}
    labels = _read_json(state_dir_path / "device_labels.json") or {}
    unlabeled = [d for d in devices.keys() if d not in labels]
    if unlabeled:
        cards.append(_card(
            f"{len(unlabeled)} device(s) haven't been confirmed yet -- labeling them "
            "improves detection accuracy for that device's type.",
            severity="info", action_url="/devices", action_label="Review Devices",
        ))

    # -- Background job health ------------------------------------------------
    job_health = _read_json(state_dir_path / "job_health.json") or {}
    now = time.time()
    for job_name, expected_hours in _EXPECTED_CADENCE_HOURS.items():
        entry = job_health.get(job_name)
        if entry is None:
            continue  # never run yet -- not necessarily a problem (e.g. optional job)
        last_success = float(entry.get("last_success", 0.0) or 0.0)
        age_hours = (now - last_success) / 3600.0 if last_success else float("inf")
        if age_hours > expected_hours:
            cards.append(_card(
                f"'{job_name}' hasn't completed successfully in {age_hours:.0f}h "
                f"(expected roughly every {expected_hours:.0f}h) -- check the System page.",
                severity="warning", action_url="/system", action_label="Open System",
            ))

    # -- Suricata available but off (informational only, per module docstring) --
    if not bool(config.get("reactive_capture_suricata_enabled", True)) \
            and bool(config.get("reactive_capture_enabled", False)):
        cards.append(_card(
            "Suricata signature scanning is available but disabled for reactive-capture "
            "bursts. Enabling it needs a config change -- see Settings (Phase 6).",
            severity="info",
        ))

    if not cards:
        cards.append(_card("Nothing needs your attention right now.", severity="ok"))

    return cards
