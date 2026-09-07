"""
cl_afpe_flip_monitor.py - v13 full-architecture plan, Workstream 2
(Documentation/V13_FULL_ARCHITECTURE_SHIFT_PLAN.md).

Runs on `.94` via scripts/scheduler.py (config.yaml's
scheduled_jobs.scheduler.cl_afpe_flip_monitor block, 15-minute cron, same mechanism
retro_hunter.py/the retired gap_monitor.py already used).

Checks state/cl_afpe_divergence_v13.jsonl (Phase 6e's shadow comparison, already
accumulating real data every cycle an alert fires) against a fixed bar and, if
cleared, flips config.yaml's `cl_afpe_engine` key from "v_current" to "v13"
automatically -- the user's explicit choice (2026-09-07): fully automatic once the
bar clears, matching this project's own A9 precedent for the retired per-mechanism
apparatus, applied here to CL-AFPE's own single, whole-engine flip. Deliberately
does NOT restart soc.service -- that stays a separate, explicit human-triggered
action, the one piece of every prior automated flip in this project's history that
has never been automated, and isn't here either.

THE BAR (deliberately no fixed time floor -- the user's explicit choice, given this
box's already-reduced risk tolerance; a volume floor + a hard veto stand in for it):
  1. Volume floor: >= MIN_ELIGIBLE_COMPARISONS real eligible comparisons logged.
     "Eligible" means BOTH sides produced a verdict for the same alert (v1_verdict
     and v13_verdict both present) -- a comparison where one side never even
     evaluated tells us nothing about agreement. Set to 50, not empirically tuned
     (same honest-status framing this project's own INDEPENDENCE_FAMILY_MAP uses for
     a similarly un-validated number) -- between the retired A10 mechanism's 15-20
     (a pure scoring refinement) and Gap 3 honeypot's 58 (a hard-stop): CL-AFPE
     controls real autonomous SUPPRESSION, not just severity scoring, so it sits
     closer to the hard-stop end of that spectrum.
  2. Hard veto, checked before the volume floor even matters: ANY false-negative-
     shaped divergence ever logged. Here that means v13 said "FALSE_POSITIVE"
     (would have suppressed the alert, hiding it from a human) while v-current's
     REAL verdict on the same alert was NOT "FALSE_POSITIVE" (v1 actually surfaced
     it as CONFIRMED_THREAT or UNCERTAIN) -- the one direction of disagreement that
     would mean a real threat silently never gets shown to an operator. The
     opposite direction (v13 more cautious than v1) is exactly the kind of
     disagreement this shadow period exists to find and is never a veto.
  3. The mechanism's own regression suite must pass on THIS box, right now -- not
     "did it pass once at build time." Deliberately narrow (this file's own two
     dedicated test files), not the full pre-existing 22-file v-current suite --
     matches the retired gap_monitor.py's own established reasoning: this rule is
     about an interactive session asking a human to wait, not about what this
     unattended, single-purpose CI-style gate may run on its own.

A veto or a failing regression test is notified once (a persisted bookmark stops a
15-minute cron from re-sending the same standing finding every tick) -- the same
"asked directly, declined" precedent already used throughout this project.
"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))  # -> src/

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from v13.ops.telegram import send_telegram  # noqa: E402

LOGGER_NAME = "cl_afpe_flip_monitor"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
CONFIG_YAML_PATH = REPO_ROOT / "config.yaml"

MIN_ELIGIBLE_COMPARISONS = 50
DIVERGENCE_LOG_FILENAME = "cl_afpe_divergence_v13.jsonl"
MONITOR_STATE_FILENAME = "cl_afpe_flip_monitor_state.json"

REGRESSION_TESTS = [
    "tests/test_v13_cl_afpe.py",
    "tests/test_v13_live_cl_afpe_shadow.py",
]


def _read_divergence_log(state_dir: Path) -> list:
    path = state_dir / DIVERGENCE_LOG_FILENAME
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _is_eligible(entry: dict) -> bool:
    return entry.get("v1_verdict") is not None and entry.get("v13_verdict") is not None


def _is_false_negative_shaped(entry: dict) -> bool:
    """The one dangerous direction: v13 would have silently suppressed an alert
    v-current's real verdict actually surfaced to a human."""
    return entry.get("v13_verdict") == "FALSE_POSITIVE" and entry.get("v1_verdict") not in (
        None, "FALSE_POSITIVE",
    )


def _find_false_negative(entries: list) -> Optional[dict]:
    for entry in entries:
        if _is_false_negative_shaped(entry):
            return entry
    return None


def _current_engine_value() -> str:
    if not CONFIG_YAML_PATH.exists():
        return "v_current"
    text = CONFIG_YAML_PATH.read_text(encoding="utf-8")
    m = re.search(r"^cl_afpe_engine:\s*(\S+)", text, re.MULTILINE)
    return m.group(1) if m else "v_current"


def _flip_to_live() -> bool:
    """Purely additive, targeted text edit -- NOT a yaml.safe_load()+dump() round
    trip, which would silently strip every comment in this heavily-annotated file.
    Requires `cl_afpe_engine:` to already exist in config.yaml (added once, by hand,
    alongside this job's own scheduler entry -- see config.yaml.example). Idempotent:
    already "v13" is a no-op that still returns True."""
    if not CONFIG_YAML_PATH.exists():
        return False
    text = CONFIG_YAML_PATH.read_text(encoding="utf-8")
    pattern = re.compile(r"(^cl_afpe_engine:\s*)(\S+)", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return False
    if match.group(2) == "v13":
        return True
    new_text = text[: match.start(2)] + "v13" + text[match.end(2):]
    tmp_path = CONFIG_YAML_PATH.with_suffix(".yaml.tmp")
    tmp_path.write_text(new_text, encoding="utf-8")
    tmp_path.replace(CONFIG_YAML_PATH)
    return True


def _run_regression_tests() -> tuple:
    for rel_path in REGRESSION_TESTS:
        test_path = REPO_ROOT / rel_path
        if not test_path.exists():
            return False, f"Regression test file not found: {test_path}"
        try:
            result = subprocess.run(
                [sys.executable, str(test_path)], capture_output=True, text=True, timeout=180,
            )
        except Exception as e:
            return False, f"Failed to run {rel_path}: {e}"
        if result.returncode != 0:
            tail = (result.stdout[-1200:] + result.stderr[-1200:]).strip()
            return False, f"{rel_path} FAILED:\n{tail}"
    return True, "all regression tests passed"


def _load_monitor_state(state_dir: Path) -> dict:
    path = state_dir / MONITOR_STATE_FILENAME
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_monitor_state(state_dir: Path, data: dict) -> None:
    path = state_dir / MONITOR_STATE_FILENAME
    tmp_path = path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def check_bar(state_dir: Path) -> dict:
    """Pure-ish decision function (isolated for direct unit testing) -- reads real
    state, returns what was found as a plain dict, doesn't touch Telegram/config
    itself. `action` is one of: already_live, veto_blocked, waiting_volume_floor,
    bar_cleared."""
    if _current_engine_value() == "v13":
        return {"action": "already_live"}

    entries = _read_divergence_log(state_dir)
    eligible = [e for e in entries if _is_eligible(e)]

    false_negative = _find_false_negative(eligible)
    if false_negative is not None:
        return {"action": "veto_blocked", "detail": false_negative}

    if len(eligible) < MIN_ELIGIBLE_COMPARISONS:
        return {
            "action": "waiting_volume_floor",
            "detail": f"{len(eligible)}/{MIN_ELIGIBLE_COMPARISONS} eligible comparisons",
        }

    return {"action": "bar_cleared", "detail": f"{len(eligible)} eligible comparisons, zero false negatives"}


def run_once(config: dict = None, monitor_state: dict = None) -> dict:
    """Separated from main() so tests can call it directly with an injected
    config/state, without touching real Telegram credentials or the real clock."""
    config = config if config is not None else CONFIG
    state_dir = Path(config.get("state_path", "state/ids_state.json")).parent
    monitor_state = monitor_state if monitor_state is not None else _load_monitor_state(state_dir)

    outcome = check_bar(state_dir)
    summary = {"action": outcome["action"]}

    if outcome["action"] == "already_live":
        _save_monitor_state(state_dir, monitor_state)
        return summary

    if outcome["action"] == "veto_blocked":
        summary["detail"] = outcome["detail"]
        if not monitor_state.get("veto_notified"):
            fn = outcome["detail"]
            send_telegram(
                config,
                "⚠️ <b>CL-AFPE v13 flip BLOCKED</b>\n"
                f"A false-negative-shaped divergence was found -- v13 would have called "
                f"<code>{fn.get('device_id', 'unknown')}</code>'s alert FALSE_POSITIVE "
                f"(suppressed) where v-current's real verdict was "
                f"<b>{fn.get('v1_verdict')}</b>.\n"
                f"This will NOT auto-flip while this stands. Needs a human look at "
                f"state/{DIVERGENCE_LOG_FILENAME}.",
            )
            monitor_state["veto_notified"] = True
        _save_monitor_state(state_dir, monitor_state)
        return summary

    if outcome["action"] == "waiting_volume_floor":
        summary["detail"] = outcome["detail"]
        _save_monitor_state(state_dir, monitor_state)
        return summary

    # bar_cleared -- run the hard regression gate before touching config.yaml.
    passed, test_output = _run_regression_tests()
    if not passed:
        summary["action"] = "regression_failed"
        summary["detail"] = test_output
        if not monitor_state.get("regression_fail_notified"):
            send_telegram(
                config,
                "⚠️ <b>CL-AFPE v13 flip BLOCKED</b>\n"
                f"Volume bar cleared but a regression test is currently FAILING on "
                f"this box -- NOT flipping. Needs a human look:\n"
                f"<pre>{test_output[-800:]}</pre>",
            )
            monitor_state["regression_fail_notified"] = True
        _save_monitor_state(state_dir, monitor_state)
        return summary

    flipped = _flip_to_live()
    summary["action"] = "flipped" if flipped else "flip_failed"
    if flipped:
        send_telegram(
            config,
            "✅ <b>CL-AFPE flipped to v13</b>\n"
            f"Bar cleared ({outcome['detail']}). Regression tests passed. "
            f"config.yaml's cl_afpe_engine is now <b>v13</b>.\n"
            f"⚠️ This does NOT restart soc.service automatically -- "
            f"run <code>sudo systemctl restart soc.service</code> manually to activate it.",
        )
    else:
        send_telegram(
            config,
            "⚠️ <b>CL-AFPE v13 flip FAILED</b>\n"
            f"Bar cleared and regression passed, but editing config.yaml failed -- "
            f"the cl_afpe_engine key may be missing. Needs a human look.",
        )
    _save_monitor_state(state_dir, monitor_state)
    return summary


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    summary = run_once()
    write_job_health(state_dir, "cl_afpe_flip_monitor", time.time() - run_start, extra=summary)


if __name__ == "__main__":
    main()
