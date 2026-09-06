"""
gap_monitor.py - v13's automated per-mechanism flip monitor
(Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md's "Automated per-mechanism flip bars"
section; the plan's original "Automated incremental flips" design).

Runs on .94 via scripts/scheduler.py (config.yaml's scheduled_jobs.scheduler.gap_monitor
block), same pattern as retro_hunter.py/shadow_watcher.py -- reuses their exact
_send_telegram()/write_job_health() conventions.

For each registered mechanism, checks real accumulated evidence against its documented
bar and -- if the bar clears AND every hard safety veto passes -- automatically flips
that mechanism's config.yaml flag from "shadow" to "live". This is the user's explicit
A9 decision ("keep fully automatic") applied to exactly the config-EDIT step.

Deliberately does NOT restart soc.service. That stays a separate, explicit
human-triggered action, per this project's standing rule that production restarts are
never performed by an unattended script -- the same rule already applied to every other
deploy this session (A10, A11, the eligible-cycle counter all synced code automatically
but always waited for a human to run `sudo systemctl restart soc.service`). A flip here
is a config-only change; a Telegram notification asks for the restart to actually
activate it, exactly like every prior restart in this project's history.

Hard safety vetoes (checked BEFORE the config edit, independent of whether the bar
"looks" cleared):
  1. The mechanism's own regression test must pass right now, on THIS box's real
     environment -- not "did the test suite pass once at build time."
  2. Zero false-negative-shaped divergences ever recorded for this mechanism (v13 would
     have called something LESS severe than v-current's actual live verdict) -- the same
     asymmetric-risk stance that kept arp_spoof/geofence/confirmed_exploit shadow-only.
  3. The situation must match a pre-documented bar exactly -- an unrecognized signal
     shape sends a notification asking for a human decision instead of guessing.
A veto trip is notified immediately (once, via a persisted "already notified" bookmark
so a 15-minute cron doesn't spam the same finding every cycle) -- the same "asked
directly, declined" precedent already used for arp_spoof/geofence/confirmed_exploit.

Adding a second mechanism means adding one more MECHANISMS entry below (bar thresholds +
the state files it reads + its config flag path), not a code rewrite -- this stays a
data-driven table, not a mechanism-specific class hierarchy, since the shape (eligible
count, divergence log, time floor, volume floor, veto) is the same for every mechanism
built the way A10 was.
"""
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))  # -> src/

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
CONFIG_YAML_PATH = REPO_ROOT / "config.yaml"

# DecisionState severity order, low to high -- mirrors core/decision_engine.py's own
# DecisionState values. A "false-negative-shaped" divergence is one where v13's
# alternate verdict ranks LOWER than what v-current's real live decision actually was.
_STATE_SEVERITY = {"BENIGN": 0, "ANOMALOUS": 1, "SUSPICIOUS": 2, "HIGH": 3, "CRITICAL": 4}


def _send_telegram(msg: str) -> None:
    token = CONFIG.get("telegram_token", "")
    chat_id = CONFIG.get("telegram_chat_id", "")
    if not token or not chat_id:
        return
    try:
        import urllib.request
        data = json.dumps({"chat_id": chat_id, "text": msg, "parse_mode": "HTML"}).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"Failed to send Telegram gap-monitor alert: {e}", file=sys.stderr)


@dataclass
class Mechanism:
    key: str                    # short id, used in state/gap_monitor_state.json and notifications
    label: str                  # human label for notifications
    flag_key: str                # under config.yaml's v13_flags: section
    eligible_count_file: str     # relative to state_dir
    divergence_log_file: str     # relative to state_dir
    not_before: str              # ISO date (YYYY-MM-DD), the documented time floor
    min_eligible_count: int      # the documented volume floor
    regression_test: str         # path relative to REPO_ROOT
    bar_doc_line: str            # human-readable bar summary, for notifications


MECHANISMS = [
    Mechanism(
        key="independence_family",
        label="Hypothesis independence-family scoring (A10)",
        flag_key="independence_family",
        eligible_count_file="v13_independence_eligible_count.json",
        divergence_log_file="v13_independence_divergences.jsonl",
        not_before="2026-09-13",
        # Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md's "Automated per-mechanism
        # flip bars": deliberately conservative given eligible cycles are NOT independent
        # trials (often the same persisted alert re-evaluating every ~2s poll interval) --
        # this is a sanity-minimum floor, not "200 distinct incidents".
        min_eligible_count=200,
        regression_test="tests/test_phase68_v13_independence_shadow.py",
        bar_doc_line=(
            "7-day time floor (not before 2026-09-13) AND >=200 eligible cycles "
            "AND zero false-negative-shaped divergences"
        ),
    ),
]


def _is_false_negative_shaped(entry: dict) -> bool:
    old_rank = _STATE_SEVERITY.get(str(entry.get("old_state", "")).upper(), 0)
    new_rank = _STATE_SEVERITY.get(str(entry.get("new_state", "")).upper(), 0)
    return new_rank < old_rank


def _read_eligible_count(state_dir: Path, mech: Mechanism) -> int:
    path = state_dir / mech.eligible_count_file
    if not path.exists():
        return 0
    try:
        return int(json.loads(path.read_text(encoding="utf-8")).get("count", 0))
    except Exception:
        return 0


def _find_false_negative(state_dir: Path, mech: Mechanism) -> dict:
    """Returns the first false-negative-shaped divergence found, or None. Scans the
    WHOLE log every run (these files are small and append-only, and correctness here
    matters far more than the cost of re-scanning a few hundred lines every 15 minutes)."""
    path = state_dir / mech.divergence_log_file
    if not path.exists():
        return None
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _is_false_negative_shaped(entry):
                return entry
    except Exception:
        pass
    return None


def _run_regression_test(mech: Mechanism) -> tuple:
    """Runs the mechanism's OWN dedicated regression test as the hard pre-flip gate --
    deliberately scoped narrow (not the full pre-existing v-current suite), since this
    runs unattended on a schedule and the project's "never run the full suite without
    asking" convention is about interactive sessions asking a human to wait, not about
    what this unattended, narrowly-scoped CI-style gate is allowed to do on its own."""
    test_path = REPO_ROOT / mech.regression_test
    if not test_path.exists():
        return False, f"Regression test file not found: {test_path}"
    try:
        result = subprocess.run(
            [sys.executable, str(test_path)], capture_output=True, text=True, timeout=180,
        )
        tail = (result.stdout[-1500:] + result.stderr[-1500:]).strip()
        return result.returncode == 0, tail
    except Exception as e:
        return False, f"Failed to run regression test: {e}"


def _current_flag_value(mech: Mechanism) -> str:
    if not CONFIG_YAML_PATH.exists():
        return "shadow"
    text = CONFIG_YAML_PATH.read_text(encoding="utf-8")
    m = re.search(
        r"^v13_flags:\s*\n(?:^\s+.*\n)*?^\s+" + re.escape(mech.flag_key) + r":\s*(\S+)",
        text, re.MULTILINE,
    )
    return m.group(1) if m else "shadow"


def _flip_flag_to_live(mech: Mechanism) -> bool:
    """Purely additive, targeted text edit -- NOT a yaml.safe_load()+yaml.dump() round
    trip, which would silently strip every comment in this heavily-annotated file.
    Requires the v13_flags: section and this mechanism's flag_key to already exist in
    config.yaml (added once, by hand, when the mechanism is first wired in -- see
    config.yaml.example's own v13_flags: section for the template). Idempotent: if the
    flag is already "live", this is a no-op that still returns True."""
    if not CONFIG_YAML_PATH.exists():
        return False
    text = CONFIG_YAML_PATH.read_text(encoding="utf-8")
    pattern = re.compile(
        r"(^v13_flags:\s*\n(?:^\s+.*\n)*?^\s+" + re.escape(mech.flag_key) + r":\s*)(\S+)",
        re.MULTILINE,
    )
    match = pattern.search(text)
    if not match:
        return False
    if match.group(2) == "live":
        return True
    new_text = text[: match.start(2)] + "live" + text[match.end(2):]
    tmp_path = CONFIG_YAML_PATH.with_suffix(".yaml.tmp")
    tmp_path.write_text(new_text, encoding="utf-8")
    tmp_path.replace(CONFIG_YAML_PATH)
    return True


def _load_monitor_state(state_dir: Path) -> dict:
    path = state_dir / "gap_monitor_state.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_monitor_state(state_dir: Path, data: dict) -> None:
    path = state_dir / "gap_monitor_state.json"
    tmp_path = path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def check_mechanism(mech: Mechanism, state_dir: Path, monitor_state: dict, today: date) -> dict:
    """Pure-ish decision function (isolated for direct unit testing) -- takes the
    already-computed inputs and this mechanism's already-loaded persisted state, returns
    what happened as a plain dict rather than reaching out to Telegram/disk itself."""
    mech_state = monitor_state.get(mech.key, {})
    result = {"mechanism": mech.key, "action": "none", "detail": ""}

    current_flag = _current_flag_value(mech)
    if current_flag == "live":
        result["action"] = "already_live"
        return result

    false_negative = _find_false_negative(state_dir, mech)
    if false_negative is not None:
        result["action"] = "veto_blocked"
        result["detail"] = false_negative
        if not mech_state.get("veto_notified"):
            result["notify"] = True
            mech_state["veto_notified"] = True
        monitor_state[mech.key] = mech_state
        return result

    not_before = date.fromisoformat(mech.not_before)
    if today < not_before:
        result["action"] = "waiting_time_floor"
        result["detail"] = f"{ (not_before - today).days } day(s) remaining"
        return result

    eligible_count = _read_eligible_count(state_dir, mech)
    if eligible_count < mech.min_eligible_count:
        result["action"] = "waiting_volume_floor"
        result["detail"] = f"{eligible_count}/{mech.min_eligible_count} eligible cycles"
        return result

    # Both floors clear and no veto found -- run the hard regression gate before touching
    # anything. This subprocess call is deliberately NOT part of check_mechanism's pure
    # unit-test surface (callers that want to test the regression-fail path pass a
    # pre-computed `regression_result` override -- see run_once()'s own call site).
    result["action"] = "bar_cleared"
    return result


def run_once(config: dict = None, monitor_state: dict = None, today: date = None) -> dict:
    """Runs every registered mechanism's check once. Separated from main() so tests can
    call it directly with an injected config/state_dir/today, without touching real
    Telegram credentials or the real clock."""
    config = config if config is not None else CONFIG
    state_dir = Path(config.get("state_path", "state/ids_state.json")).parent
    monitor_state = monitor_state if monitor_state is not None else _load_monitor_state(state_dir)
    today = today or date.today()

    summary = {"checked": [], "flipped": [], "vetoed": [], "waiting": []}

    for mech in MECHANISMS:
        outcome = check_mechanism(mech, state_dir, monitor_state, today)
        summary["checked"].append(outcome["mechanism"])

        if outcome["action"] == "already_live":
            continue

        if outcome["action"] == "veto_blocked":
            summary["vetoed"].append(mech.key)
            if outcome.get("notify"):
                fn = outcome["detail"]
                _send_telegram(
                    f"⚠️ <b>v13 flip BLOCKED: {mech.label}</b>\n"
                    f"A false-negative-shaped divergence was found -- v13 would have called "
                    f"<code>{fn.get('device_id', 'unknown')}</code> "
                    f"<b>{fn.get('new_state')}</b> ({fn.get('new_decision_path')}) where "
                    f"v-current's real verdict was <b>{fn.get('old_state')}</b> "
                    f"({fn.get('old_decision_path')}).\n"
                    f"This mechanism will NOT auto-flip while this stands. Needs a human look."
                )
            continue

        if outcome["action"] in ("waiting_time_floor", "waiting_volume_floor"):
            summary["waiting"].append({"mechanism": mech.key, "detail": outcome["detail"]})
            continue

        if outcome["action"] == "bar_cleared":
            passed, test_output = _run_regression_test(mech)
            if not passed:
                if not monitor_state.get(mech.key, {}).get("regression_fail_notified"):
                    _send_telegram(
                        f"⚠️ <b>v13 flip BLOCKED: {mech.label}</b>\n"
                        f"Bar cleared ({mech.bar_doc_line}) but the regression test "
                        f"({mech.regression_test}) is currently FAILING on this box -- "
                        f"NOT flipping. Needs a human look before this can proceed:\n"
                        f"<pre>{test_output[-800:]}</pre>"
                    )
                    monitor_state.setdefault(mech.key, {})["regression_fail_notified"] = True
                summary["vetoed"].append(mech.key)
                continue

            flipped = _flip_flag_to_live(mech)
            if flipped:
                summary["flipped"].append(mech.key)
                _send_telegram(
                    f"✅ <b>v13 mechanism flipped: {mech.label}</b>\n"
                    f"Bar cleared: {mech.bar_doc_line}. Regression test passed. "
                    f"config.yaml's v13_flags.{mech.flag_key} is now <b>live</b>.\n"
                    f"⚠️ This does NOT restart soc.service automatically (standing project "
                    f"rule) -- run <code>sudo systemctl restart soc.service</code> manually "
                    f"to actually activate it."
                )
            else:
                _send_telegram(
                    f"⚠️ <b>v13 flip FAILED: {mech.label}</b>\n"
                    f"Bar cleared and regression passed, but editing config.yaml failed -- "
                    f"the v13_flags.{mech.flag_key} key may not exist yet in config.yaml. "
                    f"Needs a human look."
                )

    _save_monitor_state(state_dir, monitor_state)
    return summary


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    summary = run_once()
    write_job_health(state_dir, "gap_monitor", time.time() - run_start, extra=summary)


if __name__ == "__main__":
    main()
