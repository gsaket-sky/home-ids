"""
Standalone runtime test for src/v13/ops/cl_afpe_flip_monitor.py -- the automated
CL-AFPE shadow-to-live flip monitor (v13 full-architecture plan, Workstream 2,
Documentation/V13_FULL_ARCHITECTURE_SHIFT_PLAN.md).

Not part of the pytest suite -- run directly:
`python3 tests/test_argus_cl_afpe_flip_monitor.py` (bare python3, no heavy deps needed,
matching every other src/v13 test file's convention).

Sections:
  A. _is_eligible / _is_false_negative_shaped: correctly classify divergence-log
     entries -- eligibility requires both sides to have produced a verdict; the one
     dangerous direction is v13 saying FALSE_POSITIVE where v1's real verdict was not
  B. _flip_to_live / _current_engine_value: a targeted text edit, not a yaml round
     trip -- preserves every surrounding comment/line, is idempotent, fails
     gracefully when the key doesn't exist yet in config.yaml
  C. check_bar: the pure decision function -- already_live, veto, volume floor, and
     bar-cleared paths, each in isolation
  D. run_once: the full orchestration, with send_telegram/subprocess monkeypatched so
     no real network call or real subprocess ever happens in this test, including the
     notification spam-guard (a standing veto/failure notifies once, not every tick)
  E. Never restarts soc.service -- source-level + AST-level check that this file
     contains no systemctl/service-restart call of any kind
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import argus.ops.cl_afpe_flip_monitor as mon  # noqa: E402

TMPDIR = Path(tempfile.mkdtemp(prefix="cl_afpe_flip_monitor_test_"))


# --- A. eligibility + false-negative classification ---

check("A: both verdicts present -> eligible",
      mon._is_eligible({"v1_verdict": "FALSE_POSITIVE", "v13_verdict": "CONFIRMED_THREAT"}))
check("A: v1_verdict missing -> not eligible (one side never evaluated)",
      not mon._is_eligible({"v13_verdict": "CONFIRMED_THREAT"}))
check("A: v13_verdict missing -> not eligible",
      not mon._is_eligible({"v1_verdict": "FALSE_POSITIVE"}))

check("A: v13=FALSE_POSITIVE, v1=CONFIRMED_THREAT -> false-negative-shaped (the "
      "dangerous direction: v13 would have silently suppressed a real alert v1 surfaced)",
      mon._is_false_negative_shaped({"v1_verdict": "CONFIRMED_THREAT", "v13_verdict": "FALSE_POSITIVE"}))
check("A: v13=FALSE_POSITIVE, v1=UNCERTAIN -> also false-negative-shaped",
      mon._is_false_negative_shaped({"v1_verdict": "UNCERTAIN", "v13_verdict": "FALSE_POSITIVE"}))
check("A: v13=CONFIRMED_THREAT, v1=FALSE_POSITIVE -> NOT false-negative-shaped -- the "
      "SAFE direction (v13 more cautious than v1), exactly what this shadow period "
      "exists to find, never a veto",
      not mon._is_false_negative_shaped({"v1_verdict": "FALSE_POSITIVE", "v13_verdict": "CONFIRMED_THREAT"}))
check("A: both agree on FALSE_POSITIVE -> not false-negative-shaped",
      not mon._is_false_negative_shaped({"v1_verdict": "FALSE_POSITIVE", "v13_verdict": "FALSE_POSITIVE"}))
check("A: v1_verdict missing entirely -> not false-negative-shaped (can't compare)",
      not mon._is_false_negative_shaped({"v13_verdict": "FALSE_POSITIVE"}))


# --- B. _flip_to_live: targeted text edit ---

_SAMPLE_CONFIG = """\
network_and_devices:
  home_subnet: 192.168.1.0/24

# cl_afpe_engine -- see config.yaml.example's own comment for the full explanation.
cl_afpe_engine: v_current

telegram:
  telegram_enabled: true
"""

_test_config_path = TMPDIR / "config.yaml"
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")
mon.CONFIG_YAML_PATH = _test_config_path

check("B: current engine value reads 'v_current' before any flip",
      mon._current_engine_value() == "v_current")

flipped_ok = mon._flip_to_live()
_after_first_flip = _test_config_path.read_text(encoding="utf-8")
check("B: _flip_to_live returns True on a successful edit", flipped_ok is True)
check("B: the value actually changed to 'v13' in the file",
      mon._current_engine_value() == "v13")
check("B: every comment line and surrounding section is byte-for-byte preserved",
      "# cl_afpe_engine -- see config.yaml.example" in _after_first_flip
      and "home_subnet: 192.168.1.0/24" in _after_first_flip
      and "telegram_enabled: true" in _after_first_flip)
check("B: only the one value changed -- no stray reformatting of the rest of the file",
      _after_first_flip.replace("cl_afpe_engine: v13", "cl_afpe_engine: v_current") == _SAMPLE_CONFIG)

flipped_again = mon._flip_to_live()
check("B: flipping an already-'v13' value is idempotent (still returns True, file unchanged)",
      flipped_again is True and _test_config_path.read_text(encoding="utf-8") == _after_first_flip)

_no_key_config_path = TMPDIR / "config_no_key.yaml"
_no_key_config_path.write_text("network_and_devices:\n  home_subnet: 192.168.1.0/24\n", encoding="utf-8")
mon.CONFIG_YAML_PATH = _no_key_config_path
check("B: current engine value defaults to 'v_current' when the key doesn't exist at all",
      mon._current_engine_value() == "v_current")
check("B: attempting to flip a nonexistent key returns False, doesn't raise",
      mon._flip_to_live() is False)
check("B: the file is completely untouched when the key doesn't exist",
      _no_key_config_path.read_text(encoding="utf-8") == "network_and_devices:\n  home_subnet: 192.168.1.0/24\n")

# Reset to a fresh not-yet-flipped config for section C/D
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")
mon.CONFIG_YAML_PATH = _test_config_path


# --- C. check_bar: the pure decision function ---

_state_dir_c = TMPDIR / "state_c"
_state_dir_c.mkdir(exist_ok=True)


def _write_log(state_dir, entries):
    path = state_dir / mon.DIVERGENCE_LOG_FILENAME
    path.write_text("\n".join(json.dumps(e) for e in entries) + ("\n" if entries else ""), encoding="utf-8")


# No log at all yet
outcome = mon.check_bar(_state_dir_c)
check("C: no divergence log yet -> waiting_volume_floor with 0 eligible",
      outcome["action"] == "waiting_volume_floor" and "0/" in outcome["detail"])

# Below the volume floor, all eligible, all safe
_write_log(_state_dir_c, [
    {"v1_verdict": "FALSE_POSITIVE", "v13_verdict": "FALSE_POSITIVE"} for _ in range(10)
])
outcome = mon.check_bar(_state_dir_c)
check("C: 10 eligible (below the 50 floor), zero false negatives -> waiting_volume_floor",
      outcome["action"] == "waiting_volume_floor" and outcome["detail"].startswith("10/"))

# At/above the volume floor, all safe
_write_log(_state_dir_c, [
    {"v1_verdict": "CONFIRMED_THREAT", "v13_verdict": "CONFIRMED_THREAT"} for _ in range(mon.MIN_ELIGIBLE_COMPARISONS)
])
outcome = mon.check_bar(_state_dir_c)
check("C: exactly MIN_ELIGIBLE_COMPARISONS eligible, zero false negatives -> bar_cleared",
      outcome["action"] == "bar_cleared")

# A single false-negative-shaped entry among many safe ones vetoes regardless of volume
entries_with_fn = [
    {"v1_verdict": "CONFIRMED_THREAT", "v13_verdict": "CONFIRMED_THREAT"} for _ in range(mon.MIN_ELIGIBLE_COMPARISONS)
]
entries_with_fn.append({"v1_verdict": "CONFIRMED_THREAT", "v13_verdict": "FALSE_POSITIVE", "device_id": "dev_x"})
_write_log(_state_dir_c, entries_with_fn)
outcome = mon.check_bar(_state_dir_c)
check("C: a false-negative-shaped entry vetoes even with the volume floor cleared",
      outcome["action"] == "veto_blocked" and outcome["detail"].get("device_id") == "dev_x")

# Ineligible entries (one side missing) don't count toward the volume floor at all
_write_log(_state_dir_c, [{"v13_verdict": "CONFIRMED_THREAT"} for _ in range(mon.MIN_ELIGIBLE_COMPARISONS)])
outcome = mon.check_bar(_state_dir_c)
check("C: entries missing v1_verdict entirely don't count as eligible",
      outcome["action"] == "waiting_volume_floor" and outcome["detail"].startswith("0/"))

# Already live -- short-circuits before even reading the log
mon._flip_to_live()
outcome = mon.check_bar(_state_dir_c)
check("C: once cl_afpe_engine is already 'v13', check_bar reports already_live without "
      "re-evaluating the log",
      outcome["action"] == "already_live")
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")  # reset for section D


# --- D. run_once: full orchestration, network/subprocess mocked ---

_telegram_calls = []
_orig_send_telegram = mon.send_telegram
_orig_run_regression = mon._run_regression_tests


def _fake_send_telegram(config, msg):
    _telegram_calls.append(msg)


mon.send_telegram = _fake_send_telegram

_state_dir_d = TMPDIR / "state_d"
_state_dir_d.mkdir(exist_ok=True)
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")

# D1: below volume floor -- no notification, no config change
_write_log(_state_dir_d, [{"v1_verdict": "FALSE_POSITIVE", "v13_verdict": "FALSE_POSITIVE"}])
summary = mon.run_once(config={"state_path": str(_state_dir_d / "ids_state.json")}, monitor_state={})
check("D1: waiting on volume floor sends no Telegram notification (nothing actionable yet)",
      summary["action"] == "waiting_volume_floor" and len(_telegram_calls) == 0)
check("D1: config.yaml is untouched while waiting",
      mon._current_engine_value() == "v_current")

# D2: veto found -- notifies once, not again on a second tick with unchanged state
_telegram_calls.clear()
entries_with_fn = [
    {"v1_verdict": "CONFIRMED_THREAT", "v13_verdict": "CONFIRMED_THREAT"} for _ in range(mon.MIN_ELIGIBLE_COMPARISONS)
]
entries_with_fn.append({"v1_verdict": "CONFIRMED_THREAT", "v13_verdict": "FALSE_POSITIVE", "device_id": "dev_veto"})
_write_log(_state_dir_d, entries_with_fn)
monitor_state = {}
summary1 = mon.run_once(config={"state_path": str(_state_dir_d / "ids_state.json")}, monitor_state=monitor_state)
check("D2: a veto sends exactly one Telegram notification", summary1["action"] == "veto_blocked" and len(_telegram_calls) == 1)
summary2 = mon.run_once(config={"state_path": str(_state_dir_d / "ids_state.json")}, monitor_state=monitor_state)
check("D2: the SAME standing veto on a second tick does not re-notify (spam guard)",
      summary2["action"] == "veto_blocked" and len(_telegram_calls) == 1)
check("D2: config.yaml is untouched while vetoed",
      mon._current_engine_value() == "v_current")

# D3: bar cleared + regression passes -- flips config and notifies
_telegram_calls.clear()
_write_log(_state_dir_d, [
    {"v1_verdict": "CONFIRMED_THREAT", "v13_verdict": "CONFIRMED_THREAT"} for _ in range(mon.MIN_ELIGIBLE_COMPARISONS)
])
mon._run_regression_tests = lambda: (True, "mocked pass")
summary = mon.run_once(config={"state_path": str(_state_dir_d / "ids_state.json")}, monitor_state={})
check("D3: bar cleared + regression pass -> flipped, exactly one success notification",
      summary["action"] == "flipped" and len(_telegram_calls) == 1
      and "flipped to v13" in _telegram_calls[0])
check("D3: config.yaml actually reflects the flip", mon._current_engine_value() == "v13")

# D4: bar cleared but regression FAILS -- does not flip, notifies once, not again
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")
_telegram_calls.clear()
mon._run_regression_tests = lambda: (False, "simulated regression failure")
monitor_state = {}
summary1 = mon.run_once(config={"state_path": str(_state_dir_d / "ids_state.json")}, monitor_state=monitor_state)
check("D4: a failing regression test blocks the flip", summary1["action"] == "regression_failed"
      and mon._current_engine_value() == "v_current")
check("D4: exactly one notification for the regression failure", len(_telegram_calls) == 1)
summary2 = mon.run_once(config={"state_path": str(_state_dir_d / "ids_state.json")}, monitor_state=monitor_state)
check("D4: the SAME standing regression failure does not re-notify on a second tick",
      summary2["action"] == "regression_failed" and len(_telegram_calls) == 1)

mon.send_telegram = _orig_send_telegram
mon._run_regression_tests = _orig_run_regression


# --- E. Never restarts soc.service ---

import inspect  # noqa: E402
import ast  # noqa: E402
mon_src = inspect.getsource(mon)
check("E: the only mention of systemctl anywhere in the file is inside a notification "
      "string telling a HUMAN to run it",
      "systemctl" in mon_src and "run <code>sudo systemctl restart soc.service</code> manually" in mon_src)
_tree = ast.parse(mon_src)
_subprocess_calls = [
    n for n in ast.walk(_tree)
    if isinstance(n, ast.Call) and getattr(n.func, "attr", "") in ("run", "Popen", "call", "check_call", "system")
]
check("E: the only subprocess-shaped call in the whole file is _run_regression_tests' "
      "own python-interpreter invocation (inside its for-loop, one call site)",
      len(_subprocess_calls) == 1)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All cl_afpe_flip_monitor.py checks PASSED.")
