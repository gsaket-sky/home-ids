"""
Standalone runtime test for src/v13/ops/gap_monitor.py -- the automated per-mechanism
flip monitor (Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md's "Automated per-mechanism
flip bars" section).

Not part of the pytest suite -- run directly: `python3 tests/test_v13_gap_monitor.py`
(bare python3, no heavy deps needed, matching every other src/v13 test file's
convention).

Sections:
  A. _is_false_negative_shaped: correctly distinguishes a real false-negative-shaped
     divergence (v13 LESS severe than v-current's real verdict) from a more-severe or
     equal-severity one, which is not a veto-worthy finding
  B. _flip_flag_to_live: a targeted text edit, not a yaml round-trip -- preserves every
     surrounding comment/line, is idempotent, and fails gracefully when the flag doesn't
     exist yet in config.yaml
  C. check_mechanism: the pure decision function -- time floor, volume floor, veto, and
     bar-cleared paths, each in isolation
  D. run_once: the full orchestration, with _send_telegram/_run_regression_test
     monkeypatched so no real network call or real subprocess ever happens in this test
  E. Never restarts soc.service -- source-level check that this file contains no
     systemctl/service-restart call of any kind
"""
import json
import sys
import tempfile
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "v13" / "ops"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import v13.ops.gap_monitor as gm  # noqa: E402

TMPDIR = Path(tempfile.mkdtemp(prefix="gap_monitor_test_"))


# --- A. _is_false_negative_shaped ---

check("A: SUSPICIOUS(live) -> BENIGN(v13) is false-negative-shaped (v13 less severe)",
      gm._is_false_negative_shaped({"old_state": "SUSPICIOUS", "new_state": "BENIGN"}))
check("A: SUSPICIOUS(live) -> HIGH(v13) is NOT false-negative-shaped (v13 MORE severe)",
      not gm._is_false_negative_shaped({"old_state": "SUSPICIOUS", "new_state": "HIGH"}))
check("A: SUSPICIOUS(live) -> SUSPICIOUS(v13) (equal) is NOT false-negative-shaped",
      not gm._is_false_negative_shaped({"old_state": "SUSPICIOUS", "new_state": "SUSPICIOUS"}))
check("A: CRITICAL(live) -> SUSPICIOUS(v13) is false-negative-shaped (a real downgrade)",
      gm._is_false_negative_shaped({"old_state": "CRITICAL", "new_state": "SUSPICIOUS"}))
check("A: unknown/missing state strings default to rank 0 and don't crash",
      gm._is_false_negative_shaped({"old_state": "SOMETHING_WEIRD", "new_state": "BENIGN"}) is False)


# --- B. _flip_flag_to_live: targeted text edit ---

_SAMPLE_CONFIG = """\
network_and_devices:
  home_subnet: 192.168.1.0/24

# v13_flags: per-mechanism live/shadow switches for src/v13/ops/gap_monitor.py.
# "shadow" (default) = compute and log only, never changes real behavior.
# "live" = this mechanism's v13 verdict replaces v-current's on eligible cycles.
v13_flags:
  independence_family: shadow

telegram:
  telegram_enabled: true
"""

_mech = gm.MECHANISMS[0]
_test_config_path = TMPDIR / "config.yaml"
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")
gm.CONFIG_YAML_PATH = _test_config_path

check("B: current flag value reads 'shadow' before any flip",
      gm._current_flag_value(_mech) == "shadow")

flipped_ok = gm._flip_flag_to_live(_mech)
_after_first_flip = _test_config_path.read_text(encoding="utf-8")
check("B: _flip_flag_to_live returns True on a successful edit", flipped_ok is True)
check("B: the flag value actually changed to 'live' in the file",
      gm._current_flag_value(_mech) == "live")
check("B: every comment line and the surrounding sections are byte-for-byte preserved",
      "# v13_flags: per-mechanism live/shadow switches" in _after_first_flip
      and "home_subnet: 192.168.1.0/24" in _after_first_flip
      and "telegram_enabled: true" in _after_first_flip)
check("B: only the one line changed -- no stray reformatting of the rest of the file",
      _after_first_flip.replace("independence_family: live", "independence_family: shadow") == _SAMPLE_CONFIG)

# Idempotency: flipping an already-live flag is a no-op that still reports success
flipped_again = gm._flip_flag_to_live(_mech)
check("B: flipping an already-'live' flag is idempotent (still returns True, file unchanged)",
      flipped_again is True and _test_config_path.read_text(encoding="utf-8") == _after_first_flip)

# Missing flag entirely -- must fail gracefully, not raise or corrupt the file
_no_flag_config_path = TMPDIR / "config_no_flag.yaml"
_no_flag_config_path.write_text("network_and_devices:\n  home_subnet: 192.168.1.0/24\n", encoding="utf-8")
gm.CONFIG_YAML_PATH = _no_flag_config_path
check("B: current flag value defaults to 'shadow' when the v13_flags section doesn't exist at all",
      gm._current_flag_value(_mech) == "shadow")
check("B: attempting to flip a nonexistent flag returns False, doesn't raise",
      gm._flip_flag_to_live(_mech) is False)
check("B: the file is completely untouched when the flag doesn't exist",
      _no_flag_config_path.read_text(encoding="utf-8") == "network_and_devices:\n  home_subnet: 192.168.1.0/24\n")

gm.CONFIG_YAML_PATH = _test_config_path  # restore for section C/D


# --- C. check_mechanism: the pure decision function ---

_state_dir_c = TMPDIR / "state_c"
_state_dir_c.mkdir(exist_ok=True)

# Reset the flag back to shadow for this section's own scenarios
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")

# C1: time floor not yet reached
c1 = gm.check_mechanism(_mech, _state_dir_c, {}, today=date(2026, 9, 7))
check("C: today before not_before (2026-09-13) -> waiting_time_floor",
      c1["action"] == "waiting_time_floor")

# C2: time floor cleared, but eligible count too low
(_state_dir_c / _mech.eligible_count_file).write_text(json.dumps({"count": 5}), encoding="utf-8")
c2 = gm.check_mechanism(_mech, _state_dir_c, {}, today=date(2026, 9, 14))
check("C: time floor cleared but eligible count (5) below min (200) -> waiting_volume_floor",
      c2["action"] == "waiting_volume_floor")

# C3: both floors clear, no divergence log at all -> bar_cleared
(_state_dir_c / _mech.eligible_count_file).write_text(json.dumps({"count": 500}), encoding="utf-8")
c3 = gm.check_mechanism(_mech, _state_dir_c, {}, today=date(2026, 9, 14))
check("C: both floors clear, no divergence log present -> bar_cleared",
      c3["action"] == "bar_cleared")

# C4: a false-negative-shaped divergence in the log vetoes regardless of floors
with open(_state_dir_c / _mech.divergence_log_file, "w", encoding="utf-8") as f:
    f.write(json.dumps({"old_state": "SUSPICIOUS", "new_state": "BENIGN", "device_id": "dev1"}) + "\n")
c4_state = {}
c4 = gm.check_mechanism(_mech, _state_dir_c, c4_state, today=date(2026, 9, 14))
check("C: a false-negative-shaped divergence vetoes even with both floors clear",
      c4["action"] == "veto_blocked")
check("C: the veto is flagged for notification the FIRST time it's seen",
      c4.get("notify") is True and c4_state.get(_mech.key, {}).get("veto_notified") is True)

# C5: same veto, second check -- must NOT re-flag for notification (spam guard)
c5_state = {_mech.key: {"veto_notified": True}}
c5 = gm.check_mechanism(_mech, _state_dir_c, c5_state, today=date(2026, 9, 14))
check("C: the SAME veto on a later check does not re-trigger notify (spam guard)",
      c5["action"] == "veto_blocked" and not c5.get("notify"))

# C6: an AGREE-shaped divergence (v13 more severe, not a real veto) never blocks
(_state_dir_c / _mech.divergence_log_file).write_text(
    json.dumps({"old_state": "SUSPICIOUS", "new_state": "HIGH", "device_id": "dev2"}) + "\n",
    encoding="utf-8",
)
c6 = gm.check_mechanism(_mech, _state_dir_c, {}, today=date(2026, 9, 14))
check("C: a divergence where v13 is MORE severe never vetoes -- bar_cleared as normal",
      c6["action"] == "bar_cleared")

# C7: already live -- short-circuits immediately
_test_config_path.write_text(_SAMPLE_CONFIG.replace("independence_family: shadow", "independence_family: live"), encoding="utf-8")
c7 = gm.check_mechanism(_mech, _state_dir_c, {}, today=date(2026, 9, 14))
check("C: a mechanism already flipped to 'live' short-circuits to already_live",
      c7["action"] == "already_live")
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")  # restore


# --- D. run_once: full orchestration with real side effects monkeypatched out ---

_telegram_calls = []
_orig_send_telegram = gm._send_telegram
_orig_run_regression = gm._run_regression_test
gm._send_telegram = lambda msg: _telegram_calls.append(msg)

_state_dir_d = TMPDIR / "state_d"
_state_dir_d.mkdir(exist_ok=True)
_config_d = {"state_path": str(_state_dir_d / "ids_state.json")}

# D1: waiting on time floor -- no Telegram noise, no flip
gm._run_regression_test = lambda mech: (True, "")
summary_d1 = gm.run_once(config=_config_d, monitor_state={}, today=date(2026, 9, 7))
check("D: waiting_time_floor produces zero Telegram calls (routine, not noteworthy)",
      len(_telegram_calls) == 0 and summary_d1["waiting"])

# D2: bar cleared, regression passes -> flips and sends exactly one notification
(_state_dir_d / _mech.eligible_count_file).write_text(json.dumps({"count": 999}), encoding="utf-8")
_telegram_calls.clear()
summary_d2 = gm.run_once(config=_config_d, monitor_state={}, today=date(2026, 9, 14))
check("D: bar cleared + regression passes -> exactly one 'flipped' Telegram notification",
      len(_telegram_calls) == 1 and "flipped" in _telegram_calls[0].lower())
check("D: run_once reports the mechanism in summary['flipped']",
      _mech.key in summary_d2["flipped"])
check("D: the flip notification explicitly says soc.service is NOT restarted automatically",
      "NOT restart soc.service automatically" in _telegram_calls[0])
check("D: config.yaml's flag is now actually 'live' on disk after run_once",
      gm._current_flag_value(_mech) == "live")

# D3: re-running after already flipped -- must be silent (already_live short-circuit)
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")  # reset to shadow for D3/D4
_telegram_calls.clear()
gm._flip_flag_to_live(_mech)  # pre-flip to live directly
summary_d3 = gm.run_once(config=_config_d, monitor_state={}, today=date(2026, 9, 14))
check("D: re-running once already live sends no further notifications",
      len(_telegram_calls) == 0)
_test_config_path.write_text(_SAMPLE_CONFIG, encoding="utf-8")  # reset to shadow for D4

# D4: bar cleared but regression FAILS -> vetoed, one notification, NOT flipped
gm._run_regression_test = lambda mech: (False, "3 checks failed: [...]")
_telegram_calls.clear()
summary_d4 = gm.run_once(config=_config_d, monitor_state={}, today=date(2026, 9, 14))
check("D: a failing regression test blocks the flip -- config.yaml stays 'shadow'",
      gm._current_flag_value(_mech) == "shadow")
check("D: exactly one 'BLOCKED' notification sent for the regression failure",
      len(_telegram_calls) == 1 and "BLOCKED" in _telegram_calls[0])
check("D: run_once reports the mechanism in summary['vetoed'], not summary['flipped']",
      _mech.key in summary_d4["vetoed"] and _mech.key not in summary_d4["flipped"])

# D5: same regression failure on a second run -- must not re-notify (spam guard)
_telegram_calls.clear()
_state_after_d4 = json.loads((_state_dir_d / "gap_monitor_state.json").read_text(encoding="utf-8"))
summary_d5 = gm.run_once(config=_config_d, monitor_state=_state_after_d4, today=date(2026, 9, 14))
check("D: a repeat regression failure does not re-send the same notification",
      len(_telegram_calls) == 0)

gm._send_telegram = _orig_send_telegram
gm._run_regression_test = _orig_run_regression


# --- E. Never restarts soc.service ---

import inspect  # noqa: E402
import ast  # noqa: E402
gm_src = inspect.getsource(gm)
check("E: the only mention of systemctl anywhere in the file is inside a notification string telling a HUMAN to run it",
      "systemctl" in gm_src and "run <code>sudo systemctl restart soc.service</code> manually" in gm_src)
# Belt-and-suspenders: no Call node in the whole module's AST actually invokes
# subprocess/os against systemctl -- the only subprocess.run() call in this file must be
# _run_regression_test's own python-interpreter invocation, never a shell/systemctl call.
_tree = ast.parse(gm_src)
_subprocess_calls = [
    n for n in ast.walk(_tree)
    if isinstance(n, ast.Call) and getattr(n.func, "attr", "") in ("run", "Popen", "call", "check_call", "system")
]
check("E: the only subprocess-shaped call in the whole file is _run_regression_test's own python invocation",
      len(_subprocess_calls) == 1)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All gap_monitor.py checks PASSED.")
