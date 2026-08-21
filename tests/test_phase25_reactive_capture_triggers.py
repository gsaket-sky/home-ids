"""
Standalone runtime test for Phase 25 (Phase D of the reactive-capture plan: wiring the
triggers). Not part of the pytest suite -- run directly:
`python3 test_phase25_reactive_capture_triggers.py`.

Two things covered here:
1. ReactiveCaptureDispatcher (extractors/fritzbox_capture.py) -- the shared hourly
   budget gate every trigger draws from. Fully exercised with a real object and an
   injected fake capture_fn, no network calls, no real threading race conditions (the
   budget check itself is synchronous; only the actual capture dispatch is threaded).
2. pipeline.py's five trigger call sites (new device, ARP-sweep, DNS-suspicion,
   HIGH/CRITICAL, periodic spot-check) -- source-level guards, same pattern as
   test_phase21/test_phase22, since fully exercising the real ~900-line per-device
   loop would need a prohibitively large amount of fixture setup for what is
   ultimately a "does this call site exist with the right guard condition" question.

NOT covered here (deliberately, same rationale as test_phase23's own notes): the real
network/auth/capture path inside capture_and_ingest() itself -- that was verified live
this session (see test_phase23_fritzbox_capture.py's own notes and this session's live
SSH verification against the production Ubuntu server).
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import re
import time

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from extractors.fritzbox_capture import ReactiveCaptureDispatcher


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: ReactiveCaptureDispatcher -- pure budget logic
# ═══════════════════════════════════════════════════════════════════════════════════
disabled_config = {"reactive_capture_enabled": False, "reactive_capture_max_bursts_per_hour": 6}
d1 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
check("disabled feature (reactive_capture_enabled=False) never consumes budget",
      d1._check_and_consume_budget(disabled_config) is False)

enabled_config = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 3}
d2 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
results = [d2._check_and_consume_budget(enabled_config) for _ in range(5)]
check("budget allows exactly max_bursts_per_hour dispatches, then denies the rest",
      results == [True, True, True, False, False], f"got {results}")

d3 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
d3._window_start = time.time() - 3601  # simulate the hourly window having elapsed
d3._count = 999
check("budget resets once the hourly window has elapsed, even if the prior window was exhausted",
      d3._check_and_consume_budget(enabled_config) is True)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: ReactiveCaptureDispatcher.try_dispatch -- actually fires the capture fn
# ═══════════════════════════════════════════════════════════════════════════════════
calls = []
def fake_capture(config, zeek_fx, out_dir, zeek_bin="/opt/zeek/bin/zeek", trigger_reason="unspecified"):
    calls.append({"trigger_reason": trigger_reason, "out_dir": out_dir, "zeek_bin": zeek_bin})

d4 = ReactiveCaptureDispatcher(capture_fn=fake_capture)
cfg = {
    "reactive_capture_enabled": True,
    "reactive_capture_max_bursts_per_hour": 1,
    "reactive_capture_scratch_dir": "state/reactive_capture_test",
    "reactive_capture_zeek_bin": "/opt/zeek/bin/zeek",
}
dispatched = d4.try_dispatch(cfg, zeek_fx=object(), trigger_reason="unit_test")
check("try_dispatch returns True when budget allows", dispatched is True)

# The actual work runs on a daemon thread -- give it a moment to complete.
for _ in range(50):
    if calls:
        break
    time.sleep(0.02)
check("the injected capture_fn actually ran (proves try_dispatch really spins a background thread)",
      len(calls) == 1, f"got {len(calls)} calls")
if calls:
    check("trigger_reason is passed through correctly", calls[0]["trigger_reason"] == "unit_test")

second_dispatch = d4.try_dispatch(cfg, zeek_fx=object(), trigger_reason="unit_test_2")
check("a second dispatch within the same hour, over budget (max=1), is refused",
      second_dispatch is False)
time.sleep(0.1)
check("a refused dispatch never calls the capture_fn at all",
      len(calls) == 1, f"got {len(calls)} calls (expected still 1)")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: pipeline.py -- source-level guards for the 5 trigger call sites
# ═══════════════════════════════════════════════════════════════════════════════════
with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src = f.read()

check("ReactiveCaptureDispatcher is imported", "from extractors.fritzbox_capture import ReactiveCaptureDispatcher" in pipeline_src)
check("a single shared dispatcher instance is created in __init__ (not one per trigger)",
      "self.reactive_capture = ReactiveCaptureDispatcher()" in pipeline_src)

check("new-device trigger fires right after a genuinely new device is cold-started",
      re.search(r'if not self\.state_manager\.has_device\(dev_id\):.*?trigger_reason="new_device"',
                pipeline_src, re.DOTALL) is not None)

check("ARP-sweep trigger checks for arp_sweep evidence in THIS cycle's threat_signal_ev "
      "(not the whole evidence store, which could include stale prior-cycle evidence)",
      'any(ev.type == "arp_sweep" for ev in threat_signal_ev)' in pipeline_src)
check("ARP-sweep trigger call site exists with the correct trigger_reason",
      'trigger_reason="arp_sweep"' in pipeline_src)

check("DNS-suspicion trigger is widened to ANY non-benign decision_path, not just SUSPICIOUS+",
      'decision.get("decision_path", "benign") != "benign"' in pipeline_src)
check("DNS-suspicion trigger call site exists with the correct trigger_reason",
      'trigger_reason="dns_suspicion"' in pipeline_src)

check("HIGH/CRITICAL trigger reuses the exact same telegram_worthy boolean as the Telegram gate "
      "(same HIGH/CRITICAL bar, not a separately-drifting threshold)",
      re.search(r'telegram_worthy and not fp_verdict\["suppress"\]:\s*\n\s*self\.reactive_capture\.try_dispatch',
                pipeline_src) is not None)
check("HIGH/CRITICAL trigger call site exists with the correct trigger_reason",
      'trigger_reason="high_severity"' in pipeline_src)

check("periodic spot-check trigger is a plain elapsed-time check (not per-device)",
      "self._last_reactive_spotcheck_ts" in pipeline_src)
check("periodic spot-check call site exists with the correct trigger_reason",
      'trigger_reason="spotcheck"' in pipeline_src)
check("spot-check interval seed avoids firing immediately on every process restart",
      "self._last_reactive_spotcheck_ts = time.time()" in pipeline_src)

# All 5 triggers must be individually config-gated, matching "each source can be
# individually disabled without touching the shared budget" from the plan.
for flag in (
    "reactive_capture_new_device_trigger_enabled",
    "reactive_capture_arp_sweep_trigger_enabled",
    "reactive_capture_dns_trigger_enabled",
    "reactive_capture_high_severity_trigger_enabled",
    "reactive_capture_spotcheck_enabled",
):
    check(f"{flag} is read from config.yaml to gate its trigger", flag in pipeline_src)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 25 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 25 reactive-capture-trigger checks PASSED.")
    sys.exit(0)
