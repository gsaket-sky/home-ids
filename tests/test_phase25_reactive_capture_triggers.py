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
import threading

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
# Section A1b (Phase 13, RouterAdapter capability check, autonomy-completion effort):
# reactive capture is AVM-pcap-format-specific -- structurally impossible without a
# real Fritz!Box, checked BEFORE reactive_capture_enabled/the rate-limit budgets, not
# alongside them.
# ═══════════════════════════════════════════════════════════════════════════════════
no_router_config = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 6,
                      "router_type": "none"}
d_no_router = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
check("router_type='none' rejects dispatch even though reactive_capture_enabled=True "
      "and the rate budget is wide open -- capability, not rate, is the reason",
      d_no_router._check_and_consume_budget(no_router_config) is False)
check("REGRESSION GUARD: a 'none' router never actually consumed a budget slot "
      "(the count never incremented) -- this is a capability rejection, not a "
      "rate-limit deferral that should count against the hourly window",
      d_no_router._count == 0)

fritzbox_config = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 6,
                     "router_type": "fritzbox"}
d_fritzbox = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
check("router_type='fritzbox' is unaffected -- dispatch proceeds normally",
      d_fritzbox._check_and_consume_budget(fritzbox_config) is True)

d_default = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
check("no router_type key at all defaults to the same (unaffected) fritzbox behavior "
      "as an explicit router_type='fritzbox' -- matches every real deployment's "
      "config.yaml before this phase existed",
      d_default._check_and_consume_budget(enabled_config) is True)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A2 (LOAD-ANALYSIS FIX #1, Documentation/REACTIVE_CAPTURE_LOAD_ANALYSIS.md §5):
# aggregate bytes-per-hour budget -- a SECOND gate alongside burst count, since count
# alone never bounded how large any one burst was (a real incident saw burst size
# spike ~10x while staying entirely within the count budget).
# ═══════════════════════════════════════════════════════════════════════════════════
bytes_config = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 6,
                "reactive_capture_max_bytes_per_hour": 1000}

d6 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
check("bytes budget allows a dispatch when nothing has been captured yet this window",
      d6._check_and_consume_budget(bytes_config) is True)
d6._bytes_captured = 1000  # simulate a prior burst having already filled the byte budget
check("bytes budget denies a dispatch once cumulative bytes captured this window meet/exceed "
      "reactive_capture_max_bytes_per_hour, even though the burst-COUNT budget (6) is nowhere "
      "near exhausted",
      d6._check_and_consume_budget(bytes_config) is False)

d7 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
d7._bytes_captured = 999_999_999
zero_bytes_budget_config = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 6,
                             "reactive_capture_max_bytes_per_hour": 0}
check("reactive_capture_max_bytes_per_hour=0 disables the bytes gate entirely (count-only, "
      "pre-fix behavior) regardless of how many bytes were already captured",
      d7._check_and_consume_budget(zero_bytes_budget_config) is True)

d8 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
d8._window_start = time.time() - 3601
d8._bytes_captured = 999_999_999
check("the bytes counter resets alongside the count on hourly window rollover",
      d8._check_and_consume_budget(bytes_config) is True and d8._bytes_captured == 0,
      f"got bytes_captured={d8._bytes_captured}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B3 (LOAD-ANALYSIS FIX #1): try_dispatch() actually records real captured
# bytes from capture_fn's return value once a burst completes, and defers a subsequent
# trigger once that pushes the window over budget.
# ═══════════════════════════════════════════════════════════════════════════════════
def fake_capture_with_bytes(config, zeek_fx, out_dir, zeek_bin="/opt/zeek/bin/zeek",
                             trigger_reason="unspecified", **kwargs):
    return {"radios_captured": {"ath0": {"bytes": 600, "records": 10},
                                 "ath1": {"bytes": 500, "records": 8}}}

d9 = ReactiveCaptureDispatcher(capture_fn=fake_capture_with_bytes)
cfg9 = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 6,
        "reactive_capture_max_bytes_per_hour": 1000,
        "reactive_capture_scratch_dir": "state/reactive_capture_test"}
first9 = d9.try_dispatch(cfg9, zeek_fx=object(), trigger_reason="unit_test")
for _ in range(50):
    if d9._bytes_captured:
        break
    time.sleep(0.02)
check("a completed burst's real captured bytes (summed across radios) are added to the "
      "dispatcher's bytes-budget counter",
      d9._bytes_captured == 1100, f"got {d9._bytes_captured}")

second9 = d9.try_dispatch(cfg9, zeek_fx=object(), trigger_reason="unit_test_2")
check("a subsequent trigger is deferred once the bytes already captured this window "
      "(1100) meets/exceeds reactive_capture_max_bytes_per_hour (1000), even though the "
      "burst-COUNT budget (6) still has room",
      second9 is False)

d10 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
cfg10 = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 6,
         "reactive_capture_max_bytes_per_hour": 1000,
         "reactive_capture_scratch_dir": "state/reactive_capture_test"}
d10.try_dispatch(cfg10, zeek_fx=object(), trigger_reason="unit_test")
time.sleep(0.1)
check("a test stub's capture_fn returning None (not a dict) is handled gracefully -- "
      "bytes counter stays at 0, no crash",
      d10._bytes_captured == 0, f"got {d10._bytes_captured}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: ReactiveCaptureDispatcher.try_dispatch -- actually fires the capture fn
# ═══════════════════════════════════════════════════════════════════════════════════
calls = []
def fake_capture(config, zeek_fx, out_dir, zeek_bin="/opt/zeek/bin/zeek", trigger_reason="unspecified", **kwargs):
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
# Section B2 (BUGFIX regression guard): concurrent bursts must never overlap. Found in
# production -- the hourly budget only ever limited total COUNT, never CONCURRENT
# execution, so rapid-fire triggers (dns_suspicion/arp_sweep/wired_probe all firing
# within seconds of each other) spawned overlapping capture_and_ingest() calls against
# the same physical radio, which can only sustain one real capture session at a time.
# Symptom in the field: repeated "Capture on athX produced an empty file" and a
# genuinely-written .std.pcap disappearing before Zeek could read it.
# ═══════════════════════════════════════════════════════════════════════════════════
_peak_concurrency = {"n": 0, "max": 0}
_peak_lock = threading.Lock()

def slow_capture(config, zeek_fx, out_dir, zeek_bin="/opt/zeek/bin/zeek", trigger_reason="unspecified", **kwargs):
    with _peak_lock:
        _peak_concurrency["n"] += 1
        _peak_concurrency["max"] = max(_peak_concurrency["max"], _peak_concurrency["n"])
    time.sleep(0.3)
    with _peak_lock:
        _peak_concurrency["n"] -= 1

d5 = ReactiveCaptureDispatcher(capture_fn=slow_capture)
cfg5 = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 6}
dispatch_results = []
for i in range(4):
    dispatch_results.append(d5.try_dispatch(cfg5, zeek_fx=object(), trigger_reason=f"burst_{i}"))
    time.sleep(0.05)
time.sleep(1.0)

check("only the first of 4 rapid-fire triggers actually dispatches; the rest defer "
      "(a burst is already in flight), not because the budget (6) was exhausted",
      dispatch_results == [True, False, False, False], f"got {dispatch_results}")
check("THE CORE FIX: no two bursts ever ran capture_fn concurrently",
      _peak_concurrency["max"] == 1, f"peak concurrent executions={_peak_concurrency['max']}")
check("a trigger deferred due to overlap does NOT consume a real budget slot "
      "(refunded, since it never actually ran)",
      d5._count == 1, f"got _count={d5._count} (expected 1 -- only the one real execution)")


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


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: ambiguous re-identification trigger -- real StateManager, no mocks
# ═══════════════════════════════════════════════════════════════════════════════════
from core.state_guard import StateManager

# D1: a hostname-only match (dhcp_score=0, ja4_sim=0, hostname_ok=True) scores exactly
# 0.50 per device_matching.match_confidence()'s formula -- squarely in the ambiguous
# band (MIN_CANDIDATE_CONFIDENCE=0.45, AUTO_MERGE_CONFIDENCE=0.75 default merge bar).
sm = StateManager()
old_state = sm.get_or_create("old_dev", "192.168.1.50", "my-nas", alpha=0.05)
old_state.last_seen = time.time() - 100.0  # idle, but within the 1800s candidate_window

new_state = sm.get_or_create("new_dev", "192.168.1.51", "my-nas", alpha=0.05,
                              ja4_set={"some_ja4_hash_not_shared_with_old_dev"})

check("an ambiguous hostname-only match does NOT auto-merge (new_dev cold-started as its own device)",
      sm.has_device("new_dev") and sm.has_device("old_dev"), f"ids={sm.get_all_device_ids()}")

ambiguous = sm.pop_last_reidentify_ambiguous()
check("THE CORE FIX: an ambiguous candidate (below the merge bar but above "
      "MIN_CANDIDATE_CONFIDENCE) is surfaced via pop_last_reidentify_ambiguous(), not silently lost",
      ambiguous is not None, f"got {ambiguous}")
if ambiguous:
    check("the ambiguous finding names the correct candidate and confidence",
          ambiguous["candidate_id"] == "old_dev" and abs(ambiguous["confidence"] - 0.50) < 1e-9,
          f"got {ambiguous}")

check("pop_last_reidentify_ambiguous() is consume-once -- a second immediate pop returns None",
      sm.pop_last_reidentify_ambiguous() is None)

# D2: a genuine strong match (DHCP match + strong JA4 overlap) still auto-merges exactly
# as before PHASE 21D -- regression guard against breaking the existing merge behavior
# while adding the ambiguous side channel.
sm2 = StateManager()
old2 = sm2.get_or_create("old_dev2", "192.168.1.60", "printer-office", alpha=0.05)
old2.last_seen = time.time() - 100.0
# get_or_create()'s dhcp_fingerprint/ja4_set params are only used transiently to
# compare an INCOMING device against EXISTING candidates -- they are not persisted
# onto the new DeviceState itself. Set them directly here to simulate a device that
# has accumulated this fingerprint over time (what _find_reidentify_candidate() reads
# via getattr(cand_state, "dhcp_fingerprint"/"ja4_seen", ...)).
old2.dhcp_fingerprint = {"vendor_class": "MSFT 5.0", "param_list": [1, 3, 6], "user_class": ""}
old2.ja4_seen = {"hashA", "hashB"}

new2 = sm2.get_or_create("new_dev2", "192.168.1.61", "printer-office", alpha=0.05,
                          dhcp_fingerprint={"vendor_class": "MSFT 5.0", "param_list": [1, 3, 6], "user_class": ""},
                          ja4_set={"hashA", "hashB"})
# migrate_device_id() merges the OLD identity's history FORWARD under the NEW
# device_id (the just-observed one) and retires the old id -- not the other way
# around.
check("a strong DHCP+JA4 match still auto-merges (continues under new_dev2, old_dev2 retired)",
      sm2.has_device("new_dev2") and not sm2.has_device("old_dev2"))
check("a genuine auto-merge is NOT also reported as ambiguous (mutually exclusive outcomes)",
      sm2.pop_last_reidentify_ambiguous() is None)

# D3: totally unrelated fingerprints -- no candidate at all, no ambiguous report either.
sm3 = StateManager()
old3 = sm3.get_or_create("old_dev3", "192.168.1.70", "esp32-sensor", alpha=0.05)
old3.last_seen = time.time() - 100.0
sm3.get_or_create("new_dev3", "192.168.1.71", "totally-different-name", alpha=0.05,
                   ja4_set={"unrelated_hash"})
check("completely unrelated fingerprints produce neither a merge nor an ambiguous report",
      sm3.has_device("old_dev3") and sm3.has_device("new_dev3") and sm3.pop_last_reidentify_ambiguous() is None)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: wired-device-probe trigger -- real ZeekFeatureExtractor, no mocks
# ═══════════════════════════════════════════════════════════════════════════════════
from extractors.zeek_features import ZeekFeatureExtractor

WIRED_IP = "192.168.1.94"
zfx_probe = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"], wired_probe_ips={WIRED_IP})

zfx_probe.ingest({"_zeek_type": "conn", "id.orig_h": "192.168.1.50", "id.resp_h": WIRED_IP,
                   "id.resp_p": 445, "proto": "tcp", "orig_bytes": 100, "uid": "C1", "ts": time.time()})
found = zfx_probe.pop_new_wired_probe_sources()
check("a first-time source contacting a configured wired-probe IP is queued",
      found == [(WIRED_IP, "192.168.1.50")], f"got {found}")

check("pop_new_wired_probe_sources() is consume-once -- a second immediate pop returns empty",
      zfx_probe.pop_new_wired_probe_sources() == [])

# Same source again -- must NOT re-queue (already known).
zfx_probe.ingest({"_zeek_type": "conn", "id.orig_h": "192.168.1.50", "id.resp_h": WIRED_IP,
                   "id.resp_p": 445, "proto": "tcp", "orig_bytes": 50, "uid": "C2", "ts": time.time()})
check("the SAME source contacting the wired device again does NOT re-trigger",
      zfx_probe.pop_new_wired_probe_sources() == [])

# A genuinely different source -- must queue.
zfx_probe.ingest({"_zeek_type": "conn", "id.orig_h": "192.168.1.51", "id.resp_h": WIRED_IP,
                   "id.resp_p": 445, "proto": "tcp", "orig_bytes": 50, "uid": "C3", "ts": time.time()})
check("a genuinely DIFFERENT new source contacting the same wired device does trigger",
      zfx_probe.pop_new_wired_probe_sources() == [(WIRED_IP, "192.168.1.51")])

# Connections to a non-wired-probe destination are never tracked at all (control).
zfx_probe.ingest({"_zeek_type": "conn", "id.orig_h": "192.168.1.99", "id.resp_h": "8.8.8.8",
                   "id.resp_p": 443, "proto": "tcp", "orig_bytes": 50, "uid": "C4", "ts": time.time()})
check("a connection to an IP NOT in wired_probe_ips is never queued",
      zfx_probe.pop_new_wired_probe_sources() == [])

# Feature is opt-in/inert when wired_probe_ips is unset (matches default config: []).
zfx_default = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
zfx_default.ingest({"_zeek_type": "conn", "id.orig_h": "192.168.1.50", "id.resp_h": "192.168.1.94",
                     "id.resp_p": 445, "proto": "tcp", "orig_bytes": 100, "uid": "C5", "ts": time.time()})
check("with wired_probe_ips unset (default), nothing is ever tracked/queued",
      zfx_default.pop_new_wired_probe_sources() == [])


# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: pipeline.py -- source-level guards for the 2 completed remaining triggers
# ═══════════════════════════════════════════════════════════════════════════════════
check("pipeline.py now passes real DHCP/JA4 fingerprints into get_or_create() (previously "
      "never did, so the reidentify branch could never even run from this call site)",
      "dhcp_fingerprint=dhcp_fp, ja4_set=ja4s" in pipeline_src)
check("ambiguous re-id trigger call site exists with the correct trigger_reason",
      'trigger_reason="ambiguous_reidentify"' in pipeline_src)
check("reactive_capture_reid_ambiguous_trigger_enabled gates the ambiguous re-id trigger",
      "reactive_capture_reid_ambiguous_trigger_enabled" in pipeline_src)

check("ZeekFeatureExtractor is constructed with wired_probe_ips from config",
      "wired_probe_ips=wired_probe_ips" in pipeline_src)
check("wired-probe trigger call site exists with the correct trigger_reason",
      'trigger_reason="wired_probe"' in pipeline_src)
check("reactive_capture_wired_probe_trigger_enabled gates the wired-probe trigger",
      "reactive_capture_wired_probe_trigger_enabled" in pipeline_src)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section G: pipeline.py wires the disk-safety stale-file sweep into the same periodic
# spot-check interval (piggybacked, not a separate timer).
# ═══════════════════════════════════════════════════════════════════════════════════
check("cleanup_stale_scratch_files is imported from fritzbox_capture.py",
      "from extractors.fritzbox_capture import ReactiveCaptureDispatcher, cleanup_stale_scratch_files" in pipeline_src)
check("the stale-file sweep is actually invoked, not just imported",
      "cleanup_stale_scratch_files(scratch_dir)" in pipeline_src)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section H (2026-09-27, Phase 2 of the autonomy-completion effort): the scratch-dir
# disk-budget gate -- reject-when-full, prune-oldest-first. Uses a REAL temp directory
# with real files (unlike Sections A/A2 above, which never touch disk) since this is
# exactly what _check_disk_budget() reads from the filesystem.
# ═══════════════════════════════════════════════════════════════════════════════════
import os as _os
import shutil
import tempfile


def _make_scratch_file(scratch_dir, name, size_bytes, age_seconds_ago):
    path = scratch_dir / name
    path.write_bytes(b"x" * size_bytes)
    ts = time.time() - age_seconds_ago
    _os.utime(path, (ts, ts))
    return path


scratch_root = _PathForSysPath(tempfile.mkdtemp(prefix="reactive_capture_disk_budget_test_"))
try:
    # --- under budget: no pruning, dispatch allowed ---
    _make_scratch_file(scratch_root, "small.pcap", 100, age_seconds_ago=10)
    d10 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
    cfg10 = {"reactive_capture_scratch_dir": str(scratch_root), "reactive_capture_max_scratch_bytes": 10_000}
    check("_check_disk_budget: under budget, allows a dispatch with no pruning",
          d10._check_disk_budget(cfg10) is True)
    check("_check_disk_budget: not degraded when under budget",
          d10._disk_degraded is False)

    # --- over budget: prunes the OLDEST file first, recovers under budget ---
    scratch_root2 = _PathForSysPath(tempfile.mkdtemp(prefix="reactive_capture_disk_budget_test2_"))
    _make_scratch_file(scratch_root2, "oldest.pcap", 6_000, age_seconds_ago=3000)
    _make_scratch_file(scratch_root2, "newest.pcap", 3_000, age_seconds_ago=10)
    d11 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
    cfg11 = {"reactive_capture_scratch_dir": str(scratch_root2), "reactive_capture_max_scratch_bytes": 5_000}
    result11 = d11._check_disk_budget(cfg11)
    check("_check_disk_budget: over budget, pruning the OLDEST file alone recovers under budget -- allows dispatch",
          result11 is True, f"remaining entries: {list(scratch_root2.iterdir())}")
    check("_check_disk_budget: the OLDEST file was removed, the NEWEST one was kept",
          not (scratch_root2 / "oldest.pcap").exists() and (scratch_root2 / "newest.pcap").exists())
    shutil.rmtree(scratch_root2, ignore_errors=True)

    # --- over budget even after pruning everything prunable: the ONLY way this can
    # happen given prune-oldest-FULLY (not partial) is the exempt history JSONL alone
    # already exceeding budget -- any other oversized file gets pruned away entirely,
    # which always succeeds. Also proves the exemption itself: the history file is
    # never deleted even though it's the oldest/largest/only thing present. ---
    scratch_root3 = _PathForSysPath(tempfile.mkdtemp(prefix="reactive_capture_disk_budget_test3_"))
    _make_scratch_file(scratch_root3, "reactive_capture_history.jsonl", 20_000, age_seconds_ago=100000)
    d12 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
    cfg12 = {"reactive_capture_scratch_dir": str(scratch_root3), "reactive_capture_max_scratch_bytes": 5_000}
    result12 = d12._check_disk_budget(cfg12)
    check("_check_disk_budget: still over budget after pruning everything prunable "
          "(only the exempt history file remains) -- rejects",
          result12 is False)
    check("_check_disk_budget: sets self._disk_degraded so try_dispatch() can log/metric the right outcome",
          d12._disk_degraded is True)
    check("_check_disk_budget: the permanent history JSONL is exempt from scratch-overflow pruning "
          "even when it's the oldest/largest/only thing present -- correctly stays over budget/rejects "
          "rather than deleting it",
          (scratch_root3 / "reactive_capture_history.jsonl").exists())
    shutil.rmtree(scratch_root3, ignore_errors=True)

    # --- try_dispatch() surfaces the disk-degraded rejection as its own metric outcome ---
    scratch_root5 = _PathForSysPath(tempfile.mkdtemp(prefix="reactive_capture_disk_budget_test5_"))
    _make_scratch_file(scratch_root5, "reactive_capture_history.jsonl", 20_000, age_seconds_ago=100000)
    d14 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
    cfg14 = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 6,
             "reactive_capture_scratch_dir": str(scratch_root5), "reactive_capture_max_scratch_bytes": 5_000}
    dispatched14 = d14.try_dispatch(cfg14, zeek_fx=object(), trigger_reason="unit_test_disk_budget")
    check("try_dispatch: a disk-degraded scratch dir rejects dispatch entirely, before even "
          "touching the hourly count budget", dispatched14 is False and d14._count == 0,
          f"dispatched={dispatched14} count={d14._count}")
    shutil.rmtree(scratch_root5, ignore_errors=True)

    # --- a nonexistent scratch dir is a safe no-op (nothing to check yet) ---
    d15 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
    cfg15 = {"reactive_capture_scratch_dir": str(scratch_root / "does_not_exist_yet"),
             "reactive_capture_max_scratch_bytes": 5_000}
    check("_check_disk_budget: a scratch dir that doesn't exist yet is a safe no-op, not a crash",
          d15._check_disk_budget(cfg15) is True)

    # --- try_dispatch() surfaces the router-capability rejection distinctly (Phase 13) ---
    d16 = ReactiveCaptureDispatcher(capture_fn=lambda *a, **k: None)
    cfg16 = {"reactive_capture_enabled": True, "reactive_capture_max_bursts_per_hour": 6, "router_type": "none"}
    dispatched16 = d16.try_dispatch(cfg16, zeek_fx=object(), trigger_reason="unit_test_no_router")
    check("try_dispatch: router_type='none' rejects dispatch entirely -- structural "
          "capability, never counted against the hourly budget",
          dispatched16 is False and d16._count == 0,
          f"dispatched={dispatched16} count={d16._count}")
finally:
    shutil.rmtree(scratch_root, ignore_errors=True)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 25 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 25 reactive-capture-trigger checks PASSED.")
    sys.exit(0)
