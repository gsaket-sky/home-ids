"""
Standalone runtime test for Phase 27 (Phase D3 of the reactive-capture plan:
autonomous improvement in detection, plus 'enable per device tuning' -- automatic
per-device ARP-sweep threshold calibration). Not part of the pytest suite -- run
directly: `python3 test_phase27_local_intel_and_confirmed_tuning.py`.

Covers:
  A. local_intel.py's LocalConfirmedIntel -- record/check/prune/TTL, real object.
  B. fp_engine.py's record_confirmed_threat() -- feeds local_intel AND the (overall
     and signature-scoped) confirmed counter; the new Stage-1 check #7 hard-stops a
     DIFFERENT device touching a previously-confirmed IOC.
  C. retro_hunter.py's check_local_intel_history() -- cross-device retroactive match,
     correctly excludes a device that already confirmed the IOC itself.
  D. train_fp_classifier.py's calibrate_arp_sweep_threshold() -- the bidirectional
     per-device rule -- plus a full run_threshold_calibration() integration proving a
     device's threshold is actually raised end-to-end from real muted-log evidence.
  E. pipeline.py source-guards for both confirmed-threat feed points.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import json
import time
import tempfile
from pathlib import Path

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.local_intel import LocalConfirmedIntel
from intelligence.fp_engine import AutonomousFPEngine


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: LocalConfirmedIntel
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    intel = LocalConfirmedIntel(tmpdir, ttl_seconds=3600.0)

    check("record() returns True for a genuinely new IOC", intel.record("ip", "1.2.3.4", "devA") is True)
    check("record() returns False on a repeat (refresh, not new)", intel.record("ip", "1.2.3.4", "devB") is False)
    check("check() finds a recorded, non-expired IOC", intel.check("ip", "1.2.3.4") is not None)
    check("check() returns None for a never-recorded value", intel.check("ip", "9.9.9.9") is None)
    check("an invalid kind is rejected safely", intel.record("ja3", "somehash", "devA") is False)
    check("empty/placeholder values are rejected", intel.record("ip", "", "devA") is False and
          intel.record("ip", "unknown", "devA") is False)

    entry = intel.check("ip", "1.2.3.4")
    check("repeated record() calls accumulate BOTH sources and count",
          entry["count"] == 2 and set(entry["sources"]) == {"devA", "devB"}, f"got {entry}")

    # TTL expiry
    intel2 = LocalConfirmedIntel(tmpdir + "_ttl", ttl_seconds=1.0)
    intel2.record("domain", "evil.example.com", "devC")
    check("a fresh entry is not expired", intel2.check("domain", "evil.example.com") is not None)
    with intel2._lock:
        intel2._store["domain"]["evil.example.com"]["last_confirmed"] = time.time() - 10.0
    check("an entry past its TTL is treated as expired (check() returns None)",
          intel2.check("domain", "evil.example.com") is None)
    pruned = intel2.prune_expired()
    check("prune_expired() actually removes the stale entry and reports the count",
          pruned == 1 and intel2.check("domain", "evil.example.com") is None)

    # Persistence round-trip
    intel3 = LocalConfirmedIntel(tmpdir, ttl_seconds=3600.0)
    check("a fresh LocalConfirmedIntel instance loads previously-saved entries from disk",
          intel3.check("ip", "1.2.3.4") is not None)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: fp_engine.py -- record_confirmed_threat() + Stage-1 check #7
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    fp.record_confirmed_threat("dev_A", "malicious-c2.example", "6.6.6.6",
                                reason="STAGE_1_HARD_STOP", signature="DATA_EXFILTRATION")

    check("record_confirmed_threat() feeds local_intel with the domain",
          fp.local_intel.check("domain", "malicious-c2.example") is not None)
    check("record_confirmed_threat() feeds local_intel with the IP",
          fp.local_intel.check("ip", "6.6.6.6") is not None)
    check("record_confirmed_threat() increments the device's OVERALL confirmed count",
          fp.get_confirmed_count("dev_A") == 1)
    check("record_confirmed_threat() ALSO increments the signature-SCOPED confirmed count",
          fp.get_confirmed_count("dev_A", signature="DATA_EXFILTRATION") == 1)
    check("a DIFFERENT signature's scoped count for this device is unaffected",
          fp.get_confirmed_count("dev_A", signature="CONNECTION_ABUSE") == 0)
    check("a DIFFERENT device's confirmed count is completely unaffected",
          fp.get_confirmed_count("dev_B") == 0)

    # THE CORE FIX: a DIFFERENT device connecting to the same confirmed IOC gets an
    # immediate hard-stop via evaluate(), without needing its own hard-stop signal.
    later_alert = {
        "device": {"id": "dev_B", "hostname": "some-other-device"},
        "network_context": {"queried_domain": "malicious-c2.example", "destination_ip": "1.1.1.1"},
        "signature": "",
        "timestamp": time.time(),
    }
    safe_features = {"ti_risk": 0.0, "zeek_lateral_moves": 0, "zeek_ja3_malicious": 0,
                      "zeek_ja4_malicious": 0, "zeek_honeypot_hits": 0, "abuseipdb_risk": 0.0,
                      "outbound_bytes_z": 0.0}
    verdict = fp.evaluate(later_alert, safe_features, risk_score=5.0, ti_engine=None)
    check("THE CORE FIX: a DIFFERENT device (dev_B) touching a domain dev_A already "
          "confirmed hard-stops as CONFIRMED_THREAT with NO hard-stop signal of its own",
          verdict["verdict"] == "CONFIRMED_THREAT" and verdict["stage"] == "STAGE_1_HARD_STOP",
          f"got={verdict}")
    check("the trigger text names the local confirmed-intel match specifically",
          any("Local confirmed-threat match" in r for r in verdict["reasons"]), f"got={verdict['reasons']}")

    # A domain/IP that was never confirmed by anyone must NOT hard-stop.
    clean_alert = {
        "device": {"id": "dev_C", "hostname": "clean-device"},
        "network_context": {"queried_domain": "totally-unrelated-safe-site.example", "destination_ip": "2.2.2.2"},
        "signature": "",
        "timestamp": time.time(),
    }
    verdict_clean = fp.evaluate(clean_alert, safe_features, risk_score=5.0, ti_engine=None)
    check("an unrelated domain/IP with no confirmed-intel match does NOT hard-stop via check #7",
          verdict_clean["stage"] != "STAGE_1_HARD_STOP", f"got={verdict_clean}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: retro_hunter.py -- check_local_intel_history()
# ═══════════════════════════════════════════════════════════════════════════════════
from scripts.retro_hunter import check_local_intel_history

with tempfile.TemporaryDirectory() as tmpdir:
    state_dir = Path(tmpdir)
    intel = LocalConfirmedIntel(state_dir)
    intel.record("ip", "7.7.7.7", "dev_confirmed_it")

    alerts_path = state_dir / "alerts.json"
    now = time.time()
    with open(alerts_path, "w", encoding="utf-8") as f:
        # A DIFFERENT device that touched the same IP 2 days ago, below its own
        # threshold at the time -- exactly the case this is supposed to catch.
        f.write(json.dumps({
            "timestamp": now - 2 * 86400, "device": {"id": "dev_missed_it", "hostname": "missed-host"},
            "network_context": {"queried_domain": "", "destination_ip": "7.7.7.7"},
        }) + "\n")
        # The SAME device that already confirmed it -- must be excluded (not a new finding).
        f.write(json.dumps({
            "timestamp": now - 1 * 86400, "device": {"id": "dev_confirmed_it", "hostname": "confirmed-host"},
            "network_context": {"queried_domain": "", "destination_ip": "7.7.7.7"},
        }) + "\n")
        # Unrelated traffic -- must not appear.
        f.write(json.dumps({
            "timestamp": now - 1 * 86400, "device": {"id": "dev_unrelated", "hostname": "unrelated-host"},
            "network_context": {"queried_domain": "", "destination_ip": "8.8.8.8"},
        }) + "\n")

    matches = check_local_intel_history(alerts_path, intel, days_back=14)
    matched_devices = {m["device_id"] for m in matches}
    check("THE CORE FIX: a DIFFERENT device's historical touch of a since-confirmed IOC is found",
          "dev_missed_it" in matched_devices, f"got devices={matched_devices}")
    check("the device that already confirmed the IOC itself is EXCLUDED (not a new finding)",
          "dev_confirmed_it" not in matched_devices, f"got devices={matched_devices}")
    check("unrelated traffic never appears in the results",
          "dev_unrelated" not in matched_devices, f"got devices={matched_devices}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: train_fp_classifier.py -- calibrate_arp_sweep_threshold() bidirectional rule
# ═══════════════════════════════════════════════════════════════════════════════════
from scripts.train_fp_classifier import (
    calibrate_arp_sweep_threshold, _collect_connection_abuse_corrections,
    run_threshold_calibration, ARP_SWEEP_MIN_CORRECTED_SAMPLES, ARP_SWEEP_MIN_CONFIRMED_SAMPLES,
)

new_val, reason = calibrate_arp_sweep_threshold(corrected_count=2, confirmed_count=0, current=8.0)
check("2+ corrections with zero confirmations RAISES the threshold",
      new_val is not None and new_val > 8.0, f"got={new_val}, reason={reason}")

new_val2, reason2 = calibrate_arp_sweep_threshold(corrected_count=0, confirmed_count=5, current=8.0)
check("5+ confirmations with zero corrections LOWERS (tightens) the threshold",
      new_val2 is not None and new_val2 < 8.0, f"got={new_val2}, reason={reason2}")

new_val3, reason3 = calibrate_arp_sweep_threshold(corrected_count=2, confirmed_count=5, current=8.0)
check("mixed/contradictory evidence (both corrections AND confirmations) makes NO automatic change",
      new_val3 is None, f"got={new_val3}, reason={reason3}")

new_val4, reason4 = calibrate_arp_sweep_threshold(corrected_count=1, confirmed_count=0, current=8.0)
check("below the minimum sample count on either side makes NO change",
      new_val4 is None, f"got={new_val4}")

new_val5, _ = calibrate_arp_sweep_threshold(corrected_count=100, confirmed_count=0, current=39.0)
check("the raised threshold never exceeds its ceiling",
      new_val5 is not None and new_val5 <= 40.0, f"got={new_val5}")

new_val6, _ = calibrate_arp_sweep_threshold(corrected_count=0, confirmed_count=100, current=4.5)
check("the lowered threshold never goes below its floor",
      new_val6 is not None and new_val6 >= 4.0, f"got={new_val6}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D2: full end-to-end integration -- real muted-log evidence -> real per-device
# threshold change, via the actual run_threshold_calibration() entry point
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    state_dir = Path(tmpdir)
    fp = AutonomousFPEngine(config={}, state_dir=str(state_dir))
    device_id = "dev_smart_hub_autocal"

    # Two real CONNECTION_ABUSE corrections via the actual mark_false_positive() path
    # (not hand-written JSONL) -- proves the whole chain from a real operator
    # correction through to automatic threshold calibration.
    for i in range(ARP_SWEEP_MIN_CORRECTED_SAMPLES):
        alert = {
            "device": {"id": device_id, "hostname": "smart-hub"},
            "network_context": {"queried_domain": "", "destination_ip": ""},
            "signature": "CONNECTION_ABUSE",
            "timestamp": time.time(),
        }
        fp.mark_false_positive(alert, "smart-hub", source="operator")

    corrections = _collect_connection_abuse_corrections(state_dir)
    check("_collect_connection_abuse_corrections() correctly counts real mark_false_positive() writes",
          corrections.get(device_id, 0) == ARP_SWEEP_MIN_CORRECTED_SAMPLES, f"got={corrections}")

    before = fp.get_device_arp_sweep_threshold(device_id, default=8.0)
    run_threshold_calibration(state_dir)
    fp2 = AutonomousFPEngine(config={}, state_dir=str(state_dir))  # fresh instance, forces a real disk reload
    after = fp2.get_device_arp_sweep_threshold(device_id, default=8.0)

    check("THE CORE INTEGRATION ('enable per device tuning'): a real run of "
          "run_threshold_calibration() actually raises this device's own "
          "arp_sweep_unique_targets_threshold end-to-end, from real correction evidence "
          "on disk, reloadable by a completely fresh AutonomousFPEngine instance",
          after > before, f"before={before} after={after}")

    autotune_stats_path = state_dir / "autotune_stats.json"
    check("autotune_stats.json is written with a 'confirmed' evidence count alongside "
          "corrected/uncorrected", autotune_stats_path.exists())
    if autotune_stats_path.exists():
        stats = json.loads(autotune_stats_path.read_text())
        check("the global evidence_counts include a 'confirmed' key",
              "confirmed" in stats.get("global", {}).get("evidence_counts", {}), f"got={stats.get('global')}")
        dev_stats = stats.get("devices", {}).get(device_id, {})
        check("this device's arp_sweep_evidence_counts are recorded in autotune_stats.json",
              dev_stats.get("arp_sweep_evidence_counts", {}).get("corrected", 0) == ARP_SWEEP_MIN_CORRECTED_SAMPLES,
              f"got={dev_stats}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: pipeline.py -- source-level guards for both confirmed-threat feed points
# ═══════════════════════════════════════════════════════════════════════════════════
with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src = f.read()

check("pipeline.py's HIGH/CRITICAL bar feeds record_confirmed_threat() as the second "
      "confirmation path (fp_engine's own Stage-1 hard-stop is the first, internal one)",
      "self.fp_engine.record_confirmed_threat(" in pipeline_src)
check("the HIGH/CRITICAL feed is gated on the same not-suppressed condition as the "
      "reactive-capture trigger and Telegram send",
      'if telegram_worthy and not fp_verdict["suppress"] and self.fp_engine:' in pipeline_src)
check("the HIGH/CRITICAL feed passes the alert's own signature through for "
      "signature-scoped confirmed-count tracking",
      "signature=primary_sig," in pipeline_src)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 27 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 27 local-intel / confirmed-tuning checks PASSED.")
    sys.exit(0)
