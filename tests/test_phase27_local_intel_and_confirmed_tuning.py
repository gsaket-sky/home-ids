"""
Standalone runtime test for Phase 27 (Phase D3 of the reactive-capture plan:
autonomous improvement in detection, plus 'enable per device tuning' -- automatic
per-device ARP-sweep threshold calibration). Not part of the pytest suite -- run
directly: `python3 test_phase27_local_intel_and_confirmed_tuning.py`.

Covers:
  A. local_intel.py's LocalConfirmedIntel -- record/check/prune/TTL, real object.
  B. the CL-AFPE's record_confirmed_threat() -- feeds local_intel AND the (overall
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
from argus.cl_afpe.engine import ClAfpeEngine
from argus.graph.store import GraphStore
from intelligence.local_intel import LocalConfirmedIntel as _LCI


def _effective_arp_sweep_threshold(fp, device_id, default=8.0):
    """What the pipeline uses (EnginePipeline._device_threshold): the engine's own per-device value, with a promoted
    autotuner value taking precedence."""
    return fp._get_autotune_engine().get_active_value(
        "arp_sweep_unique_targets_threshold", device_id=device_id,
        default=fp.get_device_arp_sweep_threshold(device_id, default=default))


def _fp(state_dir, safe_ips=None):
    """The live CL-AFPE on the same graph file the nightly calibration reads (state/v13_graph.db), with the shared
    confirmed-intel store in state_dir."""
    from pathlib import Path as _P
    _P(state_dir).mkdir(parents=True, exist_ok=True)
    return ClAfpeEngine(GraphStore(str(_P(state_dir) / "v13_graph.db")), local_intel=_LCI(str(state_dir)),
                        safe_ips=set(safe_ips or []))
from argus.graph.store import GraphStore


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: LocalConfirmedIntel
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
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
# Section B: CL-AFPE -- record_confirmed_threat() + Stage-1 check #7
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = _fp(tmpdir)

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

    # BUGFIX regression guard (found via a production alerts.json audit): amazon.com
    # (188 confirmations), amazonalexa.com (139), netflix.com (97), and microsoft.com
    # (14) had all been recorded here as "confirmed malicious" in production,
    # cascading into hundreds of Stage-1 hard-stops/day against every device that
    # legitimately uses these services -- this store matches on the ETLD+1 BASE
    # DOMAIN, far too coarse for huge shared vendor domains, where one
    # wrongly-attributed confirmation poisons every future connection to ANY
    # subdomain, for EVERY device on the network.
    fp.record_confirmed_threat("dev_A", "amazon.com", "8.8.8.8", reason="STAGE_1_HARD_STOP")
    check("THE CORE FIX (write side): record_confirmed_threat() refuses to record a "
          "known-safe base domain (amazon.com) as confirmed-malicious",
          fp.local_intel.check("domain", "amazon.com") is None)
    check("the confirmed-count still increments even when the domain write was refused "
          "(this device's alert WAS still a real confirmed threat -- only the overly-"
          "broad domain record was refused, e.g. it may have hard-stopped on the IP "
          "or another signal)",
          fp.get_confirmed_count("dev_A") == 2)

    # READ-SIDE guard: even an ALREADY-poisoned entry (simulating what production found
    # sitting in local_confirmed_intel.json before this fix, from before it existed)
    # must stop being honored -- bypass the now-fixed write guard directly to prove the
    # read-side check works independently, since the real poisoned entries won't
    # disappear from disk until their TTL expires.
    fp.local_intel.record("domain", "netflix.com", "some_other_device", reason="STAGE_1_HARD_STOP")
    check("the simulated pre-existing poisoned entry is really there before the read-side check",
          fp.local_intel.check("domain", "netflix.com") is not None)
    poisoned_alert = {
        "device": {"id": "dev_D", "hostname": "some-smart-tv"},
        "network_context": {"queried_domain": "nrdp.logs.netflix.com", "destination_ip": "2.2.2.2"},
        "signature": "",
        "timestamp": time.time(),
    }
    poisoned_alert_safe_features = {
        "ti_risk": 0.0, "zeek_lateral_moves": 0, "zeek_ja3_malicious": 0,
        "zeek_ja4_malicious": 0, "zeek_honeypot_hits": 0, "abuseipdb_risk": 0.0,
        "outbound_bytes_z": 0.0,
    }
    poisoned_verdict = fp.evaluate(poisoned_alert, poisoned_alert_safe_features)
    check("THE CORE FIX (read side): an ALREADY-poisoned known-safe base domain "
          "(netflix.com, simulating what production actually found on disk) is no "
          "longer honored as a Stage-1 hard-stop match, even though it's still "
          "physically present in the store",
          poisoned_verdict["stage"] != "STAGE_1_HARD_STOP", f"got={poisoned_verdict}")

    # REGRESSION GUARD: an unrelated, genuinely malicious domain is completely unaffected.
    fp.record_confirmed_threat("dev_E", "still-malicious.example", "9.9.9.9", reason="STAGE_1_HARD_STOP")
    check("REGRESSION GUARD: a genuinely unrelated (non-safe-listed) domain is still "
          "recorded and still hard-stops normally -- the fix is scoped to known-safe "
          "domains only",
          fp.local_intel.check("domain", "still-malicious.example") is not None)

    # BUGFIX regression guard (found via a LIVE production check, 13 minutes after
    # restarting with the domain-side fix above): the SAME poisoning pattern exists on
    # the IP side of this store, and it's WORSE -- 192.168.1.94 (this network's own
    # IDS server, already listed in config.yaml's safe_ips) had 822 false confirmations;
    # 192.168.1.1 (the router) had 121; multicast addresses (ff02::fb, 224.0.0.22,
    # 224.0.0.251 -- not real hosts) had hundreds each. Proved safe_ips was never
    # actually consulted by this store despite its own config.yaml docstring's promise.
    fp.record_confirmed_threat("dev_F", "", "192.168.1.94", reason="HIGH_CRITICAL_DECISION")
    check("THE CORE FIX (write side, IP): record_confirmed_threat() refuses to record a "
          "private LAN IP (192.168.1.94, this network's own server) as confirmed-malicious",
          fp.local_intel.check("ip", "192.168.1.94") is None)
    fp.record_confirmed_threat("dev_G", "", "224.0.0.251", reason="STAGE_1_HARD_STOP")
    check("a multicast address (224.0.0.251, mDNS -- not even a real host) is refused too",
          fp.local_intel.check("ip", "224.0.0.251") is None)
    fp.record_confirmed_threat("dev_H", "", "ff02::fb", reason="STAGE_1_HARD_STOP")
    check("an IPv6 multicast address (ff02::fb, mDNS) is refused too",
          fp.local_intel.check("ip", "ff02::fb") is None)

    # BUGFIX (live audit, same session): well-known PUBLIC DNS resolvers -- found live
    # with 8.8.8.8 at 64 "confirmed malicious" recordings, still actively renewing,
    # from devices' own direct-resolver DNS traffic (the DNS_POLICY_BYPASS shape).
    # KNOWN_PUBLIC_DNS_RESOLVERS (utils.py) is shared with dns_evasion.py's existing
    # known-resolver exemption -- same list, same reasoning, now also protecting this
    # store's write AND read paths.
    fp.record_confirmed_threat("dev_H2", "", "8.8.8.8", reason="STAGE_1_HARD_STOP")
    check("THE FIX: a well-known public DNS resolver (8.8.8.8) is refused too",
          fp.local_intel.check("ip", "8.8.8.8") is None)

    # Read-side guard: an ALREADY-poisoned private IP (simulating what production found
    # on disk before this fix existed) must stop being honored, same as the domain case.
    fp.local_intel.record("ip", "192.168.1.1", "some_other_device", reason="STAGE_1_HARD_STOP")
    check("the simulated pre-existing poisoned IP entry is really there before the read-side check",
          fp.local_intel.check("ip", "192.168.1.1") is not None)
    poisoned_ip_alert = {
        "device": {"id": "dev_I", "hostname": "some-iot-device"},
        "network_context": {"queried_domain": "unknown", "destination_ip": "192.168.1.1"},
        "signature": "", "timestamp": time.time(),
    }
    poisoned_ip_verdict = fp.evaluate(poisoned_ip_alert, poisoned_alert_safe_features)
    check("THE CORE FIX (read side, IP): an ALREADY-poisoned private IP (192.168.1.1, "
          "the router) is no longer honored as a Stage-1 hard-stop match",
          poisoned_ip_verdict["stage"] != "STAGE_1_HARD_STOP", f"got={poisoned_ip_verdict}")

    # Explicit safe_ips config path (not just automatically-private addresses) -- a
    # PUBLIC IP the operator explicitly listed in config.yaml's safe_ips must also be
    # protected, matching safe_ips' own documented promise ("NEVER treated as suspicious
    # ... even if flagged elsewhere").
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir2:
        fp_with_config = _fp(tmpdir2, safe_ips=["203.0.113.50"])
        fp_with_config.record_confirmed_threat("dev_J", "", "203.0.113.50", reason="STAGE_1_HARD_STOP")
        check("an explicitly-configured safe_ips entry (a PUBLIC IP, not automatically "
              "private) is also refused -- safe_ips' own documented promise, honored for "
              "the first time by this store",
              fp_with_config.local_intel.check("ip", "203.0.113.50") is None)

    # REGRESSION GUARD: a genuinely unrelated public IP is completely unaffected.
    # BUGFIX (live audit, same session): 8.8.4.4 used to be a fine "ordinary public IP"
    # example -- but it's Google's own secondary public DNS resolver, which is now
    # ALSO correctly protected (KNOWN_PUBLIC_DNS_RESOLVERS, utils.py) for the exact
    # same reason 8.8.8.8 needed to be: found live with 64 false "confirmed malicious"
    # recordings from devices' own direct-resolver DNS traffic. 93.184.216.34 (a
    # long-standing example.com IP, already used as a plain "ordinary public IP" test
    # fixture elsewhere in this suite -- test_phase24_dns_evasion.py) is genuinely
    # unrelated: not private/multicast/reserved (unlike RFC 5737 TEST-NET ranges like
    # 203.0.113.0/24, which Python's stdlib ipaddress actually classifies as
    # is_private=True -- confirmed live, that was this test's first replacement
    # attempt and it ALSO failed, for a reason unrelated to this fix) and not a known
    # resolver.
    fp.record_confirmed_threat("dev_K", "", "93.184.216.34", reason="STAGE_1_HARD_STOP")
    check("REGRESSION GUARD: a genuinely unrelated public IP is still recorded and "
          "still hard-stops normally -- the fix is scoped to private/multicast/"
          "safe-listed/known-public-resolver IPs only",
          fp.local_intel.check("ip", "93.184.216.34") is not None)

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
    verdict = fp.evaluate(later_alert, safe_features)
    check("THE CORE FIX: a DIFFERENT device (dev_B) touching a domain dev_A already "
          "confirmed hard-stops (PREVIOUSLY_FLAGGED: never suppressed, not a new confirmation) with NO "
          "hard-stop signal of its own",
          verdict["verdict"] == "PREVIOUSLY_FLAGGED" and verdict["stage"] == "STAGE_1_HARD_STOP"
          and verdict["suppress"] is False,
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
    verdict_clean = fp.evaluate(clean_alert, safe_features)
    check("an unrelated domain/IP with no confirmed-intel match does NOT hard-stop via check #7",
          verdict_clean["stage"] != "STAGE_1_HARD_STOP", f"got={verdict_clean}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B2: THE ROOT-CAUSE FIX -- evaluate()/_stage1_hard_stop() must not record a
# domain into local_intel unless the hard-stop that actually fired was domain-causal.
# BUGFIX (found via a live production state-folder audit, same day as the write-side
# fix above): record_confirmed_threat()'s two callers were passing base_domain
# unconditionally whenever ANY Stage-1 check fired -- but only Check 1 (ThreatIntel
# IOC) has a plausible causal link to `domain` at all. Checks 2-6 (lateral movement,
# malicious JA3/JA4, honeypot, AbuseIPDB, exfiltration burst) are pure behavioral/IP
# signals; the `domain` they're evaluated alongside is just whatever this device's
# alert happened to carry as queried_domain that cycle. Confirmed live: sharepoint.com,
# coinbase.com, alibaba.com, aws.dev, nflximg.com, vscode-cdn.net, claudeusercontent.com,
# epson.biz -- all ordinary high-traffic vendor domains, NONE on the is_telemetry_domain()
# floor from the fix above, ALL poisoned this exact way. This is the write-side's
# COMPLEMENT: is_telemetry_domain() only protects domains someone already curated;
# this fix stops the wrong domain from ever being fed in in the first place.
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir_b2:
    fp_b2 = _fp(tmpdir_b2)

    def _make_alert(domain, features):
        return {
            "device": {"id": "dev_bystander", "hostname": "some-device"},
            "network_context": {"queried_domain": domain, "destination_ip": "5.5.5.5"},
            "signature": "CONNECTION_ABUSE",
        }

    # Check 2 (lateral movement) fires; `domain` is an innocent bystander (the generic
    # target-domain fallback's pick, structurally unrelated to the lateral-movement
    # evidence) -- must NOT be recorded, even though the alert IS a genuine confirmed
    # threat (dest_ip DOES get recorded).
    lateral_alert = _make_alert("sharepoint.com", {})
    verdict_b2 = fp_b2.evaluate(lateral_alert, {"zeek_lateral_moves": 5, "zeek_lateral_unique_targets": 3})
    check("Check 2 (lateral movement) alone reaches CONFIRMED_THREAT as before",
          verdict_b2["verdict"] == "CONFIRMED_THREAT", f"got={verdict_b2}")
    check("THE FIX: a lateral-movement-only hard-stop does NOT poison the bystander "
          "domain in local_intel",
          fp_b2.local_intel.check("domain", "sharepoint.com") is None)
    check("...but DOES still record the dest_ip -- lateral movement's target IS "
          "causally the right thing to remember",
          fp_b2.local_intel.check("ip", "5.5.5.5") is not None)

    # Check 5 (AbuseIPDB) fires; different innocent bystander domain.
    abuse_alert = _make_alert("coinbase.com", {})
    fp_b2.evaluate(abuse_alert, {"abuseipdb_risk": 8.0})
    check("an AbuseIPDB-only hard-stop does NOT poison its bystander domain either",
          fp_b2.local_intel.check("domain", "coinbase.com") is None)

    # REGRESSION GUARD: Check 1 (ThreatIntel IOC) is the one case where `domain` DOES
    # have a real causal link -- a genuine domain-blacklist hit must still poison the
    # domain as before, or the fix would have thrown out real detection value too.
    ti_alert = _make_alert("actually-malicious-c2.example", {})
    fp_b2.evaluate(ti_alert, {"ti_risk": 3.5})
    check("REGRESSION GUARD: a genuine ThreatIntel IOC hit still records its domain "
          "as confirmed-malicious -- the fix is scoped to non-domain-causal checks only",
          fp_b2.local_intel.check("domain", "actually-malicious-c2.example") is not None)

    # REGRESSION GUARD: the trust-cache-override path (a SECOND call site with the
    # identical bug) gets the same fix.
    fp_b2_cached = _fp(tmpdir_b2 + "_2")
    fp_b2_cached.immunize("nflximg.com", source="operator")
    cached_alert = _make_alert("nflximg.com", {})
    fp_b2_cached.evaluate(cached_alert, {"zeek_lateral_moves": 3, "zeek_lateral_unique_targets": 2})
    check("REGRESSION GUARD: the trust-cache-override path (a trusted domain overridden "
          "by a fresh non-domain-causal hard-stop) also does not re-poison the domain",
          fp_b2_cached.local_intel.check("domain", "nflximg.com") is None)


# Section C (retro_hunter.py -- check_local_intel_history()) removed: scripts/
# retro_hunter.py was retired (v16 cleanup) once its findings/local-intel-store
# counters stayed flat across multiple live checks while argus/retro_hunter.py's
# own RetroHunter.check_local_intel_history() (a direct port of the same logic)
# kept running as the sole retro-hunt engine -- see tests/test_argus_retro_hunter.py
# for equivalent coverage of the surviving implementation.


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D0: train_fp_classifier.py -- calibrate_suppress_threshold() direct coverage
# (2026-09-21, legacy/Sheet 03a autotune reconciliation Phase E: confirmed via grep this
# pure function had ZERO direct unit tests before this -- only ever exercised indirectly
# through the full run_threshold_calibration() integration below.)
# ═══════════════════════════════════════════════════════════════════════════════════
from scripts.train_fp_classifier import (
    calibrate_suppress_threshold, AUTOTUNE_MIN_SAMPLES, AUTOTUNE_SAFETY_MARGIN, AUTOTUNE_ABSOLUTE_FLOOR,
)

cst_val, cst_reason = calibrate_suppress_threshold(
    corrected_fp_scores=[0.70] * AUTOTUNE_MIN_SAMPLES, uncorrected_uncertain_scores=[],
    current=0.80, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check(">= min_samples confirmed FPs with no ambiguous overlap LOWERS the threshold to "
      "AUTOTUNE_SAFETY_MARGIN below the lowest confirmed-FP score",
      cst_val is not None and abs(cst_val - (0.70 - AUTOTUNE_SAFETY_MARGIN)) < 1e-9,
      f"got={cst_val}, reason={cst_reason}")

cst_val2, cst_reason2 = calibrate_suppress_threshold(
    corrected_fp_scores=[0.70] * (AUTOTUNE_MIN_SAMPLES - 1), uncorrected_uncertain_scores=[],
    current=0.80, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("below min_samples confirmed FPs makes NO change",
      cst_val2 is None and cst_reason2.startswith("Only "), f"got={cst_val2}, reason={cst_reason2}")

cst_val3, cst_reason3 = calibrate_suppress_threshold(
    corrected_fp_scores=[0.70] * AUTOTUNE_MIN_SAMPLES, uncorrected_uncertain_scores=[0.72],
    current=0.80, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("an uncorrected UNCERTAIN alert scoring AT OR ABOVE the lowest confirmed-FP score "
      "refuses to calibrate -- the ambiguous-overlap guard",
      cst_val3 is None and cst_reason3.startswith("Refusing to calibrate"),
      f"got={cst_val3}, reason={cst_reason3}")

cst_val4, cst_reason4 = calibrate_suppress_threshold(
    corrected_fp_scores=[0.70] * AUTOTUNE_MIN_SAMPLES, uncorrected_uncertain_scores=[0.50],
    current=0.80, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("an uncorrected UNCERTAIN alert scoring safely BELOW the lowest confirmed-FP score "
      "does not block calibration",
      cst_val4 is not None, f"got={cst_val4}, reason={cst_reason4}")

cst_val5, cst_reason5 = calibrate_suppress_threshold(
    corrected_fp_scores=[0.10] * AUTOTUNE_MIN_SAMPLES, uncorrected_uncertain_scores=[],
    current=0.80, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("the lowered threshold never goes below AUTOTUNE_ABSOLUTE_FLOOR regardless of how "
      "low the confirmed-FP evidence scores",
      cst_val5 is not None and abs(cst_val5 - AUTOTUNE_ABSOLUTE_FLOOR) < 1e-9,
      f"got={cst_val5}, reason={cst_reason5}")

cst_val6, cst_reason6 = calibrate_suppress_threshold(
    corrected_fp_scores=[0.90] * AUTOTUNE_MIN_SAMPLES, uncorrected_uncertain_scores=[],
    current=0.80, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("calibration NEVER raises the threshold, even when the confirmed-FP evidence would "
      "otherwise compute a candidate ABOVE the current value -- one-directional by design",
      cst_val6 is None and "would not lower" in cst_reason6, f"got={cst_val6}, reason={cst_reason6}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D0b (2026-09-27, Phase 3 of the autonomy-completion effort):
# calibrate_uncertain_threshold() -- combined_uncertain_threshold's own calibration,
# same rule shape as calibrate_suppress_threshold() above but mirrored to the OPPOSITE
# boundary/population (CONFIRMED_THREAT-verdict corrections, not UNCERTAIN-verdict).
# ═══════════════════════════════════════════════════════════════════════════════════
from scripts.train_fp_classifier import (
    calibrate_uncertain_threshold, AUTOTUNE_UNCERTAIN_SAFETY_MARGIN, AUTOTUNE_UNCERTAIN_ABSOLUTE_FLOOR,
)

cut_val, cut_reason = calibrate_uncertain_threshold(
    corrected_confirmed_scores=[0.40] * AUTOTUNE_MIN_SAMPLES, uncorrected_confirmed_scores=[],
    current=0.55, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check(">= min_samples confirmed-FPs published at CONFIRMED_THREAT severity LOWERS the "
      "threshold to AUTOTUNE_UNCERTAIN_SAFETY_MARGIN above the HIGHEST such corrected score",
      cut_val is not None and abs(cut_val - (0.40 + AUTOTUNE_UNCERTAIN_SAFETY_MARGIN)) < 1e-9,
      f"got={cut_val}, reason={cut_reason}")

cut_val2, cut_reason2 = calibrate_uncertain_threshold(
    corrected_confirmed_scores=[0.40] * (AUTOTUNE_MIN_SAMPLES - 1), uncorrected_confirmed_scores=[],
    current=0.55, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("below min_samples confirmed-FPs makes NO change",
      cut_val2 is None and cut_reason2.startswith("Only "), f"got={cut_val2}, reason={cut_reason2}")

cut_val3, cut_reason3 = calibrate_uncertain_threshold(
    corrected_confirmed_scores=[0.40] * AUTOTUNE_MIN_SAMPLES, uncorrected_confirmed_scores=[0.39],
    current=0.55, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("a genuine, uncorrected CONFIRMED_THREAT scoring AT OR BELOW the highest "
      "corrected-FP score refuses to calibrate -- the ambiguous-overlap guard",
      cut_val3 is None and cut_reason3.startswith("Refusing to calibrate"),
      f"got={cut_val3}, reason={cut_reason3}")

cut_val4, cut_reason4 = calibrate_uncertain_threshold(
    corrected_confirmed_scores=[0.40] * AUTOTUNE_MIN_SAMPLES, uncorrected_confirmed_scores=[0.60],
    current=0.55, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("an uncorrected CONFIRMED_THREAT scoring safely ABOVE the highest corrected-FP "
      "score does not block calibration",
      cut_val4 is not None, f"got={cut_val4}, reason={cut_reason4}")

cut_val5, cut_reason5 = calibrate_uncertain_threshold(
    corrected_confirmed_scores=[0.05] * AUTOTUNE_MIN_SAMPLES, uncorrected_confirmed_scores=[],
    current=0.55, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("the lowered threshold never goes below AUTOTUNE_UNCERTAIN_ABSOLUTE_FLOOR "
      "regardless of how low the confirmed-FP evidence scores",
      cut_val5 is not None and abs(cut_val5 - AUTOTUNE_UNCERTAIN_ABSOLUTE_FLOOR) < 1e-9,
      f"got={cut_val5}, reason={cut_reason5}")

cut_val6, cut_reason6 = calibrate_uncertain_threshold(
    corrected_confirmed_scores=[0.90] * AUTOTUNE_MIN_SAMPLES, uncorrected_confirmed_scores=[],
    current=0.55, min_samples=AUTOTUNE_MIN_SAMPLES,
)
check("calibration NEVER raises the threshold, even when the confirmed-FP evidence "
      "would otherwise compute a candidate ABOVE the current value -- one-directional by design",
      cut_val6 is None and "would not lower" in cut_reason6, f"got={cut_val6}, reason={cut_reason6}")


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
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    state_dir = Path(tmpdir)
    fp = _fp(str(state_dir))
    device_id = "dev_smart_hub_autocal"
    d2_store = fp._get_autotune_engine().store

    # Two real CONNECTION_ABUSE corrections via the actual mark_false_positive() path
    # (not hand-written JSONL) -- proves the whole chain from a real operator
    # correction through to automatic threshold calibration. Each needs a matching
    # graph decision row for _write_muted_log() to attach its fp_suppression_log to
    # (see that method's own docstring) -- a real pipeline cycle always has one
    # (argus_live_engine's own _write_graph() runs unconditionally every cycle); this
    # fixture inserts it directly, same precondition test_phase6's own rewrite uses.
    for i in range(ARP_SWEEP_MIN_CORRECTED_SAMPLES):
        alert_ts = time.time()
        alert = {
            "device": {"id": device_id, "hostname": "smart-hub"},
            "network_context": {"queried_domain": "", "destination_ip": ""},
            "signature": "CONNECTION_ABUSE",
            "timestamp": alert_ts,
        }
        d2_store.insert_decision(device_id, alert_ts, "SUSPICIOUS", "hypothesis_suspicious", 0.5, 5.0)
        fp.mark_false_positive(alert, source="operator")

    corrections = _collect_connection_abuse_corrections(state_dir)
    check("_collect_connection_abuse_corrections() correctly counts real mark_false_positive() writes",
          corrections.get(device_id, 0) == ARP_SWEEP_MIN_CORRECTED_SAMPLES, f"got={corrections}")

    before = _effective_arp_sweep_threshold(fp, device_id)
    run1_now = time.time()
    run_threshold_calibration(state_dir, now=run1_now)
    fp.store.close()

    # 2026-09-21 (legacy/Sheet 03a autotune reconciliation, Phase C): the write side now
    # routes through AutotuneEngine's own propose -> canary -> promote lifecycle instead
    # of writing device_fp_profiles.json directly -- a single run only PROPOSES a change,
    # it is not immediately live. Verify the proposal landed in threshold_history first...
    store = GraphStore(str(state_dir / "v13_graph.db"))
    proposed_row = store._conn.execute(
        "SELECT change_id, new_value, promoted_at FROM threshold_history WHERE "
        "parameter='arp_sweep_unique_targets_threshold' AND device_id=? "
        "ORDER BY proposed_at DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    check("a single run_threshold_calibration() pass PROPOSES a real threshold_history row "
          "for this device from real correction evidence, but does not promote it yet",
          proposed_row is not None and proposed_row["new_value"] > before
          and proposed_row["promoted_at"] is None,
          f"got={dict(proposed_row) if proposed_row else None}, before={before}")
    store.close()

    fp_immediate = _fp(str(state_dir))
    immediate_value = _effective_arp_sweep_threshold(fp_immediate, device_id)
    check("...and get_device_arp_sweep_threshold() still returns the UNCHANGED value while "
          "the proposal is only in canary -- no premature effect before promotion",
          immediate_value == before, f"got={immediate_value}, before={before}")
    fp_immediate.store.close()

    # ...then, once the canary window has elapsed, a SECOND run (same recurring cron this
    # script already runs on) opportunistically promotes it -- see _propose_and_promote()'s
    # own docstring for why this reuses the existing cadence rather than a new concept.
    run2_now = run1_now + 6.0 * 3600.0 + 1.0
    run_threshold_calibration(state_dir, now=run2_now)

    fp2 = _fp(str(state_dir))  # fresh instance, forces a real disk reload
    after = _effective_arp_sweep_threshold(fp2, device_id)
    fp2.store.close()

    check("THE CORE INTEGRATION ('enable per device tuning'): a SECOND run.threshold_"
          "calibration() pass, after the canary window elapses, actually PROMOTES this "
          "device's own arp_sweep_unique_targets_threshold end-to-end, from real correction "
          "evidence on disk, as a completely fresh engine instance sees it",
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

check("pipeline.py's HIGH/CRITICAL bar feeds the CL-AFPE's record_confirmed_threat() as the second "
      "confirmation path (its own Stage-1 hard-stop is the first, internal one)",
      "self.cl_afpe.record_confirmed_threat(" in pipeline_src)
check("the HIGH/CRITICAL feed is gated on the same not-suppressed condition as the "
      "reactive-capture trigger and Telegram send",
      'if telegram_worthy and not fp_verdict["suppress"]:' in pipeline_src)
check("the HIGH/CRITICAL feed passes the alert's own signature through for "
      "signature-scoped confirmed-count tracking",
      "signature=primary_sig," in pipeline_src)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 27 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 27 local-intel / confirmed-tuning checks PASSED.")
    sys.exit(0)
