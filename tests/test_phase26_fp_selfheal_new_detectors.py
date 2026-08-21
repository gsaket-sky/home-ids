"""
Standalone runtime test for Phase 26 (Phase D2 of the reactive-capture plan:
self-healing integration for the new evidence-driven detectors). Not part of the
pytest suite -- run directly: `python3 test_phase26_fp_selfheal_new_detectors.py`.

Background: mark_false_positive() originally assumed every correction means
"immunize a domain" -- true for regular DNS-driven alerts, but structurally wrong for
two new evidence types with no domain by definition:
  - DNS_EVASION (dns_evasion.py's blind-spot audit): the signal itself IS "no matching
    DNS history"; the correctable thing is the specific unexplained destination IP.
  - CONNECTION_ABUSE (covers arp_sweep evidence among others): a domain immunization
    does nothing for a device that legitimately ARP-scans the LAN; what needs
    correcting is that device's OWN arp_sweep threshold.
Exercises the real AutonomousFPEngine and its real evaluate()/mark_false_positive()
closed loop, no mocks -- proves the correction actually changes future behavior, not
just that a function returns a plausible-looking dict.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time
import tempfile

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.fp_engine import AutonomousFPEngine


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: get_device_arp_sweep_threshold -- layered fallback, same shape as
# get_device_suppress_threshold()
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    check("a device with no profile yet falls back to the caller-supplied default",
          fp.get_device_arp_sweep_threshold("dev_no_profile", default=8.0) == 8.0)

    fp.apply_device_fp_profile("dev_with_profile", "arp_sweep_unique_targets_threshold",
                                15.0, baseline=8.0, set_by="operator", reason="test", sample_count=1)
    check("a device with a calibrated profile returns its OWN value, not the default",
          fp.get_device_arp_sweep_threshold("dev_with_profile", default=8.0) == 15.0)
    check("a DIFFERENT device with no profile is unaffected by another device's calibration",
          fp.get_device_arp_sweep_threshold("dev_no_profile", default=8.0) == 8.0)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: mark_false_positive() -- DNS_EVASION signature routes to IP immunization
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)
    device_id, hostname, unexplained_ip = "dev_iphone_vpn", "iphone-gs", "5.6.7.8"

    dns_evasion_alert = {
        "device": {"id": device_id, "hostname": hostname},
        "network_context": {"queried_domain": "", "destination_ip": unexplained_ip},
        "signature": "DNS_EVASION",
        "timestamp": time.time(),
    }
    result = fp.mark_false_positive(dns_evasion_alert, hostname, source="operator")

    check("a DNS_EVASION correction does NOT extract/immunize a base domain (there is none)",
          result["base_domain"] == "", f"got={result}")
    check("THE CORE FIX: a DNS_EVASION correction DOES immunize the alert's destination_ip",
          result["ip_immunized"] == unexplained_ip, f"got={result}")
    check("the immunized IP actually lands in the same dynamic trust cache evaluate() checks",
          unexplained_ip in fp.get_dynamic_trust_cache(), f"cache={fp.get_dynamic_trust_cache()}")
    check("sigma shift still widens for this device (the generic dampener runs regardless of branch)",
          fp.get_sigma_shift(device_id) > 0.0)

    # Closed-loop proof: a LATER alert against the SAME dest_ip must now hit the trust
    # cache fast path in evaluate(), not re-run full Stage 1-3 inference.
    later_alert = {
        "device": {"id": device_id, "hostname": hostname},
        "network_context": {"queried_domain": "", "destination_ip": unexplained_ip},
        "signature": "DNS_EVASION",
        "timestamp": time.time(),
    }
    verdict = fp.evaluate(later_alert, features={}, risk_score=5.0, ti_engine=None)
    check("THE CLOSED LOOP: a later alert against the SAME corrected IP is now suppressed "
          "via the trust-cache fast path, proving the correction actually changes future "
          "behavior, not just this one alert",
          verdict["stage"] == "TRUST_CACHE" and verdict["suppress"] is True, f"got={verdict}")

    # Missing/absent destination_ip must degrade gracefully, not crash.
    no_ip_alert = {
        "device": {"id": "dev_no_ip", "hostname": "host-no-ip"},
        "network_context": {"queried_domain": "", "destination_ip": ""},
        "signature": "DNS_EVASION",
        "timestamp": time.time(),
    }
    result_no_ip = fp.mark_false_positive(no_ip_alert, "host-no-ip", source="operator")
    check("a DNS_EVASION alert with no usable destination_ip degrades gracefully (no crash, "
          "no immunization) instead of raising",
          result_no_ip["ip_immunized"] == "" and result_no_ip["base_domain"] == "")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: mark_false_positive() -- CONNECTION_ABUSE signature routes to threshold bump
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)
    device_id, hostname = "dev_smart_hub", "smart-home-hub"

    connection_abuse_alert = {
        "device": {"id": device_id, "hostname": hostname},
        "network_context": {"queried_domain": "", "destination_ip": ""},
        "signature": "CONNECTION_ABUSE",
        "timestamp": time.time(),
    }
    before = fp.get_device_arp_sweep_threshold(device_id, default=8.0)
    result = fp.mark_false_positive(connection_abuse_alert, hostname, source="operator")
    after = fp.get_device_arp_sweep_threshold(device_id, default=8.0)

    check("a CONNECTION_ABUSE correction does NOT immunize any domain or IP (nothing to immunize)",
          result["base_domain"] == "" and result["ip_immunized"] == "", f"got={result}")
    check("THE CORE FIX: a CONNECTION_ABUSE correction raises THIS device's own "
          "arp_sweep_unique_targets_threshold", result["threshold_bumped"] is True and after > before,
          f"before={before} after={after}")
    check("a DIFFERENT device's threshold is completely unaffected by this device's correction",
          fp.get_device_arp_sweep_threshold("some_other_device", default=8.0) == 8.0)
    check("sigma shift still widens for this device too",
          fp.get_sigma_shift(device_id) > 0.0)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: regression guard -- a signature-less (regular) alert keeps the EXACT
# domain-based behavior from before Phase 21D2
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)
    regular_alert = {
        "device": {"id": "dev_regular", "hostname": "regular-host"},
        "network_context": {"queried_domain": "sub.some-regular-fp.com", "destination_ip": "1.1.1.1"},
        "timestamp": time.time(),
        # no "signature" key at all -- matches how many older/synthetic alerts look
    }
    result = fp.mark_false_positive(regular_alert, "regular-host", source="operator")
    check("a signature-less alert still extracts and immunizes the base domain exactly as before",
          result["base_domain"] == "some-regular-fp.com" and result["is_new_immunization"] is True,
          f"got={result}")
    check("a signature-less alert never touches ip_immunized/threshold_bumped (new fields "
          "stay inert for the unchanged default path)",
          result["ip_immunized"] == "" and result["threshold_bumped"] is False)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: pipeline.py -- source-level guard for the per-device threshold wiring
# ═══════════════════════════════════════════════════════════════════════════════════
with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src = f.read()

check("pipeline.py's arp_sweep_threshold computation consults the per-device FP profile "
      "before falling back to the global config default",
      "self.fp_engine.get_device_arp_sweep_threshold(dev_id, default=global_arp_sweep_threshold)" in pipeline_src)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 26 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 26 self-healing (new detectors) checks PASSED.")
    sys.exit(0)
