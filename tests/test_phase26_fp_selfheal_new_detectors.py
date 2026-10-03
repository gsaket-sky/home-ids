"""
Standalone runtime test for Phase 26 (Phase D2 of the reactive-capture plan:
self-healing integration for the new evidence-driven detectors). Not part of the
pytest suite -- run directly: `python3 test_phase26_fp_selfheal_new_detectors.py`.

Background: a correction ("mark as false positive") originally assumed every correction means
"immunize a domain" -- true for regular DNS-driven alerts, but structurally wrong for
two evidence types with no domain by definition:
  - DNS_EVASION (dns_evasion.py's blind-spot audit): the signal itself IS "no matching
    DNS history"; the correctable thing is the specific unexplained destination IP.
  - CONNECTION_ABUSE (covers arp_sweep evidence among others): a domain immunization
    does nothing for a device that legitimately ARP-scans the LAN; what needs
    correcting is that device's OWN arp_sweep threshold.

Exercises the live CL-AFPE (argus/cl_afpe/engine.py) and its real evaluate()/mark_false_positive()
closed loop, no mocks -- proves the correction actually changes future behaviour, not just that a
function returns a plausible-looking result. Section E covers EnginePipeline._device_threshold(), which
reads the per-device thresholds the engine raises.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

import tempfile
import time

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402


def _engine(tmpdir, *device_ids):
    store = GraphStore(str(_PathForSysPath(tmpdir) / "graph.db"))
    for d in device_ids:                       # the identity guard only accepts known devices
        store.upsert_device(d, timestamp=time.time())
    return ClAfpeEngine(store)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: per-device ARP-sweep threshold -- own value, else the caller's default
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = _engine(tmpdir, "dev_no_profile", "dev_with_profile")
    check("a device with no profile yet falls back to the caller-supplied default",
          fp.get_device_arp_sweep_threshold("dev_no_profile", default=8.0) == 8.0)
    fp.apply_device_fp_profile("dev_with_profile", "arp_sweep_unique_targets_threshold",
                               15.0, baseline=8.0, set_by="operator", reason="test", sample_count=1)
    check("a device with a calibrated profile returns its OWN value, not the default",
          fp.get_device_arp_sweep_threshold("dev_with_profile", default=8.0) == 15.0)
    check("a DIFFERENT device with no profile is unaffected by another device's calibration",
          fp.get_device_arp_sweep_threshold("dev_no_profile", default=8.0) == 8.0)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: DNS_EVASION corrections immunize the destination IP; the closed loop
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    device_id, hostname, unexplained_ip = "dev_iphone_vpn", "iphone-gs", "5.6.7.8"
    fp = _engine(tmpdir, device_id, "dev_no_ip")

    def _evasion_alert():
        return {
            "device": {"id": device_id, "hostname": hostname},
            "network_context": {"queried_domain": "", "destination_ip": unexplained_ip},
            "signature": "DNS_EVASION",
            # two independent evidence families -> composite trust can build (it needs two)
            "hee_evidence_families": ["dns_behavior", "network_behavior"],
            "hee_evidence_types": ["dns_evasion_anomaly", "zeek_conn_abuse"],
            "timestamp": time.time(),
        }

    result = fp.mark_false_positive(_evasion_alert(), source="operator")
    check("THE CORE FIX: a DNS_EVASION correction immunizes the alert's destination IP (there is no domain)",
          not result.refused and result.immunized_destination == unexplained_ip, f"got={result}")
    check("the immunized IP lands in the dynamic trust cache evaluate() checks",
          unexplained_ip in fp.get_dynamic_trust_cache())
    check("the sensitivity shift widens for this device (the generic dampener runs regardless of branch)",
          fp.get_sigma_shift(device_id) > 0.0)

    for _ in range(4):   # composite trust: +0.15 per family per correction (less a tiny decay); 5 clear the 0.6 bar
        fp.mark_false_positive(_evasion_alert(), source="operator")
    verdict = fp.evaluate(_evasion_alert(), features={},
                          decision={"evidence_types": ["dns_evasion_anomaly", "zeek_conn_abuse"],
                                    "evidence_families": ["dns_behavior", "network_behavior"]})
    check("THE CLOSED LOOP: once two evidence families corroborate the corrections, a later alert against the SAME "
          "corrected IP is suppressed via the trust-cache fast path",
          verdict["stage"] == "TRUST_CACHE" and verdict["suppress"] is True, f"got={verdict}")

    no_ip_alert = {"device": {"id": "dev_no_ip", "hostname": "host-no-ip"},
                   "network_context": {"queried_domain": "", "destination_ip": ""},
                   "signature": "DNS_EVASION", "timestamp": time.time()}
    result_no_ip = fp.mark_false_positive(no_ip_alert, source="operator")
    check("a DNS_EVASION alert with no usable destination degrades gracefully (no crash, nothing immunized)",
          result_no_ip.immunized_destination == "", f"got={result_no_ip}")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: CONNECTION_ABUSE corrections raise the device's own threshold
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    device_id, hostname = "dev_smart_hub", "smart-home-hub"
    fp = _engine(tmpdir, device_id)
    connection_abuse_alert = {"device": {"id": device_id, "hostname": hostname},
                              "network_context": {"queried_domain": "", "destination_ip": ""},
                              "signature": "CONNECTION_ABUSE", "timestamp": time.time()}
    before = fp.get_device_arp_sweep_threshold(device_id, default=8.0)
    result = fp.mark_false_positive(connection_abuse_alert, source="operator")
    after = fp.get_device_arp_sweep_threshold(device_id, default=8.0)
    check("a CONNECTION_ABUSE correction immunizes nothing (there is nothing to immunize)",
          result.immunized_destination == "", f"got={result}")
    check("THE CORE FIX: a CONNECTION_ABUSE correction raises THIS device's own arp_sweep_unique_targets_threshold",
          result.threshold_bumped is True and after > before, f"before={before} after={after}")
    check("a DIFFERENT device's threshold is unaffected", fp.get_device_arp_sweep_threshold("other", default=8.0) == 8.0)
    check("the sensitivity shift widens for this device too", fp.get_sigma_shift(device_id) > 0.0)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: regression guard -- a signature-less alert keeps the domain-based behaviour
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = _engine(tmpdir, "dev_regular")
    regular_alert = {"device": {"id": "dev_regular", "hostname": "regular-host"},
                     "network_context": {"queried_domain": "sub.some-regular-fp.com", "destination_ip": "1.1.1.1"},
                     "timestamp": time.time()}
    result = fp.mark_false_positive(regular_alert, source="operator")
    check("a signature-less alert immunizes the base domain",
          result.immunized_destination == "some-regular-fp.com" and result.is_new_immunization is True,
          f"got={result}")
    check("a signature-less alert never bumps a threshold", result.threshold_bumped is False)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: EnginePipeline._device_threshold() reads what the engine raised
# ═══════════════════════════════════════════════════════════════════════════════════
pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")
check("pipeline.py's arp_sweep_threshold computation uses the per-device threshold (autotuned)",
      '"arp_sweep_unique_targets_threshold", global_arp_sweep_threshold, autotuned=True)' in pipeline_src)

import argus.ops.live_engine as _live  # noqa: E402
from core.pipeline import EnginePipeline  # noqa: E402

_tmp = _PathForSysPath(tempfile.mkdtemp(prefix="phase26_threshold_"))
_live.configure(str(_tmp / "graph.db"))
_live.configure_cl_afpe(model_dir=str(_tmp / "models"), local_intel_dir=str(_tmp / "state"))


class _FakeAutotune:
    def __init__(self, value=None):
        self.value = value

    def get_active_value(self, key, device_id=None, default=None):
        return self.value if self.value is not None else default


class _FakeClAfpe:
    def __init__(self):
        self.autotune = _FakeAutotune()

    def _get_autotune_engine(self):
        return self.autotune


class _P:
    pass


_p = _P()
_p.cl_afpe = _FakeClAfpe()
_thr = EnginePipeline._device_threshold
check("_device_threshold: the default when the engine has no value for this device",
      _thr(_p, "devB", "conn_abuse_unique_ip_threshold", 5.0) == 5.0)
_live.get_graph_store().upsert_device("devA", timestamp=1.0)
_live.get_cl_afpe_engine().apply_device_fp_profile("devA", "conn_abuse_unique_ip_threshold", 11.0, 5.0, "t", "r", now=2.0)
check("_device_threshold: the value the engine raised after corrections",
      _thr(_p, "devA", "conn_abuse_unique_ip_threshold", 5.0) == 11.0)
_p.cl_afpe.autotune = _FakeAutotune(20.0)
check("_device_threshold: a promoted autotuner value wins for an autotuned key",
      _thr(_p, "devA", "arp_sweep_unique_targets_threshold", 8.0, autotuned=True) == 20.0)
check("_device_threshold: the autotuner is not consulted for a key that is not autotuned",
      _thr(_p, "devA", "conn_abuse_unique_ip_threshold", 5.0) == 11.0)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 26 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 26 self-healing (new detectors) checks PASSED.")
    sys.exit(0)
