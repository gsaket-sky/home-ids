"""
Runtime test for the live false-positive engine wiring in src/argus/ops/live_engine.py.

Run directly: `python tests/test_argus_live_cl_afpe.py`

Sections:
  C. One shared threat memory: configure_cl_afpe(local_intel=...) makes the engine use the caller's
     LocalConfirmedIntel instance (pipeline.py passes its own), so a destination confirmed by any path is
     checked for every device; merge_retired_local_intel() folds the old shadow-era store in once.
  E. LocalConfirmedIntel across processes: a write by another process is seen on the next operation, and saves
     are atomic (no temp file left behind).
  F. Per-device values come from the engine's graph metadata (sigma shift, profile thresholds).
  G. Device familiarity shared between the pipeline and the engine, persisted.
  H. Confirmed-threat counts per device/signature; corrections written as training records.
  I. One-time import of the earlier engine's flat files.
  J. False-positive thresholds read from config, layered with the device profile and the autotuner.
  K. A memory-only hard stop does not renew its confirmed-intel entry; VPN/filter resolvers never become threats.
  D. evaluate_cl_afpe_live(): returns the engine's verdict; an engine error yields UNCERTAIN (never suppressed)
     and is counted for the health manager.
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import argus.ops.live_engine as live_engine  # noqa: E402
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402

tmpdir = _PathForSysPath(tempfile.mkdtemp(prefix="clafpe_live_test_"))
state_dir = tmpdir / "state"
model_dir = str(tmpdir / "no_models_here")  # deliberately empty -- no ONNX/FastEmbed

live_engine.configure(str(tmpdir / "graph.db"))
shared = LocalConfirmedIntel(str(state_dir))
live_engine.configure_cl_afpe(model_dir=model_dir, local_intel=shared)

NOW = 1_000_000.0
_store = live_engine.get_graph_store()
_store.upsert_device("pipeline_dev", timestamp=NOW)


def _alert(device_id="pipeline_dev", signature="NETWORK_INTRUSION", domain="", dest_ip="", features=None):
    return {
        "signature": signature,
        "device": {"id": device_id, "hostname": "pipeline-host"},
        "network_context": {"queried_domain": domain, "destination_ip": dest_ip},
        "features": features or {},
    }


# --- C. one shared threat memory ---
engine = live_engine._get_cl_afpe_engine()
check("C: the engine uses the injected LocalConfirmedIntel instance (one store, not a private copy)",
      engine.local_intel is shared)
shared.record("domain", "evil-example.test", "dev_a", reason="test")
check("C: an indicator recorded through the shared store is visible to the engine's own check",
      engine.local_intel.check("domain", "evil-example.test") is not None)

old_dir = state_dir / "v13_cl_afpe"
old_dir.mkdir(parents=True)
(old_dir / "local_confirmed_intel.json").write_text(json.dumps({
    "ip": {"203.0.113.9": {"first_confirmed": time.time(), "last_confirmed": time.time(), "count": 2,
                           "sources": ["dev_b"], "reason": "shadow-era", "ttl_seconds": 86400.0}},
    "domain": {}}), encoding="utf-8")
merged = live_engine.merge_retired_local_intel(shared, state_dir)
check("C: the retired shadow-era store is merged into the shared one", merged == 1 and shared.check("ip", "203.0.113.9"))
check("C: the retired file is renamed so it is merged only once",
      not (old_dir / "local_confirmed_intel.json").exists() and (old_dir / "local_confirmed_intel.json.merged").exists())
check("C: a second merge is a no-op", live_engine.merge_retired_local_intel(shared, state_dir) == 0)

# --- E. across processes: re-read on change, atomic saves ---
other_process = LocalConfirmedIntel(str(state_dir))      # e.g. the scheduler's retro-hunt
time.sleep(0.02)
other_process.record("domain", "found-by-retro-hunt.test", "dev_c", reason="retro")
check("E: a write by another process is seen by this one on its next check",
      shared.check("domain", "found-by-retro-hunt.test") is not None)
shared.record("domain", "second.test", "dev_a")
data = json.loads((state_dir / "local_confirmed_intel.json").read_text(encoding="utf-8"))
check("E: this process's next save keeps the other process's entry (no lost update)",
      "found-by-retro-hunt.test" in data["domain"] and "second.test" in data["domain"])
check("E: saves are atomic -- no temp file left behind",
      not list(state_dir.glob("local_confirmed_intel.json.*tmp")))

# --- F. per-device values from the engine's graph metadata ---
engine._apply_sigma_shift("pipeline_dev", direction="TUNE_UP", now=NOW + 1)
check("F: get_device_sigma_shift() reads the engine's own value", live_engine.get_device_sigma_shift("pipeline_dev") == -0.5)
check("F: no profile entry -> None (the caller falls back)",
      live_engine.get_device_profile_threshold("pipeline_dev", "conn_abuse_unique_ip_threshold", 5.0) is None)
engine.apply_device_fp_profile("pipeline_dev", "conn_abuse_unique_ip_threshold", 9.0, 5.0, "test", "raised", now=NOW + 2)
check("F: a profile entry the engine wrote is returned",
      live_engine.get_device_profile_threshold("pipeline_dev", "conn_abuse_unique_ip_threshold", 5.0) == 9.0)


# --- G. shared device familiarity ---
from intelligence.device_familiarity import DeviceFamiliarity  # noqa: E402
fam = DeviceFamiliarity(str(state_dir))
live_engine.configure_cl_afpe(model_dir=model_dir, local_intel=shared, familiarity=fam)
engine = live_engine.get_cl_afpe_engine()
check("G: the engine uses the injected familiarity store", engine.familiarity is fam)
for _ in range(5):
    fam.record_device_baseline_observation("pipeline_dev", domain_base="vendor.example")
check("G: what the pipeline records is what the engine reads (5 observations = fully familiar)",
      engine.get_baseline_familiarity("pipeline_dev", domain_base="vendor.example") == 1.0)
fam.flush(force=True)
check("G: familiarity survives a restart (saved atomically to state/device_familiarity.json)",
      DeviceFamiliarity(str(state_dir)).get_baseline_familiarity("pipeline_dev", domain_base="vendor.example") == 1.0)

# --- H. confirmed-threat counts and training records ---
engine.record_confirmed_threat("pipeline_dev", "bad-c2.example", "", reason="test", signature="CONNECTION_ABUSE")
check("H: a confirmed threat is counted per device, overall and per signature",
      engine.get_confirmed_count("pipeline_dev") >= 1
      and engine.get_confirmed_count("pipeline_dev", signature="CONNECTION_ABUSE") == 1)
decision_id = _store.insert_decision("pipeline_dev", NOW + 50, "SUSPICIOUS", "hypothesis_suspicious", 0.4, 4.0)
alert_h = _alert(signature="DGA_BOTNET_C2", domain="vendor-telemetry.example", features={})
alert_h["timestamp"] = NOW + 50
result_h = engine.mark_false_positive(alert_h, source="operator", now=NOW + 60)
row = _store._conn.execute("SELECT raw_payload_json FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
payload_h = json.loads(row["raw_payload_json"] or "{}")
check("H: an operator correction is written as a training record on the alert's own decision row",
      not result_h.refused and payload_h.get("fp_suppression_log", {}).get("type") == "OPERATOR_MARKED_FALSE_POSITIVE",
      str(result_h))

# --- I. one-time import of the earlier engine's flat files ---
from argus.cl_afpe.state_import import import_legacy_state  # noqa: E402
imp_dir = tmpdir / "import_state"
imp_dir.mkdir()
(imp_dir / "device_fp_profiles.json").write_text(json.dumps({
    "old_dev": {"conn_abuse_unique_ip_threshold": {"value": 12.0, "baseline": 5.0},
                "_baseline": {"ports": {"443": {"count": 7, "first_seen": 1, "last_seen": 2}}}}}), encoding="utf-8")
(imp_dir / "fp_sigma_shifts.json").write_text(json.dumps({"old_dev": 0.75}), encoding="utf-8")
(imp_dir / "confirmed_threat_counts.json").write_text(json.dumps({"old_dev": 3, "old_dev||PORT_SCAN": 2}), encoding="utf-8")
fam_i = DeviceFamiliarity(str(imp_dir))
stats_i = import_legacy_state(imp_dir, _store, fam_i)
meta_i = _store.get_device_metadata("old_dev")
check("I: thresholds, sensitivity shift and confirmed counts are imported into the graph",
      meta_i.get("fp_profile", {}).get("conn_abuse_unique_ip_threshold", {}).get("value") == 12.0
      and meta_i.get("sigma_shift") == 0.75
      and meta_i.get("confirmed_threat_counts") == {"_total": 3, "PORT_SCAN": 2}, str(stats_i))
check("I: familiarity counts are imported", fam_i.get_baseline_familiarity("old_dev", dest_port=443) == 1.0)
check("I: each file is renamed so the import runs once",
      not (imp_dir / "device_fp_profiles.json").exists() and (imp_dir / "device_fp_profiles.json.imported").exists())
check("I: a second run imports nothing", not any(import_legacy_state(imp_dir, _store, fam_i).values()))

# --- J. False-positive thresholds: config, then the device profile, then the autotuner ---
from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402


class _FakeAutotuneJ:
    def __init__(self):
        self.values = {}

    def get_active_value(self, parameter, device_id=None, default=None):
        return self.values.get((parameter, device_id), self.values.get((parameter, None), default))


_cfg_j = {"fp_combined_suppress_threshold": 0.9, "fp_combined_uncertain_threshold": 0.4}
eng_j = ClAfpeEngine(_store, config_get=lambda k, d=None: _cfg_j.get(k, d))
eng_j._autotune_engine = _FakeAutotuneJ()
check("J: the configured global suppress threshold is used (not the built-in 0.80)",
      eng_j.get_device_suppress_threshold("pipeline_dev") == 0.9)
_cfg_j["fp_combined_suppress_threshold"] = 0.85
check("J: a config change applies on the next read", eng_j.get_device_suppress_threshold("pipeline_dev") == 0.85)
eng_j.apply_device_fp_profile("pipeline_dev", "fp_combined_suppress_threshold", 0.95, 0.85, "t", "r", now=NOW)
check("J: the device's own profile value beats the global value",
      eng_j.get_device_suppress_threshold("pipeline_dev") == 0.95)
eng_j._autotune_engine.values[("fp_combined_suppress_threshold", "pipeline_dev")] = 0.7
check("J: a promoted autotuner value (nightly calibration) wins",
      eng_j.get_device_suppress_threshold("pipeline_dev") == 0.7)
check("J: the uncertain threshold comes from config", eng_j.get_device_uncertain_threshold("pipeline_dev") == 0.4)
eng_j._autotune_engine.values[("combined_uncertain_threshold", None)] = 0.5
check("J: ...and a promoted autotuner value wins there too",
      eng_j.get_device_uncertain_threshold("pipeline_dev") == 0.5)
_profiles_j = _store.get_device_metadata_values("fp_profile")
check("J: every device's corrected thresholds can be read in one pass (the dashboard gauges)",
      _profiles_j.get("pipeline_dev", {}).get("fp_combined_suppress_threshold", {}).get("value") == 0.95)
check("J: the live engine reads config", live_engine.get_cl_afpe_engine()._config_get is not None)

# --- K. A hard stop caused only by the local-intel match does not renew that entry; VPN/filter resolvers never enter ---
from argus.cl_afpe.engine import ClAfpeEngine as _K_Engine  # noqa: E402
_k_dir = tmpdir / "k_state"
_k_intel = LocalConfirmedIntel(str(_k_dir))
_k_eng = _K_Engine(_store, local_intel=_k_intel)
_store.upsert_device("k_dev_a", timestamp=NOW)
_store.upsert_device("k_dev_b", timestamp=NOW)
_k_eng.record_confirmed_threat("k_dev_a", None, "45.155.205.77", reason="TEST_CONFIRMED", asn_owner="Example Hosting")
_k_before = dict(_k_intel.check("ip", "45.155.205.77"))
time.sleep(0.05)
_k_v = _k_eng.evaluate(_alert(device_id="k_dev_b", dest_ip="45.155.205.77"), features={}, now=NOW + 5)
_k_after = _k_intel.check("ip", "45.155.205.77")
check("K: a destination in the confirmed memory is still a confirmed threat for another device",
      _k_v["verdict"] == "CONFIRMED_THREAT" and _k_v["stage"] == "STAGE_1_HARD_STOP", str(_k_v))
check("K: ...but that memory-only hard stop does NOT renew the entry (no self-perpetuation)",
      _k_after["count"] == _k_before["count"] and _k_after["last_confirmed"] == _k_before["last_confirmed"],
      f"before={_k_before} after={_k_after}")
_k_v2 = _k_eng.evaluate(_alert(device_id="k_dev_b", dest_ip="45.155.205.77", features={"zeek_honeypot_hits": 1}),
                        features={"zeek_honeypot_hits": 1}, now=NOW + 6)
check("K: an independent hard stop (decoy contact) on the same destination does renew it",
      _k_intel.check("ip", "45.155.205.77")["count"] == _k_before["count"] + 1, str(_k_intel.check("ip", "45.155.205.77")))
_k_eng.record_confirmed_threat("k_dev_a", None, "103.86.96.100", reason="TEST_CONFIRMED")
check("K: a VPN provider's public resolver (NordVPN DNS) is never recorded as a confirmed threat",
      _k_intel.check("ip", "103.86.96.100") is None)
_k_intel.record("ip", "103.86.99.100", "k_dev_a", reason="LEGACY_ENTRY")
check("K: an entry recorded earlier for such a resolver is no longer honoured",
      _k_eng.check_local_intel_hard_stop(None, "103.86.99.100") is None)
from utils import KNOWN_PUBLIC_DNS_RESOLVERS as _K_DNS  # noqa: E402
check("K: the DNS-evasion audit's resolver list is unchanged (a VPN resolver stays visible as a policy finding)",
      "103.86.96.100" not in _K_DNS)

# --- D. an engine error never suppresses: the alert is published as UNCERTAIN ---


class _ExplodingEngine:
    def evaluate(self, *a, **kw):
        raise RuntimeError("simulated CL-AFPE failure")


alert_d = _alert(device_id="pipeline_dev", features={"zeek_honeypot_hits": 1})
live_result = live_engine.evaluate_cl_afpe_live(
    alert_payload=alert_d, features=alert_d["features"],
    decision={"state": "CRITICAL", "explanation": "Internal Honeypot Accessed"}, now=NOW + 10)
check("D: evaluate_cl_afpe_live() returns the engine's own verdict",
      live_result.get("verdict") == "CONFIRMED_THREAT" and live_result.get("stage") == "STAGE_1_HARD_STOP")
check("D: the verdict has the shape pipeline.py reads",
      set(live_result.keys()) >= {"verdict", "confidence", "calibrated_confidence", "stage", "reasons", "suppress"})

_real_get_engine = live_engine.get_cl_afpe_engine
_before = live_engine.engine_error_status().get("cl_afpe", {}).get("count", 0)
live_engine.get_cl_afpe_engine = lambda: _ExplodingEngine()
try:
    err_result = live_engine.evaluate_cl_afpe_live(alert_payload=alert_d, features=alert_d["features"], now=NOW + 11)
finally:
    live_engine.get_cl_afpe_engine = _real_get_engine
check("D: a raising engine yields UNCERTAIN and is never suppressed -- the alert is published normally",
      err_result.get("verdict") == "UNCERTAIN" and err_result.get("suppress") is False
      and err_result.get("stage") == "ENGINE_ERROR")
check("D: the error is counted for the health manager",
      live_engine.engine_error_status().get("cl_afpe", {}).get("count", 0) == _before + 1)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All live CL-AFPE wiring checks PASSED.")
