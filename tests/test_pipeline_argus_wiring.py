"""Builds the real EnginePipeline in a temp dir (no network services needed) and checks its argus wiring: the
identity manager, the CL-AFPE engine sharing the pipeline's confirmed-intel and familiarity stores, the one-time merge
of the store the argus CL-AFPE kept while it ran in shadow, and the per-device lookups.

Run directly: `python tests/test_pipeline_argus_wiring.py` (exits via os._exit: the pipeline starts daemon threads)."""
import json, os, sys, tempfile, time
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "src"))
tmp = Path(tempfile.mkdtemp(prefix="pipeline_smoke_"))
os.chdir(tmp)
state = tmp / "state"
(state / "v13_cl_afpe").mkdir(parents=True)
now = time.time()
(state / "v13_cl_afpe" / "local_confirmed_intel.json").write_text(json.dumps({
    "ip": {"198.51.100.7": {"first_confirmed": now, "last_confirmed": now, "count": 1, "sources": ["old_dev"],
                            "reason": "shadow-era", "ttl_seconds": 86400.0}}, "domain": {}}), encoding="utf-8")

config = {"state_path": str(state / "ids_state.json"), "model_path": str(tmp / "models" / "ids_model.pkl"),
          "onboarding_mode_days": 0, "telegram_enabled": False, "ips_enabled": False,
          "reactive_capture_enabled": False, "local_popularity_enabled": False, "health_manager_enabled": False}

from core.pipeline import EnginePipeline  # noqa: E402
import argus.ops.live_engine as live  # noqa: E402
from argus.identity.live_manager import LiveIdentityManager  # noqa: E402

p = EnginePipeline(config=config)
ok = True


def check(name, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + name, flush=True)
    ok = ok and cond


check("identity manager is the argus LiveIdentityManager", isinstance(p.identity_manager, LiveIdentityManager))
engine = live.get_cl_afpe_engine()
check("the pipeline's CL-AFPE is the engine singleton", p.cl_afpe is engine)
check("CL-AFPE uses the pipeline's confirmed-intel store", engine.local_intel is p.local_intel)
check("CL-AFPE uses the pipeline's familiarity store", engine.familiarity is p.familiarity)
check("threat intel's trust-cache allowlist reads CL-AFPE", getattr(p.ti_engine, "trust_cache_provider", engine) is engine)
check("retired argus store merged into the shared one", p.local_intel.check("ip", "198.51.100.7") is not None)
check("retired store renamed", (state / "v13_cl_afpe" / "local_confirmed_intel.json.merged").exists())
engine.record_confirmed_threat("devX", "pipeline-feed.test", "", reason="HIGH_CRITICAL_DECISION", signature="X")
check("HIGH/CRITICAL feed is visible to the CL-AFPE Stage-1 check", engine.local_intel.check("domain", "pipeline-feed.test") is not None)
check("sigma shift comes from CL-AFPE", live.get_device_sigma_shift("nobody") == 0.0)
check("_device_threshold default path", p._device_threshold("nobody", "conn_abuse_unique_ip_threshold", 5.0) == 5.0)
check("no earlier-engine attributes remain", not hasattr(p, "fp_engine") and not hasattr(p, "decision_engine"))
p._export_cl_afpe_gauges()
check("gauge export runs", True)
print("SMOKE", "OK" if ok else "FAILED")
sys.stdout.flush(); os._exit(0 if ok else 1)
