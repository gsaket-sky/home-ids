"""U3 (DETECTION_CORE_REWORK, handover 2026-10-14): features["zeek_outbound_bytes"] is the window TOTAL. pipeline._step
merged get_last_connection_meta() over the window features, and that meta carried the LAST single connection's bytes
under the same key, so the total was overwritten (exfil z-score, outbound baseline, CL-AFPE check 6, ML input, alert
size all read the last connection). Two connections, 3 MB then 1 KB: the feature must be the sum.

Runs the real EnginePipeline._step(). Run directly: `python tests/test_pipeline_outbound_bytes_total.py`."""
import os, sys, tempfile, time
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "src"))
tmp = Path(tempfile.mkdtemp(prefix="pipeline_bytes_"))
os.chdir(tmp)
state = tmp / "state"
state.mkdir(parents=True)
config = {"state_path": str(state / "ids_state.json"), "model_path": str(tmp / "models" / "ids_model.pkl"),
          "onboarding_mode_days": 0, "telegram_enabled": False, "ips_enabled": False,
          "reactive_capture_enabled": False, "reactive_capture_spotcheck_enabled": False,
          "reactive_capture_wired_probe_trigger_enabled": False,
          "local_popularity_enabled": False, "health_manager_enabled": False, "home_subnets": ["10.9.0.0/24"]}

from core.pipeline import EnginePipeline  # noqa: E402
import argus.ops.live_engine as live  # noqa: E402

ok = True


def check(name, cond, detail=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + (f" -- {detail}" if detail and not cond else ""), flush=True)
    ok = ok and cond


p = EnginePipeline(config=config)
now = time.time()
st = p.state_manager.get_or_create(device_id="dev", client_ip="10.9.0.20", hostname="host")
st.mac_address = "02:00:00:00:00:20"
p.state_manager.bind_mac("02:00:00:00:00:20", "dev")
st.note_address("10.9.0.20", now)


def conn(uid, size, ts):
    return {"_zeek_type": "conn", "id.orig_h": "10.9.0.20", "id.resp_h": "1.1.1.1", "id.resp_p": 443, "proto": "tcp",
            "orig_bytes": size, "uid": uid, "ts": ts, "orig_l2_addr": "02:00:00:00:00:20"}


p.pihole_collector.poll = lambda: []
p.zeek_collector.poll = lambda: [conn("Cbig", 3_000_000, now - 2), conn("Csmall", 1_000, now - 1)]
captured = {}
real_eval = live.evaluate_cycle   # the pipeline's call (U7)


def spy(*a, **k):
    captured["features"] = dict(k.get("features") or {})
    return real_eval(*a, **k)


live.evaluate_cycle = spy
try:
    p._step(now=now, window_seconds=300, alert_threshold=6.0)
    check("_step runs a full cycle on a real pipeline", True)
except Exception as exc:
    import traceback
    traceback.print_exc()
    check("_step runs a full cycle on a real pipeline", False, repr(exc))
f = captured.get("features", {})
check("zeek_outbound_bytes is the window total (3,001,000), not the last connection (1,000)",
      f.get("zeek_outbound_bytes") == 3_001_000, str(f.get("zeek_outbound_bytes")))
check("the last-connection keys still arrive (port 443, destination)",
      f.get("last_dest_port") == 443 and f.get("last_dest_ip") == "1.1.1.1", str((f.get("last_dest_port"), f.get("last_dest_ip"))))
print("OUTBOUND BYTES", "OK" if ok else "FAILED")
sys.stdout.flush()
try:
    import coverage
    cov = coverage.Coverage.current()
    if cov is not None:
        cov.stop()
        cov.save()
except ImportError:
    pass
os._exit(0 if ok else 1)
