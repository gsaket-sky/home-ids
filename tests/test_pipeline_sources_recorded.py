"""Every verdict records which evidence sources were available (P0 capability registry, core/source_availability.py).

Runs the real EnginePipeline._step() on a temp state with no Zeek logs and no threat-intel lists loaded (the fresh-install
reality: optional sources absent). The decision carries `_sources`, the persisted decision row carries it, and the
snapshot file other processes read exists. A source being down changes nothing about detection here (recording only):
what a verdict does with a missing source belongs to the layers that consume it.

Run directly: `python tests/test_pipeline_sources_recorded.py` (exits via os._exit: the pipeline starts daemon threads)."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "src"))
tmp = Path(tempfile.mkdtemp(prefix="pipeline_sources_"))
os.chdir(tmp)
state = tmp / "state"
state.mkdir(parents=True)
config = {"state_path": str(state / "ids_state.json"), "model_path": str(tmp / "models" / "ids_model.pkl"),
          "onboarding_mode_days": 0, "telegram_enabled": False, "ips_enabled": False,
          "reactive_capture_enabled": False, "reactive_capture_spotcheck_enabled": False,
          "reactive_capture_wired_probe_trigger_enabled": False,
          "local_popularity_enabled": False, "health_manager_enabled": False, "home_subnets": ["10.9.0.0/24"],
          "zeek_log_dir": str(tmp / "no_zeek_here")}

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
p.pihole_collector.poll = lambda: []
p.zeek_collector.poll = lambda: [
    {"_zeek_type": "conn", "id.orig_h": "10.9.0.20", "id.resp_h": "1.1.1.1", "id.resp_p": 443, "proto": "tcp",
     "orig_bytes": 1200, "uid": "C1", "ts": now, "orig_l2_addr": "02:00:00:00:00:20"}]
captured = {}
real = live.evaluate_cycle


def spy(*a, **k):
    decision, cycle = real(*a, **k)
    captured["decision"] = decision
    captured["sources_arg"] = k.get("sources")
    return decision, cycle


live.evaluate_cycle = spy
try:
    p._step(now=now, window_seconds=300, alert_threshold=6.0)
    check("_step runs a full cycle", True)
except Exception as exc:
    import traceback
    traceback.print_exc()
    check("_step runs a full cycle", False, repr(exc))

d = captured.get("decision", {})
src = d.get("_sources") or {}
check("the decision records the sources", {"zeek", "pihole", "geoip", "threat_intel", "abuseipdb", "virustotal"} <= set(src),
      str(src))
check("every recorded state is one of the four", all(v in ("ok", "degraded", "unavailable", "disabled") for v in src.values()),
      str(src))
check("no Zeek log directory -> zeek is unavailable (an optional/absent source is recorded, not hidden)",
      src.get("zeek") == "unavailable", str(src.get("zeek")))
check("no AbuseIPDB / VirusTotal key -> disabled, not unavailable",
      src.get("abuseipdb") == "disabled" and src.get("virustotal") == "disabled", str((src.get("abuseipdb"), src.get("virustotal"))))

store = live.get_graph_store()
rows = store._conn.execute("SELECT raw_payload_json FROM decisions WHERE device_id='dev'").fetchall()
persisted = [json.loads(r[0]).get("_sources") for r in rows if r[0]]
check("the persisted decision row carries the same record", bool(persisted) and persisted[-1] == src, str(persisted))
snap = state / "source_availability.json"
check("the snapshot file other processes read exists and agrees",
      snap.is_file() and {k: v["state"] for k, v in json.loads(snap.read_text(encoding="utf-8")).items()} == src)

print("SOURCES RECORDED", "OK" if ok else "FAILED")
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
