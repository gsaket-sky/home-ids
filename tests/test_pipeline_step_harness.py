"""Runs the real EnginePipeline._step() on a temp state (no network services needed) -- the start of the harness the
code ledger asks for (TODO 0b: _step was the largest function without any test).

First check (2026-10-12, Documentation/internal/IDENTITY_MODEL.md): a device's detection inputs are read from the
addresses it used within the feature window, not from its whole address history. Device "old" once used 10.9.0.20,
which device "new" uses now; a connection from 10.9.0.20 must count for "new" only. Before, _step aggregated Zeek
features, alerts, destinations and ports over state.known_ips -- the whole history -- so "old" took on "new"'s traffic
(on .94 a smart monitor "looked up" a name only another device uses).

Run directly: `python tests/test_pipeline_step_harness.py` (exits via os._exit: the pipeline starts daemon threads)."""
import os, sys, tempfile, time
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "src"))
tmp = Path(tempfile.mkdtemp(prefix="pipeline_step_"))
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
sm = p.state_manager
old = sm.get_or_create(device_id="old", client_ip="10.9.0.10", hostname="old-host")
old.mac_address = "02:00:00:00:00:10"
sm.bind_mac("02:00:00:00:00:10", "old")
old.known_ips.add("10.9.0.20")                  # history: used 10.9.0.20 days ago
old.note_address("10.9.0.10", now)
old.note_address("10.9.0.20", now - 3 * 86400)
new = sm.get_or_create(device_id="new", client_ip="10.9.0.20", hostname="new-host")
new.mac_address = "02:00:00:00:00:20"
sm.bind_mac("02:00:00:00:00:20", "new")
new.note_address("10.9.0.20", now)

# The real collectors stay (everything else _step reads from them is real); only what they deliver is fixed.
p.pihole_collector.poll = lambda: []
p.zeek_collector.poll = (lambda: [
    {"_zeek_type": "conn", "id.orig_h": "10.9.0.20", "id.resp_h": "1.1.1.1", "id.resp_p": 443, "proto": "tcp",
     "orig_bytes": 1200, "uid": "Cnew443", "ts": now, "orig_l2_addr": "02:00:00:00:00:20"},
])
seen = {}
real_record = live.record_device_traffic


def record(dev_id, dest_ips, *a, **k):
    seen.setdefault(dev_id, set()).update(dest_ips or ())
    return real_record(dev_id, dest_ips, *a, **k)


live.record_device_traffic = record
try:
    p._step(now=now, window_seconds=300, alert_threshold=6.0)
    check("_step runs a full cycle on a real pipeline", True)
except Exception as exc:  # report, do not hide
    import traceback
    traceback.print_exc()
    check("_step runs a full cycle on a real pipeline", False, repr(exc))

check("the device that uses the address now gets its traffic", "1.1.1.1" in seen.get("new", set()), str(seen))
check("the device that used the address before does not", "1.1.1.1" not in seen.get("old", set()), str(seen))
# The identity journal (IDENTITY_MODEL.md P1) records the cycle's attributions and writes them to the graph.
written = p._flush_identity_journal()
g = live.get_graph_store()
rows = g._conn.execute("SELECT id_kind, id_value, device_id FROM identity_bindings WHERE valid_to IS NULL").fetchall()
check("the identity journal is written by the pipeline", written > 0 and ("address", "10.9.0.20", "new") in
      [tuple(r) for r in rows], str([tuple(r) for r in rows]))
print("STEP HARNESS", "OK" if ok else "FAILED")
sys.stdout.flush()
try:   # os._exit skips coverage.py's exit hook: save what the ledger build measured before leaving
    import coverage
    cov = coverage.Coverage.current()
    if cov is not None:
        cov.stop()
        cov.save()
except ImportError:
    pass
os._exit(0 if ok else 1)
