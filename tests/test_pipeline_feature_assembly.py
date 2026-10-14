"""U3 rest (DETECTION_CORE_REWORK P0; MASTER_TODO 0d register, handover part 2 item 3): the pipeline's feature assembly has
named sources and one owner per key, and a key two sources both produce is a recorded error, not a silent overwrite.

The defect behind it (R1, window aggregates used as event facts): pipeline._step merged
`{**zeek.get_features(all known addresses), **zeek.get_last_connection_meta(client_ip)}`. Both produced last_dest_ip /
last_dest_port / dominant_protocol: the aggregate meant "the most recent connection across the device's addresses" (its own
comment says so) but picked the LAST address in list order, and the second dict then replaced it with the one current address's
meta -- or with "unknown" when that address had no connection. Same shape as the zeek_outbound_bytes overwrite U3 first fixed.

Part 1 runs the real EnginePipeline._step() on a device with two addresses (the newest connection is from the address that
is NOT the current client address). Part 2 is the assembly itself. Run directly: `python tests/test_pipeline_feature_assembly.py`."""
import os, sys, tempfile, time
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "src"))
tmp = Path(tempfile.mkdtemp(prefix="pipeline_features_"))
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


A, B = "10.9.0.20", "10.9.0.21"

# --- 1. the extractor: "the last connection" is the most recent one across the device's addresses ---------------------
from extractors.zeek_features import ZeekFeatureExtractor  # noqa: E402

zx = ZeekFeatureExtractor(home_subnets=["10.9.0.0/24"])
t0 = time.time()


def zconn(src, dst, port, uid, ts):
    return {"_zeek_type": "conn", "id.orig_h": src, "id.resp_h": dst, "id.resp_p": port, "proto": "tcp",
            "orig_bytes": 100, "uid": uid, "ts": ts}


for ev in (zconn(B, "198.51.100.10", 443, "C1", t0 - 20), zconn(A, "203.0.113.7", 8443, "C2", t0 - 1)):
    zx.ingest(ev)
f = zx.get_features([A, B])        # the pipeline passes the device's addresses, most recently seen first
check("get_features: last_dest_* is the most recent connection across the device's addresses, whatever the list order",
      f["last_dest_ip"] == "203.0.113.7" and f["last_dest_port"] == 8443,
      {k: f[k] for k in ("last_dest_ip", "last_dest_port", "dominant_protocol")})
f_rev = zx.get_features([B, A])
check("... and the same when the addresses come in the other order",
      f_rev["last_dest_ip"] == "203.0.113.7", f_rev["last_dest_ip"])
check("the last-connection meta carries no timestamp key into the features",
      "_ts" not in f and "ts" not in f)
check("get_features gives the 'no connection yet' defaults for an address that never connected",
      zx.get_features(["10.9.0.99"])["last_dest_ip"] == "unknown")

# --- 2. the real pipeline: named sources, one owner per key (the window byte total stays covered by test_pipeline_outbound_bytes_total) --------------------------------------
import core.feature_assembly as fa  # noqa: E402

p = EnginePipeline(config=config)
now = time.time()
st = p.state_manager.get_or_create(device_id="dev", client_ip=A, hostname="host")
st.mac_address = "02:00:00:00:00:20"
p.state_manager.bind_mac("02:00:00:00:00:20", "dev")
st.note_address(A, now)
st.note_address(B, now)

captured = {}
real_eval = live.evaluate_cycle
real_add = fa.FeatureAssembly.add_source
added = []


def spy(*a, **k):
    captured["features"] = dict(k.get("features") or {})
    return real_eval(*a, **k)


def spy_add(self, source, values):
    added.append((source, set(values)))
    return real_add(self, source, values)


live.evaluate_cycle = spy
fa.FeatureAssembly.add_source = spy_add
try:
    p.pihole_collector.poll = lambda: []
    # public addresses on purpose: the engine counts the documentation ranges as private (not outbound), so they carry no bytes
    p.zeek_collector.poll = lambda: [dict(zconn(A, "1.1.1.1", 443, "D1", now - 3), orig_l2_addr="02:00:00:00:00:20"),
                                     dict(zconn(B, "8.8.8.8", 8443, "D2", now - 1), orig_l2_addr="02:00:00:00:00:20")]
    p._step(now=now, window_seconds=300, alert_threshold=6.0)
    feats = captured.get("features", {})
    check("_step ran a full cycle on the real pipeline", bool(feats))
    check("the pipeline assembles from the named sources dns and zeek",
          [n for n, _ in added][:2] == ["dns", "zeek"], [n for n, _ in added])
    check("the two sources produce no key in common", not (added[0][1] & added[1][1]) if len(added) >= 2 else False,
          sorted(added[0][1] & added[1][1]) if len(added) >= 2 else "")
    check("the last connection is one of the device's own, from the most recent address",
          feats.get("last_dest_ip") == "8.8.8.8", feats.get("last_dest_ip"))
    check("the real sources collide on no key (no 'features' engine error recorded)",
          "features" not in live.engine_error_status(), live.engine_error_status())
finally:
    live.evaluate_cycle = real_eval
    fa.FeatureAssembly.add_source = real_add

# --- 4. the assembly itself -------------------------------------------------------------------------------------------
from core.feature_assembly import FeatureAssembly, FeatureCollision  # noqa: E402

a = FeatureAssembly()
a.add_source("dns", {"query_rate": 1.0, "entropy_avg": 2.0})
a.add_source("zeek", {"zeek_conn_count": 3})
check("disjoint sources assemble into one dict with every key", a.features == {"query_rate": 1.0, "entropy_avg": 2.0, "zeek_conn_count": 3})
check("every key has exactly one named owner", a.owner("zeek_conn_count") == "zeek" and a.owner("query_rate") == "dns")
check("no collision recorded for disjoint sources", a.collisions == [])

b = FeatureAssembly()
b.add_source("dns", {"x": 1, "y": 2})
b.add_source("zeek", {"y": 99, "z": 3})
check("a key two sources produce keeps its first owner's value (never silently replaced)",
      b.features["y"] == 2 and b.features["z"] == 3, b.features)
check("... and the collision is recorded with the key and both sources",
      b.collisions == [FeatureCollision("y", "dns", "zeek")], b.collisions)
try:
    s = FeatureAssembly(strict=True)
    s.add_source("dns", {"y": 1})
    s.add_source("zeek", {"y": 2})
    check("strict mode (tests, tools) raises on a collision", False)
except ValueError as e:
    check("strict mode (tests, tools) raises on a collision, naming the key and sources",
          "'y'" in str(e) and "dns" in str(e) and "zeek" in str(e), str(e))

c = FeatureAssembly()
c.add_source("dns", {"a": 1.0})
c.derive("z_scores", "a_z", 0.5)
check("a derived feature has its own named owner and may not shadow a source's key",
      c.features["a_z"] == 0.5 and c.owner("a_z") == "z_scores")
c.derive("z_scores", "a", 9.0)
check("a derived feature that shadows a source key is a collision too", c.features["a"] == 1.0 and len(c.collisions) == 1)

d = FeatureAssembly()
d.add_source("dns", {"keep": 1, "gated": 5})
d.gate("learning_period", {"gated": 0}, remove=("keep",))
check("a declared gate replaces / removes owned keys (the learning-period gate) and is recorded as such, not as a collision",
      d.features == {"gated": 0} and d.collisions == [] and d.owner("gated") == "learning_period", (d.features, d.collisions))

print("PIPELINE FEATURE ASSEMBLY", "OK" if ok else "FAILED", flush=True)
os._exit(0 if ok else 1)   # the pipeline starts daemon threads
