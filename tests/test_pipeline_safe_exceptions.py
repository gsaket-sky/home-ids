"""U2 (DETECTION_CORE_REWORK, handover 2026-10-14): the honeypot and ARP-spoof exceptions must not be switched off by a
self-reported hostname. `is_safe` in pipeline._step is "verified address OR hostname contains a safe pattern"; the
hostname comes from the client's own DHCP request, so a device naming itself like a safe pattern ("pihole-x") escaped
the honeypot evidence, the ARP-spoof hard stop and the decision engine's honeypot rule. The exceptions now read the
verified-address flag only; the hostname match stays for noise reduction elsewhere.

Runs the real EnginePipeline._step() on a temp state. Run directly: `python tests/test_pipeline_safe_exceptions.py`
(exits via os._exit: the pipeline starts daemon threads)."""
import os, sys, tempfile, time
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "src"))
tmp = Path(tempfile.mkdtemp(prefix="pipeline_safe_"))
os.chdir(tmp)
state = tmp / "state"
state.mkdir(parents=True)
config = {"state_path": str(state / "ids_state.json"), "model_path": str(tmp / "models" / "ids_model.pkl"),
          "onboarding_mode_days": 0, "telegram_enabled": False, "ips_enabled": False,
          "reactive_capture_enabled": False, "reactive_capture_spotcheck_enabled": False,
          "reactive_capture_wired_probe_trigger_enabled": False,
          "local_popularity_enabled": False, "health_manager_enabled": False, "home_subnets": ["10.9.0.0/24"],
          "honeypot_ips": ["10.9.0.99"], "safe_ips": ["10.9.0.50"], "safe_host_patterns": ["pihole"]}

from core.pipeline import EnginePipeline  # noqa: E402

ok = True


def check(name, cond, detail=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + (f" -- {detail}" if detail and not cond else ""), flush=True)
    ok = ok and cond


p = EnginePipeline(config=config)
now = time.time()
sm = p.state_manager
# (device id, address, mac, hostname): a hostname that only matches the pattern, an address listed in safe_ips, a plain one
DEVICES = [("spoofer", "10.9.0.30", "02:00:00:00:00:30", "pihole-test"),
           ("listed", "10.9.0.50", "02:00:00:00:00:50", "printer"),
           ("plain", "10.9.0.60", "02:00:00:00:00:60", "laptop")]
events = []
for dev_id, ip, mac, host in DEVICES:
    st = sm.get_or_create(device_id=dev_id, client_ip=ip, hostname=host)
    st.mac_address = mac
    sm.bind_mac(mac, dev_id)
    st.note_address(ip, now)
    events.append({"_zeek_type": "conn", "id.orig_h": ip, "id.resp_h": "10.9.0.99", "id.resp_p": 22, "proto": "tcp",
                   "orig_bytes": 60, "uid": "C" + dev_id, "ts": now, "orig_l2_addr": mac})

p.pihole_collector.poll = lambda: []
p.zeek_collector.poll = lambda: list(events)
real_pop = p.zeek_fx.pop_layer2_spoof
p.zeek_fx.pop_layer2_spoof = lambda ip: ({"old": "aa", "new": "bb"} if ip in {d[1] for d in DEVICES} else real_pop(ip))

added = set()   # (device, evidence type) of every add: an alert clears the store afterwards
real_add = p.evidence_store.add


def record_add(ev, *a, **k):
    added.add((ev.device, ev.type))
    return real_add(ev, *a, **k)


p.evidence_store.add = record_add
try:
    p._step(now=now, window_seconds=300, alert_threshold=6.0)
    check("_step runs a full cycle on a real pipeline", True)
except Exception as exc:
    import traceback
    traceback.print_exc()
    check("_step runs a full cycle on a real pipeline", False, repr(exc))


def types(dev_id):
    return {t for d, t in added if d == dev_id}


check("hostname-only 'safe' device: honeypot evidence is created", "honeypot_access" in types("spoofer"), str(types("spoofer")))
check("hostname-only 'safe' device: ARP-spoof hard-stop evidence is created", "arp_spoofing" in types("spoofer"), str(types("spoofer")))
check("address in safe_ips: honeypot evidence still exempt", "honeypot_access" not in types("listed"), str(types("listed")))
check("address in safe_ips: ARP-spoof hard stop still exempt", "arp_spoofing" not in types("listed"), str(types("listed")))
check("plain device: honeypot evidence is created", "honeypot_access" in types("plain"), str(types("plain")))
check("plain device: ARP-spoof evidence is created", "arp_spoofing" in types("plain"), str(types("plain")))
print("SAFE EXCEPTIONS", "OK" if ok else "FAILED")
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
