"""U4 (DETECTION_CORE_REWORK, handover 2026-10-14): a new domain queried once a minute must trip the C2-beacon check on
the cycle it reaches 5 queries. pipeline._step added EVERY rolling-window domain to the persisted seen_domains in every
cycle regardless of verdict, and both beacon checks (dns_features) require "domain not in seen_domains" -- so beacon
detection was defeated after a domain's first cycle. A domain is now learned only from a BENIGN/ANOMALOUS cycle and only
once it has been seen for longer than the beacon look-back (1 h).

Runs the real EnginePipeline._step() over 10 simulated minutes. Run directly: `python tests/test_pipeline_beacon_seen_domains.py`."""
import os, sys, tempfile, time
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "src"))
tmp = Path(tempfile.mkdtemp(prefix="pipeline_beacon_"))
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


DOMAIN = "qzvx-sync.example-host.net"
p = EnginePipeline(config=config)
t0 = time.time() - 700
clock = {"now": t0}
p.zeek_collector.poll = lambda: []
p.pihole_collector.poll = lambda: [{"timestamp": clock["now"], "domain": DOMAIN, "client_ip": "10.9.0.20",
                                    "hostname": "host", "status": 2, "ftl_status": 2, "reply_type": 0, "qtype": 1}]
beacon_by_cycle = []
real_eval = live.evaluate_cycle   # the pipeline's call (U7)


def spy(*a, **k):
    beacon_by_cycle.append((k.get("features") or {}).get("beaconing_c2_count", 0))
    return real_eval(*a, **k)


live.evaluate_cycle = spy
for minute in range(10):                       # one query a minute, one cycle a minute
    clock["now"] = t0 + minute * 60
    try:
        p._step(now=clock["now"], window_seconds=300, alert_threshold=6.0)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        check(f"cycle {minute} runs", False, repr(exc))
        break

check("the cycles ran", len(beacon_by_cycle) >= 8, str(beacon_by_cycle))
check("the beacon feature fires on the cycle the domain reaches 5 queries (cycle index 4)",
      len(beacon_by_cycle) > 4 and beacon_by_cycle[4] >= 1, str(beacon_by_cycle))
check("and keeps firing while it continues", all(c >= 1 for c in beacon_by_cycle[4:]), str(beacon_by_cycle))
dns_states = [v for v in p.state_manager._states.values() if len(v.rolling.events) > 0]
check("exactly one device state received the DNS events", len(dns_states) == 1, str(len(dns_states)))
check("the domain was not learned as 'seen' within its first hour",
      bool(dns_states) and DOMAIN not in dns_states[0].seen_domains)
# Positive control: a domain queried every 10 minutes for over an hour (not a beacon: spacing under the 1 h check's
# floor of 4 queries is irrelevant here, only learning is checked) is learned once it is older than the look-back.
p2_t0 = t0 + 10 * 60
for i in range(9):                              # 80 minutes, one query + one cycle every 10 minutes
    clock["now"] = p2_t0 + i * 600
    p._step(now=clock["now"], window_seconds=300, alert_threshold=6.0)
st2 = dns_states[0] if dns_states else None
if st2 is not None:
    check("a domain seen for over an hour in benign cycles is learned as seen", DOMAIN in st2.seen_domains,
          f"first_seen={st2.domain_first_seen.get(DOMAIN)} (relative to t0: {st2.domain_first_seen.get(DOMAIN, 0) - t0})")
print("BEACON SEEN DOMAINS", "OK" if ok else "FAILED")
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
