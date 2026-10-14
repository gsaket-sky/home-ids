"""The real EnginePipeline._step() publishes an alert whose target comes from the evidence that fired
(core/alert_attribution.py, 2026-10-12, TODO 0c Step 2 / new_issues item 4): an ARP-sweep alert names the swept set,
carries no domain although the window has a "most notable domain", no last-connection address or port, and the
persistence suffix is its own field. Harness as in test_pipeline_step_harness.py.

Run directly: `python tests/test_pipeline_alert_target.py` (exits via os._exit: the pipeline starts daemon threads)."""
import os, sys, tempfile, time
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "src"))
tmp = Path(tempfile.mkdtemp(prefix="pipeline_alert_target_"))
os.chdir(tmp)
state = tmp / "state"
state.mkdir(parents=True)
config = {"state_path": str(state / "ids_state.json"), "model_path": str(tmp / "models" / "ids_model.pkl"),
          "onboarding_mode_days": 0, "telegram_enabled": False, "ips_enabled": False,
          "reactive_capture_enabled": False, "reactive_capture_spotcheck_enabled": False,
          "reactive_capture_wired_probe_trigger_enabled": False,
          "local_popularity_enabled": False, "health_manager_enabled": False, "home_subnets": ["10.9.0.0/24"]}

from core.pipeline import EnginePipeline  # noqa: E402
from intelligence.hypotheses.evidence import Evidence  # noqa: E402
import argus.ops.live_engine as live  # noqa: E402
import core.pipeline as pipeline_mod  # noqa: E402

ok = True


def check(name, cond, detail=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + (f" -- {detail}" if detail and not cond else ""), flush=True)
    ok = ok and cond


p = EnginePipeline(config=config)
now = time.time()
sm = p.state_manager
dev = sm.get_or_create(device_id="scanner", client_ip="10.9.0.30", hostname="scanner-host")
dev.mac_address = "02:00:00:00:00:30"
sm.bind_mac("02:00:00:00:00:30", "scanner")
dev.note_address("10.9.0.30", now)

p.pihole_collector.poll = lambda: []
# The device's last connection goes to a public resolver: the old fallback showed it as the alert's destination.
p.zeek_collector.poll = (lambda: [
    {"_zeek_type": "conn", "id.orig_h": "10.9.0.30", "id.resp_h": "192.0.2.53", "id.resp_p": 53, "proto": "udp",
     "orig_bytes": 80, "uid": "Cdns53", "ts": now, "orig_l2_addr": "02:00:00:00:00:30"},
])
# The window's "most notable domain": the old fallback put it on every alert without its own domain.
p._select_target_domain = lambda st, ti: "bystander.example"
p.evidence_store.add(Evidence(type="arp_sweep", source="threat_signals", timestamp=now, device="scanner", value=23.0,
                              confidence=0.8, independence_group="lan_recon",
                              provenance="detector:threat_signals:arp_sweep:arp_sweep:test", domain="10.9.0.2",
                              targets=("10.9.0.2", "10.9.0.3", "10.9.0.4"), target_count=23))

real_evaluate = live.evaluate


def evaluate(*a, **k):
    d = dict(real_evaluate(*a, **k))
    d.update(state=pipeline_mod.DecisionState.SUSPICIOUS, explanation="INTERNAL_RECONNAISSANCE",
             threat_confidence=0.4, decision_path="hypothesis_suspicious", action="monitor")
    return d


live.evaluate = evaluate
written = []
real_write = p.alert_writer.write
p.alert_writer.write = lambda payload: (written.append(payload), real_write(payload))[1]
try:
    p._step(now=now, window_seconds=300, alert_threshold=6.0)
    check("_step runs a full cycle and publishes an alert", bool(written), "no alert written")
except Exception as exc:  # report, do not hide
    import traceback
    traceback.print_exc()
    check("_step runs a full cycle and publishes an alert", False, repr(exc))

alert = next((a for a in written if a.get("device", {}).get("id") == "scanner"), {})
nc = alert.get("network_context", {})
check("the window's most notable domain is not the alert's domain", nc.get("queried_domain") == "unknown", str(nc))
check("the last connection is not the alert's destination", nc.get("destination_ip") == "unknown", str(nc))
check("no port from an unrelated connection", nc.get("destination_port") == 0, str(nc))
check("the alert names the swept set", nc.get("target_set") == {
    "kind": "swept_hosts", "count": 23, "examples": ["10.9.0.2", "10.9.0.3", "10.9.0.4"]}, str(nc))
check("the target's source evidence is recorded", nc.get("target_source") == "arp_sweep", str(nc))
_rep = (alert.get("features") or {}).get("reputation_sources") or {}
check("the alert stores each reputation source's state (hit / clean / not checked), 2026-10-14",
      set(_rep) == {"threat_intel", "abuseipdb", "virustotal"}
      and all(e.get("state") in ("hit", "clean", "not_checked") for e in _rep.values()), str(_rep))
check("signature_base / persisted_seconds are their own fields",
      alert.get("signature_base") == "INTERNAL_RECONNAISSANCE" and alert.get("persisted_seconds") is None, str(alert)[:300])

# A device-level HIGH alert (no destination by design) still gets its "Mark False Positive" ledger entry: the
# correction runs from the stored payload; it was gated on a known target, so device-level alerts lost it.
def evaluate_high(*a, **k):
    d = dict(real_evaluate(*a, **k))
    d.update(state=pipeline_mod.DecisionState.HIGH, explanation="PEER_COHORT_DEVIATION",
             threat_confidence=0.85, decision_path="hypothesis_high", action="alert")
    return d


live.evaluate = evaluate_high
# W-10 remainder: the containment an alert causes is linked to the alert's graph event.
linked = []
_graph = live.get_graph_store()
_graph.link_containment_action = lambda aid, eid: linked.append((aid, eid)) or True
mit_refs = []
if p.ips_mitigator is not None:
    _real_mitigate = p.ips_mitigator.mitigate

    def _mitigate(*a, **k):
        mit_refs.append(k.get("alert_ref"))
        r = _real_mitigate(*a, **k) or {}
        return dict(r, actions=list(r.get("actions") or []) + ["act-test"])
    p.ips_mitigator.mitigate = _mitigate
sm.get_or_create(device_id="scanner", client_ip="10.9.0.30", hostname="scanner-host").last_alert_time = 0.0
written.clear()
p.zeek_collector.poll = (lambda: [
    {"_zeek_type": "conn", "id.orig_h": "10.9.0.30", "id.resp_h": "192.0.2.53", "id.resp_p": 53, "proto": "udp",
     "orig_bytes": 80, "uid": "Cdns54", "ts": now + 400, "orig_l2_addr": "02:00:00:00:00:30"},
])
try:
    p._step(now=now + 400, window_seconds=300, alert_threshold=6.0)
except Exception as exc:
    import traceback
    traceback.print_exc()
    check("second cycle runs", False, repr(exc))
ledger = [e for e in (getattr(sm, "_action_ledger", {}) or {}).values()
          if e.get("type") == "published_alert" and e.get("device_id") == "scanner"]
high = [a for a in written if a.get("device", {}).get("id") == "scanner"]
check("a device-level HIGH alert is published", bool(high), str(len(written)))
check("mitigate() receives the alert that causes the containment",
      p.ips_mitigator is None or (mit_refs and mit_refs[-1]["signature"] == "PEER_COHORT_DEVIATION"
                                  and mit_refs[-1]["incident_id"]), str(mit_refs)[:200])
check("...and what it created is linked to the alert's graph event",
      p.ips_mitigator is None or any(aid == "act-test" and eid for aid, eid in linked), str(linked))
check("...and gets its correction (Mark False Positive) entry", bool(ledger) and ledger[-1].get("target") == "device-level",
      str(ledger)[:300])

# Containment T1: a "tarpit not reaching" event from the mitigator is sent to the operator by the next cycle.
sent = []
p.alert_manager.send = lambda msg, *a, **k: sent.append(msg)
if p.ips_mitigator is not None:
    p.ips_mitigator._containment_events.append({"type": "tarpit_not_reaching", "dev_id": "scanner",
                                                "hostname": "scanner-host", "macs": ["02:00:00:00:00:30"]})
try:
    p._step(now=now + 800, window_seconds=300, alert_threshold=6.0)
except Exception as exc:
    import traceback
    traceback.print_exc()
check("a not-reaching tarpit is reported to the operator",
      p.ips_mitigator is not None and any("Tarpit not reaching scanner-host" in m for m in sent), str(sent)[:300])
check("...once", p.ips_mitigator is not None and not p.ips_mitigator.pop_containment_events())

# Interactive mode: a domain block the mitigator queued gets an approval ledger entry and ONLY its own button (no
# hardware isolation button: nothing hardware was queued at this risk).
markups = []
p.alert_manager.send = lambda msg, raw_payload=None, reply_markup=None: markups.append(reply_markup)
p.config["interactive_blocking_enabled"] = True


def evaluate_high_mid(*a, **k):
    d = dict(real_evaluate(*a, **k))
    d.update(state=pipeline_mod.DecisionState.HIGH, explanation="DATA_EXFILTRATION",   # a new incident: notified
             threat_confidence=0.6, decision_path="hypothesis_high", action="alert")
    return d


live.evaluate = evaluate_high_mid
if p.ips_mitigator is not None:
    p.ips_mitigator.mitigate = lambda *a, **k: {"actions": [], "domain_blocked": None,
                                                "pending_domain_block": "queued.example"}
sm.get_or_create(device_id="scanner", client_ip="10.9.0.30", hostname="scanner-host").last_alert_time = 0.0
try:
    p._step(now=now + 1200, window_seconds=300, alert_threshold=6.0)
except Exception as exc:
    import traceback
    traceback.print_exc()
pending = [e for e in (getattr(sm, "_action_ledger", {}) or {}).values() if e.get("type") == "pending_domain_block"]
buttons = [b["callback_data"] for m in markups if m for row in m.get("inline_keyboard", []) for b in row]
check("interactive: the queued domain block has an approval entry",
      p.ips_mitigator is None or (pending and pending[-1]["extra"]["domain"] == "queued.example"), str(pending)[:300])
check("interactive: only its own approval button is offered",
      p.ips_mitigator is None or (any(b.startswith("blockdomain:") for b in buttons)
                                  and not any(b.startswith("block:") for b in buttons)), str(buttons))
print("ALERT TARGET", "OK" if ok else "FAILED")
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
