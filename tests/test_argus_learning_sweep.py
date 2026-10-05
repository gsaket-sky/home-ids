"""
Learning-period intel sweep (src/argus/learning_sweep.py, MASTER_TODO M2).

Covers: the first refresh after start sweeps every device; network warm-up sweeps every device; a warm network with
no learning device does nothing; otherwise only learning devices are swept; the trust cache is read once per sweep
and a strong feed hit still outranks it; an unreadable trust cache does not stop the sweep; summaries are recorded
(the first one kept for the onboarding report); notification only with findings; attach() sweeps right away when the
feeds are already loaded and on every later refresh; a failing listener never breaks the refresh loop.

Run directly: `venv/Scripts/python.exe tests/test_argus_learning_sweep.py`
"""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.graph.store import GraphStore  # noqa: E402
from argus.learning_sweep import (LearningIntelSweep, TRIGGER_FIRST, TRIGGER_WARMUP,  # noqa: E402
                                  TRIGGER_LEARNING)
from intelligence.threat_intel import ThreatIntel  # noqa: E402

NOW = 3_000_000.0
DAY = 86400.0
tmp = Path(tempfile.mkdtemp(prefix="learning_sweep_"))

C2_IP = "203.0.113.7"
C2_IP_2 = "203.0.113.8"
STRONG = "c2.strong.example"
WEAK = "weak.trusted.example"


def make_ti():
    ti = ThreatIntel(cache_dir=str(tmp / f"ti{time.time_ns()}"), refresh_interval=10**9)
    ti._bad_ips[C2_IP] = {"source": "feodo_ips", "tags": ["c2"], "confidence": 0.9, "malicious": True}
    ti._bad_ips[C2_IP_2] = {"source": "feodo_ips", "tags": ["c2"], "confidence": 0.9, "malicious": True}
    ti._bad_domains[STRONG] = {"source": "feed", "tags": ["c2"], "confidence": 0.9, "malicious": True}
    ti._bad_domains[WEAK] = {"source": "feed", "tags": ["policy"], "confidence": 0.3, "malicious": True}
    ti._stats["last_refresh"] = "now"
    return ti


class FakePopularity:
    def __init__(self, active_days, pairs):
        self.days, self.pairs = active_days, pairs

    def active_days(self):
        return self.days

    def device_name_pairs_since(self, since):
        return list(self.pairs)


class TrustProvider:
    def __init__(self, names, fail=False):
        self.names, self.fail, self.calls = set(names), fail, 0

    def get_dynamic_trust_cache(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("db locked")
        return set(self.names)


def pairs_of(summary):
    return sorted((f["device_id"], f["destination_id"]) for f in summary["findings"])


# --- first refresh after start: every device, quiet traffic included ------------------------------------------------
store = GraphStore(str(tmp / "g1.db"))
store.record_device_destinations("baselined", [C2_IP], timestamp=NOW - 2 * DAY)
learning = {"newdev"}
ti = make_ti()
pop = FakePopularity(30, [("baselined", STRONG)])
sent = []
sweep = LearningIntelSweep(lambda: store, ti, lambda d: d in learning, days_back=30, popularity=pop,
                           notify=sent.append, now_fn=lambda: NOW)
s1 = sweep.run_once()
check("first sweep after start runs with the first-refresh trigger", s1 and s1["trigger"] == TRIGGER_FIRST, str(s1))
check("first sweep covers every device, including baselined ones",
      s1 and s1["devices_in_scope"] == "all" and pairs_of(s1) == [("baselined", C2_IP), ("baselined", STRONG)],
      str(s1 and s1["findings"]))
check("findings are notified once", len(sent) == 1 and "Learning-period intel sweep" in sent[0])
check("the sweep's finding is written as retro-hunter evidence for the device",
      any(e.source == "retro_hunter" for e in store.get_evidence_for_device("baselined")))

# --- warm network, nobody learning: nothing to do ---------------------------------------------------------------
s2 = sweep.run_once()
check("warm network with no learning device: no sweep", s2 is None, str(s2))
check("no notification without a sweep", len(sent) == 1)

# --- only learning devices once the network is warm ------------------------------------------------------------
store.record_device_destinations("newdev", [C2_IP_2], timestamp=NOW - DAY)
store.record_device_destinations("baselined", [C2_IP_2], timestamp=NOW - DAY)
s3 = sweep.run_once()
check("a learning device triggers a scoped sweep", s3 and s3["trigger"] == TRIGGER_LEARNING, str(s3))
check("only the learning device is swept (the baselined device's new hit waits for the nightly job)",
      s3 and pairs_of(s3) == [("newdev", C2_IP_2)] and s3["devices_in_scope"] == 1, str(s3 and s3["findings"]))

# --- network warm-up: every device ----------------------------------------------------------------------------
pop.days = 3
s4 = sweep.run_once()
check("network warm-up sweeps every device", s4 and s4["trigger"] == TRIGGER_WARMUP and s4["devices_in_scope"] == "all")
check("and finds what the scoped sweep left out, once", s4 and pairs_of(s4) == [("baselined", C2_IP_2)],
      str(s4 and s4["findings"]))
s5 = sweep.run_once()
check("a repeat warm-up sweep reports nothing already reported", s5 and s5["findings_count"] == 0, str(s5))
check("notifications: one per sweep with findings", len(sent) == 3, str(len(sent)))

# --- summaries ---------------------------------------------------------------------------------------------------
recorded = store.get_intel_sweeps(limit=50)
check("every sweep that ran is recorded (4), newest first",
      [r["trigger"] for r in recorded] == [TRIGGER_WARMUP, TRIGGER_WARMUP, TRIGGER_LEARNING, TRIGGER_FIRST])
first = store.get_intel_sweeps(first=True)
check("the first sweep is readable for the onboarding report",
      len(first) == 1 and first[0]["trigger"] == TRIGGER_FIRST and first[0]["summary"]["findings_count"] == 2)
old_cap = GraphStore.INTEL_SWEEPS_KEPT
GraphStore.INTEL_SWEEPS_KEPT = 2
store.record_intel_sweep("x", {}, timestamp=NOW)
GraphStore.INTEL_SWEEPS_KEPT = old_cap
kept = store.get_intel_sweeps(limit=50)
check("the cap keeps the newest rows AND the very first one",
      [r["trigger"] for r in kept] == ["x", TRIGGER_WARMUP, TRIGGER_FIRST], str([r["trigger"] for r in kept]))
store.close()

# --- trust cache: read once, weak hits shielded, strong hits not ------------------------------------------------
store = GraphStore(str(tmp / "g2.db"))
ti = make_ti()
provider = TrustProvider({WEAK, STRONG})  # exact names: etld1_strict needs a public-suffix list
ti.trust_cache_provider = provider
pop = FakePopularity(30, [("d1", WEAK), ("d1", STRONG), ("d1", "a.example"), ("d1", "b.example")])
sweep = LearningIntelSweep(lambda: store, ti, lambda d: False, days_back=30, popularity=pop, now_fn=lambda: NOW)
s = sweep.run_once()
check("the trust cache is read once per sweep, not once per name", provider.calls == 1, str(provider.calls))
check("a trusted name's weak hit stays shielded; a trusted name's strong hit is still found",
      s and pairs_of(s) == [("d1", STRONG)], str(s and s["findings"]))
store.close()

store = GraphStore(str(tmp / "g3.db"))
ti = make_ti()
ti.trust_cache_provider = TrustProvider({WEAK}, fail=True)
sweep = LearningIntelSweep(lambda: store, ti, lambda d: False, days_back=30,
                           popularity=FakePopularity(30, [("d1", WEAK)]), now_fn=lambda: NOW)
s = sweep.run_once()
check("an unreadable trust cache does not stop the sweep, and shields nothing", s and pairs_of(s) == [("d1", WEAK)],
      str(s and s["findings"]))
store.close()

# --- no feeds loaded: runs, finds nothing, says so ----------------------------------------------------------------
store = GraphStore(str(tmp / "g4.db"))
store.record_device_destinations("d1", [C2_IP], timestamp=NOW - DAY)
empty_ti = ThreatIntel(cache_dir=str(tmp / "ti_empty"), refresh_interval=10**9)
quiet = []
sweep = LearningIntelSweep(lambda: store, empty_ti, lambda d: True, days_back=30, notify=quiet.append,
                           now_fn=lambda: NOW)
s = sweep.run_once()
check("with no feed loaded the sweep finds nothing and records intel_ready", s and s["findings_count"] == 0
      and s["intel_ready"] is False and not quiet, str(s))
check("without a popularity ledger the network does not count as warming up",
      sweep.run_once()["trigger"] == TRIGGER_LEARNING)
store.close()

# --- attach(): immediate sweep when feeds are ready, then on every refresh ----------------------------------------
store = GraphStore(str(tmp / "g5.db"))
store.record_device_destinations("d1", [C2_IP], timestamp=time.time() - DAY)
ti = make_ti()
sweep = LearningIntelSweep(lambda: store, ti, lambda d: True, days_back=30)


def wait_for(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


sweep.attach()
check("attach() sweeps right away when the feeds are already loaded",
      wait_for(lambda: sweep.last_summary is not None and sweep.last_summary["trigger"] == TRIGGER_FIRST))
wait_for(lambda: not sweep._lock.locked())
sweep.last_summary = None
ti._notify_refresh_listeners()
check("a later feed refresh triggers another sweep",
      wait_for(lambda: sweep.last_summary is not None and sweep.last_summary["trigger"] == TRIGGER_LEARNING))
wait_for(lambda: not sweep._lock.locked())

sweep._lock.acquire()
before = sweep.last_summary
sweep.on_feed_refresh()
time.sleep(0.3)
sweep._lock.release()
check("a refresh during a running sweep does not start a second one", sweep.last_summary is before)

not_ready = ThreatIntel(cache_dir=str(tmp / "ti_nr"), refresh_interval=10**9)
lazy = LearningIntelSweep(lambda: store, not_ready, lambda d: True, days_back=30)
lazy.attach()
time.sleep(0.3)
check("attach() waits for the first refresh when the feeds are not loaded yet", lazy.last_summary is None)
store.close()

# --- a failing listener never breaks the refresh loop -------------------------------------------------------------
ti = make_ti()
seen = []
ti.add_refresh_listener(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
ti.add_refresh_listener(lambda: seen.append(1))
try:
    ti._notify_refresh_listeners()
    ok = True
except Exception:
    ok = False
check("a listener exception is contained and the next listener still runs", ok and seen == [1])

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
print("All learning-period intel sweep checks PASSED.")
