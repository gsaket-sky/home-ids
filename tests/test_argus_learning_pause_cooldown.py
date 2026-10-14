"""
The learning pause after an incident (MASTER_TODO 0d "Found while working", 2026-10-14; Design Invariant 06).

A device's baselines, regimes and Markov model do not learn while it sits at SUSPICIOUS/HIGH/CRITICAL, nor for 30 minutes
after it returns to a non-incident state. The cooldown was measured from the timestamp of the device's LATEST decision
row -- correct only if every row marks a state change. But a row is also written (a) for a device's very first decision
and (b) for each device's first cycle after every service restart (the in-memory "last decision" is empty), so a device that
never had an incident was paused for its first 30 minutes of life and again for 30 minutes after every restart of the
engine -- every device at once. The cooldown now starts when an incident ENDED: the first non-incident row after the
device's most recent incident row. A device with no incident in its history is never paused.

Run directly: `python tests/test_argus_learning_pause_cooldown.py`
"""
import sys
import tempfile
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.baseline.engine import BaselineEngine  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402

store = GraphStore(str(_P(tempfile.mkdtemp(prefix="argus_pause_")) / "g.db"))
engine = BaselineEngine(store)
T = 1_700_000_000.0
COOLDOWN = 1800.0


def device(name):
    store.upsert_device(name, device_type="laptop", timestamp=T)
    return name


def row(dev, ts, state):
    store.insert_decision(dev, ts, state, "test", 0.5, 1.0)


def paused(dev, now):
    engine._pause_cache.clear()
    return engine.is_learning_paused(dev, now)


# 1. a brand-new device: its first decision row is not the end of an incident
d = device("devNew")
row(d, T, "BENIGN")
check("a new device is not paused one minute after its first decision", paused(d, T + 60) is False)

# 2. the same device after a service restart: a second BENIGN row is written for it
row(d, T + 5000, "BENIGN")
check("a service restart (a fresh BENIGN row) does not pause a device that never had an incident",
      paused(d, T + 5060) is False)

# 3. an ANOMALOUS verdict is not an incident
d = device("devAnom")
row(d, T, "BENIGN")
row(d, T + 100, "ANOMALOUS")
check("ANOMALOUS is not an incident state: no pause", paused(d, T + 160) is False)

# 4. the incident rule itself (unchanged): paused while at an incident state, and for the cooldown after it ends
d = device("devInc")
row(d, T, "BENIGN")
row(d, T + 100, "HIGH")
check("paused while at HIGH", paused(d, T + 160) is True)
row(d, T + 200, "BENIGN")
check("paused right after returning to BENIGN", paused(d, T + 260) is True)
check("paused until the cooldown has elapsed", paused(d, T + 200 + COOLDOWN - 1) is True)
check("not paused once the cooldown since the incident ENDED has elapsed", paused(d, T + 200 + COOLDOWN + 1) is False)

# 5. a restart AFTER the cooldown writes another BENIGN row: it must not start a new pause
row(d, T + 200 + COOLDOWN + 600, "BENIGN")
check("a restart row after the cooldown does not re-pause the device",
      paused(d, T + 200 + COOLDOWN + 660) is False)

# 6. a restart row DURING the cooldown must not extend it (the cooldown runs from when the incident ended)
d = device("devRestartDuring")
row(d, T, "HIGH")
row(d, T + 100, "BENIGN")                       # incident ended at T+100
row(d, T + 1000, "BENIGN")                      # restart 900 s later
check("a restart row during the cooldown does not extend it: free at T+100+cooldown+1",
      paused(d, T + 100 + COOLDOWN + 1) is False)
check("... and still paused before that", paused(d, T + 100 + COOLDOWN - 60) is True)

# 7. a second incident restarts the cooldown from ITS end
d = device("devTwo")
row(d, T, "HIGH")
row(d, T + 100, "BENIGN")
row(d, T + 5000, "SUSPICIOUS")
row(d, T + 5100, "BENIGN")
check("a second incident: paused after it ends", paused(d, T + 5100 + 60) is True)
check("a second incident: the cooldown runs from the second end", paused(d, T + 5100 + COOLDOWN + 1) is False)

# 8. score_metric honours it for a new device (end to end)
d = device("devLearn")
row(d, T, "BENIGN")
ev = None
for i in range(5):
    ev = engine.score_metric(d, "query_rate", "gaussian", (10.0 + i,), hour=10, now=T + 60 + i)
n = store._conn.execute("SELECT n FROM device_baselines WHERE device_id=? AND metric='query_rate'", (d,)).fetchone()
check("a new device's baseline learns from its first minute (an observation was recorded)",
      n is not None and n["n"] >= 1, str(dict(n) if n else None))

print("PAUSE COOLDOWN", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
