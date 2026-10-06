"""
The graph's devices.last_seen moves only on traffic (MASTER_TODO M3, "`last_seen` moving without traffic").

On .94 (2026-10-06) a device the engine last saw 39 days earlier had last_seen = now in the graph: baseline scoring
(BaselineEngine.score_metric's foreign-key upsert, every known device every cycle), decisions re-written after each
restart, CL-AFPE trust edges, metadata mirrors and retrospective evidence all called upsert_device(), which advances
last_seen. Covers: ensure_device() creates a missing row and never moves an existing one; metadata, evidence,
decisions, containment actions and baseline scoring leave last_seen alone; recorded destinations and the pipeline's
per-cycle activity signal (live_engine.record_device_traffic(seen=True)) still advance it.

Run directly: `venv/Scripts/python.exe tests/test_device_last_seen_traffic_only.py`
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.graph.store import GraphStore  # noqa: E402
from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from argus.baseline.engine import BaselineEngine  # noqa: E402
import argus.ops.live_engine as live_engine  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="last_seen_"))
store = GraphStore(str(tmp / "graph.db"))


def last_seen(dev):
    row = store._conn.execute("SELECT last_seen FROM devices WHERE device_id = ?", (dev,)).fetchone()
    return None if row is None else row[0]


T0 = 1_000_000.0       # the device's last real traffic
LATER = T0 + 30 * 86400.0

# --- ensure_device -----------------------------------------------------------------------------------------------
store.ensure_device("new", timestamp=T0)
row = store._conn.execute("SELECT first_seen, last_seen FROM devices WHERE device_id='new'").fetchone()
check("ensure_device creates a missing row with first_seen = last_seen = the given time",
      row is not None and row[0] == T0 and row[1] == T0)
store.ensure_device("new", timestamp=LATER)
check("ensure_device never moves an existing row's last_seen", last_seen("new") == T0)

# --- non-traffic writes ------------------------------------------------------------------------------------------
store.upsert_device("idle", timestamp=T0)
store.update_device_metadata("idle", {"sigma_shift": 0.5}, timestamp=LATER)
check("a metadata write does not move last_seen", last_seen("idle") == T0)
check("...and the metadata is written", store.get_device_metadata("idle").get("sigma_shift") == 0.5)

store.insert_evidence(Evidence(device_id="idle", destination_id=NO_DESTINATION, evidence_type="reputation",
                               independence_family="reputation", timestamp=LATER, source="retro_hunter"))
check("retrospective evidence (stamped when found) does not move last_seen", last_seen("idle") == T0)

store.insert_decision("idle", LATER, "BENIGN", "test", 0.0, 0.0)
check("a decision (e.g. the one every device writes after a restart) does not move last_seen", last_seen("idle") == T0)

store.insert_containment_action("idle", "release", "ok", timestamp=LATER)
check("a containment audit row does not move last_seen", last_seen("idle") == T0)

BaselineEngine(store).score_metric("idle", "dns_query_count", "poisson", (0.0,), 3, now=LATER)
check("baseline scoring of an idle device does not move last_seen", last_seen("idle") == T0)

store.insert_evidence(Evidence(device_id="brand_new", destination_id=NO_DESTINATION, evidence_type="x",
                               independence_family="x", timestamp=LATER, source="t"))
check("evidence for an unknown device still creates its row (foreign keys)", last_seen("brand_new") == LATER)

# --- traffic -----------------------------------------------------------------------------------------------------
store.record_device_destinations("idle", ["203.0.113.5"], timestamp=LATER)
check("recorded destinations (real traffic) advance last_seen", last_seen("idle") == LATER)

live_engine._graph_store = store  # the module-level singleton record_device_traffic writes through
store.upsert_device("wifi", timestamp=T0)
live_engine.record_device_traffic("wifi", [], now=LATER, seen=False)
check("no destinations and no activity: last_seen stays", last_seen("wifi") == T0)
live_engine.record_device_traffic("wifi", [], now=LATER, seen=True)
check("DNS-only activity this cycle (seen=True, no Zeek destinations) advances last_seen", last_seen("wifi") == LATER)

active = store.get_active_device_ids(seen_since=LATER - 86400.0)
check("get_active_device_ids now lists only devices with traffic in the window",
      "idle" in active and "wifi" in active and "new" not in active, str(active))

if FAILURES:
    print(f"\n{len(FAILURES)} check(s) FAILED")
    sys.exit(1)
print("\nAll last_seen traffic-only checks PASSED.")
