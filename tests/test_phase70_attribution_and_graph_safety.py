"""
Phase 70 (2026-10-02, external architecture review):
  P0  exfiltration/beaconing evidence is attributed to what actually fired (the destination that received the
      bytes, the periodically queried domain) -- never the device's most recent connection (last_dest_ip), and
      without a batch-wide fallback; no destination is better than a wrong one.
  P1  the identity-reconcile worker thread merges through its own connection (the live singleton's connection is
      single-thread; the old call failed silently every time).
  P2  GraphStore.merge_device() is one transaction.
Run directly: python tests/test_phase70_attribution_and_graph_safety.py
"""
import sys
import tempfile
import threading
import time
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# -- P0: per-destination outbound bytes ----------------------------------------------------------------------------
from extractors.zeek_features import ZeekFeatureExtractor  # noqa: E402

zx = ZeekFeatureExtractor.__new__(ZeekFeatureExtractor)
zx._outbound_by_dst = {"10.0.0.5": deque([(1.0, "93.184.216.34", 9_000_000), (2.0, "151.101.1.69", 500_000),
                                          (3.0, "151.101.1.69", 400_000)])}
top = zx._outbound_top_destination(["10.0.0.5"])
check("the destination that received most bytes is named (90 %)", top["zeek_outbound_top_dest"] == "93.184.216.34"
      and top["zeek_outbound_top_dest_share"] > 0.9, str(top))
zx._outbound_by_dst = {"10.0.0.5": deque([(1.0, f"93.184.216.{i}", 1_000_000) for i in range(5)])}
top = zx._outbound_top_destination(["10.0.0.5"])
check("a transfer spread over many destinations names none", top["zeek_outbound_top_dest"] == "unknown", str(top))
check("no bytes -> unknown", zx._outbound_top_destination(["10.9.9.9"])["zeek_outbound_top_dest"] == "unknown")

# -- P0: detectors attribute to what fired -------------------------------------------------------------------------
from intelligence.detectors.threat_signals import ThreatSignalDetector  # noqa: E402

det = ThreatSignalDetector()
base = {"outbound_bytes_z": 6.0, "zeek_outbound_bytes": 9_900_000, "last_dest_ip": "8.8.4.4"}
ev = [e for e in det.detect("dev", dict(base, zeek_outbound_top_dest="93.184.216.34")) if e.type == "zeek_exfiltration"]
check("exfiltration names the byte receiver, not last_dest_ip",
      ev and ev[0].domain == "93.184.216.34", str([(e.type, e.domain) for e in ev]))
ev = [e for e in det.detect("dev", dict(base, zeek_outbound_top_dest="unknown")) if e.type == "zeek_exfiltration"]
check("no dominant receiver -> exfiltration evidence has no destination (still raised)",
      ev and ev[0].domain is None, str([(e.type, e.domain) for e in ev]))
ev = [e for e in det.detect("dev", dict(base, zeek_outbound_top_dest="192.168.1.20")) if e.type == "zeek_exfiltration"]
check("bytes going to a LAN address are not exfiltration", not ev)

b = det.detect("dev", {"beaconing_c2_1h": 2, "beaconing_c2_1h_domains": ["cnc.example", "x.example"],
                       "last_dest_ip": "8.8.4.4"})
bev = [e for e in b if e.type == "zeek_beaconing"]
check("low-and-slow beaconing names the periodic domain, not last_dest_ip",
      bev and bev[0].domain == "cnc.example", str([(e.type, e.domain) for e in bev]))
b = det.detect("dev", {"beaconing_c2_count": 3, "beaconing_c2_domains": ["jitter.example"], "last_dest_ip": "8.8.4.4"})
bev = [e for e in b if e.type == "zeek_beaconing"]
check("jitter beaconing names its domain", bev and bev[0].domain == "jitter.example", str([(e.type, e.domain) for e in bev]))
b = det.detect("dev", {"beaconing_c2_count": 3, "beaconing_c2_domains": ["printer.local"]})
check("periodic queries for a LAN name are not beaconing", not [e for e in b if e.type == "zeek_beaconing"])
b = det.detect("dev", {"beaconing_c2_count": 3, "last_dest_ip": "8.8.4.4"})
bev = [e for e in b if e.type == "zeek_beaconing"]
check("beaconing without a known domain is raised without a destination",
      bev and bev[0].domain is None, str([(e.type, e.domain) for e in bev]))

src = (Path(__file__).resolve().parent.parent / "src/argus/ops/live_engine.py").read_text(encoding="utf-8")
check("live_engine has no last_dest_ip fallback any more",
      "_NEEDS_LAST_DEST_IP_FALLBACK" not in src and "_build_fallback_context" not in src)

# -- P2: merge_device is atomic -----------------------------------------------------------------------------------
from argus.graph.store import GraphStore  # noqa: E402

db = str(Path(tempfile.mkdtemp()) / "g.db")
g = GraphStore(db)
real_add_edge = g.add_edge


def boom(*a, **k):
    raise RuntimeError("crash between tombstone and edge")


g.add_edge = boom
try:
    g.merge_device("orphan", "canon", timestamp=100.0)
except RuntimeError:
    pass
row = g._conn.execute("SELECT merged_into_device_id FROM devices WHERE device_id='orphan'").fetchone()
check("a failure mid-merge leaves no tombstone behind (rolled back)", row is None or row[0] is None, str(row and tuple(row)))
g.add_edge = real_add_edge
g.merge_device("orphan", "canon", timestamp=101.0)
check("a normal merge writes tombstone and edge together",
      g._conn.execute("SELECT merged_into_device_id FROM devices WHERE device_id='orphan'").fetchone()[0] == "canon"
      and g._conn.execute("SELECT count(*) FROM edges WHERE src_id='orphan' AND relation='merged_into'").fetchone()[0] == 1)

# -- P1: merging from another thread ------------------------------------------------------------------------------
from argus.ops import live_engine  # noqa: E402

db2 = str(Path(tempfile.mkdtemp()) / "g2.db")
live_engine._GRAPH_DB_PATH = db2
live_engine._graph_store = GraphStore(db2)          # the main loop's singleton, created on this thread
err = []


def worker():
    try:
        live_engine.get_graph_store().merge_device("a", "b")
    except Exception as e:                           # the old path: sqlite3 refuses the cross-thread call
        err.append(type(e).__name__)
    try:
        live_engine.merge_device_in_own_connection("c", "d")
    except Exception as e:
        err.append("new:" + repr(e))


t = threading.Thread(target=worker)
t.start()
t.join()
check("the singleton's cross-thread call works (E16/I9: each thread gets its own connection)", not err[:1], str(err))
check("the worker's own-connection merge succeeds", not [x for x in err if x.startswith("new:")], str(err))
check("and the main loop's singleton sees it",
      live_engine._graph_store.resolve_canonical_device_id("c") == "d")
psrc = (Path(__file__).resolve().parent.parent / "src/core/pipeline.py").read_text(encoding="utf-8")
check("the reconcile worker uses the own-connection merge",
      "argus_live_engine.merge_device_in_own_connection(orphan[\"device_id\"], canonical[\"device_id\"])" in psrc)

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED: {FAILURES}")
    sys.exit(1)
print("All phase-70 attribution + graph-safety checks PASSED.")
