"""
Re-decision with graph context (MASTER_TODO 0d "Found while working", 2026-10-14; follows U7's gather/decide split).

pipeline.py's GeoIP step adds a geofencing hard-stop item after the main decision and decides again. That second decision
used to call evaluate() with no device id, no features and no familiarity: it saw none of the device's graph history,
none of the derived signals, no baseline evidence, and none of the cycle's features (so the honeypot hard stop, which reads
a feature, could not fire in it). It now re-decides the cycle's own gathered facts plus the new evidence --
live_engine.redecide_with_evidence(cycle, new_evidence) -- through the pure decide(): same context as the main decision,
nothing gathered again, nothing written (the pipeline writes the supplementary row).

Run directly: `python tests/test_argus_redecide_with_evidence.py`
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


from intelligence.hypotheses.evidence import Evidence as V1Evidence  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402
import argus.ops.live_engine as live_engine  # noqa: E402

live_engine.configure(str(_P(tempfile.mkdtemp(prefix="argus_redecide_")) / "graph.db"))
store = live_engine.get_graph_store()
T0 = 1_700_000_000.0
DEV = "devRedecide"
store.upsert_device(DEV, timestamp=T0)
rep = ReputationVector(domain="", tier=1)


def notice(ts):
    return V1Evidence(type="zeek_notice_medium", source="zeek", timestamp=ts, device=DEV, value=1.0, confidence=0.6, domain="example.com")


def geofence(ts):
    return V1Evidence(type="geofencing_violation", source="geoip", timestamp=ts, device=DEV, value=10.0, confidence=1.0,
                      provenance="Blocklisted Country: XX", domain="198.51.100.7")


# Cycle 1 writes a notice into the graph; cycle 2 has NO fresh evidence of its own, so the notice is only visible through
# the graph window (history), the thing the old re-decision never saw.
live_engine.evaluate_cycle([notice(T0)], rep, features={}, device_id=DEV, now=T0)
_, cycle2 = live_engine.evaluate_cycle([], rep, features={"zeek_honeypot_hits": 1}, device_id=DEV, now=T0 + 30.0)
check("setup: cycle 2 carries the device's graph history", bool(cycle2.gathered.windowed_v2))

n_dec = store._conn.execute("SELECT COUNT(*) FROM decisions WHERE device_id=?", (DEV,)).fetchone()[0]
n_ev = store._conn.execute("SELECT COUNT(*) FROM evidence WHERE device_id=?", (DEV,)).fetchone()[0]
eng = live_engine._get_baseline_engine()
markov_before = (eng._markov.get((DEV, "activity_state")).to_dict() if eng._markov.get((DEV, "activity_state")) else None)
keys_before = (live_engine._last_decision_key.get(DEV), live_engine._last_decision_id.get(DEV))

decision = live_engine.redecide_with_evidence(cycle2, [geofence(T0 + 30.0)])

check("the re-decision sees the geofencing evidence", "geofencing_violation" in decision.get("evidence_types", []) or
      decision.get("decision_path") == "hard_stop" or "Geofencing" in str(decision.get("explanation")),
      str({k: decision.get(k) for k in ("state", "decision_path", "explanation", "evidence_types")}))
check("the re-decision sees the cycle's features: the honeypot hard stop fires (the old path had no features)",
      decision.get("state") == "CRITICAL" and decision.get("decision_path") == "hard_stop"
      and "Honeypot" in str(decision.get("explanation")),
      str({k: decision.get(k) for k in ("state", "decision_path", "explanation")}))
check("the re-decision sees the device's graph history (the old path had none)",
      "zeek_notice_medium" in decision.get("evidence_types", []), str(decision.get("evidence_types")))
check("it writes nothing: no new decision rows", store._conn.execute(
    "SELECT COUNT(*) FROM decisions WHERE device_id=?", (DEV,)).fetchone()[0] == n_dec)
check("it writes nothing: no new evidence rows", store._conn.execute(
    "SELECT COUNT(*) FROM evidence WHERE device_id=?", (DEV,)).fetchone()[0] == n_ev)
markov_after = (eng._markov.get((DEV, "activity_state")).to_dict() if eng._markov.get((DEV, "activity_state")) else None)
check("it gathers nothing: the baseline/Markov learners are untouched", markov_before == markov_after)
check("it leaves the 'last decision' bookkeeping alone",
      keys_before == (live_engine._last_decision_key.get(DEV), live_engine._last_decision_id.get(DEV)))
check("the cycle the pipeline holds is unchanged (immutable): same fresh evidence as before",
      len(cycle2.gathered.fresh_v2) == 0)

# without geofence-only context: a geofencing item alone on a quiet cycle is still a hard stop, uncorroborated -> HIGH
store.upsert_device("devQuiet", timestamp=T0)
_, quiet = live_engine.evaluate_cycle([], rep, features={}, device_id="devQuiet", now=T0)
d_quiet = live_engine.redecide_with_evidence(quiet, [V1Evidence(
    type="geofencing_violation", source="geoip", timestamp=T0, device="devQuiet", value=10.0, confidence=1.0,
    provenance="Blocklisted Country: XX", domain="198.51.100.7")])
check("a lone geofencing item on a quiet cycle stays an uncorroborated HIGH (unchanged rule)",
      d_quiet.get("state") == "HIGH", str(d_quiet.get("state")))
# The geofence rule needs an independent second source. The device's own recent notice (in the graph window) is one --
# the old path, deciding with no history, could never see it (measured on the old call shape: HIGH, uncorroborated,
# evidence_types [], independent_sources 0).
store.upsert_device("devHistory", timestamp=T0)
live_engine.evaluate_cycle([V1Evidence(type="zeek_notice_medium", source="zeek", timestamp=T0, device="devHistory",
                                       value=1.0, confidence=0.6,
                                       domain="example.com")], rep, features={}, device_id="devHistory", now=T0)
_, hist = live_engine.evaluate_cycle([], rep, features={}, device_id="devHistory", now=T0 + 30.0)
d_hist = live_engine.redecide_with_evidence(hist, [V1Evidence(
    type="geofencing_violation", source="geoip", timestamp=T0 + 30.0, device="devHistory", value=10.0, confidence=1.0,
    provenance="Blocklisted Country: XX", domain="198.51.100.7")])
check("a geofencing item corroborated by the device's own graph history is decided as corroborated (CRITICAL hard stop)",
      d_hist.get("state") == "CRITICAL" and d_hist.get("decision_path") == "hard_stop"
      and "zeek_notice_medium" in d_hist.get("evidence_types", []),
      str({k: d_hist.get(k) for k in ("state", "decision_path", "evidence_types", "independent_sources")}))
check("a cycle that could not be evaluated is re-decided as not evaluated, never by another path",
      live_engine.redecide_with_evidence(None, [geofence(T0)]) is None)

print("REDECIDE", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
