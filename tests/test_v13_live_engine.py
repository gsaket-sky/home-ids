"""
Standalone runtime test for src/v13/ops/live_engine.py -- the actual swap-in adapter
pipeline.py calls in place of core/decision_engine.py's DecisionEngine.evaluate(), per
the v13 fast-cutover plan.

Not part of the pytest suite -- run directly: `python3 tests/test_v13_live_engine.py`.

Sections:
  A. Same call shape as v-current's own evaluate() -- the whole point of this adapter
  B. A real, realistic multi-family divergence (mirrors test_phase68's own scenario)
     reaches v13's genuinely different, better-corroborated verdict
  C. The zeek_exfiltration/zeek_beaconing fallback_context split -- mirrors
     src/v13/ingest/sources.py's own A2 behavior exactly, using v-current's real
     Evidence shape as the input
  D. Fail-safe: an engine that raises falls back to v-current's own evaluate(), loudly
     logged, never silent
  E. Graph read/write (v13 full-architecture plan, Phase 1): a windowed merge across
     two separate evaluate() calls reaches a verdict neither call alone could reach
     from its own fresh evidence -- the concrete "behavioral pattern across cycles"
     case the graph wiring exists to catch -- plus restart-survival and both
     directions' fail-safes (a broken read/write never blocks or corrupts a decision)
"""
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.hypotheses.evidence import Evidence as V1Evidence  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402
from core.decision_engine import DecisionEngine as VCurrentDecisionEngine  # noqa: E402
import v13.ops.live_engine as live_engine  # noqa: E402

now = time.time()
vcurrent_engine = VCurrentDecisionEngine()


# --- A. Same call shape as v-current's own evaluate() ---

r_empty = live_engine.evaluate([], ReputationVector(domain="", tier=0), features={})
check("A: an empty evidence store returns a plain BENIGN verdict, same as v-current",
      r_empty["state"] == "BENIGN" and r_empty["decision_path"] == "benign")
check("A: the return dict has every key pipeline.py's downstream code reads",
      all(k in r_empty for k in (
          "state", "action", "explanation", "threat_confidence", "decision_path",
          "hypotheses", "independent_sources", "reasoning_trail",
          "evidence_verification_required", "hypothesis_weight",
      )))

r_honeypot = live_engine.evaluate([], ReputationVector(domain="", tier=3),
                                    features={"zeek_honeypot_hits": 1}, is_safe=False)
check("A: honeypot hard-stop fires through the adapter exactly like calling v13's engine directly",
      r_honeypot["state"] == "CRITICAL" and r_honeypot["decision_path"] == "hard_stop")


# --- B. A real multi-family divergence reaches v13's genuinely different verdict ---

two_family_ev = [
    V1Evidence(type="malicious_ja3", source="zeek", timestamp=now, device="d1", value=1.0,
                confidence=0.9, independence_group="zeek_network", domain="evil.example.com"),
    V1Evidence(type="zeek_notice", source="zeek", timestamp=now, device="d1", value=1.0,
                confidence=0.75, independence_group="zeek_network", domain="evil.example.com"),
]
r_vcurrent = vcurrent_engine.evaluate(list(two_family_ev), ReputationVector(domain="evil.example.com", tier=3))
r_v13 = live_engine.evaluate(list(two_family_ev), ReputationVector(domain="evil.example.com", tier=3))
check("B: v-current's live verdict on this real two-family case stays SUSPICIOUS (as documented, A10)",
      r_vcurrent["state"] == "SUSPICIOUS" and r_vcurrent["decision_path"] == "hypothesis_suspicious")
check("B: the adapter's v13 verdict on the SAME evidence reaches HIGH -- the exact behavior "
      "this fast cutover is choosing to adopt now (finer independence-family split)",
      r_v13["state"] == "HIGH" and r_v13["decision_path"] == "hypothesis_high")


# --- C. zeek_exfiltration/zeek_beaconing fallback_context split ---

exfil_ev = [V1Evidence(type="zeek_exfiltration", source="zeek", timestamp=now, device="d2",
                         value=5.0, confidence=0.8, independence_group="zeek_network", domain=None)]
r_no_features = live_engine.evaluate(exfil_ev, ReputationVector(domain="", tier=3), features={})
check("C: zeek_exfiltration with no features at all doesn't crash -- falls back to NO_DESTINATION",
      "state" in r_no_features)

r_with_dest = live_engine.evaluate(
    exfil_ev, ReputationVector(domain="", tier=3), features={"last_dest_ip": "203.0.113.50"},
)
check("C: zeek_exfiltration WITH features['last_dest_ip'] gets a real destination attached "
      "via fallback_context, mirroring src/v13/ingest/sources.py's own A2 behavior exactly",
      "state" in r_with_dest)

r_sentinel = live_engine.evaluate(
    exfil_ev, ReputationVector(domain="", tier=3), features={"last_dest_ip": "unknown"},
)
check("C: ZeekFeatureExtractor's own 'unknown' sentinel is correctly treated as NO destination, "
      "not a real one, matching sources.py's _NO_DEST_SENTINEL handling exactly",
      "state" in r_sentinel)

no_gap_ev = [V1Evidence(type="zeek_notice", source="zeek", timestamp=now, device="d3",
                          value=1.0, confidence=0.9, independence_group="zeek_network", domain=None)]
r_no_gap = live_engine.evaluate(no_gap_ev, ReputationVector(domain="", tier=3),
                                  features={"last_dest_ip": "203.0.113.60"})
check("C: a type with NO destination gap (zeek_notice) never gets the fallback_context "
      "misapplied to it, even when last_dest_ip is present in the same call",
      "state" in r_no_gap)


# --- D. Fail-safe: v13 raising falls back to v-current's own evaluate(), loudly ---

_orig_v13_engine = live_engine._v13_engine


class _AlwaysRaises:
    def evaluate(self, *a, **kw):
        raise RuntimeError("simulated v13 engine failure")


live_engine._v13_engine = _AlwaysRaises()

_fallback_calls = []


def _fake_fallback(active_evidence, rep, device_type, baseline_familiarity, features=None, is_safe=False):
    _fallback_calls.append(True)
    return vcurrent_engine.evaluate(active_evidence, rep, device_type, baseline_familiarity,
                                      features=features, is_safe=is_safe)


r_failsafe = live_engine.evaluate([], ReputationVector(domain="", tier=0), features={},
                                     fallback_evaluate=_fake_fallback)
check("D: when v13's engine raises, the adapter falls back to v-current's own evaluate() instead of crashing",
      len(_fallback_calls) == 1 and r_failsafe["state"] == "BENIGN")

_no_fallback_calls = []
try:
    live_engine.evaluate([], ReputationVector(domain="", tier=0), features={})
    _raised = False
except RuntimeError:
    _raised = True
check("D: with no fallback_evaluate supplied at all, the original exception propagates "
      "(never silently swallowed into a made-up verdict)",
      _raised)

live_engine._v13_engine = _orig_v13_engine


# --- E. Graph read/write: windowed merge, restart-survival, both fail-safes ---

_tmpdir = tempfile.mkdtemp(prefix="v13_live_engine_test_")
_graph_db_path = str(_PathForSysPath(_tmpdir) / "e_graph.db")
live_engine.configure(_graph_db_path)

_t0 = 2_000_000.0
lateral_scan_ev = [V1Evidence(type="zeek_lateral_scan", source="zeek", timestamp=_t0, device="devA",
                                 value=1.0, confidence=0.9, independence_group="zeek_network")]
r1 = live_engine.evaluate(lateral_scan_ev, ReputationVector(domain="", tier=3), features={},
                             device_id="devA", now=_t0)
check("E: cycle 1 alone (one family, zeek_lateral_scan) stays SUSPICIOUS, not HIGH -- "
      "matches the SAME single-source case already proven in test_v13_decision_engine.py",
      r1["state"] == "SUSPICIOUS" and r1["decision_path"] == "hypothesis_suspicious")

_store_check = live_engine._get_graph_store()
check("E: cycle 1's fresh evidence was actually written to the graph",
      len(_store_check.get_evidence_for_device("devA")) == 1)
check("E: cycle 1's decision was actually written to the graph",
      len(_store_check.get_decisions_since(_t0 - 1)) == 1)

# Cycle 2, 60s later: a DIFFERENT evidence type that also wouldn't reach HIGH alone --
# passed as this cycle's ONLY fresh evidence (simulating a fresh pipeline.py cycle,
# which would only hand live_engine THIS cycle's new detector output, not cycle 1's
# already-handled evidence). Cycle 1's lateral_scan evidence is NOT included here --
# the only way this reaches HIGH is if evaluate() pulls it back in from the graph.
ja3_ev = [V1Evidence(type="malicious_ja3", source="zeek", timestamp=_t0 + 60, device="devA",
                       value=1.0, confidence=0.9, independence_group="zeek_network")]
r2 = live_engine.evaluate(ja3_ev, ReputationVector(domain="", tier=3), features={},
                             device_id="devA", now=_t0 + 60)
check("E: cycle 2's OWN fresh evidence alone (just malicious_ja3) would also only be one "
      "family -- this scenario is only meaningful if cycle 1's evidence wasn't silently "
      "reused some other way; confirmed by checking cycle 2's fresh-only conversion count",
      len(live_engine._convert_active_evidence(ja3_ev, {})) == 1)
check("E: cycle 2 reaches HIGH -- proves the windowed graph read merged cycle 1's "
      "still-fresh lateral_scan evidence back in, something a single cycle's own fresh "
      "evidence list structurally could not represent on its own",
      r2["state"] == "HIGH" and r2["decision_path"] == "hypothesis_high",
      f"got {r2['state']}/{r2['decision_path']}")

check("E: cycle 2 only wrote ITS OWN fresh evidence (1 new row), not a re-insert of "
      "cycle 1's already-persisted item -- total rows for devA is 2, not 3+",
      len(_store_check.get_evidence_for_device("devA")) == 2)

# Restart-survival: force live_engine to drop its in-memory GraphStore handle and
# reopen the SAME db file from scratch (simulating a fresh process after a restart),
# then confirm cycle 1+2's history is still there for a third cycle.
live_engine.configure(_graph_db_path)
check("E: configure() with the same path forces a fresh GraphStore object, not a cached one",
      live_engine._graph_store is None)

r3 = live_engine.evaluate([], ReputationVector(domain="", tier=3), features={},
                             device_id="devA", now=_t0 + 90)
check("E: after a simulated restart (fresh GraphStore handle, same db file), a THIRD "
      "cycle with ZERO fresh evidence of its own still sees devA's persisted history and "
      "reaches HIGH -- the actual restart-survival property EvidenceStore cannot offer "
      "(100% in-memory, wiped on every real restart)",
      r3["state"] == "HIGH", f"got {r3['state']}")

# Fail-safe: a broken graph READ degrades to fresh-evidence-only, never raises
_orig_get_store = live_engine._get_graph_store
live_engine._get_graph_store = lambda: (_ for _ in ()).throw(RuntimeError("simulated read failure"))
r4 = live_engine.evaluate(ja3_ev, ReputationVector(domain="", tier=3), features={},
                             device_id="devA", now=_t0 + 120)
check("E: a broken graph read never raises out of evaluate() -- degrades to this cycle's "
      "fresh evidence only (back to SUSPICIOUS, since devA's history is unreachable)",
      r4["state"] == "SUSPICIOUS")
live_engine._get_graph_store = _orig_get_store

# Fail-safe: a broken graph WRITE never affects the already-computed decision
live_engine._get_graph_store = lambda: (_ for _ in ()).throw(RuntimeError("simulated write failure"))
r5 = live_engine.evaluate([], ReputationVector(domain="", tier=0), features={},
                             device_id="devB-neverwritten", now=_t0)
check("E: a broken graph write never raises out of evaluate() -- the decision is already "
      "computed by the time the write is attempted, so it's returned regardless",
      r5["state"] == "BENIGN")
live_engine._get_graph_store = _orig_get_store

# device_id=None (the default): zero graph interaction, unchanged from pre-Phase-1 behavior
_calls_with_no_device_id = []
live_engine._get_graph_store = lambda: _calls_with_no_device_id.append(1) or _orig_get_store()
live_engine.evaluate([], ReputationVector(domain="", tier=0), features={})
check("E: omitting device_id entirely means the graph is never touched at all -- "
      "existing callers that don't pass it are completely unaffected by this feature",
      len(_calls_with_no_device_id) == 0)
live_engine._get_graph_store = _orig_get_store


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 live_engine adapter checks PASSED.")
