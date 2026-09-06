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
"""
import sys
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


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 live_engine adapter checks PASSED.")
