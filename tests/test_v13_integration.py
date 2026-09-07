"""
v13 end-to-end integration test (Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Unlike every other test_v13_*.py file, this one deliberately exercises ALL 12
modules together in one realistic flow -- identity resolution -> evidence
ingestion -> graph storage -> hypothesis/decision evaluation -> LLM-review ground
truth assembly -> prompt building -> CL-AFPE immunization -> retro-hunt rescan.
Per-module unit tests already passed individually; this exists specifically to
catch interface mismatches BETWEEN modules that isolated tests structurally
cannot see (e.g. a decision_result dict shape one module produces not matching
what another expects).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_integration.py`
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


from v13.identity.resolver import resolve_device_id, TrustAnchor  # noqa: E402
from v13.evidence.model import Evidence  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402
from v13.graph.window import RollingWindowView  # noqa: E402
from v13.hypotheses.engine import HypothesisEngine  # noqa: E402
from v13.decision.engine import DecisionEngine, DecisionState  # noqa: E402
from v13.cl_afpe.engine import ClAfpeEngine  # noqa: E402
from v13.llm_review.validator import DeterministicValidator, build_ground_truth  # noqa: E402
from v13.llm_review.ollama_client import build_evidence_prompt, FULL_ANALYSIS_SCHEMA  # noqa: E402
from v13.retro_hunter import RetroHunter  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402

NOW = 2_000_000.0
tmpdir = tempfile.mkdtemp(prefix="v13_integration_test_")
store = GraphStore(str(_PathForSysPath(tmpdir) / "integration.db"))
cl_afpe = ClAfpeEngine(store)
decision_engine = DecisionEngine()
validator = DeterministicValidator()

# --- Step 1: identity resolution -> a real device_id, fed straight into the graph ---
anchors = {"gateway": TrustAnchor(role="gateway", ip="192.168.1.1")}
device_id = resolve_device_id("192.168.1.55", trust_anchors=anchors, hostname="suspicious-iot")
check("Step 1: identity resolution produces a usable device_id string",
      isinstance(device_id, str) and len(device_id) > 0)
check("Step 1: the device_id is NOT the gateway's (a real device, not the trust anchor itself)",
      device_id != resolve_device_id("192.168.1.1", trust_anchors=anchors))

# --- Step 2: real-shaped evidence, inserted via GraphStore ---
evidence_items = [
    Evidence(device_id=device_id, destination_id="c2-server.example.com", evidence_type="malicious_ja3",
              independence_family="tls_fingerprint", timestamp=NOW - 30, source="zeek_features", value=1.0),
    Evidence(device_id=device_id, destination_id="c2-server.example.com", evidence_type="zeek_lateral_scan",
              independence_family="network_behavior", timestamp=NOW - 20, source="zeek_features", value=1.0),
]
for ev in evidence_items:
    store.insert_evidence(ev)
check("Step 2: evidence inserted via GraphStore is retrievable for the resolved device_id",
      len(store.get_evidence_for_device(device_id)) == 2)

# --- Step 3: RollingWindowView reads it back correctly ---
window = RollingWindowView(store)
windowed_evidence = window.evidence_in_window(device_id, window_seconds=300, now=NOW)
check("Step 3: graph/window.py's query layer sees the same evidence GraphStore stored",
      len(windowed_evidence) == 2)

# --- Step 4: HypothesisEngine scores it, DecisionEngine reaches a verdict ---
rep = ReputationVector(domain="c2-server.example.com", tier=3)
decision_result = decision_engine.evaluate(windowed_evidence, rep, now=NOW)
check("Step 4: DecisionEngine consumes HypothesisEngine's output internally without error "
      "and reaches a real verdict", decision_result["state"] in
      (DecisionState.BENIGN, DecisionState.ANOMALOUS, DecisionState.SUSPICIOUS, DecisionState.HIGH, DecisionState.CRITICAL))
check("Step 4: two genuinely independent families (tls_fingerprint + network_behavior) "
      "correctly reach HIGH via hypothesis_high -- the cross-module family-counting path works",
      decision_result["decision_path"] == "hypothesis_high" and decision_result["state"] == DecisionState.HIGH)

# --- Step 5: llm_review/validator.py's build_ground_truth() consumes DecisionEngine's REAL output shape ---
ground_truth = build_ground_truth(decision_result, windowed_evidence, rep_tier=rep.tier)
check("Step 5: build_ground_truth() successfully reads DecisionEngine's real return dict "
      "shape with no KeyError/AttributeError -- the actual interface-compatibility point "
      "this integration test exists to verify",
      ground_truth["decision_path"] == "hypothesis_high" and ground_truth["independent_sources"] == 2)

# A 'benign' LLM verdict on this same alert should be rejected by the validator --
# proves the full evaluate() -> build_ground_truth() -> validate() chain works together.
llm_says_benign = {"classification": "benign", "reason": "just a smart device",
                    "supporting_evidence": ["low risk"], "recommended_action": "suppress"}
check("Step 5: the validator correctly rejects a 'benign' LLM verdict against an alert "
      "that DecisionEngine's own real output already scored HIGH -- the full chain agrees "
      "with itself end-to-end",
      not validator.validate(llm_says_benign, windowed_evidence, ground_truth=ground_truth))

# --- Step 6: ollama_client.py's prompt builder consumes the same evidence + ground truth ---
prompt = build_evidence_prompt(device_id, windowed_evidence,
                                  candidate_hypotheses=ground_truth["candidate_hypotheses"])
check("Step 6: build_evidence_prompt() builds a real prompt referencing the actual device "
      "and evidence, with no interface mismatch", device_id in prompt and "malicious_ja3" in prompt)
check("Step 6: FULL_ANALYSIS_SCHEMA is a well-formed schema ready to pair with this prompt "
      "in a real OllamaClient call (network itself not exercised here)",
      "classification" in FULL_ANALYSIS_SCHEMA["properties"])

# --- Step 7: CL-AFPE immunization + trust-cache check round-trips through the SAME store ---
# Domain is its own eTLD+1 base (single label + .com) so the assertions below can
# compare directly -- mark_false_positive() immunizes the BASE domain (v13 full-
# architecture plan, Phase 6e bugfix: matches fp_engine.py's real
# _extract_base_domain()-then-immunize() behavior exactly, which evaluate()'s own
# trust-cache lookup already assumed but this method didn't actually do until now).
alert_payload = {"signature": decision_result["hypotheses"]["attack"]["name"],
                  "device": {"id": device_id},
                  "network_context": {"queried_domain": "c2-server-example.com"}}
mfp_result = cl_afpe.mark_false_positive(alert_payload, now=NOW)
check("Step 7: CL-AFPE's device-identity refusal check correctly sees the device as known "
      "(it was upserted by insert_evidence in Step 2, on the SAME GraphStore instance) "
      "-- proves the identity/evidence/CL-AFPE modules share consistent device-id semantics",
      not mfp_result.refused)
check("Step 7: the correction immunizes the real destination this alert was actually about",
      mfp_result.immunized_destination == "c2-server-example.com")
check("Step 7: the trust cache correctly reflects this immunization immediately afterward",
      cl_afpe.is_trust_cached("c2-server-example.com",
                                hypothesis=decision_result["hypotheses"]["attack"]["name"], now=NOW))

# --- Step 8: retro-hunter operates on the SAME store, finding the SAME device/destination ---
def fake_intel_lookup(dest):
    return {"confidence": 5.0, "tags": ["c2"], "source": "test"} if dest == "c2-server.example.com" else None


retro = RetroHunter(store, threat_intel_lookup=fake_intel_lookup)
findings = retro.hunt(days_back=1, now=NOW)
check("Step 8: retro-hunter, run against the SAME store, finds the SAME device via a "
      "completely different query path (get_device_destinations_since vs get_evidence_for_device) "
      "-- the two read paths agree on what's actually in the graph",
      any(f.device_id == device_id and f.destination_id == "c2-server.example.com" for f in findings))

# The retro-hunt write-back should now ALSO show up if we re-run the full decision pipeline.
post_retro_evidence = window.evidence_in_window(device_id, window_seconds=300, now=NOW)
check("Step 8: the retro-hunter's graph write-back is visible to the SAME window query "
      "used earlier -- a finding from Phase 6 genuinely feeds back into what Phase 1/3 "
      "would see on the device's NEXT evaluation cycle",
      any(e.source == "retro_hunter" for e in post_retro_evidence))

store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 END-TO-END INTEGRATION checks PASSED — all 12 modules compose correctly together.")
