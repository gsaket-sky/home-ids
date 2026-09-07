"""
Standalone runtime test for v13's CL-AFPE shadow-mode wiring (v13 full-architecture
plan, Phase 6e -- src/v13/ops/live_engine.py's evaluate_cl_afpe_shadow(), the pipeline.py
call site added alongside the real self.fp_engine.evaluate() call).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_live_cl_afpe_shadow.py`

Sections:
  A. evaluate_cl_afpe_shadow() computes a real v13 CL-AFPE verdict and appends one
     divergence-log record per call, agreeing or disagreeing with the v1 verdict passed
     in -- proves the comparison itself is real, not a stub.
  B. Fail-safe: a CL-AFPE engine that raises never propagates out of
     evaluate_cl_afpe_shadow() -- "compute-only" means a shadow failure can never affect
     the real alert pipeline.py is publishing this cycle.
  C. The v13-only LocalConfirmedIntel store used for shadow local-intel poisoning
     protection is deliberately SEPARATE from v-current's real
     state/local_confirmed_intel.json -- confirmed by path, not just by docstring claim.
"""
import json
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


import v13.ops.live_engine as live_engine  # noqa: E402

tmpdir = tempfile.mkdtemp(prefix="v13_clafpe_shadow_test_")
graph_db_path = str(_PathForSysPath(tmpdir) / "graph.db")
local_intel_dir = str(_PathForSysPath(tmpdir) / "cl_afpe_intel")
divergence_log_path = str(_PathForSysPath(tmpdir) / "cl_afpe_divergence_v13.jsonl")
model_dir = str(_PathForSysPath(tmpdir) / "no_models_here")  # deliberately empty -- no ONNX/FastEmbed

live_engine.configure(graph_db_path)
live_engine.configure_cl_afpe(model_dir=model_dir, local_intel_dir=local_intel_dir)
live_engine._CL_AFPE_DIVERGENCE_LOG_PATH = divergence_log_path

NOW = 1_000_000.0

# GraphStore auto-creates devices on evidence/decision writes elsewhere, but CL-AFPE's
# own device-identity refusal guard needs the device to already exist -- create it
# directly via the same graph store singleton evaluate_cl_afpe_shadow() itself uses.
_store = live_engine.get_graph_store()
_store.upsert_device("shadow_pipeline_dev", timestamp=NOW)


def _alert(device_id="shadow_pipeline_dev", signature="NETWORK_INTRUSION",
           domain="", dest_ip="", features=None):
    return {
        "signature": signature,
        "device": {"id": device_id, "hostname": "shadow-pipeline-host"},
        "network_context": {"queried_domain": domain, "destination_ip": dest_ip},
        "features": features or {},
    }


# --- A. real end-to-end shadow evaluation + divergence logging ---

alert_a = _alert(features={"zeek_honeypot_hits": 1})
fp_verdict_v1_a = {"verdict": "CONFIRMED_THREAT", "confidence": 0.0, "stage": "STAGE_1_HARD_STOP"}
decision_a = {"state": "CRITICAL", "explanation": "Internal Honeypot Accessed"}

live_engine.evaluate_cl_afpe_shadow(
    alert_payload=alert_a, features=alert_a["features"], decision=decision_a,
    asn_owner="", fp_verdict_v1=fp_verdict_v1_a, now=NOW,
)

log_path = _PathForSysPath(divergence_log_path)
check("A: evaluate_cl_afpe_shadow() creates the divergence log on its first call",
      log_path.exists())

records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
check("A: exactly one record was appended for the one call made so far", len(records) == 1)

rec = records[0] if records else {}
check("A: the logged record carries v13's own real computed verdict (not a placeholder)",
      rec.get("v13_verdict") == "CONFIRMED_THREAT" and rec.get("v13_stage") == "STAGE_1_HARD_STOP")
check("A: the logged record carries the v1 verdict passed through unchanged",
      rec.get("v1_verdict") == "CONFIRMED_THREAT" and rec.get("v1_stage") == "STAGE_1_HARD_STOP")
check("A: agree=True when both engines reached the same verdict on this alert",
      rec.get("agree") is True)
check("A: device/hostname/signature identifiers are carried through for later analysis",
      rec.get("device_id") == "shadow_pipeline_dev" and rec.get("signature") == "NETWORK_INTRUSION")

# A genuine disagreement: v1 says FALSE_POSITIVE, v13's Check 0 (its own decision
# state) deterministically hard-stops to CONFIRMED_THREAT -- logs agree=False.
# Deliberately a Stage 1 scenario, not Stage 2/3: the real MLScorer wired into
# live_engine's shadow singleton loads v-current's REAL FastEmbed model (a live
# network/HuggingFace-cache dependency, not the deterministic rule fallback
# test_v13_cl_afpe.py itself uses with ml_scorer=None) -- staying in Stage 1 keeps
# this file fast and deterministic without asserting on that model's real output.
alert_b = _alert(domain="unknown")
fp_verdict_v1_b = {"verdict": "FALSE_POSITIVE", "confidence": 0.91, "stage": "STAGE_3_COMBINED"}
live_engine.evaluate_cl_afpe_shadow(
    alert_payload=alert_b, features=alert_b["features"],
    decision={"state": "CRITICAL", "explanation": "Layer-2 ARP Spoofing Detected"},
    asn_owner="", fp_verdict_v1=fp_verdict_v1_b, now=NOW + 1,
)
records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
check("A: a second call appends a second record (never overwrites)", len(records) == 2)
check("A: a genuine verdict mismatch is logged as agree=False, not silently dropped",
      records[1].get("agree") is False
      and records[1].get("v1_verdict") == "FALSE_POSITIVE"
      and records[1].get("v13_verdict") == "CONFIRMED_THREAT")


# --- B. fail-safe: a raising CL-AFPE engine never propagates ---

class _ExplodingEngine:
    def evaluate(self, *a, **kw):
        raise RuntimeError("simulated CL-AFPE shadow failure")


_real_get_engine = live_engine._get_cl_afpe_engine
live_engine._get_cl_afpe_engine = lambda: _ExplodingEngine()
raised = False
try:
    live_engine.evaluate_cl_afpe_shadow(
        alert_payload=_alert(), features={}, decision={"state": "BENIGN", "explanation": "ok"},
        fp_verdict_v1={"verdict": "FALSE_POSITIVE"}, now=NOW + 2,
    )
except Exception:
    raised = True
finally:
    live_engine._get_cl_afpe_engine = _real_get_engine

check("B: evaluate_cl_afpe_shadow() NEVER raises out to the caller, even when the "
      "underlying CL-AFPE engine itself raises -- pipeline.py's real alert publish "
      "must never be affected by a shadow-mode failure",
      raised is False)

records_after_failure = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
check("B: a failed shadow evaluation does NOT append a (fabricated) log record",
      len(records_after_failure) == 2)


# --- C. the shadow local-intel store is deliberately separate from v1's real one ---

check("C: CL-AFPE shadow local-intel is configured to a v13-ONLY directory, never "
      "intelligence/local_intel.py's real state/local_confirmed_intel.json -- a shared "
      "file would let a shadow-only ML verdict actually hard-stop v1's own real "
      "Stage-1 Check 7 later, exactly what 'compute-only, never suppresses' rules out",
      live_engine._CL_AFPE_LOCAL_INTEL_DIR == local_intel_dir
      and "local_confirmed_intel" not in live_engine._CL_AFPE_LOCAL_INTEL_DIR)
check("C: the shadow engine singleton was actually constructed with a real "
      "LocalConfirmedIntel wired in (not left at the None default)",
      live_engine._get_cl_afpe_engine().local_intel is not None)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 CL-AFPE shadow-wiring checks PASSED.")
