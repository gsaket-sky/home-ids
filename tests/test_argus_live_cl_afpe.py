"""
Runtime test for the live false-positive engine wiring in src/argus/ops/live_engine.py.

Run directly: `python tests/test_argus_live_cl_afpe.py`

Sections:
  C. One shared threat memory: configure_cl_afpe(local_intel=...) makes the engine use the caller's
     LocalConfirmedIntel instance (pipeline.py passes its own), so a destination confirmed by any path is
     checked for every device; merge_retired_local_intel() folds the old shadow-era store in once.
  E. LocalConfirmedIntel across processes: a write by another process is seen on the next operation, and saves
     are atomic (no temp file left behind).
  F. Per-device values come from the engine's graph metadata (sigma shift, profile thresholds).
  D. evaluate_cl_afpe_live(): returns the engine's verdict; a raising engine falls back to fallback_evaluate with
     the full context; with no fallback it re-raises instead of returning a fabricated verdict.
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import argus.ops.live_engine as live_engine  # noqa: E402
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402

tmpdir = _PathForSysPath(tempfile.mkdtemp(prefix="clafpe_live_test_"))
state_dir = tmpdir / "state"
model_dir = str(tmpdir / "no_models_here")  # deliberately empty -- no ONNX/FastEmbed

live_engine.configure(str(tmpdir / "graph.db"))
shared = LocalConfirmedIntel(str(state_dir))
live_engine.configure_cl_afpe(model_dir=model_dir, local_intel=shared)

NOW = 1_000_000.0
_store = live_engine.get_graph_store()
_store.upsert_device("pipeline_dev", timestamp=NOW)


def _alert(device_id="pipeline_dev", signature="NETWORK_INTRUSION", domain="", dest_ip="", features=None):
    return {
        "signature": signature,
        "device": {"id": device_id, "hostname": "pipeline-host"},
        "network_context": {"queried_domain": domain, "destination_ip": dest_ip},
        "features": features or {},
    }


# --- C. one shared threat memory ---
engine = live_engine._get_cl_afpe_engine()
check("C: the engine uses the injected LocalConfirmedIntel instance (one store, not a private copy)",
      engine.local_intel is shared)
shared.record("domain", "evil-example.test", "dev_a", reason="test")
check("C: an indicator recorded through the shared store is visible to the engine's own check",
      engine.local_intel.check("domain", "evil-example.test") is not None)

old_dir = state_dir / "v13_cl_afpe"
old_dir.mkdir(parents=True)
(old_dir / "local_confirmed_intel.json").write_text(json.dumps({
    "ip": {"203.0.113.9": {"first_confirmed": time.time(), "last_confirmed": time.time(), "count": 2,
                           "sources": ["dev_b"], "reason": "shadow-era", "ttl_seconds": 86400.0}},
    "domain": {}}), encoding="utf-8")
merged = live_engine.merge_retired_local_intel(shared, state_dir)
check("C: the retired shadow-era store is merged into the shared one", merged == 1 and shared.check("ip", "203.0.113.9"))
check("C: the retired file is renamed so it is merged only once",
      not (old_dir / "local_confirmed_intel.json").exists() and (old_dir / "local_confirmed_intel.json.merged").exists())
check("C: a second merge is a no-op", live_engine.merge_retired_local_intel(shared, state_dir) == 0)

# --- E. across processes: re-read on change, atomic saves ---
other_process = LocalConfirmedIntel(str(state_dir))      # e.g. the scheduler's retro-hunt
time.sleep(0.02)
other_process.record("domain", "found-by-retro-hunt.test", "dev_c", reason="retro")
check("E: a write by another process is seen by this one on its next check",
      shared.check("domain", "found-by-retro-hunt.test") is not None)
shared.record("domain", "second.test", "dev_a")
data = json.loads((state_dir / "local_confirmed_intel.json").read_text(encoding="utf-8"))
check("E: this process's next save keeps the other process's entry (no lost update)",
      "found-by-retro-hunt.test" in data["domain"] and "second.test" in data["domain"])
check("E: saves are atomic -- no temp file left behind",
      not list(state_dir.glob("local_confirmed_intel.json.*tmp")))

# --- F. per-device values from the engine's graph metadata ---
engine._apply_sigma_shift("pipeline_dev", direction="TUNE_UP", now=NOW + 1)
check("F: get_device_sigma_shift() reads the engine's own value", live_engine.get_device_sigma_shift("pipeline_dev") == -0.5)
check("F: no profile entry -> None (the caller falls back)",
      live_engine.get_device_profile_threshold("pipeline_dev", "conn_abuse_unique_ip_threshold", 5.0) is None)
engine.apply_device_fp_profile("pipeline_dev", "conn_abuse_unique_ip_threshold", 9.0, 5.0, "test", "raised", now=NOW + 2)
check("F: a profile entry the engine wrote is returned",
      live_engine.get_device_profile_threshold("pipeline_dev", "conn_abuse_unique_ip_threshold", 5.0) == 9.0)


class _ExplodingEngine:
    def evaluate(self, *a, **kw):
        raise RuntimeError("simulated CL-AFPE failure")


_real_get_engine = live_engine._get_cl_afpe_engine

# --- D. evaluate_cl_afpe_live() (Workstream 2 live-flip adapter) ---

alert_d = _alert(device_id="pipeline_dev", features={"zeek_honeypot_hits": 1})
live_result = live_engine.evaluate_cl_afpe_live(
    alert_payload=alert_d, features=alert_d["features"],
    decision={"state": "CRITICAL", "explanation": "Internal Honeypot Accessed"},
    now=NOW + 10,
)
check("D: evaluate_cl_afpe_live() returns v13's OWN real computed verdict directly "
      "(this IS the real suppression decision once flipped, not a comparison)",
      live_result.get("verdict") == "CONFIRMED_THREAT" and live_result.get("stage") == "STAGE_1_HARD_STOP")
check("D: the returned shape matches AutonomousFPEngine.evaluate()'s real shape exactly "
      "(verdict/confidence/calibrated_confidence/stage/reasons/suppress) -- a genuine "
      "drop-in replacement, not an approximation pipeline.py would need adapting for",
      set(live_result.keys()) >= {"verdict", "confidence", "calibrated_confidence", "stage", "reasons", "suppress"})

# Fail-safe: a raising CL-AFPE engine falls back to fallback_evaluate, with the exact
# params a real AutonomousFPEngine.evaluate() call needs (risk_score/ti_engine included,
# even though ClAfpeEngine.evaluate() itself never uses them -- they only matter for
# the fallback call pipeline.py's real fp_engine.evaluate() would need).
fallback_calls = []


def _fake_fallback(alert_payload, features, risk_score, ti_engine, decision, asn_owner):
    fallback_calls.append({
        "alert_payload": alert_payload, "features": features, "risk_score": risk_score,
        "ti_engine": ti_engine, "decision": decision, "asn_owner": asn_owner,
    })
    return {"verdict": "UNCERTAIN", "confidence": 0.5, "calibrated_confidence": None,
            "stage": "FALLBACK", "reasons": ["v13 raised, fell back to v1"], "suppress": False}


live_engine._get_cl_afpe_engine = lambda: _ExplodingEngine()
try:
    fallback_result = live_engine.evaluate_cl_afpe_live(
        alert_payload=alert_d, features=alert_d["features"], risk_score=7.5,
        ti_engine="sentinel_ti_engine", decision={"state": "CRITICAL"}, asn_owner="Google LLC",
        fallback_evaluate=_fake_fallback, now=NOW + 11,
    )
finally:
    live_engine._get_cl_afpe_engine = _real_get_engine

check("D: a raising CL-AFPE engine falls back to fallback_evaluate() instead of "
      "propagating -- pipeline.py's real alert publish must never crash because v13's "
      "CL-AFPE had a bug, exactly the same safety property the main decision-engine "
      "adapter (evaluate()) already has",
      len(fallback_calls) == 1 and fallback_result.get("stage") == "FALLBACK")
check("D: the fallback call received the REAL risk_score/ti_engine/asn_owner this cycle "
      "had -- a fallback that silently dropped them would call v1's real fp_engine.evaluate() "
      "with wrong context",
      fallback_calls[0]["risk_score"] == 7.5
      and fallback_calls[0]["ti_engine"] == "sentinel_ti_engine"
      and fallback_calls[0]["asn_owner"] == "Google LLC")

# No fallback provided -- must re-raise, never silently return None/{} that pipeline.py
# could mistake for a real (falsy-suppress) verdict.
live_engine._get_cl_afpe_engine = lambda: _ExplodingEngine()
raised_no_fallback = False
try:
    live_engine.evaluate_cl_afpe_live(
        alert_payload=alert_d, features=alert_d["features"], now=NOW + 12,
    )
except RuntimeError:
    raised_no_fallback = True
finally:
    live_engine._get_cl_afpe_engine = _real_get_engine

check("D: REGRESSION GUARD -- with no fallback_evaluate supplied, a raising engine "
      "re-raises rather than returning a fabricated verdict pipeline.py could act on "
      "by mistake",
      raised_no_fallback is True)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All live CL-AFPE wiring checks PASSED.")
