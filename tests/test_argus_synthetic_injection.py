"""
Standalone runtime test for v13's synthetic anomaly injection framework
(src/v13/synthetic/attacks.py + injector.py, Release 15 Sheet 01).

Covers: isolation from the live/source store (nothing written back), real
detection of each attack class through the actual DecisionEngine, benign
drift correctly NOT firing, signature diversity across repeated calls to the
same generator, and clone_device_state pulling in real prior evidence so
synthetic injection has realistic context to score against.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_synthetic_injection.py`
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


from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.synthetic.attacks import ATTACK_GENERATORS, benign_drift  # noqa: E402
from argus.synthetic import injector  # noqa: E402

NOW = 1_800_000_000.0

# =============================================================================
# Isolation: the source store is never written to
# =============================================================================
source = GraphStore(":memory:")
device = "dev_synthetic_target"
source.upsert_device(device, device_type="laptop", timestamp=NOW)

before_evidence_count = len(source.get_evidence_for_device(device))
before_device_count = len(source._conn.execute("SELECT device_id FROM devices").fetchall())

result = injector.inject_and_evaluate(source, device, "port_scan", now=NOW)

after_evidence_count = len(source.get_evidence_for_device(device))
after_device_count = len(source._conn.execute("SELECT device_id FROM devices").fetchall())
check("inject_and_evaluate: the SOURCE store's evidence count is completely "
      "unchanged after injection -- the isolation boundary the plan requires",
      before_evidence_count == after_evidence_count,
      f"before={before_evidence_count} after={after_evidence_count}")
check("inject_and_evaluate: the SOURCE store's device count is unchanged too",
      before_device_count == after_device_count)

# =============================================================================
# Each real attack class is detectable through the real DecisionEngine
# =============================================================================
detected_classes = []
for cls in sorted(ATTACK_GENERATORS):
    r = injector.inject_and_evaluate(source, device, cls, intensity="high", now=NOW + 100)
    if r["detected"]:
        detected_classes.append(cls)
    check(f"inject_and_evaluate[{cls}]: returns a well-formed result dict",
          r["state"] in ("BENIGN", "ANOMALOUS", "SUSPICIOUS", "HIGH", "CRITICAL")
          and isinstance(r["synthetic_evidence_types"], list) and len(r["synthetic_evidence_types"]) > 0)

check("inject_and_evaluate: a real majority of the 7 attack classes are "
      "actually detectable (SUSPICIOUS+) through the real DecisionEngine at "
      "high intensity -- the synthetic evidence is genuinely attack-shaped, "
      "not inert",
      len(detected_classes) >= 4, f"detected={detected_classes}")

# 2026-10-07: the honeypot hard stop reads features["zeek_honeypot_hits"] (the live pipeline's count), not the
# evidence store. The sweep used to pass no features, so this class scored 0-10 % every night on .94 and drove a
# tighten-only autotune proposal no parameter could satisfy.
hp = injector.inject_and_evaluate(source, device, "honeypot_touch", intensity="high", now=NOW + 150)
check("inject_and_evaluate[honeypot_touch]: detected through the real hard stop, given the feature the live "
      "pipeline derives from the same touch", hp["detected"] and hp["decision_path"] == "hard_stop",
      f"got state={hp['state']} path={hp['decision_path']}")
check("inject_and_evaluate: every one of the 7 attack classes is detectable at high intensity",
      sorted(detected_classes) == sorted(ATTACK_GENERATORS), f"detected={detected_classes}")

# =============================================================================
# Unknown attack class raises, doesn't silently no-op
# =============================================================================
raised = False
try:
    injector.inject_and_evaluate(source, device, "not_a_real_attack_class", now=NOW)
except ValueError:
    raised = True
check("inject_and_evaluate: an unknown attack_class raises ValueError, "
      "never silently returns a fake/empty result", raised)

# =============================================================================
# Benign drift does NOT false-positive
# =============================================================================
drift_result = injector.inject_benign_drift_and_evaluate(source, device, now=NOW + 200)
check("inject_benign_drift_and_evaluate: purely benign synthetic drift does "
      "NOT reach a detected state -- the false-positive-resistance side of "
      "the synthetic sweep",
      drift_result["false_positive"] is False, f"got state={drift_result['state']}")

# =============================================================================
# BUGFIX (2026-09-20, found on .94: this check had never once passed in 5
# nights, blocking Sheet 03a's autotuner gate entirely): a device that's
# ALREADY non-BENIGN from its own real evidence must NOT be counted as a
# false positive just because it's still non-BENIGN after ALSO adding the
# synthetic benign evidence -- only a NEW escalation the synthetic evidence
# itself caused counts.
# =============================================================================
already_suspicious_source = GraphStore(":memory:")
already_suspicious_device = "dev_already_suspicious"
already_suspicious_source.upsert_device(already_suspicious_device, device_type="laptop", timestamp=NOW)
# A real dns_tunnel_v2 hit, exactly like a live device with a single
# dns_behavior-family finding (matches test_real_world_alert_regression.py's
# own DNS_COVERT_TUNNELING case: stays SUSPICIOUS on ONE such finding).
already_suspicious_source.insert_evidence(Evidence(
    device_id=already_suspicious_device, destination_id="evil-tunnel.example.com",
    evidence_type="dns_tunnel_v2", independence_family="dns_behavior",
    timestamp=NOW, source="dns_features", confidence=0.9,
))
already_suspicious_drift = injector.inject_benign_drift_and_evaluate(
    already_suspicious_source, already_suspicious_device, now=NOW + 200)
check("THE FIX: a device already SUSPICIOUS from its own real evidence is "
      "NOT flagged as a false positive just because adding benign synthetic "
      "drift doesn't magically clear that pre-existing state",
      already_suspicious_drift["false_positive"] is False,
      f"got {already_suspicious_drift}")
check("THE FIX: the result still honestly reports the device's real "
      "(non-BENIGN) state, it just doesn't count that against the "
      "false-positive-resistance check",
      already_suspicious_drift["state"] != "BENIGN")
check("THE FIX: baseline_state is reported and matches the pre-synthetic "
      "real state",
      already_suspicious_drift.get("baseline_state") == already_suspicious_drift["state"])


class _FlipOnFirstContactDecisionEngine:
    """Stub proving the fix still catches a REAL false positive -- a
    synthetic addition that genuinely FLIPS a device from BENIGN to
    non-BENIGN must still be caught, not silently waved through by the
    baseline comparison."""
    def evaluate(self, evidence_list, rep, now=None):
        has_first_contact = any(e.evidence_type == "first_contact" for e in evidence_list)
        state = "SUSPICIOUS" if has_first_contact else "BENIGN"
        return {"state": state, "decision_path": "test_stub"}


flip_source = GraphStore(":memory:")
flip_device = "dev_genuinely_flipped"
flip_source.upsert_device(flip_device, device_type="laptop", timestamp=NOW)
flip_result = injector.inject_benign_drift_and_evaluate(
    flip_source, flip_device, now=NOW + 200, decision_engine=_FlipOnFirstContactDecisionEngine())
check("REGRESSION GUARD: a synthetic addition that GENUINELY flips a device "
      "from BENIGN to non-BENIGN is still correctly caught as a false "
      "positive -- the fix narrows the check, it doesn't disable it",
      flip_result["false_positive"] is True, f"got {flip_result}")
check("REGRESSION GUARD: the baseline state for the genuinely-flipped case "
      "is BENIGN (confirming the flip really was caused by the synthetic "
      "evidence, not already present)",
      flip_result.get("baseline_state") == "BENIGN")

# =============================================================================
# Signature diversity: repeated calls to the same generator vary
# =============================================================================
samples = [tuple(ev.value for ev in ATTACK_GENERATORS["exfiltration"](device, now=NOW)) for _ in range(15)]
check("attacks.exfiltration: repeated calls produce varying magnitudes, not "
      "one fixed canned value -- the signature-diversity fix against an "
      "autotuner overfitting to a single synthetic shape",
      len(set(samples)) > 1, f"got {len(set(samples))} distinct value(s) across 15 calls")

dga_variants = {tuple(ev.evidence_type for ev in ATTACK_GENERATORS["dga_dns_tunnel"](device, now=NOW))
                 for _ in range(20)}
check("attacks.dga_dns_tunnel: both the nxdomain-heavy and resolved-tunnel "
      "real-world shapes appear across repeated calls, not just one",
      len(dga_variants) > 1, f"got variants={dga_variants}")

# =============================================================================
# clone_device_state pulls in real prior evidence for realistic context
# =============================================================================
device2 = "dev_with_history"
source.upsert_device(device2, device_type="iot", timestamp=NOW - 1000)
source.insert_evidence(Evidence(
    device_id=device2, destination_id="9.9.9.9", evidence_type="reputation",
    independence_family="reputation", timestamp=NOW - 500, source="test", confidence=0.5, value=2.0,
))
clone = injector.clone_device_state(source, device2, now=NOW)
try:
    cloned_evidence = clone.get_evidence_for_device(device2)
    check("clone_device_state: real prior evidence from the source store is "
          "present in the isolated clone (realistic context for scoring)",
          any(e.evidence_type == "reputation" for e in cloned_evidence))
finally:
    clone.close()


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 synthetic injection checks PASSED.")
