"""
Standalone runtime test for v13's synthetic anomaly injection framework
(src/v13/synthetic/attacks.py + injector.py, Release 15 Sheet 01).

Covers: isolation from the live/source store (nothing written back), real
detection of each attack class through the actual DecisionEngine, benign
drift correctly NOT firing, signature diversity across repeated calls to the
same generator, and clone_device_state pulling in real prior evidence so
synthetic injection has realistic context to score against.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_synthetic_injection.py`
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


from v13.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402
from v13.synthetic.attacks import ATTACK_GENERATORS, benign_drift  # noqa: E402
from v13.synthetic import injector  # noqa: E402

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
