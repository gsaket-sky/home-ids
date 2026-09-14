"""
Standalone runtime test for v13's CL-AFPE composite trust key
(src/v13/cl_afpe/composite_trust.py, Release 15 Sheet 03b).

Covers the actual claim this module exists to make good on: a single
evidence family repeatedly corroborating the same tuple must NEVER alone
permit suppression (the anti-gaming fix for the classic FP-engine poisoning
move), while genuine cross-family corroboration does; incident/probation
ineligibility is a real no-op; trust decays over time; a regime change
doesn't silently inherit old trust; and operator reset actually clears
state.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_cl_afpe_composite_trust.py`
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


from v13.cl_afpe import composite_trust as ct  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402

NOW = 1_800_000_000.0
DEVICE = "dev_ct"
FINGERPRINT = "NORMAL:low_surprise"
DEST_CLASS = "cdn"
HYPOTHESIS = "NETWORK_INTRUSION"
REGIME = 0

store = GraphStore(":memory:")
store.upsert_device(DEVICE, device_type="laptop", timestamp=NOW)
# cl_afpe_trust.hypothesis_id is a real FK against the hypotheses catalog
# table (schema.sql) -- a small, mostly-static catalog, seeded once here the
# same way the schema itself seeds the '(none)' destination sentinel.
store._conn.execute("INSERT INTO hypotheses (hypothesis_id, kind) VALUES (?, 'attack')", (HYPOTHESIS,))
store._conn.commit()

# =============================================================================
# The core anti-gaming claim: ONE family repeatedly corroborating never
# permits suppression, no matter how many times it fires.
# =============================================================================
check("permits_suppression: false with no corroboration at all",
      ct.permits_suppression(store, DEVICE, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, now=NOW) is False)

for i in range(20):
    ct.record_corroborating_signal(store, DEVICE, FINGERPRINT, DEST_CLASS, HYPOTHESIS,
                                      "dns_behavior", REGIME, now=NOW + i)
check("permits_suppression: STILL false after 20 repeated corroborations "
      "from a SINGLE evidence family -- the actual anti-gaming fix, not "
      "just a documented intention",
      ct.permits_suppression(store, DEVICE, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, now=NOW + 20) is False)

row = store._conn.execute(
    "SELECT trust_value FROM cl_afpe_trust WHERE device_id=? AND evidence_family='dns_behavior'", (DEVICE,),
).fetchone()
check("record_corroborating_signal: the single family's OWN trust_value did "
      "rise toward the ceiling (proving the gate failure above is about "
      "cross-family diversity, not simply 'nothing was recorded')",
      row is not None and row["trust_value"] >= 0.9, f"got {row['trust_value'] if row else None}")

# =============================================================================
# Genuine cross-family corroboration DOES permit suppression
# =============================================================================
for i in range(5):
    ct.record_corroborating_signal(store, DEVICE, FINGERPRINT, DEST_CLASS, HYPOTHESIS,
                                      "reputation", REGIME, now=NOW + 100 + i)
check("permits_suppression: true once a SECOND, distinct evidence family "
      "has also independently corroborated the same tuple",
      ct.permits_suppression(store, DEVICE, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, now=NOW + 106) is True)

# =============================================================================
# eligible_to_contribute=False is a real no-op
# =============================================================================
before_row = store._conn.execute(
    "SELECT n FROM cl_afpe_trust WHERE device_id=? AND evidence_family='dns_behavior'", (DEVICE,),
).fetchone()
ct.record_corroborating_signal(store, DEVICE, FINGERPRINT, DEST_CLASS, HYPOTHESIS, "dns_behavior", REGIME,
                                  eligible_to_contribute=False, now=NOW + 200)
after_row = store._conn.execute(
    "SELECT n FROM cl_afpe_trust WHERE device_id=? AND evidence_family='dns_behavior'", (DEVICE,),
).fetchone()
check("record_corroborating_signal: eligible_to_contribute=False is a real "
      "no-op -- n does not increment (the incident/probation exclusion)",
      before_row["n"] == after_row["n"])

# =============================================================================
# Decay: trust erodes over time if not reinforced
# =============================================================================
device2 = "dev_ct_decay"
store.upsert_device(device2, device_type="laptop", timestamp=NOW)
# Trust growth is bounded-step (_TRUST_INCREMENT per observation), by design
# -- crossing _SUPPRESSION_TRUST_FLOOR takes several observations per
# family, not one, the same discipline as the autotuner's bounded steps.
for i in range(5):
    ct.record_corroborating_signal(store, device2, FINGERPRINT, DEST_CLASS, HYPOTHESIS, "dns_behavior", REGIME,
                                      now=NOW + i)
    ct.record_corroborating_signal(store, device2, FINGERPRINT, DEST_CLASS, HYPOTHESIS, "reputation", REGIME,
                                      now=NOW + i)
check("permits_suppression: true immediately after two-family corroboration "
      "(each family reinforced enough times to cross the trust floor)",
      ct.permits_suppression(store, device2, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, now=NOW + 5) is True)
far_future = NOW + 60 * 86400.0  # 60 days of no reinforcement
check("permits_suppression: decays back to false after a long enough gap "
      "with no reinforcement -- trust is not permanent from one confirmation",
      ct.permits_suppression(store, device2, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, now=far_future) is False)

# =============================================================================
# Regime change: old trust doesn't silently apply to a new regime
# =============================================================================
check("permits_suppression: trust earned under regime_id=0 does not apply "
      "to a lookup for regime_id=1 -- old-regime trust doesn't silently "
      "outlive the context it was earned in",
      ct.permits_suppression(store, DEVICE, FINGERPRINT, DEST_CLASS, HYPOTHESIS, regime_id=1, now=NOW + 106) is False)

# =============================================================================
# Operator reset actually clears state
# =============================================================================
removed = ct.reset_tuple(store, DEVICE, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME)
check("reset_tuple: removes real rows", removed >= 2, f"got {removed}")
check("permits_suppression: false immediately after reset",
      ct.permits_suppression(store, DEVICE, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, now=NOW + 200) is False)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 CL-AFPE composite trust checks PASSED.")
