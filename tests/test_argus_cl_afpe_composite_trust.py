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
`.venv/Scripts/python.exe tests/test_argus_cl_afpe_composite_trust.py`
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


from argus.cl_afpe import composite_trust as ct  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402

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

# BUGFIX regression (found live on .94, minutes after deploying the "3
# automated-learning gaps" fix, 2026-09-15): production's real hypotheses
# table was completely empty -- nothing had ever seeded it -- so EVERY
# record_corroborating_signal() call there failed with a caught-but-silent
# sqlite3.IntegrityError (FK violation), meaning composite-trust corroboration
# had likely never successfully written a row in production before this fix,
# for ANY caller. This test deliberately does NOT pre-seed the hypotheses
# table for UNSEEDED_HYPOTHESIS below -- proving record_corroborating_signal()
# is now self-sufficient, matching what a real production call site actually
# needs (nothing upstream reliably seeds this catalog).
UNSEEDED_HYPOTHESIS = "COORDINATED_TARGETING"
unseeded_check = store._conn.execute(
    "SELECT COUNT(*) as c FROM hypotheses WHERE hypothesis_id=?", (UNSEEDED_HYPOTHESIS,)
).fetchone()
check("setup: UNSEEDED_HYPOTHESIS genuinely has no pre-existing catalog row "
      "(proves the test below isn't accidentally passing for an unrelated reason)",
      unseeded_check["c"] == 0)
ct.record_corroborating_signal(store, DEVICE, FINGERPRINT, DEST_CLASS, UNSEEDED_HYPOTHESIS,
                                  "reputation", REGIME, now=NOW)
check("record_corroborating_signal() self-registers a missing hypothesis_id "
      "(INSERT OR IGNORE into the catalog) instead of raising a caught-but-silent "
      "sqlite3.IntegrityError -- the actual live production bug this fixes",
      store._conn.execute("SELECT COUNT(*) as c FROM hypotheses WHERE hypothesis_id=?",
                            (UNSEEDED_HYPOTHESIS,)).fetchone()["c"] == 1)
check("...and the corroboration itself was genuinely recorded, not silently dropped",
      len(ct._family_trusts(store, DEVICE, FINGERPRINT, DEST_CLASS, UNSEEDED_HYPOTHESIS, REGIME, NOW)) == 1)

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


# =============================================================================
# 2026-10-07: the pattern key is the alert kind, not the raw signature. Live, a repeating alert is re-sent as
# 'KIND (persisted 300s)', '(persisted 600s)', ...; keyed by that, every repeat was a new pattern with one
# observation (on .94: 873 ids for 10 kinds, 1 of 1,240 patterns ever permitted).
# =============================================================================
dev3 = "dev_ct_persist"
store.upsert_device(dev3, device_type="laptop", timestamp=NOW)
for i in range(5):
    sig = f"{HYPOTHESIS} (persisted {300 * (i + 1)}s)"
    ct.record_corroborating_signal(store, dev3, FINGERPRINT, DEST_CLASS, sig, "dns_behavior", REGIME, now=NOW + i)
    ct.record_corroborating_signal(store, dev3, FINGERPRINT, DEST_CLASS, sig, "reputation", REGIME, now=NOW + i)
check("persisted suffixes: five repeats with different '(persisted Ns)' suffixes build ONE pattern that is now "
      "permitted (before the fix: ten one-observation fragments, never permitted)",
      ct.permits_suppression(store, dev3, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, now=NOW + 5) is True)
check("persisted suffixes: a lookup with yet another suffix finds the same pattern",
      ct.permits_suppression(store, dev3, FINGERPRINT, DEST_CLASS, f"{HYPOTHESIS} (persisted 9999s)", REGIME,
                             now=NOW + 5) is True)
stored = {r["hypothesis_id"] for r in store._conn.execute(
    "SELECT DISTINCT hypothesis_id FROM cl_afpe_trust WHERE device_id=?", (dev3,))}
check("persisted suffixes: rows are stored under the alert kind only", stored == {HYPOTHESIS}, str(stored))

# Rows written before the fix (raw signature) are read as their alert kind: the HIGHEST trust per family, never the
# sum -- ten old one-observation fragments are worth one observation, not ten.
dev4 = "dev_ct_legacy"
store.upsert_device(dev4, device_type="laptop", timestamp=NOW)
for i in range(10):
    legacy = f"{HYPOTHESIS} (persisted {60 * (i + 1)}s)"
    store._conn.execute("INSERT OR IGNORE INTO hypotheses (hypothesis_id, kind) VALUES (?, 'attack')", (legacy,))
    for fam in ("dns_behavior", "reputation"):
        store._conn.execute(
            "INSERT INTO cl_afpe_trust (device_id, behavior_fingerprint, destination_class, hypothesis_id, "
            "evidence_family, regime_id, trust_value, n, last_updated) VALUES (?, ?, ?, ?, ?, ?, 0.15, 1, ?)",
            (dev4, FINGERPRINT, DEST_CLASS, legacy, fam, REGIME, NOW))
legacy_trusts = dict(ct._family_trusts(store, dev4, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, NOW))
check("legacy rows: read as the alert kind, highest per family (0.15), not summed (1.5)",
      legacy_trusts == {"dns_behavior": 0.15, "reputation": 0.15}, str(legacy_trusts))
check("legacy rows: ten old fragments do not permit suppression on their own",
      ct.permits_suppression(store, dev4, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, now=NOW) is False)
ct.record_corroborating_signal(store, dev4, FINGERPRINT, DEST_CLASS, f"{HYPOTHESIS} (persisted 900s)",
                               "dns_behavior", REGIME, now=NOW + 1)
new_row = store._conn.execute(
    "SELECT trust_value, n FROM cl_afpe_trust WHERE device_id=? AND hypothesis_id=? AND evidence_family='dns_behavior'",
    (dev4, HYPOTHESIS)).fetchone()
check("legacy rows: a new observation builds on the highest old value (0.15 + 0.15 = 0.30) under the alert kind",
      new_row is not None and abs(new_row["trust_value"] - 0.30) < 1e-4 and new_row["n"] == 1,
      str(dict(new_row) if new_row else None))

# The legacy match is an exact prefix, not LIKE: '_' in a kind is not a wildcard, and a longer kind sharing the
# prefix is a different kind.
for other in ("NETWORKXINTRUSION (persisted 60s)", "NETWORK_INTRUSION_WIDE (persisted 60s)"):
    store._conn.execute("INSERT OR IGNORE INTO hypotheses (hypothesis_id, kind) VALUES (?, 'attack')", (other,))
    store._conn.execute(
        "INSERT INTO cl_afpe_trust (device_id, behavior_fingerprint, destination_class, hypothesis_id, "
        "evidence_family, regime_id, trust_value, n, last_updated) VALUES (?, ?, ?, ?, 'other_family', ?, 1.0, 9, ?)",
        (dev4, FINGERPRINT, DEST_CLASS, other, REGIME, NOW))
check("legacy rows: other kinds ('NETWORKXINTRUSION', 'NETWORK_INTRUSION_WIDE') are not read as NETWORK_INTRUSION",
      "other_family" not in dict(ct._family_trusts(store, dev4, FINGERPRINT, DEST_CLASS, HYPOTHESIS, REGIME, NOW)))

summary = ct.learning_summary(store._conn, now=NOW + 5)
check("learning_summary: dev3's five suffixed repeats are one pattern, and it counts as trusted",
      summary["trusted"] >= 1, str(summary))
rows_dev3 = store._conn.execute("SELECT COUNT(*) AS c FROM cl_afpe_trust WHERE device_id=?", (dev3,)).fetchone()["c"]
check("learning_summary: one pattern per alert kind, not one per row (dev3 has 2 rows, one per family)",
      rows_dev3 == 2)

store2 = GraphStore(":memory:")
store2.upsert_device("dev_sum", device_type="laptop", timestamp=NOW)
for i in range(5):
    for fam in ("dns_behavior", "reputation"):
        ct.record_corroborating_signal(store2, "dev_sum", FINGERPRINT, DEST_CLASS,
                                       f"{HYPOTHESIS} (persisted {60 * i}s)", fam, REGIME, now=NOW + i)
    ct.record_corroborating_signal(store2, "dev_sum", FINGERPRINT, DEST_CLASS, "PORT_SCAN", "dns_behavior", REGIME,
                                   now=NOW + i)
check("learning_summary (exact): two alert kinds -> 2 patterns; only the two-family one is trusted",
      ct.learning_summary(store2._conn, now=NOW + 5) == {"patterns": 2, "trusted": 1},
      str(ct.learning_summary(store2._conn, now=NOW + 5)))
check("learning_summary: trust decays like the gate's (60 days later nothing is trusted)",
      ct.learning_summary(store2._conn, now=NOW + 60 * 86400) == {"patterns": 2, "trusted": 0})
store2.close()

removed = ct.reset_tuple(store, dev4, FINGERPRINT, DEST_CLASS, f"{HYPOTHESIS} (persisted 5s)", REGIME)
left = store._conn.execute("SELECT hypothesis_id FROM cl_afpe_trust WHERE device_id=?", (dev4,)).fetchall()
check("reset_tuple: clears the alert kind's new and legacy rows (21), and only those",
      removed == 21 and {r["hypothesis_id"] for r in left} == {"NETWORKXINTRUSION (persisted 60s)",
                                                                "NETWORK_INTRUSION_WIDE (persisted 60s)"},
      f"removed {removed}, left {[r['hypothesis_id'] for r in left]}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 CL-AFPE composite trust checks PASSED.")
