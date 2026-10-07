"""
Standalone runtime test for v13's Sheet 02 nightly backtest harness
(src/v13/ops/backtest_job.py, Release 15 closed-loop autotuning
architecture).

Covers: the golden-set subprocess check against the REAL existing
regression file (not a fake stand-in), synthetic-sweep structure and its
graceful max_devices coverage degradation, persistence to backtest_runs,
and a missing golden-set script being handled as a reported failure rather
than a crash.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_backtest_job.py`
"""
import json
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


from argus.ops import backtest_job  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from argus.autotune.engine import AutotuneEngine  # noqa: E402

NOW = 1_800_000_000.0

# =============================================================================
# run_golden_set -- against the REAL existing regression file
# =============================================================================
golden = backtest_job.run_golden_set()
check("run_golden_set: actually ran the real script (not a stub)", golden["ran"] is True)
check("run_golden_set: the real golden-incident suite currently passes -- "
      "confirms this job's zero-tolerance gate reads real signal, not a "
      "hardcoded True",
      golden["passed"] is True, f"detail={golden.get('detail', '')[:500]}")

# =============================================================================
# run_golden_set -- missing script handled gracefully
# =============================================================================
original_path = backtest_job._GOLDEN_SET_SCRIPT
backtest_job._GOLDEN_SET_SCRIPT = _PathForSysPath("/does/not/exist/regression.py")
try:
    missing_result = backtest_job.run_golden_set()
    check("run_golden_set: a missing script is reported as ran=False/passed=False, "
          "not a crash or a silent pass", missing_result == {
              "ran": False, "passed": False,
              "detail": f"golden-set script not found at {backtest_job._GOLDEN_SET_SCRIPT}",
          })
finally:
    backtest_job._GOLDEN_SET_SCRIPT = original_path

# =============================================================================
# run_synthetic_sweep -- structure and graceful coverage degradation
# =============================================================================
store = GraphStore(":memory:")
device_ids = []
for i in range(6):
    dev = f"dev_backtest_{i}"
    store.upsert_device(dev, device_type="laptop", timestamp=NOW)
    device_ids.append(dev)

full_sweep = backtest_job.run_synthetic_sweep(store, device_ids, now=NOW)
check("run_synthetic_sweep: full sweep covers every requested device",
      full_sweep["devices_covered"] == device_ids and full_sweep["coverage_fraction"] == 1.0)
check("run_synthetic_sweep: avg_detection_rate is a real, non-trivial value "
      "(the underlying injector.sweep() actually ran real attacks)",
      0.0 < full_sweep["avg_detection_rate"] <= 1.0, f"got {full_sweep['avg_detection_rate']}")

degraded_sweep = backtest_job.run_synthetic_sweep(store, device_ids, max_devices=2, now=NOW)
check("run_synthetic_sweep: max_devices reduces COVERAGE, the concrete form "
      "of 'keep improving with available items' under resource pressure",
      len(degraded_sweep["devices_covered"]) == 2 and degraded_sweep["devices_total"] == 6
      and abs(degraded_sweep["coverage_fraction"] - (2 / 6)) < 1e-9)

# =============================================================================
# run_backtest -- persistence to backtest_runs
# =============================================================================
result = backtest_job.run_backtest(store, device_ids=device_ids[:2], now=NOW)
check("run_backtest: returns a run_id and the overall_pass gate",
      "run_id" in result and isinstance(result["overall_pass"], bool))

row = store._conn.execute(
    "SELECT * FROM backtest_runs WHERE run_id=?", (result["run_id"],),
).fetchone()
check("run_backtest: a real row was persisted to backtest_runs", row is not None)
if row is not None:
    check("run_backtest: overall_pass column matches the returned summary",
          bool(row["overall_pass"]) == result["overall_pass"])
    stored_synthetic = json.loads(row["synthetic_result_json"])
    check("run_backtest: synthetic_result_json round-trips real structured data, "
          "not just a placeholder -- devices_total reflects the explicit "
          "2-device device_ids passed to run_backtest, not the full 6-device fleet",
          stored_synthetic["devices_total"] == 2 and len(stored_synthetic["devices_covered"]) == 2)
    stored_golden = json.loads(row["golden_set_result_json"])
    check("run_backtest: golden_set_result_json reflects the real subprocess run",
          stored_golden["ran"] is True)


# =============================================================================
# _hits_and_totals_by_class / _decide_scoped_change -- the safe-threshold gate
# (Documentation/PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md §3b, user-requested
# "safe threshold value for enough real data to back a promotion"). Pure unit
# tests against hand-built trial data -- no real sweep() call needed, since
# these functions only ever consume the (device_id/device_type/result) shape
# _flatten_trials() already produces, tested separately below.
# =============================================================================
def _fake_trial(device_id, device_type, detected_by_class):
    return {"device_id": device_id, "device_type": device_type,
             "result": {"attack_results": {cls: {"detected": d} for cls, d in detected_by_class.items()}}}


totals = backtest_job._hits_and_totals_by_class([
    _fake_trial("d1", "iot", {"a": True, "b": False}),
    _fake_trial("d2", "iot", {"a": True, "b": True}),
])
check("_hits_and_totals_by_class: aggregates hits/n correctly across trials",
      totals == {"a": (2, 2), "b": (1, 2)}, f"got {totals}")
check("_hits_and_totals_by_class: an empty trial list produces an empty dict, not a crash",
      backtest_job._hits_and_totals_by_class([]) == {})

_bounds = {"min": 0.5, "max": 0.99, "max_step": 0.05}
_direction = 1

# Tighten: fires on ANY miss, with NO minimum sample size -- a single trial is enough.
d1 = backtest_job._decide_scoped_change(0.80, _bounds, _direction, {"a": (0, 1)},
                                           drift_at_scope=False, scope_label="t", run_id="r", allow_loosen=True)
check("_decide_scoped_change: tightens off a SINGLE miss (n=1) -- tightening "
      "needs no sample floor, by design", d1 is not None and d1[0] < 0.80, f"got {d1}")

# Loosen blocked: below _MIN_TRIALS_FOR_LOOSENING even at a perfect raw rate.
below_floor_n = backtest_job._MIN_TRIALS_FOR_LOOSENING - 1
d2 = backtest_job._decide_scoped_change(0.80, _bounds, _direction, {"a": (below_floor_n, below_floor_n)},
                                           drift_at_scope=False, scope_label="t", run_id="r", allow_loosen=True)
check("_decide_scoped_change: refuses to loosen below _MIN_TRIALS_FOR_LOOSENING "
      "even at a perfect 100% raw rate -- the coarse pre-filter",
      d2 is None, f"got {d2}")

# Loosen blocked: enough trials, perfect raw rate, but the Wilson lower bound
# doesn't clear _TUNE_LOOSEN_WILSON_FLOOR yet (right at the coarse floor, not
# comfortably past it -- see that constant's own docstring for why 20 alone
# isn't quite enough in practice).
at_floor_n = backtest_job._MIN_TRIALS_FOR_LOOSENING
d3 = backtest_job._decide_scoped_change(0.80, _bounds, _direction, {"a": (at_floor_n, at_floor_n)},
                                           drift_at_scope=False, scope_label="t", run_id="r", allow_loosen=True)
check("_decide_scoped_change: at EXACTLY _MIN_TRIALS_FOR_LOOSENING trials, a "
      "perfect record's Wilson lower bound still doesn't clear "
      "_TUNE_LOOSEN_WILSON_FLOOR -- the real statistical gate, not just the "
      "coarse n-based pre-filter",
      d3 is None, f"got {d3}")

# Loosen succeeds: comfortably more trials, perfect rate, no drift.
comfortable_n = 40
d4 = backtest_job._decide_scoped_change(0.80, _bounds, _direction, {"a": (comfortable_n, comfortable_n)},
                                           drift_at_scope=False, scope_label="t", run_id="r", allow_loosen=True)
check("_decide_scoped_change: loosens once a comfortably large perfect-rate "
      "sample clears the Wilson floor, with no drift",
      d4 is not None and d4[0] > 0.80, f"got {d4}")

# Loosen blocked by drift even with plenty of trials at a perfect rate.
d5 = backtest_job._decide_scoped_change(0.80, _bounds, _direction, {"a": (comfortable_n, comfortable_n)},
                                           drift_at_scope=True, scope_label="t", run_id="r", allow_loosen=True)
check("_decide_scoped_change: refuses to loosen when drift is flagged for "
      "THIS scope, even with plenty of trials at a perfect rate",
      d5 is None, f"got {d5}")

# Loosen blocked: an imperfect raw rate never loosens, no matter how many trials.
d6 = backtest_job._decide_scoped_change(0.80, _bounds, _direction, {"a": (comfortable_n - 1, comfortable_n)},
                                           drift_at_scope=False, scope_label="t", run_id="r", allow_loosen=True)
check("_decide_scoped_change: an imperfect raw rate (39/40) never loosens, "
      "regardless of sample size -- _TUNE_LOOSEN_CEILING's raw-rate "
      "requirement is unchanged from the original global-only logic",
      d6 is None, f"got {d6}")

# allow_loosen=False: caller can suppress loosening entirely for a scope
# where it structurally doesn't apply, without touching the tighten path.
d7 = backtest_job._decide_scoped_change(0.80, _bounds, _direction, {"a": (comfortable_n, comfortable_n)},
                                           drift_at_scope=False, scope_label="t", run_id="r", allow_loosen=False)
check("_decide_scoped_change: allow_loosen=False suppresses loosening even "
      "when every other condition would otherwise allow it",
      d7 is None, f"got {d7}")
d8 = backtest_job._decide_scoped_change(0.80, _bounds, _direction, {"a": (0, 1)},
                                           drift_at_scope=False, scope_label="t", run_id="r", allow_loosen=False)
check("_decide_scoped_change: allow_loosen=False does NOT suppress tightening",
      d8 is not None, f"got {d8}")

check("_decide_scoped_change: no trial data at all returns None, not a crash",
      backtest_job._decide_scoped_change(0.80, _bounds, _direction, {}, False, "t", "r", True) is None)


# =============================================================================
# _scope_has_drift -- reads compute_drift_result()'s own finding shape
# =============================================================================
fake_drift = {"drift_detected": True, "findings": [
    {"parameter": "hard_stop_candidate_sensitivity", "device_id": "dev1", "device_type": None},
    {"parameter": "hard_stop_candidate_sensitivity", "device_id": None, "device_type": "iot"},
]}
check("_scope_has_drift: matches a device-scoped finding for the right device",
      backtest_job._scope_has_drift(fake_drift, "hard_stop_candidate_sensitivity", "dev1", None) is True)
check("_scope_has_drift: matches a category-scoped finding for the right category",
      backtest_job._scope_has_drift(fake_drift, "hard_stop_candidate_sensitivity", None, "iot") is True)
check("_scope_has_drift: does NOT match a DIFFERENT device just because "
      "drift_detected is True somewhere else on the network -- the real bug "
      "this closes (a global drift_detected boolean would have wrongly "
      "blocked an unrelated scope's loosening proposal)",
      backtest_job._scope_has_drift(fake_drift, "hard_stop_candidate_sensitivity", "dev2", None) is False)
check("_scope_has_drift: does NOT match a different category",
      backtest_job._scope_has_drift(fake_drift, "hard_stop_candidate_sensitivity", None, "router") is False)
check("_scope_has_drift: does NOT match the global scope when only "
      "device/category findings exist",
      backtest_job._scope_has_drift(fake_drift, "hard_stop_candidate_sensitivity", None, None) is False)


# =============================================================================
# augment_small_category_sweeps / _propose_scoped_tuning_changes -- lightweight
# real integration check (real sweep() calls, real devices, real store) --
# confirms the wiring end-to-end without asserting a specific accept/reject
# outcome (real synthetic attack detection has some run-to-run variance, same
# "loose bound, not an exact value" convention run_synthetic_sweep's own test
# above already uses for avg_detection_rate).
# =============================================================================
store_scoped = GraphStore(":memory:")
store_scoped._conn.execute(
    "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass) VALUES (?, ?, ?, ?)",
    ("bt_scoped", NOW, NOW, 1),
)
store_scoped._maybe_commit()

scoped_device_ids = []
for i in range(2):
    dev = f"dev_scoped_{i}"
    store_scoped.upsert_device(dev, device_type="smart_tv", timestamp=NOW)
    scoped_device_ids.append(dev)

scoped_synthetic = backtest_job.run_synthetic_sweep(store_scoped, scoped_device_ids, now=NOW)
scoped_drift = {"drift_detected": False, "findings": []}
device_type_of = backtest_job._device_type_lookup(store_scoped, scoped_device_ids)
check("_device_type_lookup: resolves the real device_type for every requested device",
      device_type_of == {"dev_scoped_0": "smart_tv", "dev_scoped_1": "smart_tv"}, f"got {device_type_of}")

# BUGFIX regression (found live on .94, 2026-09-21): the live pipeline never
# writes the devices.device_type COLUMN (score_metric()'s own upsert_device()
# call never passes device_type) -- it only ever lands in metadata_json via
# update_device_metadata(), the SAME landmine population_prior_builder.py's
# own _device_type_map() already hit and fixed 2026-09-16. Confirmed live: on
# .94, ALL 56 real devices had device_type=NULL in the column, which made
# devices_by_category always come back empty in augment_small_category_sweeps()
# -- the entire category/device-scoped tuning path had been silently inert.
metadata_only_dev = "dev_metadata_only"
store_scoped.upsert_device(metadata_only_dev, timestamp=NOW)  # no device_type -- column stays NULL
store_scoped.update_device_metadata(metadata_only_dev, {"device_type": "iot"}, timestamp=NOW)
column_value = store_scoped._conn.execute(
    "SELECT device_type FROM devices WHERE device_id = ?", (metadata_only_dev,)
).fetchone()["device_type"]
check("_device_type_lookup regression setup: the raw column is genuinely NULL, "
      "matching .94's real data, not just theoretically possible",
      column_value is None, f"got {column_value!r}")
metadata_only_lookup = backtest_job._device_type_lookup(store_scoped, [metadata_only_dev])
check("_device_type_lookup: resolves device_type from metadata_json when the "
      "column is NULL -- the real .94 bug this fixes",
      metadata_only_lookup == {metadata_only_dev: "iot"}, f"got {metadata_only_lookup}")

all_trials = backtest_job.augment_small_category_sweeps(store_scoped, scoped_synthetic, device_type_of, now=NOW)
check("augment_small_category_sweeps: returns at least the base pass's own "
      "trial count (2 devices) -- augmentation only ever ADDS trials",
      len(all_trials) >= 2, f"got {len(all_trials)}")
check("augment_small_category_sweeps: a 2-device category stays below "
      "_MIN_TRIALS_FOR_LOOSENING even after augmentation, capped by "
      "_MAX_SWEEP_REPETITIONS_PER_DEVICE -- the honest 'not enough devices "
      "in this category, ever' outcome, not an infinite retry loop",
      len(all_trials) <= 2 * backtest_job._MAX_SWEEP_REPETITIONS_PER_DEVICE, f"got {len(all_trials)}")
check("augment_small_category_sweeps: every trial is correctly tagged with "
      "the real category",
      all(t["device_type"] == "smart_tv" for t in all_trials))

scoped_proposals = backtest_job._propose_scoped_tuning_changes(store_scoped, all_trials, scoped_drift,
                                                                   "bt_scoped", NOW)
check("_propose_scoped_tuning_changes: runs end-to-end without crashing "
      "against real sweep data, returning a list (possibly empty -- 2 "
      "devices can't reach the loosening floor, and may not show a weak "
      "enough class to tighten on either, depending on this run's real "
      "synthetic results)",
      isinstance(scoped_proposals, list))
for p in scoped_proposals:
    has_device = bool(p.get("device_id"))
    has_category = bool(p.get("device_type"))
    check(f"_propose_scoped_tuning_changes: proposal {p.get('change_id')} is scoped "
           f"to EXACTLY one of device_id/device_type -- never both, never neither "
           f"(never a stray global proposal from this function)",
          has_device != has_category, f"got device_id={p.get('device_id')} device_type={p.get('device_type')}")


# =============================================================================
# check_retroactive_misses_and_rollback -- the retroactive circuit-breaker
# (Documentation/PER_DEVICE_CATEGORY_AUTOTUNE_PLAN.md §4, item 4;
# user-requested: "implement it and a hit should trigger an immediate
# autonomous rollback"). Real graph fixtures throughout (real evidence rows,
# real decisions rows with real raw_payload_json) -- no mocking, matching
# this file's own established convention.
# =============================================================================
CB_NOW = NOW + 500_000


def _promote_scoped_directly(store, device_id, device_type, parameter, old_value, new_value, promoted_at,
                                change_id):
    store._conn.execute(
        "INSERT INTO threshold_history (change_id, device_id, device_type, parameter, old_value, new_value, "
        "proposed_at, canary_until, promoted_at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'test setup')",
        (change_id, device_id, device_type, parameter, old_value, new_value, promoted_at, promoted_at, promoted_at),
    )
    store._maybe_commit()


def _add_suricata_evidence(store, device_id, confidence, timestamp):
    store.insert_evidence(Evidence(
        device_id=device_id, destination_id=NO_DESTINATION, evidence_type="suricata_signature_match",
        independence_family="suricata", timestamp=timestamp, source="suricata", confidence=confidence, value=1.0,
    ))


def _add_confirmed_threat_decision(store, device_id, timestamp, confirmed=True):
    store.insert_decision(
        device_id=device_id, timestamp=timestamp, state="HIGH", decision_path="hypothesis_high",
        confidence=0.85, risk_score=6.0,
        raw_payload={"fp_verdict": {"verdict": "CONFIRMED_THREAT" if confirmed else "FALSE_POSITIVE"}},
    )


# --- happy path: category-scoped loosened override, real near-miss evidence,
# real confirmed threat nearby -> rolled back ---
store_cb1 = GraphStore(":memory:")
store_cb1.upsert_device("cb_dev_a", device_type="iot", timestamp=CB_NOW)
_promote_scoped_directly(store_cb1, None, None, "hard_stop_candidate_sensitivity", 0.9, 0.70, CB_NOW - 10000, "cb1_global")
_promote_scoped_directly(store_cb1, None, "iot", "hard_stop_candidate_sensitivity", 0.70, 0.80, CB_NOW - 5000, "cb1_cat")
# confidence 0.75 sits in [0.70, 0.80) -- clears the PARENT's bar, doesn't clear this category's own
_add_suricata_evidence(store_cb1, "cb_dev_a", confidence=0.75, timestamp=CB_NOW - 100)
_add_confirmed_threat_decision(store_cb1, "cb_dev_a", timestamp=CB_NOW - 90)  # well within freshness window

rollbacks1 = backtest_job.check_retroactive_misses_and_rollback(store_cb1, now=CB_NOW)
check("check_retroactive_misses_and_rollback: rolls back a loosened category "
      "override when real near-miss evidence + a real CONFIRMED_THREAT decision "
      "line up", len(rollbacks1) == 1 and rollbacks1[0]["change_id"] == "cb1_cat", f"got {rollbacks1}")
check("check_retroactive_misses_and_rollback: the rollback takes effect "
      "IMMEDIATELY -- get_active_value() falls back to the parent tier right away",
      abs(AutotuneEngine(store_cb1).get_active_value("hard_stop_candidate_sensitivity",
                                                         device_type="iot", default=0.9) - 0.70) < 1e-9)

# --- no near-miss evidence at all -> nothing to roll back ---
store_cb2 = GraphStore(":memory:")
store_cb2.upsert_device("cb_dev_b", device_type="iot", timestamp=CB_NOW)
_promote_scoped_directly(store_cb2, None, None, "hard_stop_candidate_sensitivity", 0.9, 0.70, CB_NOW - 10000, "cb2_global")
_promote_scoped_directly(store_cb2, None, "iot", "hard_stop_candidate_sensitivity", 0.70, 0.80, CB_NOW - 5000, "cb2_cat")
rollbacks2 = backtest_job.check_retroactive_misses_and_rollback(store_cb2, now=CB_NOW)
check("check_retroactive_misses_and_rollback: no evidence in the missed band "
      "at all -- nothing rolled back", rollbacks2 == [], f"got {rollbacks2}")

# --- near-miss evidence exists, but NO confirmed-threat decision nearby ---
store_cb3 = GraphStore(":memory:")
store_cb3.upsert_device("cb_dev_c", device_type="iot", timestamp=CB_NOW)
_promote_scoped_directly(store_cb3, None, None, "hard_stop_candidate_sensitivity", 0.9, 0.70, CB_NOW - 10000, "cb3_global")
_promote_scoped_directly(store_cb3, None, "iot", "hard_stop_candidate_sensitivity", 0.70, 0.80, CB_NOW - 5000, "cb3_cat")
_add_suricata_evidence(store_cb3, "cb_dev_c", confidence=0.75, timestamp=CB_NOW - 100)
_add_confirmed_threat_decision(store_cb3, "cb_dev_c", timestamp=CB_NOW - 90, confirmed=False)  # FALSE_POSITIVE, not confirmed
rollbacks3 = backtest_job.check_retroactive_misses_and_rollback(store_cb3, now=CB_NOW)
check("check_retroactive_misses_and_rollback: near-miss evidence exists but "
      "the nearby decision was FALSE_POSITIVE, not CONFIRMED_THREAT -- nothing "
      "rolled back", rollbacks3 == [], f"got {rollbacks3}")

# --- near-miss evidence + confirmed decision, but OUTSIDE the freshness window ---
store_cb4 = GraphStore(":memory:")
store_cb4.upsert_device("cb_dev_d", device_type="iot", timestamp=CB_NOW)
_promote_scoped_directly(store_cb4, None, None, "hard_stop_candidate_sensitivity", 0.9, 0.70, CB_NOW - 10000, "cb4_global")
_promote_scoped_directly(store_cb4, None, "iot", "hard_stop_candidate_sensitivity", 0.70, 0.80, CB_NOW - 5000, "cb4_cat")
_add_suricata_evidence(store_cb4, "cb_dev_d", confidence=0.75, timestamp=CB_NOW - 100)
far_away = CB_NOW - 100 + backtest_job._HARD_STOP_FRESHNESS_SECONDS + 3600  # well past the freshness window
_add_confirmed_threat_decision(store_cb4, "cb_dev_d", timestamp=far_away)
rollbacks4 = backtest_job.check_retroactive_misses_and_rollback(store_cb4, now=CB_NOW)
check("check_retroactive_misses_and_rollback: a confirmed decision exists but "
      "well outside the hard-stop freshness window of the near-miss evidence "
      "-- not treated as related, nothing rolled back",
      rollbacks4 == [], f"got {rollbacks4}")

# --- a TIGHTENED scope is never even checked, regardless of nearby evidence ---
store_cb5 = GraphStore(":memory:")
store_cb5.upsert_device("cb_dev_e", device_type="router", timestamp=CB_NOW)
_promote_scoped_directly(store_cb5, None, None, "hard_stop_candidate_sensitivity", 0.9, 0.70, CB_NOW - 10000, "cb5_global")
_promote_scoped_directly(store_cb5, None, "router", "hard_stop_candidate_sensitivity", 0.70, 0.60, CB_NOW - 5000, "cb5_cat")  # TIGHTENED, not loosened
_add_suricata_evidence(store_cb5, "cb_dev_e", confidence=0.65, timestamp=CB_NOW - 100)
_add_confirmed_threat_decision(store_cb5, "cb_dev_e", timestamp=CB_NOW - 90)
rollbacks5 = backtest_job.check_retroactive_misses_and_rollback(store_cb5, now=CB_NOW)
check("check_retroactive_misses_and_rollback: a TIGHTENED scope (stricter than "
      "its parent) is never rolled back regardless of nearby evidence -- it "
      "can't have caused a miss, only the risky (looser) direction is checked",
      rollbacks5 == [], f"got {rollbacks5}")

# --- device-scoped (not just category-scoped) rollback also works ---
store_cb6 = GraphStore(":memory:")
store_cb6.upsert_device("cb_dev_f", device_type="phone", timestamp=CB_NOW)
_promote_scoped_directly(store_cb6, None, None, "hard_stop_candidate_sensitivity", 0.9, 0.70, CB_NOW - 10000, "cb6_global")
_promote_scoped_directly(store_cb6, "cb_dev_f", None, "hard_stop_candidate_sensitivity", 0.70, 0.80, CB_NOW - 5000, "cb6_dev")
_add_suricata_evidence(store_cb6, "cb_dev_f", confidence=0.75, timestamp=CB_NOW - 100)
_add_confirmed_threat_decision(store_cb6, "cb_dev_f", timestamp=CB_NOW - 90)
rollbacks6 = backtest_job.check_retroactive_misses_and_rollback(store_cb6, now=CB_NOW)
check("check_retroactive_misses_and_rollback: a DEVICE-scoped (not just "
      "category-scoped) loosened override is also correctly rolled back",
      len(rollbacks6) == 1 and rollbacks6[0]["change_id"] == "cb6_dev", f"got {rollbacks6}")

# =============================================================================
# check_arp_sweep_retroactive_misses_and_rollback (2026-09-21, legacy/Sheet 03a
# autotune reconciliation Phase F) -- same shape as the hard-stop check above,
# but re-bands evidence.VALUE (the raw unique-target count), not confidence.
# =============================================================================
def _add_arp_sweep_evidence(store, device_id, value, timestamp):
    store.insert_evidence(Evidence(
        device_id=device_id, destination_id=NO_DESTINATION, evidence_type="arp_sweep",
        independence_family="network_recon", timestamp=timestamp, source="threat_signals",
        confidence=0.8, value=value,
    ))


store_arp1 = GraphStore(":memory:")
store_arp1.upsert_device("arp_cb_dev_a", device_type="iot", timestamp=CB_NOW)
# global=8 (default), category raised to 16 (less sensitive -- higher threshold)
_promote_scoped_directly(store_arp1, None, "iot", "arp_sweep_unique_targets_threshold", 8.0, 16.0,
                            CB_NOW - 5000, "arp_cb1_cat")
# a real sweep of 12 unique targets: parent(8) WOULD flag it, this category's 16 does NOT
_add_arp_sweep_evidence(store_arp1, "arp_cb_dev_a", value=12.0, timestamp=CB_NOW - 100)
_add_confirmed_threat_decision(store_arp1, "arp_cb_dev_a", timestamp=CB_NOW - 90)
arp_rollbacks1 = backtest_job.check_arp_sweep_retroactive_misses_and_rollback(store_arp1, now=CB_NOW)
check("check_arp_sweep_retroactive_misses_and_rollback: rolls back a loosened "
      "category override when a real arp_sweep near-miss (by raw count, not "
      "confidence) + a real CONFIRMED_THREAT decision line up",
      len(arp_rollbacks1) == 1 and arp_rollbacks1[0]["change_id"] == "arp_cb1_cat",
      f"got {arp_rollbacks1}")

store_arp2 = GraphStore(":memory:")
store_arp2.upsert_device("arp_cb_dev_b", device_type="iot", timestamp=CB_NOW)
_promote_scoped_directly(store_arp2, None, "iot", "arp_sweep_unique_targets_threshold", 8.0, 16.0,
                            CB_NOW - 5000, "arp_cb2_cat")
# sweep count of 20 clears BOTH the parent(8) and this category's own 16 -- not a near-miss at all
_add_arp_sweep_evidence(store_arp2, "arp_cb_dev_b", value=20.0, timestamp=CB_NOW - 100)
_add_confirmed_threat_decision(store_arp2, "arp_cb_dev_b", timestamp=CB_NOW - 90)
arp_rollbacks2 = backtest_job.check_arp_sweep_retroactive_misses_and_rollback(store_arp2, now=CB_NOW)
check("check_arp_sweep_retroactive_misses_and_rollback: a count that clears "
      "this scope's OWN threshold too (not just the parent's) is not a "
      "near-miss -- nothing rolled back", arp_rollbacks2 == [], f"got {arp_rollbacks2}")

# =============================================================================
# check_fp_combined_retroactive_misses_and_rollback (Phase F) -- near-miss is a
# SUPPRESSED decision's own fp_verdict.confidence, not a separate evidence row;
# confirmation is a LATER decision for the same device reaching CONFIRMED_THREAT.
# =============================================================================
def _add_suppressed_decision(store, device_id, confidence, timestamp):
    return store.insert_decision(
        device_id=device_id, timestamp=timestamp, state="BENIGN", decision_path="fp_suppressed",
        confidence=confidence, risk_score=5.0,
        raw_payload={"fp_verdict": {"verdict": "FALSE_POSITIVE", "confidence": confidence, "suppress": True}},
    )


store_fpc1 = GraphStore(":memory:")
store_fpc1.upsert_device("fpc_dev_a", device_type="iot", timestamp=CB_NOW)
# global=0.80 (default), category LOWERED to 0.65 (less sensitive -- suppresses more)
_promote_scoped_directly(store_fpc1, None, "iot", "fp_combined_suppress_threshold", 0.80, 0.65,
                            CB_NOW - 5000, "fpc1_cat")
# suppressed at confidence=0.70: parent(0.80) would NOT suppress it, this category's 0.65 DOES
_add_suppressed_decision(store_fpc1, "fpc_dev_a", confidence=0.70, timestamp=CB_NOW - 1000)
# a LATER, separate decision for the SAME device confirms it's a real threat
_add_confirmed_threat_decision(store_fpc1, "fpc_dev_a", timestamp=CB_NOW - 100)
fpc_rollbacks1 = backtest_job.check_fp_combined_retroactive_misses_and_rollback(store_fpc1, now=CB_NOW)
check("check_fp_combined_retroactive_misses_and_rollback: rolls back a loosened "
      "category override when a real suppressed near-miss decision is later "
      "followed by a real CONFIRMED_THREAT decision for the same device",
      len(fpc_rollbacks1) == 1 and fpc_rollbacks1[0]["change_id"] == "fpc1_cat",
      f"got {fpc_rollbacks1}")

store_fpc2 = GraphStore(":memory:")
store_fpc2.upsert_device("fpc_dev_b", device_type="iot", timestamp=CB_NOW)
_promote_scoped_directly(store_fpc2, None, "iot", "fp_combined_suppress_threshold", 0.80, 0.65,
                            CB_NOW - 5000, "fpc2_cat")
_add_suppressed_decision(store_fpc2, "fpc_dev_b", confidence=0.70, timestamp=CB_NOW - 1000)
# no later confirmed-threat decision at all for this device -- must not roll back
fpc_rollbacks2 = backtest_job.check_fp_combined_retroactive_misses_and_rollback(store_fpc2, now=CB_NOW)
check("check_fp_combined_retroactive_misses_and_rollback: a suppressed "
      "near-miss with NO later confirmation for that device is never rolled back",
      fpc_rollbacks2 == [], f"got {fpc_rollbacks2}")

store_fpc3 = GraphStore(":memory:")
store_fpc3.upsert_device("fpc_dev_c", device_type="iot", timestamp=CB_NOW)
_promote_scoped_directly(store_fpc3, None, "iot", "fp_combined_suppress_threshold", 0.80, 0.65,
                            CB_NOW - 5000, "fpc3_cat")
# confidence=0.90 is ABOVE the band [0.65, 0.80) -- parent would ALSO have suppressed this one
_add_suppressed_decision(store_fpc3, "fpc_dev_c", confidence=0.90, timestamp=CB_NOW - 1000)
_add_confirmed_threat_decision(store_fpc3, "fpc_dev_c", timestamp=CB_NOW - 100)
fpc_rollbacks3 = backtest_job.check_fp_combined_retroactive_misses_and_rollback(store_fpc3, now=CB_NOW)
check("check_fp_combined_retroactive_misses_and_rollback: a suppression the "
      "PARENT tier would have made too (confidence above the band) is not a "
      "near-miss -- nothing rolled back", fpc_rollbacks3 == [], f"got {fpc_rollbacks3}")

# --- run_backtest() wiring: the circuit breaker runs and its result is surfaced ---
store_cb7 = GraphStore(":memory:")
store_cb7.upsert_device("cb_dev_g", device_type="iot", timestamp=CB_NOW)
_promote_scoped_directly(store_cb7, None, None, "hard_stop_candidate_sensitivity", 0.9, 0.70, CB_NOW - 10000, "cb7_global")
_promote_scoped_directly(store_cb7, None, "iot", "hard_stop_candidate_sensitivity", 0.70, 0.80, CB_NOW - 5000, "cb7_cat")
_add_suricata_evidence(store_cb7, "cb_dev_g", confidence=0.75, timestamp=CB_NOW - 100)
_add_confirmed_threat_decision(store_cb7, "cb_dev_g", timestamp=CB_NOW - 90)
result_cb7 = backtest_job.run_backtest(store_cb7, device_ids=["cb_dev_g"], now=CB_NOW)
check("run_backtest: surfaces circuit_breaker_rollbacks in its own return dict",
      "circuit_breaker_rollbacks" in result_cb7 and len(result_cb7["circuit_breaker_rollbacks"]) == 1,
      f"got {result_cb7.get('circuit_breaker_rollbacks')}")


# =============================================================================
# Phase 1 (2026-09-27, autonomy-completion effort): the two reputation floors'
# forward generator + retroactive circuit-breaker, and bocpd_hazard_rate's
# forward generator. See backtest_job.py's own docstrings on
# _propose_reputation_floor_changes()/_propose_bocpd_hazard_changes() for the
# evidence model each uses.
# =============================================================================
def _insert_passing_backtest_run(store, run_id, at):
    store._conn.execute(
        "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass) VALUES (?, ?, ?, ?)",
        (run_id, at, at, 1),
    )
    store._maybe_commit()


def _add_confirmed_decision_with_autotune_state(store, device_id, timestamp, autotune_state, confirmed=True):
    store.insert_decision(
        device_id=device_id, timestamp=timestamp, state="HIGH", decision_path="hypothesis_high",
        confidence=0.85, risk_score=6.0,
        raw_payload={"fp_verdict": {"verdict": "CONFIRMED_THREAT" if confirmed else "FALSE_POSITIVE"},
                       "_autotune_state": autotune_state},
    )


# --- reputation floor generator: a single confirmed miss tightens (lowers) the floor ---
store_rep1 = GraphStore(":memory:")
store_rep1.upsert_device("rep_dev_a", device_type="iot", timestamp=CB_NOW)
# vt/ti max scored 1.5, BELOW the suspicious floor (2.0) in effect at decision time --
# reputation classification missed this one, and it was later confirmed a real threat.
_add_confirmed_decision_with_autotune_state(
    store_rep1, "rep_dev_a", timestamp=CB_NOW - 100,
    autotune_state={"reputation_tier_suspicious_floor": 2.0, "reputation_vt_score": 1.5, "reputation_ti_score": 0.0},
)
_insert_passing_backtest_run(store_rep1, "rep_run_1", CB_NOW)
rep_drift1 = backtest_job.compute_drift_result(store_rep1, now=CB_NOW)
rep_proposals1 = backtest_job._propose_reputation_floor_changes(store_rep1, rep_drift1, "rep_run_1", CB_NOW)
suspicious_device_proposals1 = [p for p in rep_proposals1
                                  if p["parameter"] == "reputation_tier_suspicious_floor" and p.get("device_id") == "rep_dev_a"]
check("_propose_reputation_floor_changes: a single confirmed-malicious destination "
      "the current floor missed tightens (lowers) reputation_tier_suspicious_floor "
      "for that device, no sample floor required",
      len(suspicious_device_proposals1) == 1 and suspicious_device_proposals1[0]["accepted"]
      and suspicious_device_proposals1[0]["proposed_new_value"] < 2.0,
      f"got {suspicious_device_proposals1}")

# --- reputation floor generator: no autotune_state recorded at all -> no proposal ---
store_rep2 = GraphStore(":memory:")
store_rep2.upsert_device("rep_dev_b", device_type="iot", timestamp=CB_NOW)
_add_confirmed_threat_decision(store_rep2, "rep_dev_b", timestamp=CB_NOW - 100)  # pre-instrumentation shape
_insert_passing_backtest_run(store_rep2, "rep_run_2", CB_NOW)
rep_drift2 = backtest_job.compute_drift_result(store_rep2, now=CB_NOW)
rep_proposals2 = backtest_job._propose_reputation_floor_changes(store_rep2, rep_drift2, "rep_run_2", CB_NOW)
check("_propose_reputation_floor_changes: a decision with no recorded "
      "_autotune_state (pre-instrumentation) contributes no evidence -- no crash, "
      "no proposal from it", all(p.get("device_id") != "rep_dev_b" for p in rep_proposals2),
      f"got {rep_proposals2}")

# --- reputation floor retroactive circuit-breaker: near-miss + later confirmed threat ---
store_rep3 = GraphStore(":memory:")
store_rep3.upsert_device("rep_dev_c", device_type="iot", timestamp=CB_NOW)
# global=2.0 (default), category RAISED to 3.0 (less sensitive -- harder to classify suspicious)
_promote_scoped_directly(store_rep3, None, "iot", "reputation_tier_suspicious_floor", 2.0, 3.0,
                            CB_NOW - 5000, "rep3_cat")
# this decision's vt score (2.5) sits in [2.0, 3.0) -- parent(2.0) WOULD classify it suspicious, this category's 3.0 does NOT
_add_confirmed_decision_with_autotune_state(
    store_rep3, "rep_dev_c", timestamp=CB_NOW - 100,
    autotune_state={"reputation_tier_suspicious_floor": 3.0, "reputation_vt_score": 2.5, "reputation_ti_score": 0.0},
    confirmed=False,
)
_add_confirmed_threat_decision(store_rep3, "rep_dev_c", timestamp=CB_NOW - 90)
rep_rollbacks1 = backtest_job.check_reputation_floor_retroactive_misses_and_rollback(
    store_rep3, "reputation_tier_suspicious_floor", now=CB_NOW)
check("check_reputation_floor_retroactive_misses_and_rollback: rolls back a "
      "loosened category override when a real near-miss score + a real "
      "CONFIRMED_THREAT decision line up",
      len(rep_rollbacks1) == 1 and rep_rollbacks1[0]["change_id"] == "rep3_cat", f"got {rep_rollbacks1}")

# --- bocpd_hazard_rate generator: a confirmed incident with NO preceding regime_change tightens (raises) the hazard rate ---
store_bocpd1 = GraphStore(":memory:")
store_bocpd1.upsert_device("bocpd_dev_a", device_type="iot", timestamp=CB_NOW)
_add_confirmed_threat_decision(store_bocpd1, "bocpd_dev_a", timestamp=CB_NOW - 100)  # no regime_change BEFORE it
# 2026-10-07: a regime detector must be running on this network at all (some regime_change evidence in the window,
# here on another device, long before) -- otherwise there is no signal and no proposal (checked below).
store_bocpd1.upsert_device("bocpd_other", device_type="iot", timestamp=CB_NOW)
store_bocpd1.insert_evidence(Evidence(
    device_id="bocpd_other", destination_id=NO_DESTINATION, evidence_type="regime_change",
    independence_family="behavioral_baseline", timestamp=CB_NOW - 400000, source="baseline_engine",
    confidence=1.0, value=1.0,
))
_insert_passing_backtest_run(store_bocpd1, "bocpd_run_1", CB_NOW)
bocpd_drift1 = backtest_job.compute_drift_result(store_bocpd1, now=CB_NOW)
bocpd_proposals1 = backtest_job._propose_bocpd_hazard_changes(store_bocpd1, bocpd_drift1, "bocpd_run_1", CB_NOW)
bocpd_device_proposals1 = [p for p in bocpd_proposals1 if p.get("device_id") == "bocpd_dev_a"]
check("_propose_bocpd_hazard_changes: a confirmed incident with no preceding "
      "regime_change evidence (a missed/delayed shift) tightens (raises) "
      "bocpd_hazard_rate for that device, no sample floor required",
      len(bocpd_device_proposals1) == 1 and bocpd_device_proposals1[0]["accepted"]
      and bocpd_device_proposals1[0]["proposed_new_value"] > backtest_job._BOCPD_HAZARD_DEFAULT,
      f"got {bocpd_device_proposals1}")

# --- 2026-10-07: no regime detector producing evidence here -> no signal, no proposal at any scope ---
# (.94: BOCPD runs only on the shadow ingest host, so every confirmed incident read as a "missed shift" (0/n)
# and the hazard rate was raised every passing night.)
store_bocpd0 = GraphStore(":memory:")
store_bocpd0.upsert_device("bocpd_dev_z", device_type="iot", timestamp=CB_NOW)
for i in range(5):
    _add_confirmed_threat_decision(store_bocpd0, "bocpd_dev_z", timestamp=CB_NOW - 100 - i)
_insert_passing_backtest_run(store_bocpd0, "bocpd_run_0", CB_NOW)
bocpd_proposals0 = backtest_job._propose_bocpd_hazard_changes(
    store_bocpd0, backtest_job.compute_drift_result(store_bocpd0, now=CB_NOW), "bocpd_run_0", CB_NOW)
check("_propose_bocpd_hazard_changes: with no regime_change evidence anywhere on the network (no regime detector "
      "running) confirmed incidents are not 'missed shifts' -- no proposal at any scope",
      bocpd_proposals0 == [], f"got {bocpd_proposals0}")

# --- 2026-10-07: reputation recall counts only threats a floor in range could have caught ---
store_rep0 = GraphStore(":memory:")
store_rep0.upsert_device("rep_dev_z", device_type="iot", timestamp=CB_NOW)
for i in range(5):     # confirmed threats with reputation score 0 (DNS/behaviour findings, not reputation ones)
    _add_confirmed_decision_with_autotune_state(
        store_rep0, "rep_dev_z", timestamp=CB_NOW - 100 - i,
        autotune_state={"reputation_tier_suspicious_floor": 2.0, "reputation_tier_high_floor": 4.0,
                        "reputation_vt_score": 0.0, "reputation_ti_score": 0.0, "reputation_abuse_score": 0.0})
_insert_passing_backtest_run(store_rep0, "rep_run_0", CB_NOW)
rep_proposals0 = backtest_job._propose_reputation_floor_changes(
    store_rep0, backtest_job.compute_drift_result(store_rep0, now=CB_NOW), "rep_run_0", CB_NOW)
check("_propose_reputation_floor_changes: confirmed threats whose reputation score no floor in range could clear "
      "(score 0) are not reputation misses -- no proposal (was: lower both floors every night, 0/160 on .94)",
      rep_proposals0 == [], f"got {rep_proposals0}")
check("_reputation_recall_hits_totals: those threats are not counted at all",
      backtest_job._reputation_recall_hits_totals(store_rep0, ["rep_dev_z"], "reputation_tier_suspicious_floor",
                                                  CB_NOW - 86400) == {})

# --- bocpd_hazard_rate generator: flapping (repeated uncorroborated regime_change) blocks loosening ---
store_bocpd2 = GraphStore(":memory:")
store_bocpd2.upsert_device("bocpd_dev_b", device_type="iot", timestamp=CB_NOW)
_promote_scoped_directly(store_bocpd2, None, None, "bocpd_hazard_rate",
                            backtest_job._BOCPD_HAZARD_DEFAULT, backtest_job._BOCPD_HAZARD_DEFAULT,
                            CB_NOW - 10000, "bocpd2_global")
for i in range(backtest_job._MIN_TRIALS_FOR_LOOSENING):
    ts = CB_NOW - 1000 - i * 10
    _add_confirmed_decision_with_autotune_state(store_bocpd2, "bocpd_dev_b", timestamp=ts, autotune_state={})
    store_bocpd2.insert_evidence(Evidence(
        device_id="bocpd_dev_b", destination_id=NO_DESTINATION, evidence_type="regime_change",
        independence_family="behavioral_baseline", timestamp=ts - 5, source="baseline_engine", confidence=1.0, value=1.0,
    ))
# every one of those regime_change/CONFIRMED_THREAT pairs is a real HIT (perfect recall) --
# would ordinarily be eligible to loosen -- but ALSO fire _BOCPD_FLAP_MIN_UNCORROBORATED
# extra, uncorroborated regime_change events for the SAME device with no nearby incident at all.
for i in range(backtest_job._BOCPD_FLAP_MIN_UNCORROBORATED):
    store_bocpd2.insert_evidence(Evidence(
        device_id="bocpd_dev_b", destination_id=NO_DESTINATION, evidence_type="regime_change",
        independence_family="behavioral_baseline", timestamp=CB_NOW - 500000 - i * 10,
        source="baseline_engine", confidence=1.0, value=1.0,
    ))
bocpd_drift2 = backtest_job.compute_drift_result(store_bocpd2, now=CB_NOW)
bocpd_proposals2 = backtest_job._propose_bocpd_hazard_changes(store_bocpd2, bocpd_drift2, "bocpd_run_2", CB_NOW)
bocpd_device_proposals2 = [p for p in bocpd_proposals2 if p.get("device_id") == "bocpd_dev_b"]
check("_propose_bocpd_hazard_changes: a perfect recall record that would "
      "otherwise be eligible to loosen is BLOCKED from loosening by a real "
      "flapping signal (repeated uncorroborated regime_change events) for the "
      "same device", bocpd_device_proposals2 == [], f"got {bocpd_device_proposals2}")

# --- peer_deviation_multiplier/peer_deviation_min_absolute_count generator
# (2026-09-27, Phase 3): loosen-only, real evidence -- see
# _propose_peer_deviation_changes()'s own docstring for why only this direction. ---
store_peer1 = GraphStore(":memory:")
store_peer1.upsert_device("peer_dev_a", device_type="iot", timestamp=CB_NOW)
for i in range(backtest_job._MIN_TRIALS_FOR_LOOSENING):
    ts = CB_NOW - 1000 - i * 10
    # my_count=20, peer_avg=5 -> ratio=4.0, above the default multiplier (3.0) and
    # min_absolute_count (5.0) both -- a real firing under the CURRENT defaults.
    store_peer1.insert_evidence(Evidence(
        device_id="peer_dev_a", destination_id=NO_DESTINATION, evidence_type="peer_deviation",
        independence_family="peer_cohort_deviation", timestamp=ts, source="v13_live_engine",
        confidence=0.6, value=20.0,
        features={"device_type": "iot", "my_count": 20.0, "peer_avg": 5.0, "peer_count": 3,
                   "multiplier": 3.0, "min_absolute_count": 5.0},
    ))
    _add_confirmed_decision_with_autotune_state(store_peer1, "peer_dev_a", timestamp=ts, autotune_state={},
                                                    confirmed=False)  # FALSE_POSITIVE, not CONFIRMED_THREAT
_insert_passing_backtest_run(store_peer1, "peer_run_1", CB_NOW)
peer_proposals1 = backtest_job._propose_peer_deviation_changes(store_peer1, "peer_run_1", CB_NOW)
peer_mult_proposals1 = [p for p in peer_proposals1
                          if p["parameter"] == "peer_deviation_multiplier" and p.get("device_id") == "peer_dev_a"]
peer_count_proposals1 = [p for p in peer_proposals1
                           if p["parameter"] == "peer_deviation_min_absolute_count" and p.get("device_id") == "peer_dev_a"]
check("_propose_peer_deviation_changes: enough false-positive-confirmed firings "
      "RAISES peer_deviation_multiplier just above the highest confirmed ratio (4.0)",
      len(peer_mult_proposals1) == 1 and peer_mult_proposals1[0]["accepted"]
      and abs(peer_mult_proposals1[0]["proposed_new_value"] - (4.0 + backtest_job._PEER_DEVIATION_MULTIPLIER_SAFETY_MARGIN)) < 1e-6,
      f"got {peer_mult_proposals1}")
check("_propose_peer_deviation_changes: same evidence RAISES peer_deviation_min_absolute_count, "
      "clamped to TUNABLE_PARAMETERS' own max bound (20.0) since 20 + the safety margin would "
      "otherwise exceed it",
      len(peer_count_proposals1) == 1 and peer_count_proposals1[0]["accepted"]
      and abs(peer_count_proposals1[0]["proposed_new_value"] - 20.0) < 1e-6,
      f"got {peer_count_proposals1}")

# --- below the sample floor: no proposal at all ---
store_peer2 = GraphStore(":memory:")
store_peer2.upsert_device("peer_dev_b", device_type="iot", timestamp=CB_NOW)
for i in range(backtest_job._MIN_TRIALS_FOR_LOOSENING - 1):
    ts = CB_NOW - 1000 - i * 10
    store_peer2.insert_evidence(Evidence(
        device_id="peer_dev_b", destination_id=NO_DESTINATION, evidence_type="peer_deviation",
        independence_family="peer_cohort_deviation", timestamp=ts, source="v13_live_engine",
        confidence=0.6, value=20.0,
        features={"device_type": "iot", "my_count": 20.0, "peer_avg": 5.0, "peer_count": 3,
                   "multiplier": 3.0, "min_absolute_count": 5.0},
    ))
    _add_confirmed_decision_with_autotune_state(store_peer2, "peer_dev_b", timestamp=ts, autotune_state={},
                                                    confirmed=False)
peer_proposals2 = backtest_job._propose_peer_deviation_changes(store_peer2, "peer_run_2", CB_NOW)
check("_propose_peer_deviation_changes: below _MIN_TRIALS_FOR_LOOSENING false-positive-"
      "confirmed firings makes no proposal at all -- loosening needs proof, matching "
      "every other parameter's own asymmetry in this file",
      all(p.get("device_id") != "peer_dev_b" for p in peer_proposals2), f"got {peer_proposals2}")

# --- familiarity_trust_bar generator (2026-09-27, Phase 3): loosen-only, real
# evidence -- see _propose_familiarity_trust_bar_changes()'s own docstring. ---
store_fam1 = GraphStore(":memory:")
store_fam1.upsert_device("fam_dev_a", device_type="iot", timestamp=CB_NOW)
for i in range(backtest_job._MIN_TRIALS_FOR_LOOSENING):
    ts = CB_NOW - 1000 - i * 10
    _add_confirmed_decision_with_autotune_state(
        store_fam1, "fam_dev_a", timestamp=ts,
        autotune_state={"familiarity_trust_bar": 0.6, "baseline_familiarity": 0.5},
        confirmed=False,  # FALSE_POSITIVE
    )
_insert_passing_backtest_run(store_fam1, "fam_run_1", CB_NOW)
fam_proposals1 = backtest_job._propose_familiarity_trust_bar_changes(store_fam1, "fam_run_1", CB_NOW)
fam_device_proposals1 = [p for p in fam_proposals1 if p.get("device_id") == "fam_dev_a"]
check("_propose_familiarity_trust_bar_changes: enough false-positive-confirmed decisions "
      "with familiarity below the bar LOWERS familiarity_trust_bar just above the highest "
      "such familiarity score (0.5)",
      len(fam_device_proposals1) == 1 and fam_device_proposals1[0]["accepted"]
      and abs(fam_device_proposals1[0]["proposed_new_value"] - (0.5 + backtest_job._FAMILIARITY_SAFETY_MARGIN)) < 1e-6,
      f"got {fam_device_proposals1}")

# --- ambiguous overlap: a genuine CONFIRMED_THREAT at/below the proposed new bar blocks it ---
store_fam2 = GraphStore(":memory:")
store_fam2.upsert_device("fam_dev_b", device_type="iot", timestamp=CB_NOW)
for i in range(backtest_job._MIN_TRIALS_FOR_LOOSENING):
    ts = CB_NOW - 1000 - i * 10
    _add_confirmed_decision_with_autotune_state(
        store_fam2, "fam_dev_b", timestamp=ts,
        autotune_state={"familiarity_trust_bar": 0.6, "baseline_familiarity": 0.5},
        confirmed=False,
    )
_add_confirmed_decision_with_autotune_state(
    store_fam2, "fam_dev_b", timestamp=CB_NOW - 50,
    autotune_state={"familiarity_trust_bar": 0.6, "baseline_familiarity": 0.52},
    confirmed=True,  # a genuine CONFIRMED_THREAT scoring just above the corrected evidence
)
fam_proposals2 = backtest_job._propose_familiarity_trust_bar_changes(store_fam2, "fam_run_2", CB_NOW)
check("_propose_familiarity_trust_bar_changes: a genuine CONFIRMED_THREAT scoring at/below "
      "the proposed new bar blocks the lowering entirely -- ambiguous overlap",
      all(p.get("device_id") != "fam_dev_b" for p in fam_proposals2), f"got {fam_proposals2}")

# --- trust_cache_ttl_seconds generator (2026-09-27, Phase 4): tighten-only, real
# 'trust blindness' evidence -- see _propose_trust_cache_ttl_changes()'s own docstring. ---
store_ttl1 = GraphStore(":memory:")
store_ttl1.upsert_device("ttl_dev_a", device_type="iot", timestamp=CB_NOW)
store_ttl1.upsert_destination("ttl_dest_a", "domain", timestamp=CB_NOW - 5000)
store_ttl1.add_edge("device", "ttl_dev_a", "destination", "ttl_dest_a", "trusts",
                       timestamp=CB_NOW - 5000, metadata={"ttl_seconds": 10000.0})
# fresh attack-shaped evidence for the SAME (still-trusted) destination...
store_ttl1.insert_evidence(Evidence(
    device_id="ttl_dev_a", destination_id="ttl_dest_a", evidence_type="zeek_exfiltration",
    independence_family="network_behavior", timestamp=CB_NOW - 4000, source="zeek", confidence=0.8, value=1.0,
))
# ...and the device's own decision right around then was CONFIRMED_THREAT.
_add_confirmed_threat_decision(store_ttl1, "ttl_dev_a", timestamp=CB_NOW - 3990)
_insert_passing_backtest_run(store_ttl1, "ttl_run_1", CB_NOW)
ttl_proposals1 = backtest_job._propose_trust_cache_ttl_changes(store_ttl1, "ttl_run_1", CB_NOW)
check("_propose_trust_cache_ttl_changes: a destination still trust-cached during a "
      "real, later-confirmed incident ('trust blindness') tightens (shortens) "
      "trust_cache_ttl_seconds, no sample floor required",
      len(ttl_proposals1) == 1 and ttl_proposals1[0]["accepted"]
      and ttl_proposals1[0]["proposed_new_value"] < backtest_job._TRUST_CACHE_TTL_DEFAULT,
      f"got {ttl_proposals1}")

# --- no trust blindness at all -> no proposal ---
store_ttl2 = GraphStore(":memory:")
store_ttl2.upsert_device("ttl_dev_b", device_type="iot", timestamp=CB_NOW)
store_ttl2.upsert_destination("ttl_dest_b", "domain", timestamp=CB_NOW - 5000)
store_ttl2.add_edge("device", "ttl_dev_b", "destination", "ttl_dest_b", "trusts",
                       timestamp=CB_NOW - 5000, metadata={"ttl_seconds": 10000.0})
ttl_proposals2 = backtest_job._propose_trust_cache_ttl_changes(store_ttl2, "ttl_run_2", CB_NOW)
check("_propose_trust_cache_ttl_changes: an active trust edge with no attack-shaped "
      "evidence/confirmed incident during its window makes no proposal at all",
      ttl_proposals2 == [], f"got {ttl_proposals2}")

# --- reputation_propagation_ttl_seconds generator (2026-09-27, Phase 4): LOOSEN-
# only (shortens the TTL), gated by a sample floor -- the mirror image of
# trust_cache_ttl_seconds's own single-instance tighten above, see this
# generator's own docstring for why. ---
store_reptl1 = GraphStore(":memory:")
store_reptl1.upsert_device("reptl_dev_a", device_type="iot", timestamp=CB_NOW)
for i in range(backtest_job._MIN_TRIALS_FOR_LOOSENING):
    ts = CB_NOW - 1000 - i * 10
    store_reptl1.insert_evidence(Evidence(
        device_id="reptl_dev_a", destination_id=NO_DESTINATION, evidence_type="reputation",
        independence_family="reputation", timestamp=ts, source="v13_live_engine",
        confidence=1.0, value=5.0, provenance="v13_live_engine:reputation_propagation",
    ))
    _add_confirmed_decision_with_autotune_state(store_reptl1, "reptl_dev_a", timestamp=ts + 10,
                                                    autotune_state={}, confirmed=False)  # FALSE_POSITIVE
_insert_passing_backtest_run(store_reptl1, "reptl_run_1", CB_NOW)
reptl_proposals1 = backtest_job._propose_reputation_propagation_ttl_changes(store_reptl1, "reptl_run_1", CB_NOW)
check("_propose_reputation_propagation_ttl_changes: enough propagated-reputation-"
      "caused false positives LOOSENS (shortens) reputation_propagation_ttl_seconds",
      len(reptl_proposals1) == 1 and reptl_proposals1[0]["accepted"]
      and reptl_proposals1[0]["proposed_new_value"] < backtest_job._REPUTATION_PROPAGATION_TTL_DEFAULT,
      f"got {reptl_proposals1}")

# --- below the sample floor: no proposal at all ---
store_reptl2 = GraphStore(":memory:")
store_reptl2.upsert_device("reptl_dev_b", device_type="iot", timestamp=CB_NOW)
store_reptl2.insert_evidence(Evidence(
    device_id="reptl_dev_b", destination_id=NO_DESTINATION, evidence_type="reputation",
    independence_family="reputation", timestamp=CB_NOW - 100, source="v13_live_engine",
    confidence=1.0, value=5.0, provenance="v13_live_engine:reputation_propagation",
))
_add_confirmed_decision_with_autotune_state(store_reptl2, "reptl_dev_b", timestamp=CB_NOW - 90,
                                                autotune_state={}, confirmed=False)
reptl_proposals2 = backtest_job._propose_reputation_propagation_ttl_changes(store_reptl2, "reptl_run_2", CB_NOW)
check("_propose_reputation_propagation_ttl_changes: a single false-positive-"
      "confirmed propagation hit, below _MIN_TRIALS_FOR_LOOSENING, makes no "
      "proposal at all -- loosening needs proof",
      reptl_proposals2 == [], f"got {reptl_proposals2}")

# =============================================================================
# Phase 6 (2026-09-27, autonomy-completion effort): run_backtest()'s own
# resource-pressure wiring -- is_resource_pressure_active() itself is tested
# directly (real local HTTP server) in test_resource_pressure_modes.py; this
# confirms run_backtest() actually CONSULTS it and reacts correctly: no NEW
# candidate generation, but an ALREADY-canaried pending change still promotes.
# =============================================================================
store_pause = GraphStore(":memory:")
store_pause.upsert_device("pause_dev_a", device_type="iot", timestamp=CB_NOW)
store_pause.upsert_device("pause_dev_b", device_type="iot", timestamp=CB_NOW)
# A confirmed miss that WOULD normally tighten reputation_tier_suspicious_floor
# (see the earlier _propose_reputation_floor_changes test) -- present here to
# prove the pause actually suppresses generation, not just that nothing else
# happened to fire.
_add_confirmed_decision_with_autotune_state(
    store_pause, "pause_dev_a", timestamp=CB_NOW - 100,
    autotune_state={"reputation_tier_suspicious_floor": 2.0, "reputation_vt_score": 1.5, "reputation_ti_score": 0.0},
)
# A pre-existing, canary-elapsed, still-PENDING proposal for a DIFFERENT
# parameter/device -- must still promote even while paused (promotion is not
# "new candidate generation").
_promote_scoped_directly(store_pause, "pause_dev_b", None, "hard_stop_candidate_sensitivity",
                            0.9, 0.85, CB_NOW - 100000, "pause_pending_change")
store_pause._conn.execute(
    "UPDATE threshold_history SET canary_until=?, promoted_at=NULL WHERE change_id=?",
    (CB_NOW - 1, "pause_pending_change"),
)
store_pause._maybe_commit()

original_is_resource_pressure_active = backtest_job.is_resource_pressure_active
backtest_job.is_resource_pressure_active = lambda *a, **k: True
try:
    result_paused = backtest_job.run_backtest(store_pause, device_ids=["pause_dev_a"], now=CB_NOW)
finally:
    backtest_job.is_resource_pressure_active = original_is_resource_pressure_active

check("run_backtest: surfaces resource_paused=True in its own return dict when "
      "the live pipeline reports resource pressure",
      result_paused.get("resource_paused") is True, f"got {result_paused}")
check("run_backtest: NO new candidate generation happens while paused, even "
      "though real evidence that would otherwise tighten a parameter is present",
      result_paused["tuning_proposal"] is None and result_paused["scoped_tuning_proposals"] == [],
      f"got {result_paused}")
check("run_backtest: an ALREADY-canaried pending change still PROMOTES while "
      "paused -- promotion is not new candidate generation",
      "pause_pending_change" in result_paused["tuning_promoted"], f"got {result_paused['tuning_promoted']}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 backtest job checks PASSED.")
