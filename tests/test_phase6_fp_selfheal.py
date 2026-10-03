"""
Standalone runtime test for Phase 6 Part 2 (FP self-healing improvements). Not part of
the pytest suite — run directly: `python3 test_phase6_fp_selfheal.py`. Exercises the
real AutonomousFPEngine, StateManager action ledger, and train_fp_classifier.py dataset
loader end-to-end, no mocks except a targeted monkeypatch of _stage2_lgbm (needed to
deterministically force the low-P(FP) branch that used to early-return, since the
shipped LightGBM model is a freshly-generated untrained placeholder with no way to
otherwise control its output).

Covers:
  1. The Stage 2 early-return bug fix: a low LightGBM P(FP) no longer skips Stage 3.
  2. AutonomousFPEngine.mark_false_positive() — the operator-feedback closed loop.
  3. StateManager.record_action()'s new `extra` field round-trips through get_action().
  4. train_fp_classifier.py's load_dataset() no longer mislabels corrected FPs as threats.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time
import json
import tempfile
from pathlib import Path

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.state_guard import StateManager
from argus.graph.store import GraphStore
from argus.cl_afpe.engine import ClAfpeEngine

# Section A (a low Stage-2 score must still reach Stage 3) is structural in the live CL-AFPE: evaluate() always
# combines both stages (combine_scores, covered in test_argus_cl_afpe_ml_scoring.py).

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: mark_false_positive() — operator-feedback closed loop (live CL-AFPE)
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    graph_store = GraphStore(str(Path(tmpdir) / "graph.db"))
    fp = ClAfpeEngine(graph_store)
    device_id = "dev_operator_1"
    hostname = "laptop-gs"
    domain = "sub.operator-corrected-example.com"
    alert_ts = time.time()
    alert_payload = {
        "signature": "DGA_BOTNET_C2",
        "device": {"id": device_id, "hostname": hostname},
        "network_context": {"queried_domain": domain, "destination_ip": "5.6.7.8"},
        "timestamp": alert_ts,
        "risk": 7.2,
    }
    # A real pipeline cycle always writes the alert's decision row first; the correction is attached to it.
    graph_decision_id = graph_store.insert_decision(device_id, alert_ts, "HIGH", "hypothesis_high", 0.72, 7.2)
    result = fp.mark_false_positive(alert_payload, source="operator")
    check("mark_false_positive() immunizes the eTLD+1 base domain",
          not result.refused and result.immunized_destination == "operator-corrected-example.com", f"got={result}")
    check("the base domain is in the dynamic trust cache the evaluate() fast path uses",
          "operator-corrected-example.com" in fp.get_dynamic_trust_cache())
    check("mark_false_positive() widens this device's sensitivity shift (fewer false alarms from its baseline)",
          fp.get_sigma_shift(device_id) > 0.0, f"sigma={fp.get_sigma_shift(device_id)}")
    decision_row = graph_store._conn.execute(
        "SELECT raw_payload_json FROM decisions WHERE decision_id=?", (graph_decision_id,)).fetchone()
    fp_suppression_log = json.loads(decision_row["raw_payload_json"] or "{}").get("fp_suppression_log") if decision_row else None
    check("the correction is written as a training record on the alert's decision row "
          "(decisions.raw_payload_json.fp_suppression_log -- what the nightly retrain learns from)",
          fp_suppression_log is not None)
    if fp_suppression_log is not None:
        check("the record is tagged OPERATOR_MARKED_FALSE_POSITIVE with confidence 1.0",
              fp_suppression_log.get("type") == "OPERATOR_MARKED_FALSE_POSITIVE"
              and fp_suppression_log.get("confidence") == 1.0, f"entry={fp_suppression_log}")
        check("the record preserves the full original alert for feature extraction",
              fp_suppression_log.get("original_alert", {}).get("device", {}).get("id") == device_id)

    # No decision row for this alert: still succeeds, the missing training record is only a logged warning.
    graph_store.upsert_device("dev_no_graph_row_yet", timestamp=time.time())
    no_row_alert = {"signature": "DGA_BOTNET_C2", "device": {"id": "dev_no_graph_row_yet", "hostname": "orphan-host"},
                    "network_context": {"queried_domain": "orphan-example.com", "destination_ip": "1.2.3.4"},
                    "timestamp": time.time() - 3600, "risk": 6.5}
    result_no_row = fp.mark_false_positive(no_row_alert, source="operator")
    check("with no matching decision row the correction still applies (immunizes) instead of crashing",
          not result_no_row.refused and result_no_row.immunized_destination == "orphan-example.com", f"got={result_no_row}")

    graph_store.upsert_device("dev_bad_domain", timestamp=time.time())
    bad_alert = {"signature": "DGA_BOTNET_C2", "device": {"id": "dev_bad_domain", "hostname": "host2"},
                 "network_context": {"queried_domain": "", "destination_ip": "9.9.9.9"}, "timestamp": time.time()}
    result_bad = fp.mark_false_positive(bad_alert, source="operator")
    check("an alert with no usable domain degrades gracefully (no crash; no domain immunized)",
          not result_bad.refused and result_bad.immunized_destination != "", f"got={result_bad}")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: StateManager.record_action()'s new `extra` field
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    sm = StateManager(state_path=str(Path(tmpdir) / "state.json"))
    sample_alert_payload = {"device": {"id": "dev_x"}, "network_context": {"queried_domain": "foo.example.com"}}
    sm.record_action(
        action_id="act123", action_type="published_alert", target="foo.example.com",
        device_id="dev_x", hostname="host_x", ttl_seconds=3600.0,
        extra={"alert_payload": sample_alert_payload},
    )
    fetched = sm.get_action("act123")
    check("record_action()'s new `extra` field round-trips through get_action() intact "
          "(this is how the 'Mark False Positive' IPC handler retrieves the full alert "
          "payload from just a short action_id passed through Telegram)",
          fetched is not None and fetched.get("extra", {}).get("alert_payload") == sample_alert_payload,
          f"got={fetched}")

    # record_action() called WITHOUT extra (existing callers, e.g. immunize_domain
    # autonomous actions) must not break — defaults to an empty dict, not a missing key.
    sm.record_action(action_id="act456", action_type="immunize_domain", target="bar.example.com",
                      device_id="dev_y", hostname="host_y", ttl_seconds=3600.0)
    fetched2 = sm.get_action("act456")
    check("record_action() without `extra` (existing call sites, unchanged) still produces "
          "a valid entry with extra={} rather than a missing/None field",
          fetched2 is not None and fetched2.get("extra") == {}, f"got={fetched2}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: train_fp_classifier.py load_dataset() — mislabeling fix
# ═══════════════════════════════════════════════════════════════════════════════════
import scripts.train_fp_classifier as train_mod

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    state_dir = Path(tmpdir)
    # Bypass the configured-alert-path lookup (which prefers the real repo's
    # state/alerts.json ahead of state_dir's) so this test is fully isolated.
    train_mod._resolve_alert_input_paths = lambda sd: [sd / "alerts.json"]

    now = time.time()
    genuine_threat = {
        "device": {"id": "dev1", "type": "iot"}, "timestamp": now,
        "network_context": {"queried_domain": "totally-random-dga-abc123.biz"},
        "features": {"tranco_rank": 0, "max_label_length": 40, "outbound_bytes_z": 6.0,
                     "zeek_lateral_moves": 0, "zeek_s0_rej_count": 0, "zeek_app_protocol_weight": 0.4},
        "reasons": [],
    }
    # This alert was ALREADY autonomously suppressed as a FALSE_POSITIVE the same cycle it
    # was written (alert_payload["suppressed"]=True, set by pipeline.py) — must NOT be
    # trained as label=0 alongside its label=1 entry below.
    autonomous_fp_ts = now + 1
    autonomous_fp_alert = {
        "device": {"id": "dev2", "type": "laptop"}, "timestamp": autonomous_fp_ts,
        "network_context": {"queried_domain": "sentry.io"},
        "features": {"tranco_rank": 500, "max_label_length": 10, "outbound_bytes_z": 0.0,
                     "zeek_lateral_moves": 0, "zeek_s0_rej_count": 0, "zeek_app_protocol_weight": 0.2},
        "reasons": [], "suppressed": True,
    }
    # This alert was published normally (NOT suppressed at the time) but an operator later
    # tapped "Mark False Positive" on it — must also be excluded from the threat set once
    # its correction lands in autonomous_muted.jsonl.
    operator_corrected_ts = now + 2
    operator_corrected_alert = {
        "device": {"id": "dev3", "type": "phone"}, "timestamp": operator_corrected_ts,
        "network_context": {"queried_domain": "operator-corrected-example.com"},
        "features": {"tranco_rank": 0, "max_label_length": 30, "outbound_bytes_z": 1.0,
                     "zeek_lateral_moves": 0, "zeek_s0_rej_count": 0, "zeek_app_protocol_weight": 0.2},
        "reasons": [],
    }

    (state_dir / "alerts.json").write_text(
        "\n".join(json.dumps(d) for d in [genuine_threat, autonomous_fp_alert, operator_corrected_alert]),
        encoding="utf-8",
    )

    # 2026-09-21 (legacy/Sheet 03a autotune reconciliation, Phase G4): load_dataset()
    # now reads fp_suppression_log entries from the graph instead of
    # state/autonomous_muted.jsonl -- write the equivalent decisions rows directly
    # instead of the old flat file.
    muted_entries = [
        {"ts_unix": autonomous_fp_ts, "type": "AUTONOMOUS_FP_SUPPRESSED", "confidence": 0.9,
         "reasons": [], "device": autonomous_fp_alert["device"], "domain": "sentry.io",
         "original_alert": autonomous_fp_alert},
        {"ts_unix": operator_corrected_ts, "type": "OPERATOR_MARKED_FALSE_POSITIVE", "confidence": 1.0,
         "reasons": [], "device": operator_corrected_alert["device"], "domain": "operator-corrected-example.com",
         "original_alert": operator_corrected_alert},
    ]
    load_dataset_store = GraphStore(str(state_dir / "v13_graph.db"))
    for entry in muted_entries:
        load_dataset_store.insert_decision(
            entry["device"]["id"], entry["ts_unix"], "BENIGN", "test_fixture",
            entry["confidence"], 0.0, raw_payload={"fp_suppression_log": entry},
        )
    load_dataset_store.close()

    X, y, stats = train_mod.load_dataset(state_dir)

    check("the genuinely-published (never corrected) threat alert IS trained as label=0",
          stats["threat_accepted"] == 1, f"threat_accepted={stats['threat_accepted']}")
    check("PHASE 6 FIX: the already-autonomously-suppressed alert and the operator-corrected "
          "alert are BOTH excluded from the label=0 threat set (2 skipped), instead of the "
          "old unconditional 'every alerts.json entry = label 0' behavior",
          stats["threat_skipped_corrected"] == 2, f"threat_skipped_corrected={stats['threat_skipped_corrected']}")
    check("both muted.jsonl entries (autonomous AND operator-corrected) are trained as "
          "label=1 false positives",
          stats["fp_accepted"] == 2, f"fp_accepted={stats['fp_accepted']}")
    check("the final dataset has exactly 1 threat + 2 FP samples (3 total), not the "
          "pre-fix 3 threat + 2 FP with 2 directly-contradictory-labeled duplicate events",
          len(X) == 3 and len(y) == 3 and y.count(0) == 1 and y.count(1) == 2,
          f"len(X)={len(X)} y={y}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 6 FP self-healing checks PASSED.")
