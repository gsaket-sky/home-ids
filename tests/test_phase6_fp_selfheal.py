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


from intelligence.fp_engine import AutonomousFPEngine
from core.state_guard import StateManager
from argus.graph.store import GraphStore


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: Stage 2 early-return bug — a low LightGBM P(FP) must still reach Stage 3
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    # Force a deterministic, confidently-a-threat LightGBM score (well below the 0.75
    # suppress threshold) — this is exactly the branch that used to `return` immediately
    # with verdict=UNCERTAIN/stage=STAGE_2_LGBM, skipping Stage 3 entirely.
    fp._stage2_lgbm = lambda features, domain, hostname, device_id: 0.10

    stage3_calls = {"count": 0}
    _orig_rule_fallback = fp._stage3_rule_fallback
    def _spy_rule_fallback(domain):
        stage3_calls["count"] += 1
        return _orig_rule_fallback(domain)
    fp._stage3_rule_fallback = _spy_rule_fallback

    # aiv-delivery.net is a real curated CDN-allowlist domain (utils.py's
    # _is_cdn_or_cloud_domain) — used here purely as a domain the rule-fallback Stage 3
    # will score with high similarity, so we can tell whether Stage 3 actually ran and
    # actually influenced the outcome.
    alert_payload = {
        "device": {"id": "dev_stage2", "hostname": "test-host"},
        "network_context": {"queried_domain": "api.eu-west-1.aiv-delivery.net", "destination_ip": "1.2.3.4"},
        "timestamp": time.time(),
    }
    safe_features = {"ti_risk": 0.0, "zeek_lateral_moves": 0, "zeek_ja3_malicious": 0,
                      "zeek_ja4_malicious": 0, "zeek_honeypot_hits": 0, "abuseipdb_risk": 0.0,
                      "outbound_bytes_z": 0.0}

    verdict = fp.evaluate(alert_payload, safe_features, risk_score=6.5, ti_engine=None)

    check("THE CORE FIX: Stage 3 (rule-fallback, since FastEmbed isn't loaded yet in a "
          "fresh engine) actually ran even though LightGBM's P(FP)=0.10 is confidently "
          "'threat' — before the fix this path returned immediately after Stage 2 and "
          "Stage 3 was never called",
          stage3_calls["count"] == 1, f"stage3 call count={stage3_calls['count']}")
    check("the dead 'STAGE_2_LGBM' short-circuit verdict no longer occurs — the final "
          "verdict now always reflects the combined Stage2+Stage3 score, matching the "
          "log line's long-standing promise of 'continuing to Stage 3 for corroboration'",
          verdict["stage"] != "STAGE_2_LGBM", f"got stage={verdict['stage']}")
    check("the final verdict's reasons cite BOTH LightGBM and the combined confidence "
          "(proof Stage 3 corroboration actually fed into the decision, not just ran "
          "and got discarded)",
          any("LightGBM" in r for r in verdict["reasons"]) and
          any("ombined" in r or "imilarity" in r for r in verdict["reasons"]),
          f"got reasons={verdict['reasons']}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: mark_false_positive() — operator-feedback closed loop
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)
    device_id = "dev_operator_1"
    hostname = "laptop-gs"
    domain = "sub.operator-corrected-example.com"
    alert_ts = time.time()
    alert_payload = {
        "device": {"id": device_id, "hostname": hostname},
        "network_context": {"queried_domain": domain, "destination_ip": "5.6.7.8"},
        "timestamp": alert_ts,
        "risk": 7.2,
    }

    # 2026-09-21 (legacy/Sheet 03a autotune reconciliation, Phase G): _write_muted_log()
    # now resolves this correction's graph decision row by device_id + the alert's OWN
    # timestamp (see that method's own docstring) -- a real pipeline cycle always has
    # one (argus_live_engine's own _write_graph() runs unconditionally every cycle), so
    # this fixture inserts the matching row directly, mirroring that real precondition
    # rather than exercising the no-matching-row fallback (covered separately below).
    graph_store = fp._get_autotune_engine().store
    graph_decision_id = graph_store.insert_decision(
        device_id, alert_ts, "HIGH", "hypothesis_high", 0.72, 7.2,
    )

    result = fp.mark_false_positive(alert_payload, hostname, domain)

    check("mark_false_positive() extracts and returns the correct eTLD+1 base domain",
          result["base_domain"] == "operator-corrected-example.com", f"got={result}")
    check("mark_false_positive() actually immunizes the base domain (present + non-expired "
          "in the dynamic trust cache used by the evaluate() fast path)",
          "operator-corrected-example.com" in fp.get_dynamic_trust_cache(),
          f"trust_cache={fp.get_dynamic_trust_cache()}")
    check("mark_false_positive() widens the SPECIFIC device's sigma shift (self-strengthening "
          "against future FPs from this device's baseline)",
          fp.get_sigma_shift(device_id) > 0.0, f"sigma={fp.get_sigma_shift(device_id)}")

    decision_row = graph_store._conn.execute(
        "SELECT raw_payload_json FROM decisions WHERE decision_id=?", (graph_decision_id,),
    ).fetchone()
    fp_suppression_log = None
    if decision_row is not None:
        fp_suppression_log = json.loads(decision_row["raw_payload_json"] or "{}").get("fp_suppression_log")
    check("mark_false_positive() writes a training-correction entry into the graph's "
          "decisions.raw_payload_json.fp_suppression_log (THIS is what makes the operator's "
          "correction actually influence the weekly LightGBM retrain — previously the old "
          "immunize button never wrote here at all)",
          fp_suppression_log is not None, f"decision_row={dict(decision_row) if decision_row else None}")
    if fp_suppression_log is not None:
        check("the written entry is tagged OPERATOR_MARKED_FALSE_POSITIVE (distinguishable "
              "from AUTONOMOUS_FP_SUPPRESSED in the audit log) and confidence=1.0",
              fp_suppression_log.get("type") == "OPERATOR_MARKED_FALSE_POSITIVE"
              and fp_suppression_log.get("confidence") == 1.0,
              f"entry={fp_suppression_log}")
        check("the written entry preserves the FULL original alert payload for downstream "
              "training feature extraction",
              fp_suppression_log.get("original_alert", {}).get("device", {}).get("id") == device_id)

    # No matching graph decision row exists for this second alert -- confirms the
    # fallback-graceful-degradation path (logs a warning, never crashes or silently
    # fabricates a row) for the case a real pipeline can still hit today: an alert
    # whose decision predates argus's graph wiring, or a device on its very first
    # cycle. Uses a device_id that was never inserted into `devices` at all.
    no_graph_row_alert = {
        "device": {"id": "dev_no_graph_row_yet", "hostname": "orphan-host"},
        "network_context": {"queried_domain": "orphan-example.com", "destination_ip": "1.2.3.4"},
        "timestamp": time.time(),
        "risk": 6.5,
    }
    result_no_graph_row = fp.mark_false_positive(no_graph_row_alert, "orphan-host", "orphan-example.com")
    check("mark_false_positive() still succeeds (immunizes, widens sigma, returns a real "
          "result) even when no matching graph decision row exists to attach the audit "
          "entry to -- the missing audit trail is a logged warning, not a crash",
          result_no_graph_row.get("base_domain") == "orphan-example.com", f"got={result_no_graph_row}")

    # A domain that can't be safely reduced to an eTLD+1 must not crash the whole flow —
    # trust-cache immunization is skipped, but sigma widening + audit logging still happen.
    bad_alert = {
        "device": {"id": "dev_bad_domain", "hostname": "host2"},
        "network_context": {"queried_domain": "", "destination_ip": "9.9.9.9"},
        "timestamp": time.time(),
    }
    result_bad = fp.mark_false_positive(bad_alert, "host2", "")
    check("mark_false_positive() degrades gracefully (no crash, base_domain='') when the "
          "domain can't be safely base-domain-extracted, instead of raising",
          result_bad["base_domain"] == "", f"got={result_bad}")


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
