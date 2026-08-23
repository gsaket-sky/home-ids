"""
Standalone runtime test for Phase 36 (VERSION 11): golden regression suite for the
third-party review of a full alerts.json history (8,443+ records). Not part of the
pytest suite -- run directly: `python3 tests/test_phase36_review_regression.py`.

Purpose: the review's specific scenarios are the closest thing this project has to
an authoritative "did the architecture actually improve, or did the names just
change" test suite. Most of its findings turned out to already be covered by
existing tests (test_phase24_dns_evasion.py, test_phase27_local_intel_and_confirmed_tuning.py,
test_phase33_tunneling_dga_domain_attribution.py, test_phase34/35) written for
earlier bugfixes -- this file exists specifically for the review findings that had
NO prior test coverage: the fp_engine.py Stage-1/decision_engine.py dual-verdict
problem (review #12) and its two concrete live false positives (a bare weak
ThreatIntel score hard-stopping independently of decision_engine.py's own tier
logic, and an exfiltration-burst check missing the absolute-byte floor + telemetry
exemption threat_signals.py's equivalent check already had).

Covers:
  A. fp_engine.py Stage-1 Check 0 -- decision_engine.py's own CRITICAL verdict is
     recognized directly, not re-derived.
  B. fp_engine.py Stage-1 Check 1 -- ti_risk threshold now matches
     classifier.py's confirmed_ioc bar (>2.0), not the old, more aggressive >0.
  C. fp_engine.py Stage-1 Check 6 -- exfiltration-burst hard-stop now requires the
     same absolute-byte floor + telemetry/vendor-cloud exemption
     threat_signals.py's zeek_exfiltration evidence generator already has (this is
     the live bug found in this session's own alerts.json audit: a TCP:8883 AWS
     IoT/MQTT connection hard-stopped purely from outbound_bytes_z=9.3).
  D. classifier.py tier logic -- a weak, AbuseIPDB-only signal on an
     otherwise-unclassified destination stays tier 4 (monitor), never tier 5
     (auto-block) -- the exact 149.154.166.110/Telegram shape the review raised
     (already fixed pre-review; pinned here as a golden case).
  E. threat_signals.py / DNSTunnelingV2Hypothesis -- a CDN/telemetry domain with a
     long/encoded-looking label does not trip DNS_COVERT_TUNNELING (already fixed
     pre-review; pinned here as a golden case covering the review's specific
     msh.amazon.co.uk-shaped example).
"""
import sys
import time
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.fp_engine import AutonomousFPEngine
from intelligence.reputation.classifier import ReputationClassifier
from intelligence.detectors.threat_signals import ThreatSignalDetector
from intelligence.hypotheses.engine import DNSTunnelingV2Hypothesis
from intelligence.hypotheses.evidence import Evidence, EvidenceStore
from core.decision_engine import DecisionEngine


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: Stage-1 Check 0 -- decision_engine.py's CRITICAL verdict is recognized
# directly by fp_engine's hard-stop filter, instead of being silently re-derivable
# (or NOT re-derivable, which is the bug class this whole section fixes) from raw
# features with a separately-drifting threshold.
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    alert = {
        "device": {"id": "dev_critical", "hostname": "some-device"},
        "network_context": {"queried_domain": "unknown", "destination_ip": "6.6.6.6"},
        "signature": "Layer-2 ARP Spoofing Detected",
    }
    critical_decision = {"state": "CRITICAL", "explanation": "Layer-2 ARP Spoofing Detected"}
    verdict = fp.evaluate(alert, {}, risk_score=10.0, ti_engine=None, decision=critical_decision)
    check("Check 0: a decision_engine.py CRITICAL verdict is recognized as an "
          "immediate Stage-1 hard-stop even with an otherwise completely quiet "
          "features dict",
          verdict["verdict"] == "CONFIRMED_THREAT", f"got {verdict}")
    check("Check 0's trigger text names the HEE verdict specifically",
          any("HEE hard-stop verdict" in t for t in verdict.get("reasons", [])),
          f"got {verdict.get('reasons')}")

    # REGRESSION GUARD: a non-CRITICAL decision with an otherwise quiet features
    # dict must NOT hard-stop -- Check 0 only fires on CRITICAL specifically.
    alert2 = {
        "device": {"id": "dev_susp", "hostname": "some-device-2"},
        "network_context": {"queried_domain": "unknown", "destination_ip": "7.7.7.7"},
        "signature": "DNS_EVASION",
    }
    suspicious_decision = {"state": "SUSPICIOUS", "explanation": "DNS_EVASION"}
    verdict2 = fp.evaluate(alert2, {}, risk_score=4.0, ti_engine=None, decision=suspicious_decision)
    check("REGRESSION GUARD: a SUSPICIOUS (non-CRITICAL) decision does NOT trip "
          "Check 0 on its own",
          verdict2["stage"] != "STAGE_1_HARD_STOP" or verdict2["verdict"] != "CONFIRMED_THREAT",
          f"got {verdict2}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: Stage-1 Check 1 -- ti_risk threshold now matches classifier.py's
# confirmed_ioc bar (>2.0), not the old, independently-drifting >0.
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)
    weak_ti_alert = {
        "device": {"id": "dev_weak_ti", "hostname": "weak-ti-device"},
        "network_context": {"queried_domain": "some-domain.example", "destination_ip": "8.8.4.4"},
        "signature": "DNS_TUNNELING",
    }
    weak_verdict = fp.evaluate(weak_ti_alert, {"ti_risk": 0.5}, risk_score=4.0, ti_engine=None)
    check("THE FIX: a weak ti_risk=0.5 (below classifier.py's confirmed_ioc bar of "
          "2.0) no longer hard-stops on its own -- the exact class of threshold "
          "mismatch a third-party review's alerts.json audit found between "
          "fp_engine.py's old Check 1 (was `> 0`) and decision_engine.py's own tier "
          "logic",
          weak_verdict["verdict"] != "CONFIRMED_THREAT" or weak_verdict["stage"] != "STAGE_1_HARD_STOP",
          f"got {weak_verdict}")

    strong_ti_alert = dict(weak_ti_alert)
    strong_ti_alert["device"] = {"id": "dev_strong_ti", "hostname": "strong-ti-device"}
    strong_verdict = fp.evaluate(strong_ti_alert, {"ti_risk": 3.5}, risk_score=9.0, ti_engine=None)
    check("REGRESSION GUARD: a genuine ti_risk=3.5 (above the 2.0 bar) still "
          "hard-stops as before -- the fix only removed the OVER-aggressive part "
          "of Check 1, not real IOC detection",
          strong_verdict["verdict"] == "CONFIRMED_THREAT", f"got {strong_verdict}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: Stage-1 Check 6 -- exfiltration-burst hard-stop now requires the same
# absolute-byte floor + telemetry/vendor-cloud exemption threat_signals.py's
# zeek_exfiltration evidence generator already has. THE live bug: found in this
# session's own read of the tail of the live state/alerts.json -- a TCP:8883 AWS
# IoT/MQTT connection (ASN owner "Amazon.com, Inc.") hard-stopped purely from
# outbound_bytes_z=9.3 on an otherwise-quiet baseline, with decision_engine.py
# separately calling the SAME alert SUSPICIOUS/monitor (confidence=0.40) --
# precisely the two-subsystems-disagree shape review #12 describes.
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    live_bug_alert = {
        "device": {"id": "dev_echo", "hostname": "amazon_echotower_fritz_box"},
        "network_context": {"queried_domain": "unknown", "destination_ip": "99.83.214.173"},
        "signature": "DNS_EVASION",
    }
    live_bug_features = {"outbound_bytes_z": 9.33, "zeek_outbound_bytes": 261}  # no absolute floor cleared
    live_bug_verdict = fp.evaluate(live_bug_alert, live_bug_features, risk_score=4.0, ti_engine=None)
    check("THE FIX (live bug): a z-score spike with only 261 bytes actually moved "
          "(far below the 2.5MB absolute floor) no longer hard-stops via Check 6",
          live_bug_verdict["verdict"] != "CONFIRMED_THREAT" or live_bug_verdict["stage"] != "STAGE_1_HARD_STOP",
          f"got {live_bug_verdict}")

    telemetry_exempt_alert = {
        "device": {"id": "dev_echo2", "hostname": "amazon_echotower_2"},
        "network_context": {"queried_domain": "device-metrics-us.amazon.com", "destination_ip": "9.9.9.9"},
        "signature": "DATA_EXFILTRATION",
    }
    telemetry_exempt_features = {"outbound_bytes_z": 8.0, "zeek_outbound_bytes": 5_000_000}
    telemetry_verdict = fp.evaluate(telemetry_exempt_alert, telemetry_exempt_features, risk_score=8.0, ti_engine=None)
    check("THE FIX: a genuinely large burst (5MB, clears the floor) to a recognized "
          "telemetry domain is still exempted from Check 6, matching "
          "threat_signals.py's own is_telemetry_domain/_is_cdn_or_cloud_domain "
          "exemption for the identical signal",
          telemetry_verdict["verdict"] != "CONFIRMED_THREAT" or telemetry_verdict["stage"] != "STAGE_1_HARD_STOP",
          f"got {telemetry_verdict}")

    genuine_exfil_alert = {
        "device": {"id": "dev_genuine", "hostname": "some-compromised-device"},
        "network_context": {"queried_domain": "unknown", "destination_ip": "203.0.113.55"},
        "signature": "DATA_EXFILTRATION",
    }
    genuine_exfil_features = {"outbound_bytes_z": 8.0, "zeek_outbound_bytes": 5_000_000}
    genuine_verdict = fp.evaluate(genuine_exfil_alert, genuine_exfil_features, risk_score=8.0, ti_engine=None)
    check("REGRESSION GUARD: a genuine large burst (5MB, clears the floor) to a "
          "non-telemetry, non-CDN destination still hard-stops as before -- the fix "
          "only added guards, it didn't remove real detection power",
          genuine_verdict["verdict"] == "CONFIRMED_THREAT", f"got {genuine_verdict}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: classifier.py tier logic -- golden case for the 149.154.166.110/
# Telegram shape (weak AbuseIPDB-only signal on an unclassified destination stays
# tier 4, never auto-promotes to tier 5). Fixed before this review; pinned here so a
# future regression is caught by this suite specifically, not just by luck.
# ═══════════════════════════════════════════════════════════════════════════════════
rc = ReputationClassifier()
weak_signal_rep = rc.classify("203.0.113.99", vt_score=0.0, ti_score=0.0, abuse_score=3.78, asn_owner="Some Hosting LLC")
check("GOLDEN CASE: a weak AbuseIPDB-only signal (3.78, below the 4.0 confirmed_ioc "
      "bar) on an unclassified destination stays tier 4 (monitor), never auto-"
      "promotes to tier 5 (block)",
      weak_signal_rep.tier == 4, f"got tier={weak_signal_rep.tier}")

confirmed_rep = rc.classify("203.0.113.100", vt_score=0.0, ti_score=0.0, abuse_score=5.0, asn_owner="Some Hosting LLC")
check("REGRESSION GUARD: a genuinely confirmed AbuseIPDB score (>=4.0) still "
      "reaches tier 5",
      confirmed_rep.tier == 5, f"got tier={confirmed_rep.tier}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: threat_signals.py / DNSTunnelingV2Hypothesis -- golden case for the
# review's msh.amazon.co.uk-shaped example: a long/encoded-looking DNS label on a
# recognized CDN/cloud domain must not trip DNS_COVERT_TUNNELING. Fixed before this
# review (the evidence_domain fix in threat_signals.py); pinned here as a golden
# case using the review's own named example shape.
# ═══════════════════════════════════════════════════════════════════════════════════
detector = ThreatSignalDetector()
amazon_features = {
    "max_label_length": 63,
    "max_label_domain": "9171f26edcb0ab14.us-east-1.prod.service.minerva.devices.a2z.com",
    "dns_tunneling_domains": 0,
    "dns_tunneling_domain_examples": [],
    "suspicious_domains": 0,
}
amazon_evidence = detector.detect("dev_firetv", amazon_features, top_domain="msh.amazon.co.uk")
tunnel_hits = [e for e in amazon_evidence if e.type == "dns_tunnel_v2"]
check("GOLDEN CASE: a 63-char label (the DNS max) on a recognized Amazon/a2z.com "
      "telemetry domain produces NO dns_tunnel_v2 evidence, even though the "
      "unrelated top_domain (msh.amazon.co.uk) is what the alert would display",
      len(tunnel_hits) == 0, f"got {tunnel_hits}")

hyp = DNSTunnelingV2Hypothesis()
store = EvidenceStore()
for e in amazon_evidence:
    store.add(e)
from intelligence.reputation.classifier import ReputationVector
score = hyp.evaluate(store.get_for_device("dev_firetv"), ReputationVector(domain="msh.amazon.co.uk", tier=3))
check("GOLDEN CASE: with no dns_tunnel_v2 evidence at all, DNSTunnelingV2Hypothesis "
      "(DNS_COVERT_TUNNELING) does not fire",
      score == 0.0, f"got {score}")

genuinely_suspicious_features = {
    "max_label_length": 63,
    "max_label_domain": "qwertyuiopasdfghjklzxcvbnm382.attacker-controlled.ru",
    "dns_tunneling_domains": 3,
    "dns_tunneling_domain_examples": ["qwertyuiopasdfghjklzxcvbnm382.attacker-controlled.ru"],
    "suspicious_domains": 0,
}
genuinely_suspicious_evidence = detector.detect("dev_iot", genuinely_suspicious_features, top_domain="qwertyuiopasdfghjklzxcvbnm382.attacker-controlled.ru")
check("REGRESSION GUARD: the SAME 63-char label length on a genuinely unrecognized, "
      "non-CDN domain with real tunnel_domains count still produces dns_tunnel_v2 "
      "evidence -- the fix is scoped to CDN/telemetry domains, not label length in "
      "general",
      any(e.type == "dns_tunnel_v2" for e in genuinely_suspicious_evidence),
      f"got {genuinely_suspicious_evidence}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: calibrated_confidence actually reaches the Telegram-facing text, not just
# fp_engine.py's internal reasons list. Found via a LIVE alert during this session's own
# rollout: the "CONFIDENCE" section in pipeline.py reads fp_verdict's top-level keys
# directly and never touched reasons at all, so the review #13/#14 FP_MODEL_SCORE/
# calibration labeling never reached the one place a human actually taps
# approve/reject from.
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir_f:
    fp_f = AutonomousFPEngine(config={}, state_dir=tmpdir_f)
    uncertain_alert = {
        "device": {"id": "dev_f", "hostname": "paperless"},
        "network_context": {"queried_domain": "unknown", "destination_ip": "104.156.84.32"},
        "signature": "DNS_POLICY_BYPASS",
    }
    verdict_f = fp_f.evaluate(uncertain_alert, {}, risk_score=6.0, ti_engine=None)
    check("fp_engine.evaluate()'s returned dict has a 'calibrated_confidence' key "
          "(not just buried in the reasons text) for every Stage-2/3-scored branch",
          "calibrated_confidence" in verdict_f, f"got keys={list(verdict_f.keys())}")
    check("with no calibration file loaded (the common case until a retrain has run "
          "with enough held-out data), calibrated_confidence is None, not a fabricated "
          "number",
          verdict_f["calibrated_confidence"] is None, f"got {verdict_f['calibrated_confidence']}")

with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py", "r", encoding="utf-8") as f:
    pipeline_src_f = f.read()
check("SOURCE-GUARD: pipeline.py's Telegram CONFIDENCE section reads "
      "calibrated_confidence from fp_verdict",
      'fp_verdict.get("calibrated_confidence")' in pipeline_src_f)
check("SOURCE-GUARD: when no calibration is loaded, the Telegram CONFIDENCE line "
      "explicitly flags the estimate as uncalibrated rather than showing a bare, "
      "unqualified percentage (ALERT REDESIGN: reworded from 'uncalibrated model "
      "score, not a validated probability' to the shorter reconciled-verdict phrasing, "
      "same guarantee)",
      '"" if fp_calibrated_pct is not None else " _(uncalibrated estimate)_"' in pipeline_src_f)
check("SOURCE-GUARD: when calibration IS loaded, fp_calibrated_pct (the calibrated "
      "percentage) is what feeds the Telegram CONFIDENCE line, not the raw score alone",
      "fp_calibrated_pct if fp_calibrated_pct is not None else fp_pct" in pipeline_src_f)
check("SOURCE-GUARD: alert_payload['fp_verdict'] (the persisted audit trail) also "
      "carries calibrated_confidence, not just the live Telegram text",
      '"calibrated_confidence": fp_verdict.get("calibrated_confidence")' in pipeline_src_f)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 36 review-regression checks PASSED.")
