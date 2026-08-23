"""
Standalone runtime test for VERSION 10's remaining two architectural roadmap items,
approved after a third-party review of the full alerts.json history flagged them as
reasonable forward-looking improvements (not live bugs): per-device benign profiles
(#9/#10) and the Ollama circular-reasoning guard (#15/#16). Not part of the pytest
suite -- run directly:
`python3 tests/test_phase35_device_profiles_and_ollama_guard.py`.

#9/#10 PER-DEVICE BENIGN PROFILES: device_type is a coarse CATEGORY classification
(smart_tv, iot, gaming_console, nas, router, gateway, dns_server, laptop, phone,
tablet, printer, camera -- utils.infer_device_type()), not a brand -- there is no
detection basis to distinguish "Amazon Fire TV" from "Google Chromecast" today, so this
deliberately does NOT build the reviewer's full brand-specific benign-hypothesis catalog
(AMAZON_DEVICE_TELEMETRY, APPLE_TELEMETRY, ...). Instead: Hypothesis.evaluate() and
HypothesisEngine.evaluate_all() gained a backward-compatible optional device_type
parameter, and a new DeviceProfileBenignHypothesis scores a NAMED benign verdict
("DEVICE_PROFILE_TELEMETRY") for device categories expected to generate frequent
traffic to already-trusted/known infrastructure (smart_tv/iot/gaming_console/nas/
router/gateway/dns_server), reusing the existing global reputation classifier rather
than a new per-category domain list -- instead of falling through to the generic
UNKNOWN_BENIGN catch-all every time. Pure audit-trail/explanation-quality improvement;
does not relax any containment threshold (decision_engine.py only reads a benign
hypothesis's name when nothing attack-worthy won anyway).

#15/#16 OLLAMA CIRCULAR-REASONING GUARD: the local LLM validator (src/scripts/
ollama_soc.py) used to prompt with the WHOLE raw alert_payload undiscriminated,
including this system's own "risk": 9.9 / "signature": "Confirmed Malicious IOC" /
fp_verdict sitting right next to genuinely raw evidence -- confirmed via a third-party
review that this let the model simply reflect an existing verdict back as "confirmation"
instead of reasoning independently. Fixed with _build_evidence_only_payload() (strips
every verdict-shaped field before prompting), an updated system prompt instructing
independent reasoning, and a defense-in-depth check in ai_soc.py's
DeterministicValidator that rejects a "malicious" verdict whose free-text reasoning
cites the exact original risk score it should never have been shown. The existing
benign-only/multi-device-spread-guard asymmetry (this validator can only ever relax
containment, never escalate it) is completely unchanged.

Covers:
  A. hypotheses/engine.py -- every existing hypothesis's evaluate() signature accepts
     (and ignores) the new device_type parameter; DeviceProfileBenignHypothesis's real
     scoring behavior across category/reputation-tier combinations; UNKNOWN_BENIGN is
     no longer reached for the cases this hypothesis now covers.
  B. decision_engine.py -- device_type threaded end-to-end through evaluate().
  C. ollama_soc.py -- _build_evidence_only_payload strips every verdict-shaped field
     and keeps every genuine raw-evidence field.
  D. ai_soc.py -- DeterministicValidator's new circular-reasoning check: rejects a
     malicious verdict citing the exact original risk score, accepts one that reasons
     independently, and the pre-existing IOC/telemetry checks are unaffected.
  E. Source-guards for the pipeline.py wiring (device_type threaded from state to
     decision_engine.evaluate()).
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: hypotheses/engine.py
# ═══════════════════════════════════════════════════════════════════════════════════
from intelligence.hypotheses.engine import (
    HypothesisEngine, DeviceProfileBenignHypothesis, DNSTunnelingHypothesis,
    AdvertisingBurstHypothesis,
)
from intelligence.hypotheses.evidence import Evidence
from intelligence.reputation.classifier import ReputationVector

NOW = time.time()

def _dns_rate_ev(value):
    return Evidence(type="dns_rate", source="pihole", timestamp=NOW, device="d1",
                     value=value, confidence=0.9, independence_group="dns_behavior")

check("BACKWARD-COMPAT: an existing hypothesis's evaluate() still works when called "
      "with the old 2-arg form (device_type omitted entirely)",
      DNSTunnelingHypothesis().evaluate([], ReputationVector(domain="x", tier=3)) == 0.0)
check("BACKWARD-COMPAT: an existing hypothesis's evaluate() also accepts the new "
      "device_type kwarg without error, even though it ignores it -- score is unaffected "
      "by the signature change (4.0: high-rate, tier 2, no dns_entropy evidence present)",
      AdvertisingBurstHypothesis().evaluate([_dns_rate_ev(60)], ReputationVector(domain="x", tier=2), device_type="smart_tv") == 4.0)

dp = DeviceProfileBenignHypothesis()

check("THE CORE FIX: a smart_tv with elevated dns_rate against trusted (tier 1) "
      "infrastructure scores DEVICE_PROFILE_TELEMETRY",
      dp.evaluate([_dns_rate_ev(30)], ReputationVector(domain="apple.com", tier=1), "smart_tv") == 3.0)
check("iot category, tier 2 (known infrastructure, not fully trusted) scores lower "
      "than tier 0/1 but still fires",
      dp.evaluate([_dns_rate_ev(25)], ReputationVector(domain="cdn.example", tier=2), "iot") == 2.5)
check("REGRESSION GUARD: a laptop (not an expected high-volume category) with the "
      "IDENTICAL evidence does NOT get DEVICE_PROFILE_TELEMETRY",
      dp.evaluate([_dns_rate_ev(30)], ReputationVector(domain="apple.com", tier=1), "laptop") == 0.0)
check("REGRESSION GUARD: a smart_tv against an UNCLASSIFIED (tier 3) destination does "
      "NOT fire -- 'expected category' alone is not enough without a trusted destination",
      dp.evaluate([_dns_rate_ev(30)], ReputationVector(domain="random.biz", tier=3), "smart_tv") == 0.0)
check("REGRESSION GUARD: a smart_tv with no elevated DNS activity at all does not fire "
      "on device_type/reputation alone",
      dp.evaluate([], ReputationVector(domain="apple.com", tier=1), "smart_tv") == 0.0)
check("REGRESSION GUARD: an empty device_type (unknown/legacy state) behaves exactly "
      "like a non-expected category -- never fires",
      dp.evaluate([_dns_rate_ev(30)], ReputationVector(domain="apple.com", tier=1), "") == 0.0)

def _dga_ev(value):
    return Evidence(type="dns_dga_burst", source="threat_signals", timestamp=NOW, device="d1",
                     value=value, confidence=0.6, independence_group="dns_behavior")

# MITIGATION (found and fixed before this hypothesis was ever committed -- see the
# PROJECT_SYNC_LOG.md entry): DeviceProfileBenignHypothesis must never outscore a
# weaker-but-real attack hypothesis just because the same trusted-tier reputation both
# dampens the attack hypothesis AND satisfies this one's own requirement.
check("THE MITIGATION: DeviceProfileBenignHypothesis backs off entirely when genuine "
      "attack-shaped evidence (dns_dga_burst) is present, even though its own "
      "category/reputation/dns_rate requirements are otherwise satisfied",
      dp.evaluate([_dns_rate_ev(25), _dga_ev(6.0)], ReputationVector(domain="cdn.example", tier=2), "iot") == 0.0)
check("REGRESSION GUARD: the mitigation is scoped to genuinely attack-shaped evidence "
      "types -- dns_rate/dns_entropy (the same ambiguous signals this hypothesis "
      "itself explains) do NOT trip it",
      dp.evaluate([_dns_rate_ev(30)], ReputationVector(domain="apple.com", tier=1), "smart_tv") == 3.0)

# End-to-end via HypothesisEngine: UNKNOWN_BENIGN is no longer reached for this case.
hyp = HypothesisEngine()
check("DeviceProfileBenignHypothesis is registered in HypothesisEngine.benign_hypotheses",
      any(isinstance(h, DeviceProfileBenignHypothesis) for h in hyp.benign_hypotheses))
result = hyp.evaluate_all([_dns_rate_ev(30)], ReputationVector(domain="apple.com", tier=1), device_type="smart_tv")
check("THE CORE FIX (end-to-end): a smart_tv's routine trusted-telemetry traffic gets "
      "a named benign verdict, not the generic UNKNOWN_BENIGN catch-all",
      result["benign"]["name"] == "DEVICE_PROFILE_TELEMETRY", f"got={result['benign']}")
result_laptop = hyp.evaluate_all([_dns_rate_ev(30)], ReputationVector(domain="apple.com", tier=1), device_type="laptop")
check("REGRESSION GUARD (end-to-end): the SAME evidence on a laptop still falls "
      "through to UNKNOWN_BENIGN -- this hypothesis is category-scoped, not blanket",
      result_laptop["benign"]["name"] == "UNKNOWN_BENIGN", f"got={result_laptop['benign']}")

# THE MITIGATION (end-to-end): the exact verified incident from the sync-log entry --
# a dampened DGA_BOTNET_C2 signal on an iot device against trusted infrastructure must
# resolve to SUSPICIOUS (visible, logged), never silently to BENIGN (invisible,
# nothing logged) just because DeviceProfileBenignHypothesis's own conditions also
# happen to be satisfied.
result_masking = hyp.evaluate_all([_dns_rate_ev(25), _dga_ev(6.0)],
                                   ReputationVector(domain="cdn.example", tier=2), device_type="iot")
check("THE MITIGATION (end-to-end): a weak-but-real DGA signal on a trusted-tier iot "
      "device wins as the attack hypothesis, not silently masked by device-profile "
      "benign reasoning",
      result_masking["attack"]["name"] == "DGA_BOTNET_C2" and
      result_masking["attack"]["score"] > result_masking["benign"]["score"],
      f"got attack={result_masking['attack']} benign={result_masking['benign']}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: decision_engine.py -- device_type threaded end-to-end
# ═══════════════════════════════════════════════════════════════════════════════════
from core.decision_engine import DecisionEngine, DecisionState

de = DecisionEngine()
d_result = de.evaluate([_dns_rate_ev(30)], ReputationVector(domain="apple.com", tier=1), "smart_tv")
check("THE CORE FIX (full decision_engine path): a smart_tv's trusted telemetry "
      "resolves to BENIGN with a real explanation, not the generic catch-all",
      d_result["state"] == DecisionState.BENIGN and d_result["explanation"] == "DEVICE_PROFILE_TELEMETRY",
      f"got state={d_result['state']} explanation={d_result['explanation']}")
check("BACKWARD-COMPAT: decision_engine.evaluate() still works with device_type "
      "omitted entirely (defaults to '')",
      de.evaluate([], ReputationVector(domain="x", tier=3))["state"] == DecisionState.BENIGN)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: ollama_soc.py -- _build_evidence_only_payload
# ═══════════════════════════════════════════════════════════════════════════════════
from scripts.ollama_soc import _build_evidence_only_payload, _VERDICT_SHAPED_FIELDS

_REAL_ALERT_SHAPE = {
    "type": "ids_alert", "timestamp": NOW,
    "device": {"id": "d1", "ip": "192.168.1.94", "hostname": "paperless", "type": "laptop"},
    "network_context": {"destination_ip": "149.154.166.110", "destination_port": 443, "queried_domain": "unknown"},
    "risk": 9.9, "signature": "Confirmed Malicious IOC",
    "factors": [{"name": "Confirmed Malicious IOC", "score": 9.9}],
    "features": {"ti_risk": 0.0, "abuseipdb_risk": 3.78, "vt_risk": 0.066},
    "schema": "home_ids_alerts_v3", "evidence_verification_required": True,
    "hypothesis_weight": 0.8, "reasoning_trail": ["Verdict: CRITICAL / block"],
    "incident_id": "d1|149.154.166.110|Confirmed Malicious IOC",
}
sanitized = _build_evidence_only_payload(_REAL_ALERT_SHAPE)

check("THE CORE FIX: every verdict-shaped field (risk/signature/factors/fp_verdict/"
      "hypothesis_weight/evidence_verification_required/reasoning_trail) is stripped "
      "from the LLM prompt payload",
      not any(k in sanitized for k in _VERDICT_SHAPED_FIELDS), f"leaked={set(sanitized) & _VERDICT_SHAPED_FIELDS}")
check("REGRESSION GUARD: genuinely raw evidence fields (device, network_context, "
      "features -- including ti_risk/abuse_risk/vt_risk, which are input signals for "
      "the model to weigh, not this system's own verdict) survive intact",
      sanitized.get("device") == _REAL_ALERT_SHAPE["device"] and
      sanitized.get("network_context") == _REAL_ALERT_SHAPE["network_context"] and
      sanitized.get("features") == _REAL_ALERT_SHAPE["features"])
check("REGRESSION GUARD: incident_id (a stable identifier, not a verdict) survives",
      sanitized.get("incident_id") == _REAL_ALERT_SHAPE["incident_id"])
check("a payload missing some verdict-shaped keys entirely (e.g. an older alert "
      "record without fp_verdict) is handled without KeyError",
      _build_evidence_only_payload({"device": {}, "features": {}}) == {"device": {}, "features": {}})


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: ai_soc.py -- DeterministicValidator's circular-reasoning check
# ═══════════════════════════════════════════════════════════════════════════════════
from intelligence.ai_soc import DeterministicValidator

v = DeterministicValidator()

check("THE CORE FIX: a 'malicious' verdict whose reasoning cites the EXACT original "
      "risk score (that it should never have been shown) is rejected",
      not v.validate({"classification": "malicious", "reason": "This connection has risk 9.9 and matches known bad infrastructure."},
                      [], original_risk=9.9))
check("THE CORE FIX: the same check catches a differently-formatted but still exact "
      "match of the original risk value",
      not v.validate({"classification": "malicious", "reason": "risk=9.90 confirms malicious intent"},
                      [], original_risk=9.90))
check("REGRESSION GUARD: a 'malicious' verdict that reasons independently (no mention "
      "of the withheld risk score) is accepted",
      v.validate({"classification": "malicious", "reason": "Connects to an IP with elevated AbuseIPDB score and no DNS resolution history."},
                 [], original_risk=9.9))
check("REGRESSION GUARD: original_risk=None (e.g. a caller that hasn't been updated) "
      "never triggers the new check -- backward compatible",
      v.validate({"classification": "malicious", "reason": "risk 9.9 confirmed"}, [], original_risk=None))
check("REGRESSION GUARD: a coincidental small-number match (e.g. reason mentions "
      "'port 80' while original_risk=8.0) is NOT what this checks for -- only an exact "
      "formatted risk-value substring match triggers it",
      v.validate({"classification": "malicious", "reason": "connected on port 80 repeatedly"}, [], original_risk=8.0))

# Pre-existing checks unaffected by the new parameter.
ev_bad_ioc = [Evidence(type="reputation", source="ti", timestamp=NOW, device="d1", value=4.5, confidence=0.9)]
check("REGRESSION GUARD: the pre-existing 'benign despite confirmed IOC' rejection "
      "still works unchanged",
      not v.validate({"classification": "benign", "reason": "just ads"}, ev_bad_ioc))
check("REGRESSION GUARD: a genuinely benign verdict with no contradicting evidence "
      "is still accepted",
      v.validate({"classification": "benign", "reason": "just ads"}, []))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: pipeline.py source-guards
# ═══════════════════════════════════════════════════════════════════════════════════
import inspect
from core import pipeline as _pipeline_module

_pipeline_src = inspect.getsource(_pipeline_module)
check("SOURCE-GUARD: pipeline.py threads state.device_type into decision_engine.evaluate()",
      'self.decision_engine.evaluate(active_evidence, rep_vector, getattr(state, "device_type", ""))' in _pipeline_src)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All device-profile + Ollama circular-reasoning-guard checks PASSED.")
