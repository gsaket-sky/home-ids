"""
Standalone runtime test for a series of fixes found via third-party review of real
production alerts (lateral-movement distinct-target counting, LOCAL_DEVICE_DISCOVERY,
alert-text wording, and reputation-attribution). Not part of the pytest suite -- run
directly: `python3 tests/test_phase32_lateral_movement_targets.py`.

BUGFIX (found via a third-party review of a real production tarpit alert, verified
against this exact code and real production feature data): zeek_lateral_moves is a raw
COUNT of connections to LATERAL_PORTS (22/445/3389/5900/23) -- fp_engine.py's Stage-1
hard-stop (bypasses ALL ML/corroboration) and pipeline.py's lateral_threat (authorizes
Layer-2 tarpit containment, bypassing the normal risk>=9.0 floor) both gated on a bare
`> 0` check against this count. Confirmed live: a single ordinary SMB connection
(zeek_lateral_moves=1, a device browsing exactly one internal NAS/server share) was
sufficient to reach CONFIRMED_THREAT and trigger tarpit -- no different treatment from a
genuine multi-target scan. zeek_s0_rej_unique_ips already exists alongside
zeek_s0_rej_count for exactly this "distinguish count from distinct targets" reason; the
same tracking was simply never added for lateral movement. Fixed with a new
zeek_lateral_unique_targets feature and a config-driven
lateral_movement_unique_targets_threshold (default 2) gating both consequential sites.

Covers:
  A. zeek_features.py's get_features() -- zeek_lateral_unique_targets correctly counts
     DISTINCT destination IPs, not raw connection count.
  B. fp_engine.py's Stage-1 Check 2 -- a single-target connection no longer hard-stops;
     a genuine multi-target one still does.
  C. pipeline.py source-guard for the lateral_threat (tarpit-authorization) fix.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import tempfile
import time

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: zeek_features.py -- zeek_lateral_unique_targets counts DISTINCT targets
# ═══════════════════════════════════════════════════════════════════════════════════
from extractors.zeek_features import ZeekFeatureExtractor

SRC = "192.168.1.12"

def _conn(src, dst, port, uid, ts=None):
    return {"_zeek_type": "conn", "id.orig_h": src, "id.resp_h": dst, "id.resp_p": port,
            "proto": "tcp", "orig_bytes": 100, "uid": uid, "ts": ts or time.time()}

# A1: a single connection to ONE internal target on a lateral port.
zfx_single = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
zfx_single.ingest(_conn(SRC, "192.168.1.94", 445, "U1"))
feats_single = zfx_single.get_features(SRC)
check("a single connection to one target: zeek_lateral_moves == 1",
      feats_single["zeek_lateral_moves"] == 1, f"got {feats_single['zeek_lateral_moves']}")
check("THE CORE FIX: a single connection to one target: zeek_lateral_unique_targets == 1",
      feats_single["zeek_lateral_unique_targets"] == 1, f"got {feats_single['zeek_lateral_unique_targets']}")

# A2: THREE repeat connections to the SAME single target -- count grows, but distinct
# targets stays at 1 (repeated browsing of one NAS share, not a scan).
zfx_repeat = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
for i in range(3):
    zfx_repeat.ingest(_conn(SRC, "192.168.1.94", 445, f"U{i}"))
feats_repeat = zfx_repeat.get_features(SRC)
check("three repeat connections to the SAME target: zeek_lateral_moves == 3",
      feats_repeat["zeek_lateral_moves"] == 3, f"got {feats_repeat['zeek_lateral_moves']}")
check("THE CORE FIX: three repeat connections to the SAME target: "
      "zeek_lateral_unique_targets is STILL 1, not 3 -- this is exactly the distinction "
      "that was missing before the fix",
      feats_repeat["zeek_lateral_unique_targets"] == 1, f"got {feats_repeat['zeek_lateral_unique_targets']}")

# A3: connections to THREE distinct targets -- a genuine multi-target pattern.
zfx_multi = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
for i, dst in enumerate(["192.168.1.1", "192.168.1.2", "192.168.1.5"]):
    zfx_multi.ingest(_conn(SRC, dst, 445, f"M{i}"))
feats_multi = zfx_multi.get_features(SRC)
check("three connections to three DISTINCT targets: zeek_lateral_moves == 3",
      feats_multi["zeek_lateral_moves"] == 3, f"got {feats_multi['zeek_lateral_moves']}")
check("three connections to three DISTINCT targets: zeek_lateral_unique_targets == 3",
      feats_multi["zeek_lateral_unique_targets"] == 3, f"got {feats_multi['zeek_lateral_unique_targets']}")

# A4: a device with zero lateral-port activity at all.
zfx_clean = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
zfx_clean.ingest(_conn(SRC, "8.8.8.8", 443, "C1"))
feats_clean = zfx_clean.get_features(SRC)
check("REGRESSION GUARD: no lateral-port connections at all -> both metrics are 0",
      feats_clean["zeek_lateral_moves"] == 0 and feats_clean["zeek_lateral_unique_targets"] == 0)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: fp_engine.py's Stage-1 Check 2 -- requires a genuine distinct-target count
# ═══════════════════════════════════════════════════════════════════════════════════
from intelligence.fp_engine import AutonomousFPEngine

def _alert(domain="unrelated-domain.example"):
    return {
        "device": {"id": "dev_lateral", "hostname": "some-laptop"},
        "network_context": {"queried_domain": domain, "destination_ip": "192.168.1.94"},
        "signature": "NETWORK_INTRUSION",
    }

with tempfile.TemporaryDirectory() as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    # THE CORE FIX: a single-target connection (the real production shape found live --
    # a laptop with ONE SMB connection to its own NAS) must NOT hard-stop.
    single_target_features = {"zeek_lateral_moves": 1, "zeek_lateral_unique_targets": 1}
    verdict_single = fp.evaluate(_alert(), single_target_features, risk_score=8.5, ti_engine=None)
    check("THE CORE FIX: a single-target lateral connection (zeek_lateral_moves=1, "
          "zeek_lateral_unique_targets=1) does NOT reach Stage-1 CONFIRMED_THREAT -- "
          "this is the exact real production case that was wrongly hard-stopping",
          verdict_single["stage"] != "STAGE_1_HARD_STOP", f"got={verdict_single}")

    # Even repeated connections to the SAME single target must not hard-stop.
    repeat_single_features = {"zeek_lateral_moves": 5, "zeek_lateral_unique_targets": 1}
    verdict_repeat = fp.evaluate(_alert(), repeat_single_features, risk_score=8.5, ti_engine=None)
    check("REGRESSION GUARD: even 5 repeat connections to ONE target still does not "
          "hard-stop -- the fix keys on distinct targets, not raw connection count",
          verdict_repeat["stage"] != "STAGE_1_HARD_STOP", f"got={verdict_repeat}")

    # A genuine multi-target scan (>= the default threshold of 2) still hard-stops.
    multi_target_features = {"zeek_lateral_moves": 3, "zeek_lateral_unique_targets": 3}
    verdict_multi = fp.evaluate(_alert(), multi_target_features, risk_score=8.5, ti_engine=None)
    check("REGRESSION GUARD: a genuine multi-target scan (3 distinct targets) still "
          "reaches Stage-1 CONFIRMED_THREAT as before -- the fix doesn't weaken real "
          "detection, only the single-target false-positive shape",
          verdict_multi["verdict"] == "CONFIRMED_THREAT" and verdict_multi["stage"] == "STAGE_1_HARD_STOP",
          f"got={verdict_multi}")

    # Exactly at the default threshold (2) fires; one below (1) does not.
    at_threshold_features = {"zeek_lateral_moves": 2, "zeek_lateral_unique_targets": 2}
    verdict_at = fp.evaluate(_alert(), at_threshold_features, risk_score=8.5, ti_engine=None)
    check("exactly at the default threshold (2 distinct targets) DOES hard-stop",
          verdict_at["stage"] == "STAGE_1_HARD_STOP", f"got={verdict_at}")

    # Old data / any caller that never populated zeek_lateral_unique_targets at all
    # (e.g. a feature dict built before this fix existed) must fail closed -- not
    # treated as "unlimited targets", but as "0 known targets" (missing key -> 0).
    missing_key_features = {"zeek_lateral_moves": 5}
    verdict_missing = fp.evaluate(_alert(), missing_key_features, risk_score=8.5, ti_engine=None)
    check("a features dict missing zeek_lateral_unique_targets entirely fails CLOSED "
          "(treated as 0 distinct targets), not open",
          verdict_missing["stage"] != "STAGE_1_HARD_STOP", f"got={verdict_missing}")

    # Custom, stricter config threshold is honored.
    fp_strict = AutonomousFPEngine(config={"lateral_movement_unique_targets_threshold": 5}, state_dir=tmpdir + "_2")
    verdict_strict = fp_strict.evaluate(_alert(), multi_target_features, risk_score=8.5, ti_engine=None)
    check("a stricter configured threshold (5) is honored -- 3 distinct targets no "
          "longer hard-stops under that config",
          verdict_strict["stage"] != "STAGE_1_HARD_STOP", f"got={verdict_strict}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: pipeline.py source-guard -- lateral_threat (tarpit authorization)
# ═══════════════════════════════════════════════════════════════════════════════════
pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")

check("THE FIX: lateral_threat (which authorizes Layer-2 tarpit, bypassing the normal "
      "risk>=9.0 floor) now requires zeek_lateral_unique_targets to clear the "
      "configured threshold, not just zeek_lateral_moves > 0",
      "lateral_targets_count = int(features.get(\"zeek_lateral_unique_targets\", 0) or 0)" in pipeline_src and
      "lateral_threshold = int(self.config.get(\"lateral_movement_unique_targets_threshold\", 2))" in pipeline_src)
check("REGRESSION GUARD: honeypot hits still independently authorize lateral_threat "
      "regardless of target count -- the fix is scoped to the lateral-movement signal "
      "specifically, not honeypot access",
      'features.get("zeek_honeypot_hits", 0) > 0' in pipeline_src)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: the THIRD instance of the same gap -- NetworkIntrusionHypothesis's own
# "Hard escalate for lateral scans" branch (hypotheses/engine.py) reads the
# zeek_lateral_scan EVIDENCE item, not the raw feature -- found by verifying the
# reviewer's claim carefully: fp_engine.py's Stage-1 hard-stop and pipeline.py's
# lateral_threat were already fixed, but the HEE evidence-EMISSION site that feeds
# this hypothesis (pipeline.py, separate from both of those) still created the
# evidence from a bare zeek_lateral_moves > 0 check. Fixed at the emission source
# (don't create the misleading evidence at all) rather than inside the hypothesis --
# a single source of truth for "was this genuine lateral movement."
# ═══════════════════════════════════════════════════════════════════════════════════
check("THE THIRD FIX: the zeek_lateral_scan evidence-emission site also now requires "
      "the distinct-target threshold before creating the evidence at all -- this is "
      "what NetworkIntrusionHypothesis's 'Hard escalate for lateral scans' branch "
      "(hypotheses/engine.py) reads, so a single-target connection can no longer force "
      "that hypothesis to HIGH either",
      'if features.get("zeek_lateral_moves", 0) > 0 and lateral_unique_targets >= lateral_evidence_threshold:' in pipeline_src)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: LOCAL_DEVICE_DISCOVERY -- reviewer suggestion, implemented. A device's own
# real HTTP/SSDP/DIAL requests to media/UPnP devices on its own LAN (Spotify Connect
# app discovery, Chromecast device descriptors) is normal discovery behavior, not
# "more suspicious network activity" -- now a real benign hypothesis competing in
# decision_engine.py's attack-vs-benign scoring, not just alert-display context.
# ═══════════════════════════════════════════════════════════════════════════════════
from core.pipeline import _count_local_device_discovery_requests, _LOCAL_DEVICE_DISCOVERY_URI_PATTERNS
from intelligence.hypotheses.engine import LocalDeviceDiscoveryHypothesis, HypothesisEngine
from intelligence.hypotheses.evidence import Evidence
from intelligence.reputation.classifier import ReputationVector


class _FakeZeekFxForDiscovery:
    def __init__(self, http_reqs, home_ips):
        self._http_reqs = http_reqs
        self._home_ips = home_ips

    def get_http_reqs(self, ip):
        return self._http_reqs.get(ip, set())

    def is_home_ip(self, ip):
        return ip in self._home_ips

DISCOVERY_SRC = "192.168.1.12"

# E1: real Spotify Connect / SSDP discovery traffic to other LOCAL devices, matching
# the exact URI shapes confirmed in the live alert that prompted this fix.
fake_zfx = _FakeZeekFxForDiscovery(
    http_reqs={DISCOVERY_SRC: {
        "192.168.1.42:60000/dd.xml",
        "192.168.1.42:8009/apps/com.spotify.Spotify.TVv2",
        "192.168.1.44:8008/ssdp/device-desc.xml",
    }},
    home_ips={"192.168.1.42", "192.168.1.44"},
)
count_discovery = _count_local_device_discovery_requests(fake_zfx, DISCOVERY_SRC)
check("THE CORE FIX: real Spotify Connect/SSDP discovery requests to other local "
      "devices are correctly counted",
      count_discovery == 3, f"got {count_discovery}")

# E2: the exact SAME requests but to an EXTERNAL (non-home) IP must NOT count -- the
# URI shape alone isn't enough, the destination must genuinely be on the LAN.
fake_zfx_external = _FakeZeekFxForDiscovery(
    http_reqs={DISCOVERY_SRC: {"203.0.113.50:8008/apps/com.spotify.Spotify.TVv2"}},
    home_ips={"192.168.1.42", "192.168.1.44"},
)
count_external = _count_local_device_discovery_requests(fake_zfx_external, DISCOVERY_SRC)
check("REGRESSION GUARD: the SAME discovery-shaped URI to a NON-home IP does not count "
      "-- destination must genuinely be on the LAN",
      count_external == 0, f"got {count_external}")

# E3: ordinary, non-discovery-shaped local HTTP traffic must NOT count either -- this
# isn't "any local HTTP request is benign," only the specific discovery-protocol shapes.
fake_zfx_ordinary = _FakeZeekFxForDiscovery(
    http_reqs={DISCOVERY_SRC: {"192.168.1.94:8080/some/ordinary/path"}},
    home_ips={"192.168.1.94"},
)
count_ordinary = _count_local_device_discovery_requests(fake_zfx_ordinary, DISCOVERY_SRC)
check("REGRESSION GUARD: ordinary local HTTP traffic with no discovery-protocol shape "
      "does not count",
      count_ordinary == 0, f"got {count_ordinary}")

# E4: the hypothesis itself scores correctly and registers in the benign track.
hyp = LocalDeviceDiscoveryHypothesis()
neutral_rep = ReputationVector(domain="", tier=3)
discovery_evidence = [Evidence(type="local_device_discovery", source="zeek", timestamp=time.time(),
                                device="dev1", value=3.0, confidence=0.7, independence_group="local_context")]
score_discovery = hyp.evaluate(discovery_evidence, neutral_rep)
check("LocalDeviceDiscoveryHypothesis scores nonzero when discovery evidence is present",
      score_discovery > 0.0, f"got {score_discovery}")
check("LocalDeviceDiscoveryHypothesis scores 0.0 with no discovery evidence",
      hyp.evaluate([], neutral_rep) == 0.0)
check("THE CORE FIX: LocalDeviceDiscoveryHypothesis is registered in HypothesisEngine's "
      "benign_hypotheses list",
      any(isinstance(h, LocalDeviceDiscoveryHypothesis) for h in HypothesisEngine().benign_hypotheses))

# E5: end-to-end -- a weak, single-source attack signal is dampened by competing
# discovery evidence in the SAME evaluation, without needing to touch decision_engine.py
# directly (verifies the engine-level competition, matching how it's actually used).
engine = HypothesisEngine()
weak_attack_and_discovery = discovery_evidence + [
    Evidence(type="zeek_conn_abuse", source="zeek", timestamp=time.time(), device="dev1",
              value=5.0, confidence=0.5, independence_group="zeek_network"),
]
result = engine.evaluate_all(weak_attack_and_discovery, neutral_rep)
check("end-to-end: HypothesisEngine.evaluate_all() reports a real benign score "
      "(LOCAL_DEVICE_DISCOVERY) alongside whatever attack hypothesis fired, not just "
      "the default UNKNOWN_BENIGN placeholder",
      result["benign"]["name"] == "LOCAL_DEVICE_DISCOVERY", f"got benign={result['benign']}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: alert-text wording fixes (reviewer suggestions, implemented)
# ═══════════════════════════════════════════════════════════════════════════════════
check("THE FIX: the 'Lateral Scans' alert line now shows the distinct-target count "
      "alongside the port list, not just the ports -- the exact numbers that now "
      "actually gate containment",
      "distinct target(s)" in pipeline_src)
check("THE FIX (superseded by the Phase 28/37 alert redesign -- _build_confidence_line() "
      "now owns this, tested directly in test_phase28_alert_redesign.py): a Stage-1 "
      "hard-stop's confidence line no longer displays a bare '0%' (a hardcoded "
      "categorical value, not a computed probability) -- pipeline.py still routes "
      "through the same HARD_STOP check, just via the reconciled helper now",
      '"HARD_STOP" in fp_stage' in pipeline_src and "not a probabilistic estimate" in pipeline_src)
check("REGRESSION GUARD: pipeline.py's CONFIDENCE line is built via the reconciled "
      "_build_confidence_line() helper (VERSION 11's calibration-aware fp_score label "
      "folded in -- see test_phase28_alert_redesign.py for direct coverage of the "
      "helper itself), not the old two-separate-percentages format",
      "confidence_label, confidence_line, mixed_signal = _build_confidence_line(" in pipeline_src)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section G: reputation-attribution fix -- a MUCH deeper instance of the same bug
# class, found via third-party review of a real CRITICAL/"Confirmed Malicious IOC"
# alert for c.pki.goog (Google's own certificate-revocation infrastructure).
# ti_risk/abuse_risk/vt_risk are each a MAX across this device's several recent
# domains and its single dest_ip, with no tracking of WHICH domain/IP actually
# produced that max -- rep_classifier.classify(top_domain, ti_score=ti_risk, ...)
# then blamed top_domain (a separate, "_select_target_domain()-picked most notable
# domain in the window" value) for a risk score that may have come from a
# completely different domain/IP the same device also touched. Explicitly NOT fixed
# by adding c.pki.goog to any allowlist (would only mask this one instance) --
# reputation_target now tracks the actual source of the risk.
# ═══════════════════════════════════════════════════════════════════════════════════
check("THE CORE FIX: reputation_target is now tracked separately from top_domain, "
      "initialized to top_domain but updated whenever a HIGHER risk is found "
      "elsewhere",
      "reputation_target = top_domain" in pipeline_src)
check("THE CORE FIX: the ti_risk domain-loop updates reputation_target to the SPECIFIC "
      "domain that produced a new max, not just the running risk number",
      "if cur_risk > ti_risk:\n                            ti_risk = cur_risk\n                            reputation_target = domain" in pipeline_src)
check("THE CORE FIX: the ti_risk IP lookup updates reputation_target to dest_ip when "
      "THAT'S what produced the max",
      "if cur_ip_risk > ti_risk:\n                            ti_risk = cur_ip_risk\n                            reputation_target = dest_ip" in pipeline_src)
check("THE CORE FIX: abuse_risk (always IP-sourced when nonzero) updates "
      "reputation_target to dest_ip when it exceeds the running best",
      "if abuse_risk > _best_risk_seen:\n                    _best_risk_seen = abuse_risk\n                    reputation_target = dest_ip" in pipeline_src)
check("THE CORE FIX: vt_risk tracks whether its max came from the IP or domain "
      "contribution, and updates reputation_target to whichever one actually won",
      "if vt_ip_risk >= vt_domain_risk:" in pipeline_src and "vt_risk_source = dest_ip" in pipeline_src and "vt_risk_source = top_domain" in pipeline_src)
check("THE CORE FIX: the actual classifier call now uses reputation_target, not the "
      "raw top_domain",
      "self.rep_classifier.classify(reputation_target, vt_score=vt_risk" in pipeline_src)
check("REGRESSION GUARD: the old call site passing top_domain directly to classify() "
      "is gone",
      "self.rep_classifier.classify(top_domain, vt_score=vt_risk" not in pipeline_src)
check("THE FIX: the alert-building side also got a 'Confirmed Malicious IOC' branch "
      "(matching decision_engine.py's exact tier-5 explanation string) so the alert "
      "displays/records the real reputation_target, not target_malicious_domain",
      'elif primary_sig_base == "Confirmed Malicious IOC":' in pipeline_src)
check("THE FIX: that branch correctly routes an IP-shaped reputation_target to "
      "alert_dest_ip (not alert_target_domain) -- abuse_risk/vt_risk's IP-only "
      "signals produce an IP, not a domain",
      "ipaddress.ip_address(reputation_target)" in pipeline_src and "alert_dest_ip = reputation_target" in pipeline_src)

# Mirror the actual attribution logic (the real code has side effects -- API enqueue
# calls -- not practical to exercise directly in a unit test) to prove the priority
# rule itself is correct, matching the exact structure pipeline.py now uses.
def _resolve_reputation_target(top_domain, ti_hits, ti_ip_hit, dest_ip, abuse_risk, vt_ip_risk, vt_domain_risk):
    """ti_hits: list of (domain, risk) tuples simulating the domain-loop.
    ti_ip_hit: (risk) or None, simulating the dest_ip TI lookup."""
    reputation_target = top_domain
    ti_risk = 0.0
    for domain, cur_risk in ti_hits:
        if cur_risk > ti_risk:
            ti_risk = cur_risk
            reputation_target = domain
    if ti_ip_hit is not None and ti_ip_hit > ti_risk:
        ti_risk = ti_ip_hit
        reputation_target = dest_ip
    best = ti_risk
    if abuse_risk > best:
        best = abuse_risk
        reputation_target = dest_ip
    if vt_ip_risk >= vt_domain_risk:
        vt_risk, vt_source = vt_ip_risk, dest_ip
    else:
        vt_risk, vt_source = vt_domain_risk, top_domain
    if vt_risk > 0 and vt_risk > best:
        best = vt_risk
        reputation_target = vt_source
    return reputation_target

check("SIMULATION: no risk anywhere -> top_domain is used, nothing to misattribute",
      _resolve_reputation_target("c.pki.goog", [], None, "8.8.8.8", 0.0, 0.0, 0.0) == "c.pki.goog")
check("SIMULATION: THE EXACT INCIDENT -- top_domain (c.pki.goog) has zero risk, but a "
      "DIFFERENT domain this device also queried has a real TI hit -> that domain is "
      "blamed, not c.pki.goog",
      _resolve_reputation_target("c.pki.goog", [("xkqz289dfj10dj-393.ru", 3.2)], None,
                                  "142.250.1.1", 0.0, 0.0, 0.0) == "xkqz289dfj10dj-393.ru")
check("SIMULATION: abuse_risk (IP-only) is the highest signal -> dest_ip is blamed, "
      "not top_domain",
      _resolve_reputation_target("c.pki.goog", [], None, "203.0.113.7", 4.0, 0.0, 0.0) == "203.0.113.7")
check("SIMULATION: vt_risk's IP contribution wins over its domain contribution -> "
      "dest_ip is blamed",
      _resolve_reputation_target("c.pki.goog", [], None, "203.0.113.7", 0.0, 3.0, 1.0) == "203.0.113.7")
check("SIMULATION: vt_risk's DOMAIN contribution wins, and that domain IS top_domain "
      "-> top_domain is correctly blamed (a real hit against it, not misattribution)",
      _resolve_reputation_target("actually-bad.example", [], None, "8.8.8.8", 0.0, 0.5, 3.0) == "actually-bad.example")
check("SIMULATION: multiple signals present -- the SINGLE highest one wins, not the "
      "first one found",
      _resolve_reputation_target("c.pki.goog", [("some-domain.example", 1.0)], None,
                                  "203.0.113.7", 4.0, 0.0, 0.0) == "203.0.113.7")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section H: surface the real Zeek notice type/reason in the alert (reviewer
# suggestion, implemented). Previously every alert's WHY line said the same generic
# "Zeek policy notice fired for this connection" regardless of whether the underlying
# notice was something genuinely alarming (e.g. SSL::Invalid_Server_Cert) or routine --
# get_alerts() already carried the real note/msg text, it just never survived past
# ZeekNetworkDetector into the Evidence object.
# ═══════════════════════════════════════════════════════════════════════════════════
from intelligence.detectors.zeek_network import ZeekNetworkDetector

detector = ZeekNetworkDetector()
notice_events = [{"type": "zeek_notice", "note": "SSL::Invalid_Server_Cert",
                   "msg": "certificate validation failed", "dest_port": 443, "confidence": 0.75}]
notice_evidence = detector.detect("dev1", notice_events)
check("THE CORE FIX: ZeekNetworkDetector carries the real notice type into "
      "Evidence.provenance, not a generic fixed string",
      bool(notice_evidence) and notice_evidence[0].provenance == "detector:zeek:notice:SSL::Invalid_Server_Cert",
      f"got provenance={notice_evidence[0].provenance if notice_evidence else 'NO EVIDENCE'}")

from core.pipeline import _describe_evidence as _describe_evidence_real
description = _describe_evidence_real(notice_evidence[0])
check("THE CORE FIX: _describe_evidence() surfaces the real notice type in the WHY line",
      "SSL::Invalid_Server_Cert" in description, f"got '{description}'")

# REGRESSION GUARD: a notice with no real type (malformed/missing) doesn't show a
# useless "unknown" suffix.
unknown_events = [{"type": "zeek_notice", "note": "", "msg": "", "dest_port": 0, "confidence": 0.75}]
unknown_evidence = detector.detect("dev1", unknown_events)
description_unknown = _describe_evidence_real(unknown_evidence[0])
check("REGRESSION GUARD: a notice with no real type shows the plain description with "
      "no 'unknown' suffix clutter",
      description_unknown == "Zeek policy notice fired for this connection", f"got '{description_unknown}'")

# REGRESSION GUARD: malicious_ja3/malicious_ja4 evidence (the other two types this same
# detector emits) are unaffected by the notice-specific change.
tls_events = [{"type": "malicious_ja3", "ja3": "abc123", "dest_port": 443, "confidence": 0.95}]
tls_evidence = detector.detect("dev1", tls_events)
check("REGRESSION GUARD: malicious_ja3 evidence is unaffected by the zeek_notice change",
      bool(tls_evidence) and tls_evidence[0].type == "malicious_ja3" and tls_evidence[0].provenance == "detector:zeek:malicious_ja3")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section I: the persistence-escalation suffix bug (found via a live 1.5h alert audit
# of state/alerts.json -- a real "DNS_EVASION (persisted 603s)" alert had fallen back
# to the device's own IDS-server LAN IP as destination_ip and an unrelated domain as
# queried_domain). Cross-cycle persistence-escalation (pipeline.py, Phase 19/Phase 2)
# appends " (persisted Ns)" onto primary_sig -- and N grows every cycle -- whenever a
# SUSPICIOUS signature holds on the same device past suspicious_escalation_seconds.
# Every domain-attribution branch built this session (DNS_COVERT_TUNNELING,
# DGA_BOTNET_C2, DNS_EVASION, Confirmed Malicious IOC), the target_display fallback,
# and the alert repeat-suppression cadence all used exact `primary_sig ==`/`!=`
# comparisons against the clean, un-suffixed names -- so every one of them silently
# broke for a persisted signature, either reintroducing the exact misattribution bugs
# already fixed this session, or (for the cadence gate) spamming an alert every 60s+
# instead of respecting the normal 300s cadence, since the suffix's second-count made
# every cycle look like "a new signature." Fixed with a single
# `primary_sig_base = primary_sig.split(" (persisted ", 1)[0]` (computed once, split on
# " (persisted " rather than a bare space since "Confirmed Malicious IOC" has internal
# spaces of its own) used everywhere primary_sig was previously compared directly.
# ═══════════════════════════════════════════════════════════════════════════════════
import inspect
from core import pipeline as _pipeline_module

_pipeline_src = inspect.getsource(_pipeline_module)


def _strip_persisted_suffix(sig: str) -> str:
    """Mirrors pipeline.py's primary_sig_base derivation exactly."""
    return sig.split(" (persisted ", 1)[0]


# THE CORE FIX: the split logic itself, against real production-shaped strings.
check("THE CORE FIX: a fresh (non-persisted) signature is returned unchanged",
      _strip_persisted_suffix("DNS_EVASION") == "DNS_EVASION")
check("THE CORE FIX: the exact production string strips down to the clean signature",
      _strip_persisted_suffix("DNS_EVASION (persisted 603s)") == "DNS_EVASION")
check("THE CORE FIX: a persisted signature with internal spaces of its own "
      "('Confirmed Malicious IOC') still strips correctly, since the split key is "
      "' (persisted ' not a bare space",
      _strip_persisted_suffix("Confirmed Malicious IOC (persisted 120s)") == "Confirmed Malicious IOC")
check("THE CORE FIX: DNS_COVERT_TUNNELING strips correctly",
      _strip_persisted_suffix("DNS_COVERT_TUNNELING (persisted 4500s)") == "DNS_COVERT_TUNNELING")
check("THE CORE FIX: DGA_BOTNET_C2 strips correctly",
      _strip_persisted_suffix("DGA_BOTNET_C2 (persisted 61s)") == "DGA_BOTNET_C2")

# SOURCE-GUARD: primary_sig_base actually exists and every domain-attribution branch,
# the target_display fallback, and the repeat-suppression gate all key off it, not the
# raw (potentially-suffixed) primary_sig.
check("SOURCE-GUARD: primary_sig_base is derived via the persisted-suffix split",
      'primary_sig_base = primary_sig.split(" (persisted ", 1)[0]' in _pipeline_src)
check("SOURCE-GUARD: the DNS_EVASION dest-IP branch keys off primary_sig_base",
      'if primary_sig_base in ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS"):' in _pipeline_src)
check("SOURCE-GUARD: the DNS_COVERT_TUNNELING branch keys off primary_sig_base",
      'if primary_sig_base == "DNS_COVERT_TUNNELING":' in _pipeline_src)
check("SOURCE-GUARD: the DGA_BOTNET_C2 branch keys off primary_sig_base",
      'elif primary_sig_base == "DGA_BOTNET_C2":' in _pipeline_src)
check("SOURCE-GUARD: the DNS_EVASION target-domain branch keys off primary_sig_base",
      'elif primary_sig_base in ("DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS"):' in _pipeline_src)
check("SOURCE-GUARD: the Confirmed Malicious IOC branch keys off primary_sig_base",
      'elif primary_sig_base == "Confirmed Malicious IOC":' in _pipeline_src)
check("SOURCE-GUARD: target_display's DNS_EVASION preference keys off primary_sig_base",
      "primary_sig_base in (\"DNS_EVASION\", \"DNS_ATTRIBUTION_GAP\", \"DNS_POLICY_BYPASS\") and alert_dest_ip and alert_dest_ip != \"unknown\"" in _pipeline_src)
check("SOURCE-GUARD: the repeat-suppression cadence gate keys off primary_sig_base, "
      "not the raw suffixed signature",
      "primary_sig_base != getattr(state, \"last_alert_signature_base\", \"\")" in _pipeline_src)
check("REGRESSION GUARD: no leftover bare `primary_sig ==`/`primary_sig !=` "
      "comparison remains anywhere in the domain-attribution/cadence logic",
      "primary_sig ==" not in _pipeline_src and "primary_sig !=" not in _pipeline_src)

# SOURCE-GUARD: state.py tracks the stable base signature alongside the raw one.
from core import state as _state_module
_state_src = inspect.getsource(_state_module)
check("SOURCE-GUARD: DeviceState initializes last_alert_signature_base",
      "self.last_alert_signature_base = " in _state_src)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All lateral-movement distinct-target checks PASSED.")
