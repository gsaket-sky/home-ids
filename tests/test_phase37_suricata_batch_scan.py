"""
Standalone runtime test for Phase 37 (VERSION 11): batch-mode Suricata signature
scan. Not part of the pytest suite -- run directly:
`python3 tests/test_phase37_suricata_batch_scan.py`.

No real Suricata binary is needed for any of this -- the subprocess-invocation
function (run_suricata_on_pcap) is tested only for its graceful-failure behavior
(missing binary/rules path), matching how this codebase tests reprocess_with_zeek()
elsewhere; everything downstream of "here is a parsed eve.json" is tested against
synthetic data, the same way dns_evasion.py's tests never need a real Zeek capture.

Covers:
  A. run_suricata_on_pcap() -- missing binary and missing/empty rules_path both fail
     gracefully (empty list, no exception), matching every other reactive-capture
     stage's non-fatal-failure style.
  B. _parse_eve_json_alerts() -- extracts only event_type=="alert" records from a
     mixed synthetic eve.json.
  C. build_ip_to_device_map() -- correct device attribution from a minimal mock
     StateManager.
  D. suricata_alerts_to_evidence() -- device attribution via either src_ip or
     dest_ip, severity->confidence mapping, and Evidence field shape.
  E. SuricataSignatureHypothesis -- scoring behavior (single hit, 2+ hit "strong"
     bonus, trusted-tier dampening).
  F. decision_engine.py's has_confirmed_exploit hard-stop -- fires only at
     confidence>=0.9 (Suricata severity=1/"high"), not on weaker severity=2/3 hits.
  G. Registration: SuricataSignatureHypothesis in HypothesisEngine.attack_hypotheses,
     "suricata" in EVIDENCE_FAMILIES/ATTACK_EVIDENCE_FAMILIES.
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.detectors.suricata_scan import (
    run_suricata_on_pcap, _parse_eve_json_alerts, build_ip_to_device_map,
    suricata_alerts_to_evidence,
)
from intelligence.hypotheses.engine import SuricataSignatureHypothesis, HypothesisEngine
from intelligence.hypotheses.evidence import Evidence, EvidenceStore, EVIDENCE_FAMILIES, ATTACK_EVIDENCE_FAMILIES
from intelligence.reputation.classifier import ReputationVector
from core.decision_engine import DecisionEngine


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: run_suricata_on_pcap() graceful failure
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    tmp = _PathForSysPath(tmpdir)
    fake_pcap = tmp / "burst.pcap"
    fake_pcap.write_bytes(b"not a real pcap")

    result_missing_rules = run_suricata_on_pcap(fake_pcap, tmp / "scratch1", "/usr/bin/suricata", "")
    check("empty rules_path returns [] without attempting to invoke the binary",
          result_missing_rules == [])

    fake_rules = tmp / "does_not_exist.rules"
    result_missing_rules2 = run_suricata_on_pcap(fake_pcap, tmp / "scratch2", "/usr/bin/suricata", str(fake_rules))
    check("a rules_path that doesn't exist on disk returns [] without attempting to invoke the binary",
          result_missing_rules2 == [])

    real_rules = tmp / "real.rules"
    real_rules.write_text('alert tcp any any -> any any (msg:"test"; sid:1;)\n', encoding="utf-8")
    result_missing_binary = run_suricata_on_pcap(fake_pcap, tmp / "scratch3", "/nonexistent/suricata/binary", str(real_rules))
    check("a nonexistent suricata binary path returns [] gracefully (FileNotFoundError caught), no exception raised",
          result_missing_binary == [])

    # BUGFIX regression guard (2026-09-07, live incident: 151 timeouts / 0 successful
    # scans in 48h on `.94`, root-caused to --runmode=single pinning an 8-core box to
    # one core against real burst sizes). CORRECTED same day: an initial fix to
    # --runmode=workers was itself wrong -- "workers" isn't a valid PCAP_FILE
    # (offline, `-r`) runmode, confirmed live via journalctl ("custom type 'workers'
    # doesn't exist for this runmode type 'PCAP_FILE'"), exiting 1 immediately with
    # zero findings. --runmode=autofp is PCAP_FILE's real multi-threaded option.
    from unittest.mock import patch as _patch, MagicMock as _MagicMock
    with _patch("intelligence.detectors.suricata_scan.subprocess.run") as mock_run:
        mock_run.return_value = _MagicMock(returncode=0, stderr="")
        run_suricata_on_pcap(fake_pcap, tmp / "scratch4", "/usr/bin/suricata", str(real_rules))
        called_cmd = mock_run.call_args.args[0]
        check("REGRESSION GUARD: the real Suricata invocation uses --runmode=autofp, "
              "the actual valid multi-threaded runmode for offline pcap (-r) mode",
              "--runmode=autofp" in called_cmd)
        check("REGRESSION GUARD: --runmode=single never reappears",
              "--runmode=single" not in called_cmd)
        check("REGRESSION GUARD: --runmode=workers never reappears -- confirmed "
              "invalid for PCAP_FILE mode by Suricata itself, live on `.94`",
              "--runmode=workers" not in called_cmd)

    # 2026-09-07, second live incident same day: soc.service's own CPUQuota=40% cgroup
    # cap is inherited by any child it spawns, including a batch scan -- confirmed live
    # to cause 240s timeouts with 6+ of 8 real cores idle. cgroup_isolate=True should
    # wrap the invocation in `sudo systemd-run --scope` into its own slice; default
    # (False) and "systemd-run not on PATH" must both fall back to the plain command.
    if not hasattr(os, "getuid"):
        print("[SKIP] cgroup_isolate wrapping checks -- os.getuid() is POSIX-only "
              "(this dev box is Windows); the feature is inert here by the same guard "
              "that makes it inert, so there's nothing real to assert against.")
    else:
        with _patch("intelligence.detectors.suricata_scan.subprocess.run") as mock_run, \
             _patch("intelligence.detectors.suricata_scan.shutil.which", return_value="/usr/bin/x"):
            mock_run.return_value = _MagicMock(returncode=0, stderr="")
            run_suricata_on_pcap(fake_pcap, tmp / "scratch5", "/usr/bin/suricata", str(real_rules),
                                  cgroup_isolate=True, cpu_quota_percent=250.0)
            called_cmd = mock_run.call_args.args[0]
            check("cgroup_isolate=True + systemd-run/sudo present wraps with sudo systemd-run --scope",
                  called_cmd[:2] == ["sudo", "systemd-run"])
            check("the transient scope is auto-collected on exit (never lingers)",
                  "--collect" in called_cmd)
            check("CPUQuota is threaded through to the transient slice",
                  "-p" in called_cmd and "CPUQuota=250%" in called_cmd)
            check("the real suricata invocation is still present, unmodified, after the wrapper",
                  "/usr/bin/suricata" in called_cmd and "--runmode=autofp" in called_cmd)
            check("the wrapper preserves the caller's own uid/gid, never a hardcoded username",
                  any(a == f"--uid={os.getuid()}" for a in called_cmd)
                  and any(a == f"--gid={os.getgid()}" for a in called_cmd))

    with _patch("intelligence.detectors.suricata_scan.subprocess.run") as mock_run:
        mock_run.return_value = _MagicMock(returncode=0, stderr="")
        run_suricata_on_pcap(fake_pcap, tmp / "scratch6", "/usr/bin/suricata", str(real_rules),
                              cgroup_isolate=False)
        called_cmd = mock_run.call_args.args[0]
        check("cgroup_isolate=False (the default) never wraps the command",
              called_cmd[0] == "/usr/bin/suricata")

    with _patch("intelligence.detectors.suricata_scan.subprocess.run") as mock_run, \
         _patch("intelligence.detectors.suricata_scan.shutil.which", return_value=None):
        mock_run.return_value = _MagicMock(returncode=0, stderr="")
        run_suricata_on_pcap(fake_pcap, tmp / "scratch7", "/usr/bin/suricata", str(real_rules),
                              cgroup_isolate=True)
        called_cmd = mock_run.call_args.args[0]
        check("cgroup_isolate=True but systemd-run/sudo missing (e.g. this dev box, most "
              "test environments) falls back to the plain invocation, never raises",
              called_cmd[0] == "/usr/bin/suricata")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: _parse_eve_json_alerts()
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    eve_path = _PathForSysPath(tmpdir) / "eve.json"
    records = [
        {"event_type": "stats", "timestamp": "2026-08-23T10:00:00"},
        {"event_type": "alert", "src_ip": "192.168.1.50", "dest_ip": "203.0.113.10",
         "alert": {"signature": "ET MALWARE Generic C2 Checkin", "signature_id": 2001, "category": "A Network Trojan was detected", "severity": 1}},
        {"event_type": "flow", "timestamp": "2026-08-23T10:00:01"},
        {"event_type": "alert", "src_ip": "192.168.1.51", "dest_ip": "203.0.113.20",
         "alert": {"signature": "ET INFO Suspicious User Agent", "signature_id": 2002, "category": "Misc activity", "severity": 3}},
        "",  # blank line, must be skipped
        "not valid json {{{",  # malformed line, must be skipped without crashing
    ]
    with eve_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write((json.dumps(r) if isinstance(r, dict) else r) + "\n")

    alerts = _parse_eve_json_alerts(eve_path)
    check("only event_type=='alert' records are extracted (2 of 6 lines)",
          len(alerts) == 2, f"got {len(alerts)}")
    check("malformed/blank lines are skipped without raising",
          all(a.get("event_type") == "alert" for a in alerts))

    check("a missing eve.json returns [] rather than raising",
          _parse_eve_json_alerts(_PathForSysPath(tmpdir) / "does_not_exist.json") == [])


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: build_ip_to_device_map()
# ═══════════════════════════════════════════════════════════════════════════════════
class _MockState:
    def __init__(self, client_ip):
        self.client_ip = client_ip


class _MockCtx:
    def __init__(self, state):
        self._state = state

    def __enter__(self):
        return self._state

    def __exit__(self, *a):
        return False


class _MockStateManager:
    def __init__(self, devices):
        self._devices = devices  # {dev_id: client_ip}

    def get_all_device_ids(self):
        return list(self._devices.keys())

    def lock_device(self, dev_id):
        if dev_id not in self._devices:
            raise KeyError(dev_id)
        return _MockCtx(_MockState(self._devices[dev_id]))


mock_sm = _MockStateManager({"dev_a": "192.168.1.50", "dev_b": "192.168.1.51"})
ip_map = build_ip_to_device_map(mock_sm)
check("build_ip_to_device_map() correctly maps client_ip -> device_id for every tracked device",
      ip_map == {"192.168.1.50": "dev_a", "192.168.1.51": "dev_b"}, f"got {ip_map}")
check("build_ip_to_device_map() with state_manager=None returns an empty dict, not a crash",
      build_ip_to_device_map(None) == {})


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: suricata_alerts_to_evidence()
# ═══════════════════════════════════════════════════════════════════════════════════
capture_ts = time.time()
raw_alerts = [
    {"src_ip": "192.168.1.50", "dest_ip": "203.0.113.10",
     "alert": {"signature": "ET MALWARE Generic C2 Checkin", "signature_id": 2001,
               "category": "A Network Trojan was detected", "severity": 1}},
    {"src_ip": "203.0.113.99", "dest_ip": "192.168.1.51",  # device is the DEST this time
     "alert": {"signature": "ET INFO Suspicious User Agent", "signature_id": 2002,
               "category": "Misc activity", "severity": 3}},
    {"src_ip": "203.0.113.1", "dest_ip": "203.0.113.2",  # neither side is a tracked device
     "alert": {"signature": "unrelated", "signature_id": 9999, "category": "x", "severity": 2}},
]
ev_by_device = suricata_alerts_to_evidence(raw_alerts, ip_map, capture_ts)

check("an alert with the device as src_ip is attributed to that device",
      "dev_a" in ev_by_device and len(ev_by_device["dev_a"]) == 1)
check("an alert with the device as dest_ip is ALSO correctly attributed",
      "dev_b" in ev_by_device and len(ev_by_device["dev_b"]) == 1)
check("an alert matching neither side to a tracked device is dropped entirely",
      len(ev_by_device) == 2, f"got devices={list(ev_by_device.keys())}")

sev1_ev = ev_by_device["dev_a"][0]
check("severity=1 (Suricata 'high') maps to confidence 0.95",
      sev1_ev.confidence == 0.95, f"got {sev1_ev.confidence}")
check("Evidence.type is suricata_signature_match",
      sev1_ev.type == "suricata_signature_match")
check("Evidence.independence_group is 'suricata'",
      sev1_ev.independence_group == "suricata")
check("Evidence.domain carries the external target IP, not the tracked device's own IP",
      sev1_ev.domain == "203.0.113.10", f"got {sev1_ev.domain}")
check("Evidence.provenance carries signature_id/category/signature for audit-trail readability",
      "2001" in sev1_ev.provenance and "ET MALWARE Generic C2 Checkin" in sev1_ev.provenance)

sev3_ev = ev_by_device["dev_b"][0]
check("severity=3 (Suricata 'low') maps to a materially lower confidence (0.45) than severity=1",
      sev3_ev.confidence == 0.45, f"got {sev3_ev.confidence}")

no_severity_alert = [{"src_ip": "192.168.1.50", "dest_ip": "203.0.113.10",
                       "alert": {"signature": "no severity field", "signature_id": 3001, "category": "x"}}]
ev_no_sev = suricata_alerts_to_evidence(no_severity_alert, ip_map, capture_ts)
check("a missing severity field falls back to the default confidence (0.5) rather than crashing",
      ev_no_sev["dev_a"][0].confidence == 0.5, f"got {ev_no_sev}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: SuricataSignatureHypothesis
# ═══════════════════════════════════════════════════════════════════════════════════
hyp = SuricataSignatureHypothesis()
neutral_rep = ReputationVector(domain="", tier=3)
trusted_rep = ReputationVector(domain="", tier=1)

check("no evidence at all -> hypothesis doesn't fire", hyp.evaluate([], neutral_rep) == 0.0)

single_hit = [Evidence(type="suricata_signature_match", source="suricata", timestamp=time.time(),
                        device="dev1", value=1.0, confidence=0.7, independence_group="suricata")]
score_single = hyp.evaluate(single_hit, neutral_rep)
check("a single moderate-confidence hit satisfies the required condition (score >= 2.0)",
      score_single >= 2.0, f"got {score_single}")

two_hits = single_hit + [Evidence(type="suricata_signature_match", source="suricata", timestamp=time.time(),
                                   device="dev1", value=1.0, confidence=0.95, independence_group="suricata")]
score_two = hyp.evaluate(two_hits, neutral_rep)
check("2+ distinct signature matches reach the 'strong' bonus score (4.0)",
      score_two == 4.0, f"got {score_two}")

score_trusted = hyp.evaluate(single_hit, trusted_rep)
check("a tier-1/2 trusted reputation context dampens the score below the untrusted case",
      score_trusted < score_single, f"got {score_trusted} vs {score_single}")

check("SuricataSignatureHypothesis is registered in HypothesisEngine.attack_hypotheses",
      any(isinstance(h, SuricataSignatureHypothesis) for h in HypothesisEngine().attack_hypotheses))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: decision_engine.py's has_confirmed_exploit hard-stop
# ═══════════════════════════════════════════════════════════════════════════════════
de = DecisionEngine()
store = EvidenceStore()
store.add(Evidence(type="suricata_signature_match", source="suricata", timestamp=time.time(),
                    device="dev_exploit", value=1.0, confidence=0.95, independence_group="suricata"))
decision_high_sev = de.evaluate(store.get_for_device("dev_exploit"), ReputationVector(domain="", tier=3))
check("a severity=1/confidence>=0.9 Suricata match is an explicit CRITICAL hard-stop, "
      "matching the review's 'known malware signature'/'confirmed exploit' hard-stop category",
      decision_high_sev["state"] == "CRITICAL" and decision_high_sev["action"] == "block",
      f"got {decision_high_sev['state']}/{decision_high_sev['action']}")
check("the hard-stop path is recorded as such (decision_path == 'hard_stop')",
      decision_high_sev["decision_path"] == "hard_stop", f"got {decision_high_sev['decision_path']}")

store2 = EvidenceStore()
store2.add(Evidence(type="suricata_signature_match", source="suricata", timestamp=time.time(),
                     device="dev_weak", value=1.0, confidence=0.45, independence_group="suricata"))
decision_low_sev = de.evaluate(store2.get_for_device("dev_weak"), ReputationVector(domain="", tier=3))
check("REGRESSION GUARD: a severity=3/confidence=0.45 Suricata match does NOT hard-stop on its "
      "own -- only genuinely high-severity matches bypass normal corroboration",
      decision_low_sev["state"] != "CRITICAL", f"got {decision_low_sev['state']}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section G: evidence family registration
# ═══════════════════════════════════════════════════════════════════════════════════
check("'suricata' is registered in EVIDENCE_FAMILIES",
      "suricata" in EVIDENCE_FAMILIES)
check("'suricata' counts toward independent attack evidence sources (in ATTACK_EVIDENCE_FAMILIES)",
      "suricata" in ATTACK_EVIDENCE_FAMILIES)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 37 Suricata batch-scan checks PASSED.")
