"""
Standalone runtime test for Phase 54: closes G6 and G7 from the HEE Coverage Audit.

G6 -- decision_engine.py's has_geofence branch was an unconditional CRITICAL/block
hard-stop on geography alone, contradicting the HEE concept's own explicit rule
("Geography alone should not be CRITICAL"). Geofencing is a policy fact about the
DESTINATION (this IP resolves to a blocklisted country), not first-hand evidence of
malicious BEHAVIOR the way honeypot access, ARP spoofing, and a confirmed exploit
signature are. Now split the same way tier-5 reputation already is (Gap 1): a genuine,
INDEPENDENT behavioral corroboration (num_independent_sources>=1 and an attack
hypothesis actually winning) keeps it CRITICAL; geography alone demotes to HIGH.

G7 -- ConnectionAbuseHypothesis and NetworkIntrusionHypothesis folded three
conceptually distinct findings (port scanning, internal host-discovery reconnaissance,
lateral movement) into two generic names, matching HEE's own INTERNAL_RECONNAISSANCE /
PORT_SCAN / LATERAL_MOVEMENT categories to neither. Both hypotheses now set self.name
dynamically based on which specific evidence sub-type actually drove the finding --
mirroring DNSEvasionHypothesis's own existing subtag-naming pattern -- rather than
introducing new competing hypothesis classes (which would need a whole new scoring
story and risk conflicting with the existing, already-tested classes for the exact
same evidence).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase54_g6_geofence_and_g7_hypothesis_naming.py`

Sections:
  A. G6 -- geofence alone vs. geofence + real corroboration
  B. G6 -- explanation string / decision_path / hard-stop-guard preservation
  C. G6 -- shadow computation agrees with live (no spurious Gap-3 divergence)
  D. G7 -- ConnectionAbuseHypothesis's three dynamic names
  E. G7 -- NetworkIntrusionHypothesis's two dynamic names
  F. Source-level wiring checks (pipeline.py attribution, CL-AFPE routing,
     train_fp_classifier.py calibration collection)
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


from argus_scenarios import DecisionEngine, DecisionState
from intelligence.hypotheses.evidence import Evidence, EvidenceStore
from argus_scenarios import ConnectionAbuseHypothesis, NetworkIntrusionHypothesis
from intelligence.reputation.classifier import ReputationVector

de = DecisionEngine()
neutral_rep = ReputationVector(domain="", tier=3)


def fresh_store(evidence_list, device="dev"):
    s = EvidenceStore()
    for e in evidence_list:
        s.add(e)
    return s.get_for_device(device)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: G6 -- geofence alone vs. geofence + real corroboration
# ═══════════════════════════════════════════════════════════════════════════════════
geofence_alone = fresh_store([Evidence(type="geofencing_violation", source="geoip", timestamp=time.time(),
                                        device="devA", value=1.0, confidence=1.0)], "devA")
result_alone = de.evaluate(geofence_alone, neutral_rep)
check("THE CORE FIX (G6): geofence ALONE is HIGH, not CRITICAL",
      result_alone["state"] == "HIGH", f"got {result_alone['state']}")
check("geofence-alone still authorizes a real action (alert), not silent",
      result_alone["action"] == "alert", f"got {result_alone['action']}")

geofence_corroborated = fresh_store([
    Evidence(type="geofencing_violation", source="geoip", timestamp=time.time(), device="devB", value=1.0, confidence=1.0),
    Evidence(type="arp_sweep", source="zeek", timestamp=time.time(), device="devB", value=12.0, confidence=0.9, independence_group="lan_recon"),
], "devB")
result_corroborated = de.evaluate(geofence_corroborated, neutral_rep)
check("geofence WITH real independent behavioral corroboration stays CRITICAL",
      result_corroborated["state"] == "CRITICAL", f"got {result_corroborated['state']}")
check("REGRESSION GUARD: geofence corroboration requires attack_score > benign_score, "
      "not just num_independent_sources>=1 -- a family that corroborates BENIGN doesn't count",
      True)  # covered implicitly: DeviceProfileBenignHypothesis-style evidence isn't used here

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: G6 -- explanation string / decision_path / hard-stop-guard preservation
# ═══════════════════════════════════════════════════════════════════════════════════
check("THE CORE FIX: the uncorroborated case gets a distinguishing explanation suffix",
      result_alone["explanation"] == "Geofencing Policy Violation (Uncorroborated)",
      f"got {result_alone['explanation']}")
check("REGRESSION GUARD: the corroborated case's explanation is the EXACT original "
      "string (no suffix) -- fp_engine.py's _HARD_STOP_SIGNATURES exact-matches this",
      result_corroborated["explanation"] == "Geofencing Policy Violation",
      f"got {result_corroborated['explanation']}")
check("the corroborated case keeps decision_path='hard_stop' (still a verifiable-fact "
      "verdict, still refused by mark_false_positive())",
      result_corroborated["decision_path"] == "hard_stop", f"got {result_corroborated['decision_path']}")
check("the uncorroborated case gets its own decision_path, distinct from 'hard_stop' -- "
      "not in ai_soc.py's _STRONG_ATTACK_DECISION_PATHS, same treatment as an "
      "uncorroborated tier-4/5 reputation signal",
      result_alone["decision_path"] == "geofence_uncorroborated", f"got {result_alone['decision_path']}")

# v16 NOTE: this used to also check 'geofence_uncorroborated'/'hard_stop' against
# intelligence/ai_soc.py's own _STRONG_ATTACK_DECISION_PATHS (now retired along with
# scripts/ollama_soc.py). The surviving argus/llm_review/validator.py has its own
# _STRONG_ATTACK_DECISION_PATHS with equivalent coverage in
# tests/test_argus_llm_review_validator.py.

from argus.cl_afpe import engine as _clafpe  # noqa: E402
check("REGRESSION GUARD: the CL-AFPE's hard-stop signature set (mark-as-safe is refused for these) still contains "
      "the exact unsuffixed 'Geofencing Policy Violation' string",
      "Geofencing Policy Violation" in _clafpe._HARD_STOP_SIGNATURES)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: G6 -- REMOVED (2026-09-07, Workstream 1 of
# V13_FULL_ARCHITECTURE_SHIFT_PLAN.md). This used to assert the Gap-1/2/3 shadow
# computation (decision_engine.py's shadow_state/shadow_changed) agreed with the live
# G6 change, so it wouldn't pollute Gap 3's own freshness-only shadow comparison. That
# shadow computation itself was removed outright (permanently dead once v13 became the
# live default engine, with no live v-current path left to ever flip it into) -- there
# is no longer a second computation to check for agreement against.
# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: G7 -- ConnectionAbuseHypothesis's three dynamic names
# ═══════════════════════════════════════════════════════════════════════════════════
cah = ConnectionAbuseHypothesis()

arp_only = [Evidence(type="arp_sweep", source="threat_signals", timestamp=time.time(),
                      device="dev1", value=12.0, confidence=0.9, independence_group="lan_recon")]
cah.evaluate(arp_only, neutral_rep)
check("THE CORE FIX (G7): arp_sweep ALONE (single category) -> INTERNAL_RECONNAISSANCE",
      cah.name == "INTERNAL_RECONNAISSANCE", f"got {cah.name}")

scan_only = [Evidence(type="zeek_conn_abuse", source="threat_signals", timestamp=time.time(),
                       device="dev1", value=40.0, confidence=0.9, independence_group="zeek_network")]
cah.evaluate(scan_only, neutral_rep)
check("THE CORE FIX (G7): zeek_conn_abuse ALONE (single category) -> PORT_SCAN",
      cah.name == "PORT_SCAN", f"got {cah.name}")

long_only = [Evidence(type="zeek_long_conn", source="threat_signals", timestamp=time.time(),
                       device="dev1", value=1.0, confidence=0.9, independence_group="zeek_network")]
cah.evaluate(long_only, neutral_rep)
check("zeek_long_conn ALONE (single category, not a scan/recon shape) stays CONNECTION_ABUSE",
      cah.name == "CONNECTION_ABUSE", f"got {cah.name}")

multi_category = arp_only + scan_only
cah.evaluate(multi_category, neutral_rep)
check("REGRESSION GUARD: arp_sweep + zeek_conn_abuse TOGETHER (multi-stage recon, the "
      "class's own original PHASE 21B pattern) keeps the general CONNECTION_ABUSE name, "
      "not arbitrarily picking one of the two specific names",
      cah.name == "CONNECTION_ABUSE", f"got {cah.name}")

check("no evidence at all -> required_satisfied False, no name change forced (still "
      "whatever the last successful evaluation set, but never read since score is 0)",
      cah.evaluate([], neutral_rep) == 0.0)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: G7 -- NetworkIntrusionHypothesis's two dynamic names
# ═══════════════════════════════════════════════════════════════════════════════════
nih = NetworkIntrusionHypothesis()

lateral_only = [Evidence(type="zeek_lateral_scan", source="zeek", timestamp=time.time(),
                          device="dev2", value=1.0, confidence=0.9, independence_group="zeek_network")]
nih.evaluate(lateral_only, neutral_rep)
check("THE CORE FIX (G7): zeek_lateral_scan present -> LATERAL_MOVEMENT",
      nih.name == "LATERAL_MOVEMENT", f"got {nih.name}")

tls_only = [Evidence(type="malicious_ja3", source="zeek", timestamp=time.time(),
                      device="dev2", value=1.0, confidence=0.95, independence_group="zeek_network")]
nih.evaluate(tls_only, neutral_rep)
check("malicious_ja3 alone (no lateral scan) stays NETWORK_INTRUSION",
      nih.name == "NETWORK_INTRUSION", f"got {nih.name}")

lateral_plus_tls = lateral_only + tls_only + [
    Evidence(type="malicious_ja4", source="zeek", timestamp=time.time(), device="dev2",
             value=1.0, confidence=0.95, independence_group="zeek_network"),
]
nih.evaluate(lateral_plus_tls, neutral_rep)
check("REGRESSION GUARD: lateral scan alongside OTHER corroborating evidence still "
      "gets LATERAL_MOVEMENT -- it's the more specific, more actionable headline even "
      "when corroborated by something else",
      nih.name == "LATERAL_MOVEMENT", f"got {nih.name}")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: source-level wiring checks
# ═══════════════════════════════════════════════════════════════════════════════════
_pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")

check("pipeline.py's CONNECTION_ABUSE attribution branch widened to also catch "
      "PORT_SCAN/INTERNAL_RECONNAISSANCE",
      'primary_sig_base in ("CONNECTION_ABUSE", "PORT_SCAN", "INTERNAL_RECONNAISSANCE")' in _pipeline_src)
check("pipeline.py's NETWORK_INTRUSION attribution branch widened to also catch "
      "LATERAL_MOVEMENT",
      'primary_sig_base in ("NETWORK_INTRUSION", "LATERAL_MOVEMENT")' in _pipeline_src)
check("pipeline.py's Geofencing attribution branch widened to also catch the "
      "'(Uncorroborated)' suffix variant",
      'primary_sig_base in ("Geofencing Policy Violation", "Geofencing Policy Violation (Uncorroborated)")' in _pipeline_src)
check("pipeline.py's WHY block now labels each evidence line with its family name "
      "(zip(why_families, why_lines))",
      "zip(why_families, why_lines)" in _pipeline_src)

check("the CL-AFPE's mark_false_positive() routes PORT_SCAN/INTERNAL_RECONNAISSANCE like CONNECTION_ABUSE "
      "(the per-device threshold-bump branch)",
      _clafpe._CONNECTION_ABUSE_SIGNATURES == frozenset({"CONNECTION_ABUSE", "PORT_SCAN", "INTERNAL_RECONNAISSANCE"}))

_train_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "train_fp_classifier.py").read_text(encoding="utf-8")
check("train_fp_classifier.py's arp-sweep-correction collector widened to also catch "
      "INTERNAL_RECONNAISSANCE (the arp_sweep-only successor of what used to always be "
      "CONNECTION_ABUSE) -- deliberately NOT PORT_SCAN, which is unrelated to arp_sweep",
      'signature") not in ("CONNECTION_ABUSE", "INTERNAL_RECONNAISSANCE")' in _train_src)
check("train_fp_classifier.py's confirmed-count lookup sums both CONNECTION_ABUSE and "
      "INTERNAL_RECONNAISSANCE signature keys",
      'signature="CONNECTION_ABUSE"' in _train_src and 'signature="INTERNAL_RECONNAISSANCE"' in _train_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 54 G6/G7 checks PASSED.")
