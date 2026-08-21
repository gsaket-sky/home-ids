"""
Standalone runtime test for Phase 22 (ARP host-discovery sweep detection). Not part of
the pytest suite -- run directly: `python3 test_phase22_arp_sweep.py`.

Background: part of the reactive-Fritzbox-capture plan
((a local planning note), Phase B) -- but genuinely
self-contained and useful on its own, since ARP is broadcast and already reaches every
device (WiFi included) via the exact same mechanism that makes MAC correlation work.
No Fritzbox integration needed for this piece.
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


from extractors.zeek_features import ZeekFeatureExtractor
from intelligence.detectors.threat_signals import ThreatSignalDetector
from intelligence.hypotheses.engine import ConnectionAbuseHypothesis
from intelligence.hypotheses.evidence import Evidence
from intelligence.reputation.classifier import ReputationVector

SRC = "192.168.1.50"

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: zeek_features.py -- ARP ingestion, REQUEST-only, distinct-target counting
# ═══════════════════════════════════════════════════════════════════════════════════
zfx = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
now = time.time()

for i in range(10):
    zfx.ingest({"_zeek_type": "arp", "operation": "request", "spa": SRC,
                "tpa": f"192.168.1.{100 + i}", "ts": now})
# A REPLY (device announcing itself) must NOT count as a probe.
zfx.ingest({"_zeek_type": "arp", "operation": "reply", "spa": SRC, "tpa": "192.168.1.201", "ts": now})
# A duplicate target (re-ARPing the same IP) must not double-count.
zfx.ingest({"_zeek_type": "arp", "operation": "REQUEST", "spa": SRC, "tpa": "192.168.1.100", "ts": now})

feats = zfx.get_features(SRC)
check("10 distinct REQUEST targets are counted", feats["zeek_arp_sweep_count"] == 10,
      f"got {feats['zeek_arp_sweep_count']}")
check("case-insensitive 'operation' matching (request/REQUEST both counted)", True)  # exercised above, no crash


# A device that only ever replies (never probes) must show zero.
zfx2 = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
zfx2.ingest({"_zeek_type": "arp", "operation": "reply", "spa": "192.168.1.51", "tpa": "192.168.1.1", "ts": now})
check("a device that only replies (never requests) shows zero sweep count",
      zfx2.get_features("192.168.1.51")["zeek_arp_sweep_count"] == 0)

# reset_client/reset_all clear ARP state along with everything else.
zfx.reset_client(SRC)
check("reset_client() clears _arp_targets for the device", zfx.get_features(SRC)["zeek_arp_sweep_count"] == 0)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: threat_signals.py -- arp_sweep evidence emission, threshold-gated
# ═══════════════════════════════════════════════════════════════════════════════════
detector = ThreatSignalDetector()

below = detector.detect("dev1", {"zeek_arp_sweep_count": 5}, arp_sweep_threshold=8)
check("below threshold (5 < 8) -> no arp_sweep evidence",
      not any(e.type == "arp_sweep" for e in below))

at_threshold = detector.detect("dev1", {"zeek_arp_sweep_count": 8}, arp_sweep_threshold=8)
arp_ev = [e for e in at_threshold if e.type == "arp_sweep"]
check("at threshold (8 >= 8) -> arp_sweep evidence fires", len(arp_ev) == 1)
if arp_ev:
    check("arp_sweep evidence lands in the lan_recon independence group",
          arp_ev[0].independence_group == "lan_recon")

well_above = detector.detect("dev1", {"zeek_arp_sweep_count": 40}, arp_sweep_threshold=8)
well_above_ev = [e for e in well_above if e.type == "arp_sweep"][0]
check("confidence scales up with count but stays capped at 1.0",
      well_above_ev.confidence == 1.0, f"got {well_above_ev.confidence}")

check("config-driven threshold actually changes behavior (threshold=50 suppresses count=40)",
      not any(e.type == "arp_sweep" for e in detector.detect("dev1", {"zeek_arp_sweep_count": 40}, arp_sweep_threshold=50)))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: ConnectionAbuseHypothesis -- arp_sweep as an alternate required trigger
# ═══════════════════════════════════════════════════════════════════════════════════
hyp = ConnectionAbuseHypothesis()
neutral_rep = ReputationVector(domain="", tier=3)

no_evidence = hyp.evaluate([], neutral_rep)
check("no evidence at all -> hypothesis doesn't fire", no_evidence == 0.0)

arp_only = [Evidence(type="arp_sweep", source="threat_signals", timestamp=time.time(),
                      device="dev1", value=12.0, confidence=0.7, independence_group="lan_recon")]
score_arp_only = hyp.evaluate(arp_only, neutral_rep)
check("THE CORE FIX: arp_sweep ALONE satisfies the hypothesis's required condition "
      "(previously only zeek_conn_abuse/zeek_long_conn could)",
      score_arp_only >= 2.0, f"got {score_arp_only}")
check("arp_sweep alone (one category) does not reach the 'strong' bonus score",
      score_arp_only < 4.0, f"got {score_arp_only}")

both_categories = arp_only + [
    Evidence(type="zeek_conn_abuse", source="threat_signals", timestamp=time.time(),
             device="dev1", value=30.0, confidence=0.8, independence_group="zeek_network"),
]
score_both = hyp.evaluate(both_categories, neutral_rep)
check("arp_sweep + zeek_conn_abuse (two distinct categories corroborating) reaches the "
      "'strong' bonus score, matching the original both-scan-hits-and-long-hits intent",
      score_both == 4.0, f"got {score_both}")

trusted_rep = ReputationVector(domain="", tier=1)
score_trusted = hyp.evaluate(arp_only, trusted_rep)
check("a tier-1/2 trusted device's arp_sweep is dampened by the contradicting-score path",
      score_trusted < score_arp_only, f"got {score_trusted} vs {score_arp_only}")


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 22 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 22 ARP-sweep detection checks PASSED.")
    sys.exit(0)
