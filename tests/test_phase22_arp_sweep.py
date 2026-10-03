"""
Standalone runtime test for Phase 22 (ARP host-discovery sweep detection). Not part of
the pytest suite -- run directly: `python3 test_phase22_arp_sweep.py`.

Background: part of the reactive-Fritzbox-capture plan (Phase B) -- but genuinely
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
from argus_scenarios import ConnectionAbuseHypothesis
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

# REGRESSION GUARD (2026-09-18, third-party audit's "domain-less-evidence-bleeding"
# finding, investigated and confirmed already closed): zeek_arp_sweep_count and
# zeek_arp_swept_ip_examples are both derived from the IDENTICAL
# `{tpa for ip in ips for _ts, tpa in self._arp_targets.get(ip, [])}` set comprehension
# in zeek_features.py -- structurally, examples can only ever be real swept target IPs
# from that same set, never an unrelated/domain-less placeholder bleeding in. Locking
# this in as a test, not just a one-off trace, so a future change to either field can't
# silently reintroduce the divergence this was checked against.
swept_examples = feats["zeek_arp_swept_ip_examples"]
all_swept_targets = {f"192.168.1.{100 + i}" for i in range(10)}
check("zeek_arp_swept_ip_examples is capped at 5, not the full 10-target count",
      len(swept_examples) == 5, f"got {len(swept_examples)}")
check("every example IP is a genuine swept target from the same set zeek_arp_sweep_count "
      "counts -- never a domain-less/unrelated placeholder",
      set(swept_examples).issubset(all_swept_targets), f"got {swept_examples}")
check("examples are sorted, so the same underlying set always yields the same reported "
      "examples (not an arbitrary/unstable dict-order sample)",
      swept_examples == sorted(swept_examples))


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
check("arp_sweep + zeek_conn_abuse (two categories) reaches 3.0 but not the 4.0 ceiling: co-occurrence alone is "
      "not enough, the top rung needs genuine within-category intensity (weight >= 0.85)",
      score_both == 3.0, f"got {score_both}")

trusted_rep = ReputationVector(domain="", tier=1)
score_trusted = hyp.evaluate(arp_only, trusted_rep)
check("a tier-1/2 trusted device's arp_sweep is dampened by the contradicting-score path",
      score_trusted < score_arp_only, f"got {score_trusted} vs {score_arp_only}")


# ═══════════════════════════════════════════════════════════════════════════════════
# BUGFIX regression guards (found via a live state-folder audit, post-v9.0.0 restart):
# arp_sweep evidence (independence_group="lan_recon", added in Phase 21B) was never
# added to pipeline.py's two existing "dampen behavioral noise for infrastructure"
# exclusion sets, both written before arp_sweep existed. A router/gateway ARPs its
# entire LAN as routine DHCP/ARP-table/mesh-sync behavior -- confirmed live: this
# network's own Fritzbox (192.168.1.1, in safe_ips) generated repeated
# CONNECTION_ABUSE alerts against its own mesh repeaters (.2/.3, also in safe_ips)
# purely from zeek_arp_sweep_count=14, and a SEPARATE, unrelated ARP-spoofing
# hard-stop (decision_engine.py's has_arp_spoof, CRITICAL/block, zero corroboration)
# was ALSO reaching those same safe_ips-listed repeaters, since it was never gated on
# is_safe/safe_ips at all -- unlike every other behavioral noise source. Both are
# source-guard checks (this logic lives deep in pipeline.py's per-device loop, not
# practically unit-testable in isolation without mocking the whole pipeline).
# ═══════════════════════════════════════════════════════════════════════════════════
_pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")

check("THE FIX: the is_safe noisy_types set now includes 'lan_recon' (arp_sweep's "
      "independence_group), alongside the pre-existing zeek_network/dns/ml_anomaly "
      "exclusions",
      'noisy_types = {"ml_anomaly", "dns_rate", "dns_entropy", "dns_unique_ratio", "zeek_network", "lan_recon", "dns_evasion_anomaly"}' in _pipeline_src)
check("THE FIX: the sibling _INFRA_NOISY_TYPES set (operator-confirmed infra devices) "
      "now includes 'arp_sweep' too",
      '"arp_sweep"' in _pipeline_src.split("_INFRA_NOISY_TYPES = {")[1].split("}")[0])
check("THE FIX: the ARP-spoofing hard-stop Evidence injection is now gated on "
      "'if is_safe:' (skip) / else (inject) -- a safe_ips-listed IP's own MAC-flip "
      "heuristic no longer bypasses the same trust promise every other behavioral "
      "signal already honors",
      "if is_safe:" in _pipeline_src.split('LOGGER.critical(f"Adding HARD-STOP evidence for ARP Spoofing')[0][-400:])
check("REGRESSION GUARD: the ARP-spoofing hard-stop Evidence is still actually added "
      "for the non-safe case (the fix must not have deleted real detection)",
      'self.evidence_store.add(Evidence(type="arp_spoofing"' in _pipeline_src)

# BUGFIX (found in the SAME live audit): is_safe checked only the single current
# client_ip against safe_ips -- but a device with multiple known addresses (IPv4 +
# IPv6 forms, unified under one dev_id by MAC correlation) can have client_ip snapshot
# to any ONE of them cycle to cycle. Confirmed live: this network's own Fritzbox
# (safe_ips lists only its IPv4 192.168.1.1) still alerted at risk=8.5 in a cycle
# where client_ip was its IPv6 link-local address instead -- same device, same
# known_ips set, is_safe simply never checked the other addresses.
check("THE FIX: is_safe now also checks membership across known_ips_snapshot (every "
      "address this device is known to answer to), not just the single current "
      "client_ip snapshot",
      "any(ip in safe_ips for ip in known_ips_snapshot)" in _pipeline_src)
check("REGRESSION GUARD: the original client_ip check and the hostname-pattern check "
      "are both still present -- the fix is additive, not a replacement",
      "client_ip in safe_ips" in _pipeline_src and "pat in hostname.lower()" in _pipeline_src)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 22 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 22 ARP-sweep detection checks PASSED.")
    sys.exit(0)
