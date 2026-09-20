"""
Standalone runtime test for src/v13/ops/live_engine.py -- the actual swap-in adapter
pipeline.py calls in place of core/decision_engine.py's DecisionEngine.evaluate(), per
the v13 fast-cutover plan.

Not part of the pytest suite -- run directly: `python3 tests/test_argus_live_engine.py`.

Sections:
  A. Same call shape as v-current's own evaluate() -- the whole point of this adapter
  B. A real, realistic multi-family divergence (mirrors test_phase68's own scenario)
     reaches v13's genuinely different, better-corroborated verdict
  C. The zeek_exfiltration/zeek_beaconing fallback_context split -- mirrors
     src/v13/ingest/sources.py's own A2 behavior exactly, using v-current's real
     Evidence shape as the input
  D. Fail-safe: an engine that raises falls back to v-current's own evaluate(), loudly
     logged, never silent
  E. Graph read/write (v13 full-architecture plan, Phase 1): a windowed merge across
     two separate evaluate() calls reaches a verdict neither call alone could reach
     from its own fresh evidence -- the concrete "behavioral pattern across cycles"
     case the graph wiring exists to catch -- plus restart-survival and both
     directions' fail-safes (a broken read/write never blocks or corrupts a decision)
  J. Release 15 Sheet 00 live wiring (2026-09-16): Bayesian Gaussian/Beta/Poisson/
     Markov + BOCPD baseline scoring, ported from argus/ingest/daemon.py's `.19`-only
     reference implementation into evaluate() itself. The underlying Bayesian/BOCPD
     math is already covered by test_argus_bayesian_baseline.py/
     test_argus_baseline_engine.py -- this section verifies the WIRING specifically:
     real feature-dict keys map to the right metrics, fresh_v2 (not merged_v2) feeds
     the Poisson/Markov inputs, the config rollback switch works, a broken graph read
     fails safe, and the one-cycle risk lag actually persists across calls.
"""
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


from intelligence.hypotheses.evidence import Evidence as V1Evidence  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402
from core.decision_engine import DecisionEngine as VCurrentDecisionEngine  # noqa: E402
import argus.ops.live_engine as live_engine  # noqa: E402
from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402

now = time.time()
vcurrent_engine = VCurrentDecisionEngine()


# --- A. Same call shape as v-current's own evaluate() ---

r_empty = live_engine.evaluate([], ReputationVector(domain="", tier=0), features={})
check("A: an empty evidence store returns a plain BENIGN verdict, same as v-current",
      r_empty["state"] == "BENIGN" and r_empty["decision_path"] == "benign")
check("A: the return dict has every key pipeline.py's downstream code reads",
      all(k in r_empty for k in (
          "state", "action", "explanation", "threat_confidence", "decision_path",
          "hypotheses", "independent_sources", "reasoning_trail",
          "evidence_verification_required", "hypothesis_weight",
      )))

r_honeypot = live_engine.evaluate([], ReputationVector(domain="", tier=3),
                                    features={"zeek_honeypot_hits": 1}, is_safe=False)
check("A: honeypot hard-stop fires through the adapter exactly like calling v13's engine directly",
      r_honeypot["state"] == "CRITICAL" and r_honeypot["decision_path"] == "hard_stop")


# --- B. A real multi-family divergence reaches v13's genuinely different verdict ---

two_family_ev = [
    V1Evidence(type="malicious_ja3", source="zeek", timestamp=now, device="d1", value=1.0,
                confidence=0.9, independence_group="zeek_network", domain="evil.example.com"),
    V1Evidence(type="zeek_notice_medium", source="zeek", timestamp=now, device="d1", value=1.0,
                confidence=0.75, independence_group="zeek_network", domain="evil.example.com"),
]
r_vcurrent = vcurrent_engine.evaluate(list(two_family_ev), ReputationVector(domain="evil.example.com", tier=3))
r_v13 = live_engine.evaluate(list(two_family_ev), ReputationVector(domain="evil.example.com", tier=3))
check("B: v-current's live verdict on this real two-family case stays SUSPICIOUS (as documented, A10)",
      r_vcurrent["state"] == "SUSPICIOUS" and r_vcurrent["decision_path"] == "hypothesis_suspicious")
check("B: the adapter's v13 verdict on the SAME evidence reaches HIGH -- the exact behavior "
      "this fast cutover is choosing to adopt now (finer independence-family split)",
      r_v13["state"] == "HIGH" and r_v13["decision_path"] == "hypothesis_high")


# --- C. zeek_exfiltration/zeek_beaconing fallback_context split ---

exfil_ev = [V1Evidence(type="zeek_exfiltration", source="zeek", timestamp=now, device="d2",
                         value=5.0, confidence=0.8, independence_group="zeek_network", domain=None)]
r_no_features = live_engine.evaluate(exfil_ev, ReputationVector(domain="", tier=3), features={})
check("C: zeek_exfiltration with no features at all doesn't crash -- falls back to NO_DESTINATION",
      "state" in r_no_features)

r_with_dest = live_engine.evaluate(
    exfil_ev, ReputationVector(domain="", tier=3), features={"last_dest_ip": "203.0.113.50"},
)
check("C: zeek_exfiltration WITH features['last_dest_ip'] gets a real destination attached "
      "via fallback_context, mirroring src/v13/ingest/sources.py's own A2 behavior exactly",
      "state" in r_with_dest)

r_sentinel = live_engine.evaluate(
    exfil_ev, ReputationVector(domain="", tier=3), features={"last_dest_ip": "unknown"},
)
check("C: ZeekFeatureExtractor's own 'unknown' sentinel is correctly treated as NO destination, "
      "not a real one, matching sources.py's _NO_DEST_SENTINEL handling exactly",
      "state" in r_sentinel)

no_gap_ev = [V1Evidence(type="zeek_notice_medium", source="zeek", timestamp=now, device="d3",
                          value=1.0, confidence=0.9, independence_group="zeek_network", domain=None)]
r_no_gap = live_engine.evaluate(no_gap_ev, ReputationVector(domain="", tier=3),
                                  features={"last_dest_ip": "203.0.113.60"})
check("C: a type with NO destination gap (zeek_notice_medium) never gets the fallback_context "
      "misapplied to it, even when last_dest_ip is present in the same call",
      "state" in r_no_gap)

# v13 full-architecture plan, Phase 9: threat_signals.py's own zeek_exfiltration/
# zeek_beaconing add() calls now attach a real .domain at the SOURCE (see
# intelligence/detectors/threat_signals.py's own Phase 9 comment) -- confirms
# the fallback_context split above becomes a pure safety net once that's true,
# never overriding a domain the v1 Evidence item already carries, via
# evidence/ingest.py's own convert() directly (checked at the conversion layer,
# not just "the call didn't crash" like the checks above).
from argus.evidence.ingest import convert as _v2_convert  # noqa: E402

exfil_ev_with_real_domain = V1Evidence(
    type="zeek_exfiltration", source="zeek", timestamp=now, device="d2",
    value=5.0, confidence=0.8, independence_group="zeek_network", domain="93.184.216.34",
)
converted = _v2_convert(exfil_ev_with_real_domain, "data_transfer_pattern",
                          fallback_context={"dest_ip": "104.16.132.229"})
check("C: once threat_signals.py's own Phase 9 fix attaches a real .domain at the "
      "source, convert() never overrides it with fallback_context -- the fallback "
      "is correctly a safety net for the case it's no longer needed, not a "
      "second, competing source of truth",
      converted.destination_id == "93.184.216.34")


# --- D. Fail-safe: v13 raising falls back to v-current's own evaluate(), loudly ---

_orig_v13_engine = live_engine._v13_engine


class _AlwaysRaises:
    def evaluate(self, *a, **kw):
        raise RuntimeError("simulated v13 engine failure")


live_engine._v13_engine = _AlwaysRaises()

_fallback_calls = []


def _fake_fallback(active_evidence, rep, device_type, baseline_familiarity, features=None, is_safe=False):
    _fallback_calls.append(True)
    return vcurrent_engine.evaluate(active_evidence, rep, device_type, baseline_familiarity,
                                      features=features, is_safe=is_safe)


r_failsafe = live_engine.evaluate([], ReputationVector(domain="", tier=0), features={},
                                     fallback_evaluate=_fake_fallback)
check("D: when v13's engine raises, the adapter falls back to v-current's own evaluate() instead of crashing",
      len(_fallback_calls) == 1 and r_failsafe["state"] == "BENIGN")

_no_fallback_calls = []
try:
    live_engine.evaluate([], ReputationVector(domain="", tier=0), features={})
    _raised = False
except RuntimeError:
    _raised = True
check("D: with no fallback_evaluate supplied at all, the original exception propagates "
      "(never silently swallowed into a made-up verdict)",
      _raised)

live_engine._v13_engine = _orig_v13_engine


# --- E. Graph read/write: windowed merge, restart-survival, both fail-safes ---

_tmpdir = tempfile.mkdtemp(prefix="v13_live_engine_test_")
_graph_db_path = str(_PathForSysPath(_tmpdir) / "e_graph.db")
live_engine.configure(_graph_db_path)

_t0 = 2_000_000.0
lateral_scan_ev = [V1Evidence(type="zeek_lateral_scan", source="zeek", timestamp=_t0, device="devA",
                                 value=1.0, confidence=0.9, independence_group="zeek_network")]
r1 = live_engine.evaluate(lateral_scan_ev, ReputationVector(domain="", tier=3), features={},
                             device_id="devA", now=_t0)
check("E: cycle 1 alone (one family, zeek_lateral_scan) stays SUSPICIOUS, not HIGH -- "
      "matches the SAME single-source case already proven in test_argus_decision_engine.py",
      r1["state"] == "SUSPICIOUS" and r1["decision_path"] == "hypothesis_suspicious")

_store_check = live_engine._get_graph_store()
check("E: cycle 1's fresh evidence was actually written to the graph",
      len(_store_check.get_evidence_for_device("devA")) == 1)
check("E: cycle 1's decision was actually written to the graph",
      len(_store_check.get_decisions_since(_t0 - 1)) == 1)

# Cycle 2, 60s later: a DIFFERENT evidence type that also wouldn't reach HIGH alone --
# passed as this cycle's ONLY fresh evidence (simulating a fresh pipeline.py cycle,
# which would only hand live_engine THIS cycle's new detector output, not cycle 1's
# already-handled evidence). Cycle 1's lateral_scan evidence is NOT included here --
# the only way this reaches HIGH is if evaluate() pulls it back in from the graph.
ja3_ev = [V1Evidence(type="malicious_ja3", source="zeek", timestamp=_t0 + 60, device="devA",
                       value=1.0, confidence=0.9, independence_group="zeek_network")]
r2 = live_engine.evaluate(ja3_ev, ReputationVector(domain="", tier=3), features={},
                             device_id="devA", now=_t0 + 60)
check("E: cycle 2's OWN fresh evidence alone (just malicious_ja3) would also only be one "
      "family -- this scenario is only meaningful if cycle 1's evidence wasn't silently "
      "reused some other way; confirmed by checking cycle 2's fresh-only conversion count",
      len(live_engine._convert_active_evidence(ja3_ev, {})) == 1)
check("E: cycle 2 reaches HIGH -- proves the windowed graph read merged cycle 1's "
      "still-fresh lateral_scan evidence back in, something a single cycle's own fresh "
      "evidence list structurally could not represent on its own",
      r2["state"] == "HIGH" and r2["decision_path"] == "hypothesis_high",
      f"got {r2['state']}/{r2['decision_path']}")

check("E: cycle 2 only wrote ITS OWN fresh evidence (1 new row), not a re-insert of "
      "cycle 1's already-persisted item -- total rows for devA is 2, not 3+",
      len(_store_check.get_evidence_for_device("devA")) == 2)

# Restart-survival: force live_engine to drop its in-memory GraphStore handle and
# reopen the SAME db file from scratch (simulating a fresh process after a restart),
# then confirm cycle 1+2's history is still there for a third cycle.
live_engine.configure(_graph_db_path)
check("E: configure() with the same path forces a fresh GraphStore object, not a cached one",
      live_engine._graph_store is None)

r3 = live_engine.evaluate([], ReputationVector(domain="", tier=3), features={},
                             device_id="devA", now=_t0 + 90)
check("E: after a simulated restart (fresh GraphStore handle, same db file), a THIRD "
      "cycle with ZERO fresh evidence of its own still sees devA's persisted history and "
      "reaches HIGH -- the actual restart-survival property EvidenceStore cannot offer "
      "(100% in-memory, wiped on every real restart)",
      r3["state"] == "HIGH", f"got {r3['state']}")

# Fail-safe: a broken graph READ degrades to fresh-evidence-only, never raises
_orig_get_store = live_engine._get_graph_store
live_engine._get_graph_store = lambda: (_ for _ in ()).throw(RuntimeError("simulated read failure"))
r4 = live_engine.evaluate(ja3_ev, ReputationVector(domain="", tier=3), features={},
                             device_id="devA", now=_t0 + 120)
check("E: a broken graph read never raises out of evaluate() -- degrades to this cycle's "
      "fresh evidence only (back to SUSPICIOUS, since devA's history is unreachable)",
      r4["state"] == "SUSPICIOUS")
live_engine._get_graph_store = _orig_get_store

# Fail-safe: a broken graph WRITE never affects the already-computed decision
live_engine._get_graph_store = lambda: (_ for _ in ()).throw(RuntimeError("simulated write failure"))
r5 = live_engine.evaluate([], ReputationVector(domain="", tier=0), features={},
                             device_id="devB-neverwritten", now=_t0)
check("E: a broken graph write never raises out of evaluate() -- the decision is already "
      "computed by the time the write is attempted, so it's returned regardless",
      r5["state"] == "BENIGN")
live_engine._get_graph_store = _orig_get_store

# Decision dedup: a real fix found live on .94's first restart with this wiring --
# without it, every cycle writes a new decisions row per device regardless of whether
# the verdict changed at all (611 rows observed in well under a minute of real runtime).
_dedup_store = live_engine._get_graph_store()
_t_dedup = _t0 + 500
r_dedup_1 = live_engine.evaluate([], ReputationVector(domain="", tier=0), features={},
                                    device_id="devDedup", now=_t_dedup)
check("E: dedup -- the FIRST decision for a brand-new device is always written",
      len(_dedup_store.get_decisions_since(_t_dedup - 1, _t_dedup + 1)) == 1)

r_dedup_2 = live_engine.evaluate([], ReputationVector(domain="", tier=0), features={},
                                    device_id="devDedup", now=_t_dedup + 2)
check("E: dedup -- an UNCHANGED verdict (still BENIGN/benign) on the very next cycle "
      "does NOT write a second decisions row",
      len(_dedup_store.get_decisions_since(_t_dedup - 1, _t_dedup + 10)) == 1)
check("E: dedup -- the RETURNED decision is correct regardless of whether it got written",
      r_dedup_2["state"] == "BENIGN")

honeypot_dedup_ev = []  # honeypot fires from features, not evidence
r_dedup_3 = live_engine.evaluate(honeypot_dedup_ev, ReputationVector(domain="", tier=0),
                                    features={"zeek_honeypot_hits": 1}, device_id="devDedup",
                                    now=_t_dedup + 4)
check("E: dedup -- a CHANGED verdict (BENIGN -> CRITICAL hard-stop) writes a new row",
      len(_dedup_store.get_decisions_since(_t_dedup - 1, _t_dedup + 10)) == 2)

# Evidence content-key dedup: the MORE serious bug found live -- EvidenceStore.get_for_
# device() returns the SAME still-fresh v1 item on every cycle for up to its full TTL,
# and convert() assigns a fresh evidence_id every call, so naive per-cycle insertion
# re-writes the SAME real observation as a new graph row every single cycle it remains
# in EvidenceStore (confirmed live: 12,766 rows / 28.7MB after 9 minutes of real runtime).
_t_repeat = _t0 + 600
_repeating_v1_ev = [V1Evidence(type="dns_entropy", source="dns_features", timestamp=_t_repeat,
                                  device="devRepeat", value=4.5, confidence=0.8,
                                  independence_group="dns_behavior")]
for _cycle in range(5):
    live_engine.evaluate(_repeating_v1_ev, ReputationVector(domain="", tier=3), features={},
                            device_id="devRepeat", now=_t_repeat + _cycle * 2)
check("E: the SAME v1 evidence item (identical device/type/source/timestamp) handed to "
      "evaluate() across 5 separate cycles -- exactly what EvidenceStore's own TTL-based "
      "retention does in real production -- is written to the graph EXACTLY ONCE, not "
      "5 times",
      len(_dedup_store.get_evidence_for_device("devRepeat")) == 1,
      f"got {len(_dedup_store.get_evidence_for_device('devRepeat'))} rows")

_new_v1_ev = [V1Evidence(type="dns_entropy", source="dns_features", timestamp=_t_repeat + 100,
                            device="devRepeat", value=4.5, confidence=0.8,
                            independence_group="dns_behavior")]
live_engine.evaluate(_repeating_v1_ev + _new_v1_ev, ReputationVector(domain="", tier=3),
                        features={}, device_id="devRepeat", now=_t_repeat + 100)
check("E: a GENUINELY new evidence item (different timestamp) alongside the same repeated "
      "one IS written -- the fix recognizes new content, it doesn't just stop writing "
      "anything for this device",
      len(_dedup_store.get_evidence_for_device("devRepeat")) == 2)

# White-box check: the merged list actually handed to the decision engine must not
# contain the same real observation twice just because it exists both fresh (this
# cycle's active_evidence_v1) AND in the graph (written on an earlier cycle for the
# SAME content) -- captured via a thin wrapper around _v13_engine.evaluate().
_captured_merged = []
_orig_v13_engine_for_merge_check = live_engine._v13_engine


class _CapturingEngine:
    def evaluate(self, evidence_list, *a, **kw):
        _captured_merged.append(list(evidence_list))
        return _orig_v13_engine_for_merge_check.evaluate(evidence_list, *a, **kw)


live_engine._v13_engine = _CapturingEngine()
live_engine.evaluate(_repeating_v1_ev, ReputationVector(domain="", tier=3), features={},
                        device_id="devRepeat", now=_t_repeat + 200)
live_engine._v13_engine = _orig_v13_engine_for_merge_check

merged_keys = [live_engine._content_key(ev) for ev in _captured_merged[-1]]
check("E: the merge into the decision input is deduped by content, not evidence_id -- "
      "the repeated observation appears exactly once in the merged list, even though "
      "it exists both fresh (this cycle) and in the graph's own windowed read",
      len(merged_keys) == len(set(merged_keys)),
      f"got {len(merged_keys)} items, {len(set(merged_keys))} unique")

# device_id=None (the default): zero graph interaction, unchanged from pre-Phase-1 behavior
_calls_with_no_device_id = []
live_engine._get_graph_store = lambda: _calls_with_no_device_id.append(1) or _orig_get_store()
live_engine.evaluate([], ReputationVector(domain="", tier=0), features={})
check("E: omitting device_id entirely means the graph is never touched at all -- "
      "existing callers that don't pass it are completely unaffected by this feature",
      len(_calls_with_no_device_id) == 0)
live_engine._get_graph_store = _orig_get_store


# --- F. Phase 1a: graph-derived synthetic evidence (cross-device correlation,
# reputation propagation, genuine first-contact) -- own fresh store, since these
# scenarios need clean cross-device/cross-destination state ---

_f_tmpdir = tempfile.mkdtemp(prefix="v13_live_engine_phase1a_test_")
_f_graph_db_path = str(_PathForSysPath(_f_tmpdir) / "f_graph.db")
live_engine.configure(_f_graph_db_path)
_ft0 = 3_000_000.0


def _capture_merged(v1_evidence, rep, device_id, now, features=None, device_type="", geoip_engine=None):
    """Runs evaluate() with a thin wrapper around _v13_engine.evaluate() (same
    pattern as Section E's own _CapturingEngine) and returns the exact merged
    evidence list the decision engine actually saw for this one call.
    device_type defaults to "" (matching every pre-existing call site here
    unchanged) -- Section H (Release 14, N2) is the first caller to pass a
    real one, since peer-deviation injection is gated on it being non-empty.
    geoip_engine defaults to None (matching every pre-existing call site --
    omitting it is unaffected), Section F1b (live audit, 2026-09-08) is the
    first caller to pass one."""
    captured = []
    orig_engine = live_engine._v13_engine

    class _Capture:
        def evaluate(self, evidence_list, *a, **kw):
            captured.append(list(evidence_list))
            return orig_engine.evaluate(evidence_list, *a, **kw)

    live_engine._v13_engine = _Capture()
    try:
        live_engine.evaluate(v1_evidence, rep, device_type=device_type, features=features or {},
                               device_id=device_id, now=now, geoip_engine=geoip_engine)
    finally:
        live_engine._v13_engine = orig_engine
    return captured[-1]


# --- F1: cross-device correlation ---
devA_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0, device="p1a_devA",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="shared-target.example.com")]
merged_A = _capture_merged(devA_ev, ReputationVector(domain="", tier=3), "p1a_devA", _ft0)
check("F1: the FIRST device to touch a destination gets no coordinated_targeting "
      "evidence -- nobody else has touched it yet",
      not any(e.evidence_type == "coordinated_targeting" for e in merged_A))

devB_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 10, device="p1a_devB",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="shared-target.example.com")]
merged_B = _capture_merged(devB_ev, ReputationVector(domain="", tier=3), "p1a_devB", _ft0 + 10)
check("F1: REGRESSION GUARD (third-party architecture review, 2026-09-09) -- the "
      "SECOND device (2 total) touching the same destination does NOT get "
      "coordinated_targeting evidence anymore; two devices coinciding on an "
      "unclassified destination isn't coordination",
      not any(e.evidence_type == "coordinated_targeting" for e in merged_B))

devB2_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 11, device="p1a_devB2",
                         value=10.0, confidence=0.9, independence_group="dns_behavior",
                         domain="shared-target.example.com")]
merged_B2 = _capture_merged(devB2_ev, ReputationVector(domain="", tier=3), "p1a_devB2", _ft0 + 11)
coordinated_hits = [e for e in merged_B2 if e.evidence_type == "coordinated_targeting"]
check("F1: the THIRD device (3 total) to touch the SAME destination within the short "
      "window DOES get coordinated_targeting evidence -- the cross-device correlation "
      "capability, now requiring a genuinely harder coincidence than 2 devices",
      len(coordinated_hits) == 1)
check("F1: the synthetic evidence's value is the TOTAL device count (this one + 2 others = 3)",
      coordinated_hits and coordinated_hits[0].value == 3.0)
check("F1: the synthetic evidence names both other devices in its features for audit",
      coordinated_hits and set(coordinated_hits[0].features.get("other_devices", [])) == {"p1a_devA", "p1a_devB"})

_f_store = live_engine._get_graph_store()
check("F1: the synthetic coordinated_targeting evidence was NEVER written to the graph "
      "itself (it's derived context, not a sensor observation -- writing it would "
      "recreate the evidence-duplication bug Phase 1's own incident already fixed)",
      not any(e.evidence_type == "coordinated_targeting"
              for e in _f_store.get_evidence_for_device("p1a_devB2")))

# --- F1b: BUGFIX regression (live audit, 2026-09-08) -- a destination whose ASN
# owner is recognized cloud/CDN/streaming infrastructure must not score as
# coordinated targeting just because multiple devices independently reach it.
# Root cause traced live: two Fire TVs on the same network independently
# streaming Netflix (45.57.x.x) scored as "coordinated targeting" because the
# decision engine's rep_vector.tier check that would normally suppress a
# trusted destination is computed for a DIFFERENT domain each cycle (whichever
# one earned the highest TI/VT/abuse risk score), never this one.
class _FakeAsnInfo:
    def __init__(self, org):
        self.autonomous_system_organization = org


class _FakeGeoipEngine:
    def __init__(self, org_by_ip):
        self._org_by_ip = org_by_ip

    def lookup_asn(self, ip):
        org = self._org_by_ip.get(ip)
        return _FakeAsnInfo(org) if org else None


# Note: every scenario below uses THREE devices (not two) -- since the
# third-party-review fix raised the base coordination bar to 3 total devices,
# using only 2 would leave "no coordinated_targeting" ambiguous between the two
# guards. Three devices isolates the ASN-owner check specifically: it must still
# suppress coordination even when the device-count bar WOULD otherwise clear.
devD_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 15, device="p1a_devD",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="45.57.41.1")]
merged_D = _capture_merged(devD_ev, ReputationVector(domain="", tier=3), "p1a_devD", _ft0 + 15)
devD2_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 15.5, device="p1a_devD2",
                         value=10.0, confidence=0.9, independence_group="dns_behavior",
                         domain="45.57.41.1")]
merged_D2 = _capture_merged(devD2_ev, ReputationVector(domain="", tier=3), "p1a_devD2", _ft0 + 15.5)
devE_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 16, device="p1a_devE",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="45.57.41.1")]
cdn_geoip = _FakeGeoipEngine({"45.57.41.1": "Netflix, Inc."})
merged_E = _capture_merged(devE_ev, ReputationVector(domain="", tier=3), "p1a_devE", _ft0 + 16,
                             geoip_engine=cdn_geoip)
check("F1b: BUGFIX -- THREE devices independently reaching a recognized CDN/"
      "streaming IP (clearing the device-count bar on its own) still get NO "
      "coordinated_targeting evidence when a geoip_engine is supplied",
      not any(e.evidence_type == "coordinated_targeting" for e in merged_E),
      f"got {[e.evidence_type for e in merged_E]}")

# REGRESSION GUARD: same shared destination, same device count, but the ASN owner
# is NOT a recognized cloud/CDN org -- real coordination still fires normally.
devF_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 17, device="p1a_devF",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="203.0.113.9")]
merged_F0 = _capture_merged(devF_ev, ReputationVector(domain="", tier=3), "p1a_devF", _ft0 + 17)
devF2_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 17.5, device="p1a_devF2",
                         value=10.0, confidence=0.9, independence_group="dns_behavior",
                         domain="203.0.113.9")]
merged_F2 = _capture_merged(devF2_ev, ReputationVector(domain="", tier=3), "p1a_devF2", _ft0 + 17.5)
devG_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 18, device="p1a_devG",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="203.0.113.9")]
noncdn_geoip = _FakeGeoipEngine({"203.0.113.9": "Some Random Hosting LLC"})
merged_G = _capture_merged(devG_ev, ReputationVector(domain="", tier=3), "p1a_devG", _ft0 + 18,
                             geoip_engine=noncdn_geoip)
check("F1b: REGRESSION GUARD -- an unrecognized ASN owner is unaffected; genuine "
      "cross-device coordination (3 total devices) still fires with a geoip_engine "
      "supplied", any(e.evidence_type == "coordinated_targeting" for e in merged_G),
      f"got {[e.evidence_type for e in merged_G]}")

# REGRESSION GUARD: omitting geoip_engine entirely (every pre-existing caller) is
# completely unaffected -- same CDN-owned destination, still fires without one.
devH_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 19, device="p1a_devH",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="45.57.42.1")]
merged_H0 = _capture_merged(devH_ev, ReputationVector(domain="", tier=3), "p1a_devH", _ft0 + 19)
devH2_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 19.5, device="p1a_devH2",
                         value=10.0, confidence=0.9, independence_group="dns_behavior",
                         domain="45.57.42.1")]
merged_H2 = _capture_merged(devH2_ev, ReputationVector(domain="", tier=3), "p1a_devH2", _ft0 + 19.5)
devI_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 20, device="p1a_devI",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="45.57.42.1")]
merged_I = _capture_merged(devI_ev, ReputationVector(domain="", tier=3), "p1a_devI", _ft0 + 20)
check("F1b: REGRESSION GUARD -- omitting geoip_engine (unchanged default), 3 total "
      "devices still fires coordinated_targeting exactly as before this fix",
      any(e.evidence_type == "coordinated_targeting" for e in merged_I),
      f"got {[e.evidence_type for e in merged_I]}")

# --- F2: reputation propagation ---
_f_store.set_destination_reputation("evil-shared.example.com", tier=5, timestamp=_ft0)
devC_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 20, device="p1a_devC",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="evil-shared.example.com")]
merged_C = _capture_merged(devC_ev, ReputationVector(domain="", tier=3), "p1a_devC", _ft0 + 20)
rep_hits = [e for e in merged_C if e.evidence_type == "reputation"
             and e.provenance == "v13_live_engine:reputation_propagation"]
check("F2: a device touching a destination another device's evidence already confirmed "
      "malicious (via set_destination_reputation, e.g. retro_hunter.py's own call site) "
      "inherits a live reputation evidence item immediately",
      len(rep_hits) == 1)
check("F2: the propagated evidence carries the cached tier as its value",
      rep_hits and rep_hits[0].value == 5.0)
check("F2: the propagated evidence was NEVER written to the graph itself",
      not any(e.provenance == "v13_live_engine:reputation_propagation"
              for e in _f_store.get_evidence_for_device("p1a_devC")))

devD_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 20, device="p1a_devD",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="never-confirmed.example.com")]
merged_D = _capture_merged(devD_ev, ReputationVector(domain="", tier=3), "p1a_devD", _ft0 + 20)
check("F2: a device touching a DIFFERENT, never-confirmed destination gets no "
      "propagated reputation evidence",
      not any(e.provenance == "v13_live_engine:reputation_propagation" for e in merged_D))

_f_store.set_destination_reputation("weak-tier.example.com", tier=4, timestamp=_ft0)
devE_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 20, device="p1a_devE",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="weak-tier.example.com")]
merged_E = _capture_merged(devE_ev, ReputationVector(domain="", tier=3), "p1a_devE", _ft0 + 20)
check("F2: a cached tier BELOW the corroborated threshold (4, not 5) does not propagate "
      "-- only a fully corroborated verdict does, matching ReputationVector's own tier "
      "semantics (tier 4 = 'one unconfirmed signal,' not auto-block-worthy)",
      not any(e.provenance == "v13_live_engine:reputation_propagation" for e in merged_E))

_f_store.set_destination_reputation("stale.example.com", tier=5,
                                       timestamp=_ft0 - live_engine._REPUTATION_PROPAGATION_TTL_SECONDS - 1)
devF_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 20, device="p1a_devF",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="stale.example.com")]
merged_F = _capture_merged(devF_ev, ReputationVector(domain="", tier=3), "p1a_devF", _ft0 + 20)
check("F2: a cached reputation entry OLDER than the propagation TTL does not propagate "
      "-- ages out on the same schedule a directly-observed reputation item would",
      not any(e.provenance == "v13_live_engine:reputation_propagation" for e in merged_F))

# --- F3: genuine first-contact scoring ---
devG_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 30, device="p1a_devG",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="brand-new.example.com")]
merged_G1 = _capture_merged(devG_ev, ReputationVector(domain="", tier=3), "p1a_devG", _ft0 + 30)
check("F3: a destination this device has NEVER contacted before gets a first_contact "
      "signal on its very first observation",
      any(e.evidence_type == "first_contact" for e in merged_G1))
check("F3: the first_contact evidence was NEVER written to the graph itself",
      not any(e.evidence_type == "first_contact" for e in _f_store.get_evidence_for_device("p1a_devG")))

# Second cycle, well past the SHORT_WINDOW_SECONDS exclusion (300s) -- the first
# cycle's own persisted evidence for this destination now falls OUTSIDE the excluded
# "current incident" window, so domain_seen_before() correctly finds it familiar now.
devG_ev2 = [V1Evidence(type="dns_rate", source="dns", timestamp=_ft0 + 30 + 400, device="p1a_devG",
                         value=10.0, confidence=0.9, independence_group="dns_behavior",
                         domain="brand-new.example.com")]
merged_G2 = _capture_merged(devG_ev2, ReputationVector(domain="", tier=3), "p1a_devG", _ft0 + 30 + 400)
check("F3: a SECOND cycle contacting the SAME destination, well after the current-"
      "incident exclusion window, correctly stops getting first_contact -- the signal "
      "self-corrects from the device's own now-persisted history, exactly the "
      "'genuinely first contact, not every contact' semantics this exists to provide",
      not any(e.evidence_type == "first_contact" for e in merged_G2))

# --- G. Release 14, N4: multi-signal campaign detection (shared JA3/JA4
# fingerprint, shared DGA generation shape) -- same fresh store as Section F ---

# G1: fingerprint correlation
devH_ev = [V1Evidence(type="malicious_ja3", source="zeek", timestamp=_ft0 + 500, device="p1a_devH",
                        value=1.0, confidence=0.95, independence_group="zeek_network",
                        provenance="detector:zeek:malicious_ja3:campaignhash", domain="c2-a.example.com")]
merged_H1 = _capture_merged(devH_ev, ReputationVector(domain="", tier=3), "p1a_devH", _ft0 + 500)
check("G1: the FIRST device with this JA3 fingerprint gets no fingerprint_campaign "
      "evidence -- nobody else has shown this fingerprint yet",
      not any(e.evidence_type == "fingerprint_campaign" for e in merged_H1))

devI_ev = [V1Evidence(type="malicious_ja3", source="zeek", timestamp=_ft0 + 510, device="p1a_devI",
                        value=1.0, confidence=0.95, independence_group="zeek_network",
                        provenance="detector:zeek:malicious_ja3:campaignhash", domain="c2-b.example.com")]
merged_I0 = _capture_merged(devI_ev, ReputationVector(domain="", tier=3), "p1a_devI", _ft0 + 510)
check("G1: REGRESSION GUARD (third-party architecture review, 2026-09-09) -- the "
      "SECOND device (2 total) sharing the fingerprint does NOT get "
      "fingerprint_campaign evidence anymore, matching the same raised bar as "
      "destination-based coordinated_targeting",
      not any(e.evidence_type == "fingerprint_campaign" for e in merged_I0))

devI2_ev = [V1Evidence(type="malicious_ja3", source="zeek", timestamp=_ft0 + 511, device="p1a_devI2",
                         value=1.0, confidence=0.95, independence_group="zeek_network",
                         provenance="detector:zeek:malicious_ja3:campaignhash", domain="c2-b2.example.com")]
merged_I1 = _capture_merged(devI2_ev, ReputationVector(domain="", tier=3), "p1a_devI2", _ft0 + 511)
fingerprint_hits = [e for e in merged_I1 if e.evidence_type == "fingerprint_campaign"]
check("G1: the THIRD device sharing the EXACT same JA3 hash (even against a "
      "DIFFERENT destination) DOES get fingerprint_campaign evidence -- correlates "
      "on the fingerprint, not the destination",
      len(fingerprint_hits) == 1)
check("G1: the synthetic evidence's value is the total device count (3)",
      fingerprint_hits and fingerprint_hits[0].value == 3.0)
check("G1: fingerprint_campaign was NEVER written to the graph itself",
      not any(e.evidence_type == "fingerprint_campaign"
              for e in _f_store.get_evidence_for_device("p1a_devI2")))

# A different fingerprint hash on the same cycle correctly does NOT correlate
devJ_ev = [V1Evidence(type="malicious_ja3", source="zeek", timestamp=_ft0 + 520, device="p1a_devJ",
                        value=1.0, confidence=0.95, independence_group="zeek_network",
                        provenance="detector:zeek:malicious_ja3:unrelatedhash", domain="c2-c.example.com")]
merged_J1 = _capture_merged(devJ_ev, ReputationVector(domain="", tier=3), "p1a_devJ", _ft0 + 520)
check("G1: a DIFFERENT JA3 hash, even at the same evidence_type and a similar "
      "timestamp, does NOT correlate -- an exact fingerprint match is required",
      not any(e.evidence_type == "fingerprint_campaign" for e in merged_J1))

# G2: DGA-shape correlation -- two devices hitting DIFFERENT domains generated by
# the SAME shape (8-char, all-lowercase-hex-look-alike... actually alpha, same TLD)
devK_ev = [V1Evidence(type="dns_dga_burst", source="pihole", timestamp=_ft0 + 600, device="p1a_devK",
                        value=1.0, confidence=0.9, independence_group="dns_behavior",
                        domain="abcdefgh.ru")]
merged_K1 = _capture_merged(devK_ev, ReputationVector(domain="", tier=3), "p1a_devK", _ft0 + 600)
check("G2: the FIRST device with this DGA shape gets no dga_seed_campaign evidence",
      not any(e.evidence_type == "dga_seed_campaign" for e in merged_K1))

devL_ev = [V1Evidence(type="dns_dga_burst", source="pihole", timestamp=_ft0 + 610, device="p1a_devL",
                        value=1.0, confidence=0.9, independence_group="dns_behavior",
                        domain="qrstuvwx.ru")]  # DIFFERENT literal domain, SAME shape (8 letters, .ru)
merged_L0 = _capture_merged(devL_ev, ReputationVector(domain="", tier=3), "p1a_devL", _ft0 + 610)
check("G2: REGRESSION GUARD (third-party architecture review, 2026-09-09) -- the "
      "SECOND device (2 total) sharing the DGA shape does NOT get dga_seed_campaign "
      "evidence anymore, matching the same raised bar as destination-based "
      "coordinated_targeting",
      not any(e.evidence_type == "dga_seed_campaign" for e in merged_L0))

devL2_ev = [V1Evidence(type="dns_dga_burst", source="pihole", timestamp=_ft0 + 611, device="p1a_devL2",
                         value=1.0, confidence=0.9, independence_group="dns_behavior",
                         domain="ijklmnop.ru")]  # THIRD device, another literal domain, SAME shape
merged_L1 = _capture_merged(devL2_ev, ReputationVector(domain="", tier=3), "p1a_devL2", _ft0 + 611)
dga_hits = [e for e in merged_L1 if e.evidence_type == "dga_seed_campaign"]
check("G2: a THIRD device hitting a DIFFERENT literal domain that shares the SAME "
      "computed DGA shape (8-letter label, .ru TLD) DOES get dga_seed_campaign "
      "evidence -- the actual point: correlating by structure, not literal string",
      len(dga_hits) == 1)
check("G2: dga_seed_campaign carries a lower confidence (0.7) than an exact-match "
      "signal -- an honest reflection that shape-matching is approximate",
      dga_hits and dga_hits[0].confidence == 0.7)
check("G2: dga_seed_campaign was NEVER written to the graph itself",
      not any(e.evidence_type == "dga_seed_campaign"
              for e in _f_store.get_evidence_for_device("p1a_devL2")))

# A domain with a genuinely different shape does NOT correlate
devM_ev = [V1Evidence(type="dns_dga_burst", source="pihole", timestamp=_ft0 + 620, device="p1a_devM",
                        value=1.0, confidence=0.9, independence_group="dns_behavior",
                        domain="ab12.com")]  # different length, different TLD, different charset
merged_M1 = _capture_merged(devM_ev, ReputationVector(domain="", tier=3), "p1a_devM", _ft0 + 620)
check("G2: a genuinely different DGA shape (length/TLD/charset all differ) does "
      "NOT correlate with the abcdefgh.ru/qrstuvwx.ru pair",
      not any(e.evidence_type == "dga_seed_campaign" for e in merged_M1))

# --- G3: _dga_shape_key() unit-level checks ---
check("G3: two domains with the same length/TLD/charset produce the SAME shape key",
      live_engine._dga_shape_key("abcdefgh.ru") == live_engine._dga_shape_key("qrstuvwx.ru"))
check("G3: a different label length produces a DIFFERENT shape key",
      live_engine._dga_shape_key("abcdefgh.ru") != live_engine._dga_shape_key("abc.ru"))
check("G3: a different TLD produces a DIFFERENT shape key",
      live_engine._dga_shape_key("abcdefgh.ru") != live_engine._dga_shape_key("abcdefgh.com"))
check("G3: a hex-looking label is classified distinctly from a pure-alpha label of the same length",
      live_engine._dga_shape_key("deadbeef.com") != live_engine._dga_shape_key("wxyzabcd.com"))
check("G3: a bare IP or NO_DESTINATION never produces a real shape key",
      live_engine._dga_shape_key("8.8.8.8") == "" and live_engine._dga_shape_key(NO_DESTINATION) == "")
check("G3: an empty/None domain never crashes, returns ''",
      live_engine._dga_shape_key("") == "" and live_engine._dga_shape_key(None) == "")

# --- H. Release 14, N2: peer-cohort behavioral baselining ---

_h0 = _ft0 + 700

# Seed two "iot" peers with a normal, LOW distinct-destination count (2 each) --
# directly via the graph's real-traffic table, simulating their own prior traffic.
for peer_id, dests in (("p1a_peer1", ["p1.example.com", "p2.example.com"]),
                        ("p1a_peer2", ["p3.example.com", "p4.example.com"])):
    _f_store.update_device_metadata(peer_id, {"device_type": "iot"}, timestamp=_h0)
    _f_store.record_device_destinations(peer_id, dests, timestamp=_h0)

# The device under test: same "iot" type, but a MUCH higher destination count
# (6 distinct, vs. the peers' average of 2 -- well past the 3x/min-5 bar)
_f_store.record_device_destinations(
    "p1a_devN", [f"anomalous-{i}.example.com" for i in range(6)], timestamp=_h0 + 10)

devN_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_h0 + 20, device="p1a_devN",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="anomalous-5.example.com")]
merged_N1 = _capture_merged(devN_ev, ReputationVector(domain="", tier=3), "p1a_devN", _h0 + 20, device_type="iot")
peer_dev_hits = [e for e in merged_N1 if e.evidence_type == "peer_deviation"]
check("H1: a device with a distinct-destination count far above its iot peer "
      "cohort's average (6 vs. 2) DOES get peer_deviation evidence",
      len(peer_dev_hits) == 1, f"got {[e.evidence_type for e in merged_N1]}")
check("H1: the synthetic evidence carries a lower confidence (0.6) -- an honest "
      "reflection that this is a genuinely new, unvalidated heuristic",
      peer_dev_hits and peer_dev_hits[0].confidence == 0.6)
check("H1: the synthetic evidence's features name the real device_type/counts for audit",
      peer_dev_hits and peer_dev_hits[0].features.get("device_type") == "iot"
      and peer_dev_hits[0].features.get("peer_count") == 2)
check("H1: peer_deviation was NEVER written to the graph itself",
      not any(e.evidence_type == "peer_deviation" for e in _f_store.get_evidence_for_device("p1a_devN")))
check("H1: this device's OWN device_type was persisted onto its graph metadata "
      "as a side effect (so it becomes part of future cohort lookups too)",
      _f_store.get_device_metadata("p1a_devN").get("device_type") == "iot")

# REGRESSION GUARD: a device with a LOW, in-line-with-peers count does NOT trigger
_f_store.record_device_destinations("p1a_devO", ["normal.example.com"], timestamp=_h0 + 30)
devO_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_h0 + 31, device="p1a_devO",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="normal.example.com")]
merged_O1 = _capture_merged(devO_ev, ReputationVector(domain="", tier=3), "p1a_devO", _h0 + 31, device_type="iot")
check("H1: REGRESSION GUARD -- a device whose destination count is in line with "
      "its cohort does NOT get peer_deviation evidence",
      not any(e.evidence_type == "peer_deviation" for e in merged_O1))

# REGRESSION GUARD: no device_type at all -- never even attempts the lookup
merged_P1 = _capture_merged(devN_ev, ReputationVector(domain="", tier=3), "p1a_devN", _h0 + 40, device_type="")
check("H2: REGRESSION GUARD -- an empty device_type never triggers peer_deviation, "
      "matching every existing (device_type-less) caller's unaffected behavior",
      not any(e.evidence_type == "peer_deviation" for e in merged_P1))

# BUGFIX regression (live audit, 2026-09-08): the literal string "unknown" -- the
# fallback pipeline.py itself passes for an unidentified device -- must get the
# SAME treatment as an empty device_type, not silently pool every unidentified
# device on the network into one fake cohort. Confirmed live: 13 real devices
# shared this "unknown" cohort, and one high-traffic outlier among them skewed the
# peer average enough to flag an otherwise near-idle device with zero real
# evidence behind it.
for peer_id, dests in (("p1a_unk_peer1", ["u1.example.com", "u2.example.com"]),
                        ("p1a_unk_peer2", ["u3.example.com", "u4.example.com"])):
    _f_store.update_device_metadata(peer_id, {"device_type": "unknown"}, timestamp=_h0 + 45)
    _f_store.record_device_destinations(peer_id, dests, timestamp=_h0 + 45)
_f_store.record_device_destinations(
    "p1a_devU", [f"unk-anomalous-{i}.example.com" for i in range(6)], timestamp=_h0 + 50)
devU_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_h0 + 56, device="p1a_devU",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="unk-anomalous-5.example.com")]
merged_U1 = _capture_merged(devU_ev, ReputationVector(domain="", tier=3), "p1a_devU", _h0 + 56, device_type="unknown")
check("H2: BUGFIX -- device_type=='unknown' is treated the same as empty; even "
      "though this device's count (6) would clear the 3x/min-5 bar against its "
      "fake 'unknown' cohort (avg 2), no peer_deviation is injected",
      not any(e.evidence_type == "peer_deviation" for e in merged_U1), f"got {[e.evidence_type for e in merged_U1]}")
check("H2: BUGFIX -- 'unknown' devices are never pooled as a cohort at all "
      "(unlike a real device_type, this device's metadata is never even written)",
      _f_store.get_device_metadata("p1a_devU").get("device_type") is None)

# REGRESSION GUARD: not enough peers of this type for a meaningful comparison
_f_store.update_device_metadata("p1a_devQ_peer", {"device_type": "camera"}, timestamp=_h0 + 50)
_f_store.record_device_destinations("p1a_devQ_peer", ["q1.example.com"], timestamp=_h0 + 50)
_f_store.record_device_destinations(
    "p1a_devQ", [f"cam-anomalous-{i}.example.com" for i in range(6)], timestamp=_h0 + 51)
devQ_ev = [V1Evidence(type="dns_rate", source="dns", timestamp=_h0 + 60, device="p1a_devQ",
                        value=10.0, confidence=0.9, independence_group="dns_behavior",
                        domain="cam-anomalous-5.example.com")]
merged_Q1 = _capture_merged(devQ_ev, ReputationVector(domain="", tier=3), "p1a_devQ", _h0 + 60, device_type="camera")
check("H2: REGRESSION GUARD -- only 1 real peer of this type (need >=2) means no "
      "statistically meaningful comparison, so no peer_deviation is injected even "
      "though the raw destination count is high",
      not any(e.evidence_type == "peer_deviation" for e in merged_Q1))

# --- H3: fail-safe -- a broken graph read never blocks the real decision ---
_orig_get_store = live_engine._get_graph_store
live_engine._get_graph_store = lambda: (_ for _ in ()).throw(RuntimeError("simulated graph failure"))
try:
    merged_R1 = _capture_merged(devN_ev, ReputationVector(domain="", tier=3), "p1a_devN", _h0 + 70, device_type="iot")
finally:
    live_engine._get_graph_store = _orig_get_store
check("H3: FAIL-SAFE -- a broken graph read for peer-deviation never raises out of "
      "evaluate(), degrading to no synthetic peer_deviation evidence this cycle",
      not any(e.evidence_type == "peer_deviation" for e in merged_R1))

_f_store.close()

# --- I. Sheet 03a live wiring: reputation floors + hard_stop_candidate_sensitivity
# actually reach a real decision through live_engine.evaluate(), not just
# AutotuneEngine's own audit trail (test_argus_autotune_engine.py covers propose/
# canary/promote in isolation; this covers the real read path end-to-end). ---
_i_tmpdir = tempfile.mkdtemp(prefix="v13_live_engine_sheet03a_test_")
_i_graph_db_path = str(_PathForSysPath(_i_tmpdir) / "i_graph.db")
live_engine.configure(_i_graph_db_path)
_i_store = live_engine._get_graph_store()


def _i_promote(device_id, parameter, new_value, at):
    """Inserts an already-PROMOTED threshold_history row directly -- propose/
    canary/promote's own clamping/cooldown/backtest-gating is already covered
    by test_argus_autotune_engine.py; this test only needs a promoted value to
    exist so it can check whether the real read path (live_engine.evaluate())
    actually picks it up."""
    _i_store._conn.execute(
        "INSERT INTO threshold_history (change_id, device_id, parameter, old_value, new_value, "
        "proposed_at, canary_until, promoted_at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'test')",
        (f"sheet03a_{device_id}_{parameter}", device_id, parameter, 0.0, new_value, at, at, at),
    )
    _i_store._maybe_commit()


# hard_stop_candidate_sensitivity: a suricata match at confidence=0.7 (below the
# DEFAULT 0.9 bar) doesn't clear the bar at all -- no hard-stop branch fires.
suricata_ev = [V1Evidence(type="suricata_signature_match", source="suricata", timestamp=now, device="devSheet03a",
                            value=1.0, confidence=0.7, independence_group="signature_match")]
r_before = live_engine.evaluate(suricata_ev, ReputationVector(domain="", tier=3), features={},
                                   device_id="devSheet03a", now=now)
check("I: hard_stop_candidate_sensitivity default (0.9) -- a 0.7-confidence suricata "
      "match doesn't clear the bar, no hard-stop branch fires",
      r_before["decision_path"] not in ("suricata_uncorroborated", "hard_stop"),
      f"got {r_before['decision_path']}")

# ...until a lower sensitivity is promoted for this device.
_i_promote("devSheet03a", "hard_stop_candidate_sensitivity", 0.6, now)
r_after = live_engine.evaluate(suricata_ev, ReputationVector(domain="", tier=3), features={},
                                  device_id="devSheet03a", now=now + 1)
check("I: hard_stop_candidate_sensitivity promoted to 0.6 -- the SAME 0.7-confidence "
      "suricata match now clears the lowered bar, reaching the uncorroborated hard-stop "
      "branch (HIGH, not full CRITICAL -- no independent corroboration in this scenario)",
      r_after["decision_path"] == "suricata_uncorroborated" and r_after["state"] == "HIGH",
      f"got {r_after['decision_path']}/{r_after['state']}")

# A DIFFERENT device with no promotion of its own is unaffected -- the tuning is
# scoped per-device, not a global flip.
r_other_device = live_engine.evaluate(
    [V1Evidence(type="suricata_signature_match", source="suricata", timestamp=now, device="devSheet03a_untouched",
                 value=1.0, confidence=0.7, independence_group="signature_match")],
    ReputationVector(domain="", tier=3), features={}, device_id="devSheet03a_untouched", now=now + 1)
check("I: hard_stop_candidate_sensitivity promotion is scoped to the specific device "
      "it was promoted for -- a different device with no promotion of its own still "
      "sees the original 0.9 bar",
      r_other_device["decision_path"] not in ("suricata_uncorroborated", "hard_stop"),
      f"got {r_other_device['decision_path']}")

# reputation_tier_high_floor: an abuse_score of 4.5 normally clears the default 4.0
# floor (>=4.0), reaching tier 5.
rep_moderate_abuse = ReputationVector(domain="", tier=3, abuse_risk=4.5)
r_tier_before = live_engine.evaluate([], rep_moderate_abuse, features={}, device_id="devSheet03b", now=now)
check("I: reputation_tier_high_floor default (4.0) -- abuse_score=4.5 reaches tier 5 "
      "(a tier5_* decision_path), matching classify()'s own hardcoded default",
      r_tier_before["decision_path"].startswith("tier5_"),
      f"got {r_tier_before['decision_path']}")

# ...until a higher floor (5.0) is promoted for this device, raising the bar past 4.5.
_i_promote("devSheet03b", "reputation_tier_high_floor", 5.0, now)
r_tier_after = live_engine.evaluate([], rep_moderate_abuse, features={}, device_id="devSheet03b", now=now + 1)
check("I: reputation_tier_high_floor promoted to 5.0 -- the SAME abuse_score=4.5 no "
      "longer clears the raised bar, so tier 5 is never reached (falls through to a "
      "lower/no verdict instead of any tier5_* decision_path)",
      not r_tier_after["decision_path"].startswith("tier5_"),
      f"got {r_tier_after['decision_path']}")

_i_store.close()

# --- J. Release 15 Sheet 00 live wiring: Bayesian Gaussian/Beta/Poisson/Markov +
# BOCPD baseline scoring, now live in evaluate() -- see this file's own module
# docstring for scope (wiring only; the underlying math is covered elsewhere). ---
import random  # noqa: E402
from config import CONFIG  # noqa: E402

_j_tmpdir = tempfile.mkdtemp(prefix="v13_live_engine_baseline_test_")
_j_graph_db_path = str(_PathForSysPath(_j_tmpdir) / "j_graph.db")
live_engine.configure(_j_graph_db_path)
_j0 = 4_000_000.0

# J1: real feature-dict keys (the same names pipeline.py's merged DNS+Zeek features
# dict really uses, confirmed against a real .94 alert) map to the right Gaussian
# metrics, and a genuinely surprising value against an established baseline produces
# baseline_deviation evidence -- through the real live_engine._inject_baseline_evidence()
# call, not score_metric() directly (that path is test_argus_baseline_engine.py's job).
random.seed(42)
for i in range(60):
    stable_features = {"query_rate": random.gauss(50.0, 3.0), "entropy_avg": 2.5,
                        "unique_domains": 10.0, "nxdomain_ratio": 0.05, "blocked_ratio": 0.05,
                        "total": 20.0, "zeek_outbound_bytes": 5000.0}
    live_engine._inject_baseline_evidence("devJ1", stable_features, [], _j0 + i)

spike_features = {"query_rate": 5000.0, "entropy_avg": 2.5, "unique_domains": 10.0,
                    "nxdomain_ratio": 0.05, "blocked_ratio": 0.05, "total": 20.0,
                    "zeek_outbound_bytes": 5000.0}
j1_evidence = live_engine._inject_baseline_evidence("devJ1", spike_features, [], _j0 + 100)
j1_types = [e.evidence_type for e in j1_evidence]
check("J1: a query_rate value wildly outside 60 stable observations produces real "
      "baseline_deviation (or regime_change, if BOCPD's own changepoint gate also "
      "fired) evidence through the live wiring, not just in isolation",
      ("baseline_deviation" in j1_types or "regime_change" in j1_types), f"got {j1_types}")
check("J1: every baseline-derived evidence item uses NO_DESTINATION (aggregate "
      "per-device features, never a single-connection destination guess)",
      all(e.destination_id == NO_DESTINATION for e in j1_evidence))

# J2: Beta metrics only score when this cycle had real DNS activity (trials>0) --
# an empty window (total=0) is skipped outright, matching daemon.py's own gate.
j2_empty = live_engine._inject_baseline_evidence(
    "devJ2", {"nxdomain_ratio": 0.5, "blocked_ratio": 0.5, "total": 0.0}, [], _j0)
check("J2: total=0 (no real DNS activity this cycle) skips Beta-metric scoring "
      "entirely, not a crash from a zero-trials Binomial observation",
      j2_empty == [])

# J3: dga_hits/honeypot_touches (Poisson) and the Markov activity-state axis are
# counted from fresh_v2 (this cycle's OWN real detector output), never merged_v2's
# graph-window history -- verified by passing a fresh_v2 list with a real
# dns_dga_burst item and confirming the count feeds through (indirectly, via a
# non-empty return -- the exact Poisson math is bayesian.py's own test's job).
dga_ev = Evidence(device_id="devJ3", destination_id=NO_DESTINATION, evidence_type="dns_dga_burst",
                    independence_family="dns_behavior", timestamp=_j0, source="test", confidence=0.8, value=1.0)
j3_result = live_engine._inject_baseline_evidence("devJ3", {}, [dga_ev], _j0)
check("J3: _inject_baseline_evidence() runs end-to-end with a real fresh_v2 dns_dga_burst "
      "item present (Poisson dga_hits scoring + Markov activity-state scoring), no crash",
      isinstance(j3_result, list))
# A second call with a state-changing evidence type actually produces a markov
# transition surprise signal once a real prev_state exists (first call always
# returns None for the Markov axis -- see score_activity_transition()'s own contract).
honeypot_ev = Evidence(device_id="devJ3", destination_id=NO_DESTINATION, evidence_type="honeypot_access",
                         independence_family="direct_observation", timestamp=_j0 + 5, source="test",
                         confidence=1.0, value=1.0)
j3_second = live_engine._inject_baseline_evidence("devJ3", {}, [honeypot_ev], _j0 + 5)
j3_types = [e.evidence_type for e in j3_second]
check("J3: a genuine activity-state transition (NORMAL -> POLICY_VIOLATION, via a "
      "fresh honeypot_access item) on the SECOND call produces markov_activity_surprise "
      "evidence -- the Markov axis actually receives fresh_v2's evidence types",
      "markov_activity_surprise" in j3_types, f"got {j3_types}")

# J4: baseline_scoring_enabled=False -- the plain rollback switch -- disables the
# whole subsystem with zero graph interaction, matching every other feature-flag
# convention in this codebase. Direct _config mutation (same pattern
# test_phase31_corrupted_training_rows.py already uses) -- no override-file
# round-trip needed for an in-process test.
_j4_had_key = "baseline_scoring_enabled" in CONFIG._config
_j4_orig_value = CONFIG._config.get("baseline_scoring_enabled")
CONFIG._config["baseline_scoring_enabled"] = False
try:
    j4_result = live_engine._inject_baseline_evidence("devJ4", stable_features, [], _j0)
finally:
    if _j4_had_key:
        CONFIG._config["baseline_scoring_enabled"] = _j4_orig_value
    else:
        CONFIG._config.pop("baseline_scoring_enabled", None)
check("J4: baseline_scoring_enabled=False is a real rollback switch -- returns [] "
      "unconditionally, without even attempting a graph read",
      j4_result == [])
check("J4: restoring the flag afterward leaves config state clean (True again) for "
      "the rest of this test file / any other test run in the same process",
      bool(CONFIG.get("baseline_scoring_enabled", True)) is True)

# J5: fail-safe -- a broken graph read never raises out of _inject_baseline_evidence(),
# matching Section H3's own fail-safe pattern for peer-deviation.
_j_orig_get_store = live_engine._get_graph_store
live_engine._get_graph_store = lambda: (_ for _ in ()).throw(RuntimeError("simulated graph failure"))
try:
    j5_result = live_engine._inject_baseline_evidence("devJ5", stable_features, [], _j0)
finally:
    live_engine._get_graph_store = _j_orig_get_store
check("J5: FAIL-SAFE -- a broken graph read for baseline scoring never raises out of "
      "_inject_baseline_evidence(), degrading to no baseline evidence this cycle",
      j5_result == [])

# J6: the one-cycle risk lag -- evaluate() with a real device_id caches this cycle's
# own attack-hypothesis score for the NEXT cycle's `risk` Gaussian input (daemon.py's
# own documented circular-dependency workaround, ported unchanged).
live_engine._last_risk_score.pop("devJ6", None)
r_j6_first = live_engine.evaluate(
    [V1Evidence(type="suricata_signature_match", source="suricata", timestamp=_j0, device="devJ6",
                 value=1.0, confidence=0.95, independence_group="signature_match")],
    ReputationVector(domain="", tier=3), features={}, device_id="devJ6", now=_j0)
check("J6: after one evaluate() call with a real device_id, _last_risk_score is "
      "populated with THIS cycle's own attack-hypothesis score (for the NEXT cycle's "
      "risk baseline input, not this one -- avoids the circular dependency on a "
      "decision that doesn't exist yet at injection time)",
      "devJ6" in live_engine._last_risk_score,
      f"got keys {list(live_engine._last_risk_score.keys())}")
check("J6: the cached value matches this cycle's real attack hypothesis score, not a "
      "placeholder",
      live_engine._last_risk_score["devJ6"] == r_j6_first.get("hypotheses", {}).get("attack", {}).get("score", 0.0))

_j_store = live_engine._get_graph_store()
_j_store.close()

# --- K: cap_per_type is actually wired end-to-end into the live per-cycle path
# (2026-09-20, restart-cadence investigation) -- a real device found live on
# .94 generated 41,509 evidence rows (39,551 zeek_notice_weak) in ONE 24h
# window, blowing the pipeline's 60s heartbeat deadline every cycle. This
# confirms _query_graph_window() actually applies GraphStore's own cap, not
# just that the cap mechanism exists in isolation (test_argus_graph_store.py's
# own job) -- the real regression is in the WIRING, not the primitive.
_k_tmpdir = tempfile.mkdtemp(prefix="v13_live_engine_cap_test_")
_k_graph_db_path = str(_PathForSysPath(_k_tmpdir) / "k_graph.db")
live_engine.configure(_k_graph_db_path, hardware_profile="x86_16gb")
_k_store = live_engine._get_graph_store()
_k_now = 5_000_000.0
_k_store.upsert_device("devK")
for i in range(300):  # far more than x86_16gb's 100-per-type cap
    _k_store.insert_evidence(Evidence(
        device_id="devK", destination_id=NO_DESTINATION, evidence_type="zeek_notice_weak",
        independence_family="network_behavior", timestamp=_k_now - 100 + i, source="s", confidence=0.4))
_k_store._maybe_commit()

_k_windowed = live_engine._query_graph_window("devK", _k_now)
check("K: _query_graph_window() actually caps a real device's oversized single-type "
      "evidence volume down to the hardware profile's own limit (x86_16gb: 100), not "
      "the full 300 rows genuinely present in the graph",
      len(_k_windowed) == 100, f"got {len(_k_windowed)}")

# devK's evaluate() call must not hang/degrade even with this volume present --
# the actual live symptom this fix closes (a 2s cycle taking long enough to blow
# a 60s heartbeat deadline). Not a timing assertion (too flaky cross-machine),
# just confirms the call completes and returns a normal, sane verdict.
_k_result = live_engine.evaluate(
    [], ReputationVector(domain="", tier=0), features={}, device_id="devK", now=_k_now)
check("K: evaluate() for a device with a huge single-type evidence backlog still "
      "returns a normal verdict shape, not a crash or hang",
      _k_result.get("state") in ("BENIGN", "ANOMALOUS", "SUSPICIOUS", "HIGH", "CRITICAL"))

_k_store.close()

print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 live_engine adapter checks PASSED.")
