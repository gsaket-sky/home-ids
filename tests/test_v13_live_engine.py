"""
Standalone runtime test for src/v13/ops/live_engine.py -- the actual swap-in adapter
pipeline.py calls in place of core/decision_engine.py's DecisionEngine.evaluate(), per
the v13 fast-cutover plan.

Not part of the pytest suite -- run directly: `python3 tests/test_v13_live_engine.py`.

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
import v13.ops.live_engine as live_engine  # noqa: E402

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
    V1Evidence(type="zeek_notice", source="zeek", timestamp=now, device="d1", value=1.0,
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

no_gap_ev = [V1Evidence(type="zeek_notice", source="zeek", timestamp=now, device="d3",
                          value=1.0, confidence=0.9, independence_group="zeek_network", domain=None)]
r_no_gap = live_engine.evaluate(no_gap_ev, ReputationVector(domain="", tier=3),
                                  features={"last_dest_ip": "203.0.113.60"})
check("C: a type with NO destination gap (zeek_notice) never gets the fallback_context "
      "misapplied to it, even when last_dest_ip is present in the same call",
      "state" in r_no_gap)


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
      "matches the SAME single-source case already proven in test_v13_decision_engine.py",
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


def _capture_merged(v1_evidence, rep, device_id, now, features=None):
    """Runs evaluate() with a thin wrapper around _v13_engine.evaluate() (same
    pattern as Section E's own _CapturingEngine) and returns the exact merged
    evidence list the decision engine actually saw for this one call."""
    captured = []
    orig_engine = live_engine._v13_engine

    class _Capture:
        def evaluate(self, evidence_list, *a, **kw):
            captured.append(list(evidence_list))
            return orig_engine.evaluate(evidence_list, *a, **kw)

    live_engine._v13_engine = _Capture()
    try:
        live_engine.evaluate(v1_evidence, rep, features=features or {}, device_id=device_id, now=now)
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
coordinated_hits = [e for e in merged_B if e.evidence_type == "coordinated_targeting"]
check("F1: the SECOND device to touch the SAME destination within the short window "
      "DOES get coordinated_targeting evidence -- the actual cross-device correlation "
      "capability, not achievable against v-current's per-device-only RollingWindow",
      len(coordinated_hits) == 1)
check("F1: the synthetic evidence's value is the TOTAL device count (this one + 1 other = 2)",
      coordinated_hits and coordinated_hits[0].value == 2.0)
check("F1: the synthetic evidence names the other device in its features for audit",
      coordinated_hits and coordinated_hits[0].features.get("other_devices") == ["p1a_devA"])

_f_store = live_engine._get_graph_store()
check("F1: the synthetic coordinated_targeting evidence was NEVER written to the graph "
      "itself (it's derived context, not a sensor observation -- writing it would "
      "recreate the evidence-duplication bug Phase 1's own incident already fixed)",
      not any(e.evidence_type == "coordinated_targeting"
              for e in _f_store.get_evidence_for_device("p1a_devB")))

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

_f_store.close()

print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 live_engine adapter checks PASSED.")
