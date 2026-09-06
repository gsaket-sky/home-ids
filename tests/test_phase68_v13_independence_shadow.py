"""
Standalone runtime test for Phase 68: the first v13 mechanism wired into .94's live
decision_engine.py as a shadow-only computation (Documentation/V13_REMAINING_WORK.md
A9's prerequisite -- HEE review finding #7 / Roadmap #8, "genuine per-hypothesis
evidence independence").

decision_engine.py's live `independence_group`-based corroboration count is set
ad-hoc, per detector, at evidence-creation time -- the VERSION 10 comment in that
file already documents this exact conflation as a real past bug source (arp_sweep's
"lan_recon" group was once silently excluded from the count because nobody had
centrally registered it). v13's INDEPENDENCE_FAMILY_MAP
(src/v13/hypotheses/independence.py) is a centralized, evidence-TYPE-keyed registry
built specifically to fix this -- e.g. it splits JA3/JA4 fingerprint matches,
zeek_notice, exfiltration, and beaconing into 3 separate families where
ATTACK_EVIDENCE_FAMILIES groups them all as one ("zeek_network").

This is a SHADOW-ONLY computation: `evaluate()`'s real return values (state,
action, explanation, decision_path, threat_confidence) are completely unaffected by
any of this. The new v13_* fields exist purely for comparison, exactly like the
existing shadow_state/shadow_explanation/shadow_decision_path/shadow_changed fields
(Gap 1/2/3's own shadow experiment) -- and are logged to a SEPARATE file
(state/v13_independence_divergences.jsonl) so as not to interleave with that
unrelated experiment.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase68_v13_independence_shadow.py`

Sections:
  A. The live decision is completely unchanged by this addition (regression guard)
  B. A real divergence: v13's finer family split reaches a different verdict than
     v-current's coarser grouping, on a real attack-shaped scenario
  C. Every non-independence-gated branch (hard-stops, tier5_confirmed, tier4,
     ml_anomaly, benign) never diverges -- v13's alternate count is provably
     irrelevant there
  D. v13_independence_changed correctly gates when a divergence would be logged
  E. pipeline.py's logging wiring (source-level checks, not live I/O)
  F. v13_eligible is the real denominator for the A10 flip bar -- true on every
     cycle the shadow block actually re-resolves, independent of whether it diverges
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


from core.decision_engine import DecisionEngine, DecisionState  # noqa: E402
from intelligence.hypotheses.evidence import Evidence  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402

engine = DecisionEngine()
now = time.time()

# --- A. Regression guard: live decision fields are completely unaffected ---

result_empty = engine.evaluate([], ReputationVector(domain="", tier=3))
check("A: an empty evidence store still returns the exact same BENIGN verdict as before",
      result_empty["state"] == DecisionState.BENIGN and result_empty["decision_path"] == "benign")
check("A: v13 shadow fields are present on every call, even the trivial empty case",
      "v13_state" in result_empty and "v13_num_independent_sources" in result_empty)
check("A: on the empty case, v13's shadow verdict trivially matches live (nothing to diverge on)",
      result_empty["v13_independence_changed"] is False)

single_source_ev = [
    Evidence(type="malicious_ja3", source="zeek", timestamp=now, device="d0", value=1.0,
              confidence=0.9, independence_group="zeek_network", domain="evil.example.com"),
]
result_single = engine.evaluate(single_source_ev, ReputationVector(domain="evil.example.com", tier=3))
check("A: a single-evidence-item case reaches the SAME live verdict as before this change existed",
      result_single["state"] == DecisionState.SUSPICIOUS and result_single["decision_path"] == "hypothesis_suspicious")
check("A: v13's family mapping for a SINGLE evidence item also finds only 1 family -- no divergence possible",
      result_single["v13_num_independent_sources"] == 1 and result_single["v13_independence_changed"] is False)


# --- B. A real divergence: v13's finer split changes the verdict on a realistic case ---

# v-current's ATTACK_EVIDENCE_FAMILIES groups malicious_ja3 and zeek_notice under the
# SAME "zeek_network" independence_group (1 independent source -> SUSPICIOUS, not
# enough for HIGH's >=2 bar). v13's INDEPENDENCE_FAMILY_MAP treats JA3 fingerprint
# matches and zeek_notice as genuinely separate families (2 independent sources,
# clearing the >=2 bar) -- this is the exact real-world scenario issue #7 was about.
two_family_ev = [
    Evidence(type="malicious_ja3", source="zeek", timestamp=now, device="d1", value=1.0,
              confidence=0.9, independence_group="zeek_network", domain="evil.example.com"),
    Evidence(type="zeek_notice", source="zeek", timestamp=now, device="d1", value=1.0,
              confidence=0.75, independence_group="zeek_network", domain="evil.example.com"),
]
result_div = engine.evaluate(two_family_ev, ReputationVector(domain="evil.example.com", tier=3))
check("B: v-current's live verdict stays SUSPICIOUS (1 independence_group, below the >=2 HIGH bar)",
      result_div["independent_sources"] == 1 and result_div["state"] == DecisionState.SUSPICIOUS
      and result_div["decision_path"] == "hypothesis_suspicious")
check("B: v13's shadow count finds 2 genuinely separate families for the SAME evidence",
      result_div["v13_num_independent_sources"] == 2)
check("B: v13's shadow verdict reaches HIGH -- a real, meaningful divergence on a realistic case",
      result_div["v13_state"] == DecisionState.HIGH and result_div["v13_decision_path"] == "hypothesis_high")
check("B: v13_independence_changed correctly flags this as a real divergence",
      result_div["v13_independence_changed"] is True)
check("B: the LIVE return values are completely untouched by v13's alternate verdict existing",
      result_div["state"] == DecisionState.SUSPICIOUS and result_div["action"] == "monitor")


# --- C. Non-independence-gated branches never diverge, by construction ---

honeypot_ev = [Evidence(type="honeypot_access", source="zeek", timestamp=now, device="d2", value=1.0,
                          confidence=1.0, independence_group="honeypot")]
result_honeypot = engine.evaluate(honeypot_ev, ReputationVector(domain="", tier=3),
                                     features={"zeek_honeypot_hits": 1})
check("C: a honeypot hard-stop reaches CRITICAL exactly as before",
      result_honeypot["state"] == DecisionState.CRITICAL and result_honeypot["decision_path"] == "hard_stop")
check("C: a hard-stop verdict never diverges in the v13 shadow -- independence count is irrelevant to it",
      result_honeypot["v13_independence_changed"] is False and result_honeypot["v13_state"] == DecisionState.CRITICAL)

confirmed_ioc_ev = [Evidence(type="reputation", source="threat_intel", timestamp=now, device="d3", value=1.0,
                                confidence=0.9, independence_group="reputation")]
rep_confirmed = ReputationVector(domain="malicious.example.com", tier=5, verified_ioc=True)
result_confirmed = engine.evaluate(confirmed_ioc_ev, rep_confirmed)
check("C: a confirmed IOC (verified_ioc) reaches CRITICAL/tier5_confirmed exactly as before",
      result_confirmed["decision_path"] == "tier5_confirmed")
check("C: tier5_confirmed never diverges -- it doesn't read independence count at all",
      result_confirmed["v13_independence_changed"] is False)

result_benign = engine.evaluate([
    Evidence(type="advertising_burst", source="dns", timestamp=now, device="d4", value=1.0,
              confidence=0.5, independence_group="general"),
], ReputationVector(domain="ads.example.com", tier=3))
check("C: a benign-shaped case never diverges", result_benign["v13_independence_changed"] is False)


# --- D. v13_independence_changed correctly gates real vs. no divergence ---

check("D: divergence flag is False whenever v13_decision_path equals the live decision_path",
      all(not r["v13_independence_changed"] for r in (result_empty, result_single, result_honeypot,
                                                          result_confirmed, result_benign)))
check("D: divergence flag is True exactly when v13_decision_path differs from decision_path",
      result_div["v13_independence_changed"] and result_div["v13_decision_path"] != result_div["decision_path"])


# --- E. pipeline.py source-level wiring checks ---

import inspect  # noqa: E402
from core.pipeline import EnginePipeline  # noqa: E402

src = inspect.getsource(EnginePipeline._log_v13_independence_divergence)
check("E: _log_v13_independence_divergence writes to a SEPARATE file from the Gap-1 shadow log",
      "v13_independence_divergences.jsonl" in src and "shadow_decisions.jsonl" not in src)
check("E: _log_v13_independence_divergence never raises out to the caller (try/except, matches _log_shadow_divergence)",
      "except Exception" in src)

step_src = inspect.getsource(EnginePipeline._step)
check("E: the live pipeline gates the new log call on decision.get('v13_independence_changed')",
      "v13_independence_changed" in step_src and "_log_v13_independence_divergence" in step_src)


# --- F. v13_eligible: the real denominator, independent of whether it diverges ---

check("F: v13_eligible is False on the trivial empty case (benign branch never reads independence count)",
      result_empty["v13_eligible"] is False)
check("F: v13_eligible is True for a single-source hypothesis_suspicious case, even with zero divergence",
      result_single["v13_eligible"] is True and result_single["v13_independence_changed"] is False)
check("F: v13_eligible is True for the real two-family divergence case (B above)",
      result_div["v13_eligible"] is True)
check("F: v13_eligible is False for a honeypot hard-stop (never reads independence count)",
      result_honeypot["v13_eligible"] is False)
check("F: v13_eligible is False for tier5_confirmed (never reads independence count)",
      result_confirmed["v13_eligible"] is False)
check("F: v13_eligible is False for the benign-shaped case",
      result_benign["v13_eligible"] is False)

check("F: pipeline.py counts every eligible cycle via _count_v13_eligible_cycle, gated on decision.get('v13_eligible')",
      "v13_eligible" in step_src and "_count_v13_eligible_cycle" in step_src)

count_src = inspect.getsource(EnginePipeline._count_v13_eligible_cycle)
check("F: _count_v13_eligible_cycle writes to its OWN file, separate from the divergence log",
      "v13_independence_eligible_count.json" in count_src
      and 'open(tmp_path, "w"' in count_src)
check("F: _count_v13_eligible_cycle uses an atomic tmp-then-replace write (matches state_guard.py's pattern)",
      ".tmp" in count_src and "replace(" in count_src)
check("F: _count_v13_eligible_cycle never raises out to the caller",
      "except Exception" in count_src)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 68 v13-independence-shadow checks PASSED.")
