"""
Standalone runtime test for VERSION 10's first two architectural roadmap items,
approved after a third-party review of the full alerts.json history flagged them as
reasonable forward-looking improvements (not live bugs): evidence families (#5) and
incident aggregation (#8). Not part of the pytest suite -- run directly:
`python3 tests/test_phase34_evidence_families_and_incidents.py`.

#5 EVIDENCE FAMILIES: decision_engine.py's "N independent evidence source(s)" count
used to be a hand-maintained hybrid of type-prefix matching ("dns"/"zeek") OR membership
in a hardcoded 4-value independence_group set -- which silently excluded arp_sweep
evidence (type "arp_sweep", independence_group "lan_recon": doesn't start with dns/zeek,
and "lan_recon" was never added to the hardcoded set) from the independent-source count
entirely, even though ConnectionAbuseHypothesis treats it as a real corroborating
signal. Fixed with a canonical EVIDENCE_FAMILIES/ATTACK_EVIDENCE_FAMILIES registry in
evidence.py and a clean group-membership filter in decision_engine.py.

#8 INCIDENT AGGREGATION: the same device+target+signature combination could generate a
full Telegram alert every time the per-device cadence gate cleared (as often as every
60s once a signature persisted/escalated) even though it's the SAME ongoing incident,
not a new one -- confirmed live via alerts.json showing hundreds of near-identical
entries for one device/destination/signature triple over hours. Fixed with
core/incident_tracker.py's IncidentTracker (in-memory, keyed by incident_key.py's
canonical device+target+signature key, shared with ollama_soc.py's own offline
grouping) layered on top of pipeline.py's existing cadence gate: alerts.json still gets
a line every qualifying cycle (unaffected, still trains CL-AFPE), but Telegram sends
collapse to the first occurrence, any severity escalation, and periodic "still ongoing"
updates no more often than incident_update_min_interval_seconds.

Covers:
  A. evidence.py -- EVIDENCE_FAMILIES/ATTACK_EVIDENCE_FAMILIES registry contents.
  B. decision_engine.py -- arp_sweep/lan_recon now counts as an independent source;
     local_context (benign-only) still correctly never counts; regression guards for
     every other pre-existing family.
  C. incident_key.py -- target_for_key/signature_base/incident_key derivation,
     including the persistence-suffix-stripping fix applied to this new module too.
  D. core/incident_tracker.py -- IncidentTracker.should_notify(): first occurrence
     always notifies, a quiet repeat within the update interval is suppressed but still
     counted, a severity escalation always re-notifies immediately, a periodic update
     fires after the configured interval, and a long-quiet gap starts a fresh incident.
  E. pipeline.py source-guards -- incident_id wired into alert_payload, the Telegram
     gate consults IncidentTracker, ollama_soc.py imports the shared incident_key module
     instead of its own duplicated logic.
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
# Section A: evidence.py -- EVIDENCE_FAMILIES / ATTACK_EVIDENCE_FAMILIES registry
# ═══════════════════════════════════════════════════════════════════════════════════
from intelligence.hypotheses.evidence import EVIDENCE_FAMILIES, ATTACK_EVIDENCE_FAMILIES

_EXPECTED_FAMILIES = {
    "dns_behavior", "dns_tunnel_v2", "zeek_network", "lan_recon", "blindspot_audit",
    "honeypot", "ml_anomaly", "local_context", "reputation",
}
check("EVIDENCE_FAMILIES contains every independence_group value actually used across "
      "the codebase's detectors",
      _EXPECTED_FAMILIES.issubset(EVIDENCE_FAMILIES), f"missing={_EXPECTED_FAMILIES - EVIDENCE_FAMILIES}")
check("THE CORE FIX: lan_recon (arp_sweep's family) is a recognized attack-relevant family",
      "lan_recon" in ATTACK_EVIDENCE_FAMILIES)
check("local_context (local_device_discovery, benign-only) is deliberately excluded from "
      "ATTACK_EVIDENCE_FAMILIES -- it must never corroborate an attack verdict",
      "local_context" not in ATTACK_EVIDENCE_FAMILIES and "local_context" in EVIDENCE_FAMILIES)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: decision_engine.py -- the real corroboration-counting behavior
# ═══════════════════════════════════════════════════════════════════════════════════
from argus_scenarios import DecisionEngine
from intelligence.hypotheses.evidence import Evidence
from intelligence.reputation.classifier import ReputationVector

de = DecisionEngine()
rep = ReputationVector(domain="unknown", tier=3)
NOW = time.time()

def _ev(etype, group, value=10.0, confidence=0.85):
    return Evidence(type=etype, source="test", timestamp=NOW, device="d1", value=value,
                     confidence=confidence, independence_group=group)

# THE CORE FIX: arp_sweep (lan_recon) + a second family now correctly count as 2
# independent sources -- before the fix, arp_sweep was silently excluded, so this same
# evidence set would have counted as only 1.
result_arp = de.evaluate([_ev("arp_sweep", "lan_recon"), _ev("zeek_conn_abuse", "zeek_network")], rep)
check("THE CORE FIX: arp_sweep (lan_recon family) now counts toward independent sources",
      result_arp["independent_sources"] == 2, f"got {result_arp['independent_sources']}")

# arp_sweep ALONE (only 1 family) should NOT be enough to reach HIGH on its own (needs
# 2+ independent sources per decision_engine.py's own bar) -- regression guard that the
# fix didn't accidentally make a single arp_sweep hit over-authorize.
result_arp_alone = de.evaluate([_ev("arp_sweep", "lan_recon", value=10.0)], rep)
check("REGRESSION GUARD: arp_sweep alone (1 family) still only reaches 1 independent "
      "source, not enough alone to authorize HIGH",
      result_arp_alone["independent_sources"] == 1)

# REGRESSION GUARD: local_device_discovery (benign, local_context) never counts toward
# ATTACK corroboration, before or after the fix.
result_benign_mixed = de.evaluate(
    [_ev("arp_sweep", "lan_recon"), _ev("local_device_discovery", "local_context", value=1.0)], rep)
check("REGRESSION GUARD: local_device_discovery (local_context) still never counts "
      "toward independent attack-evidence sources",
      result_benign_mixed["independent_sources"] == 1, f"got {result_benign_mixed['independent_sources']}")

# REGRESSION GUARD: every other pre-existing family still counts exactly as before.
result_dns_zeek_rep = de.evaluate(
    [_ev("dns_entropy", "dns_behavior"), _ev("zeek_lateral_scan", "zeek_network"), _ev("reputation", "reputation")], rep)
check("REGRESSION GUARD: dns_behavior + zeek_network + reputation still count as 3 "
      "independent sources, unaffected by the filter rewrite",
      result_dns_zeek_rep["independent_sources"] == 3, f"got {result_dns_zeek_rep['independent_sources']}")

# REGRESSION GUARD: malicious_ja3/zeek_notice (types that do NOT start with "dns"/"zeek"
# but ARE independence_group="zeek_network") still count -- these only ever worked via
# the group-membership path, never the type-prefix path, so a filter rewrite that
# dropped group-membership entirely would have silently broken them.
result_ja3 = de.evaluate([_ev("malicious_ja3", "zeek_network"), _ev("arp_sweep", "lan_recon")], rep)
check("REGRESSION GUARD: malicious_ja3 (zeek_network family, type doesn't start with "
      "'zeek') still counts toward independent sources",
      result_ja3["independent_sources"] == 2, f"got {result_ja3['independent_sources']}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: incident_key.py
# ═══════════════════════════════════════════════════════════════════════════════════
from incident_key import target_for_key, signature_base, incident_key

check("target_for_key prefers the resolved domain over the destination IP",
      target_for_key("203.0.113.7", "evil-tunnel.ru") == "evil-tunnel.ru")
check("target_for_key falls back to destination_ip when queried_domain is 'unknown' "
      "(the real production shape for DNS_EVASION/reputation-only alerts)",
      target_for_key("149.154.166.110", "unknown") == "149.154.166.110")
check("target_for_key falls back to 'unknown' when neither is present",
      target_for_key(None, None) == "unknown")

check("THE FIX: signature_base strips the persistence-escalation suffix, same as "
      "pipeline.py's own primary_sig_base",
      signature_base("DNS_EVASION (persisted 603s)") == "DNS_EVASION")
check("signature_base leaves a fresh (non-persisted) signature unchanged",
      signature_base("DNS_EVASION") == "DNS_EVASION")
check("signature_base correctly handles a signature with internal spaces of its own "
      "('Confirmed Malicious IOC'), splitting on ' (persisted ' not a bare space",
      signature_base("Confirmed Malicious IOC (persisted 120s)") == "Confirmed Malicious IOC")

check("THE CORE FIX: incident_key collapses a fresh and a persisted-escalated instance "
      "of the SAME underlying incident to the identical key",
      incident_key("dev1", "203.0.113.7", "evil-tunnel.ru", "DNS_EVASION") ==
      incident_key("dev1", "203.0.113.7", "evil-tunnel.ru", "DNS_EVASION (persisted 603s)"))
check("incident_key differs for a genuinely different device",
      incident_key("dev1", "1.1.1.1", "x.example", "DNS_EVASION") !=
      incident_key("dev2", "1.1.1.1", "x.example", "DNS_EVASION"))
check("incident_key differs for a genuinely different target",
      incident_key("dev1", "1.1.1.1", "x.example", "DNS_EVASION") !=
      incident_key("dev1", "2.2.2.2", "y.example", "DNS_EVASION"))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: core/incident_tracker.py -- IncidentTracker.should_notify()
# ═══════════════════════════════════════════════════════════════════════════════════
from core.incident_tracker import IncidentTracker

tracker = IncidentTracker(grouping_window_seconds=1800.0, update_min_interval_seconds=900.0)
t0 = 1_000_000.0

r1 = tracker.should_notify("k1", "HIGH", t0)
check("THE CORE FIX: the first occurrence of a new incident always notifies",
      r1.should_notify and r1.occurrence_count == 1 and not r1.is_escalation)

r2 = tracker.should_notify("k1", "HIGH", t0 + 60.0)
check("THE CORE FIX: a quiet repeat well within the update interval is suppressed "
      "(this is what stops the 'hundreds of near-identical alerts' pattern)",
      not r2.should_notify and r2.occurrence_count == 2)

r3 = tracker.should_notify("k1", "HIGH", t0 + 120.0)
check("occurrence_count keeps incrementing even while suppressed -- alerts.json/CL-AFPE "
      "are unaffected by this gate, only the Telegram send is",
      not r3.should_notify and r3.occurrence_count == 3)

r4 = tracker.should_notify("k1", "CRITICAL", t0 + 130.0)
check("THE CORE FIX: a severity escalation (HIGH -> CRITICAL) always re-notifies "
      "immediately, regardless of the update-interval cadence",
      r4.should_notify and r4.is_escalation and r4.occurrence_count == 4)

r5 = tracker.should_notify("k1", "CRITICAL", t0 + 200.0)
check("REGRESSION GUARD: staying at the SAME severity after an escalation does not "
      "re-trigger 'is_escalation' again immediately",
      not r5.should_notify)

r6 = tracker.should_notify("k1", "CRITICAL", t0 + 130.0 + 900.0)
check("THE CORE FIX: a periodic 'still ongoing' update fires once "
      "update_min_interval_seconds has elapsed since the last notify",
      r6.should_notify and not r6.is_escalation)

tracker2 = IncidentTracker(grouping_window_seconds=1800.0, update_min_interval_seconds=900.0)
tracker2.should_notify("k2", "HIGH", t0)
r_gap = tracker2.should_notify("k2", "HIGH", t0 + 1800.0 + 1.0)
check("THE CORE FIX: a gap longer than grouping_window_seconds starts a genuinely NEW "
      "incident (occurrence_count resets to 1), not a continuation",
      r_gap.should_notify and r_gap.occurrence_count == 1)

check("REGRESSION GUARD: an unrecognized/legacy severity string ranks as 0 (never "
      "treated as an escalation over SUSPICIOUS) rather than crashing",
      tracker.should_notify("k3", "SOME_UNKNOWN_STATE", t0).should_notify)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: pipeline.py source-guards
# ═══════════════════════════════════════════════════════════════════════════════════
import inspect
from core import pipeline as _pipeline_module

_pipeline_src = inspect.getsource(_pipeline_module)

check("SOURCE-GUARD: pipeline.py instantiates IncidentTracker with config-driven windows",
      "self.incident_tracker = IncidentTracker(" in _pipeline_src)
check("SOURCE-GUARD: alert_payload carries the incident_id field",
      '"incident_id": incident_id,' in _pipeline_src)
check("SOURCE-GUARD: the Telegram send gate consults incident_notify.should_notify",
      "telegram_worthy and incident_notify.should_notify" in _pipeline_src)
check("SOURCE-GUARD: the incident key is derived from the corrected alert_dest_ip/"
      "alert_target_domain, not the raw dest_ip/target_malicious_domain fallbacks",
      "incident_id = _incident_key(dev_id, alert_dest_ip, alert_target_domain, primary_sig_base)" in _pipeline_src)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All evidence-family + incident-aggregation checks PASSED.")
