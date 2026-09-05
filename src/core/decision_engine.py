import time
from typing import List, Dict, Any, Optional
from intelligence.hypotheses.evidence import Evidence, ATTACK_EVIDENCE_FAMILIES
from intelligence.hypotheses.engine import HypothesisEngine, HYPOTHESIS_RELEVANT_EVIDENCE_TYPES
from intelligence.reputation.classifier import ReputationVector

# Gap 3, Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md: how long a hard-stop type
# (arp_spoofing/geofencing_violation/suricata_signature_match) is trusted as "this cycle's
# own event" rather than a stale EvidenceStore replay. Deliberately far shorter than
# EvidenceStore's own 600s general TTL (evidence.py) -- a hard-stop is meant to represent "this
# verifiable fact just happened," not "this fact happened at some point in the last 10
# minutes." honeypot_access uses features["zeek_honeypot_hits"] directly instead (the exact
# same raw signal pipeline.py itself uses to decide whether to create the evidence at all,
# sidestepping the timing question entirely) -- this constant is for the other three, which
# don't have as direct a raw-feature equivalent readily available here yet, and (as of
# PHASE 64) remain SHADOW-ONLY: fresh_arp_spoof/fresh_geofence/fresh_confirmed_exploit have
# never produced a single live divergence in state/shadow_decisions.jsonl since 2026-08-26
# (checked directly, not assumed), unlike honeypot's 58 confirmed stale-echo cases -- there's
# no live evidence yet that this 120s proxy is calibrated correctly for the other three, so
# only honeypot's freshness check (fresh_honeypot below) was flipped live.
_HARD_STOP_FRESHNESS_SECONDS = 120

def _safe_float(val: Any) -> float:
    try:
        return float(val) if val is not None else 0.0
    except (ValueError, TypeError):
        return 0.0

def _safe_confidence(val: Any) -> float:
    return min(1.0, max(0.0, _safe_float(val)))

class DecisionState:
    BENIGN = "BENIGN"
    ANOMALOUS = "ANOMALOUS"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DecisionEngine:
    def __init__(self):
        self.hypothesis_engine = HypothesisEngine()

    def evaluate(self, ev_store: List[Evidence], rep: ReputationVector, device_type: str = "",
                 baseline_familiarity: float = 0.0, features: Optional[dict] = None,
                 is_safe: bool = False) -> Dict[str, Any]:
        # VERSION 10 (#9/#10 per-device benign profiles): device_type is optional and
        # defaults to "" for any existing caller that hasn't been updated -- only
        # DeviceProfileBenignHypothesis (hypotheses/engine.py) actually reads it.
        # VERSION 11 (P1 follow-up): baseline_familiarity is the same kind of optional,
        # defaulted, single-consumer parameter -- see DeviceProfileBenignHypothesis's
        # own docstring for what it means and how it's computed.
        # PHASE 64 (Gap 3 honeypot flip, live): features is the same optional/defaulted/
        # single-consumer pattern -- only the honeypot freshness check below (fresh_honeypot)
        # reads it; any existing caller that hasn't been updated to pass it (tests,
        # regression_tester.py) falls back to fresh_honeypot=False, matching the old
        # has_honeypot-based behavior for a device with genuinely fresh honeypot evidence
        # but no features dict available (conservative: no false negative, just no freshness
        # discount either -- see the trail line below for how a stale-but-present hit is
        # still surfaced diagnostically even when it no longer hard-stops).
        # BUGFIX (2026-09-01, live shadow-divergence flood: 51 "home-router ... Internal
        # Honeypot Accessed" divergences in one session, all the router at one of its
        # several IPv6/IPv4 identifiers): is_safe is the SAME optional/defaulted/
        # single-consumer pattern, added because the freshness check below (fresh_honeypot)
        # copied pipeline.py's raw-feature read (features.get("zeek_honeypot_hits", 0) > 0)
        # to dodge EvidenceStore staleness, but silently dropped the "and not is_safe" half
        # of that SAME condition at its source (pipeline.py's evidence-creation gate, ~line
        # 1033) -- safe_ips devices like the router touching the honeypot for benign reasons
        # is explicitly expected and exempted live, but this check had no way to know that
        # until is_safe was threaded through too.
        hyp_results = self.hypothesis_engine.evaluate_all(ev_store, rep, device_type, baseline_familiarity)
        
        attack_score = hyp_results["attack"]["score"]
        benign_score = hyp_results["benign"]["score"]
        evidence_verification_required = False
        hypothesis_weight = 0.0

        partial_support = [e for e in ev_store if e.independence_group in {"dns_behavior", "zeek_network", "reputation", "honeypot"}]
        if partial_support:
            hypothesis_weight = sum(_safe_confidence(e.confidence) for e in partial_support) / max(1, len(partial_support))
            has_meaningful_partial_signal = any(
                _safe_confidence(e.confidence) >= 0.5 and abs(_safe_float(e.value)) > 0.0 for e in partial_support
            )
            evidence_verification_required = hypothesis_weight >= 0.5 and (
                attack_score >= 2.0 or has_meaningful_partial_signal
            )
        
        # VERSION 10 (evidence families) BUGFIX: this used to be a hand-maintained hybrid
        # of type-prefix matching ("dns"/"zeek") OR membership in a hardcoded 4-value
        # group set -- which silently excluded arp_sweep evidence (type "arp_sweep",
        # independence_group "lan_recon": doesn't start with dns/zeek, and "lan_recon"
        # was never added to the hardcoded set) from the independent-source count
        # entirely, even though ConnectionAbuseHypothesis treats it as a real
        # corroborating signal. Every Evidence construction site in the codebase already
        # sets an explicit independence_group (confirmed via audit -- "general", the
        # dataclass default, is never actually used in practice), so a clean
        # group-membership test against the canonical ATTACK_EVIDENCE_FAMILIES registry
        # (evidence.py) is both simpler and strictly more correct than the old hybrid.
        attack_evidence = [e for e in ev_store if e.independence_group in ATTACK_EVIDENCE_FAMILIES]

        # PHASE 64 (Gap 6 item 3 follow-through, redesigned after a first attempt was
        # caught by test_phase38_comprehensive_scenarios.py's own existing golden case --
        # see DECISION_LOGIC_DEPENDENCY_MAP.md for that attempt's category error).
        # "reputation" evidence is added on ANY nonzero TI/VT/AbuseIPDB score anywhere in
        # the device's rolling window (pipeline.py) -- untargeted, that's still
        # legitimate weak corroboration (the existing golden case: a DGA burst plus SOME
        # independent reputation signal, neither evidence item carrying a domain, is
        # supposed to reach HIGH -- correctly left alone below, since neither side has
        # domain info to compare). What's NOT legitimate corroboration is a reputation
        # hit AFFIRMATIVELY about a DIFFERENT destination than the one the winning attack
        # hypothesis's own evidence points at (e.g. a DNS_TUNNELING verdict about
        # domain X "corroborated" by a reputation hit that pipeline.py itself attributed
        # to a completely unrelated domain Y elsewhere in the window). Only strip a
        # reputation item when BOTH sides carry a domain and they provably differ --
        # never when either side is domain-less (that's the ambiguous case the existing
        # test already covers, and this fix must not touch it), so this can only ever
        # remove a source the evidence itself proves is unrelated, never one merely
        # lacking proof of relation. Monotonic: can only demote a verdict, never escalate
        # one -- same fail-safe direction Gap 1/G6 shipped live without a shadow period.
        winning_attack_name = hyp_results["attack"]["name"]
        relevant_types = HYPOTHESIS_RELEVANT_EVIDENCE_TYPES.get(winning_attack_name)
        hyp_domains = {
            e.domain for e in attack_evidence
            if relevant_types and e.type in relevant_types and e.domain
        } if relevant_types else set()
        if hyp_domains:
            attack_evidence = [
                e for e in attack_evidence
                if not (e.independence_group == "reputation" and e.domain and e.domain not in hyp_domains)
            ]

        independence_groups = {e.independence_group for e in attack_evidence if e.independence_group}
        num_independent_sources = len(independence_groups)

        # PHASE 8 FIX: a human-readable record of what this evaluation actually checked, in
        # the order it checked it, built alongside the decision itself (not reconstructed
        # after the fact from the final numbers) so a Telegram alert can show the real
        # reasoning chain instead of two disconnected, sometimes-contradicting subsystems
        # concatenated together. rep fields are read via getattr() since some callers
        # (e.g. tests/regression_tester.py's MockRep) intentionally duck-type only `.tier`.
        rep_owner = getattr(rep, "asn_owner", None) or "Unknown"
        rep_domain = getattr(rep, "domain", "") or "n/a"
        rep_vt = getattr(rep, "vt_detection_ratio", 0.0) or 0.0
        rep_ti = getattr(rep, "ti_risk", 0.0) or 0.0
        rep_abuse = getattr(rep, "abuse_risk", 0.0) or 0.0

        has_honeypot = any(e.type == "honeypot_access" for e in ev_store)
        # PHASE 64 (Gap 3 honeypot flip, live): has_honeypot above checks only PRESENCE in
        # ev_store, which EvidenceStore (evidence.py) keeps "active" for up to 600s after
        # creation -- a single real hit used to re-fire the identical CRITICAL verdict on
        # every pipeline cycle for up to 10 more minutes. fresh_honeypot reads
        # features["zeek_honeypot_hits"] directly instead (the same raw signal pipeline.py
        # itself gates evidence-creation on, at its own call site) -- sidesteps the timing
        # question entirely rather than needing its own freshness-window constant.
        # Confirmed live (not inferred): a home-router "Internal Honeypot Accessed" CRITICAL
        # alert with features["zeek_honeypot_hits"]==0 in its own persisted snapshot -- the
        # verdict's own evidence contradicted it. 58 confirmed stale-echo divergences in
        # state/shadow_decisions.jsonl since 2026-08-26 with zero false negatives (every
        # genuinely fresh hit shadow-agreed with live) before this flip.
        fresh_honeypot = (
            bool(features) and _safe_float((features or {}).get("zeek_honeypot_hits", 0)) > 0
            and not is_safe
        )
        has_arp_spoof = any(e.type == "arp_spoofing" for e in ev_store)
        has_geofence = any(e.type == "geofencing_violation" for e in ev_store)
        # VERSION 11 (P2, Suricata follow-up): a genuinely high-severity Suricata rule
        # match (confidence>=0.9, its own severity=1/"high") is a real signature/
        # exploit match against a curated ruleset, not a fuzzy heuristic -- matches the
        # review's explicit "known malware signature" / "confirmed exploit" hard-stop
        # category. See suricata_scan.py and SuricataSignatureHypothesis for how this
        # evidence is produced (batch-mode scan of a reactive-capture burst pcap).
        has_confirmed_exploit = any(
            e.type == "suricata_signature_match" and e.confidence >= 0.9 for e in ev_store
        )

        # PHASE 10 FIX: "tier" is context/prior about a destination (how much prior trust or
        # suspicion attaches to it), not a threat verdict — tier 4 means "one unconfirmed
        # signal exists", not "this is 4x more dangerous than tier 1". Spelling that out
        # inline (rather than just printing the bare number) is a direct response to a
        # third-party review of a real alert: "tier=4, IP owner='Telegram'" read side by
        # side looked like the system was calling known infrastructure suspicious, when the
        # actual claim is much narrower — one unconfirmed reputation signal, nothing more.
        tier_note = {
            0: "local/internal", 1: "trusted", 2: "known infrastructure",
            3: "unclassified — neutral, not malicious",
            4: "one unconfirmed signal — context, not a verdict",
            5: "corroborated across independent sources",
        }.get(rep.tier, "unrecognized")

        trail: List[str] = [
            (
                f"Hard-stop checks: honeypot={'YES' if fresh_honeypot else ('stale' if has_honeypot else 'no')}, "
                f"arp_spoofing={'YES' if has_arp_spoof else 'no'}, "
                f"geofencing={'YES' if has_geofence else 'no'}, "
                f"confirmed_exploit={'YES' if has_confirmed_exploit else 'no'}"
            ),
            (
                f"Reputation context: tier={rep.tier} ({tier_note}) — target='{rep_domain}', "
                f"VT={rep_vt:.1f}, TI={rep_ti:.1f}, AbuseIPDB={rep_abuse:.1f}, "
                f"IP owner='{rep_owner}'"
            ),
        ]
        hyp_line = (
            f"Hypotheses: attack='{hyp_results['attack']['name']}' (score={attack_score:.1f}) "
            f"vs benign='{hyp_results['benign']['name']}' (score={benign_score:.1f}) — "
            f"{num_independent_sources} independent evidence source(s)"
        )
        if attack_score == 0.0 and benign_score == 0.0:
            # Neither hypothesis found supporting evidence — this is a materially different
            # situation from "the engine weighed the evidence and leaned suspicious"; say so
            # explicitly rather than leaving a reader to infer it from two zeros.
            hyp_line += " — no hypothesis explains this evidence either way; verdict below rests on reputation context alone"
        trail.append(hyp_line)

        state = DecisionState.BENIGN
        action = "suppress"
        explanation = hyp_results["benign"]["name"]
        threat_confidence = 0.0
        # PHASE 18: which branch below actually resolved this evaluation -- exported as
        # home_ids_decision_path_total{path} so the mix (hard_stop/tier5 share shrinking,
        # benign share growing over weeks) is the direct, graphable "is the system getting
        # smarter over time" signal across all of Brain 1, not just CL-AFPE.
        decision_path = "benign"

        if fresh_honeypot:
            state = DecisionState.CRITICAL
            action = "block"
            explanation = "Internal Honeypot Accessed"
            threat_confidence = 1.0
            decision_path = "hard_stop"
            
        elif has_arp_spoof:
            state = DecisionState.CRITICAL
            action = "block"
            explanation = "Layer-2 ARP Spoofing Detected"
            threat_confidence = 1.0
            decision_path = "hard_stop"
            
        elif has_geofence:
            # VERSION 12 (G6, HEE coverage audit): geography alone is a policy fact about
            # the DESTINATION, not evidence of malicious BEHAVIOR by this device -- unlike
            # honeypot access, ARP spoofing, and a confirmed exploit signature (all three
            # are themselves direct, first-hand evidence of compromise/attack), a
            # geofence hit only says "this destination is in a blocklisted country,"
            # which says nothing about whether the CONNECTION itself was malicious. Same
            # corroboration split already applied to tier-5 reputation above (Gap 1) --
            # num_independent_sources/attack_score/benign_score are already computed at
            # the top of this function; geofencing_violation evidence itself carries
            # independence_group="general" (Evidence's own default, never set otherwise
            # for this type), which ATTACK_EVIDENCE_FAMILIES does not include -- so this
            # check requires a GENUINELY SEPARATE evidence family, not the geofence hit
            # trivially corroborating itself.
            if num_independent_sources >= 1 and attack_score > benign_score:
                # Explanation deliberately stays the EXACT original string (no suffix) --
                # fp_engine.py's _HARD_STOP_SIGNATURES refuses to "correct" an alert whose
                # signature exact-matches "Geofencing Policy Violation", the same
                # protection every other hard-stop already gets. Only the uncorroborated
                # (no-longer-a-hard-stop) case below gets a distinguishing suffix.
                state = DecisionState.CRITICAL
                action = "block"
                explanation = "Geofencing Policy Violation"
                threat_confidence = 0.95
                decision_path = "hard_stop"
            else:
                # "Geography alone should not be CRITICAL" -- still a real, specific,
                # actionable policy violation (stronger than a bare reputation score),
                # so HIGH/alert rather than demoting all the way to SUSPICIOUS/monitor.
                state = DecisionState.HIGH
                action = "alert"
                explanation = "Geofencing Policy Violation (Uncorroborated)"
                threat_confidence = 0.70
                decision_path = "geofence_uncorroborated"

        elif has_confirmed_exploit:
            state = DecisionState.CRITICAL
            action = "block"
            explanation = "Confirmed Exploit/Malware Signature (Suricata)"
            threat_confidence = 0.98
            decision_path = "hard_stop"

        elif rep.tier == 5:
            # BUGFIX (2026-08-29, Gap 1 flipped live from shadow mode after real-world
            # confirmation): this used to fire "Confirmed Malicious IOC" / CRITICAL / block
            # / 0.99 confidence for ANY tier-5 hit, whether it came from a genuine curated
            # threat-intel feed match (rep.verified_ioc, ti_score>2.0) or a bare AbuseIPDB/VT
            # aggregate score alone. Backtest (scripts/shadow_backtest.py, 80 historical
            # "Confirmed Malicious IOC" alerts): verified_ioc was True for ZERO of them.
            # Confirmed live: example_pc_fritz_box vs. 35.186.224.24 (Google LLC) fired this
            # branch 3x in one night on AbuseIPDB=4.0 alone (VT=0.0, TI=0.0) with the benign
            # hypothesis (LOCAL_DEVICE_DISCOVERY, 2.5) outscoring the attack one
            # (NETWORK_INTRUSION, 2.0) -- shadow mode, Ollama's own independent analysis, and
            # this split all agreed it wasn't a real threat. Uses the live attack_score/
            # benign_score (not the shadow-adjusted JA3/JA4 split, Gap 2 -- that's still
            # shadow-only) so this flip is scoped to verified_ioc alone. getattr(...,
            # False): duck-typed test rep objects (e.g. regression_tester.py's MockRep)
            # only set .tier, same reasoning as rep_owner/rep_vt/etc. above.
            if getattr(rep, "verified_ioc", False):
                state = DecisionState.CRITICAL
                action = "block"
                explanation = "Confirmed Malicious IOC"
                threat_confidence = 0.99
                decision_path = "tier5_confirmed"
            elif num_independent_sources >= 1 and attack_score > benign_score:
                state = DecisionState.CRITICAL
                action = "block"
                explanation = "Corroborated Reputation Signal"
                threat_confidence = 0.85
                decision_path = "tier5_corroborated"
            else:
                # Same reasoning as the tier==4 branch below: a bigger raw reputation
                # number doesn't earn a stronger verdict when real corroboration (the
                # thing that's supposed to justify CRITICAL/block) is exactly what's
                # missing -- this is the same underlying situation as tier 4, just with a
                # higher raw score.
                state = DecisionState.SUSPICIOUS
                action = "monitor"
                explanation = "Elevated Reputation Signal (Unconfirmed, Tier 5 Score)"
                threat_confidence = 0.45
                decision_path = "tier5_uncorroborated"

        elif attack_score > benign_score and attack_score >= 2.0:
            explanation = hyp_results["attack"]["name"]
            if num_independent_sources >= 2 and attack_score >= 3.0:
                state = DecisionState.HIGH
                action = "alert"
                threat_confidence = 0.85
                decision_path = "hypothesis_high"
            else:
                state = DecisionState.SUSPICIOUS
                action = "monitor"
                threat_confidence = 0.40
                decision_path = "hypothesis_suspicious"

        elif rep.tier == 4 and max(rep_vt, rep_ti, rep_abuse) >= 1.5:
            # PHASE 8 FIX: before this branch existed, a reputation signal that never rose
            # to "confirmed" (tier 5) had exactly one path through this function: silence.
            # The ONLY thing standing between "99% Confirmed Malicious IOC" and "nothing at
            # all" was a single classify() threshold — there was no representation for "a
            # real but unconfirmed signal, worth a human's attention, not worth an
            # auto-block" (exactly the 149.154.166.110/Telegram case). Mirrors the tier==5
            # branch above at lower confidence and "monitor" instead of "block": reputation
            # alone never auto-contains unless it's corroborated (tier 5) or paired with
            # real behavioral evidence (the attack_score branch above already covers that).
            state = DecisionState.SUSPICIOUS
            action = "monitor"
            explanation = "Elevated Reputation Signal (Unconfirmed)"
            threat_confidence = 0.45
            decision_path = "tier4_unconfirmed"

        elif any(e.type == "ml_anomaly" and e.value > 0.90 for e in ev_store):
            state = DecisionState.ANOMALOUS
            action = "log"
            explanation = "ML Anomaly Only"
            threat_confidence = 0.10
            decision_path = "ml_anomaly"

        trail.append(f"Verdict: {state} / {action} — {explanation} (confidence={threat_confidence:.2f})")

        # SHADOW MODE (Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md): computed alongside
        # the real verdict above, never substituted for it here -- state/action/explanation
        # returned below are UNCHANGED by any of this. Combines the remaining still-shadow
        # fixes found via a third-party review + live verification:
        #   Gap 1 (rep.verified_ioc) and Gap 3's honeypot freshness (fresh_honeypot, computed
        #   above alongside has_honeypot) are both LIVE now, not shadow -- this block still
        #   reuses their live values/branches so the shadow comparison stays apples-to-apples
        #   with what actually ran, it just no longer needs its own copies of that logic.
        #   Gap 2 (shadow_attack_score/name, from HypothesisEngine.evaluate_all()):
        #   NetworkIntrusionHypothesis.evaluate() currently weighs a generic Zeek `weird`
        #   notice identically to a real malicious JA3/JA4 TLS fingerprint match under one
        #   `has_malicious_tls` boolean -- evaluate_shadow() splits them. Only relevant when
        #   NETWORK_INTRUSION was (or would become) the winning attack hypothesis.
        #   [STALE COMMENT, PHASE 64] this block used to also compute Gap 2 (NetworkIntrusion
        #   ja3/notice split) as shadow-only -- that flipped live too (hypotheses/engine.py,
        #   NetworkIntrusionHypothesis.evaluate() now calls use_gap2_fix=True directly), so
        #   shadow_attack/hyp_results["attack"] are identical for that hypothesis now; kept
        #   here only because decision_engine.py's shadow computation still needs SOME
        #   attack-score source and shadow_attack degrades to hyp_results["attack"] cleanly.
        #   Gap 3, remaining shadow-only (fresh_arp_spoof/fresh_geofence/fresh_confirmed_exploit):
        #   same PRESENCE-vs-freshness problem honeypot had (has_arp_spoof/has_geofence/
        #   has_confirmed_exploit above check only ev_store presence, up to EvidenceStore's
        #   600s TTL) -- but unlike honeypot, these three have never produced a single live
        #   divergence in state/shadow_decisions.jsonl (checked directly), so there's no live
        #   evidence yet that _HARD_STOP_FRESHNESS_SECONDS=120 is correctly calibrated for
        #   them the way honeypot's own raw-feature check was confirmed to be. Stay
        #   shadow-only pending that same live confirmation.
        shadow_attack = hyp_results.get("shadow_attack", hyp_results["attack"])
        shadow_attack_name = shadow_attack["name"]
        shadow_attack_score = shadow_attack["score"]

        now_ts = time.time()
        fresh_arp_spoof = any(
            e.type == "arp_spoofing" and (now_ts - e.timestamp) <= _HARD_STOP_FRESHNESS_SECONDS for e in ev_store
        )
        fresh_geofence = any(
            e.type == "geofencing_violation" and (now_ts - e.timestamp) <= _HARD_STOP_FRESHNESS_SECONDS for e in ev_store
        )
        fresh_confirmed_exploit = any(
            e.type == "suricata_signature_match" and e.confidence >= 0.9
            and (now_ts - e.timestamp) <= _HARD_STOP_FRESHNESS_SECONDS
            for e in ev_store
        )

        if fresh_honeypot:
            shadow_state, shadow_explanation, shadow_decision_path = (
                DecisionState.CRITICAL, "Internal Honeypot Accessed", "hard_stop"
            )
        elif fresh_arp_spoof:
            shadow_state, shadow_explanation, shadow_decision_path = (
                DecisionState.CRITICAL, "Layer-2 ARP Spoofing Detected", "hard_stop"
            )
        elif fresh_geofence:
            # VERSION 12 (G6): mirrors the live branch's corroboration split exactly --
            # this shadow computation exists to isolate Gap 3's freshness question alone
            # (see this block's own module comment), so it must NOT diverge from live for
            # a completely different, unrelated reason (G6's corroboration requirement).
            if num_independent_sources >= 1 and attack_score > benign_score:
                shadow_state, shadow_explanation, shadow_decision_path = (
                    DecisionState.CRITICAL, "Geofencing Policy Violation", "hard_stop"
                )
            else:
                shadow_state, shadow_explanation, shadow_decision_path = (
                    DecisionState.HIGH, "Geofencing Policy Violation (Uncorroborated)", "geofence_uncorroborated"
                )
        elif fresh_confirmed_exploit:
            shadow_state, shadow_explanation, shadow_decision_path = (
                DecisionState.CRITICAL, "Confirmed Exploit/Malware Signature (Suricata)", "hard_stop"
            )
        elif rep.tier == 5:
            # BUGFIX (2026-08-29, found alongside the live Gap-1 flip above): this used
            # `rep.verified_ioc` bare -- duck-typed test rep objects (e.g.
            # regression_tester.py's MockRep, which only sets .tier) crash here with
            # AttributeError. Same getattr(..., False) fix as the live branch.
            if getattr(rep, "verified_ioc", False):
                shadow_state, shadow_explanation, shadow_decision_path = (
                    DecisionState.CRITICAL, "Confirmed Malicious IOC", "tier5_confirmed"
                )
            elif num_independent_sources >= 1 and shadow_attack_score > benign_score:
                shadow_state, shadow_explanation, shadow_decision_path = (
                    DecisionState.CRITICAL, "Corroborated Reputation Signal", "tier5_corroborated"
                )
            else:
                # BUGFIX (2026-08-27, user catch): this used to land at HIGH, which
                # contradicted its own label -- "Uncorroborated" describing a HIGH-severity
                # verdict makes no sense next to the tier==4 branch below, which already
                # treats "one unconfirmed reputation signal" (a WEAKER raw score, 1.5-4.0)
                # as SUSPICIOUS/monitor, not HIGH/alert. An aggregate score that crossed the
                # confirmed_ioc bar (>=4.0) but found no genuine corroborating evidence for
                # an attack conclusion is the SAME underlying situation as tier 4 -- a bigger
                # raw number doesn't earn it a stronger verdict when the thing that's
                # supposed to justify HIGH (real corroboration) is exactly what's missing.
                # Confirmed live: example_pc_fritz_box vs. 35.186.224.24 (Google LLC),
                # abuse_score=4.0 alone, benign hypothesis (LOCAL_DEVICE_DISCOVERY, 2.5)
                # outscoring the attack one (NETWORK_INTRUSION, 2.0) -- there is no
                # behavioral corroboration here at all, just a single crowd-sourced number.
                shadow_state, shadow_explanation, shadow_decision_path = (
                    DecisionState.SUSPICIOUS, "Elevated Reputation Signal (Unconfirmed, Tier 5 Score)", "tier5_uncorroborated"
                )
        elif shadow_attack_score > benign_score and shadow_attack_score >= 2.0:
            if num_independent_sources >= 2 and shadow_attack_score >= 3.0:
                shadow_state, shadow_explanation, shadow_decision_path = (
                    DecisionState.HIGH, shadow_attack_name, "hypothesis_high"
                )
            else:
                shadow_state, shadow_explanation, shadow_decision_path = (
                    DecisionState.SUSPICIOUS, shadow_attack_name, "hypothesis_suspicious"
                )
        elif rep.tier == 4 and max(rep_vt, rep_ti, rep_abuse) >= 1.5:
            shadow_state, shadow_explanation, shadow_decision_path = (
                DecisionState.SUSPICIOUS, "Elevated Reputation Signal (Unconfirmed)", "tier4_unconfirmed"
            )
        elif any(e.type == "ml_anomaly" and e.value > 0.90 for e in ev_store):
            shadow_state, shadow_explanation, shadow_decision_path = (
                DecisionState.ANOMALOUS, "ML Anomaly Only", "ml_anomaly"
            )
        else:
            shadow_state, shadow_explanation, shadow_decision_path = (
                DecisionState.BENIGN, hyp_results["benign"]["name"], "benign"
            )
        shadow_changed = shadow_decision_path != decision_path or shadow_explanation != explanation

        return {
            "state": state,
            "action": action,
            "explanation": explanation,
            "threat_confidence": threat_confidence,
            "independent_sources": num_independent_sources,
            "hypotheses": hyp_results,
            "evidence_verification_required": evidence_verification_required,
            "hypothesis_weight": hypothesis_weight,
            "reasoning_trail": trail,
            "decision_path": decision_path,
            "shadow_state": shadow_state,
            "shadow_explanation": shadow_explanation,
            "shadow_decision_path": shadow_decision_path,
            "shadow_changed": shadow_changed,
        }
