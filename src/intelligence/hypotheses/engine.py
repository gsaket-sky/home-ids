from typing import List, Dict, Any
from intelligence.hypotheses.evidence import Evidence, EvidenceStore
from intelligence.reputation.classifier import ReputationVector

class Hypothesis:
    def __init__(self, name: str):
        self.name = name
        self.required_satisfied = False
        self.strong_score = 0.0
        self.supporting_score = 0.0
        self.contradicting_score = 0.0

    def _reset_eval_state(self) -> None:
        self.required_satisfied = False
        self.strong_score = 0.0
        self.supporting_score = 0.0
        self.contradicting_score = 0.0

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        """Returns confidence score 0-4. `device_type` (VERSION 10, #9/#10 per-device
        benign profiles) is the device's coarse category (e.g. "smart_tv", "iot", "nas"
        -- see utils.infer_device_type()) -- optional and ignored by most hypotheses;
        only DeviceProfileBenignHypothesis below actually reads it. `baseline_familiarity`
        (VERSION 11, P1 follow-up) is 0.0-1.0: how familiar THIS specific device's own
        learned history is with the current cycle's destination (port/ASN/domain) --
        see AutonomousFPEngine.get_baseline_familiarity() (fp_engine.py) for how it's
        computed and pipeline.py for where it's read before this call. Also currently
        only read by DeviceProfileBenignHypothesis. Every subclass accepts both (even
        unused) so HypothesisEngine.evaluate_all() can call every hypothesis
        uniformly."""
        raise NotImplementedError

class DNSTunnelingHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("DNS_TUNNELING")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        # Check requirements
        has_high_rate = any(e.type == "dns_rate" and e.value > 100 for e in ev_store)
        has_high_entropy = any(e.type == "dns_entropy" and e.value > 4.0 for e in ev_store)
        
        self.required_satisfied = has_high_rate and has_high_entropy
        if not self.required_satisfied:
            return 0.0

        # Strong
        if any(e.type == "dns_unique_ratio" and e.value > 0.8 for e in ev_store):
            self.strong_score += 1.0

        # Contradicting
        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0

        score = 2.0 # Suspicious
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0 # Probable
        if self.strong_score > 0.5 and self.contradicting_score == 0 and rep_vector.tier in (3, 4):
            score = 4.0 # High

        return score


class NetworkIntrusionHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("NETWORK_INTRUSION")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        # Check requirements: Zeek evidence
        has_lateral_scan = any(e.type == "zeek_lateral_scan" and e.value > 0 for e in ev_store)
        has_malicious_tls = any(e.type in ("malicious_ja3", "malicious_ja4", "zeek_notice") for e in ev_store)
        
        self.required_satisfied = has_lateral_scan or has_malicious_tls
        if not self.required_satisfied:
            return 0.0

        # Strong
        if has_lateral_scan and has_malicious_tls:
            self.strong_score += 1.0

        # Contradicting
        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0

        score = 2.0 # Suspicious
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0 # Probable
        if self.strong_score > 0.5 and self.contradicting_score == 0 and rep_vector.tier in (3, 4, 5):
            score = 4.0 # High
            
        # Hard escalate for lateral scans (very rarely benign on a home network)
        if has_lateral_scan and self.contradicting_score == 0:
            score = 4.0

        return score

class AdvertisingBurstHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("ADVERTISING_BURST")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        has_high_rate = any(e.type == "dns_rate" and e.value > 50 for e in ev_store)
        
        self.required_satisfied = has_high_rate and (rep_vector.tier == 2)
        if not self.required_satisfied:
            return 0.0
            
        score = 3.0
        if not any(e.type == "dns_entropy" and e.value > 4.0 for e in ev_store):
            score = 4.0 # High confidence it's just ads
            
        return score

# ══════════════════════════════════════════════════════════════════════════════════════
# PHASE 1: Hypotheses ported from the dead mitigation/scoring.py RiskScorer. scoring.py
# computed these signal categories but was never imported by the live pipeline (confirmed
# dead code — see audit Finding #1). threat_signals.py's ThreatSignalDetector now emits
# the underlying Evidence; these hypotheses are what actually consumes it and lets it
# reach DecisionEngine.
# ══════════════════════════════════════════════════════════════════════════════════════

class LocalDeviceDiscoveryHypothesis(Hypothesis):
    """Reviewer suggestion, implemented: a device's real HTTP/SSDP/DIAL requests to
    OTHER devices on its own LAN, matching known media/UPnP device-discovery
    conventions (see pipeline.py's _LOCAL_DEVICE_DISCOVERY_URI_PATTERNS -- dd.xml,
    ssdp/, apps/), is normal device-discovery behavior (Spotify Connect, Chromecast,
    smart-TV app launch), not "more suspicious network activity." Deliberately a
    modest score: it should dampen a WEAK, otherwise-unexplained attack signal (the
    kind that would only just clear the SUSPICIOUS floor), but never unilaterally
    override a genuinely multi-source-corroborated attack finding -- the
    attack_score > benign_score comparison in decision_engine.py already enforces
    that naturally, since a real corroborated finding scores higher than this."""
    def __init__(self):
        super().__init__("LOCAL_DEVICE_DISCOVERY")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "local_device_discovery" and e.value > 0]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        return 2.5


class DGAHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("DGA_BOTNET_C2")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "dns_dga_burst"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.type == "dns_rate" and e.value > 100 for e in ev_store):
            self.strong_score += 1.0

        score = 2.0  # Suspicious
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0  # Probable
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0 and rep_vector.tier in (3, 4, 5):
            score = 4.0  # High
        return score


class ExfiltrationHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("DATA_EXFILTRATION")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "zeek_exfiltration"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.type in ("zeek_beaconing", "reputation") for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.contradicting_score == 0:
            score = 4.0
        return score


class BeaconingHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("C2_BEACONING")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "zeek_beaconing"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.type in ("zeek_exfiltration", "reputation", "malicious_ja3", "malicious_ja4") for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        return score


class DNSTunnelingV2Hypothesis(Hypothesis):
    """Distinct from DNSTunnelingHypothesis above (which is really a rate+entropy burst
    detector despite its name). This one uses the actual tunneling signals scoring.py
    computed: long/encoded subdomain labels, TXT/NULL query abuse, and suspicious-TLD
    concentration — broadens coverage rather than replacing the existing hypothesis."""

    def __init__(self):
        super().__init__("DNS_COVERT_TUNNELING")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "dns_tunnel_v2"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)
        # PHASE 1 FIX: provenance format is
        # "detector:threat_signals:dns_tunnel_v2:{subtag}:{note}" — split(":", 4) with
        # maxsplit=4 yields exactly 5 parts, so index [3] is always the stable category
        # subtag (e.g. "txt_null_abuse"), never the free-text note (which varies
        # cycle-to-cycle). The previous `rsplit(":", 1)[0]` grouped ALL dns_tunnel_v2 hits
        # under the same prefix regardless of which of the three tunneling checks fired,
        # so this "2+ distinct categories" bonus could never actually trigger.
        distinct_signals = len({
            e.provenance.split(":", 4)[3] if e.provenance.count(":") >= 3 else e.provenance
            for e in hits
        })

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if distinct_signals >= 2:
            self.strong_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0 and rep_vector.tier in (3, 4):
            score = 4.0
        return score


class ConnectionAbuseHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("CONNECTION_ABUSE")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        scan_hits = [e for e in ev_store if e.type == "zeek_conn_abuse"]
        long_hits = [e for e in ev_store if e.type == "zeek_long_conn"]
        # PHASE 21B: ARP host-discovery sweeps are a real recon precursor to the same
        # attack shape this hypothesis already covers -- accepted here as an alternate
        # required trigger rather than a whole separate hypothesis class, since it
        # corroborates the same "device is scanning the LAN" story. Broadcast-visible,
        # so this fires for WiFi devices too, unlike scan_hits/long_hits which currently
        # only have real data for wired devices (see PRODUCT_ARCHITECTURE.md/this
        # session's live testing on why).
        arp_hits = [e for e in ev_store if e.type == "arp_sweep"]
        self.required_satisfied = bool(scan_hits or long_hits or arp_hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in (scan_hits + long_hits + arp_hits))

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        # Two DISTINCT signal categories corroborating each other (not just two hits of
        # the same type) is what should count as "strong" -- an ARP sweep alone, or a
        # port-scan alone, stays at the base score; ARP sweep + subsequent port scan is
        # the real multi-stage recon pattern.
        distinct_categories = sum(bool(x) for x in (scan_hits, long_hits, arp_hits))
        if distinct_categories >= 2:
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        return score


class DNSEvasionHypothesis(Hypothesis):
    """PHASE 21C2: fires on dns_evasion.py's blind-spot audit finding -- real captured
    connections a device's own DNS history can't explain. Distinct from every other
    hypothesis here, which reasons over DNS-query SHAPE (entropy/rate/tunneling
    signatures); this one reasons over ground-truth connections from a reactive
    Fritzbox capture burst versus DNS history, so it can catch a device that's simply
    not using DNS to look things up at all -- structurally invisible to the others by
    design. An unexplained connection alone proves a detection GAP existed, not that
    the device is compromised -- deliberately requires a second independent source
    (another hypothesis's evidence on the same device) to reach 'strong', consistent
    with every other hypothesis's corroboration bar here and with Phase A's tightened
    Telegram gate."""
    # VERSION 11 (P1, review #3/#4): default name for the strong, unambiguous case --
    # a device with genuinely NO DNS footprint at all in the window. See evaluate()'s
    # dynamic override for the weaker "otherwise-normal DNS history, one connection
    # outlived its lookup window" case, which is not the same finding and shouldn't
    # share the same alarming name uncorroborated.
    _NAME_POLICY_BYPASS = "DNS_POLICY_BYPASS"
    _NAME_NO_DNS_HISTORY = "DNS_EVASION"
    _NAME_PARTIAL_GAP = "DNS_ATTRIBUTION_GAP"

    def __init__(self):
        super().__init__(self._NAME_NO_DNS_HISTORY)

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "dns_evasion_anomaly"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        # VERSION 11: provenance is "detector:dns_evasion:{subtag}:{note}" (see
        # dns_evasion.py's audit_device()) -- split(":", 3) with maxsplit=3 yields the
        # stable subtag at index [2], never the free-text note. Precedence matches
        # dns_evasion.py's own subtag precedence: a direct port-53/853 bypass
        # (policy_bypass) is the most specific, most actionable finding -- intentional
        # resolver avoidance, not just an attribution gap. Next is genuinely zero DNS
        # footprint (no_dns_history). A device with otherwise-normal DNS history that
        # just has a couple of attribution-window misses (partial_attribution_gap) is
        # the materially weakest case and gets the most honest, least alarming name
        # unless/until it's independently corroborated (the existing strong_score gate
        # below already requires that for ANY name to reach HIGH).
        subtags = {
            (e.provenance.split(":", 3)[2] if e.provenance.count(":") >= 2 else "")
            for e in hits
        }
        if "policy_bypass" in subtags:
            self.name = self._NAME_POLICY_BYPASS
        elif "no_dns_history" in subtags:
            self.name = self._NAME_NO_DNS_HISTORY
        else:
            self.name = self._NAME_PARTIAL_GAP

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.type != "dns_evasion_anomaly" for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        return score


class SuricataSignatureHypothesis(Hypothesis):
    """VERSION 11 (P2, Suricata follow-up): consumes suricata_scan.py's signature-
    match evidence -- a real Suricata rule match against a curated, high-confidence
    ruleset run in BATCH mode against reactive-capture burst pcaps (never
    continuously against live traffic -- see suricata_scan.py's own docstring for
    why this keeps CPU cost near-zero on both a dev box and a Raspberry Pi target).
    A genuinely high-severity match (confidence>=0.9, Suricata's own severity=1
    "high") is strong enough on its own to be one of decision_engine.py's explicit
    hard-stop conditions (has_confirmed_exploit) -- everything below that threshold
    is real evidence here like any other hypothesis, not a hard-stop."""

    def __init__(self):
        super().__init__("SIGNATURE_MATCHED_THREAT")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.type == "suricata_signature_match"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if len(hits) >= 2:
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.contradicting_score == 0:
            score = 4.0
        return score


class DeviceProfileBenignHypothesis(Hypothesis):
    """VERSION 10 (#9/#10, per-device benign profiles): device_type is a coarse
    CATEGORY classification (smart_tv, iot, gaming_console, nas, router, gateway,
    dns_server, laptop, phone, tablet, printer, camera -- see utils.infer_device_type())
    with no brand dimension at all -- there is no detection basis today to distinguish
    "Amazon Fire TV" from "Google Chromecast" from "generic smart TV", so this
    deliberately does NOT attempt a reviewer-suggested brand-specific catalog
    (AMAZON_DEVICE_TELEMETRY, APPLE_TELEMETRY, MICROSOFT_TELEMETRY, ...) -- that would
    be duplicated, brand-guessing effort with no real signal behind it. What IS
    available and genuinely useful: some device categories are EXPECTED to generate
    frequent traffic to already-trusted/known infrastructure as their normal operating
    behavior (a smart TV or IoT hub constantly phoning its vendor's telemetry endpoints
    is routine; the same volume from a laptop would be more surprising) --
    rep_vector.tier already tells us the destination is trusted (tier 0/1) or known
    infrastructure (tier 2), via the SAME global reputation classifier every other
    hypothesis already relies on (no new per-category domain list to maintain/drift out
    of sync). This lets that combination score a NAMED benign hypothesis instead of
    silently falling through to the generic UNKNOWN_BENIGN catch-all -- pure audit-trail/
    explanation-quality improvement (decision_engine.py only reads a benign hypothesis's
    NAME when nothing attack-worthy won anyway; this does not relax any containment
    threshold)."""

    # Categories where frequent traffic to trusted/known infrastructure is routine,
    # expected behavior rather than merely "not yet proven malicious" -- laptop/phone/
    # tablet/printer/camera are deliberately excluded: those categories don't have the
    # same "constant vendor telemetry is the device's normal job" profile a smart TV,
    # IoT hub, or home-infrastructure box does.
    _EXPECTED_HIGH_VOLUME_CATEGORIES = frozenset({
        "smart_tv", "iot", "gaming_console", "nas", "router", "gateway", "dns_server",
    })

    # BUGFIX (found while verifying this hypothesis, before it was ever committed):
    # decision_engine.py picks whichever of attack/benign scores higher with a strict
    # `>` comparison -- so without this guard, this hypothesis firing at 2.5-3.0 could
    # outright outscore a WEAK-but-genuine attack hypothesis that's dampened (not
    # zeroed) by the same trusted-tier reputation this hypothesis also requires (every
    # attack hypothesis here adds contradicting_score for rep_vector.tier in (1, 2),
    # capping it at its base 2.0 rather than disqualifying it). Verified concretely: a
    # dampened dns_dga_burst signal (DGA_BOTNET_C2, score 2.0) on an iot-category
    # device against trusted infrastructure would otherwise silently downgrade from
    # SUSPICIOUS to BENIGN -- logging nothing at all, worse than the generic
    # UNKNOWN_BENIGN fallback this hypothesis was built to replace. iot is exactly the
    # device category most associated with real-world botnet compromise, so this
    # can't be waved off as a laptop/phone edge case. Any of these evidence types
    # existing at all means some OTHER hypothesis has real attack-relevant material to
    # reason about -- back off entirely rather than risk outscoring it. Deliberately
    # excludes dns_rate/dns_entropy/dns_unique_ratio: those are the same ambiguous
    # signals this hypothesis itself is explaining as routine telemetry, not
    # attack-specific on their own.
    _ATTACK_SHAPED_EVIDENCE_TYPES = frozenset({
        "dns_dga_burst", "dns_tunnel_v2", "zeek_lateral_scan", "malicious_ja3",
        "malicious_ja4", "zeek_notice", "zeek_exfiltration", "zeek_beaconing",
        "zeek_conn_abuse", "zeek_long_conn", "arp_sweep", "dns_evasion_anomaly",
    })

    # VERSION 11 (P1 follow-up, review #9/#10): matches
    # AutonomousFPEngine._BASELINE_FAMILIARITY_OBSERVATIONS (fp_engine.py) -- a
    # familiarity of 0.6 means this device has used this exact port/ASN/domain at
    # least 3 of the 5 observations needed to reach full (1.0) familiarity, without
    # that ever becoming a CONFIRMED_THREAT (baseline observations are only ever
    # recorded from cycles the HEE itself already called BENIGN/ANOMALOUS -- see
    # pipeline.py). A per-device LEARNED pattern, not a global reputation tier or any
    # hardcoded list -- fully generic, ports to any home network unchanged.
    _FAMILIARITY_TRUST_BAR = 0.6

    def __init__(self):
        super().__init__("DEVICE_PROFILE_TELEMETRY")

    def evaluate(self, ev_store: List[Evidence], rep_vector: ReputationVector, device_type: str = "", baseline_familiarity: float = 0.0) -> float:
        self._reset_eval_state()
        is_expected_category = device_type in self._EXPECTED_HIGH_VOLUME_CATEGORIES
        is_trusted_destination = rep_vector.tier in (0, 1, 2)
        # VERSION 11: a destination THIS device has personally, repeatedly talked to
        # without incident is real counter-evidence even when the GLOBAL reputation
        # tier hasn't classified it (tier 3/4) -- an alternate path to the same
        # "routine, not surprising" conclusion is_trusted_destination already grants,
        # scoped to what this one device's own history actually supports.
        is_familiar_destination = baseline_familiarity >= self._FAMILIARITY_TRUST_BAR
        has_elevated_dns_activity = any(e.type == "dns_rate" and e.value > 20 for e in ev_store)
        has_competing_attack_evidence = any(e.type in self._ATTACK_SHAPED_EVIDENCE_TYPES for e in ev_store)

        self.required_satisfied = (
            is_expected_category and (is_trusted_destination or is_familiar_destination)
            and has_elevated_dns_activity and not has_competing_attack_evidence
        )
        if not self.required_satisfied:
            return 0.0

        score = 2.5
        if rep_vector.tier in (0, 1):
            # Tier 0/1 (local/internal or explicitly trusted, e.g. apple.com/google.com)
            # is stronger counter-evidence than tier 2 (merely "known infrastructure,
            # not fully trusted") or familiarity alone -- matches ReputationVector's
            # own docstring ordering.
            score = 3.0
        return score


class HypothesisEngine:
    def __init__(self):
        self.attack_hypotheses = [
            DNSTunnelingHypothesis(), NetworkIntrusionHypothesis(),
            DGAHypothesis(), ExfiltrationHypothesis(), BeaconingHypothesis(),
            DNSTunnelingV2Hypothesis(), ConnectionAbuseHypothesis(),
            DNSEvasionHypothesis(), SuricataSignatureHypothesis(),
        ]
        self.benign_hypotheses = [
            AdvertisingBurstHypothesis(), LocalDeviceDiscoveryHypothesis(),
            DeviceProfileBenignHypothesis(),
        ]

    def evaluate_all(self, ev_store: List[Evidence], rep: ReputationVector, device_type: str = "",
                      baseline_familiarity: float = 0.0) -> Dict[str, Any]:
        best_attack = None
        best_attack_score = 0.0
        
        for h in self.attack_hypotheses:
            score = h.evaluate(ev_store, rep, device_type, baseline_familiarity)
            if score > best_attack_score:
                best_attack_score = score
                best_attack = h

        best_benign = None
        best_benign_score = 0.0
        
        for h in self.benign_hypotheses:
            score = h.evaluate(ev_store, rep, device_type, baseline_familiarity)
            if score > best_benign_score:
                best_benign_score = score
                best_benign = h

        return {
            "attack": {"name": best_attack.name if best_attack else "DIRECT_IOC_HIT", "score": best_attack_score},
            "benign": {"name": best_benign.name if best_benign else "UNKNOWN_BENIGN", "score": best_benign_score}
        }
