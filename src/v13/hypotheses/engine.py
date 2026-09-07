"""
v13 HypothesisEngine (Phase 1/3 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Faithful port of intelligence/hypotheses/engine.py (786 lines, read in full this
session before writing a single line here -- not reconstructed from memory or
research notes, per this project's own "verify, don't assume" standard for
security-critical scoring logic). Every hypothesis's required/strong/contradicting
logic, dynamic naming, and score thresholds are copied line-for-line with only the
mechanical renames v13's Evidence model requires:
  - `e.type`              -> `e.evidence_type`
  - `e.effective_weight()` -> `e.effective_weight()` via ScoredEvidence (below) --
    v13 Evidence doesn't store a decaying `.freshness` on the item itself (that's a
    query-time property, not stored state -- see graph/window.py's own docstring),
    so freshness is computed once per evaluate_all() call and paired with each
    Evidence in a ScoredEvidence wrapper, keeping every hypothesis's own evaluate()
    body visually identical to its v-current counterpart for easy side-by-side audit.

WHAT'S DELIBERATELY DIFFERENT (the actual point of this rewrite, not an accident):
each hypothesis's RELEVANT_EVIDENCE_TYPES stays exactly as declared in v-current
(kept here unchanged) -- it answers "what does evaluate() read," same as always.
INDEPENDENCE_FAMILY_MAP (hypotheses/independence.py) is a completely separate
registry that this file never reads from or writes to -- corroboration-family
counting (Phase 3's decision engine) is computed independently of anything in this
file, the structural fix for the Phase 64 category error.

ReputationVector is reused directly from intelligence/reputation/classifier.py --
a stable, well-documented value object, not a target of any of the plan's
correctness fixes, so forking it would just be duplication for no benefit.
"""
import time
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional

from v13.evidence.model import Evidence

try:
    from intelligence.reputation.classifier import ReputationVector
except ImportError:  # pragma: no cover -- only exercised in this repo's own tree
    ReputationVector = None  # tests supply a minimal stand-in when this import is unavailable

# Matches intelligence/hypotheses/evidence.py's EvidenceStore.get_for_device() exactly
# (confirmed via direct read this session): 600s default TTL, 86400s for the
# "reputation" independence_family -- linear decay, freshness = max(0, 1 - age/ttl).
_DEFAULT_TTL_SECONDS = 600
_REPUTATION_TTL_SECONDS = 86400


def compute_freshness(ev: Evidence, now: float) -> Optional[float]:
    """Returns None for evidence older than its TTL (the v1 equivalent of
    EvidenceStore silently dropping it from active_evidence) -- callers filter
    these out before scoring, matching v1's behavior of never presenting stale
    evidence to a Hypothesis at all."""
    age = now - ev.timestamp
    ttl = _REPUTATION_TTL_SECONDS if ev.independence_family == "reputation" else _DEFAULT_TTL_SECONDS
    if age >= ttl:
        return None
    return max(0.0, 1.0 - (age / ttl))


@dataclass
class ScoredEvidence:
    """Pairs one Evidence item with its freshness for a single evaluate_all() call
    -- keeps every hypothesis body below reading `.evidence_type`/`.value`/
    `.provenance`/`.effective_weight()` exactly like its v-current counterpart,
    without v13 Evidence itself needing to store a decaying, call-order-dependent
    field (which would break the "fresh snapshot" property graph/window.py exists
    to preserve)."""
    evidence: Evidence
    freshness: float

    @property
    def evidence_type(self) -> str:
        return self.evidence.evidence_type

    @property
    def value(self) -> Optional[float]:
        return self.evidence.value

    @property
    def provenance(self) -> str:
        return self.evidence.provenance

    def effective_weight(self) -> float:
        return self.evidence.effective_weight(self.freshness)


def score_evidence(evidence_list: List[Evidence], now: Optional[float] = None) -> List[ScoredEvidence]:
    now = now if now is not None else time.time()
    out = []
    for ev in evidence_list:
        freshness = compute_freshness(ev, now)
        if freshness is not None:
            out.append(ScoredEvidence(ev, freshness))
    return out


class Hypothesis:
    RELEVANT_EVIDENCE_TYPES: FrozenSet[str] = frozenset()

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

    def evaluate(self, ev_store: List[ScoredEvidence], rep_vector, device_type: str = "",
                  baseline_familiarity: float = 0.0) -> float:
        raise NotImplementedError


class DNSTunnelingHypothesis(Hypothesis):
    RELEVANT_EVIDENCE_TYPES = frozenset({"dns_rate", "dns_entropy", "dns_unique_ratio"})

    def __init__(self):
        super().__init__("DNS_TUNNELING")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        has_high_rate = any(e.evidence_type == "dns_rate" and e.value > 100 for e in ev_store)
        has_high_entropy = any(e.evidence_type == "dns_entropy" and e.value > 4.0 for e in ev_store)

        self.required_satisfied = has_high_rate and has_high_entropy
        if not self.required_satisfied:
            return 0.0

        if any(e.evidence_type == "dns_unique_ratio" and e.value > 0.8 for e in ev_store):
            self.strong_score += 1.0

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if self.strong_score > 0.5 and self.contradicting_score == 0 and rep_vector.tier in (3, 4):
            score = 4.0
        return score


class NetworkIntrusionHypothesis(Hypothesis):
    RELEVANT_EVIDENCE_TYPES = frozenset({
        "zeek_lateral_scan", "malicious_ja3", "malicious_ja4", "zeek_notice", "arp_spoof_pending",
    })
    _NAME_NETWORK_INTRUSION = "NETWORK_INTRUSION"
    _NAME_LATERAL_MOVEMENT = "LATERAL_MOVEMENT"

    def __init__(self):
        super().__init__(self._NAME_NETWORK_INTRUSION)

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        # v13 has no shadow-mode concept -- Gap 2's fix (use_gap2_fix=True) is already
        # fully live in v-current by the time this port was written, so it's simply
        # baked in here, not offered as a toggle.
        self._reset_eval_state()
        has_lateral_scan = any(e.evidence_type == "zeek_lateral_scan" and e.value > 0 for e in ev_store)
        has_malicious_tls = any(e.evidence_type in ("malicious_ja3", "malicious_ja4") for e in ev_store)
        has_notable_notice = any(e.evidence_type == "zeek_notice" for e in ev_store)
        has_mac_flip = any(e.evidence_type == "arp_spoof_pending" for e in ev_store)

        self.required_satisfied = has_lateral_scan or has_malicious_tls or has_mac_flip or has_notable_notice
        if not self.required_satisfied:
            return 0.0

        self.name = self._NAME_LATERAL_MOVEMENT if has_lateral_scan else self._NAME_NETWORK_INTRUSION

        strong_count = sum([has_lateral_scan, has_malicious_tls, has_mac_flip])
        if strong_count >= 2:
            self.strong_score += 1.0
        elif has_notable_notice and strong_count >= 1:
            self.strong_score += 0.5

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if self.strong_score > 0.5 and self.contradicting_score == 0 and rep_vector.tier in (3, 4, 5):
            score = 4.0

        if has_lateral_scan and self.contradicting_score == 0:
            score = 4.0
        return score


HYPOTHESIS_RELEVANT_EVIDENCE_TYPES: Dict[str, FrozenSet[str]] = {
    "DNS_TUNNELING": DNSTunnelingHypothesis.RELEVANT_EVIDENCE_TYPES,
    NetworkIntrusionHypothesis._NAME_NETWORK_INTRUSION: NetworkIntrusionHypothesis.RELEVANT_EVIDENCE_TYPES,
    NetworkIntrusionHypothesis._NAME_LATERAL_MOVEMENT: NetworkIntrusionHypothesis.RELEVANT_EVIDENCE_TYPES,
}


class AdvertisingBurstHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("ADVERTISING_BURST")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        has_high_rate = any(e.evidence_type == "dns_rate" and e.value > 50 for e in ev_store)
        self.required_satisfied = has_high_rate and (rep_vector.tier == 2)
        if not self.required_satisfied:
            return 0.0
        score = 3.0
        if not any(e.evidence_type == "dns_entropy" and e.value > 4.0 for e in ev_store):
            score = 4.0
        return score


class LocalDeviceDiscoveryHypothesis(Hypothesis):
    def __init__(self):
        super().__init__("LOCAL_DEVICE_DISCOVERY")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type == "local_device_discovery" and e.value > 0]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        return 2.5


class DGAHypothesis(Hypothesis):
    RELEVANT_EVIDENCE_TYPES = frozenset({"dns_dga_burst", "dns_rate"})

    def __init__(self):
        super().__init__("DGA_BOTNET_C2")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type == "dns_dga_burst"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.evidence_type == "dns_rate" and e.value > 100 for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0 and rep_vector.tier in (3, 4, 5):
            score = 4.0
        return score


class ExfiltrationHypothesis(Hypothesis):
    # "first_contact" (Phase 1a) added to what this hypothesis reads -- see its
    # own strong_score bump below.
    RELEVANT_EVIDENCE_TYPES = frozenset({"zeek_exfiltration", "zeek_beaconing", "reputation", "first_contact"})

    def __init__(self):
        super().__init__("DATA_EXFILTRATION")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type == "zeek_exfiltration"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.evidence_type in ("zeek_beaconing", "reputation") for e in ev_store):
            self.strong_score += 1.0
        # Phase 1a: genuine first-contact-ever (graph/window.py's domain_seen_before(),
        # richer than baseline_familiarity's dict approximation) is a real corroborating
        # signal for exfiltration specifically -- data leaving to a destination this
        # device has NEVER talked to before is more suspicious than unusual-timing
        # traffic to an already-familiar one, which today score identically.
        if any(e.evidence_type == "first_contact" for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.contradicting_score == 0:
            score = 4.0
        # BUGFIX (Phase 1a): the two `best`-gated bumps above were this hypothesis's
        # ONLY path to SUSPICIOUS/HIGH -- strong_score was computed (beaconing/
        # reputation/first_contact) but never actually consulted, making it dead
        # weight in the checklist only. Purely additive floor: a real corroborating
        # signal can raise a moderate-effective_weight exfiltration hit to at least
        # SUSPICIOUS even when `best` alone wouldn't clear 0.6 -- can only raise
        # score relative to the two branches above, never lower it, so no existing
        # high-`best` case is affected.
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = max(score, 3.0)
        return score


class BeaconingHypothesis(Hypothesis):
    RELEVANT_EVIDENCE_TYPES = frozenset({
        "zeek_beaconing", "zeek_exfiltration", "reputation", "malicious_ja3", "malicious_ja4",
        "first_contact",
    })

    def __init__(self):
        super().__init__("C2_BEACONING")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type == "zeek_beaconing"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if any(e.evidence_type in ("zeek_exfiltration", "reputation", "malicious_ja3", "malicious_ja4") for e in ev_store):
            self.strong_score += 1.0
        # Phase 1a: a beacon to a destination this device has never contacted before
        # is more suspicious than a beacon-shaped pattern to a long-familiar one.
        if any(e.evidence_type == "first_contact" for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        return score


class DNSTunnelingV2Hypothesis(Hypothesis):
    RELEVANT_EVIDENCE_TYPES = frozenset({"dns_tunnel_v2", "first_contact"})

    def __init__(self):
        super().__init__("DNS_COVERT_TUNNELING")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type == "dns_tunnel_v2"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)
        # Matches v-current's PHASE 1 FIX exactly: provenance format
        # "detector:threat_signals:dns_tunnel_v2:{subtag}:{note}", split(":", 4)
        # maxsplit=4 -> index [3] is the stable subtag.
        distinct_signals = len({
            e.provenance.split(":", 4)[3] if e.provenance.count(":") >= 3 else e.provenance
            for e in hits
        })

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if distinct_signals >= 2:
            self.strong_score += 1.0
        # Phase 1a: a covert-tunnel-shaped pattern to a destination never seen
        # before this device's own history is a real corroborating signal, same
        # reasoning as Exfiltration/Beaconing above.
        if any(e.evidence_type == "first_contact" for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0 and rep_vector.tier in (3, 4):
            score = 4.0
        return score


class CoordinatedTargetingHypothesis(Hypothesis):
    """v13 full-architecture plan, Phase 1a -- a genuinely new detection
    capability, not a port (no v-current equivalent exists: v-current's
    per-device, in-memory-only RollingWindow has no cross-device view at all).
    Scores up when 2+ distinct devices independently reach the same destination
    within a short window -- a real signal for a compromised fleet, a coordinated
    scan, or several devices independently reaching a shared C2 destination.
    `coordinated_targeting` evidence is synthesized per-cycle by
    v13/ops/live_engine.py from graph/window.py's devices_targeting() query, never
    written back to the graph itself (it's derived context, not a sensor
    observation) -- see that module's own docstring."""
    RELEVANT_EVIDENCE_TYPES = frozenset({"coordinated_targeting"})

    def __init__(self):
        super().__init__("COORDINATED_TARGETING")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type == "coordinated_targeting"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)
        # .value carries the total number of devices (this one + the others) seen
        # targeting the destination -- see live_engine.py's injection site.
        total_devices = max((e.value or 0) for e in hits)

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        if total_devices >= 3:
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        return score


class ConnectionAbuseHypothesis(Hypothesis):
    _NAME_CONNECTION_ABUSE = "CONNECTION_ABUSE"
    _NAME_PORT_SCAN = "PORT_SCAN"
    _NAME_INTERNAL_RECONNAISSANCE = "INTERNAL_RECONNAISSANCE"
    RELEVANT_EVIDENCE_TYPES = frozenset({"zeek_conn_abuse", "zeek_long_conn", "arp_sweep"})

    def __init__(self):
        super().__init__(self._NAME_CONNECTION_ABUSE)

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        scan_hits = [e for e in ev_store if e.evidence_type == "zeek_conn_abuse"]
        long_hits = [e for e in ev_store if e.evidence_type == "zeek_long_conn"]
        arp_hits = [e for e in ev_store if e.evidence_type == "arp_sweep"]
        self.required_satisfied = bool(scan_hits or long_hits or arp_hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in (scan_hits + long_hits + arp_hits))

        if rep_vector.tier in (1, 2):
            self.contradicting_score += 1.0
        distinct_categories = sum(bool(x) for x in (scan_hits, long_hits, arp_hits))
        if distinct_categories >= 2:
            self.strong_score += 1.0

        if distinct_categories == 1:
            if arp_hits:
                self.name = self._NAME_INTERNAL_RECONNAISSANCE
            elif scan_hits:
                self.name = self._NAME_PORT_SCAN
            else:
                self.name = self._NAME_CONNECTION_ABUSE
        else:
            self.name = self._NAME_CONNECTION_ABUSE

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        return score


class DNSEvasionHypothesis(Hypothesis):
    _NAME_POLICY_BYPASS = "DNS_POLICY_BYPASS"
    _NAME_NO_DNS_HISTORY = "DNS_EVASION"
    _NAME_PARTIAL_GAP = "DNS_ATTRIBUTION_GAP"
    RELEVANT_EVIDENCE_TYPES = frozenset({"dns_evasion_anomaly"})

    def __init__(self):
        super().__init__(self._NAME_NO_DNS_HISTORY)

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type == "dns_evasion_anomaly"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)

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
        if any(e.evidence_type != "dns_evasion_anomaly" for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        return score


class SuricataSignatureHypothesis(Hypothesis):
    RELEVANT_EVIDENCE_TYPES = frozenset({"suricata_signature_match"})

    def __init__(self):
        super().__init__("SIGNATURE_MATCHED_THREAT")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type == "suricata_signature_match"]
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


HYPOTHESIS_RELEVANT_EVIDENCE_TYPES.update({
    "DGA_BOTNET_C2": DGAHypothesis.RELEVANT_EVIDENCE_TYPES,
    "DATA_EXFILTRATION": ExfiltrationHypothesis.RELEVANT_EVIDENCE_TYPES,
    "C2_BEACONING": BeaconingHypothesis.RELEVANT_EVIDENCE_TYPES,
    "DNS_COVERT_TUNNELING": DNSTunnelingV2Hypothesis.RELEVANT_EVIDENCE_TYPES,
    ConnectionAbuseHypothesis._NAME_CONNECTION_ABUSE: ConnectionAbuseHypothesis.RELEVANT_EVIDENCE_TYPES,
    ConnectionAbuseHypothesis._NAME_PORT_SCAN: ConnectionAbuseHypothesis.RELEVANT_EVIDENCE_TYPES,
    ConnectionAbuseHypothesis._NAME_INTERNAL_RECONNAISSANCE: ConnectionAbuseHypothesis.RELEVANT_EVIDENCE_TYPES,
    DNSEvasionHypothesis._NAME_POLICY_BYPASS: DNSEvasionHypothesis.RELEVANT_EVIDENCE_TYPES,
    DNSEvasionHypothesis._NAME_NO_DNS_HISTORY: DNSEvasionHypothesis.RELEVANT_EVIDENCE_TYPES,
    DNSEvasionHypothesis._NAME_PARTIAL_GAP: DNSEvasionHypothesis.RELEVANT_EVIDENCE_TYPES,
    "SIGNATURE_MATCHED_THREAT": SuricataSignatureHypothesis.RELEVANT_EVIDENCE_TYPES,
    "COORDINATED_TARGETING": CoordinatedTargetingHypothesis.RELEVANT_EVIDENCE_TYPES,
})


class DeviceProfileBenignHypothesis(Hypothesis):
    _EXPECTED_HIGH_VOLUME_CATEGORIES = frozenset({
        "smart_tv", "iot", "gaming_console", "nas", "router", "gateway", "dns_server",
    })

    # v-current hoists this from hypotheses/evidence.py's module-level
    # ATTACK_SHAPED_EVIDENCE_TYPES so ai_soc.py's validator shares the exact same set.
    # v13 doesn't have that shared-with-the-LLM-validator concern (yet -- Phase 5),
    # so this is declared directly here; kept as its own named constant (not inlined)
    # so a future Phase 5 module can import it the same way v-current's validator does.
    ATTACK_SHAPED_EVIDENCE_TYPES = frozenset({
        "dns_dga_burst", "dns_tunnel_v2", "zeek_lateral_scan", "malicious_ja3",
        "malicious_ja4", "zeek_notice", "zeek_exfiltration", "zeek_beaconing",
        "zeek_conn_abuse", "zeek_long_conn", "arp_sweep", "dns_evasion_anomaly",
        "arp_spoof_pending",
    })

    # Matches fp_engine.py's FAMILIARITY_TRUST_BAR -- v13's CL-AFPE port (Phase 4)
    # doesn't exist yet, so this is a literal copy of the current live value (0.6,
    # confirmed via the v-current source comment referencing "3 of 5 observations"),
    # not an import (no v13 fp_engine module to import from yet).
    FAMILIARITY_TRUST_BAR = 0.6

    def __init__(self):
        super().__init__("DEVICE_PROFILE_TELEMETRY")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        is_expected_category = device_type in self._EXPECTED_HIGH_VOLUME_CATEGORIES
        is_trusted_destination = rep_vector.tier in (0, 1, 2)
        is_familiar_destination = baseline_familiarity >= self.FAMILIARITY_TRUST_BAR
        has_elevated_dns_activity = any(e.evidence_type == "dns_rate" and e.value > 20 for e in ev_store)
        has_competing_attack_evidence = any(e.evidence_type in self.ATTACK_SHAPED_EVIDENCE_TYPES for e in ev_store)

        self.required_satisfied = (
            is_expected_category and (is_trusted_destination or is_familiar_destination)
            and has_elevated_dns_activity and not has_competing_attack_evidence
        )
        if not self.required_satisfied:
            return 0.0

        score = 2.5
        if rep_vector.tier in (0, 1):
            score = 3.0
        return score


class HypothesisEngine:
    def __init__(self):
        self.attack_hypotheses: List[Hypothesis] = [
            DNSTunnelingHypothesis(), NetworkIntrusionHypothesis(),
            DGAHypothesis(), ExfiltrationHypothesis(), BeaconingHypothesis(),
            DNSTunnelingV2Hypothesis(), ConnectionAbuseHypothesis(),
            DNSEvasionHypothesis(), SuricataSignatureHypothesis(),
            CoordinatedTargetingHypothesis(),
        ]
        self.benign_hypotheses: List[Hypothesis] = [
            AdvertisingBurstHypothesis(), LocalDeviceDiscoveryHypothesis(),
            DeviceProfileBenignHypothesis(),
        ]

    def evaluate_all(self, evidence_list: List[Evidence], rep_vector, device_type: str = "",
                       baseline_familiarity: float = 0.0, now: Optional[float] = None) -> Dict[str, Any]:
        """Pure per-cycle evaluation -- ev_store is scored fresh from a plain
        evidence_list each call (typically graph/window.py's evidence_in_window()
        output), never a mutated object carried across cycles. No shadow-mode
        machinery -- v13 has no shipped/unshipped Gap-style variants to compare;
        that entire mechanism was specific to v-current's incremental-flip history."""
        ev_store = score_evidence(evidence_list, now=now)

        best_attack = None
        best_attack_score = 0.0
        for h in self.attack_hypotheses:
            score = h.evaluate(ev_store, rep_vector, device_type, baseline_familiarity)
            if score > best_attack_score:
                best_attack_score = score
                best_attack = h

        best_benign = None
        best_benign_score = 0.0
        for h in self.benign_hypotheses:
            score = h.evaluate(ev_store, rep_vector, device_type, baseline_familiarity)
            if score > best_benign_score:
                best_benign_score = score
                best_benign = h

        checklist = ({
            "required_satisfied": best_attack.required_satisfied,
            "strong_score": best_attack.strong_score,
            "contradicting_score": best_attack.contradicting_score,
        } if best_attack else None)

        return {
            "attack": {
                "name": best_attack.name if best_attack else "DIRECT_IOC_HIT",
                "score": best_attack_score,
                "checklist": checklist,
            },
            "benign": {
                "name": best_benign.name if best_benign else "UNKNOWN_BENIGN",
                "score": best_benign_score,
            },
        }
