"""
v13 HypothesisEngine (Phase 1/3 -- Documentation/ARGUS_AUTONOMY_DEPENDENCY_MAP.md).

Faithful port of argus/hypotheses/engine.py (786 lines, read in full this
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

from argus.evidence.model import Evidence, NO_DESTINATION
from utils import ZEEK_NOTICE_TIER_SCORE_WEIGHT, ZEEK_NOTICE_EVIDENCE_TYPES, ZEEK_NOTICE_ATTACK_SHAPED_EVIDENCE_TYPES

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

    @property
    def destination_id(self) -> str:
        return self.evidence.destination_id

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

    def _effective_rep_tier(self, ev_store: List[ScoredEvidence], rep_vector) -> int:
        """Generalizes a214a2f's per-destination reputation fix (which only
        covered CoordinatedTargetingHypothesis) to every attack hypothesis --
        third-party review flagged the same root cause as still open everywhere
        else: pipeline.py computes ONE rep_vector per cycle for reputation_target
        (whichever destination earned the highest TI/VT/abuse risk score THAT
        CYCLE), reused verbatim by every hypothesis's rep_vector.tier check
        regardless of whether ITS OWN evidence concerns that destination at all
        (confirmed live: two Fire TVs independently streaming Netflix scored as
        coordinated targeting because that cycle's rep_vector described an
        unrelated domain with zero real touching devices -- the exact same shape
        of bug is structurally possible for every other tier-gated hypothesis
        below, just not yet caught live for each one individually).

        Same domain-linkage discipline as argus/decision/engine.py's own Gap-64 fix
        (only strip/ignore when BOTH sides carry destination info and they
        PROVABLY differ; never touch the ambiguous case where either side lacks
        it) -- rep_vector.domain is the ONE destination it was actually computed
        for; if this hypothesis's own RELEVANT_EVIDENCE_TYPES hits carry a real,
        different destination_id, rep_vector describes something else and is
        neutral (tier 3 -- "unclassified," ReputationVector's own documented
        "neutral, NOT malicious by default" value) for this hypothesis's
        purposes, applied to BOTH directions (trust-suppression tier in (0,1,2)
        AND escalation tier in (3,4)/(3,4,5) checks alike) since a wrong tier is
        equally capable of wrongly suppressing a real attack as it is of wrongly
        escalating a benign one. A hypothesis with no RELEVANT_EVIDENCE_TYPES
        declared (the benign hypotheses -- this fix is scoped to attack
        hypotheses only, matching item 3's actual problem statement) can never
        have a real destination to compare against, so this always falls
        through to the ambiguous case for them: today's behavior, unchanged.

        BUGFIX (2026-09-15, gap 2 of the "3 automated-learning gaps" audit): every
        trust-suppression check below used to read `eff_tier in (1, 2)`, silently
        excluding tier 0 ("local/internal, external reputation doesn't apply") even
        though two OTHER hypotheses in this same file (DeviceProfileBenignHypothesis's
        own `is_trusted_destination`/its own escalation check) already correctly
        included tier 0 -- existing, working precedent the rest of the file just never
        adopted. Now that ReputationClassifier.classify() actually assigns tier 0 to
        raw private/link-local/loopback IPs (it previously only matched domain-suffix
        strings -- see that module's own BUGFIX comment), leaving tier 0 out of these
        checks would have meant the fix there couldn't dampen any attack hypothesis at
        all. Widened to `(0, 1, 2)` everywhere below to match the precedent already set."""
        my_destinations = {
            e.destination_id for e in ev_store
            if e.evidence_type in self.RELEVANT_EVIDENCE_TYPES
            and e.destination_id and e.destination_id != NO_DESTINATION
        }
        rep_domain = getattr(rep_vector, "domain", "") or ""
        if my_destinations and rep_domain and rep_domain not in my_destinations:
            return 3
        return rep_vector.tier

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

        # BUGFIX (live audit, 2026-09-09, generalizing a214a2f): eff_tier is
        # rep_vector.tier only when rep_vector actually concerns THIS
        # hypothesis's own evidence destination -- see _effective_rep_tier()'s
        # own docstring.
        eff_tier = self._effective_rep_tier(ev_store, rep_vector)
        if eff_tier in (0, 1, 2):
            self.contradicting_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        # TIGHTENED (third-party architecture review, 2026-09-09): was `tier in
        # (3, 4)` -- tier 3 means "unclassified, no external signal at all," not
        # weak evidence of anything. Reaching this hypothesis's ceiling score
        # required only rate+entropy+unique_ratio plus a destination nobody had
        # ever looked up before, structurally the "unusual is not malicious" gap
        # the review named. Now requires tier 4 (at least one real, if weak,
        # external reputation signal) to reach 4.0 -- being unclassified no longer
        # helps a hypothesis reach its own maximum.
        if self.strong_score > 0.5 and self.contradicting_score == 0 and eff_tier == 4:
            score = 4.0
        return score


# BUGFIX (explicit user request, 2026-09-09): zeek_notice's tier now lives directly
# in evidence_type ("zeek_notice_{tier}", utils.py's ZEEK_NOTICE_EVIDENCE_TYPES)
# instead of a provenance subtag -- confirmed live that zeek_notice evidence was
# 214,795 of 218,405 total evidence rows (98.3%) in .94's graph, and every
# consumer that cared about tier needed to string-parse provenance just to tell
# them apart. _ZEEK_NOTICE_EVIDENCE_TYPE_WEIGHT maps the 4 stable evidence_type
# strings directly to their scoring weight -- a plain dict lookup, no parsing.
_ZEEK_NOTICE_EVIDENCE_TYPE_WEIGHT = {
    f"zeek_notice_{tier}": weight for tier, weight in ZEEK_NOTICE_TIER_SCORE_WEIGHT.items()
}


def _zeek_notice_weight(e: ScoredEvidence) -> float:
    """Returns the scoring weight for a zeek_notice_{tier} evidence item (0.0 for
    anything that isn't one of the 4 known zeek_notice evidence types) -- see
    utils.py's classify_zeek_notice()/ZEEK_NOTICE_TIER_SCORE_WEIGHT for the full
    incident and tier definitions."""
    return _ZEEK_NOTICE_EVIDENCE_TYPE_WEIGHT.get(e.evidence_type, 0.0)


class NetworkIntrusionHypothesis(Hypothesis):
    # BUGFIX (explicit user request, 2026-09-09): "zeek_notice" fragmented into 4
    # evidence_type values by tier (utils.py's ZEEK_NOTICE_EVIDENCE_TYPES).
    RELEVANT_EVIDENCE_TYPES = frozenset({
        "zeek_lateral_scan", "malicious_ja3", "malicious_ja4", "arp_spoof_pending",
    }) | ZEEK_NOTICE_EVIDENCE_TYPES
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
        has_mac_flip = any(e.evidence_type == "arp_spoof_pending" for e in ev_store)

        # BUGFIX (live audit, 2026-09-09): zeek_notice used to count as "notable"
        # purely by PRESENCE, blind to which Notice::Type/weird actually fired --
        # confirmed live against .94's own graph that the single most common notice,
        # weird:data_before_established (a TCP-capture/reordering artifact, not
        # attacker behavior), alone accounted for 68,575 real evidence rows, every
        # one of which could satisfy this hypothesis's required_satisfied gate on
        # its own. _zeek_notice_weight() (module-level, above) now reads the tier
        # zeek_network.py encodes -- only medium-or-above notices can activate or
        # corroborate this hypothesis; weak (routine protocol-edge-case/capture-
        # artifact) notices contribute nothing, matching this codebase's own
        # "unusual is not malicious" rule.
        notice_weight = max((_zeek_notice_weight(e) for e in ev_store), default=0.0)
        has_notable_notice = notice_weight > 0.0

        self.required_satisfied = has_lateral_scan or has_malicious_tls or has_mac_flip or has_notable_notice
        if not self.required_satisfied:
            return 0.0

        self.name = self._NAME_LATERAL_MOVEMENT if has_lateral_scan else self._NAME_NETWORK_INTRUSION

        strong_count = sum([has_lateral_scan, has_malicious_tls, has_mac_flip])
        if strong_count >= 2:
            self.strong_score += 1.0
        elif has_notable_notice and strong_count >= 1:
            self.strong_score += 0.5 * notice_weight
        elif has_notable_notice and notice_weight >= 1.0:
            # A highly_deterministic notice (e.g. a real Intel::Notice/Signatures::
            # match) is real corroborating weight even with no OTHER strong signal
            # this cycle -- still short of strong_count>=2's full 1.0, since it's
            # one signal, not two independently-corroborating ones.
            self.strong_score += 0.75

        eff_tier = self._effective_rep_tier(ev_store, rep_vector)
        if eff_tier in (0, 1, 2):
            self.contradicting_score += 1.0

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if self.strong_score > 0.5 and self.contradicting_score == 0 and eff_tier in (3, 4, 5):
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
    # BUGFIX (live audit, 2026-09-09): a NO-OP today (dns_rate, detectors/dns_behavior.py,
    # never sets .domain -- a device-wide rate aggregate, no single destination), but
    # this hypothesis's rep_vector.tier==2 check is a REQUIRED gate for a BENIGN verdict,
    # not just a suppression modifier -- if dns_rate destination attribution is ever added
    # later (the same gap already closed for zeek_exfiltration/zeek_beaconing via
    # live_engine.py's _NEEDS_LAST_DEST_IP_FALLBACK), an unrelated cycle's rep_vector could
    # wrongly approve real attack traffic as benign "advertising," a worse failure mode
    # than the attack-hypothesis false-negatives this session's fix targets (this one
    # needs LESS corroboration to go wrong: a single required gate, not a corroboration
    # count). Declaring this now, ahead of any live gap, costs nothing (empty
    # my_destinations today means _effective_rep_tier() is a pure pass-through) and closes
    # the risk before it's ever live.
    RELEVANT_EVIDENCE_TYPES = frozenset({"dns_rate"})

    def __init__(self):
        super().__init__("ADVERTISING_BURST")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        has_high_rate = any(e.evidence_type == "dns_rate" and e.value > 50 for e in ev_store)
        self.required_satisfied = has_high_rate and (self._effective_rep_tier(ev_store, rep_vector) == 2)
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

        eff_tier = self._effective_rep_tier(ev_store, rep_vector)
        if eff_tier in (0, 1, 2):
            self.contradicting_score += 1.0
        if any(e.evidence_type == "dns_rate" and e.value > 100 for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0 and eff_tier in (3, 4, 5):
            score = 4.0
        return score


class ExfiltrationHypothesis(Hypothesis):
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

        eff_tier = self._effective_rep_tier(ev_store, rep_vector)
        if eff_tier in (0, 1, 2):
            self.contradicting_score += 1.0
        if any(e.evidence_type in ("zeek_beaconing", "reputation") for e in ev_store):
            self.strong_score += 1.0
        # REMOVED (third-party architecture review, 2026-09-09): first_contact used
        # to also bump strong_score here -- "never talked to this destination
        # before" is real context for HOW to read other evidence, but on its own
        # it's just novelty, not corroboration ("unusual is not malicious"). Its
        # independence_family (novelty_context) was already excluded from
        # num_independent_sources; this closes the same gap at the per-hypothesis
        # score level, where it could still single-handedly raise this hypothesis's
        # OWN score into corroboration range. first_contact stays in
        # RELEVANT_EVIDENCE_TYPES (still valid context ai_soc.py/reporting can
        # read), it just no longer moves the score.

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

        eff_tier = self._effective_rep_tier(ev_store, rep_vector)
        if eff_tier in (0, 1, 2):
            self.contradicting_score += 1.0
        if any(e.evidence_type in ("zeek_exfiltration", "reputation", "malicious_ja3", "malicious_ja4") for e in ev_store):
            self.strong_score += 1.0
        # REMOVED (third-party architecture review, 2026-09-09): see
        # ExfiltrationHypothesis's own comment -- first_contact used to also bump
        # strong_score here; novelty alone is not corroboration.

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        # CAPPED (external architecture review, 2026-09-09): threat_signals.py's
        # zeek_beaconing detector has 3 branches of very different rigor (see its own
        # BUGFIX comment) -- only "persistent_single_target" (interval-regularity,
        # tdr>0.75 across >=15 observations) matches the audit's own bar for genuine
        # beacon evidence ("repeated connections + stable destination + regular
        # intervals"). "low_and_slow"/"uniform_jitter" are real signals worth their
        # own SUSPICIOUS-tier verdict, but neither requires any actual regularity --
        # same "ambiguous case stays at the base floor" treatment DNS_ATTRIBUTION_GAP
        # already gets elsewhere in this file. Matches provenance format exactly as
        # DNSTunnelingV2Hypothesis's own subtag parsing does.
        subtags = {
            (e.provenance.split(":", 4)[3] if e.provenance.count(":") >= 3 else "")
            for e in hits
        }
        if "persistent_single_target" not in subtags:
            score = min(score, 2.0)
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

        eff_tier = self._effective_rep_tier(ev_store, rep_vector)
        if eff_tier in (0, 1, 2):
            self.contradicting_score += 1.0
        if distinct_signals >= 2:
            self.strong_score += 1.0
        # REMOVED (third-party architecture review, 2026-09-09): see
        # ExfiltrationHypothesis's own comment -- first_contact used to also bump
        # strong_score here; novelty alone is not corroboration.

        score = 2.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 3.0
        if best >= 0.85 and self.strong_score > 0 and self.contradicting_score == 0 and eff_tier in (3, 4):
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
    observation) -- see that module's own docstring.

    Release 14, net-new capability N4 (multi-signal campaign detection): widened
    to ALSO score on `fingerprint_campaign` (2+ devices sharing the exact same
    JA3/JA4 TLS fingerprint) and `dga_seed_campaign` (2+ devices hitting
    different domains that share the same computed DGA "generation shape") --
    the same underlying question ("is another device independently corroborating
    this") answered via two more signals a coordinated campaign can share
    instead of, or alongside, a literal destination. All three are synthesized
    the same way (live_engine.py, never persisted), so the scoring logic below
    is unchanged -- it already only reads .effective_weight()/.value generically."""
    RELEVANT_EVIDENCE_TYPES = frozenset({"coordinated_targeting", "fingerprint_campaign", "dga_seed_campaign"})

    def __init__(self):
        super().__init__("COORDINATED_TARGETING")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type in self.RELEVANT_EVIDENCE_TYPES]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)
        # .value carries the total number of devices (this one + the others) seen
        # sharing the signal (destination, fingerprint, or DGA shape) -- see
        # live_engine.py's injection sites.
        total_devices = max((e.value or 0) for e in hits)

        if self._effective_rep_tier(ev_store, rep_vector) in (0, 1, 2):
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

        if self._effective_rep_tier(ev_store, rep_vector) in (0, 1, 2):
            self.contradicting_score += 1.0
        distinct_categories = sum(bool(x) for x in (scan_hits, long_hits, arp_hits))

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
        # REWORKED (third-party architecture review, 2026-09-09): 4.0 used to
        # require `distinct_categories >= 2` -- an ARP sweep (internal recon) and
        # an abnormally-long connection (often just a legitimate large transfer or
        # stream) are conceptually unrelated behaviors from different sensors
        # (arp_sweep is family network_recon; conn_abuse/long_conn is family
        # network_behavior already), so co-occurring already counts them as 2
        # independent sources at the DECISION level -- letting them ALSO grant
        # this ONE hypothesis its own ceiling double-counted the same diversity.
        # Now requires genuine WITHIN-category intensity (matching the pattern
        # every other hypothesis in this file already uses for its own 4.0),
        # never mere co-occurrence of unrelated categories.
        if best >= 0.85 and self.contradicting_score == 0:
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

        if self._effective_rep_tier(ev_store, rep_vector) in (0, 1, 2):
            self.contradicting_score += 1.0
        if any(e.evidence_type != "dns_evasion_anomaly" for e in ev_store):
            self.strong_score += 1.0

        score = 2.0
        if best >= 0.6 and self.contradicting_score == 0:
            score = 3.0
        if self.strong_score > 0 and self.contradicting_score == 0:
            score = 4.0
        # CAPPED (third-party architecture review, 2026-09-09): DNS_ATTRIBUTION_GAP
        # is the fallback name for "this DNS-shaped anomaly doesn't clearly match
        # either confirmed pattern above" -- an acknowledged ambiguity, not a
        # confirmed finding, but it was climbing the identical 2.0->3.0->4.0 ladder
        # as DNS_POLICY_BYPASS (an actively-evaded resolver) and DNS_EVASION (zero
        # DNS history at all), both real, specific, confirmed shapes -- and it's by
        # far the largest-volume category in production. Only a genuinely
        # classified evasion pattern can now reach SUSPICIOUS+/HIGH-contributing
        # territory; the ambiguous case stays at the base floor, still visible,
        # never independently escalating.
        if self.name == self._NAME_PARTIAL_GAP:
            score = min(score, 2.0)
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

        if self._effective_rep_tier(ev_store, rep_vector) in (0, 1, 2):
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
    # BUGFIX (live audit + explicit user request, 2026-09-09): "zeek_notice" used to
    # be a single flat type here, requiring a special-cased tier check in evaluate()
    # below (weak-tier notices, ~90% of all zeek_notice volume, shouldn't veto an
    # otherwise-legitimate benign verdict). Now that evidence_type is fragmented by
    # tier (utils.py's ZEEK_NOTICE_EVIDENCE_TYPES), the fix is just: don't include
    # the weak variant in this set at all -- ZEEK_NOTICE_ATTACK_SHAPED_EVIDENCE_TYPES
    # already excludes it, so evaluate() needs no special-casing anymore.
    ATTACK_SHAPED_EVIDENCE_TYPES = frozenset({
        "dns_dga_burst", "dns_tunnel_v2", "zeek_lateral_scan", "malicious_ja3",
        "malicious_ja4", "zeek_exfiltration", "zeek_beaconing",
        "zeek_conn_abuse", "zeek_long_conn", "arp_sweep", "dns_evasion_anomaly",
        "arp_spoof_pending",
    }) | ZEEK_NOTICE_ATTACK_SHAPED_EVIDENCE_TYPES

    # Familiarity at or above this counts as "this device normally talks here" (3 of 5 observations).
    FAMILIARITY_TRUST_BAR = 0.6

    # BUGFIX (live audit, 2026-09-09): see AdvertisingBurstHypothesis's own comment --
    # same NO-OP-today, latent-risk-later reasoning (dns_rate never carries a
    # destination yet). is_familiar_destination is a separate, real per-device signal
    # already OR'd in here and has_competing_attack_evidence is a safety valve (any
    # attack-shaped evidence at all blocks this verdict outright regardless of tier),
    # so the live risk here is smaller than AdvertisingBurstHypothesis's single-gate
    # case -- still worth closing for the same reason.
    RELEVANT_EVIDENCE_TYPES = frozenset({"dns_rate"})

    def __init__(self):
        super().__init__("DEVICE_PROFILE_TELEMETRY")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        eff_tier = self._effective_rep_tier(ev_store, rep_vector)
        is_expected_category = device_type in self._EXPECTED_HIGH_VOLUME_CATEGORIES
        is_trusted_destination = eff_tier in (0, 1, 2)
        is_familiar_destination = baseline_familiarity >= self.FAMILIARITY_TRUST_BAR
        has_elevated_dns_activity = any(e.evidence_type == "dns_rate" and e.value > 20 for e in ev_store)
        # BUGFIX (live audit, 2026-09-09): this "safety valve" used to treat ANY
        # zeek_notice as competing attack evidence purely by presence, blind to
        # tier -- given how common weak-tier notices are (a single TCP-capture
        # artifact type alone fired 68,575 times on .94's real network), this made
        # the safety valve fire on nearly every active device, making a benign
        # device-profile verdict nearly unreachable in practice whenever ordinary
        # background noise was present.
        # BUGFIX (explicit user request, 2026-09-09): now that zeek_notice's tier
        # lives directly in evidence_type, this is a plain membership check again --
        # ATTACK_SHAPED_EVIDENCE_TYPES above already excludes zeek_notice_weak, so
        # no special-casing is needed here anymore.
        has_competing_attack_evidence = any(
            e.evidence_type in self.ATTACK_SHAPED_EVIDENCE_TYPES for e in ev_store
        )

        self.required_satisfied = (
            is_expected_category and (is_trusted_destination or is_familiar_destination)
            and has_elevated_dns_activity and not has_competing_attack_evidence
        )
        if not self.required_satisfied:
            return 0.0

        score = 2.5
        if eff_tier in (0, 1):
            score = 3.0
        return score


class PeerDeviationHypothesis(Hypothesis):
    """Release 14, net-new capability N2 -- a genuinely new detection
    capability answering "does this device deviate from similar devices,"
    generalizing the SAME cross-device-query mechanism Phase 1a/N4 already
    proved out to a peer-COMPARISON question rather than a peer-CORROBORATION
    one. `peer_deviation` evidence is synthesized per-cycle by
    v13/ops/live_engine.py's _inject_peer_deviation_evidence() from a
    device_type-grouped distinct-destination-count comparison, never written
    back to the graph itself (derived context, same principle as every other
    Phase 1a/N4 synthetic signal).

    HONEST STATUS, not hidden: unlike coordinated_targeting/fingerprint_
    campaign/dga_seed_campaign (all reuse well-established, low-false-positive
    correlation concepts), this is a genuinely NEW, unvalidated anomaly
    heuristic -- real cohort variance could produce a real false positive with
    no live tuning data yet. Deliberately capped at a SUSPICIOUS ceiling (3.0)
    on its own -- this signal alone should prompt a closer look via
    corroboration with something else (the decision engine's own >=2-
    independent-source bar for HIGH already enforces that structurally), never
    an autonomous escalation to HIGH by itself the way an established signal
    can reach."""
    RELEVANT_EVIDENCE_TYPES = frozenset({"peer_deviation"})

    def __init__(self):
        super().__init__("PEER_COHORT_DEVIATION")

    def evaluate(self, ev_store, rep_vector, device_type="", baseline_familiarity=0.0) -> float:
        self._reset_eval_state()
        hits = [e for e in ev_store if e.evidence_type == "peer_deviation"]
        self.required_satisfied = bool(hits)
        if not self.required_satisfied:
            return 0.0
        best = max(e.effective_weight() for e in hits)
        if self._effective_rep_tier(ev_store, rep_vector) in (0, 1, 2):
            self.contradicting_score += 1.0
        if best >= 0.5 and self.contradicting_score == 0:
            return 3.0
        return 2.0


HYPOTHESIS_RELEVANT_EVIDENCE_TYPES.update({
    "PEER_COHORT_DEVIATION": PeerDeviationHypothesis.RELEVANT_EVIDENCE_TYPES,
})


# SECURITY FIX (live alert audit, 2026-09-28): decision/engine.py's Gap-64
# destination-anchoring filter uses this registry to decide "which destination(s)
# is the winning hypothesis actually about" -- HYPOTHESIS_RELEVANT_EVIDENCE_TYPES
# is the wrong source for that question, because it mixes each hypothesis's
# REQUIRED evidence type(s) (what required_satisfied gates on -- the type that
# defines what the verdict is fundamentally ABOUT) with merely-corroborating
# types (only ever consulted for strong_score, e.g. reputation/malicious_ja3/
# malicious_ja4/zeek_beaconing-as-corroboration-for-Exfiltration). When a
# corroborating type can itself carry a real, independently-meaningful
# destination_id (reputation is the live example: added on ANY nonzero TI/VT/
# AbuseIPDB hit ANYWHERE in the device's window, pipeline.py), that evidence's
# own destination gets unioned into the "acceptable" set purely by being
# present -- then trivially passes the very check meant to verify relatedness,
# since its own destination is now a member of a set it contributed to itself.
#
# Confirmed live: a DATA_EXFILTRATION verdict (required evidence:
# zeek_exfiltration, real destination an EC2 instance IP) reached HIGH via "2
# independent evidence families" where the second family was a reputation hit
# about a COMPLETELY unrelated S3 bucket domain the device merely also touched
# that window -- exactly the unrelated-evidence-combination failure this whole
# destination-anchoring mechanism exists to prevent, reintroduced one level up
# via its own corroboration-type inputs.
#
# This registry is the fix: ONLY a hypothesis's required/anchor evidence
# type(s) may define its accepted destination set. Every hypothesis whose
# RELEVANT_EVIDENCE_TYPES is already exactly its required set (no separate
# corroboration-only member capable of carrying an unrelated destination of its
# own -- true for every hypothesis except the two below, since their other
# corroborating types are either single-family-with-the-anchor already
# [dns_unique_ratio/dns_rate], destination-less by construction [first_contact,
# excluded from attack_evidence entirely via NON_ATTACK_FAMILIES], or
# inherently multi-destination by design with no single anchor to narrow to
# [arp_sweep] -- see ConnectionAbuseHypothesis's own REWORKED comment above)
# is unaffected here: defaulting to HYPOTHESIS_RELEVANT_EVIDENCE_TYPES keeps
# their existing, already-correct behavior unchanged. Only DATA_EXFILTRATION
# and C2_BEACONING actually have the vulnerable shape (a single required type,
# plus a corroborating type -- reputation -- that carries a real destination of
# its own), so only those two are narrowed.
HYPOTHESIS_ANCHOR_EVIDENCE_TYPES: Dict[str, FrozenSet[str]] = {
    **HYPOTHESIS_RELEVANT_EVIDENCE_TYPES,
    "DATA_EXFILTRATION": frozenset({"zeek_exfiltration"}),
    "C2_BEACONING": frozenset({"zeek_beaconing"}),
}


class HypothesisEngine:
    def __init__(self):
        self.attack_hypotheses: List[Hypothesis] = [
            DNSTunnelingHypothesis(), NetworkIntrusionHypothesis(),
            DGAHypothesis(), ExfiltrationHypothesis(), BeaconingHypothesis(),
            DNSTunnelingV2Hypothesis(), ConnectionAbuseHypothesis(),
            DNSEvasionHypothesis(), SuricataSignatureHypothesis(),
            CoordinatedTargetingHypothesis(), PeerDeviationHypothesis(),
        ]
        self.benign_hypotheses: List[Hypothesis] = [
            AdvertisingBurstHypothesis(), LocalDeviceDiscoveryHypothesis(),
            DeviceProfileBenignHypothesis(),
        ]

    def evaluate_all(self, evidence_list: List[Evidence], rep_vector, device_type: str = "",
                       baseline_familiarity: float = 0.0, now: Optional[float] = None,
                       familiarity_trust_bar: Optional[float] = None) -> Dict[str, Any]:
        """Pure per-cycle evaluation -- ev_store is scored fresh from a plain
        evidence_list each call (typically graph/window.py's evidence_in_window()
        output), never a mutated object carried across cycles. No shadow-mode
        machinery -- v13 has no shipped/unshipped Gap-style variants to compare;
        that entire mechanism was specific to v-current's incremental-flip history.

        familiarity_trust_bar (2026-09-27, Phase 3 of the autonomy-completion
        effort): plain float resolved by the caller (decision/engine.py, itself
        just passing through what live_engine.py resolved) -- this module stays
        autotune-agnostic, same reasoning as decision/engine.py's own
        hard_stop_candidate_sensitivity param. None preserves DeviceProfileBenign
        Hypothesis's own hardcoded FAMILIARITY_TRUST_BAR class default. Applied as
        an INSTANCE attribute override (not threaded through evaluate()'s shared
        positional signature, which every other hypothesis class also uses
        unchanged) -- the minimal-blast-radius way to reach one specific
        hypothesis's one specific constant without changing the other 15 classes'
        call convention."""
        ev_store = score_evidence(evidence_list, now=now)

        if familiarity_trust_bar is not None:
            for h in self.benign_hypotheses:
                if isinstance(h, DeviceProfileBenignHypothesis):
                    h.FAMILIARITY_TRUST_BAR = familiarity_trust_bar

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
