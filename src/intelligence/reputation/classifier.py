from dataclasses import dataclass
from typing import Dict, Any, Optional

@dataclass
class ReputationVector:
    """`tier` is a reputation/context classification — "how much prior trust or suspicion
    attaches to this destination" — not a threat score or a verdict. It does NOT mean
    "tier 4 is 4x more dangerous than tier 1". decision_engine.py treats tier 5 as
    corroborated-enough to justify auto-block; every lower tier only ever contributes
    context toward hypothesis evaluation, never a verdict on its own.

    0 local/internal (fritz.box, RFC1918)     — external reputation doesn't apply
    1 trusted (apple.com, google.com, ...)    — strong counter-evidence required to override
    2 known infrastructure (CDNs, cloud)      — lower suspicion, not fully trusted
    3 unclassified                            — neutral, NOT malicious by default
    4 one unconfirmed signal                  — worth surfacing, not worth auto-blocking
    5 corroborated (TI/VT match, or a very high single-source signal) — can justify auto-block
    """
    domain: str
    tier: int
    asn_owner: str = "Unknown"
    vt_detection_ratio: float = 0.0
    ti_risk: float = 0.0
    abuse_risk: float = 0.0
    cl_afpe_similarity: float = 0.0
    first_seen: bool = False
    source_confidence: str = "medium"

def _suffix_or_domain_match(domain: str, pattern: str) -> bool:
    """PHASE 0 FIX: boundary-safe tier matching. The old `domain.endswith(pattern)` check
    matched on raw substrings, so 'notgoogle.com'.endswith('google.com') was True — any
    domain that happened to END with a trusted domain's characters (not just a real
    subdomain of it) got silently promoted to a trusted tier. Patterns starting with '.'
    are true suffix patterns (e.g. '.local') where the leading dot already enforces a
    boundary; bare domain patterns (e.g. 'google.com') now require an exact match or a
    real subdomain relationship ('.' + pattern)."""
    if pattern.startswith("."):
        return domain.endswith(pattern)
    return domain == pattern or domain.endswith("." + pattern)


class ReputationClassifier:
    def __init__(self):
        self._TIER_0 = {".box", ".local", "fritz.box"}
        self._TIER_1 = {"apple.com", "microsoft.com", "google.com", "icloud.com", "windowsupdate.com"}
        self._TIER_2 = {"doubleclick.net", "cloudflare.com", "amazonaws.com", "azure.com", "akamaiedge.net", "googlesyndication.com"}

    def classify(self, domain: str, vt_score: float = 0.0, afpe_score: float = 0.0, is_new: bool = False, ti_score: float = 0.0, abuse_score: float = 0.0, asn_owner: str = "Unknown") -> ReputationVector:
        domain = (domain or "").lower().strip(".")
        tier = 3 # Unknown by default

        # Check explicit tiers (boundary-safe matching — see _suffix_or_domain_match)
        for t0 in self._TIER_0:
            if _suffix_or_domain_match(domain, t0):
                tier = 0
                break
        if tier == 3:
            for t1 in self._TIER_1:
                if _suffix_or_domain_match(domain, t1):
                    tier = 1
                    break
        if tier == 3:
            for t2 in self._TIER_2:
                if _suffix_or_domain_match(domain, t2):
                    tier = 2
                    break

        # PHASE 8 FIX: a live alert for 149.154.166.110 (Telegram's own API infrastructure,
        # AS62041) reached "Confirmed Malicious IOC" / 99% confidence / auto-block purely
        # from an AbuseIPDB score of 3.78 (~63% abuseConfidenceScore) — with VirusTotal and
        # ThreatIntel both at 0.0. AbuseIPDB is a crowd-sourced abuse-report aggregate, not
        # IOC confirmation, and it's routinely non-zero for widely-shared infrastructure.
        # fp_engine.py's own Stage 1 hard-stop already treats this exact metric
        # conservatively (only "cannot be a FP" at abuse>=4.0) — this threshold used to be
        # a lower, disagreeing bar (>2.0) for the identical number. VT (multi-vendor
        # detection) and TI (curated malware-blacklist feeds: Feodo/ThreatFox/OTX) are both
        # more authoritative single-source signals and keep their original >2.0 bar;
        # AbuseIPDB alone now has to clear the same 4.0 bar fp_engine already trusted it at.
        confirmed_ioc = vt_score > 2.0 or ti_score > 2.0 or abuse_score >= 4.0
        weak_signal = vt_score > 0.0 or ti_score > 0.0 or abuse_score > 0.0
        if confirmed_ioc:
            tier = 5
        elif weak_signal:
            tier = 4 # Weak/unconfirmed detection — surfaced as SUSPICIOUS/monitor by
                     # decision_engine.py, never auto-blocked on this alone (see PHASE 8 there).

        return ReputationVector(
            domain=domain,
            tier=tier,
            asn_owner=asn_owner or "Unknown",
            vt_detection_ratio=vt_score,
            ti_risk=ti_score,
            abuse_risk=abuse_score,
            cl_afpe_similarity=afpe_score,
            first_seen=is_new,
            source_confidence="high" if tier in (0,1,5) else "medium"
        )
