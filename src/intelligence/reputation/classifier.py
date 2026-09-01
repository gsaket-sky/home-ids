from dataclasses import dataclass
from typing import Dict, Any, Optional

from utils import is_cloud_cdn_provider_org

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
    # SHADOW-MODE GAP 1 (Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md): True only when
    # tier 5 was reached via ti_score (a genuine curated-feed IOC match -- Feodo/ThreatFox/
    # OTX), never via vt_score/abuse_score alone. Currently READ ONLY by decision_engine.py's
    # shadow computation (does not change the live tier==5 branch's behavior yet) -- see
    # that file's own comment for why. Verified via a live backtest
    # (scripts/shadow_backtest.py against state/alerts.json): of 80 historical
    # "Confirmed Malicious IOC" alerts, ti_score > 2.0 was true for ZERO of them -- every
    # single one was VT/AbuseIPDB aggregate-score-only.
    verified_ioc: bool = False

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
        # BUGFIX: found via a production alerts.json audit spanning 5+ days -- the SAME
        # PHASE 8 case (149.154.166.110, Telegram's own published server infrastructure,
        # AS62041) that the >=4.0 AbuseIPDB bar below was raised specifically to stop
        # auto-blocking on kept RECURRING anyway: AbuseIPDB's crowd-sourced score for a
        # huge, widely-shared IP block naturally drifts above and below any fixed
        # threshold over time as community reports come and go, so raising the bar once
        # only reduced the false-positive rate, it didn't eliminate it. Hundreds of
        # alerts over 5 days, oscillating between "Elevated Reputation Signal
        # (Unconfirmed)" and full "Confirmed Malicious IOC" Stage-1 hard-stops -- for a
        # domain-less raw IP, which the existing domain-based safe-lists/trust-cache can
        # never immunize regardless of how many times it recurs. Same pattern already
        # proven for VPN providers (utils.is_vpn_provider_org(), ASN-org-name matching,
        # not a brittle IP/CIDR list): a known-legitimate, publicly-documented service's
        # own infrastructure shouldn't be re-litigated against a noisy crowd-sourced
        # score every single time, regardless of what that score says on a given day.
        self._SAFE_ASN_OWNER_KEYWORDS = ("telegram",)

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

        # See _SAFE_ASN_OWNER_KEYWORDS' comment above: a known-legitimate service's own
        # infrastructure is tier 2 (known infrastructure) regardless of what a noisy
        # crowd-sourced abuse score says today -- checked BEFORE the confirmed_ioc/
        # weak_signal evaluation below so it can never be overridden back up to tier 4/5.
        # BUGFIX (2026-09-01, HEE-vs-Ollama disagreement audit): _SAFE_ASN_OWNER_KEYWORDS
        # above is a tiny, one-entry list (just "telegram") -- but utils.py's
        # is_cloud_cdn_provider_org() already maintains a broader, deliberately
        # conservative "universally-recognized cloud/CDN infrastructure" list (Google
        # LLC, AWS, Apple, Facebook/Meta, IBM Cloud, Vultr, Leaseweb, Scaleway, Contabo --
        # the SAME list fp_engine.py's confirmed-intel write guard already trusts), and
        # this function never consulted it. Confirmed live: a device's alerts to
        # updates.bravesoftware.com / two Spotify hosts / Datadog's log intake all
        # resolved to 35.186.224.0/24 (Google LLC, AS396982) -- a shared GCP customer
        # range with an AbuseIPDB score >= 4.0 from SOME OTHER tenant's traffic on the
        # same cloud IP block, not from any of these legitimate services. That pushed
        # tier straight to 5 (confirmed_ioc, abuse_score>=4.0 below) for domains that
        # are already treated as safe infrastructure everywhere ELSE in this codebase --
        # 7 of 9 total cases across a 225-case Ollama-review audit where the
        # deterministic validator overrode Ollama's (correct) benign call traced back to
        # exactly this one gap. Same trust boundary this project has already accepted
        # elsewhere, just not previously applied here.
        owner_lower = (asn_owner or "").lower()
        if tier == 3 and (
            any(kw in owner_lower for kw in self._SAFE_ASN_OWNER_KEYWORDS)
            or is_cloud_cdn_provider_org(asn_owner)
        ):
            tier = 2

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
        # BUGFIX: this used to run unconditionally, so ANY explicit tier assigned above
        # (0/1/2, including the new ASN-based safe-infrastructure check) could still be
        # escalated straight back to tier 5 by a single noisy reputation score -- directly
        # contradicting this class's own docstring ("1 trusted... strong counter-evidence
        # required to override"). No existing caller/test relies on a tier-0/1/2 domain
        # being escalatable this way. Only an still-unclassified (tier 3) domain/IP can be
        # promoted by a reputation hit now -- an explicit safe classification is a floor,
        # not a suggestion.
        verified_ioc = False
        if tier == 3:
            if confirmed_ioc:
                tier = 5
                verified_ioc = ti_score > 2.0
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
            source_confidence="high" if tier in (0,1,5) else "medium",
            verified_ioc=verified_ioc,
        )
