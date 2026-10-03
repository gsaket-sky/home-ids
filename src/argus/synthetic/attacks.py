"""
argus/synthetic/attacks.py -- Release 15 Sheet 01: synthetic anomaly injection
generators, the anti-poisoning backbone the plan's Phase 2 backtest and
Phase 3 autotuner/CL-AFPE both gate on.

Confirmed via direct research before writing this: NO synthetic anomaly
injection capability exists anywhere in this codebase before this file --
only hand-written static test fixtures (tests/test_argus_decision_engine.py)
and real-incident replays (tests/test_real_world_alert_regression.py).

Each generator returns a list of argus Evidence items shaped like a real
attack of that class, using only evidence_type strings already registered
in hypotheses/independence.py's INDEPENDENCE_FAMILY_MAP -- never a made-up
type the decision engine wouldn't actually recognize. Every generator
accepts an `intensity` in {"low", "high"} and varies OTHER parameters
(timing, destination, magnitude) across calls even at the same intensity --
signature diversity, not one canned shape per class, so a backtest floor-
check win means the attack CLASS is covered, not one memorized instance of
it (the plan's own explicit fix for an autotuner that could otherwise
become excellent at passing its own test suite specifically).

Credential-stuffing has no dedicated evidence_type in this codebase yet --
`zeek_conn_abuse` (repeated-connection-attempt shape, already registered,
family=network_behavior) is the closest real, already-recognized stand-in,
used here explicitly rather than inventing a new unregistered type.
"""
import random
import time
import uuid
from typing import List, Optional

from argus.evidence.model import Evidence, NO_DESTINATION
from argus.hypotheses.independence import family_for

_SYNTHETIC_SOURCE = "v13.synthetic.attacks"


def _ev(device_id: str, evidence_type: str, value: float, confidence: float,
         dest: str = NO_DESTINATION, timestamp: Optional[float] = None) -> Evidence:
    return Evidence(
        device_id=device_id, destination_id=dest, evidence_type=evidence_type,
        independence_family=family_for(evidence_type), timestamp=timestamp or time.time(),
        source=_SYNTHETIC_SOURCE, value=value, confidence=confidence,
        provenance="synthetic_injection",
        features={"synthetic": True, "injection_id": uuid.uuid4().hex},
    )


def _synthetic_ip(seed: Optional[int] = None) -> str:
    r = random.Random(seed)
    return f"198.51.100.{r.randint(1, 254)}"  # RFC 5737 TEST-NET-2 -- real public-shaped IP, never a live one


def port_scan(device_id: str, now: Optional[float] = None, intensity: str = "high") -> List[Evidence]:
    """A real port-scan-shaped signal: arp_sweep (network_recon family) plus
    a matching zeek_lateral_scan on the same destination. Diversity: sweep
    count and the destination vary per call."""
    now = now if now is not None else time.time()
    dest = _synthetic_ip()
    count = random.randint(15, 40) if intensity == "high" else random.randint(6, 14)
    return [
        _ev(device_id, "arp_sweep", float(count), confidence=0.6 if intensity == "high" else 0.4,
             dest=dest, timestamp=now),
        _ev(device_id, "zeek_lateral_scan", 1.0, confidence=0.55, dest=dest, timestamp=now + 1),
    ]


def dga_dns_tunnel(device_id: str, now: Optional[float] = None, intensity: str = "high") -> List[Evidence]:
    """DGA/DNS-tunneling-shaped signal. Diversity: sometimes NXDOMAIN-heavy
    (classic DGA probing), sometimes NXDOMAIN-light but high-volume/high-
    entropy (a tunnel using resolved subdomains instead) -- two real, distinct
    real-world shapes of this same broad attack class, not one fixed pattern."""
    now = now if now is not None else time.time()
    dest = f"{uuid.uuid4().hex[:16]}.invalid"
    variant = random.choice(["nxdomain_heavy", "resolved_tunnel"])
    burst = random.randint(80, 200) if intensity == "high" else random.randint(20, 60)
    items = [_ev(device_id, "dns_dga_burst", float(burst), confidence=0.65, dest=dest, timestamp=now)]
    if variant == "nxdomain_heavy":
        items.append(_ev(device_id, "dns_tunnel_v2", 1.0, confidence=0.5, dest=dest, timestamp=now + 1))
    else:
        items.append(_ev(device_id, "dns_evasion_anomaly", 1.0, confidence=0.55, dest=dest, timestamp=now + 1))
    return items


def c2_beaconing(device_id: str, now: Optional[float] = None, intensity: str = "high") -> List[Evidence]:
    """C2-beaconing-shaped signal. Diversity: fast (short, regular interval,
    the naive/high-confidence shape) vs. slow/jittered (a more evasive real
    beaconing pattern, intentionally lower confidence to reflect genuine
    real-world detection difficulty)."""
    now = now if now is not None else time.time()
    dest = _synthetic_ip()
    fast = intensity == "high" or random.random() < 0.5
    confidence = 0.6 if fast else 0.4
    return [_ev(device_id, "zeek_beaconing", 1.0, confidence=confidence, dest=dest, timestamp=now)]


def exfiltration(device_id: str, now: Optional[float] = None, intensity: str = "high") -> List[Evidence]:
    """Exfiltration-shaped signal: a large outbound-byte burst. Diversity:
    a genuinely massive single burst (high z-score) vs. a large absolute
    volume spread thinner (lower z-score, still a real exfil shape --
    the same "vendor-cloud dampening should reduce, never zero out"
    real-incident distinction this codebase's own real regression suite
    already encodes, tests/test_real_world_alert_regression.py:397-442)."""
    now = now if now is not None else time.time()
    dest = _synthetic_ip()
    if intensity == "high":
        value, confidence = random.uniform(4_000_000, 15_000_000), 0.7
    else:
        value, confidence = random.uniform(500_000, 2_000_000), 0.45
    return [_ev(device_id, "zeek_exfiltration", value, confidence=confidence, dest=dest, timestamp=now)]


def credential_stuffing(device_id: str, now: Optional[float] = None, intensity: str = "high") -> List[Evidence]:
    """No dedicated evidence_type exists for this class yet -- zeek_conn_abuse
    (repeated-connection-attempt shape) is the closest already-registered
    stand-in, used explicitly rather than inventing an unregistered type."""
    now = now if now is not None else time.time()
    dest = _synthetic_ip()
    attempts = random.randint(20, 80) if intensity == "high" else random.randint(6, 19)
    return [_ev(device_id, "zeek_conn_abuse", float(attempts), confidence=0.55, dest=dest, timestamp=now)]


def lateral_movement(device_id: str, now: Optional[float] = None, intensity: str = "high") -> List[Evidence]:
    """Lateral-movement-shaped signal: peer-cohort deviation plus a real
    coordinated-targeting cross-device signal (both already NON_ATTACK_
    FAMILIES-adjacent or cross_device_correlation -- corroborating-only
    by design, matching how this exact class fires in the real engine)."""
    now = now if now is not None else time.time()
    dest = _synthetic_ip()
    my_count = random.randint(80, 250) if intensity == "high" else random.randint(30, 79)
    return [
        _ev(device_id, "peer_deviation", float(my_count), confidence=0.5, dest=NO_DESTINATION, timestamp=now),
        _ev(device_id, "coordinated_targeting", 1.0, confidence=0.6, dest=dest, timestamp=now + 1),
    ]


def honeypot_touch(device_id: str, now: Optional[float] = None, intensity: str = "high") -> List[Evidence]:
    """A real honeypot touch is, by this codebase's own design, always a
    strong, near-deterministic signal -- diversity here is only in which
    synthetic honeypot destination was touched, not in confidence/intensity
    (a real touch doesn't come in "low intensity")."""
    now = now if now is not None else time.time()
    dest = _synthetic_ip()
    return [_ev(device_id, "honeypot_access", 1.0, confidence=0.9, dest=dest, timestamp=now)]


ATTACK_GENERATORS = {
    "port_scan": port_scan,
    "dga_dns_tunnel": dga_dns_tunnel,
    "c2_beaconing": c2_beaconing,
    "exfiltration": exfiltration,
    "credential_stuffing": credential_stuffing,
    "lateral_movement": lateral_movement,
    "honeypot_touch": honeypot_touch,
}


def benign_drift(device_id: str, now: Optional[float] = None) -> List[Evidence]:
    """The companion to every attack generator above: weird-but-harmless
    variation, specifically to catch a tuner that's become so aggressive
    everything looks suspicious -- not a detection-recall test, a false-
    positive-resistance one. A first_contact (novelty_context,
    NON_ATTACK_FAMILIES) touch to a plausible new CDN-shaped destination --
    genuinely benign traffic shape, deliberately not attack-shaped at all."""
    now = now if now is not None else time.time()
    dest = _synthetic_ip()
    return [_ev(device_id, "first_contact", 1.0, confidence=0.3, dest=dest, timestamp=now)]
