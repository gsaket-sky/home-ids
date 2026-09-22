"""
plain_explanation.py -- plain-English narrative of why an alert fired, was
suppressed, or was only logged, for a non-technical reader (Documentation/
ALERT_TRACE_GRAPH_PLAN.md, 2026-09-22 follow-up: "rewrite the telegram alert...
based on evidence graph, with device, evidence, HEE, counter argument...
readability for a normal user in plain text, no technical words").

Reuses the SAME semantic labels already used for the console's Evidence Graph
tab (middleware/humanize.py's label_evidence_type()/label_hypothesis()) rather
than a second, separately-drifting vocabulary -- "use the semantic information
stored in graph" per the same request.

Built entirely from data this engine ALREADY computes every alert-worthy cycle
(the hypothesis dict, the evidence-type list, fp_verdict) -- nothing here is a
new detection signal, only a translation of the engine's own real reasoning
into a sentence a non-technical reader can follow. "Counter argument" means
literally that: the losing hypothesis (almost always 'benign') and its own
score, stated honestly, not glossed over.
"""
from typing import Any, Dict, List, Optional

from middleware.humanize import label_evidence_type, label_hypothesis


def _describe_target(
    dest_ip: str, dest_domain: str,
    peer_hostname: Optional[str], peer_ip: Optional[str],
    dest_hostname: Optional[str], asn_owner: Optional[str], asn_country: Optional[str],
) -> Optional[str]:
    """Returns a plain-English clause describing what was contacted, or None if
    this alert genuinely has no single destination (e.g. PEER_COHORT_DEVIATION's
    evidence is a device-level behavioral statistic, not one connection -- see
    pipeline.py's own PEER_COHORT_DEVIATION special-casing for the same reason)."""
    has_domain = bool(dest_domain) and dest_domain != "unknown"
    has_ip = bool(dest_ip) and dest_ip != "unknown"
    if not has_domain and not has_ip:
        return None

    # A destination that's actually another device on THIS network -- covers
    # both a genuine "peer device" (coordinated activity, lateral movement) and
    # the common case of a destination IP simply belonging to a tracked local
    # device (e.g. a honeypot decoy host, an internal target of a port scan).
    if peer_hostname and peer_ip:
        return f"another device on your network, {peer_hostname} ({peer_ip})"

    if has_domain:
        ip_note = f", at address {dest_ip}" if has_ip else ""
        return f"a server at {dest_domain}{ip_note}"

    # IP-only destination -- use its resolved hostname when one exists, and
    # name whoever operates it (ASN owner) when that's known, so a bare IP
    # address is never the ONLY thing a non-technical reader is given.
    who = f", known as {dest_hostname}" if dest_hostname else ""
    operator = None
    if asn_owner and asn_owner != "Unknown":
        operator = asn_owner + (f" in {asn_country}" if asn_country else "")
    operator_note = f", run by {operator}" if operator else ""
    return f"an outside server at {dest_ip}{who}{operator_note}"


def _describe_counter_argument(hee_hypotheses: Dict[str, Any], winning_name: Optional[str]) -> Optional[str]:
    """The losing hypothesis's own score, stated plainly -- "the counter
    argument" the system itself weighed and rejected (or, when close, didn't
    fully rule out). Returns None if there's nothing to contrast (e.g. only one
    hypothesis was ever in play)."""
    losers = [
        h for key, h in (hee_hypotheses or {}).items()
        if isinstance(h, dict) and h.get("name") and h.get("name") != winning_name
    ]
    if not losers:
        return None
    loser = losers[0]
    loser_label, _ = label_hypothesis(loser.get("name"))
    score = loser.get("score") or 0.0
    if score <= 0.5:
        return f"The system also checked whether this could just be normal activity ({loser_label.lower()}) and found essentially nothing to support that."
    return (
        f"The system also checked whether this could just be normal activity ({loser_label.lower()}) "
        f"and found some support for that too -- which is part of why this wasn't treated as a more severe alert."
    )


_STATUS_CLOSING = {
    "FIRED": "Because of this, you're being notified now.",
    "SUPPRESSED_AUTONOMOUS": "The system decided this is very likely nothing to worry about and did not send you a notification -- you're only seeing this in the record.",
    "LOGGED_ONLY": "This wasn't serious enough to notify you about right away, so it was simply logged for the record.",
    "AWAITING_APPROVAL": "The system is waiting for you to approve or dismiss this before taking any action.",
}


def build_plain_explanation(
    hostname: str, client_ip: str, device_type: Optional[str],
    dest_ip: str, dest_domain: str,
    hee_hypotheses: Dict[str, Any], winning_name: Optional[str],
    hee_evidence_types: List[str],
    fp_verdict: Optional[str], fp_stage: Optional[str],
    alert_status: str,
    peer_hostname: Optional[str] = None, peer_ip: Optional[str] = None,
    dest_hostname: Optional[str] = None, asn_owner: Optional[str] = None,
    asn_country: Optional[str] = None,
) -> str:
    """Returns a short, plain-English paragraph explaining this specific alert --
    what device, what was noticed, where it happened, why the system leaned
    toward a threat, what the counter argument was, and what happened as a
    result. No jargon, no evidence-type codes, no confidence percentages --
    those stay in the existing technical section for anyone who wants them."""
    device_label = hostname if hostname and hostname != "unknown" else client_ip
    who = f"Your {device_type.replace('_', ' ')} \"{device_label}\" ({client_ip})" if device_type and device_type != "unknown" \
        else f"Your device \"{device_label}\" ({client_ip})"

    winning_label, winning_description = label_hypothesis(winning_name)

    evidence_labels = []
    for et in (hee_evidence_types or [])[:3]:  # a short list reads as a sentence, not a dump
        label, _ = label_evidence_type(et)
        evidence_labels.append(label.lower())
    noticed = (", ".join(evidence_labels)) if evidence_labels else "unusual network behavior"

    target_clause = _describe_target(dest_ip, dest_domain, peer_hostname, peer_ip, dest_hostname, asn_owner, asn_country)

    sentences = [f"{who} did something the system flagged for review: {noticed}."]
    if target_clause:
        sentences.append(f"This involved {target_clause}.")

    if winning_description:
        sentences.append(winning_description)
    elif winning_label:
        sentences.append(f"The pattern matches: {winning_label}.")

    counter = _describe_counter_argument(hee_hypotheses, winning_name)
    if counter:
        sentences.append(counter)

    closing = _STATUS_CLOSING.get(alert_status, "")
    if closing:
        sentences.append(closing)

    return " ".join(sentences)
