"""
mitigation/containment_gate.py -- the one place that decides whether an alert may contain a device (U1, 2026-10-14;
DETECTION_CORE_REWORK.md, owner decisions 2026-10-14). Pure: no I/O, no state.

authorize_containment(decision) -> ContainmentAuthorization
    What the decision allows. Containment needs a HIGH/CRITICAL decision that is either
      - corroborated: >= 2 independent attack sources (decision["independent_sources"], counted by the decision
        engine over attack families only) and not raised to HIGH by persistence alone; or
      - a single-signal exception the owner named (decision["single_signal_basis"], set by the decision engine):
        honeypot contact, ARP spoofing, a verified curated-feed IOC.
    Anything else -- SUSPICIOUS, a one-source HIGH (an uncorroborated Suricata rule or geofence hit, a lateral scan
    alone), a persistence-escalated HIGH -- is monitor-only: it alerts, it does not contain. Window counts (lateral
    moves, honeypot hits in the feature window) are never read here; only the decision is.

device_isolation_action(auth, critical_device, interactive_mode, released_recently) -> ISOLATE / APPROVAL / WITHHELD
    For router isolation and the tarpit. A critical-role device (router, NAS, TV ... CRITICAL_DEVICE_TYPES) waits for
    approval on every autonomous path, exceptions included (owner, 2026-10-14). A single-signal exception otherwise
    contains at once, also in interactive mode and during an operator's release cooldown (it is fresh, conclusive
    evidence). A corroborated decision honours the release cooldown first (no action and no new approval request for
    a device a person just released), then the critical-role and interactive-mode approvals. An operator's approval
    (OPERATOR_APPROVED) executes.

The step from "allowed" to "done" -- the risk floors for device isolation, safe-listed devices and domains, the
onboarding grace (autonomous actions only), the switches in config -- stays in IPSMitigator.mitigate().
"""
from dataclasses import dataclass
from typing import Any, Mapping, Optional

BASIS_CORROBORATED = "corroborated"
BASIS_OPERATOR = "operator_approved"
# The owner's single-signal exceptions (decisions 2026-10-14, "only honeypot contact, ARP spoofing and a curated feed
# naming the exact destination escalate on one signal"). The decision engine names them in decision["single_signal_basis"].
SINGLE_SIGNAL_BASES = frozenset({"honeypot", "arp_spoof", "verified_feed_ioc"})
_CONTAINING_STATES = frozenset({"HIGH", "CRITICAL"})
_MIN_CORROBORATING_SOURCES = 2

ISOLATE = "isolate"
APPROVAL = "approval"
WITHHELD = "withheld"


@dataclass(frozen=True)
class ContainmentAuthorization:
    """`basis` None = monitor only (no containment)."""
    basis: Optional[str] = None

    @property
    def authorized(self) -> bool:
        return self.basis is not None

    @property
    def single_signal(self) -> bool:
        return self.basis in SINGLE_SIGNAL_BASES

    @property
    def operator(self) -> bool:
        return self.basis == BASIS_OPERATOR


MONITOR_ONLY = ContainmentAuthorization()
OPERATOR_APPROVED = ContainmentAuthorization(BASIS_OPERATOR)


def authorize_containment(decision: Optional[Mapping[str, Any]]) -> ContainmentAuthorization:
    """See the module docstring. `decision` is the engine's decision dict after the pipeline's persistence step (which
    sets `escalated_via_persistence`)."""
    if not decision or str(decision.get("state", "")) not in _CONTAINING_STATES:
        return MONITOR_ONLY
    if decision.get("escalated_via_persistence"):
        return MONITOR_ONLY
    basis = decision.get("single_signal_basis")
    if basis in SINGLE_SIGNAL_BASES:
        return ContainmentAuthorization(basis)
    try:
        sources = int(decision.get("independent_sources") or 0)
    except (TypeError, ValueError):
        sources = 0
    if sources >= _MIN_CORROBORATING_SOURCES:
        return ContainmentAuthorization(BASIS_CORROBORATED)
    return MONITOR_ONLY


def device_isolation_action(auth: ContainmentAuthorization, *, critical_device: bool, interactive_mode: bool,
                            released_recently: bool) -> str:
    """ISOLATE, APPROVAL (queue for a person) or WITHHELD, for router isolation and the tarpit. See the module docstring."""
    if not auth.authorized:
        return WITHHELD
    if auth.operator:
        return ISOLATE
    if auth.single_signal:
        return APPROVAL if critical_device else ISOLATE
    if released_recently:          # a person released this device recently: no new autonomous action, no new request
        return WITHHELD
    if critical_device or interactive_mode:
        return APPROVAL
    return ISOLATE
