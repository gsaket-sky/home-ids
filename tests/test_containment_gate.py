"""
U1 (DETECTION_CORE_REWORK, handover 2026-10-14): one containment-authorisation gate.

Before, `lateral_threat` (a window count: >= 2 internal hosts on admin ports, or any honeypot hit) authorised router
isolation and the tarpit on ANY alert -- a SUSPICIOUS one included -- bypassing the risk floor, the release cooldown,
interactive mode and the critical-device approval; device isolation was gated on a risk number, never on the decision;
and the operator's own "Approve" (fritzbox_api) re-queued the action for approval in interactive mode and for a
critical-role device, so it never executed (reproduced on the old code 2026-10-14: SUSPICIOUS + lateral -> isolated
and tarpitted; approval in interactive mode / for a router -> nothing).

Now (owner decisions 2026-10-14):
- containment only from a HIGH/CRITICAL decision that is corroborated (>= 2 independent attack sources) and not
  persistence-escalated, or from a single-signal exception the owner named: honeypot contact, ARP spoofing, a verified
  curated-feed IOC; lateral movement alone alerts but never contains;
- approval (interactive mode) and the release cooldown are honoured on every non-exception path; a critical-role device
  (router/NAS/TV...) waits for approval on every path, exceptions included;
- an operator's approval executes (and is not withheld by the onboarding grace, which holds autonomous actions only).
No addresses or vendors: device roles come from CRITICAL_DEVICE_TYPES, test addresses are documentation-only.
"""
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import StateManager  # noqa: E402
from mitigation.ips import IPSMitigator  # noqa: E402
from mitigation.containment_gate import (  # noqa: E402
    APPROVAL, ISOLATE, MONITOR_ONLY, OPERATOR_APPROVED, WITHHELD, ContainmentAuthorization, authorize_containment,
    device_isolation_action,
)

MAC = "aa:bb:cc:00:00:01"


def _decision(state, sources=0, basis=None, persisted=False):
    d = {"state": state, "independent_sources": sources, "single_signal_basis": basis}
    if persisted:
        d["escalated_via_persistence"] = True
    return d


# ------------------------------------------------------------------------------------------------ the gate (pure)

@pytest.mark.parametrize("decision,expected", [
    (_decision("SUSPICIOUS", 3), None),                                     # never below HIGH
    (_decision("ANOMALOUS", 2), None),
    (_decision("HIGH", 1), None),                                           # one source: watch, not contain
    (_decision("HIGH", 2), "corroborated"),
    (_decision("CRITICAL", 2), "corroborated"),
    (_decision("HIGH", 3, persisted=True), None),                           # persistence is not corroboration
    (_decision("CRITICAL", 1, basis="honeypot"), "honeypot"),
    (_decision("CRITICAL", 1, basis="arp_spoof"), "arp_spoof"),
    (_decision("CRITICAL", 1, basis="verified_feed_ioc"), "verified_feed_ioc"),
    (_decision("HIGH", 1, basis="not_a_named_exception"), None),            # only the owner's three
    ({}, None),
    (None, None),
])
def test_authorize_containment(decision, expected):
    assert authorize_containment(decision).basis == expected


def test_lateral_window_counts_alone_never_authorise():
    # a SUSPICIOUS decision on a device whose window shows a 'lateral scan' and a honeypot count: the counts are not
    # the decision; only the decision (and the exception it names) authorises
    d = _decision("SUSPICIOUS", 1)
    d["features"] = {"zeek_lateral_moves": 9, "zeek_lateral_unique_targets": 5, "zeek_honeypot_hits": 2}
    assert authorize_containment(d) == MONITOR_ONLY


@pytest.mark.parametrize("auth,critical,interactive,released,expected", [
    (MONITOR_ONLY, False, False, False, WITHHELD),
    (ContainmentAuthorization("corroborated"), False, False, False, ISOLATE),
    (ContainmentAuthorization("corroborated"), False, True, False, APPROVAL),
    (ContainmentAuthorization("corroborated"), True, False, False, APPROVAL),
    (ContainmentAuthorization("corroborated"), False, False, True, WITHHELD),     # cooldown honoured
    (ContainmentAuthorization("corroborated"), False, True, True, WITHHELD),
    (ContainmentAuthorization("corroborated"), True, False, True, WITHHELD),      # released: no new request either
    (ContainmentAuthorization("honeypot"), False, True, False, ISOLATE),          # exception: no approval needed
    (ContainmentAuthorization("honeypot"), False, False, True, ISOLATE),          # ... and re-contains in cooldown
    (ContainmentAuthorization("honeypot"), True, False, False, APPROVAL),         # owner: critical role waits
    (ContainmentAuthorization("arp_spoof"), True, True, True, APPROVAL),
    (ContainmentAuthorization("verified_feed_ioc"), False, True, False, ISOLATE),
    (OPERATOR_APPROVED, True, True, True, ISOLATE),                               # the person decided
])
def test_device_isolation_action(auth, critical, interactive, released, expected):
    assert device_isolation_action(auth, critical_device=critical, interactive_mode=interactive,
                                   released_recently=released) == expected


# ------------------------------------------------------------------------------------------------ the decision engine names its basis

def test_decision_engine_names_the_single_signal_basis():
    from argus.decision.engine import DecisionEngine
    from intelligence.reputation.classifier import ReputationClassifier, ReputationVector
    eng = DecisionEngine()
    d = eng.evaluate([], ReputationVector(domain="", tier=1), features={"zeek_honeypot_hits": 1}, now=1000.0)
    assert d["state"] == "CRITICAL" and d["single_signal_basis"] == "honeypot"
    rep = ReputationVector(domain="ioc.example", tier=5)
    rep.verified_ioc = True
    d = eng.evaluate([], rep, features={}, now=1000.0)
    assert d["state"] == "CRITICAL" and d["single_signal_basis"] == "verified_feed_ioc"
    d = eng.evaluate([], ReputationVector(domain="", tier=1), features={}, now=1000.0)
    assert d.get("single_signal_basis") is None


# ------------------------------------------------------------------------------------------------ mitigate() obeys it

@pytest.fixture
def make(tmp_path):
    def _make(interactive=False, device_type="unknown", onboarding_days=0, released=False):
        sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
        sm.get_or_create("d1", "192.0.2.5", "host-d1")
        cfg = {"ips_enabled": True, "ips_pihole_enabled": True, "ips_router_enabled": True, "ips_tarpit_enabled": True,
               "simulation_mode": True, "onboarding_mode_days": onboarding_days,
               "pihole_api_url": "http://pihole.invalid", "state_path": str(tmp_path / "ids_state.json"),
               "interactive_blocking_enabled": interactive}
        m = IPSMitigator(config=cfg, state_manager=sm, start_workers=False)
        m.tarpit_armed = True
        isolated, blocked = [], []
        m._isolate_device_router = lambda **kw: isolated.append(kw["mac"]) or True
        m._block_domain = lambda **kw: blocked.append(kw["domain"]) or True
        if released:
            m._operator_released_devices["d1"] = __import__("time").time()
        st = SimpleNamespace(client_ip="192.0.2.5", hostname="host-d1", device_id="d1", mac_address=MAC,
                             device_type=device_type, known_ips=["192.0.2.5"])
        return SimpleNamespace(m=m, st=st, isolated=isolated, blocked=blocked)
    return _make


def _run(env, auth, risk=9.5, domain="unknown"):
    return env.m.mitigate(env.st, target_domain=domain, risk_score=risk, authorization=auth, is_safe=False) or {}


def test_monitor_only_contains_nothing(make):
    env = make()
    res = _run(env, authorize_containment(_decision("SUSPICIOUS", 1)), risk=9.9, domain="bad.example")
    assert not env.isolated and not env.m._tarpit_active_targets and not env.blocked
    assert not res.get("pending_device_containment")


def test_corroborated_high_contains(make):
    env = make()
    _run(env, ContainmentAuthorization("corroborated"), domain="bad.example")
    assert env.isolated == [MAC] and env.m._tarpit_active_targets and env.blocked == ["bad.example"]


def test_uncorroborated_high_blocks_no_domain(make):
    env = make()
    _run(env, authorize_containment(_decision("HIGH", 1)), domain="bad.example")
    assert not env.blocked and not env.isolated


def test_corroborated_interactive_waits_and_reports_it(make):
    env = make(interactive=True)
    res = _run(env, ContainmentAuthorization("corroborated"))
    assert not env.isolated and not env.m._tarpit_active_targets and res.get("pending_device_containment") is True


def test_corroborated_during_release_cooldown_is_withheld(make):
    env = make(released=True)
    res = _run(env, ContainmentAuthorization("corroborated"))
    assert not env.isolated and not env.m._tarpit_active_targets and not res.get("pending_device_containment")


def test_honeypot_exception_contains_in_interactive_mode_and_cooldown(make):
    env = make(interactive=True, released=True)
    _run(env, ContainmentAuthorization("honeypot"), risk=10.0)
    assert env.isolated == [MAC] and env.m._tarpit_active_targets


def test_honeypot_on_critical_role_device_waits_for_approval(make):
    env = make(device_type="router")
    res = _run(env, ContainmentAuthorization("honeypot"), risk=10.0)
    assert not env.isolated and not env.m._tarpit_active_targets and res.get("pending_device_containment") is True


@pytest.mark.parametrize("kw", [{"interactive": True}, {"device_type": "router"}, {"onboarding_days": 30},
                                {"released": True}])
def test_operator_approval_executes(make, kw):
    env = make(**kw)
    res = _run(env, OPERATOR_APPROVED, risk=10.0, domain="-")
    assert env.isolated == [MAC] and env.m._tarpit_active_targets and not res.get("pending_device_containment")


def test_below_the_severity_floor_no_device_isolation(make):
    env = make()
    _run(env, ContainmentAuthorization("corroborated"), risk=8.0)
    assert not env.isolated and not env.m._tarpit_active_targets


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
