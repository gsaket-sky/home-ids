"""
Tests for the new operator-driven containment methods on IPSMitigator
(operator_isolate_router / operator_tarpit), added so the console's "Isolate via
Fritz!Box" / "Tarpit (Layer-2)" buttons have something real to call. Direct-call style,
same convention as test_config_api.py / test_devices_api.py.

Network I/O (the Fritz!Box webhook call inside _isolate_device_router()) is monkeypatched
out -- these tests exercise the state-registration/bookkeeping logic this session added,
not fritzconnection/requests itself.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import StateManager  # noqa: E402
import mitigation.ips as ips_module  # noqa: E402
from mitigation.ips import IPSMitigator  # noqa: E402


@pytest.fixture
def mitigator(tmp_path):
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    config = {"ips_router_enabled": True, "ips_tarpit_enabled": True}
    m = IPSMitigator(config=config, state_manager=sm)
    return m


def test_operator_isolate_router_refuses_when_disabled(tmp_path):
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    m = IPSMitigator(config={"ips_router_enabled": False}, state_manager=sm)
    ok, reason = m.operator_isolate_router("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is False
    assert "disabled" in reason


def test_operator_isolate_router_refuses_without_mac(mitigator):
    ok, reason = mitigator.operator_isolate_router("dev1", "10.0.0.5", "unknown", "host1")
    assert ok is False
    assert "MAC" in reason


def test_operator_isolate_router_success_registers_state(mitigator, monkeypatch):
    monkeypatch.setattr(mitigator, "_isolate_device_router", lambda **kw: True)
    ok, reason = mitigator.operator_isolate_router("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is True
    assert "Isolated" in reason
    assert "aa:bb:cc:dd:ee:ff" in mitigator._router_isolated_devices
    assert mitigator._router_isolated_devices["aa:bb:cc:dd:ee:ff"]["ip"] == "10.0.0.5"


def test_operator_isolate_router_idempotent_when_already_isolated(mitigator, monkeypatch):
    monkeypatch.setattr(mitigator, "_isolate_device_router", lambda **kw: True)
    mitigator.operator_isolate_router("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    calls = []
    monkeypatch.setattr(mitigator, "_isolate_device_router", lambda **kw: calls.append(1) or True)
    ok, reason = mitigator.operator_isolate_router("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is True
    assert "Already" in reason
    assert calls == []  # webhook not called again


def test_operator_isolate_router_reports_webhook_failure(mitigator, monkeypatch):
    monkeypatch.setattr(mitigator, "_isolate_device_router", lambda **kw: False)
    ok, reason = mitigator.operator_isolate_router("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is False
    assert "unreachable" in reason or "refused" in reason
    assert "aa:bb:cc:dd:ee:ff" not in mitigator._router_isolated_devices


def test_operator_tarpit_refuses_when_disabled(tmp_path):
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    m = IPSMitigator(config={"ips_tarpit_enabled": False}, state_manager=sm)
    ok, reason = m.operator_tarpit("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is False
    assert "disabled" in reason


def test_operator_tarpit_refuses_when_not_armed(mitigator):
    # tarpit_armed is False in any test environment without a real raw-socket-capable
    # scapy install -- exactly the condition this guard exists for.
    mitigator.tarpit_armed = False
    ok, reason = mitigator.operator_tarpit("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is False
    assert "armed" in reason


def test_operator_tarpit_success_registers_state(mitigator):
    mitigator.tarpit_armed = True
    ok, reason = mitigator.operator_tarpit("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is True
    assert "Tarpitted" in reason
    assert "10.0.0.5" in mitigator._tarpit_active_targets


def test_operator_tarpit_idempotent(mitigator):
    mitigator.tarpit_armed = True
    mitigator.operator_tarpit("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    ok, reason = mitigator.operator_tarpit("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is True
    assert "Already" in reason


# --- unisolate_all: BUGFIX regression (log-spam/wasted-webhook audit) ---------------
# unisolate_all() is called on every device-identity re-resolution (e.g. any MAC
# rotation from a privacy-randomizing phone/laptop), not just ones that were ever
# actually isolated. It used to call the router webhook unconditionally whenever
# ips_router_enabled was set, producing a real outbound HTTP call plus a misleading
# CRITICAL "un-isolation accepted for unknown (unknown)" log line for the common case
# of a device that was never isolated in the first place.

def test_unisolate_all_no_webhook_when_never_isolated(mitigator, monkeypatch):
    calls = []
    monkeypatch.setattr(mitigator, "_unisolate_device_router", lambda **kw: calls.append(kw) or True)
    mitigator.unisolate_all(mac_addr="aa:bb:cc:dd:ee:ff", ip_addr="10.0.0.5")
    assert calls == []  # never isolated -- no webhook call, no log spam


def test_unisolate_all_calls_webhook_when_router_isolated(mitigator, monkeypatch):
    mitigator._router_isolated_devices["aa:bb:cc:dd:ee:ff"] = {
        "ip": "10.0.0.5", "hostname": "host1", "dev_id": "dev1",
    }
    calls = []
    monkeypatch.setattr(mitigator, "_unisolate_device_router", lambda **kw: calls.append(kw) or True)
    mitigator.unisolate_all(mac_addr="aa:bb:cc:dd:ee:ff", ip_addr="10.0.0.5")
    assert len(calls) == 1
    assert calls[0]["hostname"] == "host1" and calls[0]["dev_id"] == "dev1"
    assert "aa:bb:cc:dd:ee:ff" not in mitigator._router_isolated_devices


def test_unisolate_all_clears_tarpit_without_router_webhook(mitigator, monkeypatch):
    # Only the tarpit entry exists (not the router-isolation one) -- clearing local
    # tarpit bookkeeping should not also fire the ROUTER un-isolate webhook, since
    # that's specifically for undoing a Fritz!Box isolation that never happened here.
    mitigator._tarpit_active_targets["10.0.0.5"] = {
        "hostname": "host1", "dev_id": "dev1", "mac": "aa:bb:cc:dd:ee:ff",
    }
    calls = []
    monkeypatch.setattr(mitigator, "_unisolate_device_router", lambda **kw: calls.append(kw) or True)
    mitigator.unisolate_all(mac_addr="aa:bb:cc:dd:ee:ff", ip_addr="10.0.0.5")
    assert calls == []
    assert "10.0.0.5" not in mitigator._tarpit_active_targets


# --- _arm_tarpit_for_dual_stack_coverage / router-agnostic IPv6 device-identity plan
# (2026-09-16) -------------------------------------------------------------------
# Router isolation (Fritz!Box TR-064 DisallowWANAccessByIP) is IPv4-only by
# construction. Once a device is dual-stack, "isolating" it left its IPv6 path
# completely open -- confirmed live via mitigate()'s own two SEPARATE risk
# thresholds: router fires at risk_score>=8.5, but the tarpit block (the only thing
# that actually disrupts IPv6 neighbor discovery) had its OWN, stricter,
# independent risk_score>=9.0 gate, so a device isolated at 8.5-8.99 got ZERO IPv6
# coverage, not partial. See Documentation/IPV6_DEVICE_IDENTITY_PLAN.md.

def test_arm_tarpit_for_dual_stack_coverage_registers_target(mitigator):
    mitigator.config["simulation_mode"] = True  # bypass the real-scapy/raw-socket gate portably
    armed = mitigator._arm_tarpit_for_dual_stack_coverage(
        client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff", hostname="host1",
        dev_id="dev1", reason="test")
    assert armed is True
    assert "10.0.0.5" in mitigator._tarpit_active_targets
    assert mitigator._tarpit_active_targets["10.0.0.5"]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_arm_tarpit_for_dual_stack_coverage_idempotent(mitigator):
    mitigator.config["simulation_mode"] = True
    mitigator._arm_tarpit_for_dual_stack_coverage(
        client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff", hostname="host1", dev_id="dev1", reason="t")
    armed_again = mitigator._arm_tarpit_for_dual_stack_coverage(
        client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff", hostname="host1", dev_id="dev1", reason="t")
    assert armed_again is False  # already tarpitted -- no double-registration, no error


def test_arm_tarpit_for_dual_stack_coverage_respects_opt_out(mitigator):
    mitigator.config["simulation_mode"] = True
    mitigator.config["ips_tarpit_follows_router_isolation"] = False
    armed = mitigator._arm_tarpit_for_dual_stack_coverage(
        client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff", hostname="host1", dev_id="dev1", reason="t")
    assert armed is False
    assert "10.0.0.5" not in mitigator._tarpit_active_targets


def test_arm_tarpit_for_dual_stack_coverage_respects_tarpit_disabled(mitigator):
    mitigator.config["simulation_mode"] = True
    mitigator.config["ips_tarpit_enabled"] = False
    armed = mitigator._arm_tarpit_for_dual_stack_coverage(
        client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff", hostname="host1", dev_id="dev1", reason="t")
    assert armed is False
    assert "10.0.0.5" not in mitigator._tarpit_active_targets


def test_arm_tarpit_for_dual_stack_coverage_needs_scapy_or_simulation(mitigator, monkeypatch):
    # Neither real scapy availability nor simulation_mode -- the same gate the
    # pre-existing autonomous tarpit block in mitigate() already uses. SCAPY_AVAILABLE
    # (scapy package importable) is True in most CI/dev environments even without raw-
    # socket permission (a separate runtime check, see ips.py's own "no permission to
    # open a raw socket" warning) -- monkeypatch the module-level constant directly to
    # genuinely exercise the "unavailable" case rather than relying on the environment.
    monkeypatch.setattr(ips_module, "SCAPY_AVAILABLE", False)
    armed = mitigator._arm_tarpit_for_dual_stack_coverage(
        client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff", hostname="host1", dev_id="dev1", reason="t")
    assert armed is False


def test_arm_tarpit_for_dual_stack_coverage_needs_mac(mitigator):
    mitigator.config["simulation_mode"] = True
    armed = mitigator._arm_tarpit_for_dual_stack_coverage(
        client_ip="10.0.0.5", mac_addr="unknown", hostname="host1", dev_id="dev1", reason="t")
    assert armed is False
    assert "10.0.0.5" not in mitigator._tarpit_active_targets


def test_operator_isolate_router_also_arms_tarpit(mitigator, monkeypatch):
    # A human operator clicking "Isolate via Fritz!Box" gets the SAME dual-stack
    # coverage the autonomous path now gets -- no separate manual tarpit click needed.
    mitigator.config["simulation_mode"] = True
    monkeypatch.setattr(mitigator, "_isolate_device_router", lambda **kw: True)
    ok, reason = mitigator.operator_isolate_router("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is True
    assert "tarpit armed" in reason.lower()
    assert "10.0.0.5" in mitigator._tarpit_active_targets


def test_operator_isolate_router_message_stays_honest_when_tarpit_not_armed(mitigator, monkeypatch):
    # Neither simulation_mode nor real scapy availability -- router isolation still
    # succeeds, but the message must NOT falsely claim tarpit coverage.
    monkeypatch.setattr(ips_module, "SCAPY_AVAILABLE", False)
    monkeypatch.setattr(mitigator, "_isolate_device_router", lambda **kw: True)
    ok, reason = mitigator.operator_isolate_router("dev1", "10.0.0.5", "aa:bb:cc:dd:ee:ff", "host1")
    assert ok is True
    assert reason == "Isolated via Fritz!Box."
    assert "10.0.0.5" not in mitigator._tarpit_active_targets


def test_mitigate_autonomous_router_isolation_now_also_arms_tarpit(mitigator, monkeypatch):
    # THE CORE FIX, end-to-end: risk_score=8.7 clears router isolation's own bar
    # (>=8.5) but NOT the tarpit block's own separate, stricter bar (>=9.0) further
    # down in mitigate() -- before this fix, this exact case left the device's IPv6
    # path completely uncovered despite being severe enough to isolate.
    mitigator.config["simulation_mode"] = True
    mitigator.config["interactive_blocking_enabled"] = False
    monkeypatch.setattr(mitigator, "_isolate_device_router", lambda **kw: True)
    st = SimpleNamespace(client_ip="10.0.0.5", hostname="host1", device_id="dev1", mac_address="aa:bb:cc:dd:ee:ff")
    mitigator.mitigate(st, target_domain="unknown", risk_score=8.7, lateral_threat=False,
                        is_safe=False, decision_state="HIGH")
    assert "aa:bb:cc:dd:ee:ff" in mitigator._router_isolated_devices
    assert "10.0.0.5" in mitigator._tarpit_active_targets, (
        "risk 8.7 is below tarpit's own 9.0 bar -- this only passes because router "
        "isolation's success now ALSO arms the tarpit directly, closing the IPv6 gap")


def test_mitigate_below_router_threshold_arms_neither(mitigator, monkeypatch):
    # REGRESSION GUARD: the fix ties tarpit-arming to an ACTUAL router-isolation
    # success, not to every mitigate() call regardless of severity.
    mitigator.config["simulation_mode"] = True
    mitigator.config["interactive_blocking_enabled"] = False
    monkeypatch.setattr(mitigator, "_isolate_device_router", lambda **kw: True)
    st = SimpleNamespace(client_ip="10.0.0.5", hostname="host1", device_id="dev1", mac_address="aa:bb:cc:dd:ee:ff")
    mitigator.mitigate(st, target_domain="unknown", risk_score=5.0, lateral_threat=False,
                        is_safe=False, decision_state="SUSPICIOUS")
    assert "aa:bb:cc:dd:ee:ff" not in mitigator._router_isolated_devices
    assert "10.0.0.5" not in mitigator._tarpit_active_targets


def test_mitigate_respects_tarpit_follows_router_isolation_opt_out(mitigator, monkeypatch):
    mitigator.config["simulation_mode"] = True
    mitigator.config["interactive_blocking_enabled"] = False
    mitigator.config["ips_tarpit_follows_router_isolation"] = False
    monkeypatch.setattr(mitigator, "_isolate_device_router", lambda **kw: True)
    st = SimpleNamespace(client_ip="10.0.0.5", hostname="host1", device_id="dev1", mac_address="aa:bb:cc:dd:ee:ff")
    mitigator.mitigate(st, target_domain="unknown", risk_score=8.7, lateral_threat=False,
                        is_safe=False, decision_state="HIGH")
    assert "aa:bb:cc:dd:ee:ff" in mitigator._router_isolated_devices  # router isolation itself unaffected
    assert "10.0.0.5" not in mitigator._tarpit_active_targets  # coupling opted out


# --- get_containment_status(): combined badge when both mechanisms are active -----
# Previously mutually-exclusive-by-return-order (TARPITTED checked first, so an
# operator would never even see that router isolation ALSO succeeded) -- now that
# _arm_tarpit_for_dual_stack_coverage() makes "both active at once" the routine
# case for an isolated dual-stack device, the status text must say so honestly.

def test_get_containment_status_combines_both_when_both_active(mitigator):
    mitigator._tarpit_active_targets["10.0.0.5"] = {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "host1", "dev_id": "dev1"}
    mitigator._router_isolated_devices["aa:bb:cc:dd:ee:ff"] = {"ip": "10.0.0.5", "hostname": "host1", "dev_id": "dev1"}
    status = mitigator.get_containment_status(client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff")
    assert "TARPITTED" in status
    assert "ROUTER ISOLATED" in status


def test_get_containment_status_tarpit_only_unchanged(mitigator):
    mitigator._tarpit_active_targets["10.0.0.5"] = {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "host1", "dev_id": "dev1"}
    status = mitigator.get_containment_status(client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff")
    assert "TARPITTED" in status
    assert "ROUTER ISOLATED" not in status


def test_get_containment_status_router_only_unchanged(mitigator):
    mitigator._router_isolated_devices["aa:bb:cc:dd:ee:ff"] = {"ip": "10.0.0.5", "hostname": "host1", "dev_id": "dev1"}
    status = mitigator.get_containment_status(client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff")
    assert "ROUTER ISOLATED" in status
    assert "TARPITTED" not in status


def test_get_containment_status_combines_via_dev_id_fallback(mitigator):
    # Both entries found only via the dev_id fallback (mismatched client_ip/mac_addr) --
    # proves the combined-badge logic works through that path too, not just direct keys.
    mitigator._tarpit_active_targets["10.0.0.99"] = {"mac": "unknown", "hostname": "host1", "dev_id": "dev1"}
    mitigator._router_isolated_devices["11:22:33:44:55:66"] = {"ip": "10.0.0.99", "hostname": "host1", "dev_id": "dev1"}
    status = mitigator.get_containment_status(client_ip="10.0.0.5", mac_addr="aa:bb:cc:dd:ee:ff", dev_id="dev1")
    assert "TARPITTED" in status
    assert "ROUTER ISOLATED" in status
