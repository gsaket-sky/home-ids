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

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import StateManager  # noqa: E402
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
