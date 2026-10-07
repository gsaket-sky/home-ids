"""
Tests for src/middleware/routers/mitigation_api.py -- the console's block/unblock
endpoints. Direct-call style, same convention as test_config_api.py / test_devices_api.py.

IPSMitigator's own network-touching methods (_isolate_device_router, _block_domain,
unblock_domain) are monkeypatched at the class level -- these tests are about the
endpoint's own identity-resolution/response-shape logic, not Fritz!Box/Pi-hole's real
APIs (covered separately by test_ips_operator_actions.py and the pre-existing ips.py
behavior these endpoints reuse unchanged).
"""
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import StateManager  # noqa: E402
from mitigation.ips import IPSMitigator  # noqa: E402
from middleware.routers import mitigation_api  # noqa: E402


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    path = tmp_path / "ids_state.json"
    sm = StateManager(state_path=str(path))
    sm.get_or_create("dev_a", "192.168.1.50", "workstation-1")
    with sm.lock_device("dev_a") as st:
        st.mac_address = "aa:bb:cc:dd:ee:ff"
    sm.flush_to_disk()
    monkeypatch.setattr(mitigation_api, "CONFIG", {"state_path": str(path), "ips_router_enabled": True, "ips_tarpit_enabled": True})
    return path


def test_get_mitigation_state_shapes_contained_devices_and_domains(state_file):
    sm = StateManager(state_path=str(state_file))
    sm.load_from_disk()
    sm.save_ips_state({
        "tarpit_targets": {"192.168.1.50": {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "workstation-1", "dev_id": "dev_a"}},
        "blocked_domains": {"evil.example": {"device_id": "dev_a", "hostname": "workstation-1", "device_ip": "192.168.1.50", "comment": "auto-block", "timestamp": 111.0}},
    })
    sm.flush_to_disk()

    result = mitigation_api.get_mitigation_state(token="test")
    assert len(result["contained_devices"]) == 1
    assert result["contained_devices"][0]["device_id"] == "dev_a"
    assert result["contained_devices"][0]["tarpitted"] is True
    assert result["blocked_domains"] == [{"domain": "evil.example", "hostname": "workstation-1", "device_id": "dev_a", "device_ip": "192.168.1.50", "reason": "auto-block", "blocked_at": 111.0}]


def test_isolate_device_router_unknown_device_404(state_file):
    with pytest.raises(HTTPException) as exc:
        mitigation_api.isolate_device_router("no-such-device", mitigation_api.ReasonPayload(), token="test")
    assert exc.value.status_code == 404


def test_isolate_device_router_success(state_file, monkeypatch):
    monkeypatch.setattr(IPSMitigator, "_isolate_device_router", lambda self, **kw: True)
    result = mitigation_api.isolate_device_router("dev_a", mitigation_api.ReasonPayload(reason="test"), token="test")
    assert result["status"] == "success"


def test_isolate_device_router_failure_returns_502(state_file, monkeypatch):
    monkeypatch.setattr(IPSMitigator, "_isolate_device_router", lambda self, **kw: False)
    with pytest.raises(HTTPException) as exc:
        mitigation_api.isolate_device_router("dev_a", mitigation_api.ReasonPayload(), token="test")
    assert exc.value.status_code == 502


def _publish_engine_tarpit(state_file, armed):
    """What the engine's own IPSMitigator does at start (_publish_engine_tarpit_state), then flushes."""
    sm = StateManager(state_path=str(state_file))
    sm.load_from_disk()
    engine_side = IPSMitigator(config={"state_path": str(state_file)}, state_manager=sm, start_workers=False)
    engine_side.tarpit_armed = armed
    engine_side._publish_engine_tarpit_state()
    sm.flush_to_disk()


def test_tarpit_device_success(state_file):
    """2026-10-07: the console tarpit always answered 502 since W-01 -- the API's state-only mitigator was never
    armed. It now follows the ENGINE's published armed state, registers the target in the shared state, and the
    engine applies it on the sync signal."""
    _publish_engine_tarpit(state_file, armed=True)
    result = mitigation_api.tarpit_device("dev_a", mitigation_api.ReasonPayload(), token="test")
    assert result["status"] == "success"
    sm = StateManager(state_path=str(state_file))
    sm.load_from_disk()
    targets = sm.get_ips_state()["tarpit_targets"]
    assert targets["192.168.1.50"]["dev_id"] == "dev_a" and targets["192.168.1.50"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert (state_file.parent / ".ipc_sync_signal").exists()          # the engine is told to pick it up


@pytest.mark.parametrize("published", [False, None])
def test_tarpit_device_refused_when_the_engine_tarpit_is_not_armed(state_file, published):
    if published is not None:
        _publish_engine_tarpit(state_file, armed=published)        # engine started without raw-socket access
    with pytest.raises(HTTPException) as exc:                       # None: engine never published (not started yet)
        mitigation_api.tarpit_device("dev_a", mitigation_api.ReasonPayload(), token="test")
    assert exc.value.status_code == 502 and "engine" in exc.value.detail
    sm = StateManager(state_path=str(state_file))
    sm.load_from_disk()
    assert sm.get_ips_state().get("tarpit_targets", {}) == {}


def test_release_device_console(state_file):
    result = mitigation_api.release_device_console("dev_a", token="test")
    assert result["status"] == "success"


def test_block_domain_console_with_device(state_file, monkeypatch):
    monkeypatch.setattr(IPSMitigator, "_block_domain", lambda self, **kw: True)
    result = mitigation_api.block_domain_console(
        mitigation_api.DomainBlockPayload(domain="evil.example", device_id="dev_a"), token="test"
    )
    assert result == {"status": "success", "blocked_domain": "evil.example"}


def test_block_domain_console_manual_no_device(state_file, monkeypatch):
    captured = {}
    def fake_block(self, **kw):
        captured.update(kw)
        return True
    monkeypatch.setattr(IPSMitigator, "_block_domain", fake_block)
    mitigation_api.block_domain_console(mitigation_api.DomainBlockPayload(domain="evil.example"), token="test")
    assert captured["dev_id"] == "manual"


def test_unblock_domain_console(state_file, monkeypatch):
    monkeypatch.setattr(IPSMitigator, "unblock_domain", lambda self, domain, reason="manual": True)
    result = mitigation_api.unblock_domain_console(mitigation_api.DomainUnblockPayload(domain="evil.example"), token="test")
    assert result == {"status": "success", "unblocked_domain": "evil.example"}


def test_unblock_domain_console_failure_502(state_file, monkeypatch):
    monkeypatch.setattr(IPSMitigator, "unblock_domain", lambda self, domain, reason="manual": False)
    with pytest.raises(HTTPException) as exc:
        mitigation_api.unblock_domain_console(mitigation_api.DomainUnblockPayload(domain="evil.example"), token="test")
    assert exc.value.status_code == 502
