"""
The live `ips_enabled: false` override stops EVERY active-response mechanism (MASTER_TODO Section I, found 2026-10-06):
the console's All settings writes state/config_overrides.json; enforce_ips_master_switch() ran only on a config.yaml /
environment reload, so DNS blocking stopped but router isolation and the tarpit kept acting until a restart. Lifting
the override restores what each mechanism had. And each mechanism checks the master switch where it acts.
"""
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import config as config_module  # noqa: E402
from config import LiveConfig  # noqa: E402

MECH = ("ips_pihole_enabled", "ips_router_enabled", "ips_tarpit_enabled")


@pytest.fixture
def live(tmp_path, monkeypatch):
    for env in ("IDS_IPS_ENABLED", "IDS_IPS_PIHOLE_ENABLED", "IDS_IPS_ROUTER_ENABLED", "IDS_IPS_TARPIT_ENABLED"):
        monkeypatch.delenv(env, raising=False)
    (tmp_path / "config.yaml").write_text(
        "ips_mitigation:\n  ips_enabled: true\n  ips_pihole_enabled: true\n  ips_router_enabled: true\n"
        "  ips_tarpit_enabled: true\n", encoding="utf-8")
    (tmp_path / "state").mkdir()
    return LiveConfig({"ips_enabled": True}, tmp_path / "config.yaml"), tmp_path / "state" / "config_overrides.json"


def _write(path, overrides):
    path.write_text(json.dumps({k: {"value": v, "baseline": True, "set_at": time.time(), "set_by": "console"}
                                for k, v in overrides.items()}), encoding="utf-8")


def test_live_override_off_forces_every_mechanism_off_and_back(live):
    cfg, path = live
    assert all(cfg.get(k) for k in MECH)
    _write(path, {"ips_enabled": False})
    cfg._load_overrides()
    assert cfg.get("ips_enabled") is False and not any(cfg.get(k) for k in MECH)
    path.write_text("{}", encoding="utf-8")                                     # the override is lifted
    cfg._load_overrides()
    assert cfg.get("ips_enabled") is True and all(cfg.get(k) for k in MECH)


def test_a_mechanism_the_operator_had_off_stays_off_after_the_switch_returns(live):
    cfg, path = live
    _write(path, {"ips_router_enabled": False})
    cfg._load_overrides()
    _write(path, {"ips_router_enabled": False, "ips_enabled": False})
    cfg._load_overrides()
    _write(path, {"ips_router_enabled": False})
    cfg._load_overrides()
    assert cfg.get("ips_enabled") and cfg.get("ips_pihole_enabled") and cfg.get("ips_tarpit_enabled")
    assert cfg.get("ips_router_enabled") is False                              # its own override still holds


def test_reverting_through_the_api_restores_too(live):
    cfg, path = live
    _write(path, {"ips_enabled": False})
    cfg._load_overrides()
    path.write_text("{}", encoding="utf-8")
    cfg.revert_override("ips_enabled", True)                                   # the console's DELETE, this process
    assert all(cfg.get(k) for k in MECH)


def test_each_mechanism_checks_the_master_switch_where_it_acts(tmp_path):
    from core.state_guard import StateManager
    from mitigation.ips import IPSMitigator
    from mitigation.containment_gate import ContainmentAuthorization
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    # a config whose mechanism keys were left on although the master switch is off (e.g. a caller's own dict)
    m = IPSMitigator(config={"ips_enabled": False, "ips_router_enabled": True, "ips_tarpit_enabled": True,
                             "simulation_mode": True, "onboarding_mode_days": 0,
                             "state_path": str(tmp_path / "ids_state.json")}, state_manager=sm, start_workers=False)
    m._isolate_device_router = lambda **kw: pytest.fail("router isolation while ips_enabled is false")
    st = SimpleNamespace(client_ip="10.0.0.5", hostname="h", device_id="d1", mac_address="aa:bb:cc:00:00:01",
                         device_type="unknown", known_ips=[])
    m.mitigate(st, target_domain="bad.example", risk_score=9.9, authorization=ContainmentAuthorization("corroborated"), is_safe=False)
    assert m._tarpit_active_targets == {} and m._router_isolated_devices == {}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
