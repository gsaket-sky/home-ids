"""ips_enabled: false must disable EVERY active-response mechanism (2026-09-30). Offline; pytest."""
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import config as cfg  # noqa: E402

MECH = ("ips_pihole_enabled", "ips_router_enabled", "ips_tarpit_enabled")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("IDS_IPS_PIHOLE_ENABLED", "IDS_IPS_ROUTER_ENABLED", "IDS_IPS_TARPIT_ENABLED"):
        monkeypatch.delenv(k, raising=False)
    cfg._ips_master_switch_warned = False


def test_master_off_forces_all_mechanisms_off():
    c = {"ips_enabled": False, "ips_pihole_enabled": True, "ips_router_enabled": True, "ips_tarpit_enabled": True}
    cfg.enforce_ips_master_switch(c)
    assert [c[k] for k in MECH] == [False, False, False]


def test_master_on_leaves_mechanisms_alone():
    c = {"ips_enabled": True, "ips_pihole_enabled": True, "ips_router_enabled": False, "ips_tarpit_enabled": True}
    cfg.enforce_ips_master_switch(dict(c))
    d = dict(c)
    cfg.enforce_ips_master_switch(d)
    assert d == c


def test_missing_master_key_defaults_to_on():
    c = {"ips_pihole_enabled": True}
    cfg.enforce_ips_master_switch(c)
    assert c["ips_pihole_enabled"] is True


def test_env_cannot_re_enable_when_master_off(monkeypatch):
    """The Docker env template ships IDS_IPS_*_ENABLED=true; that must not beat ips_enabled: false."""
    for k in ("IDS_IPS_PIHOLE_ENABLED", "IDS_IPS_ROUTER_ENABLED", "IDS_IPS_TARPIT_ENABLED"):
        monkeypatch.setenv(k, "true")
    c = {"ips_enabled": False}
    cfg.apply_env_overrides(c)
    assert [c[k] for k in MECH] == [False, False, False]


def test_env_applies_normally_when_master_on(monkeypatch):
    monkeypatch.setenv("IDS_IPS_ROUTER_ENABLED", "true")
    monkeypatch.setenv("IDS_IPS_TARPIT_ENABLED", "false")
    c = {"ips_enabled": True}
    cfg.apply_env_overrides(c)
    assert c["ips_router_enabled"] is True and c["ips_tarpit_enabled"] is False


def test_warns_once_then_quiet(caplog):
    c = {"ips_enabled": False, "ips_tarpit_enabled": True}
    with caplog.at_level(logging.WARNING, logger="home_ids.config"):
        cfg.enforce_ips_master_switch(c)
        cfg.enforce_ips_master_switch({"ips_enabled": False, "ips_tarpit_enabled": True})
    assert sum("ips_enabled is false" in r.message for r in caplog.records) == 1


def test_reload_restores_explicit_values_when_master_turned_back_on(monkeypatch):
    """A value set in the environment/YAML comes back when the master switch is turned on again."""
    monkeypatch.setenv("IDS_IPS_TARPIT_ENABLED", "true")
    c = {"ips_enabled": False}
    cfg.apply_env_overrides(c)
    assert c["ips_tarpit_enabled"] is False
    c["ips_enabled"] = True                      # operator flips it back; env is re-applied on reload
    cfg.apply_env_overrides(c)
    assert c["ips_tarpit_enabled"] is True


def test_default_only_mechanism_stays_off_after_flip_back_failsafe():
    c = {"ips_enabled": False, "ips_tarpit_enabled": True}   # built-in default, no env/yaml source
    cfg.apply_env_overrides(c)
    c["ips_enabled"] = True
    cfg.apply_env_overrides(c)
    assert c["ips_tarpit_enabled"] is False      # not re-armed without an explicit setting
