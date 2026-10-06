"""
Placeholder hostnames and device-type fixes (2026-10-06, found on .94).

A laptop's private-MAC address was listed by the Fritz!Box under a random UUID, an iPhone under a UUID and later the
router's "PC-A6-EB-..." placeholder. Taken as names, they replaced the devices' real names on every event from those
addresses (the laptop flipped between "office-laptop", "office_laptop_fritz_box" and the UUID) and left the type guess with nothing.
A config rule "office-laptop" never matched the stored form "office_laptop_fritz_box".

Run: python -m pytest tests/test_hostname_placeholders.py   (or python tests/test_hostname_placeholders.py)
"""
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from utils import (device_type_from_dhcp_fingerprint, hostname_key, is_local_name, is_network_dns_name,  # noqa: E402
                   is_placeholder_hostname, note_network_dns_domain)

# The router's DNS domain is learned from its DHCP answers (Zeek dhcp.log `domain`), not built in; these tests run as
# on a network whose router announced "fritz.box".
note_network_dns_domain("fritz.box")

UUID = "63069992-0aeb-4f3c-bdc2-452a7c9a31ef"
IPHONE_PARAMS = [1, 121, 3, 6, 15, 108, 114, 119, 162, 252]          # seen on .94
MAC_PARAMS = [1, 121, 3, 6, 15, 108, 114, 119, 252, 95, 44, 46]
LINUX_PARAMS = [1, 2, 6, 12, 15, 26, 28, 121, 3, 33, 40, 41, 42, 119, 249, 252, 17]   # the .94 laptop's


@pytest.mark.parametrize("name", [UUID, UUID.upper(), UUID.replace("-", "_"), UUID + ".fritz.box",
                                  "PC-A6-EB-99-7C-A0-05", "pc_a6_eb_99_7c_a0_05", "pc-a6-eb-99-7c-a0-05.fritz.box"])
def test_placeholders_are_recognised(name):
    assert is_placeholder_hostname(name)


@pytest.mark.parametrize("name", ["office-laptop", "office_laptop_fritz_box", "iphone-alex", "pc-alex", "PC-A6-EB",
                                  "unknown", "", None, "esp-c74d8a-smart-home"])
def test_real_names_are_not_placeholders(name):
    assert not is_placeholder_hostname(name)


def test_hostname_key_treats_forms_alike():
    assert hostname_key("Office-Laptop") == hostname_key("office-laptop.fritz.box") == hostname_key("office_laptop_fritz_box") == "office_laptop"
    assert hostname_key("printer.lan") == "printer"
    assert hostname_key("unknown") == "" and hostname_key(None) == ""


def test_router_domain_is_learned_not_built_in():
    # Another router's domain: not stripped until this network's DHCP server announces it.
    assert hostname_key("tv-1.speedport.ip") == "tv_1_speedport_ip"
    assert not is_network_dns_name("tv-1.speedport.ip")
    assert note_network_dns_domain("speedport.ip") and not note_network_dns_domain("Speedport.IP.")
    assert hostname_key("tv-1.speedport.ip") == hostname_key("TV-1") == "tv_1"
    assert is_network_dns_name("tv-1.speedport.ip") and is_network_dns_name("speedport.ip")
    # A learned domain never grants the detection-side "local" status (any LAN host can answer DHCP).
    assert not is_local_name("tv-1.speedport.ip")
    assert not note_network_dns_domain("bad domain!") and not note_network_dns_domain("")


def test_dhcp_fingerprint_types():
    assert device_type_from_dhcp_fingerprint({"param_list": IPHONE_PARAMS}) == "phone"
    assert device_type_from_dhcp_fingerprint({"param_list": MAC_PARAMS}) == "laptop"
    assert device_type_from_dhcp_fingerprint({"param_list": LINUX_PARAMS}) == ""
    assert device_type_from_dhcp_fingerprint(None) == "" and device_type_from_dhcp_fingerprint({"param_list": "x"}) == ""


@pytest.fixture
def idm(tmp_path):
    from core.identity import DeviceIdentityManager
    from core.state_guard import StateManager
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"), max_devices=20)
    return DeviceIdentityManager(sm, {}), sm


def _refresh(idm, sm, dev, hostname, overwrite=True):
    with sm.lock_device(dev) as st:
        idm._refresh_identity_signals(st, "aa:bb:cc:dd:ee:01", "10.0.0.5", hostname, None, overwrite_hostname=overwrite)
        return st.hostname


def test_name_does_not_flip_between_forms_or_to_a_placeholder(idm):
    idm, sm = idm
    sm.get_or_create(device_id="lap", client_ip="10.0.0.5", hostname="unknown")
    assert _refresh(idm, sm, "lap", "office-laptop") == "office-laptop"
    assert _refresh(idm, sm, "lap", "office_laptop_fritz_box") == "office-laptop"      # same name, other form: kept
    assert _refresh(idm, sm, "lap", UUID) == "office-laptop"                    # placeholder: never replaces
    assert _refresh(idm, sm, "lap", "office-laptop") == "office-laptop"  # a real rename still applies
    assert _refresh(idm, sm, "lap", "other-name", overwrite=False) == "office-laptop"


def test_stored_placeholder_is_cleared(idm):
    idm, sm = idm
    sm.get_or_create(device_id="ph", client_ip="10.0.0.6", hostname="unknown")
    with sm.lock_device("ph") as st:
        st.hostname = UUID
    assert _refresh(idm, sm, "ph", "unknown") == "unknown"
    assert _refresh(idm, sm, "ph", "PC-A6-EB-99-7C-A0-05") == "unknown"


def test_placeholder_dropped_when_loading_state():
    from core.state import DeviceState
    st = DeviceState.from_dict({"device_id": "ph", "client_ip": "10.0.0.6", "hostname": UUID})
    assert st.hostname == "unknown"
    assert DeviceState.from_dict({"device_id": "x", "client_ip": "10.0.0.7", "hostname": "office-laptop"}).hostname == "office-laptop"


def test_override_rule_matches_every_form_of_the_name(idm):
    idm, sm = idm
    sm.get_or_create(device_id="lap", client_ip="10.0.0.5", hostname="unknown")
    with sm.lock_device("lap") as st:
        st.hostname = "office_laptop_fritz_box"
        idm.apply_device_type(st, {"office-laptop": "server"})
        assert (st.device_type, st.device_type_is_override) == ("server", True)


def test_iphone_without_a_name_is_typed_by_its_dhcp_fingerprint(idm):
    idm, sm = idm
    sm.get_or_create(device_id="ph", client_ip="10.0.0.6", hostname="unknown")
    with sm.lock_device("ph") as st:
        st.mac_address = "a6:eb:99:7c:a0:05"          # private (locally administered) MAC: no vendor
        st.dhcp_fingerprint = {"param_list": IPHONE_PARAMS}
        idm.apply_device_type(st, {})
        assert (st.device_type, st.device_type_is_override) == ("phone", False)


def test_placeholders_never_anchor_an_identity():
    from argus.identity.resolver import is_generic_hostname
    from core.identity import _is_generic_hostname
    assert _is_generic_hostname(UUID) and is_generic_hostname(UUID)
    assert _is_generic_hostname("pc_a6_eb_99_7c_a0_05") and is_generic_hostname("PC-A6-EB-99-7C-A0-05")
    assert not _is_generic_hostname("office-laptop") and not is_generic_hostname("office-laptop")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
