"""core/alert_attribution.py: an alert's target comes only from the evidence that fired (2026-10-12, TODO 0c Step 2,
new_issues items 3/4). Every signature family, plus the cases that used to fall back to the window's "most notable
domain" or the device's last connection."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.alert_attribution import (  # noqa: E402
    UNKNOWN, attribute_alert_target, describe_target_set, DNS_EVASION_NAMES, REPUTATION_VERDICTS,
)
from intelligence.hypotheses.evidence import Evidence  # noqa: E402


def ev(etype, domain=None, confidence=0.5, ts=1.0, targets=(), target_count=0, value=1.0):
    return Evidence(type=etype, source="t", timestamp=ts, device="d", value=value, confidence=confidence,
                    domain=domain, targets=tuple(targets), target_count=target_count)


def test_recon_names_the_swept_set_not_one_member_and_no_domain():
    # new_issues item 4: an internal ARP sweep alert showed a website and the last flow's address.
    t = attribute_alert_target("INTERNAL_RECONNAISSANCE",
                               [ev("arp_sweep", "10.0.0.7", targets=["10.0.0.2", "10.0.0.3", "10.0.0.7"],
                                   target_count=23)])
    assert t.domain == UNKNOWN and t.dest_ip == UNKNOWN
    assert t.target_set == {"kind": "swept_hosts", "count": 23, "examples": ["10.0.0.2", "10.0.0.3", "10.0.0.7"]}
    assert t.evidence_linked and t.source == "arp_sweep"
    assert describe_target_set(t.target_set) == "23 hosts (e.g. 10.0.0.2, 10.0.0.3, 10.0.0.7)"


def test_rejected_connections_preferred_over_the_sweep_and_a_single_host_is_the_destination():
    t = attribute_alert_target("PORT_SCAN", [ev("arp_sweep", "10.0.0.9", targets=["10.0.0.9"], target_count=12),
                                             ev("zeek_conn_abuse", "203.0.113.5", targets=["203.0.113.5"],
                                                target_count=1)])
    assert t.target_set["kind"] == "rejected_connections"
    assert t.dest_ip == "203.0.113.5"        # a set of exactly one host IS the destination


def test_scan_evidence_from_before_the_targets_field_still_names_its_example():
    t = attribute_alert_target("CONNECTION_ABUSE", [ev("zeek_conn_abuse", "198.51.100.4")])
    assert t.target_set == {"kind": "rejected_connections", "count": 1, "examples": ["198.51.100.4"]}


def test_scan_without_any_target_is_device_level():
    t = attribute_alert_target("CONNECTION_ABUSE", [ev("zeek_long_conn", None)])
    assert (t.dest_ip, t.domain, t.target_set, t.evidence_linked) == (UNKNOWN, UNKNOWN, None, False)


def test_intrusion_takes_the_strongest_item_and_a_lateral_scan_is_a_set():
    strong = ev("zeek_notice_highly_deterministic", "192.0.2.10", confidence=0.2)
    weak = ev("zeek_notice_weak", "192.0.2.99", confidence=0.9)
    t = attribute_alert_target("NETWORK_INTRUSION", [weak, strong])
    assert t.dest_ip == "192.0.2.10" and t.domain == UNKNOWN and t.target_set is None
    lat = ev("zeek_lateral_scan", "10.0.0.5", targets=["10.0.0.5", "10.0.0.6"], target_count=4)
    t = attribute_alert_target("LATERAL_MOVEMENT", [strong, lat])
    assert t.target_set == {"kind": "lateral_targets", "count": 4, "examples": ["10.0.0.5", "10.0.0.6"]}
    assert t.dest_ip == UNKNOWN


def test_intrusion_without_evidence_target_has_no_guess():
    assert attribute_alert_target("NETWORK_INTRUSION", [ev("zeek_notice", None)]).dest_ip == UNKNOWN


@pytest.mark.parametrize("sig,etype", [("DNS_COVERT_TUNNELING", "dns_tunnel_v2"), ("DGA_BOTNET_C2", "dns_dga_burst"),
                                       ("DNS_TUNNELING", "dns_entropy")])
def test_domain_signatures_use_their_evidence_domain_and_its_own_wire_address(sig, etype):
    wire = {"x7k2q.example.net": "203.0.113.77"}
    t = attribute_alert_target(sig, [ev("dns_rate", "other.example"), ev(etype, "x7k2q.example.net")],
                               wire_ip_of=wire.get)
    assert t.domain == "x7k2q.example.net"
    assert t.dest_ip == "203.0.113.77"     # this device's own answer for it, not its last connection


def test_domain_signature_without_wire_answer_keeps_destination_unknown():
    t = attribute_alert_target("DGA_BOTNET_C2", [ev("dns_dga_burst", "q9w8e7.example")], wire_ip_of=lambda d: None)
    assert (t.domain, t.dest_ip) == ("q9w8e7.example", UNKNOWN)


def test_domain_signature_without_evidence_domain_is_unknown_not_the_window_domain():
    # The old code kept target_malicious_domain here -- the path to the wrong Pi-hole blocks.
    t = attribute_alert_target("DNS_TUNNELING", [ev("dns_rate", None), ev("dns_unique_ratio", None)])
    assert (t.domain, t.dest_ip, t.evidence_linked) == (UNKNOWN, UNKNOWN, False)


@pytest.mark.parametrize("sig", DNS_EVASION_NAMES)
def test_dns_evasion_family_names_the_unexplained_address(sig):
    t = attribute_alert_target(sig, [ev("dns_evasion_anomaly", "198.51.100.200")])
    assert (t.dest_ip, t.domain) == ("198.51.100.200", UNKNOWN)


@pytest.mark.parametrize("sig", REPUTATION_VERDICTS)
def test_reputation_verdicts_route_the_scored_target_by_shape(sig):
    assert attribute_alert_target(sig, [], reputation_target="203.0.113.9").dest_ip == "203.0.113.9"
    t = attribute_alert_target(sig, [], reputation_target="bad.example")
    assert t.domain == "bad.example" and t.dest_ip == UNKNOWN
    assert not attribute_alert_target(sig, [], reputation_target="unknown").evidence_linked


@pytest.mark.parametrize("sig,etype", [("COORDINATED_TARGETING", "coordinated_targeting"),
                                       ("DATA_EXFILTRATION", "zeek_exfiltration"),
                                       ("C2_BEACONING", "zeek_beaconing")])
def test_argus_only_signatures_read_winning_evidence(sig, etype):
    we = [{"evidence_type": "other", "destination_id": "192.0.2.1"},
          {"evidence_type": etype, "destination_id": "(none)"},
          {"evidence_type": etype, "destination_id": "203.0.113.50"}]
    t = attribute_alert_target(sig, [], winning_evidence=we)
    assert t.dest_ip == "203.0.113.50" and t.source == etype


def test_beaconing_to_a_name_is_a_domain_not_an_address():
    # destination_id carries whatever the detector named; a name used to land in destination_ip.
    t = attribute_alert_target("C2_BEACONING", [], winning_evidence=[
        {"evidence_type": "zeek_beaconing", "destination_id": "beacon.example"}], wire_ip_of=lambda d: "203.0.113.3")
    assert (t.domain, t.dest_ip) == ("beacon.example", "203.0.113.3")


@pytest.mark.parametrize("sig,etype", [("SIGNATURE_MATCHED_THREAT", "suricata_signature_match"),
                                       ("Confirmed Exploit/Malware Signature (Suricata, Uncorroborated)",
                                        "suricata_signature_match"),
                                       ("Layer-2 ARP Spoofing Detected", "arp_spoofing"),
                                       ("Internal Honeypot Accessed", "honeypot_access"),
                                       ("Geofencing Policy Violation (Uncorroborated)", "geofencing_violation")])
def test_hard_stop_signatures_use_their_evidence(sig, etype):
    assert attribute_alert_target(sig, [ev(etype, "198.51.100.33")]).dest_ip == "198.51.100.33"
    assert attribute_alert_target(sig, [ev("dns_rate", "198.51.100.34")]).dest_ip == UNKNOWN


@pytest.mark.parametrize("sig", ["PEER_COHORT_DEVIATION", "Threshold Exceeded", "SOME_FUTURE_HYPOTHESIS"])
def test_signatures_without_a_rule_are_device_level(sig):
    t = attribute_alert_target(sig, [ev("dns_tunnel_v2", "x.example"), ev("arp_sweep", "10.0.0.1")],
                               winning_evidence=[{"evidence_type": "peer_deviation", "destination_id": "1.2.3.4"}],
                               reputation_target="203.0.113.1")
    assert (t.dest_ip, t.domain, t.target_set, t.evidence_linked) == (UNKNOWN, UNKNOWN, None, False)


def test_ipv6_scoped_address_is_an_address():
    t = attribute_alert_target("DNS_EVASION", [ev("dns_evasion_anomaly", "fe80::1%eth0")])
    assert t.dest_ip == "fe80::1%eth0" and t.domain == UNKNOWN


def test_describe_target_set():
    assert describe_target_set(None) == ""
    assert describe_target_set({"count": 1, "examples": []}) == "1 host"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
