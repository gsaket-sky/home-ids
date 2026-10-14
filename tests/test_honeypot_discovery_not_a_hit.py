"""Harmless discovery traffic is not a honeypot "hit" (owner decision 2026-10-14, after the U1 discussion).

A router (and a NAS, a TV) routinely touches addresses nobody uses: DHCP address checks and device-list scans (ping),
WS-Discovery, LLMNR, NetBIOS, SSDP, mDNS, DHCP itself. Counting those made a CRITICAL "Internal Honeypot Accessed"
for ordinary housekeeping. They are built in as allowed, for every device and every network (protocol facts, no
addresses). Anything else toward the decoy -- a TCP connect to a service port, any other UDP port -- still counts.

Run directly: `python tests/test_honeypot_discovery_not_a_hit.py`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from extractors.zeek_features import ZeekFeatureExtractor  # noqa: E402

ok = True


def check(name, cond, detail=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + (f" -- {detail}" if detail and not cond else ""), flush=True)
    ok = ok and cond


HP, SRC = "10.9.0.99", "10.9.0.1"


def hits(proto, port):
    fx = ZeekFeatureExtractor(home_subnets=["10.9.0.0/24"], honeypot_ips={HP})
    fx.ingest({"_zeek_type": "conn", "id.orig_h": SRC, "id.resp_h": HP, "id.resp_p": port, "proto": proto,
               "orig_bytes": 0, "uid": "C1", "ts": 1000.0})
    return fx.get_features(SRC)["zeek_honeypot_hits"]


for name, proto, port in [("ping (ICMP echo, code 8)", "icmp", 8), ("ICMP neighbour/other type", "icmp", 135),
                          ("NetBIOS name", "udp", 137), ("SSDP", "udp", 1900), ("mDNS", "udp", 5353),
                          ("WS-Discovery", "udp", 3702), ("LLMNR", "udp", 5355), ("DHCP", "udp", 67)]:
    check(f"{name} is not a hit", hits(proto, port) == 0, str(hits(proto, port)))
for name, proto, port in [("TCP connect to SSH", "tcp", 22), ("TCP connect to SMB", "tcp", 445),
                          ("TCP to a discovery-looking port number (not UDP discovery)", "tcp", 3702),
                          ("UDP to an arbitrary port", "udp", 40000)]:
    check(f"{name} still counts", hits(proto, port) == 1, str(hits(proto, port)))
print("HONEYPOT DISCOVERY", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
