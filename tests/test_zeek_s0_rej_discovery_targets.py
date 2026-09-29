"""Standalone test (run directly): S0/REJ toward multicast/link-local/broadcast is
discovery chatter and must not count toward zeek_s0_rej_count; S0/REJ toward a real
LAN unicast host still must. Real alert: a phone's mDNS (224.0.0.251) + LAN pings
saturated the LGBM port-scan feature (71 rejects) and drove P(FP) to 0.5%."""
import sys
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))
import time
from extractors.zeek_features import ZeekFeatureExtractor

FAILURES = []
def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)

SRC = "192.168.77.22"
def _conn(dst, uid, state):
    return {"_zeek_type": "conn", "id.orig_h": SRC, "id.resp_h": dst, "id.resp_p": 0,
            "proto": "icmp", "orig_bytes": 0, "uid": uid, "ts": time.time(), "conn_state": state}

zfx = ZeekFeatureExtractor(home_subnets=["192.168.77.0/24"])
for i, dst in enumerate(["224.0.0.251", "ff02::fb", "fe80::1", "192.168.77.255", "255.255.255.255"]):
    zfx.ingest(_conn(dst, f"D{i}", "S0"))
f = zfx.get_features(SRC)
check("S0/REJ to multicast/link-local/broadcast is not counted", f["zeek_s0_rej_count"] == 0, f"got {f['zeek_s0_rej_count']}")
check("...nor added to rejected-IP set", f["zeek_s0_rej_unique_ips"] == 0, f"got {f['zeek_s0_rej_unique_ips']}")

zfx2 = ZeekFeatureExtractor(home_subnets=["192.168.77.0/24"])
for i, dst in enumerate(["192.168.77.25", "192.168.77.27", "203.0.113.5"]):
    zfx2.ingest(_conn(dst, f"U{i}", "REJ"))
f2 = zfx2.get_features(SRC)
check("REJ to LAN/external unicast hosts still counts (real scans stay detectable)",
      f2["zeek_s0_rej_count"] == 3 and f2["zeek_s0_rej_unique_ips"] == 3, f"got {f2['zeek_s0_rej_count']}/{f2['zeek_s0_rej_unique_ips']}")

if FAILURES:
    print(f"FAILED: {FAILURES}"); sys.exit(1)
print("All checks PASSED.")
