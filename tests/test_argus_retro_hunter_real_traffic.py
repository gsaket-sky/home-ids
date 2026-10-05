"""
RetroHunter reads real traffic, not only flagged destinations, and looks IPs up as IPs.

Covers: a quiet destination IP that only exists in device_destinations is found; an address goes to the IP lookup
and a name to the name lookup (a real ThreatIntel's lookup_domain() never matches an address); the popularity
ledger's names are hunted; multicast addresses are skipped; a second run reports and writes nothing new; the
local-intel cross-reference also sees quiet traffic.

Run directly: `venv/Scripts/python.exe tests/test_argus_retro_hunter_real_traffic.py`
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.graph.store import GraphStore  # noqa: E402
from argus.retro_hunter import RetroHunter, RETRO_HUNTER_SOURCE  # noqa: E402
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402
from intelligence.local_popularity import LocalPopularity  # noqa: E402
from intelligence.threat_intel import ThreatIntel  # noqa: E402

NOW = 2_000_000.0
DAY = 86400.0
tmp = Path(tempfile.mkdtemp(prefix="retro_real_traffic_"))
store = GraphStore(str(tmp / "g.db"))

BAD_IP = "203.0.113.7"
BAD_NAME = "c2.bad.example"

# Quiet C2 address: real traffic only, no evidence of any kind.
store.record_device_destinations("dev1", [BAD_IP, "198.51.100.9", "224.0.0.251", "192.168.1.20"], timestamp=NOW - 3 * DAY)
# Too old for a 14-day window.
store.record_device_destinations("dev2", [BAD_IP], timestamp=NOW - 30 * DAY)

calls = {"name": [], "ip": []}


def name_lookup(d):
    calls["name"].append(d)
    return {"confidence": 0.9, "tags": ["c2"], "source": "feed"} if d == BAD_NAME else None


def ip_lookup(ip):
    calls["ip"].append(ip)
    return {"confidence": 0.9, "tags": ["c2"], "source": "feed"} if ip == BAD_IP else None


hunter = RetroHunter(store, name_lookup, ip_lookup=ip_lookup)
findings = hunter.hunt(days_back=14, now=NOW)
check("a quiet destination that only exists in device_destinations is found",
      [(f.device_id, f.destination_id) for f in findings] == [("dev1", BAD_IP)], str(findings))
check("an address goes to the IP lookup, never the name lookup", BAD_IP in calls["ip"] and BAD_IP not in calls["name"])
check("multicast addresses are not looked up (the shared protocol-group filter)", "224.0.0.251" not in calls["ip"])
check("traffic outside the window is not hunted (dev2)", all(f.device_id != "dev1x" for f in findings)
      and not any(f.device_id == "dev2" for f in findings))
check("the destination gets network-wide tier-5 reputation",
      (store.get_destination_reputation(BAD_IP) or {}).get("tier") == 5)

# Ledger names (extra pairs) are hunted through the name lookup.
findings = hunter.hunt(days_back=14, now=NOW + 60, extra_pairs=[("dev3", BAD_NAME), ("dev3", "fine.example")])
check("a ledger name is found", [(f.device_id, f.destination_id) for f in findings] == [("dev3", BAD_NAME)], str(findings))
check("a name goes to the name lookup", BAD_NAME in calls["name"] and BAD_NAME not in calls["ip"])

# Second run: nothing new to report or write.
n_before = len(store.get_pairs_written_by_source_since(RETRO_HUNTER_SOURCE, 0))
again = hunter.hunt(days_back=14, now=NOW + 120, extra_pairs=[("dev3", BAD_NAME)])
check("a second run reports nothing for already-reported pairs", again == [], str(again))
check("and writes no new evidence", len(store.get_pairs_written_by_source_since(RETRO_HUNTER_SOURCE, 0)) == n_before)

# A new device reaching the same destination IS new.
store.record_device_destinations("dev4", [BAD_IP], timestamp=NOW + 100)
later = hunter.hunt(days_back=14, now=NOW + 200)
check("a different device on the same bad destination is a new finding",
      [(f.device_id, f.destination_id) for f in later] == [("dev4", BAD_IP)], str(later))

# Without an IP lookup, behaviour is as before: one lookup for everything.
plain_calls = []
plain = RetroHunter(store, lambda d: plain_calls.append(d) or None)
plain.hunt(days_back=14, now=NOW + 300)
check("without ip_lookup every destination goes to the one lookup", BAD_IP in plain_calls)

# The real ThreatIntel: lookup_domain() cannot see an address, lookup_ip() can.
ti = ThreatIntel(cache_dir=str(tmp / "ti"), refresh_interval=10**9)
ti._bad_ips[BAD_IP] = {"source": "feodo_ips", "tags": ["c2"], "confidence": 0.9, "malicious": True}
check("real ThreatIntel: lookup_domain() does not match an address", ti.lookup_domain(BAD_IP) is None)
real = RetroHunter(store, ti.lookup_domain, ip_lookup=ti.lookup_ip)
store.record_device_destinations("dev5", [BAD_IP], timestamp=NOW + 400)
got = real.hunt(days_back=14, now=NOW + 500)
check("real ThreatIntel wired through ip_lookup finds the address", [(f.device_id) for f in got] == ["dev5"], str(got))

# Local-intel cross-reference sees quiet traffic.
li = LocalConfirmedIntel(str(tmp / "li"))
li.record("ip", "198.51.100.9", "other-dev", "STAGE_1_HARD_STOP")
matches = hunter.check_local_intel_history(li, days_back=14, now=NOW + 600)
check("local-intel cross-reference finds a device that quietly touched a since-confirmed IP",
      [(m["device_id"], m["matched_value"]) for m in matches] == [("dev1", "198.51.100.9")], str(matches))

# Popularity ledger accessor.
pop = LocalPopularity(tmp / "pop.db", now_fn=lambda: NOW)
pop.observe("dev6", "seen.example.org", NOW - DAY)
pop.observe("dev7", "seen.example.org", NOW - DAY)
pop.observe("dev6", "old.example.org", NOW - 50 * DAY)
pop.flush()
pairs = pop.device_name_pairs_since(NOW - 14 * DAY)
check("ledger pairs: every device per recent name, none for old names",
      sorted(pairs) == [("dev6", "seen.example.org"), ("dev7", "seen.example.org")], str(pairs))

store.close()
print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
print("All retro-hunter real-traffic checks PASSED.")
