"""
How much one threat-intel match counts for (intelligence/intel_strength.py, MASTER_TODO M3 "NTP time servers on a Tor
list become sweep findings") and the stale-intel renewal in the nightly cross-device check.

On .94 the first learning-period sweep reported 15 findings: 9 were NTP-pool servers on the ET Tor list (confidence
0.25), 6 ordinary app domains on ET misc lists (0.40). Every one also became network-wide tier-5 reputation (33
destinations, among them api.telegram.org and cloudflare-dns.com). Covers: a weak (context-only, < 0.5) match is never
a retro/sweep finding, never tier-5 reputation and never written back, but is counted; a strong one is unchanged; a
Tor-list match counts in the live engine only for a TCP connection seen on the wire; the nightly local-intel
cross-check notes a device without renewing the entry, and does not report it twice.

Run directly: `venv/Scripts/python.exe tests/test_argus_intel_strength.py`
"""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.intel_strength import (STRONG_MATCH_CONFIDENCE, is_strong_match, is_tor_listing,  # noqa: E402
                                         tor_listing_applies)

TOR = {"confidence": 0.25, "tags": ["et_open", "et_tor"], "source": "et_open"}
MISC = {"confidence": 0.40, "tags": ["et_open", "misc-activity"], "source": "et_open"}
C2 = {"confidence": 0.95, "tags": ["c2", "botnet"], "source": "feodo_ips"}

# --- the rules -------------------------------------------------------------------------------------------------------
check("the strong bar is the hard-stop bar (confidence 0.5 = risk 2.0)", STRONG_MATCH_CONFIDENCE == 0.5)
check("C2 is strong; Tor, misc and DROP-level matches are not",
      is_strong_match(C2) and not is_strong_match(TOR) and not is_strong_match(MISC)
      and not is_strong_match({"confidence": 0.45}) and is_strong_match({"confidence": 0.5}))
check("no match, or a broken confidence, is not strong", not is_strong_match(None) and not is_strong_match({"confidence": "x"}))
check("ET Tor entries are recognised as Tor listings", is_tor_listing(TOR) and not is_tor_listing(C2))
check("a Tor listing applies to a TCP connection seen on the wire", tor_listing_applies(TOR, True, "TCP"))
check("...not to UDP (an NTP-pool server that is also a relay)", not tor_listing_applies(TOR, True, "UDP"))
check("...not to an address the device only resolved", not tor_listing_applies(TOR, False, "TCP"))
check("any other match always applies", tor_listing_applies(C2, False, "UDP") and tor_listing_applies(MISC, False, None))

# --- the retro-hunt / learning sweep ---------------------------------------------------------------------------------
from argus.graph.store import GraphStore  # noqa: E402
from argus.retro_hunter import RetroHunter, RETRO_HUNTER_SOURCE  # noqa: E402

NOW = time.time()
tmp = Path(tempfile.mkdtemp(prefix="intel_strength_"))
store = GraphStore(str(tmp / "graph.db"))
NTP_TOR_IP, C2_IP, APP = "136.243.177.133", "203.0.113.66", "figma.com"
store.record_device_destinations("firetv", [NTP_TOR_IP, C2_IP], timestamp=NOW - 3600)
intel_ips = {NTP_TOR_IP: TOR, C2_IP: C2}
hunter = RetroHunter(store, lambda d: MISC if d == APP else None, ip_lookup=lambda ip: intel_ips.get(ip))
findings = hunter.hunt(days_back=7, now=NOW, extra_pairs=[("laptop", APP)])
check("only the strong match is a finding", [(f.device_id, f.destination_id) for f in findings] == [("firetv", C2_IP)],
      str([(f.device_id, f.destination_id, f.confidence) for f in findings]))
check("the weak matches are counted", hunter.last_weak_matches == 2, str(hunter.last_weak_matches))
check("a weak match never becomes network-wide tier-5 reputation",
      store.get_destination_reputation(NTP_TOR_IP) is None and store.get_destination_reputation(APP) is None)
check("a strong one still does", (store.get_destination_reputation(C2_IP) or {}).get("tier") == 5)
retro_rows = store._conn.execute("SELECT destination_id FROM evidence WHERE source = ?", (RETRO_HUNTER_SOURCE,)).fetchall()
check("no evidence is written back for a weak match", [r[0] for r in retro_rows] == [C2_IP], str([r[0] for r in retro_rows]))

# --- the nightly local-intel cross-check: note, never renew ----------------------------------------------------------
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402
from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402
from argus.ops import live_retro_hunter  # noqa: E402

intel = LocalConfirmedIntel(str(tmp / "intel"))
VPN_IP = "187.40.40.147"
intel.record("ip", VPN_IP, "phone", reason="STAGE_1_HARD_STOP")
before = dict(intel.check("ip", VPN_IP))
store.record_device_destinations("laptop", [VPN_IP], timestamp=NOW - 600)
matches = hunter.check_local_intel_history(intel, days_back=7, now=NOW)
check("another device that touched the entry is found", [m["device_id"] for m in matches] == ["laptop"], str(matches))
time.sleep(0.02)
closed = live_retro_hunter._close_local_intel_loop(ClAfpeEngine(store, local_intel=intel), matches)
after = intel.check("ip", VPN_IP)
check("the loop is closed for it", closed == 1)
check("...without renewing the entry (last_confirmed, count and sources unchanged)",
      after["last_confirmed"] == before["last_confirmed"] and after["count"] == before["count"]
      and after["sources"] == ["phone"], f"before={before} after={after}")
check("...and the device is noted on it", after.get("implicated") == ["laptop"], str(after))
check("the next run does not report it again", hunter.check_local_intel_history(intel, days_back=7, now=NOW) == [])
check("noting twice is a no-op, and a source or a missing entry is never noted",
      not intel.note_implicated("ip", VPN_IP, "laptop") and not intel.note_implicated("ip", VPN_IP, "phone")
      and not intel.note_implicated("ip", "198.51.100.1", "laptop"))

# --- the live engine applies the Tor rule at its IP lookup -----------------------------------------------------------
src = (Path(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")
lookup_at = src.find("ip_ti_res = self.ti_engine.lookup_ip(dest_ip)")
check("the live IP lookup is followed by the Tor rule",
      lookup_at > 0 and "tor_listing_applies(" in src[lookup_at:lookup_at + 600])
store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
print("All intel-strength checks PASSED.")
