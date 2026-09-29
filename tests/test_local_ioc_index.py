"""Standalone test (run directly): src/intelligence/local_ioc_index.py -- ET Open ruleset parser.

Synthetic cases cover the parsing rules; an optional real-ruleset case runs when the env var
IDS_ET_RULES points at a downloaded suricata.rules (skipped otherwise)."""
import os
import sys
import tempfile
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))
from intelligence.local_ioc_index import parse_et_rules, save_index, load_index

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


RULES = r'''
# alert ip [9.9.9.9,8.8.4.4] any -> $HOME_NET any (msg:"ET DROP disabled rule"; sid:1; rev:1;)
alert ip [45.155.204.0/24,5.188.10.7,10.0.0.5,192.168.1.0/24,127.0.0.1,!45.45.45.45] any -> $HOME_NET any (msg:"ET DROP Spamhaus DROP Listed Traffic Inbound group 1"; classtype:misc-attack; sid:2400000; rev:1;)
alert ip $HOME_NET any -> [162.243.103.246,2a00:1450:4001:81b::200e] any (msg:"ET CNC Feodo Tracker Reported CnC Server group 1"; classtype:trojan-activity; sid:2404300; rev:1;)
alert ip [104.244.72.115] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 1"; sid:2403300; rev:1;)
alert ip [185.220.101.1] any -> $HOME_NET any (msg:"ET TOR Known Tor Exit Node Traffic group 1"; sid:2520000; rev:1;)
alert ip [93.184.216.34] any -> $HOME_NET any (msg:"ET COMPROMISED Known Compromised or Hostile Host Traffic group 1"; sid:2500000; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ET MALWARE Observed Evil DNS Query"; dns.query; content:"evil-c2.example.net"; nocase; endswith; classtype:trojan-activity; sid:2029107; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ET ADWARE_PUP Adware DNS"; dns_query; content:".adware-thing.info"; depth:18; endswith; nocase; classtype:pup-activity; sid:2029108; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Observed Bad Domain (bad-tls.org in TLS SNI)"; flow:established,to_server; tls.sni; content:"bad-tls.org"; endswith; classtype:trojan-activity; sid:2029109; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ET MALWARE Hex Escaped"; dns.query; content:"hex|2d|escaped.example.org"; nocase; sid:2029110; rev:1; classtype:trojan-activity;)
alert dns $HOME_NET any -> any any (msg:"ET MALWARE not a domain"; dns.query; content:"nodot"; sid:2029111; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ET RETIRED Old Domain"; dns.query; content:"old-domain.example.com"; sid:2029112; rev:1; classtype:trojan-activity;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET JA3 Hash - Metasploit http scanner"; ja3_hash; content:"16f17c896273d1d098314a02e87dd4cb"; classtype:unknown; sid:2028301; rev:2;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET MALWARE Some Signature"; content:"GET /x"; sid:3000000; rev:1;)
'''.strip().splitlines()

p = parse_et_rules(RULES)
check("disabled ('#') rules are skipped", "9.9.9.9" not in p.ips and "8.8.4.4" not in p.ips)
check("public CIDR kept, public single IP kept",
      any(c == "45.155.204.0/24" for c, _ in p.cidrs) and "5.188.10.7" in p.ips)
check("private/loopback space never becomes an indicator",
      "10.0.0.5" not in p.ips and "127.0.0.1" not in p.ips and not any(c.startswith("192.168.") for c, _ in p.cidrs))
check("negated entries (!ip) are ignored", "45.45.45.45" not in p.ips)
check("dst-side list ($HOME_NET -> [C2]) is read too, incl. IPv6",
      "162.243.103.246" in p.ips and "2a00:1450:4001:81b::200e" in p.ips)
check("IP metadata carries category + sid", p.ips["162.243.103.246"]["category"] == "ET CNC"
      and p.ips["162.243.103.246"]["sid"] == 2404300)
check("C2 IP can hard-stop alone (confidence >= 0.5)", p.ips["162.243.103.246"]["confidence"] >= 0.5)
check("CINS / Tor / DROP / COMPROMISED can NOT hard-stop alone (< 0.5)",
      all(p.ips[i]["confidence"] < 0.5 for i in ("104.244.72.115", "185.220.101.1", "93.184.216.34"))
      and all(m["confidence"] < 0.5 for c, m in p.cidrs if c == "45.155.204.0/24"))
check("Tor is the weakest signal (context only)", p.ips["185.220.101.1"]["confidence"] <= 0.25)
check("dns.query domain parsed; malware classtype -> high confidence",
      p.domains.get("evil-c2.example.net", {}).get("confidence", 0) >= 0.9)
check("tls.sni domain parsed", "bad-tls.org" in p.domains)
check("dns_query with leading dot normalised; PUP classtype -> low confidence",
      p.domains.get("adware-thing.info", {}).get("confidence", 1) < 0.5)
check("|2d| hex escape decoded", "hex-escaped.example.org" in p.domains)
check("a content string that is not a domain is rejected", "nodot" not in p.domains)
check("ET RETIRED domains get the low default confidence",
      p.domains.get("old-domain.example.com", {}).get("confidence", 1) < 0.5)
check("JA3 hash extracted", "16f17c896273d1d098314a02e87dd4cb" in p.ja3)
check("rules without any indicator are counted as seen but not used",
      p.rules_seen == 13 and p.rules_used < p.rules_seen, f"seen={p.rules_seen} used={p.rules_used}")

with tempfile.TemporaryDirectory() as d:
    path = _P(d) / "idx" / "et.json.gz"
    save_index(p, path, source_version="test-1", fetched_at=1234.0)
    loaded = load_index(path)
    check("save/load round-trips every indicator", loaded is not None and loaded[0].counts() == p.counts())
    check("metadata round-trips", loaded[1]["source_version"] == "test-1" and loaded[1]["fetched_at"] == 1234.0)
    check("no temp files left behind by the atomic write", [f.name for f in path.parent.iterdir()] == ["et.json.gz"])
    path.write_bytes(b"not gzip")
    check("a corrupt index returns None (never raises)", load_index(path) is None)
    check("a missing index returns None", load_index(_P(d) / "nope.gz") is None)

real = os.environ.get("IDS_ET_RULES")
if real and _P(real).exists():
    with open(real, encoding="utf-8", errors="replace") as f:
        r = parse_et_rules(f)
    c = r.counts()
    print("real ruleset counts:", c)
    check("real ruleset: >10k IPs, >1k CIDRs, >5k domains, >50 JA3",
          c["ips"] > 10000 and c["cidrs"] > 1000 and c["domains"] > 5000 and c["ja3"] > 50, str(c))
    allm = list(r.ips.values()) + [m for _, m in r.cidrs] + list(r.domains.values()) + list(r.ja3.values())
    hard = sum(1 for m in allm if m["confidence"] >= 0.5)
    check("real ruleset: only a minority of indicators can hard-stop alone (<35%)", hard / len(allm) < 0.35,
          f"{hard}/{len(allm)}")
else:
    print("[SKIP] real-ruleset case (set IDS_ET_RULES=path/to/suricata.rules)")

if FAILURES:
    print(f"FAILED: {FAILURES}")
    sys.exit(1)
print("All checks PASSED.")
