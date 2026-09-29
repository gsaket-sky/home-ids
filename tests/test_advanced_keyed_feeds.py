"""Standalone test (run directly): hidden advanced_keyed_feeds switch (default off) + VirusTotal removal."""
import sys
import tempfile
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))
import intelligence.threat_intel as ti_mod
from intelligence.threat_intel import ThreatIntel
from config import DEFAULT_CONFIG

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def fetched_feeds(**kw):
    with tempfile.TemporaryDirectory() as d:
        ti = ThreatIntel(cache_dir=d, et_open_enabled=False, **kw)
        seen = []
        ti._fetch_with_cache = lambda url, cache_file, ttl, feed_name="": seen.append(feed_name) or None
        ti._fetch_otx = lambda ips, domains: seen.append("otx")
        ti._refresh_all()
        return ti, seen


ti, seen = fetched_feeds(otx_api_key="secret")
check("default: only keyless Feodo is fetched (no OTX call)", seen == ["feodo_ips"], str(seen))
check("default: OTX key ignored", ti.otx_api_key == "")
check("default: advanced flag off", ti.advanced_feeds is False)

ti, seen = fetched_feeds(otx_api_key="secret", advanced_feeds=True)
check("advanced: all four feeds fetched", set(seen) == {"feodo_ips", "urlhaus_hosts", "urlhaus_urls", "threatfox_iocs", "otx"}, str(seen))
check("advanced: OTX key honoured", ti.otx_api_key == "secret")

check("config default is off", DEFAULT_CONFIG.get("advanced_keyed_feeds") is False)
check("VirusTotalClient is gone", not hasattr(ti_mod, "VirusTotalClient"))
check("virustotal_api_key no longer a config default", "virustotal_api_key" not in DEFAULT_CONFIG)

pipe_src = (_P(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")
check("pipeline gates AbuseIPDB key on the switch", 'if self.config.get("advanced_keyed_feeds", False) else ""' in pipe_src)
check("pipeline keeps the honeypot signal in vt_risk", "if dest_ip in honeypots:\n                    vt_risk = 4.0" in pipe_src)
check("pipeline no longer references virustotal", "virustotal" not in pipe_src.replace("VirusTotal was removed", ""))

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED: {FAILURES}")
    sys.exit(1)
print("ALL PASSED")
