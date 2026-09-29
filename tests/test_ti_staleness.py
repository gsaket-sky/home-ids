"""Standalone test (run directly): threat-intel staleness -- decay policy, ThreatIntel integration, WebUI text."""
import json
import sys
import tempfile
import time
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))
from intelligence import ti_staleness as ts
from intelligence.local_ioc_index import ParsedIOCs, save_index
from intelligence.threat_intel import ThreatIntel

FAILURES = []
DAY = 86400.0


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# --- pure policy ---
check("fresh = 1.0", ts.decay_factor(0) == 1.0 and ts.decay_factor(14 * DAY) == 1.0)
check("unknown age = 1.0", ts.decay_factor(None) == 1.0)
check("zero at 60d and beyond", ts.decay_factor(60 * DAY) == 0.0 and ts.decay_factor(400 * DAY) == 0.0)
check("linear midpoint (37d = 0.5)", abs(ts.decay_factor(37 * DAY) - 0.5) < 1e-9)
check("monotonic", ts.decay_factor(20 * DAY) > ts.decay_factor(30 * DAY) > ts.decay_factor(50 * DAY))

# --- describe ---
check("text: today", ts.describe(3600) == "Threat data updated today")
check("text: 1 day", ts.describe(1.5 * DAY) == "Threat data updated 1 day ago")
check("text: 5 days", ts.describe(5 * DAY) == "Threat data updated 5 days ago")
check("text: aging shows weight", "weight reduced to 50%" in ts.describe(37 * DAY))
check("text: expired", "no longer used" in ts.describe(70 * DAY))
check("text: never", "not downloaded" in ts.describe(None))


def meta(conf):
    return {"source": "et_open", "tags": ["c2"], "confidence": conf}


def build(d, last_success_days_ago):
    p = ParsedIOCs()
    p.ips = {"45.9.9.9": meta(0.9)}
    p.domains = {"evil.example-bad.net": meta(0.9)}
    p.ja3 = {"a" * 32: meta(0.9)}
    save_index(p, _P(d) / "et_open_index.json.gz", source_version="t", fetched_at=time.time())
    (_P(d) / "et_open_state.json").write_text(json.dumps({"last_success": time.time() - last_success_days_ago * DAY}))


# --- read_age_seconds ---
with tempfile.TemporaryDirectory() as d:
    check("age: no files -> None", ts.read_age_seconds(d) is None)
    build(d, 3)
    check("age: from state file (~3d)", abs(ts.read_age_seconds(d) - 3 * DAY) < 5)
    (_P(d) / "et_open_state.json").write_text("garbage")
    check("age: corrupt state falls back to index mtime", ts.read_age_seconds(d) < 60)

# --- ThreatIntel integration ---
for days, want_ip_score, want_hit, want_ja3 in [(3, 3.6, True, True), (37, 1.8, True, True), (70, 0.0, False, False)]:
    with tempfile.TemporaryDirectory() as d:
        build(d, days)
        ti = ThreatIntel(cache_dir=d)
        got = ti.ioc_risk_score(ip="45.9.9.9")
        check(f"{days}d: ip risk ~{want_ip_score}", abs(got - want_ip_score) < 0.05, str(got))
        check(f"{days}d: domain hit={want_hit}", (ti.lookup_domain("x.evil.example-bad.net") is not None) == want_hit)
        check(f"{days}d: ET JA3 active={want_ja3}", (("a" * 32) in ti.dynamic_ja3) == want_ja3)
        if days == 37:
            check("37d: below hard-stop (2.0)", got < 2.0)
            check("37d: hit marked decayed", ti.lookup_ip("45.9.9.9").get("decayed") is True)
        # stored meta must never be mutated by decay
        check(f"{days}d: stored confidence untouched", ti._bad_ips["45.9.9.9"]["confidence"] == 0.9)

with tempfile.TemporaryDirectory() as d:
    # non-ET feed is never decayed, even when ET is expired
    build(d, 70)
    ti = ThreatIntel(cache_dir=d)
    ti._feed_ips["feodo_ips"] = {"77.7.7.7": {"source": "feodo_ips", "confidence": 0.95, "malicious": True}}
    ti._combine_feeds()
    check("other feeds not decayed", abs(ti.ioc_risk_score(ip="77.7.7.7") - 3.8) < 1e-6)

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED: {FAILURES}")
    sys.exit(1)
print("ALL PASSED")
