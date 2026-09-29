"""Standalone test (run directly): ThreatIntel <-> local ET Open index wiring, JA3 union, suffix matching.

Offline: ETOpenUpdater's HTTP layer is never hit (update() is stubbed); the index is built from a
synthetic ParsedIOCs and saved with save_index()."""
import sys
import tempfile
import time
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))
from intelligence.local_ioc_index import ParsedIOCs, save_index
from intelligence.et_open_fetch import UpdateResult
from intelligence.threat_intel import ThreatIntel

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def meta(conf, tag="c2"):
    return {"source": "et_open", "tags": [tag], "confidence": conf}


def parsed():
    p = ParsedIOCs()
    p.ips = {"45.9.9.9": meta(0.9), "46.1.1.1": meta(0.3, "cins")}
    p.cidrs = [("203.0.113.0/24", meta(0.9)), ("not-a-cidr", meta(0.9))]
    p.domains = {"go.querymo.com": meta(0.9, "malware"), "evil.example-bad.net": meta(0.9, "malware")}
    p.ja3 = {"a" * 32: meta(0.9, "ja3"), "B" * 32: meta(0.9, "ja3")}
    return p


with tempfile.TemporaryDirectory() as d:
    # --- boot load: index already on disk, no network involved ---
    save_index(parsed(), _P(d) / "et_open_index.json.gz", source_version="t1", fetched_at=time.time())
    ti = ThreatIntel(cache_dir=d)
    check("boot: direct IP hit", (ti.lookup_ip("45.9.9.9") or {}).get("source") == "et_open")
    check("boot: hit carries ip/malicious keys", (ti.lookup_ip("45.9.9.9") or {}).get("ip") == "45.9.9.9"
          and ti.lookup_ip("45.9.9.9").get("malicious") is True)
    check("boot: CIDR hit", ti.lookup_ip("203.0.113.77") is not None)
    check("boot: bad CIDR string skipped", ti.lookup_ip("8.8.8.8") is None)
    check("boot: CIDR meta has cidr key", (ti.lookup_ip("203.0.113.77") or {}).get("cidr") == "203.0.113.0/24")
    check("boot: ti_risk hard-stops for C2 IP", ti.ioc_risk_score(ip="45.9.9.9") >= 2.0)
    check("boot: weak list stays below hard-stop", 0 < ti.ioc_risk_score(ip="46.1.1.1") < 2.0)
    check("boot: exact domain hit", ti.lookup_domain("go.querymo.com") is not None)
    check("boot: JA3 loaded and lower-cased", ti.dynamic_ja3 == frozenset({"a" * 32, "b" * 32}), str(ti.dynamic_ja3))

    # --- domain suffix matching: every label, most specific first ---
    check("suffix: subdomain of 3-label indicator", (ti.lookup_domain("x.go.querymo.com") or {}).get("matched_parent") is True)
    check("suffix: deep subdomain of 3-label indicator", ti.lookup_domain("a.b.c.go.querymo.com") is not None)
    check("suffix: sibling of 3-label indicator does NOT match", ti.lookup_domain("www.querymo.com") is None)
    check("suffix: 2-label indicator matches deep subdomain", ti.lookup_domain("a.b.evil.example-bad.net") is not None)
    check("suffix: bare TLD never matched", ti.lookup_domain("net") is None and ti.lookup_domain("com") is None)

    # --- JA3 union of SSLBL + ET ---
    ti._sslbl_ja3 = frozenset({"c" * 32})
    ti._rebuild_ja3()
    check("ja3: union of SSLBL and ET", ti.dynamic_ja3 == frozenset({"a" * 32, "b" * 32, "c" * 32}))
    p2 = parsed()
    p2.ja3 = {"d" * 32: meta(0.9)}
    ti._apply_et_index(p2)
    check("ja3: ET refresh replaces only ET part", ti.dynamic_ja3 == frozenset({"c" * 32, "d" * 32}))

    # --- refresh hook: updated swaps in the new index, and tables get rebuilt ---
    p3 = parsed()
    p3.ips = {"77.7.7.7": meta(0.9)}
    calls = []
    ti._et_updater.update = lambda force=False: (calls.append(1), UpdateResult("updated", "", p3, {}))[1]
    ti._refresh_et_open()
    ti._combine_feeds()
    check("refresh: new IP present", ti.lookup_ip("77.7.7.7") is not None)
    check("refresh: dropped IP gone", ti.lookup_ip("45.9.9.9") is None)
    check("refresh: updater called once", len(calls) == 1)

    # --- refresh hook: error / unchanged keep the last good data ---
    ti._et_updater.update = lambda force=False: UpdateResult("error", "boom")
    ti._refresh_et_open()
    check("refresh error: last good index kept", ti.lookup_ip("77.7.7.7") is not None)
    ti._et_updater.update = lambda force=False: (_ for _ in ()).throw(RuntimeError("bang"))
    ti._refresh_et_open()
    check("refresh exception swallowed, data kept", ti.lookup_ip("77.7.7.7") is not None)

    # --- clash: higher confidence wins ---
    ti._feed_ips["feodo_ips"] = {"77.7.7.7": {"source": "feodo_ips", "confidence": 0.95, "malicious": True}}
    ti._combine_feeds()
    check("clash: higher confidence entry wins", ti.lookup_ip("77.7.7.7")["source"] == "feodo_ips")

with tempfile.TemporaryDirectory() as d:
    # --- disabled: no updater, no ET data, update hook is a no-op ---
    save_index(parsed(), _P(d) / "et_open_index.json.gz", source_version="t1", fetched_at=time.time())
    off = ThreatIntel(cache_dir=d, et_open_enabled=False)
    check("disabled: no updater", off._et_updater is None)
    off._refresh_et_open()
    check("disabled: index on disk ignored", off.lookup_ip("45.9.9.9") is None and not off.dynamic_ja3)

with tempfile.TemporaryDirectory() as d:
    # --- empty cache dir boots cleanly ---
    e = ThreatIntel(cache_dir=d)
    check("empty: boots with no data", e.lookup_ip("45.9.9.9") is None and e.lookup_domain("x.example.com") is None)

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED: {FAILURES}")
    sys.exit(1)
print("ALL PASSED")
