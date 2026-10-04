"""
Every local-name check goes through utils.is_local_name() (master TODO follow-up to PR #5, 2026-10-05): the
reputation classifier's tier 0, the threat-signal detector's local-name test and LocalPopularity.observe().
No network's local suffix is built in; `local_domain_suffixes` configures it. ".box" (a public TLD the classifier
used to treat as local) is no longer assumed local.

Not part of the pytest suite -- run directly:
`venv/Scripts/python.exe tests/test_local_suffix_consumers.py`
"""
import sys
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from config import CONFIG  # noqa: E402
from intelligence.detectors import threat_signals as ts  # noqa: E402
from intelligence.local_popularity import LocalPopularity  # noqa: E402
from intelligence.reputation.classifier import ReputationClassifier  # noqa: E402


def configure(value):
    with CONFIG._lock:
        CONFIG._config["local_domain_suffixes"] = value


c = ReputationClassifier()
for cfg, label in (([], "no config"), (["fritz.box"], "fritz.box configured")):
    configure(cfg)
    check(f"{label}: built-in .local is tier 0", c.classify("tv.local").tier == 0)
    check(f"{label}: .box is no longer assumed local (public TLD)", c.classify("evil.box").tier == 3)
    check(f"{label}: threat_signals treats .localdomain/.lan as local",
          ts._is_local_name("pc.localdomain") and ts._is_local_name("nas.lan"))

configure([])
check("no config: fritz.box is tier 3 / not local", c.classify("fritz.box").tier == 3 and not ts._is_local_name("nas.fritz.box"))
configure(["fritz.box"])
check("configured: fritz.box and subdomains are tier 0", c.classify("nas.fritz.box").tier == 0)
check("configured: threat_signals sees nas.fritz.box as local", ts._is_local_name("nas.fritz.box"))
check("fritz.box no longer sits in the vendor-cloud list", "fritz.box" not in ts._VENDOR_CLOUD_API_DOMAINS)

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
    lp = LocalPopularity(_PathForSysPath(d) / "pop.db", etld1_fn=lambda n: ".".join(n.split(".")[-2:]))
    configure([])
    lp.observe("dev1", "nas.fritz.box")
    check("no config: nas.fritz.box is observed", bool(lp._etld_memo.get("nas.fritz.box")))
    configure(["fritz.box"])
    lp.observe("dev1", "cam.fritz.box")
    check("configured: cam.fritz.box is not observed", "cam.fritz.box" not in lp._etld_memo)
    lp.observe("dev1", "x.local")
    check("built-in: .local never observed", "x.local" not in lp._etld_memo)
    for attr in ("close",):
        getattr(lp, attr, lambda: None)()
configure([])

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
print("ALL PASSED")
