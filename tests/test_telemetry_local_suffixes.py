"""
utils.is_telemetry_domain() / is_local_name(): no network's local suffixes are built in (master TODO B, 2026-10-05).

Built in: only suffixes that cannot name a public host on any network (.arpa, .local, .internal, .lan, .home).
Configured: this network's own local domain, via `local_domain_suffixes` -- a delegated TLD such as ".sky" or the
router's ".fritz.box" is never assumed.

Not part of the pytest suite -- run directly:
`venv/Scripts/python.exe tests/test_telemetry_local_suffixes.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from config import CONFIG, DEFAULT_CONFIG  # noqa: E402
from utils import is_local_name, is_telemetry_domain  # noqa: E402


def configure(value):
    with CONFIG._lock:
        CONFIG._config["local_domain_suffixes"] = value


check("the shipped default lists no network-specific suffix", DEFAULT_CONFIG.get("local_domain_suffixes") == [])

configure([])
for name in ("printer.local", "1.0.168.192.in-addr.arpa", "router.home.arpa", "svc.internal", "nas.lan", "tv.home"):
    check(f"built in, no config: {name} is a local name and telemetry", is_local_name(name) and is_telemetry_domain(name))
check("built in: a trailing dot and upper case do not matter", is_local_name("Printer.LOCAL."))

check("no config: a .sky name is NOT assumed local (it is a delegated public TLD)",
      not is_local_name("evil.sky") and not is_telemetry_domain("evil.sky"))
check("no config: a .fritz.box name is NOT assumed local (vendor default, not a standard)",
      not is_local_name("nas.fritz.box"))
check("a public name is not local", not is_local_name("example.com") and not is_telemetry_domain("unknown-host.example"))
check("a name merely containing a local suffix is not local", not is_local_name("local.example.com")
      and not is_local_name("mylan.example.org"))
check("empty and None are not local", not is_local_name("") and not is_local_name(None) and not is_telemetry_domain(""))

configure(["sky", ".Fritz.Box."])
check("configured suffixes apply (case, dots, leading dot normalised)",
      is_local_name("tv.sky") and is_telemetry_domain("tv.sky") and is_local_name("nas.fritz.box"))
check("configured: the bare suffix itself is not a host name under it", not is_local_name("sky"))
check("configured: the built-ins still apply", is_local_name("printer.local"))
check("configured suffix does not widen to lookalikes", not is_local_name("tv.notsky") and not is_local_name("sky.com"))

configure(["lan", "", None, 5])
check("junk, empty and built-in-duplicate entries are ignored", is_local_name("nas.lan") and not is_local_name("x.5"))
configure("sky")
check("a non-list setting is ignored, built-ins keep working", is_local_name("a.local") and not is_local_name("a.sky"))

configure(["sky"])
check("a live config change applies on the next call", is_local_name("tv.sky"))
configure([])
check("... and removing it applies too", not is_local_name("tv.sky"))

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All local-suffix checks PASSED.")
