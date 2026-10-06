"""
Small items from the runtime trace run 2 (finding 4.7) and the trust-cache failure counter (MASTER_TODO M3).

Covers: etld1() still returns "" for IP-shaped input (IPv4, IPv6, trailing dot) and the right base for names, without
raising for ordinary ones; l2_raw.attach_ns_filter no longer fails on socket.__slots__; the ET state file is written
group/other-readable (the web UI runs as another uid); a failing trust-cache read is counted.

Run directly: `venv/Scripts/python.exe tests/test_small_trace_fixes.py`
"""
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from utils import etld1  # noqa: E402

check("etld1: names", etld1("mail.google.com") == "google.com" and etld1("a.b.example.co.uk") == "example.co.uk")
check("etld1: IPv4, IPv6 and a trailing dot give no base",
      etld1("149.154.166.110") == "" and etld1("2001:db8::1") == "" and etld1("fe80::1") == "" and etld1("10.0.0.1.") == "")
check("etld1: junk and a single label give no base", etld1("unknown") == "" and etld1("") == "" and etld1(None) == "")
check("etld1: a numeric-looking name that is not an address does not raise", etld1("123.456.789.012") in ("", "789.012"))

# attach_ns_filter: AttributeError on the socket must not turn a successful attach into False
from mitigation import l2_raw  # noqa: E402


class _Sock:
    __slots__ = ("calls",)

    def __init__(self):
        self.calls = []

    def setsockopt(self, *a):
        self.calls.append(a)


s = _Sock()
if sys.platform.startswith("linux"):   # the BPF program packing is Linux-only (native 8-byte "L")
    check("attach_ns_filter reports success on a socket without a writable __dict__ (the kernel copies the program)",
          l2_raw.attach_ns_filter(s) is True and len(s.calls) == 1)
else:
    check("attach_ns_filter no longer assigns an attribute to the socket", "_ns_filter_buf = " not in inspect.getsource(l2_raw.attach_ns_filter))

# ET state file permissions (POSIX only)
from intelligence.et_open_fetch import ETOpenUpdater  # noqa: E402
src = inspect.getsource(ETOpenUpdater._save_state)
check("the ET state file is made readable by the web UI before it replaces the old one", "0o644" in src)

# trust-cache failure counter
from metrics import fp_trust_cache_read_errors_total as ctr  # noqa: E402
from intelligence import threat_intel  # noqa: E402
check("the counter is incremented where the trust-cache read failure is caught",
      "fp_trust_cache_read_errors_total.inc()" in inspect.getsource(threat_intel.ThreatIntel.is_allowlisted))
before = ctr._value.get()
ctr.inc()
check("the counter is a working Prometheus counter", ctr._value.get() == before + 1)

if FAILURES:
    print(f"\n{len(FAILURES)} check(s) FAILED")
    sys.exit(1)
print("\nAll small trace-fix checks PASSED.")
