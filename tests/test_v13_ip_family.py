"""
Standalone runtime test for core/pipeline.py's _ip_family() -- the alert-payload
IPv6 display-labeling fix (v13 full-architecture plan, Phase 3). Lives in
core/pipeline.py itself (an alert-payload construction concern, not identity
resolution), tracked as v13 work per the same investigation that found it.

Imports core.pipeline (real v-current code, real deps) -- run via the venv python:
`.venv/Scripts/python.exe tests/test_v13_ip_family.py`
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


from core.pipeline import _ip_family  # noqa: E402

check("a real IPv4 address is labeled 'ipv4'", _ip_family("192.168.77.1") == "ipv4")
check("an IPv6 link-local address (the real fe80:: incident from this session) is "
      "labeled 'ipv6-link-local', not left as an unexplained raw literal",
      _ip_family("fe80::725a:fff:feba:5caa") == "ipv6-link-local")
check("a real IPv6 global/ULA address is labeled 'ipv6-global'",
      _ip_family("2001:db8::1") == "ipv6-global")
check("an unparseable string fails safe to 'unknown' rather than raising",
      _ip_family("not-an-ip-at-all") == "unknown")
check("an empty string fails safe to 'unknown'", _ip_family("") == "unknown")


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 _ip_family() checks PASSED.")
