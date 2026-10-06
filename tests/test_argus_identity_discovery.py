"""
Standalone runtime test for argus/identity/discovery.py -- Phase 10 of the
16-parameter autonomy-completion effort (zero-site bootstrap B: auto-discovery).

No real packet capture or network I/O in this file -- psutil.net_if_addrs(),
subprocess.run() (the 'ip route' call), and the neighbour-table lookup are all mocked.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_identity_discovery.py`
"""
import socket
import sys
from collections import namedtuple
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import argus.identity.discovery as discovery  # noqa: E402

_SNICADDR = namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])


class _FakeAFLink:
    """Stand-in for psutil.AF_LINK -- a distinct sentinel from socket.AF_INET,
    exactly what discovery.py's own family-comparison code checks against."""


_AF_LINK = _FakeAFLink()


def _mock_net_if_addrs(mapping):
    return lambda: mapping


def _mock_run(stdout, returncode=0):
    class _Result:
        pass
    r = _Result()
    r.stdout = stdout
    r.returncode = returncode
    return lambda *a, **kw: r


# --- A. single-NIC host: straightforward this_host + gateway discovery ---

_orig_net_if_addrs = discovery.psutil.net_if_addrs
_orig_af_link = discovery.psutil.AF_LINK
_orig_run = discovery.subprocess.run
# The gateway is read from /proc/net/route first (the host's real one on a Linux CI runner); this test drives the
# `ip route` fallback through its subprocess mock, so the /proc reader reports nothing here.
_orig_proc_route = discovery._gateway_from_proc_route
discovery._gateway_from_proc_route = lambda *a, **k: None

discovery.psutil.net_if_addrs = _mock_net_if_addrs({
    "lo": [_SNICADDR(socket.AF_INET, "127.0.0.1", "255.0.0.0", None, None)],
    "eth0": [
        _SNICADDR(socket.AF_INET, "192.168.1.50", "255.255.255.0", None, None),
        _SNICADDR(_AF_LINK, "aa:bb:cc:dd:ee:01", None, None, None),
    ],
})
discovery.psutil.AF_LINK = _AF_LINK
discovery.subprocess.run = _mock_run("default via 192.168.1.1 dev eth0 \n")


def _mock_arp_resolve(ip, timeout=2.0):
    return {"192.168.1.1": "11:22:33:44:55:66"}.get(ip)


_orig_arp_resolve = discovery._arp_resolve_mac
discovery._arp_resolve_mac = _mock_arp_resolve

result_a = discovery.discover(previous_trust_anchors=[])
by_role_a = {a["role"]: a for a in result_a}
check("A: a single-NIC host discovers exactly a 'this_host' and a 'gateway' anchor",
      set(by_role_a.keys()) == {"this_host", "gateway"}, f"got {result_a}")
check("A: this_host's ip/mac come from the real (mocked) interface table",
      by_role_a["this_host"]["ip"] == "192.168.1.50" and by_role_a["this_host"]["mac"] == "aa:bb:cc:dd:ee:01")
check("A: gateway's ip comes from the real (mocked) default route",
      by_role_a["gateway"]["ip"] == "192.168.1.1")
check("A: gateway's mac comes from the real (mocked) ARP resolution",
      by_role_a["gateway"]["mac"] == "11:22:33:44:55:66")

# The output is directly consumable by load_trust_anchors() with zero adaptation.
from argus.config.trust_anchors import load_trust_anchors  # noqa: E402
loaded_a = load_trust_anchors(result_a)
check("A: discover()'s output is directly consumable by load_trust_anchors() -- "
      "the same shape config.yaml's hand-edited network.trust_anchors already uses",
      set(loaded_a.keys()) == {"this_host", "gateway"})


# --- B. multi-NIC host: the correct LAN-facing interface is selected ---

discovery.psutil.net_if_addrs = _mock_net_if_addrs({
    "lo": [_SNICADDR(socket.AF_INET, "127.0.0.1", "255.0.0.0", None, None)],
    "docker0": [
        _SNICADDR(socket.AF_INET, "172.17.0.1", "255.255.0.0", None, None),
        _SNICADDR(_AF_LINK, "02:42:aa:bb:cc:dd", None, None, None),
    ],
    "eth0": [
        _SNICADDR(socket.AF_INET, "192.168.1.50", "255.255.255.0", None, None),
        _SNICADDR(_AF_LINK, "aa:bb:cc:dd:ee:01", None, None, None),
    ],
})
result_b = discovery.discover(previous_trust_anchors=[])
by_role_b = {a["role"]: a for a in result_b}
check("B: with a Docker bridge interface ALSO present, the interface actually on "
      "the gateway's own subnet (eth0) is selected as this_host, not docker0 "
      "(whichever psutil happened to enumerate first)",
      by_role_b["this_host"]["ip"] == "192.168.1.50", f"got {by_role_b.get('this_host')}")


# --- C. no default gateway found: still returns a this_host anchor, no crash ---

discovery.subprocess.run = _mock_run("")
result_c = discovery.discover(previous_trust_anchors=[])
by_role_c = {a["role"]: a for a in result_c}
check("C: no default route found -- still discovers this_host, no 'gateway' key at all "
      "(not a crash, not a fabricated placeholder)",
      "this_host" in by_role_c and "gateway" not in by_role_c, f"got {result_c}")


# --- D. ARP resolution fails: gateway anchor still emitted, with mac=None ---

discovery.subprocess.run = _mock_run("default via 192.168.1.1 dev eth0 \n")
discovery._arp_resolve_mac = lambda ip, timeout=2.0: None
result_d = discovery.discover(previous_trust_anchors=[])
by_role_d = {a["role"]: a for a in result_d}
check("D: a failed ARP resolution still emits the gateway anchor (ip known from "
      "the routing table regardless), just with mac=None -- degrades gracefully, "
      "doesn't drop the whole anchor",
      by_role_d.get("gateway", {}).get("ip") == "192.168.1.1"
      and by_role_d.get("gateway", {}).get("mac") is None)


# --- E. no interfaces at all: returns an empty list, never raises ---

discovery.psutil.net_if_addrs = _mock_net_if_addrs({})
discovery.subprocess.run = _mock_run("")
result_e = discovery.discover(previous_trust_anchors=[])
check("E: completely empty interface table returns an empty list, not a crash",
      result_e == [], f"got {result_e}")


# --- F. _log_diff drift detection (called internally by discover(), tested directly) ---

import logging  # noqa: E402


class _CapturingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


handler = _CapturingHandler()
discovery.LOGGER.addHandler(handler)
discovery.LOGGER.setLevel(logging.DEBUG)

discovery._log_diff(
    previous=[{"role": "gateway", "ip": "192.168.1.1"}],
    current=[{"role": "gateway", "ip": "192.168.1.1"}],
)
check("F: identical previous/current anchors log at INFO with no drift warning",
      handler.records[-1].levelno == logging.INFO and "no drift" in handler.records[-1].getMessage())

discovery._log_diff(
    previous=[{"role": "gateway", "ip": "192.168.1.1"}],
    current=[{"role": "gateway", "ip": "192.168.1.99"}],
)
check("F: a genuinely changed gateway ip logs a WARNING-level drift alert -- "
      "real, visible drift detection, not silent",
      handler.records[-1].levelno == logging.WARNING and "drift detected" in handler.records[-1].getMessage())

discovery.LOGGER.removeHandler(handler)

# --- restore all mocked module state ---
discovery.psutil.net_if_addrs = _orig_net_if_addrs
discovery.psutil.AF_LINK = _orig_af_link
discovery.subprocess.run = _orig_run
discovery._gateway_from_proc_route = _orig_proc_route
discovery._arp_resolve_mac = _orig_arp_resolve


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All argus/identity/discovery.py checks PASSED.")
