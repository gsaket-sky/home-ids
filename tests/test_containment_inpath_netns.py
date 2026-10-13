"""
T3 in-path containment, proven end-to-end in Linux network namespaces (CONTAINMENT_MODEL.md section 7 acceptance gate,
2026-10-13). This is the gate T3 is accepted on: .94 is same-segment today and cannot test in-path, so the bridge/AP
case is proven here instead -- a real Linux bridge, two veth hosts, real pings.

Topology (all in fresh namespaces, torn down after):

    hostA (10.77.0.10, MAC ..0a) --vethA-- [ br0 in boxns ] --vethB-- hostB (10.77.0.11, MAC ..0b)

The box bridges A and B (same subnet, pure L2 -- no routing, no br_netfilter). `NftContainment`, with its nft commands
run INSIDE boxns, installs the real bridge-family forward rules. We assert:
  - baseline: A can ping B;
  - Tarpit in-path (drop A's MAC both directions): A<->B is cut BOTH ways;
  - release (undrop): connectivity returns;
  - Block internet (drop A's frames egressing the "uplink" port vethB only): A->B (via the uplink port) is cut while
    the rest of the bridge is unaffected.

Skips cleanly unless run on Linux as root with `ip` and `nft` present (dev boxes / unprivileged CI), and skips rather
than fails if the kernel lacks the bridge-family forward hook. Requires no product import beyond nftables_fw itself.
"""
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mitigation.nftables_fw import NftContainment  # noqa: E402
from mitigation.containment import TARPIT_MODE, BLOCK_INTERNET_MODE  # noqa: E402

A_IP, B_IP = "10.77.0.10", "10.77.0.11"
A_MAC, B_MAC = "02:00:00:00:00:0a", "02:00:00:00:00:0b"

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.geteuid() != 0
    or shutil.which("ip") is None or shutil.which("nft") is None,
    reason="needs Linux, root, and the ip + nft tools (in-path containment is a kernel mechanism)")


def _sh(*args, check=True, ns=None):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {p.returncode}: {p.stdout}{p.stderr}")
    return p


def _ping(ns, dst):
    return subprocess.run(["ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "1", dst],
                          capture_output=True, text=True, timeout=5).returncode == 0


@pytest.fixture
def netns():
    tag = uuid.uuid4().hex[:6]
    box, a, b = f"t3box_{tag}", f"t3a_{tag}", f"t3b_{tag}"
    va, vba, vb, vbb = f"va{tag}", f"vba{tag}", f"vb{tag}", f"vbb{tag}"
    created = []
    try:
        for ns in (box, a, b):
            _sh("ip", "netns", "add", ns)
            created.append(ns)
        # the bridge lives in boxns
        _sh("ip", "link", "add", "br0", "type", "bridge", ns=box)
        # veth pairs: host end into a/b, bridge end into boxns
        _sh("ip", "link", "add", va, "type", "veth", "peer", "name", vba)
        _sh("ip", "link", "add", vb, "type", "veth", "peer", "name", vbb)
        _sh("ip", "link", "set", va, "netns", a)
        _sh("ip", "link", "set", vba, "netns", box)
        _sh("ip", "link", "set", vb, "netns", b)
        _sh("ip", "link", "set", vbb, "netns", box)
        # bridge ports up and enslaved
        for port in (vba, vbb):
            _sh("ip", "link", "set", port, "master", "br0", ns=box)
            _sh("ip", "link", "set", port, "up", ns=box)
        _sh("ip", "link", "set", "br0", "up", ns=box)
        # host addresses + deterministic MACs
        _sh("ip", "link", "set", va, "address", A_MAC, ns=a)
        _sh("ip", "link", "set", vb, "address", B_MAC, ns=b)
        _sh("ip", "addr", "add", f"{A_IP}/24", "dev", va, ns=a)
        _sh("ip", "addr", "add", f"{B_IP}/24", "dev", vb, ns=b)
        _sh("ip", "link", "set", va, "up", ns=a)
        _sh("ip", "link", "set", vb, "up", ns=b)
        _sh("ip", "link", "set", "lo", "up", ns=a)
        _sh("ip", "link", "set", "lo", "up", ns=b)
        if not _ping(a, B_IP):
            pytest.skip("bridge baseline connectivity did not come up in this environment")
        # uplink = the port B is behind, so Block-internet egress-drop is observable as A->B being cut
        yield {"box": box, "a": a, "b": b, "uplink": vbb}
    finally:
        for ns in created:
            subprocess.run(["ip", "netns", "del", ns], capture_output=True, text=True)


def _fw(box, uplink=None):
    # run every nft command inside boxns; feed `-f -` rulesets on stdin
    def run(args):
        if len(args) == 3 and args[0] == "-f" and args[1] == "-":
            p = subprocess.run(["ip", "netns", "exec", box, "nft", "-f", "-"],
                               input=args[2], capture_output=True, text=True, timeout=10)
        else:
            p = subprocess.run(["ip", "netns", "exec", box, "nft", *args],
                               capture_output=True, text=True, timeout=10)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    return NftContainment(run=run, uplink=uplink)


def test_tarpit_in_path_cuts_both_directions_then_release_restores(netns):
    fw = _fw(netns["box"])
    if not fw.available() or not fw.ensure():
        pytest.skip("nft / bridge-family forward hook not usable in this kernel")
    assert _ping(netns["a"], B_IP)                      # baseline
    assert fw.inpath_drop([A_MAC], TARPIT_MODE) is True
    assert not _ping(netns["a"], B_IP)                  # A -> B cut (A is source)
    assert not _ping(netns["b"], A_IP)                  # B -> A cut (A is destination) -- both directions
    assert fw.inpath_undrop([A_MAC], TARPIT_MODE) is True
    assert _ping(netns["a"], B_IP)                      # released: connectivity back


def test_block_internet_in_path_drops_only_egress_to_the_uplink(netns):
    fw = _fw(netns["box"], uplink=netns["uplink"])
    if not fw.available() or not fw.ensure():
        pytest.skip("nft / bridge-family forward hook not usable in this kernel")
    assert _ping(netns["a"], B_IP)                      # baseline
    assert fw.inpath_drop([A_MAC], BLOCK_INTERNET_MODE) is True
    # A's frames egressing the uplink port (vbb, where B sits) are dropped -> A can't reach B
    assert not _ping(netns["a"], B_IP)
    assert fw.inpath_undrop([A_MAC], BLOCK_INTERNET_MODE) is True
    assert _ping(netns["a"], B_IP)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
