"""mitigation/nftables_fw.py: the containment firewall. Box-drop (T2) lives in an `inet` table's input hook; in-path
(T3) lives in a `bridge` table's forward hook, where bridged frames keep their MACs both directions. Driven by a fake
nft runner so the emitted rules are asserted without root/kernel; proves it no-ops cleanly when nft is absent and
manages per-device MACs as set elements."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mitigation.nftables_fw import NftContainment, TABLE, BR_TABLE  # noqa: E402
from mitigation.containment import TARPIT_MODE, BLOCK_INTERNET_MODE  # noqa: E402

M1, M2 = "aa:bb:cc:00:00:01", "AA:BB:CC:00:00:02"


class FakeNft:
    """Records every nft invocation; a table 'exists' once its setup script runs."""
    def __init__(self, version_ok=True):
        self.calls = []
        self.exists = set()
        self.version_ok = version_ok

    def __call__(self, args):
        self.calls.append(args)
        if args[:1] == ["--version"]:
            return (0, "nftables v1.0") if self.version_ok else (1, "not found")
        if args[:2] == ["list", "table"]:
            fam, name = args[2], args[3]
            return (0, "") if (fam, name) in self.exists else (1, "No such file or directory")
        if args[:1] == ["-f"]:
            script = args[-1]
            if f"add table inet {TABLE}" in script:
                self.exists.add(("inet", TABLE))
            if f"add table bridge {BR_TABLE}" in script:
                self.exists.add(("bridge", BR_TABLE))
            return (0, "")
        if args[:2] == ["delete", "table"]:
            self.exists.discard((args[2], args[3]))
            return (0, "")
        return (0, "")

    def scripts(self):
        return [a[-1] for a in self.calls if a[:1] == ["-f"]]


def test_box_drop_is_an_inet_input_rule_created_once():
    nft = FakeNft()
    fw = NftContainment(run=nft, uplink="eno1")
    assert fw.box_drop([M1, M2]) is True
    scripts = nft.scripts()
    setup = scripts[0]
    assert f"add table inet {TABLE}" in setup
    assert "type filter hook input" in setup
    assert "ether saddr @box_blocked drop" in setup
    add = scripts[1]
    assert "add element inet homeids_containment box_blocked { aa:bb:cc:00:00:01 }" in add
    assert "add element inet homeids_containment box_blocked { aa:bb:cc:00:00:02 }" in add   # normalised lower-case
    nft.calls.clear()
    fw.box_drop(["aa:bb:cc:00:00:03"])                      # a second device does NOT recreate the table
    assert not any(f"add table inet {TABLE}" in s for s in nft.scripts())


def test_box_undrop_deletes_elements():
    nft = FakeNft()
    fw = NftContainment(run=nft)
    fw.box_drop([M1])
    nft.calls.clear()
    fw.box_undrop([M1])
    assert any("delete element inet homeids_containment box_blocked { aa:bb:cc:00:00:01 }" in s for s in nft.scripts())


def test_in_path_is_a_bridge_forward_table_both_directions_for_tarpit():
    nft = FakeNft()
    fw = NftContainment(run=nft, uplink="eth0")
    fw.inpath_drop([M1], TARPIT_MODE)
    setup = next(s for s in nft.scripts() if f"add table bridge {BR_TABLE}" in s)
    assert "type filter hook forward" in setup
    assert "forward ether saddr @inpath_blocked drop" in setup
    assert "forward ether daddr @inpath_blocked drop" in setup        # both directions
    assert 'forward ether saddr @inpath_internet oifname "eth0" drop' in setup   # block-internet egress only
    assert any("add element bridge homeids_containment_br inpath_blocked { aa:bb:cc:00:00:01 }" in s
               for s in nft.scripts())


def test_inpath_tarpit_vs_block_internet_use_different_bridge_sets():
    nft = FakeNft()
    fw = NftContainment(run=nft, uplink="eth0")
    fw.inpath_drop([M1], TARPIT_MODE)
    fw.inpath_drop([M2], BLOCK_INTERNET_MODE)
    joined = "\n".join(nft.scripts())
    assert "inpath_blocked { aa:bb:cc:00:00:01 }" in joined
    assert "inpath_internet { aa:bb:cc:00:00:02 }" in joined


def test_box_and_in_path_are_separate_families():
    nft = FakeNft()
    fw = NftContainment(run=nft, uplink="eth0")
    fw.box_drop([M1])
    fw.inpath_drop([M1], TARPIT_MODE)
    assert ("inet", TABLE) in nft.exists and ("bridge", BR_TABLE) in nft.exists


def test_no_op_when_nft_unavailable():
    nft = FakeNft(version_ok=False)
    fw = NftContainment(run=nft)
    assert fw.available() is False
    assert fw.box_drop([M1]) is False
    assert fw.inpath_drop([M1], TARPIT_MODE) is False
    assert not nft.scripts()          # never tried to write rules


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
