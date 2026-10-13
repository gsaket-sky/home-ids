"""mitigation/nftables_fw.py: the containment firewall (T2 box-drop, T3 in-path). Driven by a fake nft runner so the
emitted rules are asserted without root/kernel; proves it no-ops cleanly when nft is absent and manages per-device MACs
as set elements in a dedicated table."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mitigation.nftables_fw import NftContainment, TABLE  # noqa: E402
from mitigation.containment import TARPIT_MODE, BLOCK_INTERNET_MODE  # noqa: E402

M1, M2 = "aa:bb:cc:00:00:01", "AA:BB:CC:00:00:02"


class FakeNft:
    """Records every nft invocation; `table_exists` flips to True once the setup script runs."""
    def __init__(self, version_ok=True):
        self.calls = []
        self.table_exists = False
        self.version_ok = version_ok

    def __call__(self, args):
        self.calls.append(args)
        if args[:1] == ["--version"]:
            return (0, "nftables v1.0") if self.version_ok else (1, "not found")
        if args[:3] == ["list", "table", "inet", TABLE][:3] and "table" in args:
            return (0, "") if self.table_exists else (1, "No such file or directory")
        if args[:1] == ["-f"]:
            script = args[-1]
            if f"add table inet {TABLE}" in script:
                self.table_exists = True
            return (0, "")
        if args[:2] == ["delete", "table"]:
            self.table_exists = False
            return (0, "")
        return (0, "")

    def scripts(self):
        return [a[-1] for a in self.calls if a[:1] == ["-f"]]


def test_box_drop_creates_the_table_once_then_adds_elements():
    nft = FakeNft()
    fw = NftContainment(run=nft, uplink="eno1")
    assert fw.box_drop([M1, M2]) is True
    scripts = nft.scripts()
    setup = scripts[0]
    assert f"add table inet {TABLE}" in setup
    assert "ether saddr @box_blocked drop" in setup                      # input hook
    assert 'ether saddr @inpath_internet oifname "eno1" drop' in setup   # block-internet in-path uses the uplink
    add = scripts[1]
    assert "add element inet homeids_containment box_blocked { aa:bb:cc:00:00:01 }" in add
    assert "add element inet homeids_containment box_blocked { aa:bb:cc:00:00:02 }" in add   # normalised lower-case
    # a SECOND device does not recreate the table (setup ran once)
    nft.calls.clear()
    fw.box_drop(["aa:bb:cc:00:00:03"])
    assert not any(f"add table inet {TABLE}" in s for s in nft.scripts())


def test_box_undrop_deletes_elements():
    nft = FakeNft()
    fw = NftContainment(run=nft)
    fw.box_drop([M1])
    nft.calls.clear()
    fw.box_undrop([M1])
    assert any("delete element inet homeids_containment box_blocked { aa:bb:cc:00:00:01 }" in s for s in nft.scripts())


def test_inpath_tarpit_vs_block_internet_use_different_sets():
    nft = FakeNft()
    fw = NftContainment(run=nft)
    fw.inpath_drop([M1], TARPIT_MODE)
    fw.inpath_drop([M2], BLOCK_INTERNET_MODE)
    joined = "\n".join(nft.scripts())
    assert "inpath_blocked { aa:bb:cc:00:00:01 }" in joined
    assert "inpath_internet { aa:bb:cc:00:00:02 }" in joined


def test_no_op_when_nft_unavailable():
    nft = FakeNft(version_ok=False)
    fw = NftContainment(run=nft)
    assert fw.available() is False
    assert fw.box_drop([M1]) is False
    assert not nft.scripts()          # never tried to write rules


def test_static_forward_rules_cover_both_directions_for_tarpit():
    nft = FakeNft()
    fw = NftContainment(run=nft)
    fw.ensure()
    setup = nft.scripts()[0]
    assert "forward ether saddr @inpath_blocked drop" in setup
    assert "forward ether daddr @inpath_blocked drop" in setup


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
