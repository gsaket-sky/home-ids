"""
Domain popularity learned on this network (2026-10-01), replacing the Tranco list (CC BY-NC input, cannot ship).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from intelligence.local_popularity import LocalPopularity, MIN_DAYS, MIN_DEVICES  # noqa: E402
from utils import etld1  # noqa: E402

DAY = 86400.0
T0 = 1_790_000_000.0


def _lp(tmp_path, now=None):
    clock = {"t": now or T0 + 30 * DAY}
    lp = LocalPopularity(tmp_path / "pop.db", etld1_fn=etld1, now_fn=lambda: clock["t"])
    return lp, clock


def _use(lp, name, devices, days, start=T0 + 20 * DAY):
    for d in range(days):
        for dev in range(devices):
            lp.observe(f"dev{dev}", name, start + d * DAY + dev)


def test_established_needs_enough_devices_and_days(tmp_path):
    lp, _ = _lp(tmp_path)
    _use(lp, "www.netflix.com", MIN_DEVICES, MIN_DAYS)
    _use(lp, "rare.example.org", MIN_DEVICES - 1, MIN_DAYS + 3)     # too few devices
    _use(lp, "new.example.net", MIN_DEVICES + 2, MIN_DAYS - 1)      # too few days
    lp.flush()
    assert lp.is_established("www.netflix.com") and lp.is_established("netflix.com")
    assert not lp.is_established("rare.example.org")
    assert not lp.is_established("new.example.net")
    assert not lp.is_established("other.netflix.com")              # exact names only


def test_rank_orders_by_devices_then_days_and_falls_back_to_the_base_domain(tmp_path):
    lp, _ = _lp(tmp_path)
    _use(lp, "a.big.com", 6, 9)
    _use(lp, "b.small.com", 2, 9)
    lp.flush()
    assert 0 < lp.get_rank("a.big.com") < lp.get_rank("b.small.com")
    assert lp.get_rank("never-seen.big.com") == lp.get_rank("big.com") > 0      # base-domain fallback
    assert lp.get_rank("unknown.example") == 0


def test_survives_restart_and_ignores_local_names(tmp_path):
    lp, _ = _lp(tmp_path)
    _use(lp, "cdn.example.com", MIN_DEVICES, MIN_DAYS)
    lp.observe("dev0", "printer.local", T0)
    lp.observe("dev0", "1.168.192.in-addr.arpa", T0)
    lp.observe("dev0", "fritz.box", T0)
    lp.flush()
    lp2, _ = _lp(tmp_path)
    assert lp2.is_established("cdn.example.com")
    assert lp2.get_rank("printer.local") == 0 and lp2.get_rank("1.168.192.in-addr.arpa") == 0


def test_old_days_age_out(tmp_path):
    lp, clock = _lp(tmp_path)
    _use(lp, "old.example.com", MIN_DEVICES, MIN_DAYS, start=T0)
    lp.flush()
    assert lp.is_established("old.example.com")
    clock["t"] = T0 + 120 * DAY                                     # beyond the 60-day window
    lp.flush()
    assert not lp.is_established("old.example.com")


# --- ThreatIntel: the anti-poisoning rule -------------------------------------------------------------------------

def _ti(tmp_path, lp):
    from intelligence.threat_intel import ThreatIntel
    ti = ThreatIntel(cache_dir=str(tmp_path / "ti"), et_open_enabled=False)
    ti.local_popularity = lp
    return ti


def test_learned_allowlist_hides_weak_and_suffix_hits_but_never_a_strong_direct_one(tmp_path):
    lp, _ = _lp(tmp_path)
    for name in ("api.ipify.org", "c2.evil-but-popular.com", "files.shared-host.net"):
        _use(lp, name, MIN_DEVICES, MIN_DAYS)
    lp.flush()
    ti = _ti(tmp_path, lp)
    ti._bad_domains["api.ipify.org"] = {"source": "test", "confidence": 0.4}            # weak, policy-style
    ti._bad_domains["c2.evil-but-popular.com"] = {"source": "test", "confidence": 0.95}  # strong, direct
    ti._bad_domains["shared-host.net"] = {"source": "test", "confidence": 0.9}           # parent of a popular name
    assert ti.is_allowlisted("api.ipify.org") and ti.lookup_domain("api.ipify.org") is None
    assert not ti.is_allowlisted("c2.evil-but-popular.com")
    assert ti.lookup_domain("c2.evil-but-popular.com")["confidence"] == 0.95
    assert ti.lookup_domain("files.shared-host.net") is None                             # suffix match shielded
    assert ti.lookup_domain("other.shared-host.net")["confidence"] == 0.9                # not learned: still hit


def test_rank_feature_uses_the_learned_list_when_tranco_is_off(tmp_path):
    lp, _ = _lp(tmp_path)
    _use(lp, "www.example.com", 4, 8)
    lp.flush()
    ti = _ti(tmp_path, lp)
    assert ti.tranco_enabled is False
    assert ti.get_tranco_rank("www.example.com") == lp.get_rank("www.example.com") > 0
    ti.local_popularity = None
    assert ti.get_tranco_rank("www.example.com") == 0


def test_identity_feeds_the_learner_but_not_with_blocked_queries():
    from core import identity
    assert 1 in identity._PIHOLE_BLOCKED_STATUSES and 2 not in identity._PIHOLE_BLOCKED_STATUSES
    src = Path(identity.__file__).read_text(encoding="utf-8")
    assert 'row.get("status") not in _PIHOLE_BLOCKED_STATUSES' in src and "popularity.observe(" in src
