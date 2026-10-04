"""
Learning-adoption ledger (intelligence/local_popularity.py): a name that only devices still in their own learning
period ever used is not "normal" for a baselined device that picks it up. Covers the infected-at-onboarding gap
(MASTER_TODO W-04 "Known blind spot"): malware present when a device joins, or when the system is first switched on,
must not become "normal here" for every other device just by being used for three days.

What it deliberately does NOT do: count a device's own learning-period names against that same device. From local
history alone a camera infected since day one cannot be told from a clean camera polling its vendor since day one.
"""
import sqlite3
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from intelligence.local_popularity import LocalPopularity  # noqa: E402
from utils import etld1  # noqa: E402

DAY = 86400.0
T0 = 1_800_000_000.0


class _Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


def _network(tmp_path, learning):
    clock = _Clock()
    pop = LocalPopularity(tmp_path / "popularity.db", etld1_fn=etld1, now_fn=clock,
                          learning_fn=lambda d: learning.get(d, False))
    return pop, clock


def _use(pop, clock, day, device, *names):
    clock.now = T0 + day * DAY + 3600
    for n in names:
        pop.observe(device, n, clock.now)
    pop.flush()


def test_install_time_name_is_unproven_for_a_baselined_device(tmp_path):
    learning = {"cam": True, "laptop": True}
    pop, clock = _network(tmp_path, learning)
    for day in range(7):                                   # first install: everyone is learning
        _use(pop, clock, day, "cam", "c2-example.net")
        _use(pop, clock, day, "laptop", "news-example.org")
    learning["laptop"] = False                             # the laptop's normal behaviour is now known
    _use(pop, clock, 8, "laptop", "c2-example.net")        # ...and it starts using the camera's name
    clock.now += 120                                       # past the learning-status memo
    assert pop.is_preexisting("c2-example.net", device_id="laptop") is False
    assert pop.is_preexisting("c2-example.net") is True    # network-level answer unchanged


def test_a_devices_own_learning_names_stay_its_own(tmp_path):
    learning = {"cam": True}
    pop, clock = _network(tmp_path, learning)
    for day in range(7):
        _use(pop, clock, day, "cam", "vendor-cloud.example")
    learning["cam"] = False
    _use(pop, clock, 8, "cam", "vendor-cloud.example")
    clock.now += 120
    assert pop.is_preexisting("vendor-cloud.example", device_id="cam") is True


def test_a_baselined_adopter_vouches_for_the_name(tmp_path):
    learning = {"cam": True, "phone": False, "laptop": False}
    pop, clock = _network(tmp_path, learning)
    for day in range(7):
        _use(pop, clock, day, "cam", "vendor-cloud.example")
        _use(pop, clock, day, "phone", "vendor-cloud.example")   # baselined device, independent use
    _use(pop, clock, 8, "laptop", "vendor-cloud.example")
    assert pop.is_preexisting("vendor-cloud.example", device_id="laptop") is True


def test_established_names_are_always_normal(tmp_path):
    learning = {"a": True, "b": True, "c": True, "laptop": False}
    pop, clock = _network(tmp_path, learning)
    for day in range(8):
        for dev in ("a", "b", "c"):
            _use(pop, clock, day, dev, "big-site.example")
    assert pop.is_established("big-site.example")
    assert pop.is_preexisting("big-site.example", device_id="laptop") is True


def test_adoption_status_is_fixed_at_first_use(tmp_path):
    learning = {"cam": True}
    pop, clock = _network(tmp_path, learning)
    _use(pop, clock, 0, "cam", "c2-example.net")
    learning["cam"] = False
    clock.now += 120
    for day in range(1, 4):
        _use(pop, clock, day, "cam", "c2-example.net")
    with sqlite3.connect(str(tmp_path / "popularity.db")) as db:
        assert db.execute("SELECT learning FROM names WHERE name='c2-example.net'").fetchone()[0] == "cam"


def test_old_database_is_migrated_and_keeps_old_behaviour(tmp_path):
    db_path = tmp_path / "popularity.db"
    with sqlite3.connect(str(db_path)) as db:
        db.execute("CREATE TABLE names (name TEXT PRIMARY KEY, devices TEXT NOT NULL, days TEXT NOT NULL, "
                   "first_seen REAL NOT NULL, last_seen REAL NOT NULL)")
        days = ",".join(str(int(T0 // DAY) - d) for d in range(8))
        db.execute("INSERT INTO names VALUES ('legacy.example', 'cam', ?, ?, ?)", (days, T0 - 5 * DAY, T0))
    clock = _Clock()
    pop = LocalPopularity(db_path, etld1_fn=etld1, now_fn=clock, learning_fn=lambda d: False)
    with sqlite3.connect(str(db_path)) as db:
        assert "learning" in {r[1] for r in db.execute("PRAGMA table_info(names)")}
    assert pop.is_preexisting("legacy.example", device_id="laptop") is True


def test_without_a_learning_source_nothing_changes(tmp_path):
    clock = _Clock()
    pop = LocalPopularity(tmp_path / "popularity.db", etld1_fn=etld1, now_fn=clock)
    for day in range(7):
        _use(pop, clock, day, "cam", "c2-example.net")
    _use(pop, clock, 8, "laptop", "c2-example.net")
    assert pop.is_preexisting("c2-example.net", device_id="laptop") is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
