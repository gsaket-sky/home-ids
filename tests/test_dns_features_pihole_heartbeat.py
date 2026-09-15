"""
Tests for PiHoleCollector.poll()'s health heartbeat write (src/extractors/
dns_features.py), added 2026-09-15 per the console/health audit -- Pi-hole's
existing health check only ever verified reachability/auth, never whether DNS
queries were actually being polled and processed (the same class of gap fixed
for Suricata the same session). Uses a REAL temp SQLite file shaped like
Pi-hole's own FTL database (PiHoleCollector opens it read-only, `mode=ro`, so
the schema/rows must exist before construction), not a mock -- matching this
project's own general preference for exercising real code paths.

Not part of the pytest suite in the sense of needing network/pihole -- run via
pytest directly: `.venv/Scripts/python.exe -m pytest tests/test_dns_features_pihole_heartbeat.py`
"""
import sqlite3
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from extractors.dns_features import PiHoleCollector  # noqa: E402
from core.heartbeat import read_component_heartbeats  # noqa: E402
import config as config_module  # noqa: E402


def _make_pihole_db(path: Path, n_rows: int = 3) -> None:
    conn = sqlite3.connect(str(path))
    # PiHoleCollector._connect() opens read-only (mode=ro) and issues
    # "PRAGMA journal_mode=WAL" unconditionally -- on a real Pi-hole FTL
    # database that's already a no-op (FTL runs in WAL mode), but a fresh
    # rollback-journal-mode file (SQLite's own default) genuinely can't be
    # switched to WAL over a read-only connection ("attempt to write a
    # readonly database"). Set WAL here, while this connection still has
    # write access, so the on-disk file matches production reality.
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp REAL, domain TEXT, client TEXT, status INTEGER)")
    conn.execute("CREATE TABLE network_addresses (ip TEXT, name TEXT)")
    now = time.time()
    for i in range(n_rows):
        conn.execute(
            "INSERT INTO queries (id, timestamp, domain, client, status) VALUES (?, ?, ?, ?, ?)",
            (i + 1, now, f"example{i}.com", "192.168.1.50", 2),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def real_pihole_collector(tmp_path, monkeypatch):
    db_path = tmp_path / "pihole-FTL.db"
    _make_pihole_db(db_path, n_rows=3)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    # PiHoleCollector's own properties read the module-level CONFIG singleton
    # directly for state_path/safe_ips/safe_host_patterns -- monkeypatch its
    # .get() rather than constructing a whole fake LiveConfig.
    monkeypatch.setattr(config_module.CONFIG, "get", lambda key, default=None: {
        "state_path": str(state_dir / "ids_state.json"),
        "safe_ips": [],
        "safe_host_patterns": [],
        "startup_lookback_seconds": 300,
    }.get(key, default))
    collector = PiHoleCollector(db_path=str(db_path))
    collector.last_id = 0  # force poll() to see all 3 rows, not just the last-5000-row backfill window
    return collector, state_dir


def test_poll_writes_a_heartbeat_on_successful_poll_with_new_rows(real_pihole_collector):
    collector, state_dir = real_pihole_collector
    results = collector.poll()
    assert len(results) == 3
    hb = read_component_heartbeats(state_dir)
    assert "pihole_poll" in hb
    assert hb["pihole_poll"]["new_rows"] == 3


def test_poll_writes_a_heartbeat_even_with_zero_new_rows(real_pihole_collector):
    """THE ACTUAL FIX: zero new rows is a successful poll, not a failure -- must
    still refresh the health recency signal, not be silently indistinguishable
    from Pi-hole being unreachable."""
    collector, state_dir = real_pihole_collector
    collector.poll()  # first call consumes all 3 rows, last_id advances
    hb_after_first = read_component_heartbeats(state_dir)
    first_ts = hb_after_first["pihole_poll"]["last_heartbeat"]

    collector._last_heartbeat_write = 0.0  # bypass this test's own rate-limit window
    time.sleep(0.05)
    results = collector.poll()  # nothing new since last_id already advanced
    assert results == []
    hb_after_second = read_component_heartbeats(state_dir)
    assert hb_after_second["pihole_poll"]["new_rows"] == 0
    assert hb_after_second["pihole_poll"]["last_heartbeat"] > first_ts


def test_poll_rate_limits_heartbeat_writes(real_pihole_collector):
    """poll() runs roughly every 2s in production (config.yaml's poll_interval)
    -- writing the shared heartbeat file on literally every call would be both
    wasteful and out of line with write_component_heartbeat()'s own documented
    'once per ~10s at most' contract."""
    collector, state_dir = real_pihole_collector
    collector.poll()
    hb_first = read_component_heartbeats(state_dir)
    first_ts = hb_first["pihole_poll"]["last_heartbeat"]

    collector.last_id = 0  # pretend there's more to see again
    collector.poll()  # called again immediately -- must NOT rewrite yet
    hb_second = read_component_heartbeats(state_dir)
    assert hb_second["pihole_poll"]["last_heartbeat"] == first_ts


def test_poll_does_not_write_a_heartbeat_when_the_query_fails(real_pihole_collector):
    """A genuine failure must never refresh the recency clock -- that would
    mask exactly the outage this feature exists to surface. Forces a real
    sqlite3 failure (closing the connection out from under poll()) rather than
    monkeypatching sqlite3.Connection.execute, which is a read-only C-level
    attribute on this Python build."""
    collector, state_dir = real_pihole_collector
    collector._conn.close()
    results = collector.poll()
    assert results == []
    hb = read_component_heartbeats(state_dir)
    assert "pihole_poll" not in hb
