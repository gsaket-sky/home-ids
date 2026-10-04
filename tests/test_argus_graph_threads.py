"""
E16 / I9 regression: GraphStore is shared across threads (main loop, reactive-capture dispatcher, threadpool).
A sqlite3 connection opened on one thread used from another raised "SQLite objects created in a thread can only
be used in that same thread", so threat_intel.is_allowlisted() fell through to external lookups.
Each thread must get its own connection and transaction flag.
"""
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from argus.graph.store import GraphStore  # noqa: E402


def _run_in_thread(fn):
    errors = []

    def runner():
        try:
            fn()
        except Exception as exc:  # collected and asserted on the main thread
            errors.append(exc)

    t = threading.Thread(target=runner)
    t.start()
    t.join(timeout=30)
    return errors


@pytest.fixture
def store(tmp_path):
    s = GraphStore(str(tmp_path / "graph.db"))
    yield s
    s.close()


def test_store_query_works_from_another_thread(store):
    def query():
        assert store._conn.execute("SELECT 1").fetchone()[0] == 1

    assert _run_in_thread(query) == []


def test_creating_thread_connection_is_still_its_own(store):
    main_conn = store._conn
    seen = []
    _run_in_thread(lambda: seen.append(store._conn))
    assert seen and seen[0] is not main_conn
    assert store._conn is main_conn


def test_transaction_flag_is_per_thread(store):
    # Thread A is inside a transaction; thread B must not see the flag and must not be treated as nested.
    inside = threading.Event()
    release = threading.Event()

    def holder():
        with store.transaction():
            inside.set()
            release.wait(timeout=10)

    t = threading.Thread(target=holder)
    t.start()
    inside.wait(timeout=10)
    try:
        seen = []
        _run_in_thread(lambda: seen.append(store._in_transaction))
        assert seen == [False]
        assert store._in_transaction is False  # main thread is not in a transaction either
    finally:
        release.set()
        t.join(timeout=10)


def test_close_closes_connections_from_every_thread(store):
    _run_in_thread(lambda: store._conn.execute("SELECT 1"))
    store.close()
    # The closed connection stays bound to this thread, so use-after-close still raises as it did before.
    with pytest.raises(sqlite3.ProgrammingError):
        store._conn.execute("SELECT 1")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
