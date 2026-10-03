"""
graph_client.py -- shared helper for the console API routers (devices_api, hunt_api,
graph_api) that need read access to the argus evidence graph.

GraphStore.__init__ is a plain sqlite3.connect() with no check_same_thread=False.
FastAPI's sync `def` handlers run across a threadpool, so a single shared GraphStore
instance touched from multiple request threads risks
"SQLite objects created in a thread can only be used in that same thread". A fresh
connection per request avoids that entirely and is cheap -- schema.sql bakes in
PRAGMA journal_mode=WAL, confirmed safe for any number of concurrent readers against
the SAME writer (the main detection pipeline) this way; this is also exactly the
pattern src/argus/ops/threat_hunt.py's own CLI already uses for a second, independent
connection to the same file.
"""
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from config import CONFIG_FILE

from argus.graph.store import GraphStore

GRAPH_DB_PATH = CONFIG_FILE.parent / "state" / "v13_graph.db"


@contextmanager
def open_store():
    """Yields a fresh GraphStore for the duration of one request, always closed
    afterward. Yields None if the graph db doesn't exist yet (a fresh deployment with
    no argus data) -- callers should return an empty/appropriate response rather than
    treat that as an error."""
    if not GRAPH_DB_PATH.exists():
        yield None
        return
    store = GraphStore(str(GRAPH_DB_PATH))
    try:
        yield store
    finally:
        store.close()
