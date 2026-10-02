"""
state_store.py - SQLite persistence behind StateManager (devices, IPS state, action ledger, merge redirects).

Why (checklist §K, flash wear): state/ids_state.json was one JSON document, rewritten whole -- ~6 MB on .94 -- on every
periodic flush (about once a minute), although usually only a handful of devices and the newest ledger entries had
changed. On an SD card that is the single largest write load of the appliance. Here every device, every ledger entry
and each of the few global blobs is its own row, and a flush writes only the rows whose JSON actually changed, in one
transaction (WAL mode, synchronous=NORMAL: durable across a process crash; a power cut can lose at most the last flush,
the same as the old atomic file replace).

The database lives next to the old file: state_path "state/ids_state.json" -> "state/ids_state.db". The config key and
every caller stay the same. An existing ids_state.json is migrated on the first flush and then renamed to
ids_state.json.pre-sqlite (kept as a backup, never read again while the database exists).

Readers that are not StateManager (the web UI, recommendations) use read_snapshot(), which returns the same dict shape
the JSON file had. Every process opens its own short-lived connection; SQLite's own locking serialises the writers
(engine, its API subprocess, maintenance scripts) and busy_timeout makes them wait instead of failing.
"""
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

SCHEMA_VERSION = "1"
KV_KEYS = ("ips_state", "merge_redirects")
_BUSY_TIMEOUT_S = 15.0


def db_path_for(state_path) -> Path:
    p = Path(state_path)
    return p.with_suffix(".db") if p.suffix == ".json" else p.with_name(p.name + ".db")


def legacy_json_path(state_path) -> Path:
    p = Path(state_path)
    return p if p.suffix == ".json" else p.with_suffix(".json")


def _share_with_group(db: Path) -> None:
    """SQLite creates its files 0644 whatever the umask, and gives -wal/-shm the database file's mode. The engine runs
    as root and the web UI as the IDS user in the same (setgid) group, and a WAL reader must be able to write -shm --
    so the files are made group read/write (best effort; a no-op where we do not own them, e.g. on Windows)."""
    for p in (db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")):
        try:
            mode = p.stat().st_mode & 0o777
            if mode & 0o060 != 0o060:
                os.chmod(p, mode | 0o060)
        except OSError:
            pass


def _connect(db: Path, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=_BUSY_TIMEOUT_S,
                               isolation_level=None, check_same_thread=False)
        try:
            conn.execute("SELECT 1 FROM kv LIMIT 1")
        except sqlite3.OperationalError:
            # e.g. a WAL database whose -shm this user cannot use read-only: plain read-write (never creates tables)
            conn.close()
            conn = sqlite3.connect(f"file:{db.as_posix()}?mode=rw", uri=True, timeout=_BUSY_TIMEOUT_S,
                                   isolation_level=None, check_same_thread=False)
    else:
        db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db), timeout=_BUSY_TIMEOUT_S, isolation_level=None, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, data TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS ledger  (id TEXT PRIMARY KEY, data TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS kv      (key TEXT PRIMARY KEY, data TEXT NOT NULL);"
        )
        _share_with_group(db)
    conn.execute(f"PRAGMA busy_timeout={int(_BUSY_TIMEOUT_S * 1000)}")
    return conn


def exists(state_path) -> bool:
    """True once a flush has written the database (it holds the schema marker)."""
    db = db_path_for(state_path)
    if not db.is_file():
        return False
    try:
        conn = _connect(db, readonly=True)
        try:
            row = conn.execute("SELECT data FROM kv WHERE key='schema'").fetchone()
            return row is not None
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def read_rows(state_path, tables: Iterable[str] = ("devices", "ledger", "kv")) -> Optional[Dict[str, Dict[str, str]]]:
    """Raw JSON strings per row: {"devices": {id: json}, "ledger": {id: json}, "kv": {key: json}}; None without a
    database. The strings let StateManager remember exactly what is on disk, so its next flush skips unchanged rows."""
    if not exists(state_path):
        return None
    conn = _connect(db_path_for(state_path), readonly=True)
    try:
        out: Dict[str, Dict[str, str]] = {}
        conn.execute("BEGIN")          # one consistent snapshot across the tables
        for t in tables:
            key = "key" if t == "kv" else "id"
            out[t] = {k: v for k, v in conn.execute(f"SELECT {key}, data FROM {t}")}
        conn.execute("COMMIT")
        return out
    finally:
        conn.close()


_writers: Dict[str, sqlite3.Connection] = {}
_writers_lock = threading.Lock()


def _writer(db: Path) -> sqlite3.Connection:
    """One long-lived writer connection per database and process. Closing the last connection makes SQLite
    checkpoint the WAL into the database and delete it -- once a minute that meant every changed page written twice
    plus a file created and removed each flush. Kept open, the WAL batches changes and checkpoints every ~4 MB."""
    key = str(db)
    with _writers_lock:
        conn = _writers.get(key)
        if conn is not None and not db.exists():      # database removed underneath us: start over
            try:
                conn.close()
            except sqlite3.Error:
                pass
            conn = None
        if conn is None:
            conn = _connect(db)
            _writers[key] = conn
        return conn


def write_changes(state_path, devices: Dict[str, str], devices_deleted: Iterable[str], ledger: Dict[str, str],
                  ledger_deleted: Iterable[str], kv: Dict[str, str]) -> None:
    """Upserts/deletes exactly the given rows in one transaction."""
    conn = _writer(db_path_for(state_path))
    with _writers_lock:
        _write_rows(conn, devices, devices_deleted, ledger, ledger_deleted, kv)
    _share_with_group(db_path_for(state_path))


def _write_rows(conn, devices, devices_deleted, ledger, ledger_deleted, kv) -> None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        if devices:
            conn.executemany("INSERT OR REPLACE INTO devices (id, data) VALUES (?, ?)", devices.items())
        conn.executemany("DELETE FROM devices WHERE id = ?", [(d,) for d in devices_deleted])
        if ledger:
            conn.executemany("INSERT OR REPLACE INTO ledger (id, data) VALUES (?, ?)", ledger.items())
        conn.executemany("DELETE FROM ledger WHERE id = ?", [(a,) for a in ledger_deleted])
        rows = dict(kv)
        rows.setdefault("schema", json.dumps(SCHEMA_VERSION))
        conn.executemany("INSERT OR REPLACE INTO kv (key, data) VALUES (?, ?)", rows.items())
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def close_writers() -> None:
    """Closes the long-lived writer connections (tests; a clean shutdown does not need it)."""
    with _writers_lock:
        for conn in _writers.values():
            try:
                conn.close()
            except sqlite3.Error:
                pass
        _writers.clear()


def last_modified(state_path) -> Optional[float]:
    """Newest mtime of the state storage (database, its WAL, or the legacy JSON) -- a cheap change check for caches."""
    db = db_path_for(state_path)
    times = []
    for p in (db, db.with_name(db.name + "-wal"), legacy_json_path(state_path)):
        try:
            times.append(os.path.getmtime(p))
        except OSError:
            pass
    return max(times) if times else None


def read_snapshot(state_path, ledger: bool = True) -> Optional[Dict[str, Any]]:
    """The whole state in the old ids_state.json shape ({"devices", "ips_state", "action_ledger", "merge_redirects"}),
    from the database, else from a not-yet-migrated JSON file; None when neither exists or neither is readable.
    ledger=False skips the action ledger (most of the data) for readers that only need devices and IPS state."""
    try:
        rows = read_rows(state_path, tables=("devices", "ledger", "kv") if ledger else ("devices", "kv"))
    except sqlite3.Error:
        rows = None
    if rows is not None:
        kv = {k: json.loads(v) for k, v in rows["kv"].items()}
        return {"devices": {k: json.loads(v) for k, v in rows["devices"].items()},
                "action_ledger": {k: json.loads(v) for k, v in rows.get("ledger", {}).items()},
                "ips_state": kv.get("ips_state") or {}, "merge_redirects": kv.get("merge_redirects") or {}}
    path = legacy_json_path(state_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


if __name__ == "__main__":
    # Human-readable export (replaces "just read ids_state.json"):
    #   python3 src/core/state_store.py [state/ids_state.json] > state_export.json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "state/ids_state.json"
    snap = read_snapshot(target)
    if snap is None:
        sys.exit(f"no state found for {target}")
    json.dump(snap, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
