"""
state_client.py -- shared, mtime-cached StateManager accessor for the console API's
READ-ONLY routers (graph_api, autonomy_api, devices_api, hunt_api).

Chronic latency, found live 2026-09-22 (same session as graph_client.py's own
_migrate_existing_db() per-request fix): every read-only console GET endpoint that
needs to resolve a device's hostname/state independently constructed a fresh
StateManager and called load_from_disk() -- a full JSON parse plus per-device
DeviceState reconstruction of state/ids_state.json (5.7MB / ~50 devices on .94) --
on EVERY single request, even though the file itself is only actually rewritten by
the main pipeline process roughly once every couple of minutes (state_guard.py's
own periodic flush).

get_cached_state_manager() instead reuses one process-lifetime StateManager
instance across requests, only re-running load_from_disk() when the file's own
mtime has actually advanced since the last load -- a plain os.stat() on every
request that finds nothing new, not a full reparse.

Deliberately NOT used by anything that takes a containment/mitigation action
(pihole_api.py, fritzbox_api.py, mitigation_api.py's own block/unblock/isolate/
release/revoke paths keep constructing their own fresh, unshared instance). Those
endpoints change real network state; sharing a cached instance into that path is a
different and much higher-stakes risk than a dashboard read being briefly stale, and
isn't where this latency complaint came from. Only wire this into a genuinely
read-only endpoint.
"""
import threading
from typing import Optional

from core import state_store
from core.state_guard import StateManager

_lock = threading.Lock()
_cached_sm: Optional[StateManager] = None
_cached_mtime: Optional[float] = None
_cached_path: Optional[str] = None


def get_cached_state_manager(state_path: str) -> StateManager:
    global _cached_sm, _cached_mtime, _cached_path
    with _lock:
        mtime = state_store.last_modified(state_path)   # the SQLite file/WAL (or a not-yet-migrated JSON)
        if (_cached_sm is not None and _cached_path == state_path
                and mtime is not None and mtime == _cached_mtime):
            return _cached_sm
        sm = StateManager(state_path=state_path)
        sm.load_from_disk(ledger=False)   # read-only views never need the action ledger (most of the data)
        _cached_sm = sm
        _cached_mtime = mtime
        _cached_path = state_path
        return sm
