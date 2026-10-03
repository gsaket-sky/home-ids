"""
local_intel.py - Self-growing local confirmed-threat store.

Once any device on this network is confirmed talking to a malicious destination --
Stage-1 CONFIRMED_THREAT in the CL-AFPE, or the same 2-independent-source HIGH/
CRITICAL bar the Telegram gate uses (pipeline.py) -- that IOC is recorded here.
A DIFFERENT device connecting to the SAME IOC later gets an immediate hard-stop
instead of re-earning 2 independent sources from scratch: the network gets
collectively harder to compromise via the same infrastructure, the more it confirms.

Scope note: kinds are "ip" and "domain" only, not "ja3"/"ja4" -- the CL-AFPE's
evaluate() only ever receives aggregated malicious-hit COUNTS
(zeek_ja3_malicious/zeek_ja4_malicious), not the actual hash strings, so there is
nothing reliable to record/check a specific fingerprint against at this layer without
deeper plumbing changes. Scoped to what's genuinely wired end-to-end today rather than
adding kinds that would silently never populate.

TTL-bounded (default 30 days) -- confirmed-malicious infrastructure from months ago may
be repurposed or abandoned, so this is explicitly not permanent, same reasoning as
the CL-AFPE's own domain trust cache.

One file, several processes: the engine (live checks and records), the scheduler's retro-hunt
and the maintenance tools all use state/local_confirmed_intel.json. Every operation therefore
re-reads the file when another process changed it, and saves atomically (temp file + rename),
so a power cut never leaves a half-written store and one writer does not silently undo another.
"""
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Set

LOGGER = logging.getLogger("home_ids.local_intel")

_KINDS = ("ip", "domain")
DEFAULT_TTL_SECONDS = 30 * 86400.0


class LocalConfirmedIntel:
    def __init__(self, state_dir, ttl_seconds: float = DEFAULT_TTL_SECONDS):
        Path(state_dir).mkdir(parents=True, exist_ok=True)
        self._path = Path(state_dir) / "local_confirmed_intel.json"
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._store: Dict[str, Dict[str, dict]] = {k: {} for k in _KINDS}
        self._mtime_ns = None   # file mtime at our last load/save; a different value = another process wrote it
        self._load()

    def _entry_ttl(self, entry: dict) -> float:
        """PHASE 67 (HEE_ROADMAP.md item 6, malicious-track calibration wiring):
        per-entry TTL override, same shape-agnostic pattern as the CL-AFPE's own
        `_trust_entry_ttl()` (Phase 52) -- an entry without a stored `ttl_seconds`
        (every entry written before this phase) falls back to the instance-wide
        `self._ttl`, so a live upgrade never breaks reading pre-existing entries."""
        ttl = entry.get("ttl_seconds")
        return float(ttl) if ttl else self._ttl

    def record(self, kind: str, value: str, device_id: str, reason: str = "",
               ttl_seconds: Optional[float] = None) -> bool:
        """Records a confirmed IOC. Returns True if this is a NEW entry, False if it
        was a refresh of an already-known one -- same is_new convention as
        the CL-AFPE's _immunize_domain(). `ttl_seconds` (PHASE 67, optional) overrides
        the instance-wide default for THIS entry only -- same per-entry-override shape
        as the CL-AFPE's trust cache (Phase 52); None (every caller before this phase)
        means "use the instance default", not "no TTL"."""
        if kind not in _KINDS or not value or str(value).lower() in ("unknown", "null", "none", ""):
            return False
        now = time.time()
        self._refresh_if_changed()
        with self._lock:
            bucket = self._store[kind]
            existing = bucket.get(value)
            is_new = existing is None
            if existing:
                existing["last_confirmed"] = now
                existing["count"] = existing.get("count", 1) + 1
                sources = existing.setdefault("sources", [])
                if device_id not in sources:
                    sources.append(device_id)
                if ttl_seconds:
                    existing["ttl_seconds"] = float(ttl_seconds)
            else:
                bucket[value] = {
                    "first_confirmed": now, "last_confirmed": now, "count": 1,
                    "sources": [device_id], "reason": reason,
                    "ttl_seconds": float(ttl_seconds) if ttl_seconds else self._ttl,
                }
        self._save()
        if is_new:
            LOGGER.warning("🌐 [LOCAL INTEL] NEW confirmed %s: '%s' (device=%s, reason=%s)",
                            kind, value, device_id, reason)
        return is_new

    def check(self, kind: str, value: str) -> Optional[dict]:
        """Returns the (non-expired) entry for value, or None if it isn't a confirmed
        IOC of this kind, or its TTL has lapsed."""
        if kind not in _KINDS or not value:
            return None
        now = time.time()
        self._refresh_if_changed()
        with self._lock:
            entry = self._store[kind].get(value)
        if entry and (now - entry["last_confirmed"]) < self._entry_ttl(entry):
            return entry
        return None

    def all_confirmed(self, kind: str) -> Set[str]:
        """All non-expired confirmed values of one kind -- used by retro_hunter.py's
        retroactive cross-device re-scan."""
        if kind not in _KINDS:
            return set()
        now = time.time()
        self._refresh_if_changed()
        with self._lock:
            return {v for v, e in self._store[kind].items() if (now - e["last_confirmed"]) < self._entry_ttl(e)}

    def prune_expired(self) -> int:
        """Removes expired entries across all kinds. Returns the count pruned. Meant
        to be called periodically (e.g. alongside retro_hunter.py's own scheduled
        run) rather than on every access."""
        now = time.time()
        pruned = 0
        self._refresh_if_changed()
        with self._lock:
            for kind in _KINDS:
                bucket = self._store[kind]
                expired = [key for key, e in bucket.items() if (now - e["last_confirmed"]) >= self._entry_ttl(e)]
                for key in expired:
                    del bucket[key]
                    pruned += 1
        if pruned:
            self._save()
        return pruned

    def merge_from(self, other_path) -> int:
        """Folds the entries of another store file into this one (union per indicator: newest
        last_confirmed wins, sources combined). Returns how many indicators were added or updated."""
        try:
            raw = json.loads(Path(other_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return 0
        changed = 0
        self._refresh_if_changed()
        with self._lock:
            for k in _KINDS:
                for value, entry in (raw.get(k) or {}).items():
                    if not isinstance(entry, dict) or "last_confirmed" not in entry:
                        continue
                    mine = self._store[k].get(value)
                    if mine is None:
                        self._store[k][value] = dict(entry)
                        changed += 1
                    elif entry["last_confirmed"] > mine.get("last_confirmed", 0):
                        sources = list(dict.fromkeys((mine.get("sources") or []) + (entry.get("sources") or [])))
                        mine.update(entry)
                        mine["sources"] = sources
                        changed += 1
        if changed:
            self._save()
        return changed

    def _file_mtime(self):
        try:
            return self._path.stat().st_mtime_ns
        except OSError:
            return None

    def _refresh_if_changed(self) -> None:
        """Re-reads the file when another process wrote it since our last load/save."""
        mtime = self._file_mtime()
        if mtime is not None and mtime != self._mtime_ns:
            self._load()

    def _save(self) -> None:
        try:
            with self._lock:
                snapshot = {k: dict(v) for k, v in self._store.items()}
            tmp = self._path.with_name(f"{self._path.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            os.replace(tmp, self._path)
            self._mtime_ns = self._file_mtime()
        except Exception as exc:
            LOGGER.error("Failed to save local_confirmed_intel.json: %s", exc)

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            mtime = self._file_mtime()
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            with self._lock:
                for k in _KINDS:
                    self._store[k] = raw[k] if isinstance(raw.get(k), dict) else {}
                self._mtime_ns = mtime
            LOGGER.debug("Local confirmed-intel store loaded: %s", {k: len(v) for k, v in self._store.items()})
        except Exception as exc:
            LOGGER.error("Failed to load local_confirmed_intel.json: %s", exc)
