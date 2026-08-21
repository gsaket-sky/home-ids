"""
local_intel.py - Self-growing local confirmed-threat store (Phase 21D3).

Once any device on this network is confirmed talking to a malicious destination --
Stage-1 CONFIRMED_THREAT in fp_engine.py, or the same 2-independent-source HIGH/
CRITICAL bar Phase A's Telegram gate uses (pipeline.py) -- that IOC is recorded here.
A DIFFERENT device connecting to the SAME IOC later gets an immediate hard-stop
instead of re-earning 2 independent sources from scratch: the network gets
collectively harder to compromise via the same infrastructure, the more it confirms.

Scope note: kinds are "ip" and "domain" only, not "ja3"/"ja4" -- fp_engine.py's
evaluate() only ever receives aggregated malicious-hit COUNTS
(zeek_ja3_malicious/zeek_ja4_malicious), not the actual hash strings, so there is
nothing reliable to record/check a specific fingerprint against at this layer without
deeper plumbing changes. Scoped to what's genuinely wired end-to-end today rather than
adding kinds that would silently never populate.

TTL-bounded (default 30 days) -- confirmed-malicious infrastructure from months ago may
be repurposed or abandoned, so this is explicitly not permanent, same reasoning as
fp_engine.py's own domain trust cache.
"""
import json
import logging
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
        self._load()

    def record(self, kind: str, value: str, device_id: str, reason: str = "") -> bool:
        """Records a confirmed IOC. Returns True if this is a NEW entry, False if it
        was a refresh of an already-known one -- same is_new convention as
        fp_engine.py's _immunize_domain()."""
        if kind not in _KINDS or not value or str(value).lower() in ("unknown", "null", "none", ""):
            return False
        now = time.time()
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
            else:
                bucket[value] = {
                    "first_confirmed": now, "last_confirmed": now, "count": 1,
                    "sources": [device_id], "reason": reason,
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
        with self._lock:
            entry = self._store[kind].get(value)
        if entry and (now - entry["last_confirmed"]) < self._ttl:
            return entry
        return None

    def all_confirmed(self, kind: str) -> Set[str]:
        """All non-expired confirmed values of one kind -- used by retro_hunter.py's
        retroactive cross-device re-scan."""
        if kind not in _KINDS:
            return set()
        now = time.time()
        with self._lock:
            return {v for v, e in self._store[kind].items() if (now - e["last_confirmed"]) < self._ttl}

    def prune_expired(self) -> int:
        """Removes expired entries across all kinds. Returns the count pruned. Meant
        to be called periodically (e.g. alongside retro_hunter.py's own scheduled
        run) rather than on every access."""
        now = time.time()
        pruned = 0
        with self._lock:
            for kind in _KINDS:
                bucket = self._store[kind]
                expired = [key for key, e in bucket.items() if (now - e["last_confirmed"]) >= self._ttl]
                for key in expired:
                    del bucket[key]
                    pruned += 1
        if pruned:
            self._save()
        return pruned

    def _save(self) -> None:
        try:
            with self._lock:
                snapshot = {k: dict(v) for k, v in self._store.items()}
            self._path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        except Exception as exc:
            LOGGER.error("Failed to save local_confirmed_intel.json: %s", exc)

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            with self._lock:
                for k in _KINDS:
                    if isinstance(raw.get(k), dict):
                        self._store[k] = raw[k]
            LOGGER.info("✅ Local confirmed-intel store loaded: %s",
                        {k: len(v) for k, v in self._store.items()})
        except Exception as exc:
            LOGGER.error("Failed to load local_confirmed_intel.json: %s", exc)
