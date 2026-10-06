"""
learning_sweep.py -- the learning-period intel sweep (MASTER_TODO M2: zero-day-infected network, already-infected
device).

Why: whatever a device does during its learning period becomes its "normal" (EWMA baselines, per-device models, the
W-04 novelty gates), and threat intel only answers for what was listed at the moment the traffic happened. A C2 that
gets listed a day later is invisible to every baseline-relative detector. The nightly retro-hunt
(argus/ops/live_retro_hunter.py) re-checks the whole retained history once a night; this sweep covers the window
where waiting for it matters most. It runs in the pipeline process right after a feed refresh:
  - on the first refresh after start: the first chance to re-check what was seen before the feeds were loaded (until
    then every lookup is a silent "no match"), and at first install the only "before" there is;
  - on every refresh while the network itself is warming up (fewer than HISTORY_WARMUP_ACTIVE_DAYS active days), for
    every device;
  - on every refresh while any device with traffic in the window is in its own learning period, for those devices
    only.
Otherwise it does nothing; the nightly job covers everyone.

It reuses RetroHunter (same pair sources, same name/IP split, same evidence write-back and tier-5 destination
reputation, and the same "report each (device, destination) pair once" rule the nightly job follows) and the
pipeline's own in-memory feeds: no second download, and the lookup applies the same allowlist and trust-cache rules
as the live path, including the rule that an activated feed's strong hit outranks every trust entry. The trust cache
is read once per sweep, not once per name. Nothing waits for a person: findings go into the normal decision path.
With no feed loaded nothing matches, and the sweep only records that it ran.
"""
import logging
import threading
import time
from typing import Any, Callable, Dict, Optional

from argus.retro_hunter import RetroHunter, format_findings_message

LOGGER = logging.getLogger("argus.learning_sweep")

TRIGGER_FIRST = "first_refresh"
TRIGGER_WARMUP = "network_warmup"
TRIGGER_LEARNING = "devices_learning"

_FINDINGS_KEPT_IN_SUMMARY = 100


class LearningIntelSweep:
    def __init__(self, store_fn: Callable[[], Any], threat_intel: Any, learning_fn: Callable[[str], bool],
                 days_back: float, popularity: Any = None, notify: Optional[Callable[[str], None]] = None,
                 warmup_days: Optional[int] = None, now_fn: Callable[[], float] = time.time):
        """`store_fn()` returns the GraphStore (the pipeline's singleton accessor; GraphStore keeps one connection per
        thread). `threat_intel` is the pipeline's ThreatIntel. `learning_fn(device_id)` is True while that device is
        in its learning period. `popularity` (LocalPopularity, optional) supplies the network's active days and the
        ledger's (device, name) pairs. `notify(text)` sends a findings message (Telegram)."""
        if warmup_days is None:
            from intelligence.local_popularity import HISTORY_WARMUP_ACTIVE_DAYS
            warmup_days = HISTORY_WARMUP_ACTIVE_DAYS
        self.store_fn = store_fn
        self.ti = threat_intel
        self.learning_fn = learning_fn
        self.days_back = float(days_back)
        self.popularity = popularity
        self.notify = notify
        self.warmup_days = int(warmup_days)
        self.now_fn = now_fn
        self._lock = threading.Lock()
        self._ran_since_start = False
        self.last_summary: Optional[Dict[str, Any]] = None

    # --- triggering ---------------------------------------------------------------------------------------------

    def attach(self) -> None:
        """Run after every feed refresh from now on. The refresh thread starts before the pipeline is built, so the
        first refresh may already be done: then sweep right away."""
        self.ti.add_refresh_listener(self.on_feed_refresh)
        try:
            ready = bool(self.ti.is_ready())
        except Exception:
            ready = False
        if ready:
            self.on_feed_refresh()

    def on_feed_refresh(self) -> None:
        """Refresh-thread callback: hands the sweep to its own thread and returns. A sweep still running when the
        next refresh comes is not doubled up; that refresh is simply skipped."""
        if self._lock.locked():
            return
        threading.Thread(target=self._run_guarded, daemon=True, name="learning-intel-sweep").start()

    def _run_guarded(self) -> None:
        if not self._lock.acquire(blocking=False):
            return
        try:
            self.run_once()
        except Exception as e:
            LOGGER.warning("Learning-period intel sweep failed (the next feed refresh tries again): %s", e)
        finally:
            self._lock.release()

    # --- the sweep ----------------------------------------------------------------------------------------------

    def _network_warming(self) -> bool:
        if self.popularity is None:
            return False
        try:
            # A property on LocalPopularity (calling it raised TypeError, read as "warm", until 2026-10-05).
            return int(self.popularity.active_days) < self.warmup_days
        except Exception:
            return False

    def _in_learning(self, device_id: str) -> bool:
        try:
            return bool(self.learning_fn(device_id))
        except Exception:
            return False

    def _trust_snapshot(self) -> Optional[set]:
        provider = getattr(self.ti, "trust_cache_provider", None)
        if provider is None:
            return None
        try:
            return set(provider.get_dynamic_trust_cache())
        except Exception as e:
            # Same as the live path when the read fails: no trust entry shields anything.
            LOGGER.warning("Learning-period intel sweep: trust cache unreadable, sweeping without it: %s", e)
            return set()

    def run_once(self) -> Optional[Dict[str, Any]]:
        """One sweep, synchronously. Returns its summary, or None when there was nothing to sweep (network warm,
        no device learning, not the first refresh)."""
        started = time.time()
        now = self.now_fn()
        since = now - self.days_back * 86400
        store = self.store_fn()

        ledger_pairs = []
        if self.popularity is not None:
            try:
                ledger_pairs = self.popularity.device_name_pairs_since(since)
            except Exception as e:
                LOGGER.warning("Learning-period intel sweep: popularity ledger unreadable: %s", e)

        snapshot = self._trust_snapshot()
        hunter = RetroHunter(store, lambda d: self.ti.lookup_domain(d, trust_cache=snapshot),
                             ip_lookup=self.ti.lookup_ip)

        scope = None
        if not self._ran_since_start:
            trigger = TRIGGER_FIRST
        elif self._network_warming():
            trigger = TRIGGER_WARMUP
        else:
            learning = {d for d in hunter.window_devices(self.days_back, now=now, extra_pairs=ledger_pairs)
                        if self._in_learning(d)}
            if not learning:
                return None
            trigger, scope = TRIGGER_LEARNING, learning

        findings = hunter.hunt(days_back=self.days_back, now=now, extra_pairs=ledger_pairs, only_devices=scope)
        self._ran_since_start = True

        summary = {
            "trigger": trigger,
            "days_back": self.days_back,
            "devices_in_scope": "all" if scope is None else len(scope),
            "pairs_checked": hunter.last_pairs_checked,
            "destinations_checked": hunter.last_destinations_checked,
            "intel_ready": bool(self.ti.is_ready()),
            "findings_count": len(findings),
            "weak_matches_count": hunter.last_weak_matches,   # context-only matches, not findings (intel_strength.py)
            "findings": [{"device_id": f.device_id, "destination_id": f.destination_id, "source": f.source,
                          "confidence": f.confidence, "tags": f.tags} for f in findings[:_FINDINGS_KEPT_IN_SUMMARY]],
            "duration_seconds": round(time.time() - started, 3),
        }
        try:
            store.record_intel_sweep(trigger, summary, timestamp=now)
        except Exception as e:
            LOGGER.warning("Learning-period intel sweep: could not record its summary: %s", e)
        self.last_summary = summary
        LOGGER.info("Learning-period intel sweep (%s): %d new finding(s), %d destination(s) over %s device(s).",
                    trigger, len(findings), hunter.last_destinations_checked, summary["devices_in_scope"])
        if findings and self.notify is not None:
            try:
                self.notify(format_findings_message(findings, self.days_back, title="Learning-period intel sweep"))
            except Exception as e:
                LOGGER.warning("Learning-period intel sweep: notification failed: %s", e)
        return summary
