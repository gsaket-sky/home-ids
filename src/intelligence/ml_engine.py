"""
ml_engine.py – Machine Learning Anomaly Detection & Registry.

Provides per-device and global IsolationForest anomaly detection models,
Markov state transition sequence trackers, and the MLRegistry coordination interface.

RECENT FIXES:
- FIXED (O(n²) PERFORMANCE BOTTLENECK): Replaced plain Python lists (`self.training = []`) 
  with `collections.deque(maxlen=...)` for both `DeviceMLEngine` and `GlobalMLEngine`. 
  Ring buffer appends and FIFO evictions are now strictly O(1), eliminating memory-shifting overhead.
- FIXED (CRITICAL): Resolved the "retrain-freeze" bug using the `_samples_since_retrain` delta counter.
- ADDED (MIGRATION): `migrate_device` method securely transfers in-memory ML engines and renames `.pkl` files.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from collections import OrderedDict, deque
from pathlib import Path
import logging
import os
import joblib
import threading
from typing import Optional, Any
import time
from config import CONFIG
from intelligence.iforest_fast import compile_model
from extractors.pihole_codes import DNS_RATIO_SCHEME
from metrics import (
    ml_warmup_completions_total,
    ml_retrain_events_total,
    ml_poisoning_rejections_total,
    ml_model_invalidations_total,
    device_profile_discards_total,
)
LOGGER = logging.getLogger("home_ids.ml_engine")

ML_FEATURE_KEYS = (
    "query_rate",
    "entropy_avg",
    "unique_domains",
    "nxdomain_ratio",
    "blocked_ratio",
    "zeek_outbound_bytes",
    "zeek_lateral_moves",
    "zeek_s0_rej_count",
    "zeek_app_protocol_weight",
    "time_sin",   # derived in-engine
    "time_cos",   # derived in-engine
)
ML_FEATURE_DIM = 11

_MAXLEN_DEVICE = 20000
_MAXLEN_GLOBAL = 100000

_WARMUP_GLOBAL = 1000  # samples before first global fit
_RETRAIN_N = 500       # retrain every 500 new samples (~17 min) for faster adaptation


REJECT_THREAT_WINDOW_SECONDS = 120.0  # ~1 pipeline cycle worth of "don't learn from this" guard

# Every fitted model records how nxdomain_ratio/blocked_ratio were measured when it learned them; load_models()
# drops a model learned under another scheme (extractors/pihole_codes.DNS_RATIO_SCHEME). Models saved before the stamp
# existed count as scheme 1.
_SCHEME_ATTR = "ids_dns_ratio_scheme"


def _stamp(model):
    setattr(model, _SCHEME_ATTR, DNS_RATIO_SCHEME)
    return model


def _model_scheme(model) -> int:
    return getattr(model, _SCHEME_ATTR, 1)


class _FastScorer:
    """Per-engine cache of the compiled form of the CURRENT model (see
    intelligence/iforest_fast.py for why: sklearn's single-row decision_function()
    costs ~21 ms of fixed overhead, paid for every device on every cycle). Recompiled
    only when the model object is swapped by a background fit or a load; any model
    the compiler can't handle, or input it doesn't model, falls back to sklearn."""
    __slots__ = ("_model", "_compiled")

    def __init__(self):
        self._model = None
        self._compiled = None

    def decision_function_one(self, model, vec: np.ndarray) -> float:
        if model is not self._model:
            self._model = model
            self._compiled = compile_model(model)
        if self._compiled is not None:
            value = self._compiled.decision_function_one(vec[0])
            if value is not None:
                return value
        return float(model.decision_function(vec)[0])


class DeviceMLEngine:
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.training = deque(maxlen=_MAXLEN_DEVICE)
        self.model = IsolationForest(contamination=0.01, random_state=42)
        self.warmed_up = False
        self._samples_since_retrain = 0
        self._fit_lock = threading.Lock()   # guards model swap during background fit
        self._fit_in_progress = False
        self._scorer = _FastScorer()
        self._last_missing_feature_log = 0.0
        # PHASE 0 FIX: reject_threat() used to be a pure log statement — it never actually
        # stopped a confirmed-threat sample from being trained on. This tracks a short
        # window after a confirmed threat during which learn_normal() calls for this
        # device are skipped, so the anomaly model doesn't get poisoned into treating
        # attack traffic as its new normal baseline.
        self._reject_until = 0.0
        LOGGER.debug("Initialized DeviceMLEngine for device: %s", device_id)

    def _validate_feature_payload(self, features: dict) -> None:
        missing = [k for k in ML_FEATURE_KEYS[:9] if k not in features]
        if missing:
            now = time.time()
            if (now - self._last_missing_feature_log) > 60.0:
                LOGGER.warning(
                    "ML feature payload missing keys for device %s: %s (defaults will be used). Expected dim=%d",
                    self.device_id, ",".join(missing), ML_FEATURE_DIM
                )
                self._last_missing_feature_log = now

    def _extract_vector(self, features: dict) -> list:
        self._validate_feature_payload(features)
        now = time.localtime()
        minutes_since_midnight = now.tm_hour * 60 + now.tm_min
        time_sin = np.sin(2 * np.pi * minutes_since_midnight / 1440.0)
        time_cos = np.cos(2 * np.pi * minutes_since_midnight / 1440.0)
        
        return [
            float(features.get("query_rate", 0) or 0), 
            float(features.get("entropy_avg", 0) or 0), 
            float(features.get("unique_domains", 0) or 0),
            float(features.get("nxdomain_ratio", 0) or 0),
            float(features.get("blocked_ratio", 0) or 0),
            min(float(features.get("zeek_outbound_bytes", 0) or 0) / 100000.0, 1.0),
            min(float(features.get("zeek_lateral_moves", 0) or 0) / 10.0, 1.0),
            min(float(features.get("zeek_s0_rej_count", 0) or 0) / 50.0, 1.0),
            float(features.get("zeek_app_protocol_weight", 0.2) or 0.2),
            time_sin,
            time_cos
        ]

    def learn(self, features: dict):
        self.learn_normal(features)

    def learn_normal(self, features: dict):
        """Learns normal feature combination (reinforces benign lateral/port/app bounds)."""
        if time.time() < self._reject_until:
            LOGGER.debug(
                "🛡️ [ML ANTI-POISONING] Device %s: skipping training sample (within post-threat rejection window, %.0fs remaining)",
                self.device_id, self._reject_until - time.time()
            )
            ml_poisoning_rejections_total.labels(device=self.device_id).inc()
            return

        vec = self._extract_vector(features)
        self.training.append(vec)

        if not self.warmed_up and len(self.training) >= CONFIG.get("ml_warmup_samples", 5000):
            LOGGER.info("Device %s reached warmup phase (%d samples). Initiating background fit.", self.device_id, len(self.training))
            ml_warmup_completions_total.labels(device=self.device_id).inc()
            self._fit_background()
        elif self.warmed_up:
            self._samples_since_retrain += 1
            if self._samples_since_retrain >= _RETRAIN_N:
                LOGGER.debug("Device %s reached retrain threshold (%d new samples). Retraining in background.", self.device_id, _RETRAIN_N)
                ml_retrain_events_total.labels(device=self.device_id).inc()
                self._fit_background()

    def reject_threat(self, features: dict):
        """PHASE 0 FIX: actually excludes malicious threat features from IsolationForest
        baseline fitting, instead of just logging. Opens a short rejection window so any
        learn_normal() call for this device shortly after a confirmed threat is skipped —
        preventing the anomaly model from being poisoned into treating attack traffic as
        its own new baseline."""
        self._reject_until = time.time() + REJECT_THREAT_WINDOW_SECONDS
        LOGGER.debug(
            "🛡️ [ML ANTI-POISONING] Device %s: threat features rejected from baseline training (guard window: %.0fs)",
            self.device_id, REJECT_THREAT_WINDOW_SECONDS
        )

    def _fit_background(self):
        """Schedules a background thread to fit the IsolationForest model without blocking the pipeline."""
        if self._fit_in_progress:
            return  # don't pile up concurrent fits for the same device
        self._fit_in_progress = True
        # Snapshot training data under the fit lock to avoid mutation during fit
        snapshot = list(self.training)
        threading.Thread(target=self._fit_worker, args=(snapshot,), daemon=True,
                         name=f"ml_fit_{self.device_id[:12]}").start()

    def _fit_worker(self, snapshot: list):
        """Background thread: fits IsolationForest on a snapshot, then atomically swaps the model."""
        try:
            if len(snapshot) < 50:
                return
            start_t = time.time()
            X_raw = np.array(snapshot, dtype=np.float32)
            new_model = _stamp(IsolationForest(contamination=0.01, random_state=42))
            new_model.fit(X_raw)
            elapsed = time.time() - start_t
            # Atomic model swap
            with self._fit_lock:
                self.model = new_model
                self.warmed_up = True
                self._samples_since_retrain = 0
            LOGGER.debug("[BG FIT] DeviceMLEngine for %s fitted in %.3fs on %d samples.",
                         self.device_id, elapsed, len(snapshot))
        except Exception as exc:
            LOGGER.error("Background fit failed for device %s: %s", self.device_id, exc)
        finally:
            self._fit_in_progress = False

    def score(self, features: dict) -> float:
        if not self.warmed_up:
            return 0.0
        # Atomically grab model reference (background fit may swap it)
        with self._fit_lock:
            model = self.model
        if model is None:
            return 0.0
        vec = np.array([self._extract_vector(features)], dtype=np.float32)
        
        # Guard against feature count mismatch (e.g. legacy 5-feature model vs current 9-feature)
        if hasattr(model, "n_features_in_") and model.n_features_in_ != vec.shape[1]:
            LOGGER.warning(
                "⚠️ [ML ENGINE] Feature count mismatch for device %s (model expected %d, got %d). Invalidating legacy model.",
                self.device_id, model.n_features_in_, vec.shape[1]
            )
            ml_model_invalidations_total.labels(device=self.device_id).inc()
            with self._fit_lock:
                self.warmed_up = False
                self.model = IsolationForest(contamination=0.01, random_state=42)
            return 0.0

        try:
            raw_score = self._scorer.decision_function_one(model, vec)
            anomaly_val = float(max(0.0, -raw_score))
            return min(1.0, anomaly_val)
        except Exception as exc:
            LOGGER.error("❌ Error calculating IsolationForest score for %s: %s", self.device_id, exc)
            return 0.0


class GlobalMLEngine:
    def __init__(self):
        self.training = deque(maxlen=_MAXLEN_GLOBAL)
        self.model = IsolationForest(contamination=0.01, random_state=42)
        self.warmed_up = False
        self._samples_since_retrain = 0
        self._fit_lock = threading.Lock()
        self._fit_in_progress = False
        self._scorer = _FastScorer()
        self._last_missing_feature_log = 0.0
        self._reject_until = 0.0  # PHASE 0 FIX: see DeviceMLEngine._reject_until
        LOGGER.debug("Initialized GlobalMLEngine.")

    def _validate_feature_payload(self, features: dict) -> None:
        missing = [k for k in ML_FEATURE_KEYS[:9] if k not in features]
        if missing:
            now = time.time()
            if (now - self._last_missing_feature_log) > 60.0:
                LOGGER.warning(
                    "Global ML feature payload missing keys: %s (defaults will be used). Expected dim=%d",
                    ",".join(missing), ML_FEATURE_DIM
                )
                self._last_missing_feature_log = now

    def _extract_vector(self, features: dict) -> list:
        self._validate_feature_payload(features)
        now = time.localtime()
        minutes_since_midnight = now.tm_hour * 60 + now.tm_min
        time_sin = np.sin(2 * np.pi * minutes_since_midnight / 1440.0)
        time_cos = np.cos(2 * np.pi * minutes_since_midnight / 1440.0)
        
        return [
            float(features.get("query_rate", 0) or 0), 
            float(features.get("entropy_avg", 0) or 0), 
            float(features.get("unique_domains", 0) or 0),
            float(features.get("nxdomain_ratio", 0) or 0),
            float(features.get("blocked_ratio", 0) or 0),
            min(float(features.get("zeek_outbound_bytes", 0) or 0) / 100000.0, 1.0),
            min(float(features.get("zeek_lateral_moves", 0) or 0) / 10.0, 1.0),
            min(float(features.get("zeek_s0_rej_count", 0) or 0) / 50.0, 1.0),
            float(features.get("zeek_app_protocol_weight", 0.2) or 0.2),
            time_sin,
            time_cos
        ]

    def learn(self, features: dict):
        self.learn_normal(features)

    def learn_normal(self, features: dict):
        if time.time() < self._reject_until:
            LOGGER.debug("🛡️ [ML ANTI-POISONING] Global ML: skipping training sample (within post-threat rejection window)")
            return

        vec = self._extract_vector(features)
        self.training.append(vec)

        if not self.warmed_up and len(self.training) >= _WARMUP_GLOBAL:
            LOGGER.info("Global ML Engine reached warmup phase (%d samples). Initiating background fit.", len(self.training))
            self.fit_and_update()
        elif self.warmed_up:
            self._samples_since_retrain += 1
            if self._samples_since_retrain >= _RETRAIN_N:
                LOGGER.debug("Global ML Engine reached retrain threshold. Retraining in background.")
                self.fit_and_update()

    def reject_threat(self, features: dict):
        """PHASE 0 FIX: see DeviceMLEngine.reject_threat() — same real exclusion window,
        applied to the shared global baseline model."""
        self._reject_until = time.time() + REJECT_THREAT_WINDOW_SECONDS
        LOGGER.debug("🛡️ [ML ANTI-POISONING] Global ML: threat features rejected from baseline training (guard window: %.0fs)", REJECT_THREAT_WINDOW_SECONDS)

    def fit_and_update(self):
        """Schedules a background thread to fit the global IsolationForest model."""
        if self._fit_in_progress or len(self.training) < 100:
            return
        self._fit_in_progress = True
        snapshot = list(self.training)
        threading.Thread(target=self._fit_worker, args=(snapshot,), daemon=True,
                         name="ml_fit_global").start()

    def _fit_worker(self, snapshot: list):
        try:
            start_t = time.time()
            X_raw = np.array(snapshot, dtype=np.float32)
            new_model = _stamp(IsolationForest(contamination=0.01, random_state=42))
            new_model.fit(X_raw)
            elapsed = time.time() - start_t
            with self._fit_lock:
                self.model = new_model
                self.warmed_up = True
                self._samples_since_retrain = 0
            LOGGER.debug("[BG FIT] GlobalMLEngine fitted in %.3fs on %d samples.", elapsed, len(snapshot))
        except Exception as exc:
            LOGGER.error("Background global fit failed: %s", exc)
        finally:
            self._fit_in_progress = False

    def score(self, features: dict) -> float:
        if not self.warmed_up:
            return 0.0
        with self._fit_lock:
            model = self.model
        if model is None:
            return 0.0
        vec = np.array([self._extract_vector(features)], dtype=np.float32)
        
        if hasattr(model, "n_features_in_") and model.n_features_in_ != vec.shape[1]:
            LOGGER.warning(
                "⚠️ [ML ENGINE] Feature count mismatch for Global ML (model expected %d, got %d). Invalidating legacy model.",
                model.n_features_in_, vec.shape[1]
            )
            with self._fit_lock:
                self.warmed_up = False
                self.model = IsolationForest(contamination=0.01, random_state=42)
            return 0.0

        try:
            raw_score = self._scorer.decision_function_one(model, vec)
            anomaly_val = float(max(0.0, -raw_score))
            return min(1.0, anomaly_val)
        except Exception as exc:
            LOGGER.error("❌ Error calculating Global IsolationForest score: %s", exc)
            return 0.0


class MultiDeviceMLEngine:
    # Chronic pipeline-freeze root cause, found live 2026-09-22: pipeline.py's main
    # loop calls save_models() synchronously, inline, every 60s (same block as
    # state_guard.py's own flush_to_disk() -- see that method's own
    # _FLUSH_IO_TIMEOUT_SECONDS/_bounded_io, added 2026-09-21 for the EXACT same
    # class of bug). flush_to_disk() was already bounded to 20s; save_models()
    # right next to it never was. Confirmed live via py-spy: pipeline_main_loop's
    # own MainThread caught mid-way through this exact call while the heartbeat
    # was stale. journalctl showed 25 self-restarts in one day, heartbeat-stale
    # durations up to 1819s (30+ min of zero detection coverage), 84% of which
    # needed a hard SIGKILL fallback because the graceful shutdown handler was
    # ALSO blocked on this same synchronous joblib.dump() loop. A slow SD-card
    # write (contending with Zeek's own log writes, reactive packet captures, and
    # the graph db's WAL) now degrades to "this cycle's model save is skipped,
    # retried in 60s" instead of freezing the whole pipeline.
    #
    # P2 FOLLOW-UP (third-party review, 2026-09-28): the fix above still made the
    # main loop BLOCK for up to 20s waiting on the background thread via t.join(
    # timeout=...) before giving up -- an improvement over unbounded, but still
    # real starvation every single 60s cycle whenever the disk is merely slow, not
    # hung. save_models() below is now genuinely fire-and-forget for its normal
    # periodic caller (pipeline.py step()'s 60s flush): it starts the background
    # thread and returns immediately, no join at all. Only pipeline.py's stop()
    # passes wait=True, for the same reason flush_to_disk() stays synchronous at
    # shutdown -- durability of the FINAL save matters there in a way it doesn't
    # for a save that'll just be superseded by next cycle's -- and even that wait
    # stays bounded to _SAVE_IO_TIMEOUT_SECONDS, matching flush_to_disk()'s own
    # shutdown precedent (an unbounded shutdown wait would reintroduce the exact
    # hang-then-needs-SIGKILL failure mode this whole fix chain exists to avoid).
    # self._save_thread tracks the one in-flight save (guarded by self._save_lock)
    # so a slow save from a previous cycle is never joined by a new periodic call
    # (would reintroduce the starvation) but IS joined by a shutdown call (so
    # stop() can't return before the on-disk state is actually current).
    _SAVE_IO_TIMEOUT_SECONDS = 20.0

    def __init__(self, model_dir: Optional[Any] = None, global_model_path: Optional[Any] = None, **kwargs):
        self._lock = threading.RLock()
        self.global_engine = GlobalMLEngine()
        self.devices = OrderedDict()
        self.max_active_devices = 200
        # path -> the model object last written there (or loaded from there). A model
        # is only ever replaced, never mutated in place (background fits swap in a new
        # object), so an identity check tells whether the file is already current.
        # Before (2026-09-23, live profiling on .94): every 60 s flush re-dumped every
        # warmed-up model (13 files, ~15 MB) although each refits only every
        # _RETRAIN_N samples -- ~6% of the main loop's wall time spent waiting on it.
        self._persisted = {}
        # Guards save_models()'s background-thread bookkeeping -- see that method's
        # own docstring and _SAVE_IO_TIMEOUT_SECONDS's comment above.
        self._save_lock = threading.Lock()
        self._save_thread: Optional[threading.Thread] = None
        self.model_dir = Path(model_dir) if model_dir else None
        if self.model_dir:
            self.model_dir.mkdir(parents=True, exist_ok=True)
            self.global_model_path = Path(global_model_path) if global_model_path else (self.model_dir / "global_isolation_forest.pkl")
        else:
            self.global_model_path = Path(global_model_path) if global_model_path else None
        LOGGER.info("Initialized MultiDeviceMLEngine with model persistence dir: %s", self.model_dir)

    def _get_or_create_device(self, device_id: str) -> DeviceMLEngine:
        with self._lock:
            if device_id in self.devices:
                self.devices.move_to_end(device_id)
                return self.devices[device_id]
        
            engine = DeviceMLEngine(device_id)
            if len(self.devices) >= self.max_active_devices:
                evicted_id, evicted_engine = self.devices.popitem(last=False)
                LOGGER.debug("Evicted oldest LRU ML engine for device: %s", evicted_id)
        
            self.devices[device_id] = engine
            return engine

    def learn(self, device_id: str, features: dict):
        self.learn_normal(device_id, features)

    def learn_normal(self, device_id: str, features: dict):
        engine = self._get_or_create_device(device_id)
        engine.learn_normal(features)
        self.global_engine.learn_normal(features)

    def reject_threat(self, device_id: str, features: dict):
        engine = self._get_or_create_device(device_id)
        engine.reject_threat(features)
        self.global_engine.reject_threat(features)

    @property
    def global_warmed_up(self) -> bool:
        """M7: Expose global model warmup status for pipeline health metrics."""
        return self.global_engine.warmed_up

    def score(self, device_id: str, features: dict) -> float:
        if device_id in self.devices and self.devices[device_id].warmed_up:
            return self.devices[device_id].score(features)
        return self.global_engine.score(features)

    def migrate_device(self, old_id: str, new_id: str) -> bool:
        if old_id not in self.devices:
            return False

        engine = self.devices.pop(old_id)
        engine.device_id = new_id
        self.devices[new_id] = engine
        self.devices.move_to_end(new_id)

        if self.model_dir:
            old_path = self.model_dir / f"{old_id}.pkl"
            new_path = self.model_dir / f"{new_id}.pkl"
            self._persisted.pop(old_path, None)
            self._persisted.pop(new_path, None)
            if old_path.exists():
                try:
                    old_path.rename(new_path)
                    LOGGER.info("Migrated physical ML model: %s -> %s", old_id, new_id)
                except OSError as exc:
                    LOGGER.error("Failed to rename ML model file during migration: %s", exc)

        LOGGER.debug("Successfully migrated ML Engine state for %s to %s", old_id, new_id)
        return True

    def discard_device(self, device_id: str, reason: str = "merge") -> bool:
        """Drops a device's in-memory ML engine and deletes its on-disk model file, if
        any. Used by the device-identity fragmentation fix's merge_into_canonical(): an
        orphan device_id being folded into a richer canonical identity has its own
        engine/model DISCARDED (not moved) since migrate_device()'s overwrite-the-
        destination semantics would be wrong here — the destination (canonical_id)
        already has its own live engine that must not be clobbered by the orphan's
        near-empty one. Safe no-op if the device has no in-memory engine and no model
        file on disk. `reason` ("merge" vs "prune") only distinguishes which caller
        triggered this for dashboard transparency -- it has no effect on behavior."""
        had_engine = self.devices.pop(device_id, None) is not None
        removed_file = False
        if self.model_dir:
            model_path = self.model_dir / f"{device_id}.pkl"
            self._persisted.pop(model_path, None)
            if model_path.exists():
                try:
                    model_path.unlink()
                    removed_file = True
                except OSError as exc:
                    LOGGER.error("Failed to remove discarded ML model file for %s: %s", device_id, exc)
        if had_engine or removed_file:
            LOGGER.info("Discarded ML Engine state for merged-away device %s (model file removed: %s)", device_id, removed_file)
            device_profile_discards_total.labels(reason=reason).inc()
        return had_engine or removed_file

    @staticmethod
    def _atomic_dump(model, path: Path) -> None:
        """BUGFIX (live, 2026-09-23): joblib.dump() used to write straight into the
        final file. A process killed mid-write -- the SIGKILL shutdown fallback, or
        interpreter exit while an abandoned _bounded_io save thread was still writing --
        left a truncated .pkl ("EOF: reading array data"). On .94 one such file
        (written 2026-09-22 21:00) then made load_models() fail on every restart.
        Write a sibling temp file, then os.replace(): a kill at any instant leaves
        either the previous complete model or the new complete model, never a partial."""
        tmp = path.with_name(path.name + ".tmp")
        joblib.dump(model, tmp)
        os.replace(tmp, path)

    def save_models(self, wait: bool = False):
        """Persists every warmed-up model whose in-memory object has changed since
        its last save. Fire-and-forget by default (see _SAVE_IO_TIMEOUT_SECONDS's
        comment) -- starts a background thread and returns immediately, never
        blocking the caller. Pass wait=True (pipeline.py's stop() only) to block
        until the save genuinely completes, bounded to _SAVE_IO_TIMEOUT_SECONDS."""
        if not self.model_dir:
            return

        def _save_if_changed(model, path: Path) -> bool:
            if self._persisted.get(path) is model and path.exists():
                return False
            self._atomic_dump(model, path)
            self._persisted[path] = model
            return True

        def _do_save():
            try:
                saved_devs = 0
                if self.global_model_path and self.global_engine.warmed_up:
                    _save_if_changed(self.global_engine.model, self.global_model_path)

                with self._lock:
                    devices_snapshot = list(self.devices.items())

                for dev_id, engine in devices_snapshot:
                    if engine.warmed_up and _save_if_changed(engine.model, self.model_dir / f"{dev_id}.pkl"):
                        saved_devs += 1
                if saved_devs:
                    LOGGER.info("Persisted %d changed Device ML model(s) to disk.", saved_devs)
            except Exception as exc:
                LOGGER.error("Failed to save ML models: %s", exc)
            finally:
                with self._save_lock:
                    self._save_thread = None

        with self._save_lock:
            in_flight = self._save_thread
            if in_flight is None:
                t = threading.Thread(target=_do_save, daemon=True, name="ml_save_io")
                self._save_thread = t
                t.start()
            else:
                t = in_flight
                if not wait:
                    LOGGER.debug(
                        "Skipping this cycle's ML model save -- a previous "
                        "background save is still running; the next periodic "
                        "flush will catch up."
                    )
                    return

        if wait:
            t.join(timeout=self._SAVE_IO_TIMEOUT_SECONDS)
            if t.is_alive():
                LOGGER.error(
                    "ML model save did not complete within %.0fs at shutdown "
                    "(likely a slow/stalled disk write) -- leaving it to finish "
                    "on its own daemon thread; this save may be lost if the "
                    "process exits before it does.", self._SAVE_IO_TIMEOUT_SECONDS,
                )

    def _verify_model_shape(self, model, expected_features: int = 11) -> bool:
        if hasattr(model, "n_features_in_"):
            return model.n_features_in_ == expected_features
        return hasattr(model, "decision_function")

    def _discard_unreadable_model(self, path: Path, exc: Exception) -> None:
        """A model file that can't be read is useless and would fail again on every
        start -- log exactly which one and why, remove it, count it, carry on. The
        device simply re-learns (warmup) like a new one."""
        LOGGER.error("ML model file %s is unreadable (%s) -- removing it; that device re-learns from scratch.",
                     path.name, exc)
        try:
            path.unlink()
        except OSError as unlink_exc:
            LOGGER.error("Could not remove unreadable ML model file %s: %s", path.name, unlink_exc)
        device_profile_discards_total.labels(reason="corrupt").inc()

    def load_models(self):
        """BUGFIX (live, 2026-09-23): one try/except used to wrap the WHOLE load, so a
        single unreadable file aborted it -- every model after it in directory order
        was silently dropped too, on every restart, and the bad file was never removed
        (on .94: 1 truncated file cost 8 of 13 device models). Each file is now loaded
        independently."""
        if not self.model_dir:
            return
        # Leftovers of a save interrupted before its atomic rename -- never valid models.
        for stray in self.model_dir.glob("*.pkl.tmp"):
            try:
                stray.unlink()
            except OSError:
                pass

        if self.global_model_path and self.global_model_path.exists():
            try:
                loaded = joblib.load(self.global_model_path)
                target_model = loaded[0] if isinstance(loaded, tuple) else loaded
                if _model_scheme(target_model) != DNS_RATIO_SCHEME:
                    LOGGER.warning("Global ML model learned under DNS ratio scheme %s, now %s: discarding; it re-learns "
                                   "(scores 0 until warm).", _model_scheme(target_model), DNS_RATIO_SCHEME)
                    ml_model_invalidations_total.labels(device="global").inc()
                    self.global_model_path.unlink()
                elif self._verify_model_shape(target_model, expected_features=11):
                    self.global_engine.model = target_model
                    self.global_engine.warmed_up = True
                    self._persisted[self.global_model_path] = target_model
                    LOGGER.info("Loaded Global ML Model from disk.")
                else:
                    LOGGER.warning("Legacy global ML model found. Discarding and resetting to current 11-feature schema.")
                    self.global_model_path.unlink()
            except Exception as exc:
                self._discard_unreadable_model(self.global_model_path, exc)

        loaded_devs = 0
        discarded = 0
        for dev_path in self.model_dir.glob("*.pkl"):
            if dev_path == self.global_model_path:
                continue
            dev_id = dev_path.stem
            try:
                loaded = joblib.load(dev_path)
            except Exception as exc:
                self._discard_unreadable_model(dev_path, exc)
                discarded += 1
                continue
            target_model = loaded[0] if isinstance(loaded, tuple) else loaded
            if _model_scheme(target_model) != DNS_RATIO_SCHEME:
                LOGGER.warning("Device ML model for %s learned under DNS ratio scheme %s, now %s: discarding; the "
                               "device re-learns (global model meanwhile).", dev_id, _model_scheme(target_model),
                               DNS_RATIO_SCHEME)
                ml_model_invalidations_total.labels(device=dev_id).inc()
                dev_path.unlink()
                discarded += 1
                continue
            engine = self._get_or_create_device(dev_id)
            if self._verify_model_shape(target_model, expected_features=11):
                engine.model = target_model
                engine.warmed_up = True
                self._persisted[dev_path] = target_model
                loaded_devs += 1
            else:
                LOGGER.warning("Legacy device ML model for %s found with incompatible feature shape. Discarding.", dev_id)
                dev_path.unlink()

        LOGGER.info("Loaded %d compatible 11-feature Device ML models from disk (%d unreadable or outdated file(s) removed).",
                    loaded_devs, discarded)


# Backwards-compatibility alias for main.py / pipeline.py imports
MLRegistry = MultiDeviceMLEngine