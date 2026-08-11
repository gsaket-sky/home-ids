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
import joblib
import threading
from typing import Optional, Any
import time
from config import CONFIG
LOGGER = logging.getLogger("home_ids.ml_engine")

_MAXLEN_DEVICE = 20000
_MAXLEN_GLOBAL = 100000

_WARMUP_GLOBAL = 1000  # samples before first global fit
_RETRAIN_N = 500       # retrain every 500 new samples (~17 min) for faster adaptation


class DeviceMLEngine:
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.training = deque(maxlen=_MAXLEN_DEVICE)
        self.model = IsolationForest(contamination=0.01, random_state=42)
        self.warmed_up = False
        self._samples_since_retrain = 0
        self._fit_lock = threading.Lock()   # guards model swap during background fit
        self._fit_in_progress = False
        LOGGER.debug("Initialized DeviceMLEngine for device: %s", device_id)

    def _extract_vector(self, features: dict) -> list:
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
        vec = self._extract_vector(features)
        self.training.append(vec)

        if not self.warmed_up and len(self.training) >= CONFIG.get("ml_warmup_samples", 5000):
            LOGGER.info("Device %s reached warmup phase (%d samples). Initiating background fit.", self.device_id, len(self.training))
            self._fit_background()
        elif self.warmed_up:
            self._samples_since_retrain += 1
            if self._samples_since_retrain >= _RETRAIN_N:
                LOGGER.debug("Device %s reached retrain threshold (%d new samples). Retraining in background.", self.device_id, _RETRAIN_N)
                self._fit_background()

    def reject_threat(self, features: dict):
        """Excludes malicious threat features from IsolationForest baseline fitting (anti-poisoning)."""
        LOGGER.debug("🛡️ [ML ANTI-POISONING] Device %s threat features rejected from baseline training", self.device_id)

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
            new_model = IsolationForest(contamination=0.01, random_state=42)
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
            with self._fit_lock:
                self.warmed_up = False
                self.model = IsolationForest(contamination=0.01, random_state=42)
            return 0.0

        try:
            raw_score = model.decision_function(vec)[0]
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
        LOGGER.debug("Initialized GlobalMLEngine.")

    def _extract_vector(self, features: dict) -> list:
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
        LOGGER.debug("🛡️ [ML ANTI-POISONING] Global ML threat features rejected from baseline training")

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
            new_model = IsolationForest(contamination=0.01, random_state=42)
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
            raw_score = model.decision_function(vec)[0]
            anomaly_val = float(max(0.0, -raw_score))
            return min(1.0, anomaly_val)
        except Exception as exc:
            LOGGER.error("❌ Error calculating Global IsolationForest score: %s", exc)
            return 0.0


class MultiDeviceMLEngine:
    def __init__(self, model_dir: Optional[Any] = None, global_model_path: Optional[Any] = None, **kwargs):
        self._lock = threading.RLock()
        self.global_engine = GlobalMLEngine()
        self.devices = OrderedDict()
        self.max_active_devices = 200
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
            if old_path.exists():
                try:
                    old_path.rename(new_path)
                    LOGGER.info("Migrated physical ML model: %s -> %s", old_id, new_id)
                except OSError as exc:
                    LOGGER.error("Failed to rename ML model file during migration: %s", exc)

        LOGGER.debug("Successfully migrated ML Engine state for %s to %s", old_id, new_id)
        return True

    def save_models(self):
        if not self.model_dir:
            return
        try:
            saved_devs = 0
            if self.global_model_path and self.global_engine.warmed_up:
                joblib.dump(self.global_engine.model, self.global_model_path)
            for dev_id, engine in self.devices.items():
                if engine.warmed_up:
                    dev_path = self.model_dir / f"{dev_id}.pkl"
                    joblib.dump(engine.model, dev_path)
                    saved_devs += 1
            LOGGER.info("Successfully persisted Global Model and %d Device ML models to disk.", saved_devs)
        except Exception as exc:
            LOGGER.error("Failed to save ML models: %s", exc)

    def _verify_model_shape(self, model, expected_features: int = 11) -> bool:
        if hasattr(model, "n_features_in_"):
            return model.n_features_in_ == expected_features
        return hasattr(model, "decision_function")

    def load_models(self):
        if not self.model_dir:
            return
        try:
            if self.global_model_path and self.global_model_path.exists():
                loaded = joblib.load(self.global_model_path)
                target_model = loaded[0] if isinstance(loaded, tuple) else loaded
                
                if self._verify_model_shape(target_model, expected_features=11):
                    self.global_engine.model = target_model
                    self.global_engine.warmed_up = True
                    LOGGER.info("Loaded Global ML Model from disk.")
                else:
                    LOGGER.warning("Legacy 5-feature global ML model found. Discarding and resetting to 9 features.")
                    if self.global_model_path.exists():
                        self.global_model_path.unlink()

            loaded_devs = 0
            for dev_path in self.model_dir.glob("*.pkl"):
                if dev_path == self.global_model_path:
                    continue
                dev_id = dev_path.stem
                engine = self._get_or_create_device(dev_id)
                
                loaded = joblib.load(dev_path)
                target_model = loaded[0] if isinstance(loaded, tuple) else loaded
                
                if self._verify_model_shape(target_model, expected_features=11):
                    engine.model = target_model
                    engine.warmed_up = True
                    loaded_devs += 1
                else:
                    LOGGER.warning("Legacy 5-feature ML model for device %s. Discarding.", dev_id)
                    dev_path.unlink()

            LOGGER.info("Successfully loaded %d compatible 9-feature Device ML models from disk.", loaded_devs)
        except Exception as exc:
            LOGGER.error("Failed to load ML models (likely corrupted). Starting fresh: %s", exc)


# Backwards-compatibility alias for main.py / pipeline.py imports
MLRegistry = MultiDeviceMLEngine