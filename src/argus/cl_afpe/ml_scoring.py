"""
CL-AFPE model scoring: Stage 2 (a LightGBM classifier exported to ONNX) and Stage 3 (FastEmbed similarity of a
destination name to known vendor telemetry), plus text embedding for the alert search.

The models are trained by src/scripts/train_fp_classifier.py (nightly) into the model dir (Path(config
["model_path"]).parent): fp_classifier.onnx and fastembed_cache/. This module only reads them:

  - warm_up_async() loads both in a background thread at start-up, so the first alert never waits for a model load
    or download inside the detection loop;
  - the ONNX model is reloaded when the nightly retrain replaces the file (checked at most every
    _MODEL_RECHECK_SECONDS), so scoring always uses the latest model;
  - a model that is not available yet degrades to None (Stage 2) or the static rule fallback (Stage 3);
  - the classifier is used only when fp_classifier_quality.json (written by the trainer after its quality gate)
    vouches for exactly that file (sha256) and the current feature version. A model without it -- e.g. one trained
    before the gate existed -- is not used.
"""
import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger("home_ids.cl_afpe.ml")

_MODEL_RECHECK_SECONDS = 60.0

# Bumped when the meaning of the feature vector changes; a model trained for another version is not loaded.
# 2 = feature 5 (historical_fp_flag) neutralised in training (2026-10-03).
FP_FEATURE_VERSION = 2
QUALITY_FILE_NAME = "fp_classifier_quality.json"


def file_sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
EMBED_MODEL_NAME = "BAAI/bge-small-en-v1.5"

# Reference set for Stage 3: known-legitimate vendor telemetry names. A queried destination whose name embeds close to
# one of these looks like routine telemetry. Add entries here; they are re-embedded at the next start.
SAFE_VENDOR_PATTERNS: List[Dict[str, str]] = [
    # Developer error tracking & APM
    {"label": "Sentry Ingest US", "text": "o1234.ingest.us.sentry.io"},
    {"label": "Sentry Ingest EU", "text": "o9999.ingest.de.sentry.io"},
    {"label": "Sentry API", "text": "sentry.io"},
    {"label": "Datadog APM", "text": "trace.agent.datadoghq.com"},
    {"label": "New Relic APM", "text": "collector.newrelic.com"},
    {"label": "Grafana Telemetry", "text": "telemetry.grafana.com"},
    # Browsers
    {"label": "Brave Usage Ping", "text": "usage-ping.brave.com"},
    {"label": "Firefox Telemetry", "text": "incoming.telemetry.mozilla.org"},
    {"label": "Chrome SafeBrowsing", "text": "safebrowsing.googleapis.com"},
    {"label": "Chrome Update", "text": "update.googleapis.com"},
    # Antivirus & security cloud
    {"label": "Bitdefender NIMBUS", "text": "nimbus.bitdefender.net"},
    {"label": "Bitdefender EU NIMBUS", "text": "eu.nimbus.bitdefender.net"},
    {"label": "Bitdefender Telemetry", "text": "telemetry.bitdefender.com"},
    {"label": "Norton Cloud", "text": "lookup.norton.com"},
    {"label": "Malwarebytes Telemetry", "text": "telemetry.malwarebytes.com"},
    # Apple
    {"label": "Apple Push Notification", "text": "32-courier.push.apple.com"},
    {"label": "Apple iCloud Sync", "text": "p12-caldav.icloud.com"},
    {"label": "Apple Software Update", "text": "swscan.apple.com"},
    {"label": "Apple Device Activation", "text": "albert.apple.com"},
    {"label": "Apple Diagnostics", "text": "radarsubmissions.apple.com"},
    # Google
    {"label": "Google GMS Check-in", "text": "android.clients.google.com"},
    {"label": "Google Optimization Guide", "text": "optimizationguide-pa.googleapis.com"},
    {"label": "Firebase Database", "text": "project.firebaseio.com"},
    # Microsoft / Windows
    {"label": "Windows Update", "text": "windowsupdate.microsoft.com"},
    {"label": "Microsoft NCSI", "text": "www.msftncsi.com"},
    {"label": "Office 365", "text": "outlook.office365.com"},
    # Amazon / Alexa
    {"label": "Amazon Captive Portal", "text": "captive.amazon.com"},
    {"label": "FireTV Captive Portal", "text": "firetvcaptiveportal.com"},
    {"label": "Alexa Smart Home", "text": "alexa.amazon.com"},
    # CDN & infrastructure
    {"label": "Cloudflare", "text": "cloudflare.com"},
    {"label": "Fastly CDN", "text": "fastly.net"},
    {"label": "Akamai CDN", "text": "akamaized.net"},
    {"label": "Let's Encrypt ACME", "text": "acme-v02.api.letsencrypt.org"},
    # Package registries & developer APIs
    {"label": "Wordnik Dictionary API", "text": "www.wordnik.com"},
    {"label": "NPM Registry", "text": "registry.npmjs.org"},
    {"label": "PyPI Package Index", "text": "pypi.org"},
    {"label": "GitHub API", "text": "api.github.com"},
    {"label": "DockerHub", "text": "registry-1.docker.io"},
    # Smart home & IoT
    {"label": "TP-Link Tapo Cloud", "text": "euw1-api.tplinkcloud.com"},
    {"label": "Tuya Smart Home", "text": "a1.tuyaus.com"},
    {"label": "Synology QuickConnect", "text": "global.quickconnect.to"},
    {"label": "Sonos Music", "text": "music.sonos.com"},
    {"label": "Samsung SmartThings", "text": "samsungcloud.com"},
    # Streaming
    {"label": "Netflix CDN", "text": "nflxvideo.net"},
    {"label": "Spotify CDN", "text": "scdn.co"},
    # Router & local services
    {"label": "Fritz!Box Local UI", "text": "fritz.box"},
    {"label": "Fritz!Box MyFRITZ! DDNS", "text": "myfritz.net"},
    {"label": "Local Grafana Dashboard", "text": "grafana.lan"},
    {"label": "Local Prometheus", "text": "prometheus.lan"},
    {"label": "Local Pi-hole", "text": "pihole.lan"},
    {"label": "Home Assistant Local", "text": "homeassistant.local"},
    # App analytics
    {"label": "Napps2 App Backend", "text": "tp.napps-2.com"},
]

# Stage 2/3 combination weights, and the score Stage 2 gives when no classifier is loaded.
LGBM_WEIGHT = 0.45
EMBED_WEIGHT = 0.55
NEUTRAL_LGBM_SCORE = 0.50


def build_feature_vector(features: Dict[str, Any], domain: str, is_trust_cached: bool) -> List[float]:
    """Matches _stage2_lgbm()'s real 11-feature vector construction exactly (lines
    1310-1377) -- MUST stay in lockstep with train_fp_classifier.py's own
    extract_features_from_alert(), the same "no shared helper by design"
    relationship the earlier engine's own docstring documents (one runs in the always-on pipeline
    process, the other in a separate weekly retrain script); argus joins that
    relationship rather than inventing a third, independently-drifting copy."""
    from utils import entropy as compute_entropy

    tranco_rank = float(features.get("tranco_rank", 0) or 0)
    f0_tranco = max(0.0, 1.0 - (tranco_rank / 1_000_000.0)) if tranco_rank > 0 else 0.0

    label = domain.split(".")[0] if domain else ""
    f1_entropy = min(compute_entropy(label) / 5.0, 1.0)

    max_label = float(features.get("max_label_length", 0) or 0)
    f2_label_len = min(max_label / 60.0, 1.0)

    out_z = float(features.get("outbound_bytes_z", 0.0) or 0.0)
    f3_out_z = min(max(out_z, 0.0) / 10.0, 1.0)

    dev_type_weights = {
        "laptop": 0.5, "desktop": 0.5,
        "phone": 0.4, "tablet": 0.4,
        "smart_tv": 0.3, "gaming_console": 0.3,
        "printer": 0.2, "nas": 0.2,
        "iot": 0.1, "camera": 0.1,
        "unknown": 0.3,
    }
    dev_type = str(features.get("device_type", "unknown") or "unknown")
    f4_dev_type = dev_type_weights.get(dev_type, 0.3)

    f5_hist_fp = 1.0 if is_trust_cached else 0.0

    f6_lateral = min(float(features.get("zeek_lateral_moves", 0) or 0) / 10.0, 1.0)
    f7_port_scans = min(float(features.get("zeek_s0_rej_count", 0) or 0) / 50.0, 1.0)
    f8_app_proto = min(max(float(features.get("zeek_app_protocol_weight", 0.2) or 0.2), 0.0), 1.0)
    f9_arp_sweep = min(float(features.get("zeek_arp_sweep_count", 0) or 0) / 20.0, 1.0)
    f10_dns_evasion = min(max(float(features.get("zeek_dns_evasion_ratio", 0.0) or 0.0), 0.0), 1.0)

    return [f0_tranco, f1_entropy, f2_label_len, f3_out_z, f4_dev_type, f5_hist_fp,
            f6_lateral, f7_port_scans, f8_app_proto, f9_arp_sweep, f10_dns_evasion]


def parse_onnx_prob(outputs: list) -> float:
    """Matches _parse_onnx_prob() exactly: handles both skl2onnx ZipMap format
    ([{0: p0, 1: p1}]) and raw 2D/1D numpy array formats, always extracting class-1
    probability; falls back to the neutral sentinel if unparseable."""
    if not outputs:
        return NEUTRAL_LGBM_SCORE
    target = outputs[1] if len(outputs) > 1 else outputs[0]
    if isinstance(target, list) and len(target) > 0 and isinstance(target[0], dict):
        d = target[0]
        val = d.get(1, d.get(1.0, d.get("1", NEUTRAL_LGBM_SCORE)))
        return float(val)
    try:
        import numpy as np
        arr = np.array(target)
        if arr.ndim == 2 and arr.shape[1] >= 2:
            return float(arr[0][1])
        elif arr.ndim == 1 and arr.shape[0] >= 2:
            return float(arr[1])
        elif arr.size == 1:
            return float(arr.flat[0])
    except Exception:
        pass
    return NEUTRAL_LGBM_SCORE


def stage3_rule_fallback(domain: str) -> Tuple[float, str]:
    """Matches _stage3_rule_fallback() exactly -- the static rule-based fallback
    used when FastEmbed itself isn't available/loaded."""
    from utils import _is_cdn_or_cloud_domain, is_telemetry_domain
    if is_telemetry_domain(domain):
        return 0.92, "static rule: known telemetry domain"
    if _is_cdn_or_cloud_domain(domain):
        return 0.88, "static rule: known CDN/cloud vendor domain"
    return 0.05, "static rule: no vendor pattern match"


def combine_scores(lgbm_prob: Optional[float], embed_sim: Optional[float],
                     embed_similarity_threshold: float) -> float:
    """Matches evaluate()'s real 3-way weighted-combination logic exactly:
    embed_sim is None -> lgbm alone (never blended with a fabricated 0.0); lgbm at
    the not-ready sentinel (0.50) AND embed clears the threshold -> embed alone
    (lets Stage 3 decide when Stage 2 has nothing real to contribute); else the
    weighted blend."""
    if embed_sim is None:
        return lgbm_prob if lgbm_prob is not None else NEUTRAL_LGBM_SCORE
    if lgbm_prob is None:
        lgbm_prob = NEUTRAL_LGBM_SCORE
    if lgbm_prob == NEUTRAL_LGBM_SCORE and embed_sim >= embed_similarity_threshold:
        return embed_sim
    return lgbm_prob * LGBM_WEIGHT + embed_sim * EMBED_WEIGHT


class MLScorer:
    """Reads the trained ONNX classifier and the FastEmbed model from `model_dir`; never trains or writes there."""

    def __init__(self, model_dir: str):
        self.model_dir = Path(model_dir)
        self._lock = threading.Lock()
        self._lgbm_session = None
        self._lgbm_mtime = None
        self._lgbm_checked_at = 0.0
        self._embed_model = None
        self._safe_vendor_embeddings = None
        self._safe_vendor_labels: List[str] = []
        self._embed_load_attempted = False

    # --- loading -------------------------------------------------------------------------------------------
    def warm_up_async(self) -> None:
        """Loads both models in a daemon thread (start-up), so no detection cycle waits for them."""
        def _run():
            self._ensure_lgbm_loaded(force_check=True)
            self._ensure_embed_loaded()
        threading.Thread(target=_run, name="cl-afpe-model-warmup", daemon=True).start()

    def ready(self) -> Dict[str, bool]:
        return {"classifier": self._lgbm_session is not None, "embeddings": self._embed_model is not None}

    def _ensure_lgbm_loaded(self, force_check: bool = False) -> None:
        now = time.time()
        if not force_check and now - self._lgbm_checked_at < _MODEL_RECHECK_SECONDS:
            return
        self._lgbm_checked_at = now
        onnx_path = self.model_dir / "fp_classifier.onnx"
        quality_path = self.model_dir / QUALITY_FILE_NAME
        try:
            mtime = (onnx_path.stat().st_mtime, quality_path.stat().st_mtime if quality_path.exists() else None)
        except OSError:
            return  # not trained yet: Stage 2 unavailable
        if mtime == self._lgbm_mtime:
            return
        refusal = self._quality_refusal(onnx_path, quality_path)
        if refusal:
            with self._lock:
                self._lgbm_session, self._lgbm_mtime = None, mtime
            LOGGER.warning("Not using the false-positive classifier in %s: %s", self.model_dir, refusal)
            return
        try:
            import onnxruntime as ort
            sess_opts = ort.SessionOptions()
            sess_opts.intra_op_num_threads = 1
            sess_opts.inter_op_num_threads = 1
            sess_opts.log_severity_level = 3
            session = ort.InferenceSession(str(onnx_path), sess_options=sess_opts)
            with self._lock:
                self._lgbm_session, self._lgbm_mtime = session, mtime
            LOGGER.info("Loaded the false-positive classifier from %s", onnx_path)
        except ImportError:
            LOGGER.warning("onnxruntime not installed -- Stage 2 unavailable.")
            self._lgbm_mtime = mtime
        except Exception as e:
            LOGGER.error("Failed to load %s: %s", onnx_path, e, exc_info=True)
            self._lgbm_mtime = mtime   # don't retry a broken file every cycle; a new file has a new mtime

    @staticmethod
    def _quality_refusal(onnx_path: Path, quality_path: Path) -> str:
        """Why the classifier must not be used, or "" when its quality file vouches for it."""
        try:
            quality = json.loads(quality_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return f"no {QUALITY_FILE_NAME} (trained before the quality gate, or the gate rejected every retrain)"
        except (OSError, ValueError) as e:
            return f"unreadable {QUALITY_FILE_NAME}: {e}"
        if not quality.get("passed"):
            return "its quality gate did not pass"
        if quality.get("feature_version") != FP_FEATURE_VERSION:
            return f"trained for feature version {quality.get('feature_version')}, engine uses {FP_FEATURE_VERSION}"
        try:
            if quality.get("model_sha256") != file_sha256(onnx_path):
                return "the model file does not match the one its quality gate checked"
        except OSError as e:
            return f"cannot read the model file: {e}"
        return ""

    def _ensure_embed_loaded(self) -> None:
        with self._lock:
            if self._embed_load_attempted:
                return
            self._embed_load_attempted = True
        try:
            from fastembed import TextEmbedding
            import numpy as np

            model = TextEmbedding(model_name=EMBED_MODEL_NAME, cache_dir=str(self.model_dir / "fastembed_cache"))
            labels = [p["label"] for p in SAFE_VENDOR_PATTERNS]
            embed_matrix = np.array(list(model.embed([p["text"] for p in SAFE_VENDOR_PATTERNS])), dtype=np.float32)
            norms = np.linalg.norm(embed_matrix, axis=1, keepdims=True) + 1e-9
            self._safe_vendor_embeddings = embed_matrix / norms
            self._safe_vendor_labels = labels
            self._embed_model = model
            LOGGER.info("Loaded FastEmbed %s with %d vendor patterns.", EMBED_MODEL_NAME, len(labels))
        except ImportError:
            LOGGER.warning("fastembed not installed -- Stage 3 falls back to static rules.")
        except Exception as e:
            LOGGER.error("Failed to load FastEmbed: %s", e, exc_info=True)

    # --- helpers for callers outside evaluate() ------------------------------------------------------------------
    def embed_text(self, text: str) -> Optional[bytes]:
        """float32 bytes of `text`'s embedding (alert search), or None while the model is not loaded."""
        if self._embed_model is None or not text:
            return None
        try:
            import numpy as np
            return np.array(list(self._embed_model.embed([text]))[0], dtype=np.float32).tobytes()
        except Exception as exc:
            LOGGER.debug("embed_text failed (the alert just won't be searchable): %s", exc)
            return None

    def vendor_similarity(self, domain: str) -> Tuple[float, str]:
        """(similarity, best label) of a destination name to known vendor telemetry; the static rule fallback while
        FastEmbed is not loaded; (0.0, ...) for a placeholder name. Never blocks on a model load."""
        if not domain or domain.strip().lower() in ("unknown", "null", "none"):
            return 0.0, "N/A (no resolved hostname/domain)"
        if self._embed_model is not None:
            sim, label = self.score_stage3(domain)
            if sim is not None:
                return sim, label
        return stage3_rule_fallback(domain)

    def score_stage2(self, features: Dict[str, Any], domain: str, is_trust_cached: bool) -> Optional[float]:
        """Returns P(FP) in [0,1], or None if the model isn't ready -- caller
        substitutes the neutral 0.50 sentinel, matching the earlier engine exactly."""
        self._ensure_lgbm_loaded()
        session = self._lgbm_session
        if session is None:
            return None
        try:
            import numpy as np
            feat_vec_full = build_feature_vector(features, domain, is_trust_cached)
            input_spec = session.get_inputs()[0]
            expected_feats = (
                input_spec.shape[1] if (len(input_spec.shape) > 1 and isinstance(input_spec.shape[1], int)) else 6
            )
            # Matches the earlier engine's own 6-feature legacy / 9-feature multi-threat / 11-feature
            # ARP-sweep+DNS-evasion shape handling -- an older exported model still
            # loads and runs correctly on whichever shape it was actually trained
            # with, it just won't have the newer-dimension signal until retrained.
            if expected_feats == 6:
                feat_vec = np.array([feat_vec_full[:6]], dtype=np.float32)
            elif expected_feats == 11:
                feat_vec = np.array([feat_vec_full], dtype=np.float32)
            else:
                feat_vec = np.array([feat_vec_full[:9]], dtype=np.float32)
            input_name = input_spec.name
            outputs = session.run(None, {input_name: feat_vec})
            return parse_onnx_prob(outputs)
        except Exception as e:
            LOGGER.error("Stage 2 ONNX inference error: %s", e, exc_info=True)
            return None

    def score_stage3(self, domain: str) -> Tuple[Optional[float], Optional[str]]:
        """Returns (cosine_similarity, best_match_label), or (None, None) if
        FastEmbed isn't ready -- caller falls back to stage3_rule_fallback()."""
        self._ensure_embed_loaded()
        if self._embed_model is None or self._safe_vendor_embeddings is None:
            return None, None
        try:
            import numpy as np
            query_vec = list(self._embed_model.embed([domain]))[0]
            query_vec = np.array(query_vec, dtype=np.float32)
            q_norm = query_vec / (np.linalg.norm(query_vec) + 1e-9)
            similarities = self._safe_vendor_embeddings @ q_norm
            best_idx = int(np.argmax(similarities))
            best_sim = float(similarities[best_idx])
            best_label = self._safe_vendor_labels[best_idx] if best_idx < len(self._safe_vendor_labels) else "unknown"
            return best_sim, best_label
        except Exception as e:
            LOGGER.error("Stage 3 FastEmbed error: %s", e, exc_info=True)
            return None, None
