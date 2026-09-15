"""
v13 CL-AFPE ML scoring (Phase 6d -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Reuses v-current's ALREADY-TRAINED LightGBM ONNX model and FastEmbed vendor-pattern
embeddings, read-only -- no separate training pipeline. Ported from a direct read of
fp_engine.py's real _stage2_lgbm()/_parse_onnx_prob()/_stage3_embed()/
_stage3_rule_fallback()/_load_lgbm_model()/_load_embed_model() (lines 1279-1498,
2515-2726).

THE DESIGN DECISION THIS MODULE EXISTS TO PROVE OUT: loads from the SAME model_dir
v-current already writes to (Path(config["model_path"]).parent, matching v1's own
path resolution exactly) -- train_fp_classifier.py's weekly retrain keeps producing
fp_classifier.onnx/fp_calibration.json/the fastembed_cache regardless of who reads
them. This module is a READER, not a second trainer -- there is no training-data-
continuity problem to solve, unlike what the original full-architecture plan feared
before this file existed.

Deliberately NOT ported: placeholder-model generation (_generate_placeholder_lgbm).
If v-current hasn't produced a real model yet, this degrades to Stage 2 unavailable
(None) -- the same "model not ready" fallback v1 itself uses while ITS OWN loader
thread is still warming up. Generating a SEPARATE placeholder here would violate
the single-source-of-truth design this whole phase exists to establish.

Vendor patterns for Stage 3 are reused directly from fp_engine.py's own
_build_safe_vendor_patterns() -- called as an UNBOUND method
(AutonomousFPEngine._build_safe_vendor_patterns(None)), confirmed by reading the
method body to return a pure static list that never touches `self`. This avoids
duplicating ~80 lines of vendor-pattern data that would silently drift from v1's
own maintained list, and avoids ever constructing a real AutonomousFPEngine
instance (whose __init__ starts 3 background daemon threads -- never something v13
should trigger as a side effect of reading a static list).
"""
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger("v13_cl_afpe_ml_scoring")

# Matches fp_engine.py's real combination weights/sentinel exactly (its evaluate()
# method's weighted-combination logic, confirmed via direct read).
LGBM_WEIGHT = 0.45
EMBED_WEIGHT = 0.55
NEUTRAL_LGBM_SCORE = 0.50


def build_feature_vector(features: Dict[str, Any], domain: str, is_trust_cached: bool) -> List[float]:
    """Matches _stage2_lgbm()'s real 11-feature vector construction exactly (lines
    1310-1377) -- MUST stay in lockstep with train_fp_classifier.py's own
    extract_features_from_alert(), the same "no shared helper by design"
    relationship v1's own docstring documents (one runs in the always-on pipeline
    process, the other in a separate weekly retrain script); v13 joins that
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
    """Lazily loads and calls v-current's REAL, already-trained ONNX/FastEmbed
    artifacts read-only -- never trains, never writes to model_dir. A model that
    isn't ready yet (missing file, or its library isn't installed) degrades to
    None/rule-fallback, matching v1's own real-production behavior during its own
    loader threads' warm-up window. Load attempts happen at most once per instance
    (not retried every call) -- matches v1's own one-shot background-thread loader
    shape, just synchronous/lazy instead of threaded, since v13 has no equivalent
    background-loader infrastructure yet."""

    def __init__(self, model_dir: str):
        self.model_dir = Path(model_dir)
        self._lgbm_session = None
        self._lgbm_load_attempted = False
        self._embed_model = None
        self._safe_vendor_embeddings = None
        self._safe_vendor_labels: List[str] = []
        self._embed_load_attempted = False

    def _ensure_lgbm_loaded(self) -> None:
        if self._lgbm_load_attempted:
            return
        self._lgbm_load_attempted = True
        onnx_path = self.model_dir / "fp_classifier.onnx"
        if not onnx_path.exists():
            LOGGER.info("No fp_classifier.onnx at %s yet -- Stage 2 unavailable this cycle.", onnx_path)
            return
        try:
            import onnxruntime as ort
            sess_opts = ort.SessionOptions()
            sess_opts.intra_op_num_threads = 1
            sess_opts.inter_op_num_threads = 1
            sess_opts.log_severity_level = 3
            self._lgbm_session = ort.InferenceSession(str(onnx_path), sess_options=sess_opts)
            LOGGER.info("Loaded LightGBM ONNX from %s (v-current's own real, continuously-retrained model).", onnx_path)
        except ImportError:
            LOGGER.warning("onnxruntime not installed -- Stage 2 unavailable.")
        except Exception as e:
            LOGGER.error("Failed to load %s: %s", onnx_path, e, exc_info=True)

    def _ensure_embed_loaded(self) -> None:
        if self._embed_load_attempted:
            return
        self._embed_load_attempted = True
        try:
            from fastembed import TextEmbedding
            import numpy as np
            from intelligence.fp_engine import AutonomousFPEngine

            cache_dir = str(self.model_dir / "fastembed_cache")
            model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5", cache_dir=cache_dir)

            patterns = AutonomousFPEngine._build_safe_vendor_patterns(None)
            labels = [p["label"] for p in patterns]
            texts = [p["text"] for p in patterns]
            raw_embeddings = list(model.embed(texts))
            embed_matrix = np.array(raw_embeddings, dtype=np.float32)
            norms = np.linalg.norm(embed_matrix, axis=1, keepdims=True) + 1e-9

            self._embed_model = model
            self._safe_vendor_embeddings = embed_matrix / norms
            self._safe_vendor_labels = labels
            LOGGER.info("Loaded FastEmbed BAAI/bge-small-en-v1.5, %d vendor patterns (v-current's own).", len(patterns))
        except ImportError:
            LOGGER.warning("fastembed not installed -- Stage 3 falls back to static rules.")
        except Exception as e:
            LOGGER.error("Failed to load FastEmbed: %s", e, exc_info=True)

    def score_stage2(self, features: Dict[str, Any], domain: str, is_trust_cached: bool) -> Optional[float]:
        """Returns P(FP) in [0,1], or None if the model isn't ready -- caller
        substitutes the neutral 0.50 sentinel, matching v1 exactly."""
        self._ensure_lgbm_loaded()
        if self._lgbm_session is None:
            return None
        try:
            import numpy as np
            feat_vec_full = build_feature_vector(features, domain, is_trust_cached)
            input_spec = self._lgbm_session.get_inputs()[0]
            expected_feats = (
                input_spec.shape[1] if (len(input_spec.shape) > 1 and isinstance(input_spec.shape[1], int)) else 6
            )
            # Matches v1's own 6-feature legacy / 9-feature multi-threat / 11-feature
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
            outputs = self._lgbm_session.run(None, {input_name: feat_vec})
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
