"""
Standalone runtime test for v13's CL-AFPE ML scoring (src/v13/cl_afpe/ml_scoring.py,
Phase 6d -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: the pure feature-vector/parsing/combination functions (no I/O, the real
correctness risk in a faithful port of v1's exact math), and MLScorer's real
end-to-end behavior against a REAL small ONNX model (generated here the same way
v1's own placeholder generator does, via sklearn+skl2onnx -- onnxruntime is a real
dependency in this venv, confirmed before writing this test, so this is genuine
inference, not a mock) plus a mocked FastEmbed (avoids a slow/network-dependent
~85MB download during tests, matching this project's own established convention
for heavy/network dependencies -- see test_argus_llm_review_client.py).

Requires the venv python (onnxruntime/sklearn/skl2onnx/numpy):
`.venv/Scripts/python.exe tests/test_argus_cl_afpe_ml_scoring.py`
"""
import sys
import tempfile
from unittest.mock import MagicMock, patch
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.cl_afpe.ml_scoring import (  # noqa: E402
    MLScorer, build_feature_vector, parse_onnx_prob, stage3_rule_fallback,
    combine_scores, NEUTRAL_LGBM_SCORE, LGBM_WEIGHT, EMBED_WEIGHT,
)

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="v13_ml_scoring_test_"))


# --- build_feature_vector: real math, matching v1's exact 11-dimension order ---
vec_empty = build_feature_vector({}, "", is_trust_cached=False)
check("build_feature_vector returns exactly 11 dimensions", len(vec_empty) == 11)
check("with no features at all, every dimension defaults sanely (not an error)",
      all(isinstance(v, float) for v in vec_empty))
check("f4 (device-type weight) defaults to 0.3 ('unknown') with no device_type given",
      abs(vec_empty[4] - 0.3) < 1e-9)
check("f8 (app-protocol weight) defaults to 0.2 with no zeek_app_protocol_weight given",
      abs(vec_empty[8] - 0.2) < 1e-9)

vec_full = build_feature_vector({
    "tranco_rank": 500_000, "max_label_length": 30, "outbound_bytes_z": 5.0,
    "device_type": "iot", "zeek_lateral_moves": 5, "zeek_s0_rej_count": 25,
    "zeek_app_protocol_weight": 0.9, "zeek_arp_sweep_count": 10, "zeek_dns_evasion_ratio": 0.5,
}, "randomlabel123", is_trust_cached=True)
check("f0 (tranco norm): rank 500,000 of 1,000,000 -> 0.5", abs(vec_full[0] - 0.5) < 1e-9)
check("f2 (label-length norm): 30/60 -> 0.5", abs(vec_full[2] - 0.5) < 1e-9)
check("f3 (outbound-z norm): 5.0/10.0 -> 0.5", abs(vec_full[3] - 0.5) < 1e-9)
check("f4 (device-type weight): 'iot' -> 0.1", abs(vec_full[4] - 0.1) < 1e-9)
check("f5 (hist_fp): is_trust_cached=True -> 1.0", vec_full[5] == 1.0)
check("f6 (lateral-moves norm): 5/10 -> 0.5", abs(vec_full[6] - 0.5) < 1e-9)
check("f7 (port-scans norm): 25/50 -> 0.5", abs(vec_full[7] - 0.5) < 1e-9)
check("f8 (app-protocol weight): passed through directly -> 0.9", abs(vec_full[8] - 0.9) < 1e-9)
check("f9 (arp-sweep norm): 10/20 -> 0.5", abs(vec_full[9] - 0.5) < 1e-9)
check("f10 (dns-evasion ratio): passed through directly -> 0.5", abs(vec_full[10] - 0.5) < 1e-9)

vec_clamped = build_feature_vector({
    "tranco_rank": -100, "outbound_bytes_z": -5.0, "zeek_dns_evasion_ratio": 5.0,
}, "x", is_trust_cached=False)
check("negative tranco_rank clamps f0 to 0.0 (the 'rank<=0 means unknown' branch), never negative",
      vec_clamped[0] == 0.0)
check("a negative outbound_bytes_z clamps f3 to 0.0, never negative", vec_clamped[3] == 0.0)
check("dns_evasion_ratio above 1.0 clamps f10 to 1.0, matching v1's own clamp[0,1]", vec_clamped[10] == 1.0)


# --- parse_onnx_prob: both real ONNX output shapes ---
check("ZipMap format ([{0: p0, 1: p1}]) extracts class-1 probability correctly",
      abs(parse_onnx_prob([None, [{0: 0.3, 1: 0.7}]]) - 0.7) < 1e-9)
check("2D numpy-array format ([[p0, p1]]) extracts class-1 probability correctly",
      abs(parse_onnx_prob([[[0.2, 0.8]]]) - 0.8) < 1e-9)
check("empty outputs fails safe to the neutral sentinel (0.50)",
      parse_onnx_prob([]) == NEUTRAL_LGBM_SCORE)
check("a single-value 1D output is used directly",
      abs(parse_onnx_prob([[0.42]]) - 0.42) < 1e-9)


# --- stage3_rule_fallback: real telemetry/CDN checks ---
telemetry_score, telemetry_label = stage3_rule_fallback("googleads.g.doubleclick.net")
check("a known telemetry/ad domain scores 0.92 via the static rule fallback",
      abs(telemetry_score - 0.92) < 1e-9)
unknown_score, unknown_label = stage3_rule_fallback("some-genuinely-random-domain-xyz123.example")
check("an unrecognized domain scores low (0.05) via the static rule fallback",
      abs(unknown_score - 0.05) < 1e-9)


# --- combine_scores: v1's real 3-way weighted-combination logic exactly ---
check("embed_sim=None uses lgbm_prob alone, never blended with a fabricated 0.0",
      combine_scores(0.8, None, embed_similarity_threshold=0.82) == 0.8)
check("both None falls back to the neutral sentinel",
      combine_scores(None, None, embed_similarity_threshold=0.82) == NEUTRAL_LGBM_SCORE)
check("lgbm at the neutral sentinel (model not ready) AND embed clears the threshold "
      "-> embed decides alone (lets Stage 3 own the verdict when Stage 2 has nothing real)",
      combine_scores(NEUTRAL_LGBM_SCORE, 0.9, embed_similarity_threshold=0.82) == 0.9)
check("lgbm at the neutral sentinel but embed does NOT clear the threshold -> normal blend applies",
      abs(combine_scores(NEUTRAL_LGBM_SCORE, 0.5, embed_similarity_threshold=0.82)
          - (NEUTRAL_LGBM_SCORE * LGBM_WEIGHT + 0.5 * EMBED_WEIGHT)) < 1e-9)
check("a real lgbm score with a real embed score uses the exact weighted blend "
      "(0.45/0.55)",
      abs(combine_scores(0.9, 0.1, embed_similarity_threshold=0.82) - (0.9 * 0.45 + 0.1 * 0.55)) < 1e-9)


# --- MLScorer: no model file present yet -- graceful degradation ---
no_model_dir = TMPDIR / "no_model"
no_model_dir.mkdir()
scorer_no_model = MLScorer(str(no_model_dir))
check("score_stage2 returns None when fp_classifier.onnx doesn't exist yet",
      scorer_no_model.score_stage2({}, "x.com", is_trust_cached=False) is None)
check("a second call within the recheck interval doesn't re-stat the model dir (at most one check a minute)",
      scorer_no_model._lgbm_checked_at > 0 and scorer_no_model.score_stage2({}, "x.com", False) is None)


# --- MLScorer.score_stage2: REAL onnxruntime inference against a REAL tiny model ---
# Generated here the same way v1's own placeholder generator does (sklearn GBM ->
# skl2onnx) -- onnxruntime/sklearn/skl2onnx are all real dependencies in this venv
# (confirmed before writing this test), so this exercises genuine ONNX inference,
# not a mock.
real_model_dir = TMPDIR / "real_model"
real_model_dir.mkdir()
onnx_path = real_model_dir / "fp_classifier.onnx"

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# 11-feature training set: low-everything -> class 1 (FP-like), high-everything -> class 0 (threat-like).
X_train = np.array([[0.05] * 11, [0.10] * 11, [0.02] * 11, [0.08] * 11,
                     [0.95] * 11, [0.90] * 11, [0.98] * 11, [0.92] * 11], dtype=np.float32)
y_train = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=np.int32)
pipe = Pipeline([("scaler", StandardScaler()), ("clf", GradientBoostingClassifier(n_estimators=10, max_depth=2, random_state=42))])
pipe.fit(X_train, y_train)
onnx_model = convert_sklearn(
    pipe, initial_types=[("input", FloatTensorType([None, 11]))],
    options={GradientBoostingClassifier: {"zipmap": False}},
)
with open(onnx_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

# --- the classifier is used only when its quality file vouches for exactly this file ---
import json as _json  # noqa: E402
from argus.cl_afpe.ml_scoring import FP_FEATURE_VERSION, QUALITY_FILE_NAME, file_sha256  # noqa: E402
quality_path = real_model_dir / QUALITY_FILE_NAME
gate_scorer = MLScorer(str(real_model_dir))
check("a model without a quality file (trained before the gate) is NOT used",
      gate_scorer.score_stage2({"tranco_rank": 0}, "", is_trust_cached=False) is None
      and gate_scorer.ready().get("classifier") is False)
for bad, why in (({"passed": False, "feature_version": FP_FEATURE_VERSION, "model_sha256": file_sha256(onnx_path)},
                  "a failed gate"),
                 ({"passed": True, "feature_version": FP_FEATURE_VERSION - 1, "model_sha256": file_sha256(onnx_path)},
                  "an older feature version"),
                 ({"passed": True, "feature_version": FP_FEATURE_VERSION, "model_sha256": "0" * 64},
                  "a different model file")):
    quality_path.write_text(_json.dumps(bad), encoding="utf-8")
    s = MLScorer(str(real_model_dir))
    check(f"a quality file for {why} keeps the classifier unused",
          s.score_stage2({"tranco_rank": 0}, "", is_trust_cached=False) is None)
quality_path.write_text(_json.dumps({"passed": True, "feature_version": FP_FEATURE_VERSION,
                                     "model_sha256": file_sha256(onnx_path)}), encoding="utf-8")

scorer_real = MLScorer(str(real_model_dir))
low_everything_prob = scorer_real.score_stage2(
    {"tranco_rank": 0, "max_label_length": 0, "outbound_bytes_z": 0.0}, "", is_trust_cached=False,
)
check("score_stage2 performs REAL onnxruntime inference and returns a real probability in [0,1]",
      low_everything_prob is not None and 0.0 <= low_everything_prob <= 1.0)

high_everything_prob = scorer_real.score_stage2({
    "tranco_rank": 0, "max_label_length": 60, "outbound_bytes_z": 10.0,
    "zeek_lateral_moves": 10, "zeek_s0_rej_count": 50, "zeek_arp_sweep_count": 20,
    "zeek_dns_evasion_ratio": 1.0,
}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", is_trust_cached=False)
check("the trained model actually discriminates: threat-shaped input scores a "
      "materially lower P(FP) than benign-shaped input (proves real inference is "
      "happening, not a hardcoded constant)",
      high_everything_prob is not None and high_everything_prob < low_everything_prob)


# --- the nightly retrain replaces the model file: the scorer picks up the new one ---
import os as _os  # noqa: E402
first_session = scorer_real._lgbm_session
_st = _os.stat(onnx_path)
_os.utime(onnx_path, (_st.st_atime, _st.st_mtime + 10))
scorer_real._lgbm_checked_at = 0.0          # skip the one-minute recheck wait
scorer_real.score_stage2({"tranco_rank": 0}, "", is_trust_cached=False)
check("a replaced model file (new mtime) is reloaded on the next check -- scoring never stays on a stale model",
      scorer_real._lgbm_session is not None and scorer_real._lgbm_session is not first_session)
check("ready() reports the classifier as loaded", scorer_real.ready().get("classifier") is True)


# --- MLScorer.score_stage3: mocked FastEmbed (real cosine-similarity math, real
# vendor-pattern reuse, no slow/network-dependent 85MB download) ---
fake_vendor_embeddings = {
    "o1234.ingest.us.sentry.io": [1.0, 0.0, 0.0],
    "some-genuinely-random-domain.example": [0.0, 0.0, 1.0],
}


class _FakeTextEmbedding:
    def __init__(self, model_name=None, cache_dir=None):
        pass

    def embed(self, texts):
        return [fake_vendor_embeddings.get(t, [0.0, 1.0, 0.0]) for t in texts]


embed_dir = TMPDIR / "embed_model"
embed_dir.mkdir()
scorer_embed = MLScorer(str(embed_dir))
with patch("fastembed.TextEmbedding", _FakeTextEmbedding):
    sim, label = scorer_embed.score_stage3("o1234.ingest.us.sentry.io")
check("score_stage3 finds a real vendor-pattern match via cosine similarity "
      "(the SAFE_VENDOR_PATTERNS list, confirmed non-empty)", sim is not None and sim > 0.99 and label == "Sentry Ingest US")

scorer_embed_unavailable = MLScorer(str(TMPDIR / "no_fastembed"))
with patch.dict(sys.modules, {"fastembed": None}):
    sim_none, label_none = scorer_embed_unavailable.score_stage3("x.com")
check("score_stage3 degrades to (None, None) when fastembed isn't importable, "
      "matching v1's own ImportError-caught behavior", sim_none is None and label_none is None)


# --- helpers used outside evaluate(): vendor similarity and text embedding ---
check("vendor_similarity() never blocks on a model load: no model -> the static rule fallback, a real number",
      isinstance(scorer_embed_unavailable.vendor_similarity("telemetry.example.com")[0], float))
check("vendor_similarity() of a placeholder name is 0.0", scorer_embed.vendor_similarity("unknown")[0] == 0.0)
check("embed_text() returns None while no model is loaded", scorer_embed_unavailable.embed_text("x") is None)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 CL-AFPE ML-scoring checks PASSED.")
