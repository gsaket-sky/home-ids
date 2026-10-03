"""
The false-positive classifier's quality gate (scripts/train_fp_classifier.py) and the engine's refusal to use a model
the gate did not vouch for (argus/cl_afpe/ml_scoring.py).

Background (2026-10-03, .94): feature 5 ("in the trust cache") was 1.0 in every false-positive training row and 0.0 in
every threat row, so the model learned only that column, reported 100% training accuracy, and scored every live alert
0.005. The gate must reject such a model however good its accuracy looks.

Run directly: `python tests/test_fp_classifier_quality_gate.py`
"""
import json
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from scripts import train_fp_classifier as t  # noqa: E402
from argus.cl_afpe.ml_scoring import MLScorer, QUALITY_FILE_NAME, FP_FEATURE_VERSION, file_sha256  # noqa: E402
from sklearn.ensemble import GradientBoostingClassifier  # noqa: E402
from sklearn.pipeline import make_pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

rng = random.Random(7)


def _row(label, leak=False):
    """Overlapping, noisy classes: threats lean towards unpopular, high-entropy names and evasion; no feature alone
    separates them. With leak=True, column 5 equals the label (the 2026-10-03 bug)."""
    base = 0.35 if label == 0 else 0.65
    row = [min(1.0, max(0.0, rng.gauss(base if j in (0, 4) else 1.0 - base, 0.22))) for j in range(t.FP_FEATURE_DIM)]
    row[5] = float(label) if leak else 0.0
    return row


def _dataset(n, leak=False):
    y = [rng.random() < 0.5 and 1 or 0 for _ in range(n)]
    return [_row(c, leak) for c in y], y


def _fit(X, y):
    p = make_pipeline(StandardScaler(), GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42))
    p.fit(X, y)
    return p


# --- A. the gate ---
Xl, yl = _dataset(600, leak=True)
leaky = _fit(Xl[:450], yl[:450])
ok, metrics, reasons = t.model_quality_gate(leaky, Xl[450:], yl[450:])
check("A: a model trained on a leaked label is REJECTED although its held-out accuracy is perfect",
      not ok and metrics.get("held_out_balanced_accuracy", 0) > 0.99, f"{metrics} {reasons}")
check("A: the rejection names the leaked feature",
      any("historical_fp_flag" in r for r in reasons), str(reasons))

Xg, yg = _dataset(600)
good = _fit(Xg[:450], yg[:450])
ok, metrics, reasons = t.model_quality_gate(good, Xg[450:], yg[450:])
check("A: a model that learned a real (overlapping) pattern passes", ok, f"{metrics} {reasons}")

Xr = [[rng.random() for _ in range(t.FP_FEATURE_DIM)] for _ in range(600)]
yr = [rng.randint(0, 1) for _ in range(600)]
ok, metrics, reasons = t.model_quality_gate(_fit(Xr[:450], yr[:450]), Xr[450:], yr[450:])
check("A: a model no better than chance is rejected", not ok and any("balanced accuracy" in r for r in reasons),
      f"{metrics} {reasons}")

ok, _, reasons = t.model_quality_gate(good, Xg[:10], yg[:10])
check("A: too little held-out data is rejected (cannot be verified)", not ok and "held-out" in reasons[0])

# --- B. training rows never carry the leaked column ---
X, y, stats = [], [], {"x_accepted": 0, "x_rejected": 0}
t._append_sample(X, y, {"reasons": ["'a.com' previously verified safe – dynamic trust cache hit"],
                        "features": {}, "network_context": {"queried_domain": "a.com"}}, 1, stats, "x")
check("B: a trust-cache-hit training row has feature 5 = 0", X and X[0][5] == 0.0, str(X))

# --- C. end to end: rejected -> nothing installed; passed -> installed and loadable ---
with tempfile.TemporaryDirectory() as tmp:
    model_dir = Path(tmp) / "models"
    real_load = t.load_dataset
    try:
        t.load_dataset = lambda state_dir: (list(Xr), list(yr), {"threat_accepted": 0, "threat_rejected": 0,
                                                                 "fp_accepted": 0, "fp_rejected": 0,
                                                                 "threat_skipped_corrected": 0,
                                                                 "threat_skipped_non_alert": 0,
                                                                 "skipped_corrupted_attribution": 0})
        installed = t.train_and_export_onnx(Path(tmp), model_dir)
        check("C: a model that fails the gate is not installed",
              installed is False and not (model_dir / "fp_classifier.onnx").exists())
        rejected = json.loads((model_dir / "fp_classifier_rejected.json").read_text(encoding="utf-8"))
        check("C: the rejection is recorded with its reasons", rejected.get("reasons"))

        t.load_dataset = lambda state_dir: (list(Xg), list(yg), {"threat_accepted": 0, "threat_rejected": 0,
                                                                 "fp_accepted": 0, "fp_rejected": 0,
                                                                 "threat_skipped_corrected": 0,
                                                                 "threat_skipped_non_alert": 0,
                                                                 "skipped_corrupted_attribution": 0})
        installed = t.train_and_export_onnx(Path(tmp), model_dir)
        quality = json.loads((model_dir / QUALITY_FILE_NAME).read_text(encoding="utf-8"))
        check("C: a model that passes is installed with a quality file vouching for exactly that file",
              installed is True and quality.get("passed") is True and quality.get("feature_version") == FP_FEATURE_VERSION
              and quality.get("model_sha256") == file_sha256(model_dir / "fp_classifier.onnx"))
        check("C: the earlier rejection record is removed", not (model_dir / "fp_classifier_rejected.json").exists())
        scorer = MLScorer(str(model_dir))
        p = scorer.score_stage2({"tranco_rank": 0}, "example.com", is_trust_cached=False)
        check("C: the engine loads and uses the vouched-for model", p is not None and scorer.ready()["classifier"])
    finally:
        t.load_dataset = real_load

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED")
    sys.exit(1)
print("All false-positive classifier quality-gate checks PASSED.")
