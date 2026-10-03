"""
Regression test for the P0-2 model-path-mismatch bug (2026-09-07,
Documentation/V13_FULL_ARCHITECTURE_SHIFT_PLAN.md): train_fp_classifier.py's
train_and_export_onnx() used to hardcode state_dir/"models" as its output
directory, while the live loader read from Path(config["model_path"]).parent instead -- two different directories, so
every retrained model was silently never picked up by live inference. Confirmed
live on .94: state/models/fp_classifier.onnx was hours-old while the file
actually loaded (top-level models/fp_classifier.onnx) was weeks-stale.

Fix: train_and_export_onnx() now takes an explicit model_dir param (default:
derived from CONFIG["model_path"]), the same directory pipeline.py points the CL-AFPE MLScorer at.
"""
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

pytest.importorskip("sklearn")
pytest.importorskip("skl2onnx")

from scripts import train_fp_classifier  # noqa: E402


@pytest.fixture(autouse=True)
def _realistic_dataset(monkeypatch):
    """Enough overlapping, noisy rows for the quality gate to verify a model (an empty state dir only has the 16
    synthetic rows, which the gate rightly refuses to install). These tests are about WHERE files land."""
    import random
    rng = random.Random(3)
    X, y = [], []
    for _ in range(400):
        label = rng.randint(0, 1)
        base = 0.35 if label == 0 else 0.65
        row = [min(1.0, max(0.0, rng.gauss(base, 0.22))) for _ in range(train_fp_classifier.FP_FEATURE_DIM)]
        row[5] = 0.0
        X.append(row)
        y.append(label)
    stats = {k: 0 for k in ("threat_accepted", "threat_rejected", "fp_accepted", "fp_rejected",
                            "threat_skipped_corrected", "threat_skipped_non_alert", "skipped_corrupted_attribution")}
    monkeypatch.setattr(train_fp_classifier, "load_dataset", lambda state_dir: (list(X), list(y), dict(stats)))


def test_train_and_export_onnx_writes_to_explicit_model_dir(tmp_path):
    """A model_dir explicitly passed in must be exactly where the files land --
    not state_dir/"models", regardless of what state_dir is."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    model_dir = tmp_path / "somewhere_else" / "models"

    ok = train_fp_classifier.train_and_export_onnx(state_dir, model_dir=model_dir)

    assert ok is True
    assert (model_dir / "fp_classifier.onnx").exists()
    assert (model_dir / "fp_calibration.json").exists()
    # The bug's own footprint: the old hardcoded location must NOT have been used.
    assert not (state_dir / "models" / "fp_classifier.onnx").exists()


def test_train_and_export_onnx_default_model_dir_matches_config(tmp_path, monkeypatch):
    """With no model_dir passed, the default must come from CONFIG["model_path"] --
    the exact same source fp_engine.py's own loader reads from -- not state_dir."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    fake_model_path = tmp_path / "models" / "ids_model.pkl"
    monkeypatch.setitem(train_fp_classifier.CONFIG._config, "model_path", str(fake_model_path))

    ok = train_fp_classifier.train_and_export_onnx(state_dir)

    assert ok is True
    assert (fake_model_path.parent / "fp_classifier.onnx").exists()
    assert not (state_dir / "models").exists()


def test_model_dir_is_single_source_shared_by_reader_and_writer(tmp_path):
    """The reader (the CL-AFPE MLScorer, pointed by pipeline.py at Path(model_path).parent) and the writer
    (train_and_export_onnx()'s default) resolve to the same directory, and a model the writer produces there is
    the one the reader loads."""
    from argus.cl_afpe.ml_scoring import MLScorer

    fake_model_path = tmp_path / "models" / "ids_model.pkl"
    reader = MLScorer(str(Path(fake_model_path).parent))      # what pipeline.py configures
    ok = train_fp_classifier.train_and_export_onnx(tmp_path / "state", model_dir=Path(fake_model_path).parent)
    assert ok is True
    assert reader.score_stage2({"tranco_rank": 0}, "", is_trust_cached=False) is not None


def test_model_dir_default_falls_back_consistently(monkeypatch):
    """pipeline.py and train_and_export_onnx() both fall back to "models/ids_model.pkl" when model_path is absent."""
    pipeline_src = (SRC_DIR / "core" / "pipeline.py").read_text(encoding="utf-8")
    assert 'Path(self.config.get("model_path", "models/ids_model.pkl")).parent' in pipeline_src
    monkeypatch.delitem(train_fp_classifier.CONFIG._config, "model_path", raising=False)
    assert Path(train_fp_classifier.CONFIG.get("model_path", "models/ids_model.pkl")).parent == Path("models")
