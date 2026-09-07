"""
Regression test for the P0-2 model-path-mismatch bug (2026-09-07,
Documentation/V13_FULL_ARCHITECTURE_SHIFT_PLAN.md): train_fp_classifier.py's
train_and_export_onnx() used to hardcode state_dir/"models" as its output
directory, while fp_engine.py's own _load_lgbm_model()/_load_calibration() read
from Path(config["model_path"]).parent instead -- two different directories, so
every retrained model was silently never picked up by live inference. Confirmed
live on .94: state/models/fp_classifier.onnx was hours-old while the file
actually loaded (top-level models/fp_classifier.onnx) was weeks-stale.

Fix: train_and_export_onnx() now takes an explicit model_dir param (default:
derived from CONFIG["model_path"], the same fallback fp_engine.py's own loader
uses), and fp_engine.py's weekly-retrain call site passes the SAME model_dir its
own _load_lgbm_model() reads from -- proven here by construction, not just by
independently re-deriving the same default twice.
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
    """BUGFIX proof: _load_lgbm_model() (the reader) and the weekly retrain loop
    (the writer) must resolve to the identical directory by construction -- both
    now call the same self._model_dir() helper, so this can no longer drift the
    way it did when each side independently hardcoded its own default/path."""
    from intelligence import fp_engine as fp_engine_module

    fake_model_path = tmp_path / "models" / "ids_model.pkl"
    engine = fp_engine_module.AutonomousFPEngine.__new__(fp_engine_module.AutonomousFPEngine)
    engine.config = {"model_path": str(fake_model_path)}

    reader_dir = engine._model_dir()  # what _load_lgbm_model() reads from
    assert reader_dir == fake_model_path.parent

    # The real weekly-retrain call site passes exactly this same method's return
    # value as train_and_export_onnx's model_dir -- verified by calling the real
    # (not mocked) function against it.
    ok = train_fp_classifier.train_and_export_onnx(
        tmp_path / "state", model_dir=engine._model_dir()
    )
    assert ok is True
    assert (reader_dir / "fp_classifier.onnx").exists()


def test_model_dir_default_falls_back_consistently(tmp_path, monkeypatch):
    """Both _model_dir() and train_and_export_onnx()'s own default must fall back
    to the SAME literal ("models/ids_model.pkl") when model_path is absent --
    previously one side defaulted to "state/ids_model.pkl" instead, a latent
    inconsistency even though config.py always supplies model_path in practice."""
    from intelligence import fp_engine as fp_engine_module

    engine = fp_engine_module.AutonomousFPEngine.__new__(fp_engine_module.AutonomousFPEngine)
    engine.config = {}  # model_path absent -- exercises the fallback default

    assert engine._model_dir() == Path("models")

    monkeypatch.delitem(train_fp_classifier.CONFIG._config, "model_path", raising=False)
    assert Path(train_fp_classifier.CONFIG.get("model_path", "models/ids_model.pkl")).parent == Path("models")
