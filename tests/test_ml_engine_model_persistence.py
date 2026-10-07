"""
Regression tests for intelligence/ml_engine.py model persistence (live, 2026-09-23):
one truncated per-device .pkl (a save killed mid-write on 2026-09-22) made
load_models() fail on EVERY restart, silently dropping every model after it in
directory order -- 8 of 13 device models on .94.

Covers: a bad file no longer blocks the others and is removed; a save killed mid-write
leaves the previous complete model intact (atomic temp + os.replace); leftover temp
files are cleaned up; a normal save/load round trip still works.
"""
import sys
from pathlib import Path

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import intelligence.ml_engine as ml_engine  # noqa: E402
from intelligence.ml_engine import MultiDeviceMLEngine  # noqa: E402
import metrics  # noqa: E402


def _fitted_model(seed=0):
    # Stamped like the engine's own fits: load_models() discards a model learned under another DNS ratio scheme, so an
    # unstamped test model was dropped on load and these tests no longer guarded the 09-22 bug (they failed instead).
    rng = np.random.default_rng(seed)
    return ml_engine._stamp(IsolationForest(n_estimators=10, random_state=seed).fit(rng.normal(size=(64, 11))))


def _registry_with(tmp_path, device_ids):
    reg = MultiDeviceMLEngine(model_dir=tmp_path)
    for i, dev in enumerate(device_ids):
        eng = reg._get_or_create_device(dev)
        eng.model = _fitted_model(i)
        eng.warmed_up = True
    return reg


def _discards(reason):
    for s in metrics.device_profile_discards_total.collect()[0].samples:
        if s.name.endswith("_total") and s.labels.get("reason") == reason:
            return s.value
    return 0.0


def _loaded_ids(tmp_path):
    reg = MultiDeviceMLEngine(model_dir=tmp_path)
    reg.load_models()
    return {d for d, e in reg.devices.items() if e.warmed_up}


def test_round_trip(tmp_path):
    _registry_with(tmp_path, ["dev_a", "dev_b"]).save_models(wait=True)
    assert _loaded_ids(tmp_path) == {"dev_a", "dev_b"}
    assert not list(tmp_path.glob("*.tmp"))


def test_one_truncated_file_no_longer_drops_the_others(tmp_path):
    devices = ["dev_a", "dev_b", "dev_c", "dev_d"]
    _registry_with(tmp_path, devices).save_models(wait=True)
    bad = tmp_path / "dev_b.pkl"
    data = bad.read_bytes()
    bad.write_bytes(data[: len(data) // 2])  # what a kill mid-write leaves behind
    before = _discards("corrupt")

    assert _loaded_ids(tmp_path) == {"dev_a", "dev_c", "dev_d"}
    assert not bad.exists(), "the unreadable file must be removed, not fail again on every restart"
    assert _discards("corrupt") == before + 1


def test_save_killed_mid_write_keeps_previous_model(tmp_path, monkeypatch):
    _registry_with(tmp_path, ["dev_a"]).save_models(wait=True)
    good = (tmp_path / "dev_a.pkl").read_bytes()

    real_dump = ml_engine.joblib.dump

    def dump_then_die(obj, path, *a, **kw):
        real_dump(obj, path, *a, **kw)
        Path(path).write_bytes(Path(path).read_bytes()[:100])  # partial write...
        raise KeyboardInterrupt("killed mid-write")  # ...then the process dies

    monkeypatch.setattr(ml_engine.joblib, "dump", dump_then_die)
    reg = _registry_with(tmp_path, ["dev_a"])
    with pytest.raises(KeyboardInterrupt):
        reg._atomic_dump(reg.devices["dev_a"].model, tmp_path / "dev_a.pkl")
    monkeypatch.setattr(ml_engine.joblib, "dump", real_dump)

    assert (tmp_path / "dev_a.pkl").read_bytes() == good, "final file must be untouched by an interrupted save"
    assert (tmp_path / "dev_a.pkl.tmp").exists()
    assert _loaded_ids(tmp_path) == {"dev_a"}
    assert not (tmp_path / "dev_a.pkl.tmp").exists(), "load must clean up interrupted-save leftovers"


def test_unreadable_global_model_does_not_block_device_models(tmp_path):
    _registry_with(tmp_path, ["dev_a"]).save_models(wait=True)
    glob_path = tmp_path / "global.pkl"
    glob_path.write_bytes(b"not a model")
    reg = MultiDeviceMLEngine(model_dir=tmp_path, global_model_path=glob_path)
    reg.load_models()
    assert reg.devices["dev_a"].warmed_up
    assert not glob_path.exists()
