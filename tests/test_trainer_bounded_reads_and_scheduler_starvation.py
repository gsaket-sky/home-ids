"""2026-09-30 .94 freeze fixes: bounded-memory reads in train_fp_classifier.py, the
scheduler's deferred-job retry helper, the scheduler.log cap, and the external
scheduler mode's healing action. Offline; run with pytest."""
import json
import sys
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from scripts import train_fp_classifier as tfc  # noqa: E402
from scripts import scheduler  # noqa: E402
from core import job_coordinator  # noqa: E402
from core import healing_actions  # noqa: E402


def _write_jsonl(path: Path, docs, extra_lines=()):
    lines = [json.dumps(d) for d in docs] + list(extra_lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _old_read_alert_docs(path: Path) -> list:
    """The pre-fix implementation, kept here as the reference behavior."""
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [d for d in parsed if isinstance(d, dict)]
    except json.JSONDecodeError:
        pass
    docs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
            if isinstance(doc, dict):
                docs.append(doc)
        except json.JSONDecodeError:
            continue
    return docs


def test_streaming_reader_matches_old_reader_on_jsonl(tmp_path):
    p = tmp_path / "alerts.json"
    docs = [{"type": "ids_alert", "i": i} for i in range(50)]
    _write_jsonl(p, docs, extra_lines=["", "   ", "{not json", "[1, 2]", "42"])
    assert list(tfc._iter_alert_docs(p)) == _old_read_alert_docs(p) == docs


def test_streaming_reader_matches_old_reader_on_legacy_json_array(tmp_path):
    p = tmp_path / "alerts.json"
    docs = [{"type": "ids_alert", "i": i} for i in range(5)]
    p.write_text("\n  " + json.dumps(docs + [7, "x"]), encoding="utf-8")
    assert list(tfc._iter_alert_docs(p)) == _old_read_alert_docs(p) == docs


@pytest.mark.parametrize("content", [None, "", "   \n\n"])
def test_streaming_reader_missing_or_empty(tmp_path, content):
    p = tmp_path / "alerts.json"
    if content is not None:
        p.write_text(content, encoding="utf-8")
    assert list(tfc._iter_alert_docs(p)) == [] == _old_read_alert_docs(p)


def test_tail_equals_slice_of_full_list(tmp_path):
    p = tmp_path / "alerts.json"
    docs = [{"i": i} for i in range(120)]
    _write_jsonl(p, docs)
    assert tfc._read_alert_docs(p, tail=30) == docs[-30:]
    assert tfc._read_alert_docs(p, tail=500) == docs
    assert tfc._read_alert_docs(p) == docs


def test_collectors_use_passed_muted_docs_without_reading_the_graph(tmp_path, monkeypatch):
    def _no_graph(*_a, **_k):
        raise AssertionError("graph must not be read when muted_docs is passed")

    monkeypatch.setattr(tfc, "_read_muted_docs_from_graph", _no_graph)
    monkeypatch.setattr(tfc, "_resolve_alert_input_paths", lambda _sd: [tmp_path / "alerts.json"])
    _write_jsonl(tmp_path / "alerts.json", [
        {"type": "ids_alert", "fp_verdict": {"verdict": "UNCERTAIN", "confidence": 0.6},
         "device": {"id": "d1"}, "timestamp": 1.0, "signature": "S", "domain": "a.example"},
        {"type": "ids_alert", "fp_verdict": {"verdict": "CONFIRMED_THREAT", "stage": "STAGE_3_COMBINED",
         "confidence": 0.9}, "device": {"id": "d2"}, "timestamp": 2.0, "signature": "T", "domain": "b.example"},
    ])
    muted = []
    c, u, pdc, pdu = tfc._collect_calibration_evidence(tmp_path, muted_docs=muted)
    assert (c, u, pdu) == ([], [0.6], {"d1": [0.6]})
    c2, u2, _, _ = tfc._collect_uncertain_calibration_evidence(tmp_path, muted_docs=muted)
    assert (c2, u2) == ([], [0.9])
    assert tfc._collect_connection_abuse_corrections(tmp_path, muted_docs=muted) == {}


def _locked(*_a, **_k):
    import sqlite3
    raise sqlite3.OperationalError("database is locked")


def _fake_graph(tmp_path):
    (tmp_path / "v13_graph.db").write_bytes(b"")   # exists; reads are monkeypatched


def test_missing_graph_is_empty_history_not_a_failure(tmp_path):
    assert tfc._read_muted_docs_from_graph(tmp_path, strict=True) == []


def test_non_lock_error_fails_fast_without_retrying(monkeypatch, tmp_path):
    import sqlite3
    _fake_graph(tmp_path)
    calls = []

    def once(*a, **k):
        calls.append(1)
        raise sqlite3.DatabaseError("file is not a database")

    monkeypatch.setattr(tfc, "_read_muted_docs_once", once)
    monkeypatch.setattr(tfc, "GRAPH_READ_RETRY_SECONDS", 999.0)   # would hang if it retried
    with pytest.raises(tfc.GraphReadError):
        tfc._read_muted_docs_from_graph(tmp_path, strict=True)
    assert len(calls) == 1


def test_strict_graph_read_retries_then_raises(monkeypatch, tmp_path):
    _fake_graph(tmp_path)
    calls = []

    def once(*a, **k):
        calls.append(1)
        _locked()

    monkeypatch.setattr(tfc, "_read_muted_docs_once", once)
    monkeypatch.setattr(tfc, "GRAPH_READ_RETRY_SECONDS", 0.0)
    monkeypatch.setattr(tfc, "GRAPH_READ_ATTEMPTS", 3)
    with pytest.raises(tfc.GraphReadError):
        tfc._read_muted_docs_from_graph(tmp_path, strict=True)
    assert len(calls) == 3


def test_strict_graph_read_recovers_when_lock_clears(monkeypatch, tmp_path):
    _fake_graph(tmp_path)
    state = {"n": 0}

    def once(*a, **k):
        state["n"] += 1
        if state["n"] < 3:
            _locked()
        return [{"type": "x"}]

    monkeypatch.setattr(tfc, "_read_muted_docs_once", once)
    monkeypatch.setattr(tfc, "GRAPH_READ_RETRY_SECONDS", 0.0)
    assert tfc._read_muted_docs_from_graph(tmp_path, strict=True) == [{"type": "x"}]
    assert state["n"] == 3


def test_non_strict_graph_read_still_swallows(monkeypatch, tmp_path):
    monkeypatch.setattr(tfc, "_read_muted_docs_once", _locked)
    assert tfc._read_muted_docs_from_graph(tmp_path) == []


def test_unreadable_graph_aborts_retrain_and_keeps_existing_model(monkeypatch, tmp_path):
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    (model_dir / "fp_classifier.onnx").write_bytes(b"GOOD-MODEL")
    (model_dir / "fp_calibration.json").write_text('{"reliable": true}')
    _fake_graph(tmp_path)
    monkeypatch.setattr(tfc, "_read_muted_docs_once", _locked)
    monkeypatch.setattr(tfc, "GRAPH_READ_RETRY_SECONDS", 0.0)
    monkeypatch.setattr(tfc, "GRAPH_READ_ATTEMPTS", 2)
    assert tfc.train_and_export_onnx(tmp_path, model_dir) is False
    assert (model_dir / "fp_classifier.onnx").read_bytes() == b"GOOD-MODEL"
    assert (model_dir / "fp_calibration.json").read_text() == '{"reliable": true}'


def test_is_deferred_lifecycle(tmp_path):
    assert job_coordinator.is_deferred(tmp_path, "live_prune") is False
    job_coordinator.record_deferral_start(tmp_path, "live_prune")
    assert job_coordinator.is_deferred(tmp_path, "live_prune") is True
    assert job_coordinator.is_deferred(tmp_path, "backtest_job") is False
    job_coordinator.clear_deferral(tmp_path, "live_prune")
    assert job_coordinator.is_deferred(tmp_path, "live_prune") is False


def test_scheduler_log_cap_rotates_one_generation(tmp_path):
    log = tmp_path / "scheduler.log"
    log.write_bytes(b"a" * 2048)
    scheduler._cap_scheduler_log(tmp_path, cap_bytes=4096)
    assert log.stat().st_size == 2048 and not (tmp_path / "scheduler.log.1").exists()
    log.write_bytes(b"b" * 5000)
    scheduler._cap_scheduler_log(tmp_path, cap_bytes=4096)
    assert log.stat().st_size == 0
    assert (tmp_path / "scheduler.log.1").read_bytes() == b"b" * 5000
    log.write_bytes(b"c" * 6000)
    scheduler._cap_scheduler_log(tmp_path, cap_bytes=4096)
    assert (tmp_path / "scheduler.log.1").read_bytes() == b"c" * 6000  # one generation only


def test_scheduler_log_cap_missing_file_is_noop(tmp_path):
    scheduler._cap_scheduler_log(tmp_path, cap_bytes=1)
    assert not (tmp_path / "scheduler.log").exists()


def test_failed_job_run_does_not_count_as_success(tmp_path):
    import utils
    utils.write_job_health(tmp_path, "zeek_log_prune", 1.0, extra={"deleted_dirs": 3})
    first = json.loads((tmp_path / "job_health.json").read_text())["zeek_log_prune"]["last_success"]
    time.sleep(0.01)
    utils.write_job_health(tmp_path, "zeek_log_prune", 2.0, extra={"error": "read-only file system"})
    entry = json.loads((tmp_path / "job_health.json").read_text())["zeek_log_prune"]
    assert entry["last_success"] == first          # not advanced by the failure
    assert entry["last_failure"] > first and entry["error"] == "read-only file system"
    utils.write_job_health(tmp_path, "never_ok", 1.0, extra={"error": "boom"})
    assert "last_success" not in json.loads((tmp_path / "job_health.json").read_text())["never_ok"]


class _FakeHM:
    def __init__(self, mode):
        self.config = {"scheduler_mode": mode}
        self.scheduler_proc = None
        self.scheduler_log_file = None


def test_external_scheduler_is_never_relaunched_embedded(monkeypatch):
    def _boom():
        raise AssertionError("must not launch an embedded scheduler in external mode")

    monkeypatch.setattr(healing_actions.subprocess_launchers, "start_scheduler_subprocess", _boom)
    ok, msg = healing_actions.restart_scheduler_subprocess(_FakeHM("external"), "scheduler_subprocess")
    assert ok is False and "external" in msg


def test_embedded_scheduler_still_relaunched(monkeypatch):
    class _P:
        pid = 4242

    monkeypatch.setattr(healing_actions.subprocess_launchers, "start_scheduler_subprocess", lambda: (_P(), None))
    hm = _FakeHM("embedded")
    ok, msg = healing_actions.restart_scheduler_subprocess(hm, "scheduler_subprocess")
    assert ok is True and hm.scheduler_proc.pid == 4242
