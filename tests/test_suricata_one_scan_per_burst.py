"""
A6 (2026-10-01): one Suricata run per reactive-capture burst, over a directory holding every radio's pcap, instead of
one run per radio (each run reloads ~48k rules, ~90-100 s on .94).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import extractors.fritzbox_capture as fc  # noqa: E402


def _setup(monkeypatch, tmp_path, zeek_fails_on=()):
    calls = []

    def fake_burst(ip, user, pw, radios, secs, out_dir, snaplen=0):
        out = {}
        for r in radios:
            p = out_dir / f"{r}.avm"
            p.write_bytes(b"avm")
            out[r] = p
        return out

    def fake_convert(avm, std):
        std.parent.mkdir(parents=True, exist_ok=True)
        std.write_bytes(b"pcap")
        return 10

    def fake_zeek(std, scratch, zeek_bin=None, memory_limit_mb=0):
        if std.stem in zeek_fails_on:
            raise fc.FritzboxCaptureError("zeek could not read it")
        scratch.mkdir(parents=True, exist_ok=True)

    def fake_suricata(pcap_dir, scratch, *a, **kw):
        calls.append({"dir": pcap_dir, "files": sorted(p.name for p in Path(pcap_dir).iterdir()),
                      "timeout": kw.get("timeout")})
        return {}

    monkeypatch.setattr(fc, "run_burst", fake_burst)
    monkeypatch.setattr(fc, "avm_pcap_to_standard", fake_convert)
    monkeypatch.setattr(fc, "reprocess_with_zeek", fake_zeek)
    monkeypatch.setattr(fc, "ingest_zeek_logs", lambda *a, **k: {"conn": 1})
    monkeypatch.setattr(fc, "run_suricata_and_attribute", fake_suricata)
    monkeypatch.setattr(fc, "write_component_heartbeat", lambda *a, **k: None)
    monkeypatch.setattr(fc, "_append_burst_history", lambda *a, **k: None)
    cfg = {"fritz_password": "x", "reactive_capture_radios": ["ath0", "ath1"],
           "reactive_capture_suricata_enabled": True, "reactive_capture_suricata_rules_path": "/rules",
           "reactive_capture_suricata_timeout_seconds": 100.0, "dns_evasion_audit_enabled": False}
    return calls, cfg


def test_two_radios_get_one_suricata_run_over_both_pcaps(monkeypatch, tmp_path):
    calls, cfg = _setup(monkeypatch, tmp_path)
    fc.capture_and_ingest(cfg, zeek_fx=None, out_dir=tmp_path)
    assert len(calls) == 1
    assert calls[0]["files"] == ["ath0.pcap", "ath1.pcap"]
    assert calls[0]["timeout"] == 200.0          # same total budget the two per-radio runs had
    assert not any(p.name.startswith("suricata_pcaps_") for p in tmp_path.iterdir())   # cleaned up
    assert not list(tmp_path.glob("*.avm"))


def test_a_radio_zeek_could_not_read_is_left_out_of_the_scan(monkeypatch, tmp_path):
    calls, cfg = _setup(monkeypatch, tmp_path, zeek_fails_on=("ath1",))
    fc.capture_and_ingest(cfg, zeek_fx=None, out_dir=tmp_path)
    assert len(calls) == 1 and calls[0]["files"] == ["ath0.pcap"]


def test_no_scan_when_no_radio_survives(monkeypatch, tmp_path):
    calls, cfg = _setup(monkeypatch, tmp_path, zeek_fails_on=("ath0", "ath1"))
    fc.capture_and_ingest(cfg, zeek_fx=None, out_dir=tmp_path)
    assert calls == []


def test_kept_raw_files_do_not_leave_a_bad_pcap_in_the_scan_dir(monkeypatch, tmp_path):
    calls, cfg = _setup(monkeypatch, tmp_path, zeek_fails_on=("ath1",))
    cfg["reactive_capture_delete_after_ingest"] = False
    fc.capture_and_ingest(cfg, zeek_fx=None, out_dir=tmp_path)
    assert calls[0]["files"] == ["ath0.pcap"]


def test_repeated_deferrals_are_logged_once_per_interval(caplog):
    import logging
    d = fc.ReactiveCaptureDispatcher.__new__(fc.ReactiveCaptureDispatcher)
    d._deferral_log = {}
    with caplog.at_level(logging.DEBUG, logger="home_ids.fritzbox_capture"):
        for _ in range(50):
            d._log_deferral("burst_budget", "[DEFERRED] cap reached, deferring '%s'", "dns_suspicion")
    info = [r for r in caplog.records if r.levelno == logging.INFO]
    assert len(info) == 1                                 # was 50 INFO lines
    assert sum(r.levelno == logging.DEBUG for r in caplog.records) == 49
    d._deferral_log["burst_budget"] = (d._deferral_log["burst_budget"][0] - 1000, 49)   # interval passed
    with caplog.at_level(logging.INFO, logger="home_ids.fritzbox_capture"):
        d._log_deferral("burst_budget", "[DEFERRED] cap reached, deferring '%s'", "dns_suspicion")
    assert "49 more deferral(s)" in caplog.records[-1].getMessage()
    d._log_deferral("concurrent", "[DEFERRED] busy")      # another kind is logged independently
    assert caplog.records[-1].levelno == logging.INFO
