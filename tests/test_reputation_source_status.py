"""
Every optional reputation source in three states -- hit / checked clean / not checked (MASTER_TODO 0c Step 3,
2026-10-14). A source that is off, has no key, is rate-limited, holds stale lists or failed its lookup wrote risk 0.0
like a clean lookup; readers took that for "checked, clean". Covers the sources' own check_status(), the combined
per-alert record (`intelligence/reputation/source_status.py`) in the three setups the plan names -- all off (shipped
default), all on, on but failing -- and the alert text. CL-AFPE's own-device suppression: test_argus_cl_afpe.py.
"""
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from intelligence.threat_intel import AbuseIPDB, ThreatIntel, VirusTotalClient  # noqa: E402
from intelligence.reputation import source_status as ss  # noqa: E402

PUBLIC = "198.51.100.7"     # TEST-NET-2: ipaddress calls it non-global
NOW = time.time()


@pytest.fixture(autouse=True)
def _public_test_nets(monkeypatch):
    # The documentation ranges are not "global" to ipaddress; in these tests they stand for public addresses.
    monkeypatch.setattr(ss, "_public", lambda ip: bool(ip) and not ip.startswith(("10.", "192.168.")))


# --- threat-intel lists ------------------------------------------------------------------------------------------

def _ti(tmp_path, *, loaded_at=None, ips=None):
    ti = ThreatIntel(cache_dir=str(tmp_path))
    ti._bad_ips = dict(ips or {})
    ti._last_loaded_at = loaded_at
    return ti


def test_threat_intel_not_loaded_empty_stale_paused_and_fresh(tmp_path):
    assert _ti(tmp_path).check_status() == (False, "not loaded")
    assert _ti(tmp_path, loaded_at=NOW).check_status() == (False, "empty")
    old = NOW - ThreatIntel.FEED_MAX_AGE_SECONDS - 60
    assert _ti(tmp_path, loaded_at=old, ips={"203.0.113.1": {}}).check_status() == (False, "stale")
    fresh = _ti(tmp_path, loaded_at=NOW - 3600, ips={"203.0.113.1": {}})
    assert fresh.check_status() == (True, "")
    fresh.paused = True
    assert fresh.check_status() == (False, "paused")


def test_threat_intel_freshness_is_the_data_time_and_survives_a_restart(tmp_path):
    ti = _ti(tmp_path, loaded_at=NOW - 5 * 86400, ips={"203.0.113.1": {}})
    ti._save_cache(ti._bad_ips, {}, {}, [])          # a refresh that only re-saved old data
    ti2 = ThreatIntel(cache_dir=str(tmp_path))
    assert ti2._bad_ips and ti2.check_status() == (False, "stale")


# --- AbuseIPDB ------------------------------------------------------------------------------------------------------

def _abuse(tmp_path, on=True):
    return AbuseIPDB(api_key="k", cache_dir=tmp_path, enabled_fn=lambda: on)


def test_abuseipdb_states(tmp_path):
    assert _abuse(tmp_path, on=False).check_status(PUBLIC) == ("not_checked", "off")
    assert AbuseIPDB(api_key="", cache_dir=tmp_path).check_status(PUBLIC) == ("not_checked", "off")
    a = _abuse(tmp_path)
    assert a.check_status(PUBLIC) == ("not_checked", "pending")
    a._live_cache[PUBLIC] = {"result": {"abuseConfidenceScore": 0}, "expires": NOW + 60}
    assert a.check_status(PUBLIC) == ("clean", "")
    a._live_cache[PUBLIC] = {"result": {"abuseConfidenceScore": 40}, "expires": NOW + 60}
    assert a.check_status(PUBLIC) == ("hit", "")
    a._live_cache[PUBLIC] = {"result": None, "expires": NOW + 60}      # the worker's failed-lookup entry
    assert a.check_status(PUBLIC) == ("not_checked", "failed")
    a._live_cache[PUBLIC] = {"result": {"abuseConfidenceScore": 0}, "expires": NOW - 1}
    a._quota_exhausted_until = NOW + 600
    assert a.check_status(PUBLIC) == ("not_checked", "rate-limited")
    a._bad_ips = {PUBLIC}
    assert a.check_status(PUBLIC) == ("hit", "")


# --- VirusTotal -----------------------------------------------------------------------------------------------------

def _vt(tmp_path, on=True):
    vt = VirusTotalClient(api_key="", cache_dir=tmp_path, enabled_fn=lambda: on)   # no key: no worker thread
    vt.api_key = "k"
    return vt


def test_virustotal_states(tmp_path):
    assert _vt(tmp_path, on=False).check_status("ip", PUBLIC) == ("not_checked", "off")
    vt = _vt(tmp_path)
    assert vt.check_status("domain", "x.example") == ("not_checked", "pending")
    vt._cache["domain:x.example"] = {"result": {}, "expires": NOW + 60}        # 404: never seen, a valid answer
    assert vt.check_status("domain", "x.example") == ("clean", "")
    vt._cache["domain:x.example"] = {"result": None, "expires": NOW + 60}
    assert vt.check_status("domain", "x.example") == ("not_checked", "failed")
    vt._cache["ip:" + PUBLIC] = {"result": {"last_analysis_stats": {"malicious": 3, "harmless": 7}},
                                 "expires": NOW + 60}
    assert vt.check_status("ip", PUBLIC) == ("hit", "")


def test_virustotal_failed_lookup_is_not_the_never_seen_answer(tmp_path, monkeypatch):
    import intelligence.threat_intel as ti_mod
    vt = _vt(tmp_path)

    def _raise(code):
        def _open(*a, **k):
            raise HTTPError("u", code, "x", {}, None) if code else URLError("connection refused")
        return _open

    monkeypatch.setattr(ti_mod.feed_health, "record_failure", lambda *a, **k: None)
    monkeypatch.setattr(ti_mod, "urlopen", _raise(404))
    assert vt._query("domain", "x.example") == {}
    monkeypatch.setattr(ti_mod, "urlopen", _raise(500))
    assert vt._query("domain", "x.example") is None
    monkeypatch.setattr(ti_mod, "urlopen", _raise(None))
    assert vt._query("domain", "x.example") is None


# --- the per-alert record: three setups -----------------------------------------------------------------------------

class _FakeTI:
    def __init__(self, ok=True, why=""):
        self._r = (ok, why)

    def check_status(self):
        return self._r


def test_all_off_shipped_default(tmp_path):
    rec = ss.collect(_FakeTI(), _abuse(tmp_path, on=False), _vt(tmp_path, on=False),
                     ti_match=False, dest_ip=PUBLIC, domain="x.example")
    assert rec["threat_intel"] == {"state": "clean", "reason": ""}
    assert rec["abuseipdb"] == {"state": "not_checked", "reason": "off"}
    assert rec["virustotal"] == {"state": "not_checked", "reason": "off"}
    assert ss.verified_clean(rec) is True                 # off by choice is not a failure
    assert ss.unavailable(rec) == []
    assert ss.describe_not_checked(rec) == "AbuseIPDB (off), VirusTotal (off)"


def test_all_on_and_answered(tmp_path):
    a, vt = _abuse(tmp_path), _vt(tmp_path)
    a._live_cache[PUBLIC] = {"result": {"abuseConfidenceScore": 0}, "expires": NOW + 60}
    vt._cache["ip:" + PUBLIC] = {"result": {"last_analysis_stats": {"harmless": 70}}, "expires": NOW + 60}
    vt._cache["domain:x.example"] = {"result": {}, "expires": NOW + 60}
    rec = ss.collect(_FakeTI(), a, vt, ti_match=False, dest_ip=PUBLIC, domain="x.example")
    assert {k: e["state"] for k, e in rec.items()} == {"threat_intel": "clean", "abuseipdb": "clean",
                                                       "virustotal": "clean"}
    assert ss.verified_clean(rec) is True and ss.describe_not_checked(rec) == ""
    vt._cache["domain:x.example"] = {"result": {"last_analysis_stats": {"malicious": 1}}, "expires": NOW + 60}
    rec = ss.collect(_FakeTI(), a, vt, ti_match=True, dest_ip=PUBLIC, domain="x.example")
    assert rec["threat_intel"]["state"] == "hit" and rec["virustotal"]["state"] == "hit"
    assert ss.verified_clean(rec) is False


def test_on_but_failing(tmp_path):
    a, vt = _abuse(tmp_path), _vt(tmp_path)
    a._live_cache[PUBLIC] = {"result": None, "expires": NOW + 60}
    vt._quota_exhausted_until = NOW + 600
    rec = ss.collect(_FakeTI(False, "stale"), a, vt, ti_match=False, dest_ip=PUBLIC, domain="x.example")
    assert rec["threat_intel"] == {"state": "not_checked", "reason": "stale"}
    assert rec["abuseipdb"] == {"state": "not_checked", "reason": "failed"}
    assert rec["virustotal"] == {"state": "not_checked", "reason": "rate-limited"}
    assert ss.verified_clean(rec) is False
    assert sorted(ss.unavailable(rec)) == ["abuseipdb", "threat_intel", "virustotal"]
    assert ss.describe_not_checked(rec) == ("threat-intel lists (lists out of date), AbuseIPDB (lookup failed), "
                                            "VirusTotal (rate-limited)")


def test_a_switched_on_source_still_waiting_is_not_clean(tmp_path):
    rec = ss.collect(_FakeTI(), _abuse(tmp_path, on=False), _vt(tmp_path),
                     ti_match=False, dest_ip=None, domain="x.example")
    assert rec["virustotal"] == {"state": "not_checked", "reason": "pending"}
    assert ss.verified_clean(rec) is False


def test_private_destination_is_not_applicable_not_a_failure(tmp_path):
    a = _abuse(tmp_path)
    rec = ss.collect(_FakeTI(), a, _vt(tmp_path, on=False), ti_match=False, dest_ip="192.168.5.20", domain=None)
    assert rec["abuseipdb"] == {"state": "not_checked", "reason": "no public address"}
    assert ss.verified_clean(rec) is True


def test_missing_sources_and_old_payloads():
    rec = ss.collect(None, None, None, ti_match=False, dest_ip=PUBLIC, domain=None)
    assert all(e == {"state": "not_checked", "reason": "off"} for e in rec.values())
    assert ss.verified_clean(rec) is False                # no threat-intel lists at all: nothing checked
    assert ss.verified_clean(None) is None and ss.verified_clean({}) is None   # written before: caller's old rule


# --- alert text -----------------------------------------------------------------------------------------------------

def _benign(**kw):
    from core.pipeline import _benign_explanations_checked
    args = dict(target="x.example", app_name="", http_reqs=[], ti_risk=0.0, abuse_risk=0.0,
                asn_owner=None, asn_owner_is_safe=None, families=[])
    args.update(kw)
    return "\n".join(_benign_explanations_checked(**args))


def test_alert_text_names_what_was_not_checked():
    default = {"threat_intel": {"state": "clean", "reason": ""},
               "abuseipdb": {"state": "not_checked", "reason": "off"},
               "virustotal": {"state": "not_checked", "reason": "off"}}
    text = _benign(reputation_sources=default)
    assert "on no reputation list that checked it" in text
    assert "Not checked: AbuseIPDB (off), VirusTotal (off)" in text
    assert "no threat-intel or AbuseIPDB list" not in text

    nothing = {k: {"state": "not_checked", "reason": r}
               for k, r in (("threat_intel", "not loaded"), ("abuseipdb", "off"), ("virustotal", "off"))}
    text = _benign(reputation_sources=nothing)
    assert "No reputation source could check the destination" in text
    assert "threat-intel lists (lists not loaded yet)" in text


def test_alert_text_without_a_record_is_unchanged():
    text = _benign()
    assert "no threat-intel or AbuseIPDB list" in text and "Not checked" not in text


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
