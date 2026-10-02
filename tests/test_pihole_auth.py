"""Pi-hole v6 login helper (mitigation/pihole_auth.py) and its use by check_pihole_health. Offline; pytest."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from mitigation import pihole_auth  # noqa: E402
from mitigation import ips  # noqa: E402

URL = "http://127.0.0.1:8080"


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.content = b"x"

    def json(self):
        return self._body


class _FakeSession:
    """Records calls; `logins` is a queue of responses for POST /api/auth, `gets` for GETs."""
    def __init__(self, logins=None, gets=None):
        self.logins = list(logins or [])
        self.gets = list(gets or [])
        self.post_calls, self.get_calls = [], []

    def post(self, url, json=None, timeout=None):
        self.post_calls.append((url, json))
        return self.logins.pop(0) if self.logins else _Resp(401, {"session": {"valid": False}})

    def get(self, url, headers=None, timeout=None):
        self.get_calls.append((url, dict(headers or {})))
        return self.gets.pop(0) if self.gets else _Resp(200, {"domains": []})


def _ok(sid="SID1", validity=300):
    return _Resp(200, {"session": {"valid": True, "sid": sid, "validity": validity}})


@pytest.fixture(autouse=True)
def _clean():
    pihole_auth.clear()
    yield
    pihole_auth.clear()


def test_no_password_means_no_headers():
    s = _FakeSession()
    assert pihole_auth.auth_headers(URL, "", s) == {}
    assert s.post_calls == []


def test_logs_in_once_and_caches_the_session():
    s = _FakeSession(logins=[_ok("SID1")])
    assert pihole_auth.auth_headers(URL, "pw", s) == {"sid": "SID1"}
    assert pihole_auth.auth_headers(URL + "/", "pw", s) == {"sid": "SID1"}      # trailing slash = same key
    assert len(s.post_calls) == 1
    assert s.post_calls[0] == (f"{URL}/api/auth", {"password": "pw"})


def test_invalidate_forces_a_new_login():
    s = _FakeSession(logins=[_ok("A"), _ok("B")])
    assert pihole_auth.auth_headers(URL, "pw", s) == {"sid": "A"}
    pihole_auth.invalidate(URL, "pw")
    assert pihole_auth.auth_headers(URL, "pw", s) == {"sid": "B"}


def test_open_api_without_a_session_id_needs_no_header():
    s = _FakeSession(logins=[_Resp(200, {"session": {"valid": True, "sid": None}})])
    assert pihole_auth.auth_headers(URL, "pw", s) == {}


def test_refused_login_falls_back_to_the_legacy_raw_header():
    s = _FakeSession(logins=[_Resp(401, {"session": {"valid": False, "message": "password incorrect"}})])
    assert pihole_auth.auth_headers(URL, "pw", s) == {"sid": "pw"}


def test_failed_login_is_not_retried_every_call():
    s = _FakeSession(logins=[_Resp(401, {"session": {"valid": False}})])
    pihole_auth.auth_headers(URL, "pw", s)
    pihole_auth.auth_headers(URL, "pw", s)
    assert len(s.post_calls) == 1


def test_connection_error_falls_back_instead_of_raising():
    class Boom:
        def post(self, *a, **k):
            raise ConnectionError("down")
    assert pihole_auth.auth_headers(URL, "pw", Boom()) == {"sid": "pw"}


def test_short_validity_is_clamped_so_it_does_not_log_in_every_request():
    s = _FakeSession(logins=[_ok("A", validity=1)])
    pihole_auth.auth_headers(URL, "pw", s)
    pihole_auth.auth_headers(URL, "pw", s)
    assert len(s.post_calls) == 1


CFG = {"ips_pihole_enabled": True, "pihole_api_url": URL, "pihole_api_path": "/api/domains", "pihole_api_password": "pw"}


def test_health_check_uses_a_real_session_not_the_raw_password():
    s = _FakeSession(logins=[_ok("SID1")], gets=[_Resp(200, {"domains": []})])
    ok, msg = ips.check_pihole_health(CFG, session=s)
    assert ok, msg
    assert s.get_calls[0][1] == {"sid": "SID1"}


def test_health_check_relogs_in_once_when_the_session_expired():
    s = _FakeSession(logins=[_ok("OLD"), _ok("NEW")],
                     gets=[_Resp(401), _Resp(200, {"domains": []})])
    ok, msg = ips.check_pihole_health(CFG, session=s)
    assert ok, msg
    assert [c[1] for c in s.get_calls] == [{"sid": "OLD"}, {"sid": "NEW"}]


def test_health_check_still_reports_a_genuinely_wrong_password():
    s = _FakeSession(logins=[_Resp(401, {"session": {"valid": False}}), _Resp(401, {"session": {"valid": False}})],
                     gets=[_Resp(401), _Resp(401)])
    ok, msg = ips.check_pihole_health(CFG, session=s)
    assert not ok and "authentication rejected" in msg
