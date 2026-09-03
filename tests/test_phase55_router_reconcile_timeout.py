"""
Standalone runtime test for Phase 55: the router-isolation reconciliation mechanism
(ips.py's reconcile_router_isolation_state(), built to fix "device unblocked directly
in the Fritz!Box admin UI stays shown as isolated in Grafana forever") has been
completely non-functional in production since it was built, for a reason invisible in
its own logs: it reused router_webhook_timeout_seconds (5.0s, tuned for the isolate/
unisolate SET action) as the timeout for its own read-only status QUERY -- confirmed
live (2026-09-04, family_pc_fritz_box) that this Fritzbox's TR-064 GetWANAccessByIP
genuinely takes ~10s round-trip, so every single reconcile attempt (boot-time AND every
scheduled 300s pass since) silently timed out, caught by a bare `except Exception:
LOGGER.debug(...)` that's invisible at this service's normal INFO log level. Live
reproduction: Fritz!Box correctly reported the device unblocked
(GET .../router_isolation_status -> {"isolated": false}), the reconcile worker had run
at boot and at least twice more on schedule, yet home_ids_ips_router_isolated_active
was still 1.0 and _router_isolated_devices still had the stale entry -- confirmed by
running reconcile_router_isolation_state() directly against live state and catching the
exact requests.exceptions.ReadTimeout the production logs never surfaced.

Fix: a new, separate router_status_query_timeout_seconds config key (default 20.0) for
this query specifically, used both by ips.py's own HTTP call to the internal FastAPI
endpoint AND by that endpoint's own FritzConnection(timeout=...) call
(middleware/routers/fritzbox_api.py's router_isolation_status()) -- the isolate/
unisolate SET actions keep their original 5.0s router_webhook_timeout_seconds
unchanged. Both failure paths (non-200 response, exception) are upgraded from silent/
DEBUG to LOGGER.warning() so a future recurrence -- for any reason, not just this exact
timeout -- doesn't go unnoticed through every scheduled pass again.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase55_router_reconcile_timeout.py`

Sections:
  A. Config defaults -- router_status_query_timeout_seconds exists, defaults to 20.0,
     independent of router_webhook_timeout_seconds (still 5.0, unchanged)
  B. reconcile_router_isolation_state() uses the NEW config key for its HTTP call's
     timeout, not the old one
  C. A non-200 response now logs a WARNING (not a silent `continue`) and leaves the
     record in place
  D. An exception (e.g. the exact ReadTimeout this was found via) now logs a WARNING
     (not DEBUG) and leaves the record in place
  E. REGRESSION GUARD: a genuinely successful "isolated: false" response still clears
     the stale entry and gauge exactly as before -- this fix only changes the timeout
     budget and failure-path logging, never the success-path behavior
  F. Source-level checks: fritzbox_api.py's endpoint also uses the new config key; the
     SET-action timeout config key is untouched everywhere
"""
import sys
import logging
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from config import DEFAULT_CONFIG as CONFIG_DEFAULTS
from mitigation.ips import IPSMitigator
from core.state_guard import StateManager


class _FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json_body = json_body or {}

    def json(self):
        return self._json_body


class _LogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _make_ips(tmpdir, router_isolated=None):
    state_path = str(_PathForSysPath(tmpdir) / "ids_state.json")
    sm = StateManager(state_path=state_path)
    config = {"interactive_blocking_enabled": True, "state_path": state_path, "fastapi_port": 8010}
    ips = IPSMitigator(config=config, state_manager=sm)
    if router_isolated:
        ips._router_isolated_devices.update(router_isolated)
    return ips


TARGET = {"aa:bb:cc:dd:ee:01": {"ip": "192.168.1.50", "hostname": "test_device", "dev_id": "dev_reconcile_1"}}

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: config defaults
# ═══════════════════════════════════════════════════════════════════════════════════
check("router_status_query_timeout_seconds exists in config defaults, set to 20.0",
      CONFIG_DEFAULTS.get("router_status_query_timeout_seconds") == 20.0,
      f"got {CONFIG_DEFAULTS.get('router_status_query_timeout_seconds')!r}")
check("REGRESSION GUARD: router_webhook_timeout_seconds (the SET-action timeout) is "
      "UNCHANGED at 5.0 -- this fix adds a new key, it doesn't touch the existing one",
      CONFIG_DEFAULTS.get("router_webhook_timeout_seconds") == 5.0,
      f"got {CONFIG_DEFAULTS.get('router_webhook_timeout_seconds')!r}")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: reconcile uses the NEW config key for its HTTP timeout
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    ips = _make_ips(tmpdir, router_isolated=dict(TARGET))
    ips.config["router_status_query_timeout_seconds"] = 33.0
    ips.config["router_webhook_timeout_seconds"] = 5.0  # must NOT be what gets used

    captured_kwargs = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured_kwargs["timeout"] = timeout
        return _FakeResponse(200, {"isolated": True})  # still isolated -- don't clear, just observe the call

    ips.session.get = fake_get
    ips.reconcile_router_isolation_state()
    check("THE CORE FIX: the HTTP call to the internal status endpoint uses "
          "router_status_query_timeout_seconds (33.0), NOT router_webhook_timeout_seconds (5.0)",
          captured_kwargs.get("timeout") == 33.0, f"got timeout={captured_kwargs.get('timeout')}")

with tempfile.TemporaryDirectory() as tmpdir:
    ips = _make_ips(tmpdir, router_isolated=dict(TARGET))
    # No explicit override -- must fall back to the 20.0 default, not crash/None.
    captured_kwargs = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured_kwargs["timeout"] = timeout
        return _FakeResponse(200, {"isolated": True})

    ips.session.get = fake_get
    ips.reconcile_router_isolation_state()
    check("with no explicit config override, the timeout defaults to 20.0",
          captured_kwargs.get("timeout") == 20.0, f"got timeout={captured_kwargs.get('timeout')}")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: a non-200 response now logs a WARNING and leaves the record in place
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    ips = _make_ips(tmpdir, router_isolated=dict(TARGET))
    ips.session.get = lambda *a, **k: _FakeResponse(503)

    ips_logger = logging.getLogger("home_ids.ips")
    cap = _LogCapture()
    ips_logger.addHandler(cap)
    old_level = ips_logger.level
    ips_logger.setLevel(logging.DEBUG)
    try:
        cleared = ips.reconcile_router_isolation_state()
    finally:
        ips_logger.removeHandler(cap)
        ips_logger.setLevel(old_level)

    check("THE CORE FIX: a non-200 status query response now produces a WARNING-level "
          "log record (previously a silent `continue`, invisible at any log level)",
          any(r.levelno == logging.WARNING for r in cap.records), f"records={[r.getMessage() for r in cap.records]}")
    check("REGRESSION GUARD: a non-200 response does NOT clear the existing record "
          "(still 'leave state alone rather than guess')",
          "aa:bb:cc:dd:ee:01" in ips._router_isolated_devices and cleared == 0)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: an exception (the exact live failure mode) now logs a WARNING, not DEBUG
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    ips = _make_ips(tmpdir, router_isolated=dict(TARGET))

    def raise_timeout(*a, **k):
        import requests
        raise requests.exceptions.ReadTimeout("Read timed out.")
    ips.session.get = raise_timeout

    ips_logger = logging.getLogger("home_ids.ips")
    cap = _LogCapture()
    ips_logger.addHandler(cap)
    old_level = ips_logger.level
    ips_logger.setLevel(logging.DEBUG)
    try:
        cleared = ips.reconcile_router_isolation_state()
    finally:
        ips_logger.removeHandler(cap)
        ips_logger.setLevel(old_level)

    check("THE CORE FIX (the exact live bug): a ReadTimeout exception now produces a "
          "WARNING-level log record, not a DEBUG one that's invisible at this "
          "service's normal INFO level -- this is precisely the silence that let the "
          "production bug go unnoticed through every scheduled reconcile pass",
          any(r.levelno == logging.WARNING and "ReadTimeout" in r.getMessage() for r in cap.records),
          f"records={[r.getMessage() for r in cap.records]}")
    check("REGRESSION GUARD: an exception does NOT clear the existing record either",
          "aa:bb:cc:dd:ee:01" in ips._router_isolated_devices and cleared == 0)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: REGRESSION GUARD -- a genuine "isolated: false" success still clears
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    ips = _make_ips(tmpdir, router_isolated=dict(TARGET))
    ips.session.get = lambda *a, **k: _FakeResponse(200, {"isolated": False})

    cleared = ips.reconcile_router_isolation_state()
    check("REGRESSION GUARD: a genuine 'no longer isolated' response still clears the "
          "stale record and reports it cleared -- this fix changes the timeout/logging, "
          "never the actual reconciliation decision",
          cleared == 1 and "aa:bb:cc:dd:ee:01" not in ips._router_isolated_devices,
          f"cleared={cleared}, remaining={ips._router_isolated_devices}")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: source-level checks
# ═══════════════════════════════════════════════════════════════════════════════════
_fritzbox_api_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "middleware" / "routers" / "fritzbox_api.py").read_text(encoding="utf-8")
check("fritzbox_api.py's router_isolation_status() endpoint also uses the new "
      "router_status_query_timeout_seconds config key for its own FritzConnection call",
      'CONFIG.get("router_status_query_timeout_seconds", 20.0)' in _fritzbox_api_src)
check("REGRESSION GUARD: execute_fritzbox_isolation() (the SET action) still uses the "
      "original router_webhook_timeout_seconds key, untouched by this fix",
      'CONFIG.get("router_webhook_timeout_seconds", 5.0)' in _fritzbox_api_src)

_ips_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "mitigation" / "ips.py").read_text(encoding="utf-8")
check("REGRESSION GUARD: _isolate_device_router()/_unisolate_device_router() (the SET "
      "webhook calls) still use router_webhook_timeout_seconds, untouched by this fix",
      _ips_src.count('self.config.get("router_webhook_timeout_seconds", 5.0)') == 2)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 55 router-reconcile-timeout checks PASSED.")
