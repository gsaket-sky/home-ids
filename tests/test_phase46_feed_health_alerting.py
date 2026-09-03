"""
Standalone runtime test for Phase 46: feed_health.py, a consecutive-failure tracker
for external threat-intel feeds/API keys that sends one Telegram alert once a real
outage (not a single blip) is detected -- and one recovery message when it clears.

Context (2026-08-29): feodotracker.abuse.ch started returning HTTP 503 "certificate
has expired" (their own backend origin cert -- confirmed via direct openssl/curl
checks the public-facing edge cert was fine, entirely their infrastructure, nothing
this codebase could fix). threat_intel.py's existing fetch functions already degrade
gracefully (log + fall back to cache) but never tracked failure duration or told a
human. Important distinction this feature encodes: "external_infra"/"rate_limited"
failures are never fixable from here (a provider's own server is their problem) and
only alert after 3 consecutive failures to filter out single blips; "auth_expired"
(a 401/403 -- OUR OWN API key being rejected) alerts on the very first occurrence,
since retrying an invalid key never helps.

Not part of the pytest suite -- run directly:
`python3 tests/test_phase46_feed_health_alerting.py`.

feed_health.py's Telegram send is the same real-network-call raw-urllib pattern used
throughout this codebase (retro_hunter.py/ollama_soc.py) -- covered here with a real
CONFIG object that has no telegram_token set, so _send_telegram() takes its documented
early-return path (no token/chat_id -> return before ever making a request) rather
than mocking the network call, matching this repo's no-mock convention.
"""
import sys
import tempfile
import os
from pathlib import Path as _PathForSysPath

_SRC_DIR = str(_PathForSysPath(__file__).resolve().parent.parent / "src")
sys.path.insert(0, _SRC_DIR)

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# Real CONFIG object, pointed at a real temp state dir -- no mocks. telegram_token
# left unset so _send_telegram() exercises its real early-return path instead of
# attempting an actual network call during a test run.
_tmpdir = tempfile.mkdtemp()
os.makedirs(os.path.join(_tmpdir, "state"), exist_ok=True)
import config as _config_module
# BUGFIX (2026-09-03): was CONFIG._data -- LiveConfig.get() actually reads
# self._config (config.py), so this never redirected anything. The test's own
# temp-dir isolation was a complete no-op: every run silently read/wrote the
# REAL production state/feed_health.json instead, confirmed live (test_vt_quota
# etc. found sitting in it with real accumulated counts from repeated test runs).
_config_module.CONFIG._config = {
    "state_path": os.path.join(_tmpdir, "state", "ids_state.json"),
    "telegram_token": "", "telegram_chat_id": "",
}

from intelligence import feed_health


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: external_infra / rate_limited -- threshold-gated, only alerts once
# ═══════════════════════════════════════════════════════════════════════════════════
feed_health.record_failure("test_feodo", "HTTP 503", "external_infra")
s = feed_health._load_state()
check("1st external_infra failure does NOT alert yet",
      s["test_feodo"]["alerted_at"] is None, f"got {s['test_feodo']}")
check("1st failure records consecutive_failures=1",
      s["test_feodo"]["consecutive_failures"] == 1)

feed_health.record_failure("test_feodo", "HTTP 503", "external_infra")
s = feed_health._load_state()
check("2nd consecutive external_infra failure still does NOT alert (below threshold)",
      s["test_feodo"]["alerted_at"] is None)

feed_health.record_failure("test_feodo", "HTTP 503", "external_infra")
s = feed_health._load_state()
check("3rd consecutive failure crosses the threshold and alerts",
      s["test_feodo"]["alerted_at"] is not None, f"got {s['test_feodo']}")
first_alert_ts = s["test_feodo"]["alerted_at"]

feed_health.record_failure("test_feodo", "HTTP 503", "external_infra")
s = feed_health._load_state()
check("4th consecutive failure does NOT re-alert (already alerted this streak)",
      s["test_feodo"]["alerted_at"] == first_alert_ts,
      f"alerted_at changed: {first_alert_ts} -> {s['test_feodo']['alerted_at']}")
check("consecutive_failures keeps counting past the alert threshold",
      s["test_feodo"]["consecutive_failures"] == 4)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: auth_expired -- alerts on the very FIRST occurrence, no threshold
# ═══════════════════════════════════════════════════════════════════════════════════
feed_health.record_failure("test_abuseipdb", "HTTP 401 Unauthorized", "auth_expired")
s = feed_health._load_state()
check("auth_expired alerts on the very first failure (retrying a bad key never helps)",
      s["test_abuseipdb"]["alerted_at"] is not None, f"got {s['test_abuseipdb']}")
check("auth_expired category is recorded correctly",
      s["test_abuseipdb"]["category"] == "auth_expired")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B2: rate_limited -- BUGFIX (user catch), NEVER alerts, at any streak length.
# Hitting a free-tier daily/hourly cap is expected/routine, not an outage -- unlike
# external_infra, no threshold makes it "bad enough" to page the operator, because
# there's nothing to act on either way; it resolves at the provider's own reset.
# ═══════════════════════════════════════════════════════════════════════════════════
for _ in range(10):
    feed_health.record_failure("test_vt_quota", "HTTP 429 Too Many Requests", "rate_limited")
s = feed_health._load_state()
check("rate_limited NEVER alerts, even after 10 consecutive occurrences",
      s["test_vt_quota"]["alerted_at"] is None, f"got {s['test_vt_quota']}")
check("rate_limited failures are still recorded in state (for observability)",
      s["test_vt_quota"]["consecutive_failures"] == 10
      and s["test_vt_quota"]["category"] == "rate_limited")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: recovery -- record_success() resets the streak and clears alerted_at
# ═══════════════════════════════════════════════════════════════════════════════════
feed_health.record_success("test_feodo")
s = feed_health._load_state()
check("record_success() resets consecutive_failures to 0",
      s["test_feodo"]["consecutive_failures"] == 0)
check("record_success() clears alerted_at",
      s["test_feodo"]["alerted_at"] is None)
check("record_success() sets last_success_ts",
      s["test_feodo"]["last_success_ts"] is not None)

feed_health.record_success("test_abuseipdb")
s = feed_health._load_state()
check("record_success() also clears an auth_expired alert streak",
      s["test_abuseipdb"]["alerted_at"] is None and s["test_abuseipdb"]["consecutive_failures"] == 0)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: a feed that was never alerted doesn't send a spurious recovery message on
# its first-ever success (no crash on a feed_name with no prior state at all)
# ═══════════════════════════════════════════════════════════════════════════════════
try:
    feed_health.record_success("test_never_seen_before")
    no_crash = True
except Exception as exc:
    no_crash = False
    _exc = exc
check("record_success() on a never-before-seen feed name does not crash",
      no_crash, f"raised {_exc if not no_crash else ''}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: classify_url_error() -- the shared status-code categorizer
# ═══════════════════════════════════════════════════════════════════════════════════
class _FakeHTTPError(Exception):
    def __init__(self, code):
        self.code = code

check("classify_url_error() maps HTTP 401 to auth_expired",
      feed_health.classify_url_error(_FakeHTTPError(401)) == "auth_expired")
check("classify_url_error() maps HTTP 403 to auth_expired",
      feed_health.classify_url_error(_FakeHTTPError(403)) == "auth_expired")
check("classify_url_error() maps HTTP 429 to rate_limited",
      feed_health.classify_url_error(_FakeHTTPError(429)) == "rate_limited")
check("classify_url_error() maps HTTP 503 (or any other code) to external_infra",
      feed_health.classify_url_error(_FakeHTTPError(503)) == "external_infra")
check("classify_url_error() defaults to external_infra for an exception with no .code "
      "at all (a bare network/timeout error, not an HTTP status)",
      feed_health.classify_url_error(Exception("connection refused")) == "external_infra")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: source-guard -- every call site the plan named actually wires this in
# ═══════════════════════════════════════════════════════════════════════════════════
_ti_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "intelligence" / "threat_intel.py").read_text(encoding="utf-8")
check("SOURCE-GUARD: threat_intel.py imports feed_health",
      "from intelligence import feed_health" in _ti_src)
check("SOURCE-GUARD: _fetch_with_cache() records both success and failure",
      "feed_health.record_success(feed_name)" in _ti_src
      and "feed_health.record_failure(feed_name, str(exc), feed_health.classify_url_error(exc))" in _ti_src)
check("SOURCE-GUARD: the OTX refresh path records both success and failure",
      'feed_health.record_success("otx")' in _ti_src and 'feed_health.record_failure("otx"' in _ti_src)
check("SOURCE-GUARD: AbuseIPDB._refresh() records both success and failure",
      'feed_health.record_success("abuseipdb")' in _ti_src and 'feed_health.record_failure("abuseipdb"' in _ti_src)
check("SOURCE-GUARD: VirusTotalClient._query() records both success and failure",
      'feed_health.record_success("virustotal")' in _ti_src and 'feed_health.record_failure("virustotal"' in _ti_src)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 46 feed-health alerting checks PASSED.")
