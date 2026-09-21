"""
Standalone runtime test for AlertManager._safe_exc() (src/mitigation/alerts.py).

Context (2026-09-21): .94's logs showed persistent SSLError: UNEXPECTED_EOF_WHILE_READING
failures against the Telegram API over several hours (a network/TLS-interception issue on
that host, unrelated to any of this codebase's logic). requests/urllib3 exceptions raised
against a Telegram URL embed the FULL request URL in their own str() -- and Telegram puts
the bot token directly in the URL path (https://api.telegram.org/bot<TOKEN>/sendMessage)
rather than in a header the way AbuseIPDB/VirusTotal do -- so every one of those SSLError
log lines leaked the live bot token in plaintext into the log file. `_safe_exc()` scrubs the
token out of any exception string before it reaches a log call.

Not part of the pytest suite -- run directly:
`python3 tests/test_alerts_token_redaction.py`.
"""
import sys
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


from mitigation.alerts import AlertManager

_FAKE_TOKEN = "123456789:AAFakeTokenForTestingOnlyNotReal12345"
mgr = AlertManager(token=_FAKE_TOKEN, chat_id="1", enabled=False)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: the real-world shape -- a urllib3/requests SSLError embedding the full URL
# ═══════════════════════════════════════════════════════════════════════════════════
real_shaped_exc = Exception(
    f"HTTPSConnectionPool(host='api.telegram.org', port=443): Max retries exceeded with "
    f"url: /bot{_FAKE_TOKEN}/sendMessage (Caused by SSLError(SSLError(8, "
    f"'[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol')))"
)
scrubbed = mgr._safe_exc(real_shaped_exc)
check("token is removed from a urllib3-style SSLError message",
      _FAKE_TOKEN not in scrubbed, f"got: {scrubbed}")
check("redaction placeholder is present in its place",
      "***REDACTED***" in scrubbed, f"got: {scrubbed}")
check("the rest of the diagnostic text is preserved (host/reason still visible)",
      "UNEXPECTED_EOF_WHILE_READING" in scrubbed and "api.telegram.org" in scrubbed)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: an exception with no token in it at all -- must pass through unchanged
# ═══════════════════════════════════════════════════════════════════════════════════
plain_exc = Exception("connection refused")
check("an exception with no token in it is returned unchanged",
      mgr._safe_exc(plain_exc) == "connection refused")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: no token configured at all -- must not crash (empty-string .replace() guard)
# ═══════════════════════════════════════════════════════════════════════════════════
mgr_no_token = AlertManager(token="", chat_id="1", enabled=False)
check("an empty token never triggers a spurious replace / crash",
      mgr_no_token._safe_exc(Exception("some error")) == "some error")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: source-guard -- every real except-block that can see a token-bearing
# exception actually routes it through _safe_exc() before logging, not raw str(exc)/e.
# ═══════════════════════════════════════════════════════════════════════════════════
_alerts_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "mitigation" / "alerts.py").read_text(encoding="utf-8")
check("SOURCE-GUARD: dispatch worker logs the exception through _safe_exc()",
      'LOGGER.error("Exception in Telegram dispatch worker: %s", self._safe_exc(exc))' in _alerts_src)
check("SOURCE-GUARD: bot updates worker logs the exception through _safe_exc()",
      'LOGGER.debug("Telegram bot updates worker exception: %s", self._safe_exc(exc))' in _alerts_src)
check("SOURCE-GUARD: callback query handler logs the exception through _safe_exc()",
      'LOGGER.error("Failed to process Telegram callback query: %s", self._safe_exc(e))' in _alerts_src)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All alerts.py token-redaction checks PASSED.")
