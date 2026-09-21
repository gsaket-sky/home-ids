"""
Standalone runtime test for main.py's _SecretRedactingFormatter.

Context (2026-09-21): a live log line pasted by the user during the OOM-crash-loop
investigation showed .94's REAL Telegram bot token in plaintext -- not from any
exception this codebase catches and formats itself (src/mitigation/alerts.py's
_safe_exc(), shipped earlier the same session, already covers that), but from
urllib3's OWN internal "Retrying ... after connection broken by ..." warning,
logged automatically whenever alerts.py's Retry-configured requests.Session retries
a connection -- and Telegram's API puts the bot token directly in the URL path, so
that URL (with the live token) ends up in the log line urllib3 itself emits.
Chasing individual libraries/call sites one at a time is the same whack-a-mole this
session already learned not to play with health_manager's blocking calls --
_SecretRedactingFormatter redacts every configured secret from the FULLY rendered
text of every log record, from every logger, closing the whole class of leak
instead of one instance of it.

Not part of the pytest suite -- run directly:
`python3 tests/test_logging_secret_redaction.py`.
"""
import logging
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


from main import _SecretRedactingFormatter

_FAKE_TOKEN = "123456789:AAFakeTokenForTestingOnlyNotReal12345"
_FAKE_PASSWORD = "SuperSecretPihole123"


def _render(formatter: _SecretRedactingFormatter, record: logging.LogRecord) -> str:
    return formatter.format(record)


def _make_record(msg, args=(), exc_info=None) -> logging.LogRecord:
    record = logging.LogRecord(
        name="urllib3.connectionpool", level=logging.WARNING, pathname=__file__,
        lineno=1, msg=msg, args=args, exc_info=exc_info,
    )
    return record


fmt = _SecretRedactingFormatter(
    "%(levelname)s %(name)s %(message)s", secrets=[_FAKE_TOKEN, _FAKE_PASSWORD],
)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: the real-world shape -- a third-party library's own log message embeds
# a token-bearing URL via %s args, not anything this codebase's own code formatted.
# ═══════════════════════════════════════════════════════════════════════════════════
record = _make_record(
    "Retrying (Retry(total=2)) after connection broken by 'ReadTimeoutError(...)': "
    "/bot%s/getUpdates?offset=0&timeout=10",
    args=(_FAKE_TOKEN,),
)
out = _render(fmt, record)
check("token is redacted from a third-party library's own %s-formatted log line",
      _FAKE_TOKEN not in out, f"got: {out}")
check("redaction placeholder appears in its place", "***REDACTED***" in out)
check("the rest of the diagnostic text is preserved", "ReadTimeoutError" in out and "getUpdates" in out)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: a secret embedded inside an exception TRACEBACK (exc_info=True) -- a
# Filter running before formatting cannot catch this; a Formatter wrapping the
# fully-rendered text (including the traceback) does.
# ═══════════════════════════════════════════════════════════════════════════════════
try:
    raise ValueError(f"auth rejected for password {_FAKE_PASSWORD}")
except ValueError:
    exc_info = sys.exc_info()
record2 = _make_record("Pi-hole auth check failed", exc_info=exc_info)
out2 = _render(fmt, record2)
check("a secret embedded inside an exception traceback is also redacted",
      _FAKE_PASSWORD not in out2, f"got: {out2}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: a message with no secret in it at all -- must pass through unchanged
# (aside from the normal formatter fields).
# ═══════════════════════════════════════════════════════════════════════════════════
record3 = _make_record("Pipeline loop active. Ingesting network telemetry...")
out3 = _render(fmt, record3)
check("a message with no secret in it is unaffected",
      "Pipeline loop active. Ingesting network telemetry..." in out3)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: no secrets configured at all (e.g. telegram disabled, empty token) --
# must not crash on an empty-string secret list.
# ═══════════════════════════════════════════════════════════════════════════════════
fmt_empty = _SecretRedactingFormatter("%(message)s", secrets=["", None, "   "])
record4 = _make_record("some message")
out4 = _render(fmt_empty, record4)
check("empty/blank configured secrets never crash or spuriously redact",
      out4 == "some message", f"got: {out4}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: source-guard -- setup_logging() actually installs this formatter on
# every root handler, seeded from the real secret config keys, not just defines it.
# ═══════════════════════════════════════════════════════════════════════════════════
_main_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "main.py").read_text(encoding="utf-8")
check("SOURCE-GUARD: setup_logging() builds a _SecretRedactingFormatter",
      "_redacting_formatter = _SecretRedactingFormatter(" in _main_src)
check("SOURCE-GUARD: setup_logging() installs it on every root logger handler",
      "_handler.setFormatter(_redacting_formatter)" in _main_src)
for _key in ("telegram_token", "otx_api_key", "abuseipdb_api_key", "virustotal_api_key",
             "pihole_api_password", "fritz_password", "fritz_api_token"):
    check(f"SOURCE-GUARD: {_key} is included in the redacted secret set",
          f'"{_key}"' in _main_src)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All logging secret-redaction checks PASSED.")
