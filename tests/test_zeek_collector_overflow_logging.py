"""
Standalone runtime test for src/extractors/zeek_features.py's ZeekCollector --
regression coverage for the 2026-09-23 restart-loop root cause: overflowing
the 100k-event internal buffer used to log one WARNING per dropped event,
synchronously, on the main detection loop's own thread. A burst of ~40,000
drops in under two minutes blew the heartbeat watchdog's deadline and forced
a restart every ~5-6 minutes, all day. Fixed by counting drops and logging
one summary line per poll() cycle instead.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_zeek_collector_overflow_logging.py`
"""
import logging
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from extractors.zeek_features import ZeekCollector  # noqa: E402


class _CapturingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


logger = logging.getLogger("home_ids.zeek")
handler = _CapturingHandler()
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# Build a collector without touching a real Zeek log dir -- point it at a
# nonexistent path so _init_tailers() sets _available=False and no tailer
# threads exist; _on_event()/poll() are exercised directly instead.
collector = ZeekCollector(log_dir="/does/not/exist", state_dir=_PathForSysPath("/tmp/zeek_overflow_test_state"))
# poll()'s own availability check is unrelated to what this test covers
# (the drop-counting/summary-logging behavior); force it available with no
# real tailers so poll() reaches that logic instead of early-returning [].
collector._available = True
collector._tailers = {}

# Fill the buffer to capacity with no drops.
for i in range(100000):
    collector._on_event("conn", {"id.orig_h": f"10.0.0.{i % 250}"})

check("buffer holds exactly 100000 events at capacity, no drops yet",
      len(collector._events) == 100000 and collector._dropped_event_count == 0,
      f"events={len(collector._events)} dropped={collector._dropped_event_count}")

# Simulate a burst that overflows the buffer by 5000 events -- this is the
# exact shape of the live incident (buffer full, more events keep arriving
# faster than poll() can drain it).
handler.records.clear()
for i in range(5000):
    collector._on_event("notice", {"id.orig_h": "192.168.1.50"})

check("no per-event log line is emitted while the buffer is overflowing",
      len(handler.records) == 0,
      f"got {len(handler.records)} log records during the overflow burst")
check("dropped-event counter tracks the overflow instead of logging each one",
      collector._dropped_event_count == 5000,
      f"dropped_event_count={collector._dropped_event_count}")

# poll() should emit exactly ONE summary line for this cycle's drops, then
# reset the counter for the next cycle.
handler.records.clear()
collector.poll()

check("poll() emits exactly one summary warning for the whole burst",
      len(handler.records) == 1,
      f"got {len(handler.records)} log records after poll()")
if handler.records:
    msg = handler.records[0].getMessage()
    check("the summary line reports the correct drop count",
          "5000" in msg,
          f"message was: {msg!r}")
check("poll() resets the drop counter for the next cycle",
      collector._dropped_event_count == 0,
      f"dropped_event_count={collector._dropped_event_count}")

# A quiet cycle (no drops) must not log anything at all.
handler.records.clear()
collector.poll()
check("a poll() cycle with zero drops logs nothing",
      len(handler.records) == 0,
      f"got {len(handler.records)} log records on a quiet cycle")

logger.removeHandler(handler)

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILURE(S): {FAILURES}")
    sys.exit(1)
else:
    print("All checks passed.")
