"""
Standalone runtime test for StateManager.flush_to_disk()'s bounded I/O
(src/core/state_guard.py).

Context (2026-09-21): live incident, same session as the health_manager watchdog
hangs -- a graceful shutdown (pipeline.py's stop(), itself triggered by
health_manager's own pipeline_main_loop-heartbeat self-heal) got stuck for 5+
minutes inside flush_to_disk()'s json.dump()/file-write, the same "even basic
filesystem I/O can stall under this cgroup's memory pressure" pattern already
found (twice, via a live py-spy dump) in health_manager.py's psutil/sysfs reads.
flush_to_disk() is also called every ~60s from the hot pipeline loop, so this
stall is plausibly the ROOT CAUSE of the pipeline_main_loop heartbeat going
stale in the first place -- _bounded_io() bounds the write+replace so a stall
can no longer block the caller (the pipeline's hot loop, or a shutdown sequence)
forever.

Not part of the pytest suite -- run directly:
`python3 tests/test_state_guard_flush_timeout.py`.
"""
import json
import sys
import tempfile
import threading
import time
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


from core.state_guard import StateManager

_tmpdir = tempfile.mkdtemp()
_state_path = str(_PathForSysPath(_tmpdir) / "ids_state.json")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: _bounded_io() itself -- the same shape as health_manager.py's
# _bounded_call(), verified independently here since it's a deliberate local copy.
# ═══════════════════════════════════════════════════════════════════════════════════
value, timed_out = StateManager._bounded_io(lambda: 42, timeout=1.0)
check("a fast fn() returns its real value promptly", value == 42 and timed_out is False)

try:
    StateManager._bounded_io(lambda: (_ for _ in ()).throw(ValueError("boom")), timeout=1.0)
    check("a real exception is propagated", False, "no exception raised")
except ValueError as e:
    check("a real exception is propagated", str(e) == "boom")

released = threading.Event()


def _hang():
    released.wait(timeout=5.0)


value2, timed_out2 = StateManager._bounded_io(_hang, timeout=0.2)
check("a hung fn() is bounded rather than blocking forever", timed_out2 is True and value2 is None)
released.set()


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: a normal flush completes and is readable back, end to end -- the
# bounded-thread wrapping must not change flush_to_disk()'s real behavior when
# nothing is actually stuck.
# ═══════════════════════════════════════════════════════════════════════════════════
sm = StateManager(state_path=_state_path, max_devices=100)
ok = sm.flush_to_disk()
check("a normal flush with no devices still succeeds", ok is True)
check("the state file was actually written", _PathForSysPath(_state_path).exists())
on_disk = json.loads(_PathForSysPath(_state_path).read_text(encoding="utf-8"))
check("the written file round-trips through disk with the expected shape",
      "devices" in on_disk and "ips_state" in on_disk)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: end-to-end -- flush_to_disk() itself returns False (not hanging the
# test) when the underlying write is stuck, via a monkeypatched _bounded_io.
# ═══════════════════════════════════════════════════════════════════════════════════
_original_bounded_io = StateManager._bounded_io
StateManager._bounded_io = staticmethod(lambda fn, timeout: (None, True))
try:
    start = time.time()
    result = sm.flush_to_disk()
    elapsed = time.time() - start
finally:
    StateManager._bounded_io = _original_bounded_io

check("flush_to_disk() returns False (not raise, not hang) when the write times out",
      result is False)
check("flush_to_disk() returns promptly rather than blocking on the stuck write",
      elapsed < 2.0, f"took {elapsed:.2f}s")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: source-guard -- the real write+replace path actually goes through
# _bounded_io(), not a direct unbounded call.
# ═══════════════════════════════════════════════════════════════════════════════════
_sg_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "state_guard.py").read_text(encoding="utf-8")
check("SOURCE-GUARD: flush_to_disk() routes its write through _bounded_io()",
      "self._bounded_io(_write_and_replace, timeout=self._FLUSH_IO_TIMEOUT_SECONDS)" in _sg_src)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All state_guard flush-timeout checks PASSED.")
