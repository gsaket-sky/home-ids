"""Standalone test (run directly): ZeekCollector's background reader keeps file
reading/JSON parsing off the main loop. Root cause it guards (2026-09-29 py-spy
captures): ~75% of pipeline_main_loop heartbeat stalls were the main thread inside
the Zeek tailer's read loop. Requires: no event lost/delayed, poll() returns fast even
with a large backlog, and the cursor is saved incrementally."""
import json, sys, tempfile, time
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))
from extractors.zeek_features import ZeekCollector

FAILURES = []
def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)

with tempfile.TemporaryDirectory() as d:
    logd, stated = _P(d) / "logs", _P(d) / "state"
    logd.mkdir(); stated.mkdir()
    conn = logd / "conn.log"
    conn.write_text("")  # exists, empty -> tailer starts at offset 0/EOF=0
    coll = ZeekCollector(log_dir=str(logd), state_dir=stated)
    N = 60000
    line = lambda i: json.dumps({"ts": time.time(), "uid": f"C{i}", "id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.3", "id.resp_p": 80}) + "\n"
    with open(conn, "a") as f:
        f.write("".join(line(i) for i in range(N)))

    coll.start()
    t0 = time.time()
    check("reader thread is running", coll._reader_running())
    got = []
    deadline = time.time() + 20
    max_poll = 0.0
    while len(got) < N and time.time() < deadline:
        p0 = time.time()
        got.extend(coll.poll())
        max_poll = max(max_poll, time.time() - p0)
        time.sleep(0.05)
    check(f"all {N} backlog events delivered, none lost", len(got) == N, f"got {len(got)}")
    check("poll() on the main thread never blocked on file parsing (<0.25s)", max_poll < 0.25, f"max poll {max_poll:.3f}s")
    cur = json.loads((stated / "zeek_cursor_conn.json").read_text())
    check("cursor advanced to end of file", cur["pos"] == conn.stat().st_size, f"{cur}")

    # live tail: a new line shows up without any inline read in poll()
    with open(conn, "a") as f:
        f.write(line(N))
    time.sleep(0.8)
    check("a newly written line is delivered promptly via the reader thread", len(coll.poll()) == 1)
    coll.stop()

# fallback: without start(), poll() still reads inline (backward compatible)
with tempfile.TemporaryDirectory() as d:
    logd, stated = _P(d) / "logs", _P(d) / "state"
    logd.mkdir(); stated.mkdir()
    (logd / "conn.log").write_text("")
    c2 = ZeekCollector(log_dir=str(logd), state_dir=stated)
    with open(logd / "conn.log", "a") as f:
        f.write(line(1))
    check("without start(), poll() still reads inline", len(c2.poll()) == 1)

if FAILURES:
    print(f"FAILED: {FAILURES}"); sys.exit(1)
print("All checks PASSED.")
