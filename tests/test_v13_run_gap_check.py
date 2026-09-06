"""
Standalone runtime test for v13's lightweight divergence-check cron entrypoint
(src/v13/ops/run_gap_check.py, Phase 7 wiring).

Covers: run_once()'s config-driven paths (real values, and defaults when the
`compare`/`ingest` sections are absent), graceful no-op when the graph db
doesn't exist yet, and end-to-end wiring -- a real alert + a real matching
v13 decision produces a real divergence record written to the configured
output path.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_run_gap_check.py`
"""
import json
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath

sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.ops.run_gap_check import run_once  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402


# --- graceful no-op when the graph db doesn't exist yet ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    config = {
        "ingest": {"graph_db_path": str(tmp_path / "does_not_exist.db")},
        "compare": {"alerts_mount_path": str(tmp_path / "alerts.json")},
    }
    result = run_once(config)
    check("run_once returns an empty list, not an error, when the graph db doesn't exist yet",
          result == [])


# --- config-driven paths, with real defaults when compare/ingest are absent ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    graph_db_path = tmp_path / "gap_check_test.db"
    alerts_path = tmp_path / "alerts.json"
    output_path = tmp_path / "nested" / "divergence.jsonl"
    cursor_path = tmp_path / "cursor.json"

    store = GraphStore(str(graph_db_path))
    now = time.time()
    store.insert_decision(device_id="10.0.0.50", timestamp=now, state="HIGH",
                            decision_path="hypothesis_high", confidence=0.9, risk_score=8.0)
    store.close()

    config = {
        "ingest": {"graph_db_path": str(graph_db_path)},
        "compare": {
            "alerts_mount_path": str(alerts_path),
            "cursor_path": str(cursor_path),
            "output_path": str(output_path),
            "lookback_seconds": 3600,
        },
    }

    # A fresh AlertsJsonlTailer (constructed fresh inside run_once() every call,
    # persisted only via its cursor FILE) seeks to EOF of whatever already
    # exists in alerts_path at construction time -- it never replays
    # pre-existing content, matching ZeekLogSource/PiHoleLogSource's own
    # documented behavior. So the file must exist (even empty) BEFORE the
    # first priming call, and the real alert appended only AFTER that --
    # otherwise the very first run_once() call "sees" the alert as
    # already-old and silently skips it, same pitfall this session already
    # hit once building the daemon's own tests.
    alerts_path.write_text("", encoding="utf-8")
    priming = run_once(config, now=now)
    check("the priming call (empty alerts file) finds nothing yet, as expected",
          priming == [])

    with open(alerts_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "device": {"ip": "10.0.0.50"}, "timestamp": now,
            "hee_decision_path": "hypothesis_high", "signature": "TEST_SIG", "risk": 8.0,
        }) + "\n")

    divergences = run_once(config, now=now + 1)
    check("run_once finds a real divergence end-to-end using config-driven paths",
          len(divergences) == 1 and divergences[0].kind == "AGREE")
    check("run_once creates the configured output_path's parent directory and writes to it",
          output_path.exists())
    check("run_once uses the configured cursor_path, not a hardcoded default",
          cursor_path.exists())

    # A second call with no new alerts should be a clean no-op, not re-process
    # the same alert (the tailer's own cursor persistence handles this).
    divergences2 = run_once(config, now=now + 2)
    check("a second run_once call with no new alerts returns an empty list (cursor persisted)",
          divergences2 == [])


# --- sensible defaults apply when compare/ingest sections are entirely absent ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    # An empty config with no graph db present at the DEFAULT relative path
    # ("state/v13_graph.db") should still no-op safely rather than crash on a
    # missing key -- exercised from a scratch cwd-independent absolute check:
    # since we can't safely chdir in a shared test process, just confirm the
    # default path construction doesn't raise and correctly reports missing.
    import os
    old_cwd = os.getcwd()
    try:
        os.chdir(tmp)
        result = run_once({})
        check("run_once with a completely empty config falls back to defaults without crashing",
              result == [])
    finally:
        os.chdir(old_cwd)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 run-gap-check checks PASSED.")
