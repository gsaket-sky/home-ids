"""
runtime_paths.py - where files that are rewritten every few seconds live.

Flash wear (2026-10-02, measured on .94): heartbeats, the health snapshot and the Zeek tail cursors are tiny but
rewritten every 2-15 s -- tens of thousands of small writes a day, each costing an SD card a whole flash-block
rewrite. None of them needs to survive a reboot: a heartbeat is only meaningful while the process runs, the health
snapshot is rebuilt every cycle, and a lost cursor just means the tailer starts at the end of the current Zeek log.

In the Docker stack `state/run` is a RAM-backed volume (tmpfs, see docker-compose.yml) shared by the engine, the
scheduler and the web UI. Without it (native install, tests) everything falls back to the state directory itself,
exactly as before.
"""
from pathlib import Path

RUN_SUBDIR = "run"


def runtime_dir(state_dir) -> Path:
    run = Path(state_dir) / RUN_SUBDIR
    return run if run.is_dir() else Path(state_dir)
