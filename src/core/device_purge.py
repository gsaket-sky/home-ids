"""device_purge.py - hands "Remove device" requests from the API process to the engine.

The web UI's Remove device runs in the API process, but the engine holds the device in memory (state, familiarity,
per-device model, evidence, metric labels) and its next state flush would write the device straight back. So the API
queues a request here and touches .ipc_sync_signal; the engine applies it on its next cycle (pending_purges() +
done()), and also once at start-up for requests made while it was down.

One file per request (state/purge_requests/<random>.json), so the two processes never write the same file.
"""
import json
import logging
import os
import uuid
from pathlib import Path
from typing import List, Tuple

LOGGER = logging.getLogger("home_ids.device_purge")

QUEUE_DIR = "purge_requests"


def request_purge(state_dir, device_id: str) -> Path:
    queue = Path(state_dir) / QUEUE_DIR
    queue.mkdir(parents=True, exist_ok=True)
    path = queue / f"{uuid.uuid4().hex}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"device_id": device_id}), encoding="utf-8")
    os.replace(tmp, path)
    return path


def pending_purges(state_dir) -> List[Tuple[Path, str]]:
    """(request file, device_id) for every queued request, oldest first. Unreadable files are dropped."""
    queue = Path(state_dir) / QUEUE_DIR
    if not queue.is_dir():
        return []
    out = []
    for path in sorted(queue.glob("*.json"), key=lambda p: p.stat().st_mtime):
        try:
            device_id = str(json.loads(path.read_text(encoding="utf-8")).get("device_id") or "")
        except (OSError, ValueError, AttributeError) as exc:
            LOGGER.warning("Dropping unreadable purge request %s: %s", path.name, exc)
            done(path)
            continue
        if device_id:
            out.append((path, device_id))
        else:
            done(path)
    return out


def done(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
