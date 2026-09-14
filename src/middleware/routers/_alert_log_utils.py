"""
_alert_log_utils.py -- shared bounded backward-scan over state/alerts.json,
extracted out of suricata_api.py (the first place this pattern was needed) so
a second consumer (overview_api.py) doesn't reimplement it.

alerts.json is a 170MB+ append-only NDJSON log on the real deployment (one
JSON object per line, no enclosing array) -- reading it forward from the
start would mean parsing the whole file on every request. This tails it
BACKWARD from the end in bounded chunks instead, per the Pi-8GB-target
bounded-I/O rule suricata_api.py's own module docstring already established.
"""
from pathlib import Path


def iter_lines_reverse(path: Path, max_bytes: int, chunk_bytes: int = 1 * 1024 * 1024):
    """Yields complete lines from `path`, most-recent-first, reading backward in
    `chunk_bytes` chunks and stopping once `max_bytes` has been scanned. The very
    first (oldest, leftmost) fragment of the scanned window is dropped unless it's
    genuinely the start of the file -- it may be a partial line whose real start
    lies further back than we read."""
    size = path.stat().st_size
    if size == 0:
        return
    scanned = 0
    pos = size
    buf = b""
    with path.open("rb") as f:
        while pos > 0 and scanned < max_bytes:
            read_size = min(chunk_bytes, pos)
            pos -= read_size
            f.seek(pos)
            buf = f.read(read_size) + buf
            scanned += read_size
            parts = buf.split(b"\n")
            buf = parts[0]
            for line in reversed(parts[1:]):
                if line.strip():
                    yield line
    if pos == 0 and buf.strip():
        yield buf
