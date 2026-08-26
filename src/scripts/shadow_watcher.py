"""
shadow_watcher.py - Fires a Telegram notification the moment state/shadow_decisions.jsonl
gets new entries (decision_engine.py's shadow-mode divergence log for the evidence-taxonomy
fix -- see Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md).

Runs independently of any interactive session via scripts/scheduler.py's own cron mechanism
(config.yaml's scheduled_jobs.scheduler block) -- same pattern as retro_hunter.py's own
_send_telegram(), just watching a different file. Tracks how many lines it's already
notified about in state/shadow_watcher_bookmark.json so a repeated cron fire (every 5
minutes) never re-sends the same entries, and a shadow_decisions.jsonl that doesn't exist
yet (the common case -- the divergence-worthy pattern is infrequent) is a silent no-op, not
an error.
"""
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import CONFIG
from utils import write_job_health


def _send_telegram(msg: str) -> None:
    token = CONFIG.get("telegram_token", "")
    chat_id = CONFIG.get("telegram_chat_id", "")
    if not token or not chat_id:
        return
    try:
        data = json.dumps({"chat_id": chat_id, "text": msg, "parse_mode": "HTML"}).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"Failed to send Telegram shadow-watcher alert: {e}", file=sys.stderr)


def _load_bookmark(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        return int(json.loads(path.read_text(encoding="utf-8")).get("last_notified_line", 0))
    except Exception:
        return 0


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    shadow_path = state_dir / "shadow_decisions.jsonl"
    bookmark_path = state_dir / "shadow_watcher_bookmark.json"

    if not shadow_path.exists():
        write_job_health(state_dir, "shadow_watcher", time.time() - run_start)
        return

    last_notified_line = _load_bookmark(bookmark_path)
    lines = shadow_path.read_text(encoding="utf-8").splitlines()
    new_lines = lines[last_notified_line:]

    if not new_lines:
        write_job_health(state_dir, "shadow_watcher", time.time() - run_start, extra={"total_divergences_seen": len(lines)})
        return

    entries = []
    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if entries:
        is_first_ever = last_notified_line == 0
        header = (
            "🔬 <b>Shadow-Mode: FIRST divergence observed</b>"
            if is_first_ever else
            f"🔬 <b>Shadow-Mode: {len(entries)} new divergence(s)</b>"
        )
        msg_lines = [
            header,
            "Live verdict vs. the proposed evidence-taxonomy fix "
            "(Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md):",
            "",
        ]
        for e in entries[:10]:
            msg_lines.append(
                f"• <code>{e.get('hostname', 'unknown')}</code> ({e.get('client_ip', 'unknown')}) — "
                f"live: <b>{e.get('old_state')}</b> / {e.get('old_explanation')} "
                f"→ shadow: <b>{e.get('new_state')}</b> / {e.get('new_explanation')} "
                f"(independent sources={e.get('independent_sources')})"
            )
        if len(entries) > 10:
            msg_lines.append(f"...and {len(entries) - 10} more (see state/shadow_decisions.jsonl)")
        _send_telegram("\n".join(msg_lines)[:4000])

    try:
        bookmark_path.write_text(
            json.dumps({"last_notified_line": len(lines), "updated_at": time.time()}, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        print(f"Failed to write shadow_watcher_bookmark.json: {e}", file=sys.stderr)

    write_job_health(state_dir, "shadow_watcher", time.time() - run_start, extra={"total_divergences_seen": len(lines)})


if __name__ == "__main__":
    main()
