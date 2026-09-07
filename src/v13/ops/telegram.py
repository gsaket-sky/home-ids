"""
v13 Telegram notification helper (v13 full-architecture plan, Phase 7).

A direct port of scripts/retro_hunter.py's own _send_telegram() (itself mirroring
scripts/top_domains_report.py's send_telegram()) -- same config keys
(telegram_token/telegram_chat_id), same silent no-op when unconfigured, same
best-effort try/except (a notification failure must never affect the job that
tried to send it). Factored out as its own small module so it's shared, not
re-copied a third time -- Phase 7's retro-hunter cross-reference is its first
caller, Phase 8d's LLM-review digest is its next.
"""
import json
import logging
import urllib.request
from typing import Any, Dict

LOGGER = logging.getLogger("v13_telegram")


def send_telegram(config: Dict[str, Any], msg: str) -> None:
    """Matches scripts/retro_hunter.py's _send_telegram() exactly: silently
    returns if telegram_token/telegram_chat_id aren't configured (not every
    deployment wants this), logs (never raises) on send failure."""
    token = config.get("telegram_token", "")
    chat_id = config.get("telegram_chat_id", "")
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
        LOGGER.error("Failed to send v13 Telegram notification: %s", e)
