"""Staleness policy for the locally fetched threat-intel index (ET Open).

A device that stops getting updates must not keep trusting old indicators at full weight forever:
full weight up to FULL_DAYS, linear decay to zero at ZERO_DAYS. Age is measured from the last
SUCCESSFUL check (fresh download or confirmed-unchanged), as recorded by ETOpenUpdater.
Shared by ThreatIntel (engine) and the WebUI (display) -- pure functions, no engine imports."""
import json
import time
from pathlib import Path
from typing import Optional

DAY = 86400.0
FULL_DAYS = 14.0
ZERO_DAYS = 60.0


def decay_factor(age_seconds: Optional[float]) -> float:
    """1.0 while fresh, linear to 0.0 at ZERO_DAYS. Unknown age -> 1.0 (never punish missing bookkeeping)."""
    if age_seconds is None:
        return 1.0
    days = age_seconds / DAY
    if days <= FULL_DAYS:
        return 1.0
    if days >= ZERO_DAYS:
        return 0.0
    return (ZERO_DAYS - days) / (ZERO_DAYS - FULL_DAYS)


def read_age_seconds(cache_dir, now: Optional[float] = None) -> Optional[float]:
    """Age of the ET index from the updater's state file (last_success), else the index file's mtime."""
    now = time.time() if now is None else now
    d = Path(cache_dir)
    try:
        last = json.loads((d / "et_open_state.json").read_text()).get("last_success")
        if last is not None:
            return max(0.0, now - float(last))
    except (OSError, ValueError, AttributeError):
        pass
    try:
        return max(0.0, now - (d / "et_open_index.json.gz").stat().st_mtime)
    except OSError:
        return None


def describe(age_seconds: Optional[float]) -> str:
    """Human line for the WebUI."""
    if age_seconds is None:
        return "Threat data: not downloaded yet"
    days = int(age_seconds // DAY)
    when = "today" if days == 0 else ("1 day ago" if days == 1 else f"{days} days ago")
    text = f"Threat data updated {when}"
    f = decay_factor(age_seconds)
    if f <= 0.0:
        text += " -- too old, no longer used (check the internet connection)"
    elif f < 1.0:
        text += f" -- getting old, weight reduced to {int(round(f * 100))}%"
    return text
