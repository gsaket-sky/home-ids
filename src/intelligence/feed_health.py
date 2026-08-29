"""
feed_health.py - Tracks consecutive-failure streaks for external threat-intel feeds
and API-key-based integrations (Feodo Tracker, URLhaus, ThreatFox, AlienVault OTX,
AbuseIPDB, VirusTotal), and sends a Telegram alert once a real outage (not a single
transient blip) is detected.

Prompted by a live incident (2026-08-29): feodotracker.abuse.ch started returning
HTTP 503 "certificate has expired" (their own backend origin cert, confirmed via
direct openssl/curl checks that the public-facing edge cert was fine -- entirely
their infrastructure, nothing this codebase could ever fix). threat_intel.py's
existing fetch functions already degrade gracefully on any failure (log a WARNING,
fall back to the last cached response) but nothing tracked HOW LONG a feed had been
down, and nothing told a human. This module is the fix: record success/failure per
feed, and alert once a streak crosses a threshold -- distinguishing two genuinely
different situations:
  - "external_infra": the provider's own server/network/cert is the problem. There is
    NOTHING to fix here -- alerts only after `_EXTERNAL_INFRA_ALERT_THRESHOLD`
    consecutive failures (filters out single blips), text explicitly says so, and
    resolves itself once the provider does.
  - "auth_expired": OUR OWN API key (AbuseIPDB/VirusTotal/OTX) is being rejected
    (401/403) -- retrying doesn't help, so this alerts on the FIRST occurrence, with
    a direct link to where to regenerate the credential.
  - "rate_limited" (HTTP 429): NEVER alerts. Hitting a free-tier daily/hourly cap is
    expected, routine behavior (AbuseIPDB/VirusTotal's own clients already size their
    request volume against a _DAILY_CAP specifically because crossing the provider's
    real limit is normal, not a fault) -- it resolves itself at the next reset with no
    operator action possible or needed, so it's tracked in state for observability but
    never sent to Telegram. Kept as its own category (not folded into external_infra)
    so this distinction is explicit rather than accidental.
"""
import json
import logging
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional

from config import CONFIG

LOGGER = logging.getLogger("home_ids.feed_health")

_EXTERNAL_INFRA_ALERT_THRESHOLD = 3  # consecutive failures before alerting (see module docstring)
_STATE_LOCK = threading.Lock()

_CATEGORY_LABELS = {
    "external_infra": "the provider's own infrastructure",
    "rate_limited": "rate limiting",
    "auth_expired": "an invalid/expired API key",
}

# Where a human should go to regenerate each credential -- only feeds with a real key
# need this; the free abuse.ch feeds (feodo/urlhaus/threatfox) never hit auth_expired.
_CREDENTIAL_HELP = {
    "abuseipdb": ("ABUSEIPDB_KEY", "https://www.abuseipdb.com/account/api"),
    "virustotal": ("VIRUSTOTAL_KEY", "https://www.virustotal.com/gui/my-apikey"),
    "otx": ("OTX_API_KEY", "https://otx.alienvault.com/api"),
}


def _state_path() -> Path:
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    return state_dir / "feed_health.json"


def _load_state() -> dict:
    path = _state_path()
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    try:
        path = _state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception as exc:
        LOGGER.debug("Failed to write feed_health.json: %s", exc)


def _send_telegram(msg: str) -> None:
    """Same raw-urllib pattern already duplicated in retro_hunter.py/ollama_soc.py --
    no shared helper exists yet in this codebase, so this is a third copy rather than
    introducing a new cross-cutting dependency for one call site."""
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
    except Exception as exc:
        LOGGER.error("Failed to send feed-health Telegram alert: %s", exc)


def record_success(feed_name: str) -> None:
    """Call on every successful fetch. Resets the failure streak; if the feed was
    previously in an alerted state, sends one recovery message and clears it."""
    with _STATE_LOCK:
        state = _load_state()
        entry = state.get(feed_name, {})
        was_alerted = bool(entry.get("alerted_at"))
        first_failure_ts = entry.get("first_failure_ts")
        state[feed_name] = {
            "consecutive_failures": 0, "last_success_ts": time.time(),
            "last_error": None, "category": None, "alerted_at": None,
        }
        _save_state(state)

    if was_alerted:
        down_for = ""
        if first_failure_ts:
            hours = (time.time() - first_failure_ts) / 3600.0
            down_for = f" (was down for ~{hours:.1f}h)"
        _send_telegram(f"✅ <b>{feed_name}</b> recovered{down_for} — back to normal.")


def record_failure(feed_name: str, error: str, category: str) -> None:
    """Call on every failed fetch. category: "external_infra" | "auth_expired" |
    "rate_limited". auth_expired alerts on the first occurrence (retrying an invalid
    key never helps); the other two alert only after
    _EXTERNAL_INFRA_ALERT_THRESHOLD consecutive failures, and only once per streak."""
    now = time.time()
    with _STATE_LOCK:
        state = _load_state()
        entry = state.get(feed_name, {})
        consecutive = entry.get("consecutive_failures", 0) + 1
        first_failure_ts = entry.get("first_failure_ts") if consecutive > 1 else now
        already_alerted = bool(entry.get("alerted_at"))
        state[feed_name] = {
            "consecutive_failures": consecutive, "first_failure_ts": first_failure_ts,
            "last_error": str(error), "category": category,
            "alerted_at": entry.get("alerted_at"), "last_success_ts": entry.get("last_success_ts"),
        }
        # BUGFIX (2026-08-29, user catch): rate_limited (HTTP 429) must NEVER alert --
        # hitting a free-tier daily/hourly cap is expected, routine behavior (this
        # codebase's own AbuseIPDB/VirusTotal clients already size their own request
        # volume against a _DAILY_CAP specifically because crossing the provider's
        # real limit is a normal, self-resolving-at-the-next-reset condition, not an
        # outage). Still recorded in state (useful for observability) -- just never
        # sent to Telegram.
        should_alert = not already_alerted and category != "rate_limited" and (
            category == "auth_expired" or consecutive >= _EXTERNAL_INFRA_ALERT_THRESHOLD
        )
        if should_alert:
            state[feed_name]["alerted_at"] = now
        _save_state(state)

    if not should_alert:
        return

    label = _CATEGORY_LABELS.get(category, category)
    if category == "auth_expired":
        env_var, help_url = _CREDENTIAL_HELP.get(feed_name, ("its API key", ""))
        link = f"\nGenerate a new one: {help_url}\nThen update <code>{env_var}</code> in .env." if help_url else ""
        msg = (
            f"🔑 <b>{feed_name}</b> API key appears invalid/expired (HTTP auth failure).\n"
            f"This needs YOU to act — retrying won't fix it.{link}\n"
            f"Last error: {error}"
        )
    else:
        hours_down = (now - first_failure_ts) / 3600.0
        msg = (
            f"🌐 <b>{feed_name}</b> has failed {consecutive} refresh cycles in a row "
            f"(~{hours_down:.1f}h) — {label}.\n"
            f"Nothing to fix here — this is on their side, not ours. Will auto-recover "
            f"once they do; still using the last-known-good cached data meanwhile.\n"
            f"Last error: {error}"
        )
    _send_telegram(msg)


def classify_url_error(exc: Exception) -> str:
    """Best-effort category from a urllib URLError/HTTPError -- shared by every call
    site so they don't each reimplement the same status-code check."""
    code = getattr(exc, "code", None)
    if code in (401, 403):
        return "auth_expired"
    if code == 429:
        return "rate_limited"
    return "external_infra"
