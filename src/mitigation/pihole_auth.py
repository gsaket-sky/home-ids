"""Pi-hole v6 API authentication for every engine call site.

Pi-hole v6 does not accept the web/API password as a session header. A client logs in with
`POST /api/auth {"password": ...}` and sends the returned session id as the `sid` header.
The engine used to send the raw password as `sid`; that only "worked" while the Pi-hole had NO
password (API open) -- e.g. a native install with an empty `pwhash`. The moment a Pi-hole is
password-protected (the Docker stack sets one), every call returned 401 and the health check
reported "authentication rejected" (found 2026-09-30 after moving the live host to Docker).

`auth_headers()` logs in once, caches the session until shortly before it expires, and returns
the headers to use. If the login itself fails it falls back to the old raw-password header (an
open API, or an older Pi-hole, keeps working; a wrong password still surfaces as 401 upstream).
"""
import logging
import threading
import time
from typing import Any, Dict, Optional

import requests

LOGGER = logging.getLogger("home_ids.pihole_auth")

_LOCK = threading.Lock()
_CACHE: Dict[tuple, tuple] = {}   # (api_url, password) -> (headers, expires_at)
_MIN_TTL_SECONDS = 30.0           # never cache shorter than this (avoid a login per request)
_FAIL_TTL_SECONDS = 15.0          # after a failed login, don't hammer /api/auth
_OPEN_API_TTL_SECONDS = 60.0
_TTL_FRACTION = 0.8               # renew at 80% of the session's validity


def invalidate(api_url: str, password: str) -> None:
    """Forget a cached session (call after a 401 so the next call logs in again)."""
    with _LOCK:
        _CACHE.pop(((api_url or "").rstrip("/"), password), None)


def clear() -> None:
    with _LOCK:
        _CACHE.clear()


def _login(base: str, password: str, session: Optional[Any], timeout: float):
    client = session or requests
    try:
        resp = client.post(f"{base}/api/auth", json={"password": password}, timeout=timeout)
        data = resp.json() if resp.content else {}
        s = (data.get("session") or {}) if isinstance(data, dict) else {}
        if resp.status_code == 200 and s.get("valid"):
            sid = s.get("sid")
            if sid:
                validity = float(s.get("validity") or 300.0)
                return {"sid": sid}, max(_MIN_TTL_SECONDS, validity * _TTL_FRACTION)
            return {}, _OPEN_API_TTL_SECONDS      # valid without a session id: the API is not protected
        LOGGER.debug("Pi-hole login refused (HTTP %s)", resp.status_code)
    except Exception as exc:
        LOGGER.debug("Pi-hole login failed: %s", exc)
    return {"sid": password}, _FAIL_TTL_SECONDS


def auth_headers(api_url: str, password: str, session: Optional[Any] = None, timeout: float = 3.0) -> Dict[str, str]:
    """Headers to send to the Pi-hole API. `{}` when no password is configured. The appliance's shared
    password (core/shared_password.py), when set, wins over the configured one -- it is the single source
    of truth for every app's login."""
    try:
        from core import shared_password
        password = shared_password.get() or password
    except Exception:
        pass
    if not password:
        return {}
    base = (api_url or "").rstrip("/")
    if not base:
        return {"sid": password}
    key = (base, password)
    now = time.time()
    with _LOCK:
        hit = _CACHE.get(key)
        if hit and hit[1] > now:
            return dict(hit[0])
    headers, ttl = _login(base, password, session, timeout)
    with _LOCK:
        _CACHE[key] = (headers, now + ttl)
    return dict(headers)
