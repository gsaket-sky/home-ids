import sys
from pathlib import Path
import logging
import secrets
from typing import Optional

from fastapi import HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Ensure src/ is in sys.path
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG

LOGGER = logging.getLogger("fritz_middleware")
security = HTTPBearer(auto_error=False)

_PROXY_HEADERS = ("x-forwarded-for", "x-real-ip", "forwarded", "x-forwarded-host")


def _arrived_via_proxy(request: Request) -> bool:
    """A reverse proxy on this host (nginx) connects from 127.0.0.1, so every proxied request LOOKS local.
    Proxies add these headers; a genuine local caller (the web UI's IPC, scripts on the host) does not."""
    return any(request.headers.get(h) for h in _PROXY_HEADERS)


def _accepted_credentials() -> list:
    """The one shared password (when set) plus the legacy API token (Fritz!Box/Pi-hole integrations that
    were configured with it before the shared password existed)."""
    creds = []
    try:
        from core import shared_password
        shared = shared_password.get()
        if shared:
            creds.append(shared)
    except Exception:
        pass
    legacy = CONFIG.get("fritz_api_token", "")
    if legacy:
        creds.append(legacy)
    return creds


def verify_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Security(security)):
    client_host = getattr(request.client, "host", "") if request.client else ""
    via_proxy = _arrived_via_proxy(request)
    # Loopback is trusted ONLY for a direct local caller. Behind nginx the peer is always 127.0.0.1, so
    # trusting it there would let anyone on the LAN skip authentication (found 2026-09-30, console.sky).
    if client_host in ("127.0.0.1", "::1", "localhost") and not via_proxy:
        return "local_loopback_ipc"
    if via_proxy:
        client_host = request.headers.get("x-forwarded-for", client_host).split(",")[0].strip() or client_host

    accepted = _accepted_credentials()
    if not accepted:
        LOGGER.warning("Rejected remote request from %s: no API token or shared password configured.", client_host)
        raise HTTPException(status_code=403, detail="API token required for remote access")

    query_token = request.query_params.get("token")
    if query_token and any(secrets.compare_digest(query_token, c) for c in accepted):
        return query_token

    if not credentials or not any(secrets.compare_digest(credentials.credentials, c) for c in accepted):
        LOGGER.warning("Unauthorized access attempt rejected from %s.", client_host)
        raise HTTPException(status_code=403, detail="Invalid or missing API Token")
    return credentials.credentials
