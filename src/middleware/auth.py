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

def verify_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Security(security)):
    client_host = getattr(request.client, "host", "") if request.client else ""
    if client_host in ("127.0.0.1", "::1", "localhost"):
        return "local_loopback_ipc"

    expected_token = CONFIG.get("fritz_api_token", "")
    if not expected_token:
        LOGGER.warning("Rejected remote request from %s: API token not configured.", client_host)
        raise HTTPException(status_code=403, detail="API token required for remote access")

    query_token = request.query_params.get("token")
    if query_token and secrets.compare_digest(query_token, expected_token):
        return query_token

    if not credentials or not secrets.compare_digest(credentials.credentials, expected_token):
        LOGGER.warning("Unauthorized access attempt rejected from %s.", client_host)
        raise HTTPException(status_code=403, detail="Invalid or missing API Token")
    return credentials.credentials
