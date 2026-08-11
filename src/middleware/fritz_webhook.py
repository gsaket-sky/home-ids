"""
fritz_webhook.py - FastAPI Middleware for Fritz!Box Active Mitigation

Acts as a secure bridge between the Home-IDS engine and the Fritz!Box 7530.
Receives isolation/un-isolation payloads via HTTPS, authenticates them, and executes 
TR-064 SOAP commands to neutralize or restore network access.

RECENT FIXES:
- FIXED (PATH RESOLUTION): Dynamically injects the `src/` directory into `sys.path` 
  to eliminate `ModuleNotFoundError` when Uvicorn is invoked from the project root.
- FIXED (TIMING SIDE-CHANNEL): Replaced non-constant-time string comparison in `verify_token` 
  with `secrets.compare_digest()` to securely prevent bearer token timing attacks.
- FIXED (BIDIRECTIONAL FILTERING): Updated `execute_fritzbox_isolation` to support both 
  `isolate` (`NewDisallow=1`) and `unisolate` (`NewDisallow=0`), leveraging AVM's IP-based 
  `DisallowWANAccessByIP` TR-064 action.
"""

import sys
from pathlib import Path

# ARCHITECTURAL FIX: Dynamically add the 'src' directory to sys.path so absolute 
# imports (like 'config' or 'core') resolve correctly regardless of where Uvicorn is spawned.
CURRENT_DIR = Path(__file__).resolve().parent  # src/middleware
SRC_DIR = CURRENT_DIR.parent                  # src
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import logging
import time
import secrets
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fritzconnection import FritzConnection
from fritzconnection.lib.fritzhosts import FritzHosts
from fritzconnection.core.exceptions import FritzConnectionException, FritzServiceError, FritzActionError

try:
    from config import CONFIG
except ImportError:
    from core.config import CONFIG

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
LOGGER = logging.getLogger("fritz_middleware")

app = FastAPI(title="Fritz!Box Mitigation API", version="1.0.6")
security = HTTPBearer(auto_error=False)

class IsolationRequest(BaseModel):
    action: str = Field(..., description="Action to perform ('isolate' or 'unisolate')")
    ip: str = Field(..., description="IPv4 address of the device")
    mac: str = Field(..., description="MAC address of the device")
    reason: str = Field(default="No reason provided")

def verify_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Security(security)):
    client_host = getattr(request.client, "host", "") if request.client else ""
    if client_host in ("127.0.0.1", "::1", "localhost"):
        # Local loopback IPC (CLI release_device tool, Telegram worker) is trusted on localhost
        return "local_loopback_ipc"

    expected_token = CONFIG.get("fritz_api_token", "")
    if not expected_token:
        return "unauthenticated_local"
    
    if not credentials or not secrets.compare_digest(credentials.credentials, expected_token):
        LOGGER.warning("Unauthorized access attempt rejected from %s.", client_host)
        raise HTTPException(status_code=403, detail="Invalid or missing API Token")
    return credentials.credentials

def execute_fritzbox_isolation(action: str, mac_address: str, ip_address: str, reason: str):
    """
    Background worker that connects to the Fritz!Box TR-064 API to execute 
    WAN blocking (Disallow=1) or WAN restoration (Disallow=0) via AVM's 
    `DisallowWANAccessByIP` action.
    """
    start_time = time.time()
    is_isolating = (action.lower() == "isolate")
    disallow_value = 1 if is_isolating else 0
    
    LOGGER.info("Executing router %s for IP: %s (MAC: %s) | Reason: %s", 
                "isolation" if is_isolating else "restoration", ip_address, mac_address, reason)

    fritz_ip = CONFIG.get("fritz_ip", "192.168.1.1")
    fritz_user = CONFIG.get("fritz_user", "admin")
    fritz_pass = CONFIG.get("fritz_password", "")

    if not fritz_pass:
        LOGGER.error("❌ [CONFIG ERROR] Fritz!Box password is empty in configuration.")
        return

    timeout_seconds = float(CONFIG.get("router_webhook_timeout_seconds", 5.0))
    if timeout_seconds <= 0:
        timeout_seconds = 5.0

    try:
        fc = FritzConnection(address=fritz_ip, user=fritz_user, password=fritz_pass, timeout=timeout_seconds)
        try:
            fc.call_action(
                "X_AVM-DE_HostFilter:1", 
                "DisallowWANAccessByIP", 
                NewIPv4Address=ip_address,
                NewDisallow=disallow_value
            )
            elapsed = round((time.time() - start_time) * 1000, 2)
            LOGGER.critical("✅ [SUCCESS] Fritz!Box WAN %s executed for %s (%s) in %sms", 
                            "isolation" if is_isolating else "restoration", ip_address, mac_address, elapsed)
        except FritzActionError as e:
            LOGGER.error("❌ [API ERROR] Fritz!Box refused TR-064 action for %s: %s", ip_address, e)
    except FritzConnectionException as e:
        LOGGER.error("❌ [NETWORK ERROR] Could not reach Fritz!Box at %s: %s", fritz_ip, e)
    except Exception as e:
        LOGGER.error("❌ [FATAL ERROR] Unexpected failure during router action: %s", e)

@app.post("/isolate", status_code=202)
async def isolate_device(
    payload: IsolationRequest, 
    background_tasks: BackgroundTasks, 
    token: str = Depends(verify_token)
):
    action_lower = payload.action.lower()
    if action_lower not in ("isolate", "unisolate"):
        raise HTTPException(status_code=400, detail="Unsupported action. Expected 'isolate' or 'unisolate'.")

    LOGGER.info("Received router webhook command '%s' for %s (%s)", action_lower, payload.mac, payload.ip)
    
    background_tasks.add_task(
        execute_fritzbox_isolation, 
        action=action_lower,
        mac_address=payload.mac, 
        ip_address=payload.ip, 
        reason=payload.reason
    )
    
    return {"status": "Accepted", "message": f"Router {action_lower} command queued for execution."}

@app.get("/hosts", response_model=List[Dict[str, Any]])
async def get_dhcp_hosts(token: str = Depends(verify_token)):
    fritz_ip = CONFIG.get("fritz_ip", "192.168.1.1")
    fritz_user = CONFIG.get("fritz_user", "admin")
    fritz_pass = CONFIG.get("fritz_password", "")

    if not fritz_pass:
        raise HTTPException(status_code=500, detail="FritzBox credentials not configured.")

    timeout_seconds = float(CONFIG.get("router_hosts_timeout_seconds", 5.0))
    if timeout_seconds <= 0:
        timeout_seconds = 5.0

    try:
        fh = FritzHosts(address=fritz_ip, user=fritz_user, password=fritz_pass, timeout=timeout_seconds)
        hosts_info = fh.get_hosts_info()
        parsed_hosts = []
        for host in hosts_info:
            if host.get("ip"):
                parsed_hosts.append({
                    "ip": host.get("ip"),
                    "mac": host.get("mac", "unknown").lower(),
                    "name": host.get("name", "unknown")
                })
        return parsed_hosts
    except Exception as errors:
        LOGGER.error("Failed to fetch hosts from FritzBox: %s", errors)
        raise HTTPException(status_code=503, detail="FritzBox connection failed.")

@app.get("/health")
async def health_check():
    return {"status": "online", "time": time.time(), "fritz_ip_target": CONFIG.get("fritz_ip")}

class IPCReleaseRequest(BaseModel):
    target: str = Field(..., description="Target IP, MAC, hostname, or 'all'")

@app.post("/api/ipc/release")
def ipc_release(payload: IPCReleaseRequest, token: str = Depends(verify_token)):
    """IPC endpoint for releasing isolated devices.

    ARCHITECTURE NOTE: This endpoint runs in the Uvicorn subprocess — a separate process from
    the main pipeline. It cannot reference the live master_state_manager in memory. The fix is:
    1. Load IPS state from disk (the pipeline flushes every 60s).
    2. Execute release (modifies disk state).
    3. Write a sentinel file so the pipeline reconciles its in-memory IPS state on next cycle.
    """
    LOGGER.info("Received IPC release request for target: %s", payload.target)
    try:
        from core.state_guard import StateManager
        from mitigation.ips import IPSMitigator
        from pathlib import Path
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()
        ips = IPSMitigator(config=CONFIG, state_manager=sm)
        
        if payload.target.lower() in ("all", "--all"):
            count = ips.release_all_devices()
            sm.flush_to_disk()
            # Signal the live pipeline process to reconcile its in-memory IPS state from disk
            Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
            return {"status": "success", "released_count": count}
        else:
            released = ips.release_device(payload.target)
            sm.flush_to_disk()
            # Signal the live pipeline process to reconcile its in-memory IPS state from disk
            Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
            return {"status": "success", "released": released}
    except Exception as e:
        LOGGER.error("IPC release failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

class IPCTargetRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP")

@app.post("/api/ipc/immunize")
def ipc_immunize(payload: IPCTargetRequest, token: str = Depends(verify_token)):
    """IPC endpoint for immunizing a domain (False Positive cache)."""
    LOGGER.info("Received IPC immunize request for domain: %s", payload.target)
    try:
        from core.state_guard import StateManager
        from intelligence.fp_engine import AutonomousFPEngine
        from pathlib import Path
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()
        
        # Load the trust cache and inject the domain
        fp = AutonomousFPEngine(config=CONFIG, state_dir=str(Path(state_path).parent))
        fp._immunize_domain(payload.target, "telegram_operator")
        
        # Reset device validation flags and increment FP count
        for state in sm._states.values():
            state.fp_count = getattr(state, "fp_count", 0) + 1
            state.has_validated_threat = False
        
        sm.flush_to_disk()
        Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
        return {"status": "success", "immunized": payload.target}
    except Exception as e:
        LOGGER.error("IPC immunize failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ipc/block")
def ipc_block(payload: IPCTargetRequest, token: str = Depends(verify_token)):
    """IPC endpoint for explicitly blocking a device via Telegram (interactive mode)."""
    LOGGER.info("Received IPC block request for IP: %s", payload.target)
    try:
        from core.state_guard import StateManager
        from mitigation.ips import IPSMitigator
        from pathlib import Path
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()
        
        ips = IPSMitigator(config=CONFIG, state_manager=sm)
        
        # Locate the device by IP in the state_manager to get its MAC and DevID
        dev_id = sm.resolve_device_id(payload.target, "unknown")

        # FIX: Acquire or create state safely under lock
        with sm.lock_device(dev_id) as state:
            state.has_validated_threat = True
            state.confirmed_threat_count = getattr(state, "confirmed_threat_count", 0) + 1
        
            # Explicit mitigation bypasses interactive mode checks
            # Interactive mode logic only runs when checking to SEND an alert.
            # This explicit mitigate call forces the hardware isolation.
            ips.mitigate(
                st=state,
                target_domain="-",
                risk_score=10.0,
                c2_hits=0,
                dga_burst=False,
                lateral_threat=False,
                is_safe=False,
                reason="Operator explicitly approved hardware isolation."
            )
        
        sm.flush_to_disk()
        Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
        return {"status": "success"}
    except Exception as e:
        LOGGER.error("IPC block failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))