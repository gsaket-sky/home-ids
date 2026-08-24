import time
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fritzconnection import FritzConnection
from fritzconnection.lib.fritzhosts import FritzHosts
from fritzconnection.core.exceptions import FritzConnectionException, FritzActionError

from middleware.auth import verify_token, CONFIG, LOGGER
from core.state_guard import StateManager
from mitigation.ips import IPSMitigator
from pathlib import Path

router = APIRouter()

class IsolationRequest(BaseModel):
    action: str = Field(..., description="Action to perform ('isolate' or 'unisolate')")
    ip: str = Field(..., description="IPv4 address of the device")
    mac: str = Field(..., description="MAC address of the device")
    reason: str = Field(default="No reason provided")

def execute_fritzbox_isolation(action: str, mac_address: str, ip_address: str, reason: str):
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

@router.post("/isolate", status_code=202)
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

@router.get("/hosts", response_model=List[Dict[str, Any]])
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

@router.get("/api/ipc/router_isolation_status")
def router_isolation_status(ip: str, token: str = Depends(verify_token)):
    """Queries Fritz!Box directly for whether this IP's WAN access is CURRENTLY
    disallowed (real router state), for ips.py's reconciliation worker -- so a
    device unblocked outside this IDS's own flow (e.g. an operator toggling it
    directly in the Fritz!Box admin UI) doesn't leave `_router_isolated_devices`
    (and therefore Grafana's containment panel) stuck reporting "still isolated"
    forever. Mirrors execute_fritzbox_isolation()'s own connection/action pattern,
    just a Get instead of a Set on the same X_AVM-DE_HostFilter:1 TR-064 service."""
    fritz_ip = CONFIG.get("fritz_ip", "192.168.1.1")
    fritz_user = CONFIG.get("fritz_user", "admin")
    fritz_pass = CONFIG.get("fritz_password", "")
    if not fritz_pass:
        raise HTTPException(status_code=500, detail="FritzBox credentials not configured.")

    timeout_seconds = float(CONFIG.get("router_webhook_timeout_seconds", 5.0))
    if timeout_seconds <= 0:
        timeout_seconds = 5.0

    try:
        fc = FritzConnection(address=fritz_ip, user=fritz_user, password=fritz_pass, timeout=timeout_seconds)
        result = fc.call_action("X_AVM-DE_HostFilter:1", "GetWANAccessByIP", NewIPv4Address=ip)
        is_disallowed = bool(result.get("NewDisallow", 0))
        return {"ip": ip, "isolated": is_disallowed}
    except FritzActionError as e:
        LOGGER.error("❌ [API ERROR] Fritz!Box refused TR-064 status query for %s: %s", ip, e)
        raise HTTPException(status_code=502, detail=f"FritzBox refused status query: {e}")
    except FritzConnectionException as e:
        LOGGER.error("❌ [NETWORK ERROR] Could not reach Fritz!Box at %s: %s", fritz_ip, e)
        raise HTTPException(status_code=503, detail="FritzBox connection failed.")

class IPCReleaseRequest(BaseModel):
    target: str = Field(..., description="Target IP, MAC, hostname, or 'all'")

@router.post("/api/ipc/release")
def ipc_release(payload: IPCReleaseRequest, token: str = Depends(verify_token)):
    return _ipc_release_logic(payload.target)

@router.get("/api/ipc/release_get")
def ipc_release_get(target: str, token: str = Depends(verify_token)):
    return _ipc_release_logic(target)

def _ipc_release_logic(target: str):
    LOGGER.info("Received IPC release request for target: %s", target)
    try:
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()
        ips = IPSMitigator(config=CONFIG, state_manager=sm)
        
        if target.lower() in ("all", "--all"):
            count = ips.release_all_devices()
            sm.flush_to_disk()
            Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
            return {"status": "success", "released_count": count}
        else:
            released = ips.release_device(target)
            sm.flush_to_disk()
            Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
            return {"status": "success", "released": released}
    except Exception as e:
        LOGGER.error("IPC release failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

class IPCTargetRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP")

@router.post("/api/ipc/block")
def ipc_block(payload: IPCTargetRequest, token: str = Depends(verify_token)):
    return _ipc_block_logic(payload.target)

@router.get("/api/ipc/block_get")
def ipc_block_get(target: str, token: str = Depends(verify_token)):
    return _ipc_block_logic(target)

def _ipc_block_logic(target: str):
    LOGGER.info("Received IPC block request for IP: %s", target)
    try:
        state_path = CONFIG.get("state_path", "state/ids_state.json")
        sm = StateManager(state_path=state_path)
        sm.load_from_disk()
        
        ips = IPSMitigator(config=CONFIG, state_manager=sm)
        
        dev_id = target
        for id_str in sm.get_all_device_ids():
            with sm.lock_device(id_str) as st:
                if st.client_ip == target or st.mac_address == target:
                    dev_id = id_str
                    break

        if not sm.has_device(dev_id):
            sm.get_or_create(dev_id, target, "unknown")

        with sm.lock_device(dev_id) as state:
            state.has_validated_threat = True
            state.confirmed_threat_count = getattr(state, "confirmed_threat_count", 0) + 1
        
            ips.mitigate(
                st=state,
                target_domain="-",
                risk_score=10.0,
                lateral_threat=False,
                is_safe=False,
                reason="Operator explicitly approved hardware isolation.",
                decision_state="CRITICAL"
            )
        
        sm.flush_to_disk()
        Path(state_path).parent.joinpath(".ipc_sync_signal").touch()
        return {"status": "success"}
    except Exception as e:
        LOGGER.error("IPC block failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
