"""
mitigation_api.py -- console-facing block/unblock endpoints, wired to the SAME
IPSMitigator machinery the Telegram bot and Grafana panel buttons already use
(fritzbox_api.py's `_ipc_*_logic`, pihole_api.py's IPC endpoints) -- this is the first
time any of it is reachable from the console UI itself.

GET /api/mitigation/state is a pure read: it inspects StateManager.get_ips_state()
directly rather than instantiating IPSMitigator, because that constructor spins up four
background threads (retry worker, router-reconcile worker, ARP/NDP tarpit loops on
raw sockets) as a side effect -- fine for the rare manual-action endpoints below (they
already accept this cost, matching the existing `_ipc_*_logic` precedent), wrong for
something hit on every console page load.

The three action endpoints (isolate_router / tarpit / release) and the two domain
endpoints DO instantiate IPSMitigator per call, same as every existing IPC endpoint --
not fixed here; see IPSMitigator.__init__'s own docstring-equivalent comments for why
that's an accepted, pre-existing cost for infrequent manual actions, not a new one.
"""
from typing import Any, Dict, Optional
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from middleware.auth import verify_token, CONFIG, LOGGER
from core.state_guard import StateManager
from mitigation.ips import IPSMitigator

router = APIRouter()


class ReasonPayload(BaseModel):
    reason: Optional[str] = None


class DomainBlockPayload(BaseModel):
    domain: str = Field(..., description="Domain to block")
    device_id: Optional[str] = Field(None, description="Device this block is attributed to, if any")
    reason: Optional[str] = None


class DomainUnblockPayload(BaseModel):
    domain: str = Field(..., description="Domain to unblock")


def _load_state_manager() -> StateManager:
    sm = StateManager(state_path=CONFIG.get("state_path", "state/ids_state.json"))
    sm.load_from_disk()
    return sm


def _resolve_identity(sm: StateManager, device_id: str) -> Dict[str, Any]:
    device_id = sm.resolve_merge_redirect(device_id)   # an id merged away since names the device it is part of now
    if not sm.has_device(device_id):
        raise HTTPException(status_code=404, detail=f"No such device '{device_id}'.")
    with sm.lock_device(device_id) as state:
        return {
            "device_id": device_id,
            "ip": getattr(state, "client_ip", "unknown"),
            "mac": getattr(state, "mac_address", "unknown"),
            "hostname": getattr(state, "hostname", "unknown"),
            "known_ips": list(getattr(state, "known_ips", None) or []),   # newest last (BoundedSet LRU order)
        }


def _require_exact_identity(sm: StateManager, device_id: str) -> None:
    """An operator containment action acts only on a device identified exactly (StateManager.identity_check: its own
    MAC, no other device with that MAC or currently using its address) -- otherwise it could cut off another device
    that shares an address or a record with it (2026-10-12: on .94 a laptop's addresses were filed under a phone).
    Not exact means wait: the device is identified again the next time its traffic is observed."""
    check = sm.identity_check(device_id)
    if not check["exact"]:
        raise HTTPException(status_code=409, detail=f"This device is not identified exactly yet: {check['reason']} "
                                                    "It is identified again the next time its traffic is observed; "
                                                    "try again then.")


def _touch_sync_signal() -> None:
    Path(CONFIG.get("state_path", "state/ids_state.json")).parent.joinpath(".ipc_sync_signal").touch()


@router.get("/api/mitigation/state")
def get_mitigation_state(token: str = Depends(verify_token)):
    sm = _load_state_manager()
    ips_state = sm.get_ips_state()

    tarpit = ips_state.get("tarpit_targets", {})
    router_isolated = ips_state.get("router_isolated_devices", {})
    blocked_domains = ips_state.get("blocked_domains", {})

    contained_by_dev: Dict[str, Dict[str, Any]] = {}
    for _key, meta in tarpit.items():          # keyed by device ("dev:<id>"), containment T1
        dev_id = meta.get("dev_id", "unknown")
        entry = contained_by_dev.setdefault(dev_id, {
            "device_id": dev_id, "hostname": meta.get("hostname", "unknown"),
            "ip": meta.get("registered_ip", "unknown"), "mac": meta.get("mac", "unknown"),
            "tarpitted": False, "router_isolated": False,
        })
        entry["tarpitted"] = True
        entry["macs"] = meta.get("macs") or [meta.get("mac", "unknown")]
        entry["tarpit_status"] = meta.get("status", "")
    for mac, meta in router_isolated.items():
        dev_id = meta.get("dev_id", "unknown")
        entry = contained_by_dev.setdefault(dev_id, {
            "device_id": dev_id, "hostname": meta.get("hostname", "unknown"),
            "ip": meta.get("ip", "unknown"), "mac": mac,
            "tarpitted": False, "router_isolated": False,
        })
        entry["router_isolated"] = True
        entry["mac"] = mac

    domains = [
        {"domain": domain, "hostname": meta.get("hostname", "unknown"),
         "device_id": meta.get("device_id", "unknown"), "device_ip": meta.get("device_ip", "unknown"),
         "reason": meta.get("comment", ""), "blocked_at": meta.get("timestamp")}
        for domain, meta in blocked_domains.items()
    ]
    domains.sort(key=lambda d: d["blocked_at"] or 0, reverse=True)

    return {
        "contained_devices": list(contained_by_dev.values()),
        "blocked_domains": domains,
    }


@router.post("/api/devices/{device_id}/isolate_router")
def isolate_device_router(device_id: str, payload: ReasonPayload, token: str = Depends(verify_token)):
    sm = _load_state_manager()
    device_id = sm.resolve_merge_redirect(device_id)   # a link from before a merge names the old id
    identity = _resolve_identity(sm, device_id)
    _require_exact_identity(sm, device_id)
    ips = IPSMitigator(config=CONFIG, state_manager=sm, start_workers=False)
    success, reason = ips.operator_isolate_router(
        dev_id=device_id, ip=identity["ip"], mac=identity["mac"], hostname=identity["hostname"],
        reason=payload.reason or "Operator-requested Fritz!Box isolation (console)",
    )
    sm.flush_to_disk()
    _touch_sync_signal()
    if not success:
        raise HTTPException(status_code=502, detail=reason)
    return {"status": "success", "device_id": device_id, "detail": reason}


@router.post("/api/devices/{device_id}/tarpit")
def tarpit_device(device_id: str, payload: ReasonPayload, token: str = Depends(verify_token)):
    sm = _load_state_manager()
    device_id = sm.resolve_merge_redirect(device_id)   # a link from before a merge names the old id
    identity = _resolve_identity(sm, device_id)
    _require_exact_identity(sm, device_id)
    ips = IPSMitigator(config=CONFIG, state_manager=sm, start_workers=False)
    success, reason = ips.operator_tarpit(
        dev_id=device_id, ip=identity["ip"], mac=identity["mac"], hostname=identity["hostname"],
        reason=payload.reason or "Operator-requested Layer-2 tarpit (console)",
        ipv4_candidates=identity["known_ips"],   # the ARP half needs IPv4; client_ip can be an IPv6 address
    )
    sm.flush_to_disk()
    _touch_sync_signal()
    if not success:
        raise HTTPException(status_code=502, detail=reason)
    return {"status": "success", "device_id": device_id, "detail": reason}


@router.post("/api/devices/{device_id}/release")
def release_device_console(device_id: str, token: str = Depends(verify_token)):
    sm = _load_state_manager()
    device_id = sm.resolve_merge_redirect(device_id)   # a link from before a merge names the old id
    if not sm.has_device(device_id):
        raise HTTPException(status_code=404, detail=f"No such device '{device_id}'.")
    ips = IPSMitigator(config=CONFIG, state_manager=sm, start_workers=False)
    released = ips.release_device(device_id)
    sm.flush_to_disk()
    _touch_sync_signal()
    return {"status": "success", "device_id": device_id, "released": released}


@router.post("/api/domains/block")
def block_domain_console(payload: DomainBlockPayload, token: str = Depends(verify_token)):
    sm = _load_state_manager()
    hostname, device_ip, dev_id = "manual (console)", "unknown", "manual"
    if payload.device_id:
        identity = _resolve_identity(sm, payload.device_id)
        hostname, device_ip, dev_id = identity["hostname"], identity["ip"], identity["device_id"]

    ips = IPSMitigator(config=CONFIG, state_manager=sm, start_workers=False)
    success = ips._block_domain(
        domain=payload.domain, hostname=hostname, device_ip=device_ip, dev_id=dev_id,
        reason=payload.reason or "Operator explicitly blocked via console",
    )
    sm.flush_to_disk()
    _touch_sync_signal()
    if not success:
        raise HTTPException(status_code=502, detail="Pi-hole block failed -- see server logs.")
    return {"status": "success", "blocked_domain": payload.domain}


@router.post("/api/domains/unblock")
def unblock_domain_console(payload: DomainUnblockPayload, token: str = Depends(verify_token)):
    sm = _load_state_manager()
    ips = IPSMitigator(config=CONFIG, state_manager=sm, start_workers=False)
    success = ips.unblock_domain(payload.domain, reason="manual (console)")
    sm.flush_to_disk()
    _touch_sync_signal()
    if not success:
        raise HTTPException(status_code=502, detail="Pi-hole unblock failed -- see server logs.")
    return {"status": "success", "unblocked_domain": payload.domain}
