import os
import time
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from middleware.routers import (
    fritzbox_api, pihole_api, config_api, devices_api, hunt_api, graph_api,
    mitigation_api, suricata_api, health_api, overview_api, autonomy_api,
)
from middleware.auth import CONFIG
from core.heartbeat import write_component_heartbeat

app = FastAPI(title="Fritz!Box Mitigation API", version="1.0.6")

# Mount Routers
app.include_router(fritzbox_api.router)
app.include_router(pihole_api.router)
app.include_router(config_api.router)
app.include_router(devices_api.router)
app.include_router(hunt_api.router)
app.include_router(graph_api.router)
app.include_router(mitigation_api.router)
app.include_router(suricata_api.router)
app.include_router(health_api.router)
app.include_router(overview_api.router)
app.include_router(autonomy_api.router)


@app.on_event("startup")
async def _start_heartbeat_task():
    """Self-reports this subprocess's own liveness to the health manager, which
    runs in the SEPARATE main pipeline process and has no other way to see this
    subprocess is alive/responsive beyond hitting /health over HTTP. See
    core/heartbeat.py's module docstring for why this is a file, not a shared
    in-memory object -- different process, different memory space."""
    import asyncio

    async def _beat_loop():
        state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
        while True:
            try:
                write_component_heartbeat(state_dir, "api_subprocess", extra={"pid": os.getpid()})
            except Exception:
                pass
            await asyncio.sleep(10)

    asyncio.create_task(_beat_loop())

# The console UI is one static file at the repo root's web/ directory (src/middleware ->
# src -> repo root, 3 levels up). Served unauthenticated -- it's static markup with no
# secrets embedded; every API call the page itself makes is still token-gated by
# middleware.auth.verify_token like everything else in this app.
WEB_DIR = Path(__file__).resolve().parent.parent.parent / "web"

@app.get("/console")
async def serve_console():
    return FileResponse(WEB_DIR / "console.html")

@app.get("/health")
async def health_check():
    return {"status": "online", "time": time.time(), "fritz_ip_target": CONFIG.get("fritz_ip")}
