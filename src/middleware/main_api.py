import time
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from middleware.routers import fritzbox_api, pihole_api, config_api, devices_api, hunt_api, graph_api
from middleware.auth import CONFIG

app = FastAPI(title="Fritz!Box Mitigation API", version="1.0.6")

# Mount Routers
app.include_router(fritzbox_api.router)
app.include_router(pihole_api.router)
app.include_router(config_api.router)
app.include_router(devices_api.router)
app.include_router(hunt_api.router)
app.include_router(graph_api.router)

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
