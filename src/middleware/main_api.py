import time
from fastapi import FastAPI
from middleware.routers import fritzbox_api, pihole_api
from middleware.auth import CONFIG

app = FastAPI(title="Fritz!Box Mitigation API", version="1.0.6")

# Mount Routers
app.include_router(fritzbox_api.router)
app.include_router(pihole_api.router)

@app.get("/health")
async def health_check():
    return {"status": "online", "time": time.time(), "fritz_ip_target": CONFIG.get("fritz_ip")}
