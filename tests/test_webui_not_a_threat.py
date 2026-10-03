"""
"Not a threat" from the web UI's Alerts page: POST /api/ipc/incident/{incident_id}/not_a_threat (engine API) marks
the incident's newest alert as a false positive through the same CL-AFPE path as the Telegram button, refuses
hard-stop alerts, and records the operator action. Before this the web UI had no way to correct an alert, and only
alerts sent to Telegram could be corrected at all.

Run directly: `python tests/test_webui_not_a_threat.py`
"""
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from config import CONFIG  # noqa: E402
from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from core.state_guard import StateManager  # noqa: E402
import middleware.routers.pihole_api as api  # noqa: E402
from middleware.auth import verify_token  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="not_a_threat_"))
_orig_state_path = CONFIG._config.get("state_path")
CONFIG._config["state_path"] = str(tmp / "ids_state.json")
try:
    sm = StateManager(state_path=str(tmp / "ids_state.json"))
    sm.get_or_create("dev_tv", "192.168.1.40", "living-room-tv")
    sm.flush_to_disk()

    store = GraphStore(str(tmp / "v13_graph.db"))
    now = time.time()
    store.upsert_device("dev_tv", timestamp=now)

    def _alert(sig, domain, ts):
        return {"signature": sig, "device": {"id": "dev_tv", "hostname": "living-room-tv"},
                "network_context": {"queried_domain": domain, "destination_ip": "203.0.113.9"},
                "features": {}, "timestamp": ts, "incident_id": f"dev_tv|{sig}"}

    dec = store.insert_decision("dev_tv", now - 60, "SUSPICIOUS", "hypothesis", 0.4, 4.0)
    for ts, dom in ((now - 120, "old.tracker.example"), (now - 60, "ads.vendor-telemetry.example")):
        store.insert_alert_event(dec, "dev_tv", ts, "LOGGED_ONLY", incident_id="dev_tv|DNS_ATTRIBUTION_GAP",
                                 alert_payload=_alert("DNS_ATTRIBUTION_GAP", dom, ts))
    store.insert_alert_event(dec, "dev_tv", now - 30, "LOGGED_ONLY", incident_id="dev_tv|Internal Honeypot Accessed",
                             alert_payload=_alert("Internal Honeypot Accessed", "", now - 30))

    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[verify_token] = lambda: "test"
    client = TestClient(app)

    r = client.post("/api/ipc/incident/dev_tv|DNS_ATTRIBUTION_GAP/not_a_threat")
    body = r.json()
    check("the incident's NEWEST alert is corrected (its base domain becomes trusted)",
          r.status_code == 200 and body.get("status") == "success"
          and body.get("immunized") == "vendor-telemetry.example", str(body))
    check("the destination is now in the trust cache",
          "vendor-telemetry.example" in ClAfpeEngine(store).get_dynamic_trust_cache())
    check("the response names the incident", body.get("incident_id") == "dev_tv|DNS_ATTRIBUTION_GAP")
    n_actions = store._conn.execute("SELECT COUNT(*) FROM operator_actions").fetchone()[0]
    check("the operator action is recorded against the alert event", n_actions == 1, str(n_actions))

    r = client.post("/api/ipc/incident/dev_tv|Internal Honeypot Accessed/not_a_threat")
    check("a decoy-contact alert is refused, with the reason",
          r.status_code == 200 and r.json().get("status") == "refused" and r.json().get("reason"), str(r.json()))

    r = client.post("/api/ipc/incident/no_such_incident/not_a_threat")
    check("an unknown incident is a 404", r.status_code == 404)

    # Regression (2026-10-03): one shared sqlite connection failed every request that FastAPI ran on another worker
    # thread ("SQLite objects created in a thread can only be used in that same thread").
    codes = {client.post("/api/ipc/incident/dev_tv|DNS_ATTRIBUTION_GAP/not_a_threat").status_code for _ in range(20)}
    check("20 requests in a row all succeed, whichever worker thread runs them", codes == {200}, str(codes))
finally:
    if _orig_state_path is None:
        CONFIG._config.pop("state_path", None)
    else:
        CONFIG._config["state_path"] = _orig_state_path

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED")
    sys.exit(1)
print("All not-a-threat checks PASSED.")
