"""
Containment label + audit and interactive domain blocks (MASTER_TODO 0c Step 2, 2026-10-12):

- every block / router isolation / tarpit an alert causes records that alert (incident, signature, the evidence that
  fired); mitigate() returns the containment actions it created, which the engine links to the alert's graph event;
- the alert says "DOMAIN BLOCKED" only when its own incident caused the block -- a domain on the list since an earlier,
  unrelated alert reads "already on blocklist";
- in interactive mode the Pi-hole block waits for a person (router isolation and the tarpit already did): an approval
  ledger entry, a Telegram button, an IPC route that blocks once and only before the approval expires.
"""
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state_guard import StateManager  # noqa: E402
from mitigation.ips import IPSMitigator  # noqa: E402
from mitigation.containment_gate import MONITOR_ONLY, ContainmentAuthorization  # noqa: E402

MAC = "aa:bb:cc:00:00:01"
REF = {"incident_id": "d1|bad.example|DGA_BOTNET_C2", "signature": "DGA_BOTNET_C2", "target_source": "dns_dga_burst",
       "evidence_types": ["dns_dga_burst"]}


class _Graph:
    def __init__(self):
        self.n, self.rows = 0, {}

    def insert_containment_action(self, device_id, action_type, status, target=None, reason=None):
        self.n += 1
        aid = f"a{self.n}"
        self.rows[aid] = (device_id, action_type, target)
        return aid

    def update_containment_status(self, action_id, status):
        return True


class _Resp:
    status_code, text = 201, "{}"

    def json(self):
        return {}


@pytest.fixture
def env(tmp_path, monkeypatch):
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    sm.get_or_create("d1", "10.0.0.5", "host-d1")
    with sm.lock_device("d1") as st:
        st.mac_address = MAC
    sm.bind_mac(MAC, "d1")
    graph = _Graph()
    cfg = {"ips_enabled": True, "ips_pihole_enabled": True, "ips_router_enabled": True, "ips_tarpit_enabled": True,
           "simulation_mode": True, "onboarding_mode_days": 0, "pihole_api_url": "http://pihole.invalid",
           "state_path": str(tmp_path / "ids_state.json")}
    m = IPSMitigator(config=cfg, state_manager=sm, graph_store=graph, start_workers=False)
    m.tarpit_armed = True
    m.session.post = lambda *a, **k: _Resp()
    m.session.get = lambda *a, **k: _Resp()
    m._isolate_device_router = lambda **kw: True
    monkeypatch.setattr("mitigation.pihole_auth.auth_headers", lambda *a, **k: {})
    st = SimpleNamespace(client_ip="10.0.0.5", hostname="host-d1", device_id="d1", mac_address=MAC,
                         device_type="unknown", known_ips=["10.0.0.5"])
    return SimpleNamespace(sm=sm, m=m, graph=graph, st=st)


def test_every_action_records_its_alert_and_is_returned(env):
    res = env.m.mitigate(env.st, target_domain="bad.example", risk_score=9.6, authorization=ContainmentAuthorization("corroborated"), is_safe=False, alert_ref=REF)
    ips = env.sm.get_ips_state()
    assert ips["blocked_domains"]["bad.example"]["alert"] == REF
    assert env.m._router_isolated_devices[MAC]["alert"] == REF
    assert env.m._tarpit_active_targets["dev:d1"]["alert"] == REF
    assert res["domain_blocked"] == "bad.example"
    kinds = sorted(env.graph.rows[a][1] for a in res["actions"])
    assert kinds == ["dns_block", "router_isolate", "tarpit"]                 # each once, all linkable


def test_domain_blocked_label_only_for_the_incident_that_caused_it(env):
    env.m.mitigate(env.st, target_domain="bad.example", risk_score=5.0, authorization=ContainmentAuthorization("corroborated"), is_safe=False, alert_ref=REF)
    same = env.m.get_containment_status("10.0.0.5", "unknown", domain="bad.example", dev_id="dx",
                                        incident_id=REF["incident_id"])
    other = env.m.get_containment_status("10.0.0.5", "unknown", domain="bad.example", dev_id="dx",
                                         incident_id="d2|bad.example|DNS_TUNNELING")
    assert "DOMAIN BLOCKED" in same
    assert "ALREADY ON BLOCKLIST" in other and "DOMAIN BLOCKED" not in other
    from core.pipeline import containment_code
    assert containment_code(other) == "DOMAIN_ALREADY_BLOCKED" and containment_code(same) == "DOMAIN_BLOCKED"


def test_an_already_listed_domain_is_not_this_alerts_block(env):
    env.m.mitigate(env.st, target_domain="bad.example", risk_score=5.0, authorization=ContainmentAuthorization("corroborated"), is_safe=False, alert_ref=REF)
    later = dict(REF, incident_id="d1|bad.example|C2_BEACONING")
    res = env.m.mitigate(env.st, target_domain="bad.example", risk_score=5.0, authorization=ContainmentAuthorization("corroborated"), is_safe=False, alert_ref=later)
    assert res["domain_blocked"] is None and res["actions"] == []
    assert env.sm.get_ips_state()["blocked_domains"]["bad.example"]["alert"] == REF       # the cause is kept


# ------------------------------------------------------------------------------------------------ interactive mode

def test_interactive_mode_queues_the_domain_block_instead_of_blocking(env):
    env.m.config["interactive_blocking_enabled"] = True
    res = env.m.mitigate(env.st, target_domain="bad.example", risk_score=5.0, authorization=ContainmentAuthorization("corroborated"), is_safe=False, alert_ref=REF)
    assert res["pending_domain_block"] == "bad.example" and res["domain_blocked"] is None
    assert "bad.example" not in env.sm.get_ips_state()["blocked_domains"]


def _approval(sm, aid="p1", ttl=3600.0):
    sm.record_action(action_id=aid, action_type="pending_domain_block", target="bad.example", device_id="d1",
                     hostname="host-d1", ttl_seconds=ttl,
                     extra={"domain": "bad.example", "device_ip": "10.0.0.5", "reason": "DGA_BOTNET_C2",
                            "incident_id": REF["incident_id"], "signature": "DGA_BOTNET_C2",
                            "target_source": "dns_dga_burst"})
    sm.flush_to_disk()


def test_the_approval_blocks_once_with_its_alert(env, monkeypatch, tmp_path):
    from fastapi import HTTPException
    from middleware.routers import pihole_api
    _approval(env.sm)
    monkeypatch.setattr(pihole_api, "CONFIG", dict(env.m.config))
    calls = []
    monkeypatch.setattr(IPSMitigator, "_block_domain", lambda self, **kw: calls.append(kw) or True)
    out = pihole_api.ipc_approve_domain_block(pihole_api.IPCTargetRequest(target="p1"), token="t")
    assert out == {"status": "success", "domain": "bad.example", "blocked": True}
    assert calls[0]["domain"] == "bad.example" and calls[0]["alert_ref"]["incident_id"] == REF["incident_id"]
    assert calls[0]["alert_ref"]["approved"] is True
    with pytest.raises(HTTPException) as exc:                                   # a second tap does nothing
        pihole_api.ipc_approve_domain_block(pihole_api.IPCTargetRequest(target="p1"), token="t")
    assert exc.value.status_code == 404 and len(calls) == 1


def test_an_expired_approval_is_refused(env, monkeypatch):
    from fastapi import HTTPException
    from middleware.routers import pihole_api
    _approval(env.sm, aid="p2", ttl=-1.0)
    monkeypatch.setattr(pihole_api, "CONFIG", dict(env.m.config))
    monkeypatch.setattr(IPSMitigator, "_block_domain", lambda self, **kw: pytest.fail("blocked after expiry"))
    with pytest.raises(HTTPException) as exc:
        pihole_api.ipc_approve_domain_block(pihole_api.IPCTargetRequest(target="p2"), token="t")
    assert exc.value.status_code == 404


def test_the_telegram_button_calls_the_approval_route(monkeypatch):
    from mitigation import alerts as alerts_mod
    am = alerts_mod.AlertManager.__new__(alerts_mod.AlertManager)
    posted = []

    class _S:
        def post(self, url, json=None, headers=None, timeout=None):
            posted.append((url, json))
            r = SimpleNamespace(status_code=200, json=lambda: {"domain": "bad.example", "blocked": True})
            return r
    am.session = _S()
    am._is_sender_allowed = lambda chat_id: True
    am._safe_exc = lambda e: str(e)
    am.token = "x"
    am._handle_telegram_callback("blockdomain:p1", "c1", {"message": {"chat": {"id": 1}}})
    assert any(u.endswith("/api/ipc/approve_domain_block") and j == {"target": "p1"} for u, j in posted)
    assert any("Blocked 'bad.example'" in str(j) for _u, j in posted)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
