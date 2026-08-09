import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path('src').resolve()))

from core.state_guard import StateManager
from mitigation.ips import IPSMitigator
from core.decision_engine import DecisionEngine
from intelligence.hypotheses.evidence import Evidence
from intelligence.reputation.classifier import ReputationClassifier

root = Path('state_verify_out')
root.mkdir(exist_ok=True)
state_path = root / 'ids_state.json'
if state_path.exists():
    state_path.unlink()

cfg = {
    'state_path': str(state_path),
    'max_device_states': 100,
    'ips_pihole_enabled': True,
    'ips_router_enabled': False,
    'ips_tarpit_enabled': True,
    'simulation_mode': True,
    'pihole_api_url': 'http://example',
    'pihole_api_timeout_seconds': 1.0,
    'router_webhook_timeout_seconds': 1.0,
    'alert_threshold': 6.0,
    'safe_domains': [],
}

manager = StateManager(state_path=str(state_path), max_devices=100)
ips = IPSMitigator(config=cfg, state_manager=manager)

ips._ensure_tarpit_target('192.168.1.99', '00:11:22:33:44:55', 'mobile-device', 'dev-99')
ips._ensure_tarpit_target('192.168.1.99', 'aa:bb:cc:dd:ee:ff', 'mobile-device', 'dev-99')
assert ips._tarpit_active_targets['192.168.1.99']['mac'] == 'aa:bb:cc:dd:ee:ff'

assert ips._finalize_block('evil.example', 'test-host', '192.168.1.50', 'dev-50')
state = manager.get_ips_state()
assert state['blocked_domains']['evil.example']['status'] == 'active'
assert state['blocked_domains']['evil.example']['persisted'] is True

engine = DecisionEngine()
rep = ReputationClassifier().classify('example.com', ti_score=0.0, abuse_score=0.0, vt_score=0.0)
ev_store = [
    Evidence(type='dns_rate', source='pihole', timestamp=1.0, device='dev', value=70.0, confidence=0.6, independence_group='dns_behavior', provenance='detector:dns'),
    Evidence(type='dns_entropy', source='pihole', timestamp=1.0, device='dev', value=4.2, confidence=0.6, independence_group='dns_behavior', provenance='detector:dns')
]
decision = engine.evaluate(ev_store, rep)
assert decision['evidence_verification_required'] is True
assert decision['hypothesis_weight'] >= 0.5

Path('verify_mitigation.out').write_text('OK\n', encoding='utf-8')
print('verify_mitigation: OK')
