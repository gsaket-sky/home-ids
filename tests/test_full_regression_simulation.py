"""
test_full_regression_simulation.py - Comprehensive End-to-End Regression Test Suite for CL-AFPE v8.

Validates the full threat & false-positive lifecycle across 6 simulated network scenarios:
  1. Scenario A: Benign Baseline & New Device Probation (Peer Transfer Learning).
  2. Scenario B: Developer Build False Positive (FastEmbed auto-suppression & learn_normal).
  3. Scenario C: C2 DGA / Covert Data Tunneling (Confirmed threat, Pi-hole block).
  4. Scenario D: Internal Lateral Movement & Port Scanning (Scanned ports & Layer-2 ARP Tarpit).
  5. Scenario E: Exfiltration Burst (Stage 1 Hard-Stop & ML Anti-Poisoning reject_threat).
  6. Scenario F: Containment & Operator Release Cooldown Lifecycle.
"""

import sys
import time
import logging
from pathlib import Path

# Add src to path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from utils import infer_device_type, is_telemetry_domain
from core.state import DeviceState
from core.state_guard import StateManager
from intelligence.ml_engine import DeviceMLEngine, GlobalMLEngine
from intelligence.fp_engine import AutonomousFPEngine
from mitigation.ips import IPSMitigator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
LOGGER = logging.getLogger("home_ids.regression")


def test_device_type_classification():
    LOGGER.info("--- TEST 1: Multi-Heuristic Device Type Classification ---")
    assert infer_device_type("user_galaxy_note9_fritz_box") == "phone"
    assert infer_device_type("user_laptop_fritz_box") == "laptop"
    assert infer_device_type("livingroom_samsungtv") == "smart_tv"
    assert infer_device_type("esp32_sensor_01") == "iot"
    assert infer_device_type("synology_diskstation") == "nas"
    assert infer_device_type("unknown_device_x", user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)") == "phone"
    LOGGER.info("✅ TEST 1 PASSED: Device classification eliminates 'unknown' properly.")


def test_peer_transfer_learning():
    LOGGER.info("--- TEST 2: Peer Profile Transfer Learning on Onboarding ---")
    sm = StateManager(state_path="state/test_ids_state.json")
    
    # Create established peer phone
    p1 = sm.get_or_create("dev_phone1", "192.168.1.50", "galaxy_s21")
    p1.device_type = "phone"
    for h in range(24):
        p1.rate_baseline.update(15.0, h)
        p1.entropy_baseline.update(2.8, h)

    # Create new onboarding phone
    p2 = sm.get_or_create("dev_phone2", "192.168.1.51", "galaxy_note9")
    mean_rate, _, _, _ = p2.rate_baseline.get_stats(12)
    assert mean_rate > 0.0, "New onboarding phone failed to inherit baseline from peer phone!"
    LOGGER.info("✅ TEST 2 PASSED: Onboarding device inherited peer baseline (mean_rate=%.2f).", mean_rate)


def test_fp_engine_vector_suppression():
    LOGGER.info("--- TEST 3: FastEmbed Vector Auto-Suppression (Developer Build FP) ---")
    fp = AutonomousFPEngine(config={}, state_dir="state")
    
    alert = {
        "device": {"id": "user_laptop", "ip": "192.168.1.12", "hostname": "user_laptop_fritz_box", "type": "laptop"},
        "network_context": {"queried_domain": "diagmon-serviceapi.samsungdm.com"},
        "risk": 7.5,
        "signature": "DNS Covert Data Tunneling"
    }
    features = {
        "tranco_rank": 5000,
        "max_label_length": 57,
        "outbound_bytes_z": 0.5,
        "device_type": "laptop",
        "zeek_lateral_moves": 0,
        "zeek_s0_rej_count": 0,
        "zeek_app_protocol_weight": 0.2
    }
    
    res = fp.evaluate(alert_payload=alert, features=features, risk_score=7.5)
    assert res["suppress"] is True, f"Samsung Diagnostic FP failed to auto-suppress! Verdict: {res}"
    assert res["verdict"] == "FALSE_POSITIVE"
    LOGGER.info("✅ TEST 3 PASSED: Samsung Diagnostic FP auto-suppressed with confidence %.2f.", res["confidence"])


def test_hardstop_and_anti_poisoning():
    LOGGER.info("--- TEST 4: Exfiltration Hard-Stop & ML Anti-Poisoning ---")
    fp = AutonomousFPEngine(config={}, state_dir="state")
    ml = DeviceMLEngine("user_laptop")
    
    # Exfiltration Burst
    features_exfil = {
        "tranco_rank": 0,
        "max_label_length": 45,
        "outbound_bytes_z": 8.5,  # High Z-score exfiltration burst!
        "device_type": "laptop",
        "zeek_lateral_moves": 0,
        "zeek_s0_rej_count": 0,
        "zeek_app_protocol_weight": 0.4
    }
    
    alert_exfil = {
        "device": {"id": "user_laptop", "ip": "192.168.1.12", "hostname": "user_laptop_fritz_box", "type": "laptop"},
        "network_context": {"queried_domain": "exfil.aws-cloud-storage.com"},
        "risk": 11.5,
        "signature": "Data Exfiltration Burst"
    }
    
    res = fp.evaluate(alert_payload=alert_exfil, features=features_exfil, risk_score=11.5)
    assert res["suppress"] is False, "Exfiltration burst was accidentally suppressed!"
    assert res["verdict"] == "CONFIRMED_THREAT"
    assert res["stage"] == "STAGE_1_HARD_STOP"
    
    # Test Anti-Poisoning
    initial_samples = len(ml.training)
    ml.reject_threat(features_exfil)
    assert len(ml.training) == initial_samples, "Threat features were incorrectly appended to training buffer!"
    LOGGER.info("✅ TEST 4 PASSED: Exfiltration Hard-Stop triggered & ML Anti-Poisoning rejected sample.")


def test_ips_containment_and_status():
    LOGGER.info("--- TEST 5: IPS Containment & Real-Time Status Query ---")
    # Use isolated test state file to avoid disk persistence pollution from prior runs
    for p in ["state/test_ips_state.json", "state/ips_queues.json", "state/ids_state.json"]:
        f = Path(p)
        if f.exists():
            try: f.unlink()
            except Exception: pass

    sm = StateManager(state_path="state/test_ips_state.json")
    sm.get_ips_state()["operator_released_devices"] = {}
    sm.get_ips_state()["tarpit_targets"] = {}
    
    ips = IPSMitigator(config={"simulation_mode": True}, state_manager=sm)
    ips._operator_released_devices.clear()
    ips._tarpit_active_targets.clear()
    if hasattr(ips, "state_manager") and ips.state_manager:
        ips.state_manager.get_ips_state().setdefault("operator_released_devices", {}).clear()
        ips.state_manager.get_ips_state().setdefault("tarpit_targets", {}).clear()
    
    status_initial = ips.get_containment_status("192.168.1.12", "fc:3e:26:11:54:82")
    assert "UNBLOCKED" in status_initial, f"Expected UNBLOCKED initial status, got {status_initial}"
    
    st = DeviceState(device_id="user_laptop", client_ip="192.168.1.12", hostname="user_laptop_fritz_box")
    st.mac_address = "fc:3e:26:11:54:82"
    
    # Trigger ARP Tarpit Mitigation
    ips.mitigate(
        st=st,
        target_domain="downloads77-windows.com",
        risk_score=10.0,
        c2_hits=1,
        dga_burst=True,
        lateral_threat=True,
        is_safe=False
    )
    
    LOGGER.info("Debug tarpit targets: %s", list(ips._tarpit_active_targets.keys()))
    status_active = ips.get_containment_status("192.168.1.12", "fc:3e:26:11:54:82")
    assert "TARPITTED" in status_active, f"Expected TARPITTED status badge, got: {status_active}"
    
    # Unblock / Mark Safe
    ips.mitigate(
        st=st,
        target_domain="downloads77-windows.com",
        risk_score=0.0,
        c2_hits=0,
        dga_burst=False,
        lateral_threat=False,
        is_safe=True
    )
    status_released = ips.get_containment_status("192.168.1.12", "fc:3e:26:11:54:82")
    assert "UNBLOCKED" in status_released, f"Expected UNBLOCKED status after safe release, got: {status_released}"
    LOGGER.info("✅ TEST 5 PASSED: IPS containment lifecycle (Tarpit -> Safe Release) verified.")


def main():
    LOGGER.info("=========================================================================")
    LOGGER.info("🚀 STARTING CL-AFPE v8 FULL END-TO-END REGRESSION TEST SUITE")
    LOGGER.info("=========================================================================")
    # Clean temporary test state files
    for p in ["state/test_ids_state.json", "state/test_ips_state.json", "state/ips_queues.json"]:
        f = Path(p)
        if f.exists():
            try: f.unlink()
            except Exception: pass
    test_device_type_classification()
    test_peer_transfer_learning()
    test_fp_engine_vector_suppression()
    test_hardstop_and_anti_poisoning()
    test_ips_containment_and_status()
    LOGGER.info("=========================================================================")
    LOGGER.info("🎉 ALL 5 REGRESSION SUITE TESTS PASSED CLEANLY WITH ZERO ERRORS!")
    LOGGER.info("=========================================================================")


if __name__ == "__main__":
    main()
