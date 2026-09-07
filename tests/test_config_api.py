"""
Tests for src/middleware/routers/config_api.py and the LiveConfig.revert_override()
addition it depends on.

Calls the router's handler functions directly (no TestClient/HTTP layer -- FastAPI's
Depends() markers are just default parameter values, so passing token="test" explicitly
bypasses them cleanly). This repo has no TestClient/pytest-fixture convention for the
middleware to plug into (only tests/test_train_fp_classifier_model_path.py is a real
pytest file elsewhere) -- this follows that one file's direct-import, tmp_path/monkeypatch
style rather than introducing a new dependency (httpx) for a first TestClient-based test.

CONFIG (src/config.py) is a process-wide singleton constructed against the REAL
config.yaml the moment config.py is first imported -- these tests must never read or
write the real state/config_overrides.json, and must restore CONFIG._config afterward
so no test leaks a mutated value into another. See the isolated_overrides fixture.
"""
import json
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG  # noqa: E402
from middleware.routers import config_api  # noqa: E402


@pytest.fixture
def isolated_overrides(tmp_path, monkeypatch):
    overrides_path = tmp_path / "config_overrides.json"
    audit_path = tmp_path / "config_changes.jsonl"
    monkeypatch.setattr(config_api, "_STATE_DIR", tmp_path)
    monkeypatch.setattr(config_api, "_OVERRIDES_PATH", overrides_path)
    monkeypatch.setattr(config_api, "_AUDIT_LOG_PATH", audit_path)
    monkeypatch.setattr(CONFIG, "_overrides_path", overrides_path)
    snapshot = dict(CONFIG._config)
    yield overrides_path, audit_path
    CONFIG._config.clear()
    CONFIG._config.update(snapshot)


def test_patch_applies_live_and_writes_override(isolated_overrides):
    overrides_path, audit_path = isolated_overrides
    original = CONFIG.get("poll_interval")

    result = config_api.patch_config(
        "poll_interval", config_api.ConfigValuePayload(value=7, reason="test"), token="test"
    )

    assert result["value"] == 7
    assert CONFIG.get("poll_interval") == 7
    data = json.loads(overrides_path.read_text(encoding="utf-8"))
    assert data["poll_interval"]["value"] == 7
    assert data["poll_interval"]["baseline"] == original
    assert audit_path.exists()
    audit_lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert audit_lines[-1]["action"] == "set"
    assert audit_lines[-1]["key"] == "poll_interval"


def test_patch_rejects_static_key(isolated_overrides):
    original = CONFIG.get("metrics_port")
    with pytest.raises(HTTPException) as exc:
        config_api.patch_config("metrics_port", config_api.ConfigValuePayload(value=9999), token="test")
    assert exc.value.status_code == 400
    assert CONFIG.get("metrics_port") == original  # untouched


def test_patch_rejects_runtime_restart_key(isolated_overrides):
    """lateral_movement_ports isn't in _STATIC_KEYS but IS read once at
    ZeekFeatureExtractor construction -- config_schema.RUNTIME_RESTART_KEYS should still
    block it."""
    with pytest.raises(HTTPException) as exc:
        config_api.patch_config("lateral_movement_ports", config_api.ConfigValuePayload(value=[1, 2]), token="test")
    assert exc.value.status_code == 400


def test_patch_rejects_dotted_key(isolated_overrides):
    with pytest.raises(HTTPException) as exc:
        config_api.patch_config(
            "scheduler.ollama_soc.enabled", config_api.ConfigValuePayload(value=False), token="test"
        )
    assert exc.value.status_code == 400


def test_patch_unknown_key_404(isolated_overrides):
    with pytest.raises(HTTPException) as exc:
        config_api.patch_config("not_a_real_key", config_api.ConfigValuePayload(value=1), token="test")
    assert exc.value.status_code == 404


def test_delete_reverts_to_baseline(isolated_overrides):
    original = CONFIG.get("poll_interval")
    config_api.patch_config("poll_interval", config_api.ConfigValuePayload(value=9), token="test")
    assert CONFIG.get("poll_interval") == 9

    result = config_api.delete_config("poll_interval", token="test")

    assert result["had_override"] is True
    assert CONFIG.get("poll_interval") == original


def test_delete_without_override_is_a_noop(isolated_overrides):
    result = config_api.delete_config("poll_interval", token="test")
    assert result["had_override"] is False


def test_device_type_override_merge_and_remove(isolated_overrides):
    config_api.patch_device_type_override("TESTHOST-A", config_api.DeviceTypePayload(type="nas"), token="test")
    current = CONFIG.get("device_type_overrides", {})
    assert current.get("TESTHOST-A") == "nas"

    config_api.patch_device_type_override("TESTHOST-B", config_api.DeviceTypePayload(type="iot"), token="test")
    current = CONFIG.get("device_type_overrides", {})
    assert current.get("TESTHOST-A") == "nas"  # first entry preserved, not clobbered
    assert current.get("TESTHOST-B") == "iot"

    config_api.delete_device_type_override("TESTHOST-A", token="test")
    current = CONFIG.get("device_type_overrides", {})
    assert "TESTHOST-A" not in current
    assert current.get("TESTHOST-B") == "iot"


def test_device_type_override_rejects_unknown_type(isolated_overrides):
    with pytest.raises(HTTPException) as exc:
        config_api.patch_device_type_override(
            "TESTHOST-C", config_api.DeviceTypePayload(type="not_a_real_type"), token="test"
        )
    assert exc.value.status_code == 400


def test_get_config_excludes_secrets(isolated_overrides):
    response = config_api.get_config(token="test")
    keys = {row["key"] for row in response["rows"]}
    for secret_key in ("telegram_token", "fritz_password", "fritz_api_token", "otx_api_key",
                       "abuseipdb_api_key", "virustotal_api_key", "pihole_api_password",
                       "telegram_chat_id"):
        assert secret_key not in keys


def test_get_config_marks_restart_required(isolated_overrides):
    response = config_api.get_config(token="test")
    by_key = {row["key"]: row for row in response["rows"]}
    assert by_key["metrics_port"]["restart_required"] is True
    assert by_key["metrics_port"]["editable"] is False
    assert by_key["lateral_movement_ports"]["restart_required"] is True
    assert by_key["poll_interval"]["restart_required"] is False
    assert by_key["poll_interval"]["editable"] is True
