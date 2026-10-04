"""
W-01 regression: request handlers build IPSMitigator per call. A default instance starts two permanent workers
(plus tarpit threads when privileged) and never stops them, so 5 requests left 10 live threads behind.
start_workers=False must leave no thread behind.
"""
import sys
import threading
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from mitigation.ips import IPSMitigator  # noqa: E402


class _FakeStateManager:
    def get_ips_state(self):
        return {}


CONFIG = {"ips_tarpit_enabled": True, "ips_router_enabled": False, "pihole_api_url": "http://pihole"}


def test_state_only_instance_starts_no_threads():
    before = set(threading.enumerate())
    for _ in range(5):
        IPSMitigator(config=CONFIG, state_manager=_FakeStateManager(), start_workers=False)
    new = [t for t in threading.enumerate() if t not in before and t.is_alive()]
    assert new == []


def test_default_instance_still_starts_workers():
    before = set(threading.enumerate())
    IPSMitigator(config=CONFIG, state_manager=_FakeStateManager())
    new = [t.name for t in threading.enumerate() if t not in before and t.is_alive()]
    assert "ips_retry_worker" in new
    assert "ips_router_reconcile_worker" in new


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
