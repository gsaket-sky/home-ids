"""
test_identity_reconcile_pass.py - device-identity fragmentation fix, continuation
session: covers EnginePipeline._identity_reconcile_pass() end to end (not just
find_fragmented_groups()/pick_canonical() in isolation) -- the in-process
background worker that periodically reconciles fragmented device_ids against
the LIVE StateManager, added specifically because an external/subprocess-based
scheduled job would be silently clobbered by soc.service's own next
flush_to_disk() (see this method's own docstring in core/pipeline.py for the
full reasoning, verified this session via direct reads of
scripts/scheduler.py's subprocess.Popen and pipeline.py's .ipc_sync_signal
handling).

Uses a lightweight stand-in object (not a full EnginePipeline construction,
which pulls in Zeek/GeoIP/ThreatIntel/etc.) with real StateManager and real
DeviceIdentityManager instances -- both of which the merge/cleanup path
actually needs to be real to prove anything -- plus simple recording fakes for
ips_mitigator/evidence_store/metrics_exporter/alert_manager.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_identity_reconcile_pass.py`
"""
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

FAILURES = []


def check(label: str, condition: bool) -> None:
    status = "[PASS]" if condition else "[FAIL]"
    print(f"{status} {label}")
    if not condition:
        FAILURES.append(label)


from core.state_guard import StateManager  # noqa: E402
from core.identity import DeviceIdentityManager  # noqa: E402
from core.pipeline import EnginePipeline  # noqa: E402


class _FakeEvidenceStore:
    def __init__(self):
        self.cleared = []

    def clear_device(self, dev_id):
        self.cleared.append(dev_id)


class _FakeMetricsExporter:
    def __init__(self):
        self.removed = []

    def remove_device_metric_labels(self, dev_id, hostname, device_type):
        self.removed.append((dev_id, hostname, device_type))


class _FakeIpsMitigator:
    def __init__(self):
        self.unisolated = []

    def unisolate_all(self, mac_addr, ip_addr):
        self.unisolated.append((mac_addr, ip_addr))


class _FakeAlertManager:
    def __init__(self):
        self.sent = []

    def send(self, msg, **kw):
        self.sent.append(msg)


class _FakeConfig(dict):
    def get(self, k, default=None):
        return dict.get(self, k, default)


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        config = _FakeConfig({"telegram_enabled": True})
        sm = StateManager(state_path=str(Path(d) / "ids_state.json"), max_devices=100)
        identity_manager = DeviceIdentityManager(sm, config)

        # Fragmented pair sharing a known IP -- the real live pattern this session
        # found (MAC-randomized device, IP stayed constant across the rotation).
        a = sm.get_or_create(device_id="devA", client_ip="10.0.0.2", hostname="unknown")
        a.known_ips.add("10.0.0.2")
        a.mac_address = "ee:df:70:c2:5b:15"
        b = sm.get_or_create(device_id="devB", client_ip="10.0.0.99", hostname="unknown")
        b.known_ips.add("10.0.0.2")
        b.mac_address = "0a:df:70:c2:5b:15"

        # Unrelated device -- must never be touched.
        sm.get_or_create(device_id="devC", client_ip="10.0.0.50", hostname="printer_office")

        fake_self = SimpleNamespace(
            state_manager=sm,
            ml_registry=None,
            fp_engine=None,
            identity_manager=identity_manager,
            ips_mitigator=_FakeIpsMitigator(),
            evidence_store=_FakeEvidenceStore(),
            metrics_exporter=_FakeMetricsExporter(),
            config=config,
            alert_manager=_FakeAlertManager(),
        )

        merged_count = EnginePipeline._identity_reconcile_pass(fake_self)

        check("exactly 1 merge happened", merged_count == 1)
        surviving = sm.get_all_device_ids()
        check("only ONE of devA/devB survives as a tracked device (not both)",
              len({"devA", "devB"} & set(surviving)) == 1)
        check("devC (unrelated) is still tracked, untouched", "devC" in surviving)
        check("evidence_store.clear_device() was called exactly once (for the orphan)",
              len(fake_self.evidence_store.cleared) == 1)
        check("metrics_exporter.remove_device_metric_labels() was called exactly once",
              len(fake_self.metrics_exporter.removed) == 1)
        check("a Telegram notification was sent (telegram_enabled=True)",
              len(fake_self.alert_manager.sent) == 1)
        check("the notification text mentions 1 merged device",
              "1 fragmented" in fake_self.alert_manager.sent[0])

        # Idempotency: immediately re-running must be a safe, silent no-op.
        merged_count_2 = EnginePipeline._identity_reconcile_pass(fake_self)
        check("re-running immediately after is a no-op (idempotent, nothing left to merge)",
              merged_count_2 == 0)
        check("no second Telegram notification on the no-op re-run",
              len(fake_self.alert_manager.sent) == 1)

        # REGRESSION GUARD: telegram_enabled=False must suppress the notification
        # even when a real merge happens.
        config["telegram_enabled"] = False
        e = sm.get_or_create(device_id="devE", client_ip="10.0.0.7", hostname="unknown")
        e.known_ips.add("10.0.0.7")
        f = sm.get_or_create(device_id="devF", client_ip="10.0.0.8", hostname="unknown")
        f.known_ips.add("10.0.0.7")
        merged_count_3 = EnginePipeline._identity_reconcile_pass(fake_self)
        check("REGRESSION GUARD: a real merge with telegram_enabled=False sends no notification",
              merged_count_3 == 1 and len(fake_self.alert_manager.sent) == 1)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All _identity_reconcile_pass() end-to-end checks PASSED.")


if __name__ == "__main__":
    main()
