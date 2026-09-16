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


def test_reapply_device_type_overrides() -> None:
    """2026-09-16, user report: "in console the device type change do not get
    apply." Root cause (confirmed live on .94 before writing this fix): the
    console's device_type_overrides PATCH reaches this process's own CONFIG
    immediately (LiveConfig's own watcher), but a device's STORED device_type
    only gets recomputed by apply_device_type(), which only ever runs from
    inside process_dns_identities()/process_zeek_identities() -- i.e. only when
    that device generates fresh traffic. devices_api.py's console display reads
    the stored value directly, never recomputing from device_type_overrides
    itself, so an idle device's console-displayed type could stay stale
    indefinitely -- looking to the operator like the change simply "doesn't
    apply," not just that it's delayed.

    core/pipeline.py's own _reapply_device_type_overrides() is the fix -- tested
    here directly against a real StateManager + real DeviceIdentityManager
    (matching this file's own established "real objects, not full
    EnginePipeline" convention), without needing the full pipeline's IPC
    sentinel plumbing around it."""
    from core.pipeline import _reapply_device_type_overrides

    with tempfile.TemporaryDirectory() as d:
        config = _FakeConfig({})
        sm = StateManager(state_path=str(Path(d) / "ids_state.json"), max_devices=100)
        identity_manager = DeviceIdentityManager(sm, config)

        idle_dev = sm.get_or_create(device_id="idle_dev", client_ip="10.0.1.5", hostname="my-smart-tv")
        idle_dev.device_type = "laptop"  # stale -- as if inferred long ago, before this hostname was even known
        idle_dev.device_type_is_override = False

        unrelated_dev = sm.get_or_create(device_id="unrelated_dev", client_ip="10.0.1.6", hostname="printer_office")
        unrelated_dev.device_type = "printer"
        unrelated_dev.device_type_is_override = False

        # Simulates the console PATCH having just landed in CONFIG -- the exact
        # dict apply_device_type() reads (device_type_overrides is a
        # hostname-substring map, confirmed via config_api.py's own docstring).
        fresh_overrides = {"smart-tv": "smart_tv"}

        reapplied = _reapply_device_type_overrides(sm, identity_manager, fresh_overrides)
        check("_reapply_device_type_overrides: reports exactly 1 device actually changed",
              reapplied == 1)
        with sm.lock_device("idle_dev") as st:
            check("_reapply_device_type_overrides: the idle device's STORED "
                  "device_type is updated immediately, without it ever "
                  "generating fresh traffic",
                  st.device_type == "smart_tv")
            check("_reapply_device_type_overrides: device_type_is_override is "
                  "correctly set True by the underlying apply_device_type() call",
                  st.device_type_is_override is True)
        with sm.lock_device("unrelated_dev") as st:
            check("_reapply_device_type_overrides: an unrelated device (no "
                  "matching pattern) is left completely untouched",
                  st.device_type == "printer" and st.device_type_is_override is False)

        # Idempotency: re-running with the SAME overrides changes nothing further.
        reapplied_again = _reapply_device_type_overrides(sm, identity_manager, fresh_overrides)
        check("_reapply_device_type_overrides: re-running with the same "
              "overrides is a safe no-op (0 changed, not re-flagged as changed "
              "every cycle)", reapplied_again == 0)

        # No overrides configured at all -- must never touch anything or crash.
        reapplied_empty = _reapply_device_type_overrides(sm, identity_manager, {})
        check("_reapply_device_type_overrides: an empty overrides dict is a "
              "safe no-op, not a crash", reapplied_empty == 0)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All _reapply_device_type_overrides() checks PASSED.")


if __name__ == "__main__":
    main()
    test_reapply_device_type_overrides()
