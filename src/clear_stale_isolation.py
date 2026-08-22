"""
clear_stale_isolation.py - CLI utility to clear STALE router-isolation/tarpit bookkeeping
for a device that was already manually released directly on the Fritzbox (or wherever),
bypassing the IDS's own release path.

The IDS's ips_state.json (router_isolated_devices, tarpit_targets, blocked_domains) is
its OWN internal belief about what's currently contained -- populated only when the IDS
itself performs a block/release action. It does not poll or reconcile against the
router/Pi-hole's actual live state, so a manual out-of-band change (releasing a device
directly in the Fritzbox admin UI, for example) leaves the IDS still believing the
device is isolated.

Unlike release_device.py (mitigation/ips.py's release_device()), this tool does NOT:
  - call the Fritzbox "unisolate" API (the device is already released there manually)
  - touch blocked_domains at all -- release_device() unconditionally releases every
    Pi-hole domain block tied to the device too, which is wrong here if the device is
    still suspected compromised (its domain blocks may be the only thing left standing
    between it and its C2 infrastructure). Use release_wrongly_blocked_domains.py or
    the normal Telegram/IPC release flow separately if you also want those released,
    once you're confident the device is actually clean.

Usage:
  python3 src/clear_stale_isolation.py <IP_OR_MAC_OR_HOSTNAME_OR_DEV_ID>
"""
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG
from core.state_guard import StateManager


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 src/clear_stale_isolation.py <IP_OR_MAC_OR_HOSTNAME_OR_DEV_ID>")
        sys.exit(1)

    identifier = sys.argv[1].strip()

    state_path = CONFIG.get("state_path", "state/ids_state.json")
    sm = StateManager(state_path=state_path)
    sm.load_from_disk()

    ips_state = sm.get_ips_state()
    tarpit = dict(ips_state.get("tarpit_targets", {}))
    router = dict(ips_state.get("router_isolated_devices", {}))

    cleared = []

    for ip, meta in list(tarpit.items()):
        if identifier in (ip, meta.get("mac"), meta.get("hostname"), meta.get("dev_id")):
            del tarpit[ip]
            cleared.append(f"tarpit_targets[{ip}] ({meta.get('hostname', 'unknown')})")

    for mac, meta in list(router.items()):
        if identifier in (mac, meta.get("ip"), meta.get("hostname"), meta.get("dev_id")):
            del router[mac]
            cleared.append(f"router_isolated_devices[{mac}] ({meta.get('hostname', 'unknown')})")

    if not cleared:
        print(f"No stale isolation entries found matching '{identifier}'. Nothing to clear.")
        return

    sm.update_ips_state_atomic({"tarpit_targets": tarpit, "router_isolated_devices": router})
    sm.flush_to_disk()

    print(f"Cleared {len(cleared)} stale isolation record(s):")
    for entry in cleared:
        print(f"  {entry}")
    print("\nblocked_domains was NOT touched -- any Pi-hole domain blocks for this device "
          "are still in place. Use release_wrongly_blocked_domains.py or the normal "
          "release flow separately if you also want those released.")
    print("Restart the service (or wait for the next .ipc_sync_signal-triggered reload) "
          "to pick up the change.")


if __name__ == "__main__":
    main()
