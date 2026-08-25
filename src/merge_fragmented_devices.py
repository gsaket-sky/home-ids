"""
merge_fragmented_devices.py - CLI utility to reconcile pre-existing device-identity
fragmentation in state/ids_state.json.

Background: DeviceIdentityManager.resolve_device_id() (core/identity.py) now retroactively
merges a fragmented device_id going forward (see the fix landed alongside this script --
_merge_orphan_if_fragmented(), StateManager.merge_into_canonical()), but that fix only
catches fragmentation as it's DISCOVERED during live traffic processing. It does nothing
for device_ids that were already fragmented in an existing state/ids_state.json BEFORE the
fix landed -- a real, confirmed problem: a live scan of one production deployment found 24
fragmented groups across 60 of its 88 tracked device_ids (see Documentation/
DEVICE_IDENTITY_LIFECYCLE.md for the full root-cause writeup).

Groups device_ids that plausibly represent the SAME physical device (sharing a known IP,
a resolved MAC address, or a non-generic hostname -- transitively, via union-find, so a
3-4-way fragmented device unifies into one group even if no two members directly share
all three signals), picks the richest member as canonical per a deterministic tie-break
rule, and folds every other member into it via the exact same
StateManager.merge_into_canonical() the live-traffic fix uses.

Usage (from anywhere -- resolves state relative to config.yaml's state_path):
  1. Dry run (shows every fragmented group, canonical pick + reasoning, changes nothing):
       python3 src/merge_fragmented_devices.py
  2. Actually merge every group's orphans into their canonical identity:
       python3 src/merge_fragmented_devices.py --apply
  BACK UP state/ids_state.json (and the models/ directory, if ml models are in use)
  before running --apply -- this codebase has no undo for a discarded DeviceState or a
  deleted ML model file, same as this script's siblings (release_wrongly_blocked_domains.py,
  clear_stale_isolation.py) already implicitly rely on manual backups for their own
  irreversible actions.
"""
import sys
import time
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG
from core.state_guard import StateManager
from core.identity import _is_generic_hostname


def _device_snapshot(sm: StateManager, dev_id: str) -> dict:
    """Read-only snapshot of the fields this script needs, via the same public
    lock_device() context manager live code uses -- no direct access to
    StateManager's private _states dict."""
    with sm.lock_device(dev_id) as state:
        known_ips = set(state.known_ips.to_list())
        client_ip = getattr(state, "client_ip", "")
        if client_ip:
            known_ips.add(client_ip)
        return {
            "device_id": dev_id,
            "hostname": getattr(state, "hostname", "unknown"),
            "mac_address": getattr(state, "mac_address", "unknown"),
            "device_type": getattr(state, "device_type", "unknown"),
            "known_ips": known_ips,
            "last_seen": getattr(state, "last_seen", 0.0),
        }


def find_fragmented_groups(sm: StateManager) -> list:
    """Union-find over every currently-tracked device_id: two device_ids are unioned if
    they share ANY known IP, OR share a non-'unknown' mac_address, OR share a
    non-generic hostname (reuses identity.py's own _is_generic_hostname() so two
    devices that both merely fell back to the same generic name, e.g. two different
    "laptop"s, don't get falsely unioned -- only an exact, specific, real hostname
    match counts). Returns a list of groups (each a list of device_id snapshots),
    groups of size 1 (no fragmentation) excluded."""
    dev_ids = sm.get_all_device_ids()
    snapshots = {dev_id: _device_snapshot(sm, dev_id) for dev_id in dev_ids}

    parent = {dev_id: dev_id for dev_id in dev_ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i, a in enumerate(dev_ids):
        sa = snapshots[a]
        for b in dev_ids[i + 1:]:
            sb = snapshots[b]
            linked = False
            if sa["known_ips"] & sb["known_ips"]:
                linked = True
            elif (sa["mac_address"] not in ("unknown", "") and sb["mac_address"] not in ("unknown", "")
                  and sa["mac_address"] == sb["mac_address"]):
                linked = True
            elif (not _is_generic_hostname(sa["hostname"]) and not _is_generic_hostname(sb["hostname"])
                  and sa["hostname"].lower() == sb["hostname"].lower()):
                linked = True
            if linked:
                union(a, b)

    groups_by_root = {}
    for dev_id in dev_ids:
        groups_by_root.setdefault(find(dev_id), []).append(snapshots[dev_id])

    return [members for members in groups_by_root.values() if len(members) > 1]


def pick_canonical(group: list) -> dict:
    """Deterministic tie-break: (has real MAC, has real hostname, most known_ips, most
    recent last_seen), in that priority order -- matches the pattern already observed
    in every live-scanned fragmented group (exactly one member almost always has a
    resolved MAC/hostname while the rest have neither)."""
    def score(member):
        has_mac = member["mac_address"] not in ("unknown", "")
        has_hostname = not _is_generic_hostname(member["hostname"])
        return (has_mac, has_hostname, len(member["known_ips"]), member["last_seen"])

    return max(group, key=score)


def _age_str(last_seen: float) -> str:
    if not last_seen:
        return "never"
    age_s = max(0.0, time.time() - last_seen)
    if age_s < 3600:
        return f"{int(age_s // 60)}m ago"
    if age_s < 86400:
        return f"{age_s / 3600:.1f}h ago"
    return f"{age_s / 86400:.1f}d ago"


def main():
    apply_changes = "--apply" in sys.argv

    state_path = CONFIG.get("state_path", "state/ids_state.json")
    sm = StateManager(state_path=state_path)
    sm.load_from_disk()

    groups = find_fragmented_groups(sm)
    if not groups:
        print("No fragmented device groups found -- nothing to merge.")
        return

    total_orphans = 0
    print(f"Found {len(groups)} fragmented group(s):\n")
    for group in groups:
        canonical = pick_canonical(group)
        orphans = [m for m in group if m["device_id"] != canonical["device_id"]]
        total_orphans += len(orphans)
        print(f"=== canonical: {canonical['device_id']}  "
              f"(hostname={canonical['hostname']!r}, mac={canonical['mac_address']!r}, "
              f"type={canonical['device_type']!r}, {len(canonical['known_ips'])} known IP(s), "
              f"last seen {_age_str(canonical['last_seen'])}) ===")
        for orphan in orphans:
            print(f"  orphan: {orphan['device_id']}  "
                  f"(hostname={orphan['hostname']!r}, mac={orphan['mac_address']!r}, "
                  f"type={orphan['device_type']!r}, {len(orphan['known_ips'])} known IP(s), "
                  f"last seen {_age_str(orphan['last_seen'])})")
        print()

    if not apply_changes:
        print(f"Dry run only -- would merge {len(groups)} group(s), {total_orphans} orphan "
              f"device_id(s) total, discarding each orphan's own accumulated state (baselines, "
              f"evidence, learned FP thresholds) and redirecting its known IPs/MAC to its "
              f"group's canonical identity. Re-run with --apply to actually perform the merge.\n"
              f"BACK UP state/ids_state.json (and models/, if ML anomaly models are in use) "
              f"before running --apply -- discarded state and deleted model files cannot be "
              f"undone by this tool.")
        return

    # ml_registry/fp_engine are intentionally NOT constructed here -- this is an offline
    # script with no running pipeline, so there's no live MLRegistry/AutonomousFPEngine
    # instance whose in-memory state also needs updating (unlike merge_into_canonical()'s
    # live-traffic caller in identity.py, which always has both). Any orphan .pkl model
    # files under models/ are left in place, reported below for a manual follow-up pass
    # rather than deleted sight-unseen by a script that never loaded them.
    merged_count = 0
    for group in groups:
        canonical = pick_canonical(group)
        for orphan in group:
            if orphan["device_id"] == canonical["device_id"]:
                continue
            if sm.merge_into_canonical(orphan["device_id"], canonical["device_id"]):
                merged_count += 1

    sm.flush_to_disk()
    print(f"Done. Merged {merged_count} orphan device_id(s) into {len(groups)} canonical "
          f"identit(y/ies).")
    print("Orphan ML model files (models/<device_id>.pkl), if any, were NOT touched by this "
          "offline run -- compare `ls models/*.pkl` against the surviving device_ids and "
          "remove anything unreferenced manually if you're using per-device ML models.")
    print("Restart the service (or wait for the next .ipc_sync_signal-triggered reload) to "
          "pick up the change.")


if __name__ == "__main__":
    main()
