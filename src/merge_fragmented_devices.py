"""
merge_fragmented_devices.py - CLI utility to reconcile pre-existing device-identity
fragmentation in state/ids_state.json.

Background: DeviceIdentityManager.resolve_device_id() (core/identity.py) retroactively
merges a fragmented device_id going forward (see StateManager.merge_into_canonical()),
but that fix only catches fragmentation as it's DISCOVERED during live traffic
processing. It does nothing for device_ids that were already fragmented in an existing
state/ids_state.json before that mechanism existed -- a real, confirmed problem on a
live deployment (see Documentation/DEVICE_IDENTITY_LIFECYCLE.md for the full
root-cause writeup).

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
from typing import Optional

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG
from core.state_guard import ADDRESS_HOLD_WINDOW_SECONDS, StateManager
from core.identity import _is_generic_hostname
from core.device_matching import (
    dhcp_fingerprint_match, ja4_overlap, hostname_corroborates,
    match_confidence, AUTO_MERGE_CONFIDENCE, mac_from_eui64,
)
from argus.graph.store import GraphStore


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
            "client_ip": client_ip or "",
            "mac_address": getattr(state, "mac_address", "unknown"),
            # every MAC the device is known by (its field and the MAC index): a field wiped by a MAC-less event must
            # not make a real device look like an address-only fragment (2026-10-12)
            "macs": set(),
            "device_type": getattr(state, "device_type", "unknown"),
            "known_ips": known_ips,
            "last_seen": getattr(state, "last_seen", 0.0),
            # Device-identity fragmentation fix, continuation session: captured so
            # find_fragmented_groups() can ALSO corroborate via the same
            # DHCP-fingerprint/JA4-overlap/hostname scoring device_matching.py
            # already uses for cold-start reidentify -- see that module's own
            # docstring for why each signal alone is deliberately capped, and
            # match_confidence()'s own docstring for how they combine. Closes a
            # real gap: a MAC-randomized device with no shared known_ip and no
            # shared exact MAC/hostname (this script's original 3 signals) but a
            # real DHCP+JA4 fingerprint match was previously invisible to this
            # script entirely.
            "dhcp_fingerprint": getattr(state, "dhcp_fingerprint", None),
            "ja4_seen": set(state.ja4_seen.to_list()) if hasattr(state, "ja4_seen") else set(),
        }


def _mac(snap: dict) -> Optional[str]:
    mac = snap.get("mac_address")
    return mac if mac and mac != "unknown" else None


def _macs(snap: dict) -> set:
    macs = set(snap.get("macs") or ())
    if _mac(snap):
        macs.add(_mac(snap))
    return macs


def _link_reason(sa: dict, sb: dict, window: float) -> Optional[str]:
    """Why two devices are one physical device, or None. An address is a lease, not an identity (2026-10-12, see
    StateManager): before, ANY address shared by the two histories linked them, so DHCP reuse merged unrelated devices
    (on .94 a laptop's whole identity was folded into a phone's), and every merge grew the history behind the next."""
    ma, mb = _macs(sa), _macs(sb)
    if ma & mb:
        return "same MAC"
    both_macs = bool(ma and mb)                       # here: two different MACs
    if not both_macs:
        # An address-only fragment (cold-started before its MAC was known) belongs to a device only on evidence of
        # ownership: its address is built from one of the device's MACs (EUI-64), or it is the address the device uses
        # NOW (and the device was active at least as recently). A device's address HISTORY is not evidence: it is
        # exactly what wrong merges filled -- on .94 a smart monitor's polluted history pulled seven fragments of other
        # devices into it in one reconcile pass (2026-10-12, 12:25).
        for frag, dev in ((sa, sb), (sb, sa)):
            addr = frag.get("client_ip")
            if _macs(frag) or not _macs(dev) or not addr:
                continue
            eui = mac_from_eui64(addr)
            if eui:
                if eui in _macs(dev):
                    return f"address-only fragment {addr} (built from MAC {eui})"
                continue                      # provably another device's address
            if addr == dev.get("client_ip") and (frag.get("last_seen") or 0.0) <= (dev.get("last_seen") or 0.0) + window:
                return f"address-only fragment {addr} (the device's current address)"
    if both_macs and abs((sa.get("last_seen") or 0.0) - (sb.get("last_seen") or 0.0)) < window:
        return None                                   # two MACs active at the same time: two devices (or two NICs)
    rotation = " (MAC rotation)" if both_macs else ""
    if (not _is_generic_hostname(sa["hostname"]) and not _is_generic_hostname(sb["hostname"])
            and sa["hostname"].lower() == sb["hostname"].lower()):
        return f"same name {sa['hostname']!r}{rotation}"
    # The SAME DHCP-fingerprint/JA4-overlap/hostname scoring cold-start reidentify already trusts live
    # (device_matching.py), applied retroactively -- catches a MAC-randomized device with no shared MAC/name but a real
    # fingerprint corroboration. Same AUTO_MERGE_CONFIDENCE bar, not a separately-tuned threshold.
    dhcp_score = dhcp_fingerprint_match(sa["dhcp_fingerprint"], sb["dhcp_fingerprint"])
    ja4_score = ja4_overlap(sa["ja4_seen"], sb["ja4_seen"])
    hostname_ok = hostname_corroborates(sa["hostname"], sb["hostname"])
    if match_confidence(dhcp_score, ja4_score, hostname_ok) >= AUTO_MERGE_CONFIDENCE:
        return f"fingerprint{rotation}"
    return None


def find_fragmented_groups(sm: StateManager, window: float = ADDRESS_HOLD_WINDOW_SECONDS,
                           ambiguous: Optional[list] = None) -> list:
    """Union-find over every currently-tracked device_id, linked by _link_reason() (same MAC; an address-only fragment
    and the device that used its address; a MAC rotation by name or fingerprint). Returns the groups (each a list of
    snapshots, every member with "linked_by": the reasons of its links), groups of size 1 excluded.

    A group that still holds two different MACs not directly linked as a rotation was chained through a third member
    (e.g. an address-only fragment whose address both devices used): it is not merged -- which device the fragment
    belongs to is not known yet -- and is appended to `ambiguous` (if given) as {"members": [...], "reason": str}."""
    dev_ids = sm.get_all_device_ids()
    snapshots = {dev_id: _device_snapshot(sm, dev_id) for dev_id in dev_ids}
    for dev_id, snap in snapshots.items():
        macs_of = getattr(sm, "macs_of", None)
        snap["macs"] = set(macs_of(dev_id)) if macs_of else ({snap["mac_address"]} - {"unknown", ""})
        if snap["mac_address"] in ("unknown", "") and snap["macs"]:
            snap["mac_address"] = sorted(snap["macs"])[0]
    reasons: dict = {}

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
            reason = _link_reason(sa, snapshots[b], window)
            if reason:
                reasons[frozenset((a, b))] = reason
                union(a, b)

    groups_by_root = {}
    for dev_id in dev_ids:
        groups_by_root.setdefault(find(dev_id), []).append(snapshots[dev_id])

    groups = []
    for members in groups_by_root.values():
        if len(members) < 2:
            continue
        ids = [m["device_id"] for m in members]
        for m in members:
            m["linked_by"] = sorted({r for pair, r in reasons.items() if m["device_id"] in pair and pair <= set(ids)})
        macs = [(m["device_id"], _mac(m)) for m in members if _mac(m)]
        unlinked = [(x, y) for i, (x, mx) in enumerate(macs) for y, my in macs[i + 1:]
                    if mx != my and "MAC rotation" not in reasons.get(frozenset((x, y)), "")]
        if unlinked:
            if ambiguous is not None:
                ambiguous.append({"members": members, "reason": f"{len({m for _, m in macs})} different MACs "
                                                               f"(e.g. {unlinked[0][0]} and {unlinked[0][1]}) "
                                                               f"not linked as a MAC rotation"})
            continue
        groups.append(members)
    return groups


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

    ambiguous: list = []
    groups = find_fragmented_groups(sm, window=float(CONFIG.get("identity_reidentify_window_seconds", 1800.0)),
                                    ambiguous=ambiguous)
    for amb in ambiguous:
        print("NOT merged, identity not certain (" + amb["reason"] + "): " + ", ".join(
            f"{m['device_id']} (mac={m['mac_address']!r}, ip={m['client_ip']!r})" for m in amb["members"]))
    if ambiguous:
        print()
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
                  f"last seen {_age_str(orphan['last_seen'])}) -- {'; '.join(orphan.get('linked_by') or [])}")
        print()

    # continuation session: mirror each merge into the
    # argus graph too (GraphStore.merge_device(), audit-preserving -- tombstones the
    # orphan rather than deleting it, so its own evidence/decisions keep resolving
    # through the canonical id via resolve_canonical_device_id()). Real gap found
    # by direct investigation: this script (and the live merge path) previously
    # only ever updated state/ids_state.json, leaving the argus graph's own devices
    # table completely unaware of any merge -- an orphan's graph-side evidence
    # stayed permanently fragmented from its canonical counterpart forever.
    # Best-effort and OPTIONAL: a box with engine="v_current" (no argus graph
    # produced yet) or a missing db file just skips this half silently -- the
    # state-side merge below is unaffected either way.
    graph_db_path = Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "v13_graph.db"
    graph_store = GraphStore(str(graph_db_path)) if graph_db_path.exists() else None
    if graph_store is None:
        print(f"(No graph db found at {graph_db_path} -- graph-side merge mirroring skipped.)")

    if not apply_changes:
        print(f"Dry run only -- would merge {len(groups)} group(s), {total_orphans} orphan "
              f"device_id(s) total, discarding each orphan's own accumulated state (baselines, "
              f"evidence, learned FP thresholds) and redirecting its known IPs/MAC to its "
              f"group's canonical identity{' (and audit-preservingly tombstoning it in the graph)' if graph_store else ''}. "
              f"Re-run with --apply to actually perform the merge.\n"
              f"BACK UP state/ids_state.json (and models/, if ML anomaly models are in use) "
              f"before running --apply -- discarded state and deleted model files cannot be "
              f"undone by this tool.")
        if graph_store:
            graph_store.close()
        return

    # ml_registry/familiarity are intentionally NOT constructed here -- this is an offline
    # script with no running pipeline, so there's no live MLRegistry/DeviceFamiliarity
    # instance whose in-memory state also needs updating (unlike merge_into_canonical()'s
    # live-traffic caller in identity.py, which always has both). Any orphan .pkl model
    # files under models/ are left in place, reported below for a manual follow-up pass
    # rather than deleted sight-unseen by a script that never loaded them.
    merged_count = 0
    graph_merged_count = 0
    for group in groups:
        canonical = pick_canonical(group)
        for orphan in group:
            if orphan["device_id"] == canonical["device_id"]:
                continue
            if sm.merge_into_canonical(orphan["device_id"], canonical["device_id"],
                                        reason="offline merge script: " + "; ".join(orphan.get("linked_by") or ["linked"])):
                merged_count += 1
                if graph_store is not None:
                    try:
                        graph_store.merge_device(orphan["device_id"], canonical["device_id"])
                        graph_merged_count += 1
                    except Exception as e:
                        print(f"  WARNING: failed to mirror merge of {orphan['device_id']} "
                              f"into the graph (the state merge above already succeeded): {e}")

    sm.flush_to_disk()
    if graph_store is not None:
        graph_store.close()
    print(f"Done. Merged {merged_count} orphan device_id(s) into {len(groups)} canonical "
          f"identit(y/ies)."
          + (f" Mirrored {graph_merged_count} of those into the graph." if graph_store else ""))
    print("Orphan ML model files (models/<device_id>.pkl), if any, were NOT touched by this "
          "offline run -- compare `ls models/*.pkl` against the surviving device_ids and "
          "remove anything unreferenced manually if you're using per-device ML models.")
    print("Restart the service (or wait for the next .ipc_sync_signal-triggered reload) to "
          "pick up the change.")


if __name__ == "__main__":
    main()
