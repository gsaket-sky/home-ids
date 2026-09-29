"""
Standalone runtime test for merge_fragmented_devices.py (the one-time device-identity
cleanup script, Phase 39). Not part of the pytest suite — run directly:
`python3 test_phase39_merge_fragmented_devices_script.py`. No mocks — a real StateManager
against a temp state file, matching this codebase's other standalone test files.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time
import tempfile
import os

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.state_guard import StateManager
from merge_fragmented_devices import find_fragmented_groups, pick_canonical

IPV4 = "192.168.1.42"
IPV6_LL = "fe80::1a2b:3c4d:5e6f:7788"
IPV6_ULA = "fd7c:1234:5678::42"
MAC = "aa:bb:cc:dd:ee:05"
OTHER_MAC = "aa:bb:cc:dd:ee:06"


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: find_fragmented_groups() — the 5 grouping cases from the plan
# ═══════════════════════════════════════════════════════════════════════════════════
sm = StateManager(state_path="/tmp/_phase39_script_test_a.json")

# (a) two devices sharing a known_ip get grouped
a1 = sm.get_or_create("share_ip_1", IPV4, "unknown")
a2 = sm.get_or_create("share_ip_2", IPV6_LL, "unknown")
a2.known_ips.add(IPV4)  # a2 also knows about a1's address

# (b) two devices sharing a mac_address get grouped
b1 = sm.get_or_create("share_mac_1", "192.168.1.50", "unknown")
b1.mac_address = MAC
b2 = sm.get_or_create("share_mac_2", "192.168.1.51", "unknown")
b2.mac_address = MAC

# (c) two devices sharing a real (non-generic) hostname get grouped
c1 = sm.get_or_create("share_host_1", "192.168.1.60", "my-nas-box")
c2 = sm.get_or_create("share_host_2", "192.168.1.61", "my-nas-box")

# (d) two devices sharing NOTHING don't get grouped
d1 = sm.get_or_create("unrelated_1", "192.168.1.70", "unknown")
d2 = sm.get_or_create("unrelated_2", "192.168.1.71", "unknown")

# (d-bis) two devices sharing only a GENERIC hostname must NOT be grouped
e1 = sm.get_or_create("generic_host_1", "192.168.1.80", "laptop")
e2 = sm.get_or_create("generic_host_2", "192.168.1.81", "laptop")

# (e) three-way TRANSITIVE grouping: f1-f2 share an IP, f2-f3 share a MAC, f1 and f3
# share nothing directly -- union-find must still land all three in ONE group.
f1 = sm.get_or_create("transitive_1", "192.168.1.90", "unknown")
f2 = sm.get_or_create("transitive_2", "192.168.1.91", "unknown")
f2.known_ips.add("192.168.1.90")  # f2 <-> f1 via shared IP
f2.mac_address = OTHER_MAC
f3 = sm.get_or_create("transitive_3", "192.168.1.92", "unknown")
f3.mac_address = OTHER_MAC  # f3 <-> f2 via shared MAC

groups = find_fragmented_groups(sm)
group_id_sets = [set(m["device_id"] for m in g) for g in groups]

check("(a) two devices sharing a known_ip are grouped together",
      {"share_ip_1", "share_ip_2"} in group_id_sets, f"groups={group_id_sets}")
check("(b) two devices sharing a mac_address are grouped together",
      {"share_mac_1", "share_mac_2"} in group_id_sets, f"groups={group_id_sets}")
check("(c) two devices sharing a real hostname are grouped together",
      {"share_host_1", "share_host_2"} in group_id_sets, f"groups={group_id_sets}")
check("(d) two devices sharing nothing are NOT grouped",
      not any({"unrelated_1", "unrelated_2"} <= s for s in group_id_sets), f"groups={group_id_sets}")
check("two devices sharing only a GENERIC hostname ('laptop') are NOT falsely grouped",
      not any({"generic_host_1", "generic_host_2"} <= s for s in group_id_sets), f"groups={group_id_sets}")
check("(e) three-way transitive grouping (IP + MAC links) lands all three in ONE group",
      {"transitive_1", "transitive_2", "transitive_3"} in group_id_sets, f"groups={group_id_sets}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: pick_canonical() — the tie-break rule, matching the real production shape
# (one member with mac+hostname, two orphans with neither)
# ═══════════════════════════════════════════════════════════════════════════════════
rich = {"device_id": "rich", "hostname": "home_fritzbox", "mac_address": "aa:bb:cc:dd:ee:13",
        "device_type": "router", "known_ips": {IPV4, IPV6_LL, IPV6_ULA}, "last_seen": time.time()}
orphan_old = {"device_id": "orphan_old", "hostname": "unknown", "mac_address": "unknown",
              "device_type": "laptop", "known_ips": {IPV6_LL}, "last_seen": time.time() - 86400 * 6}
orphan_recent = {"device_id": "orphan_recent", "hostname": "unknown", "mac_address": "unknown",
                  "device_type": "laptop", "known_ips": {IPV6_ULA}, "last_seen": time.time() - 60}

picked = pick_canonical([rich, orphan_old, orphan_recent])
check("pick_canonical() picks the member with a real MAC+hostname over two "
      "unresolved orphans, matching the pattern seen in every live-scanned group",
      picked["device_id"] == "rich", f"got={picked['device_id']}")

# Tie-break on known_ips count when neither has a resolved MAC/hostname.
tie_a = {"device_id": "tie_a", "hostname": "unknown", "mac_address": "unknown",
         "device_type": "laptop", "known_ips": {IPV4, IPV6_LL}, "last_seen": 100.0}
tie_b = {"device_id": "tie_b", "hostname": "unknown", "mac_address": "unknown",
         "device_type": "laptop", "known_ips": {IPV6_ULA}, "last_seen": 200.0}
picked_tie = pick_canonical([tie_a, tie_b])
check("with no resolved mac/hostname on either side, more known_ips wins the tie-break",
      picked_tie["device_id"] == "tie_a", f"got={picked_tie['device_id']}")

# Final tiebreaker: most recent last_seen when everything else ties.
tie_c = {"device_id": "tie_c", "hostname": "unknown", "mac_address": "unknown",
         "device_type": "laptop", "known_ips": {IPV4}, "last_seen": 100.0}
tie_d = {"device_id": "tie_d", "hostname": "unknown", "mac_address": "unknown",
         "device_type": "laptop", "known_ips": {IPV6_LL}, "last_seen": 999.0}
picked_final = pick_canonical([tie_c, tie_d])
check("as the final tiebreaker, most recent last_seen wins",
      picked_final["device_id"] == "tie_d", f"got={picked_final['device_id']}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: end-to-end dry-run vs --apply smoke test against a temp state file
# ═══════════════════════════════════════════════════════════════════════════════════
tmp_dir = tempfile.mkdtemp(prefix="phase39_script_e2e_")
tmp_state_path = os.path.join(tmp_dir, "ids_state.json")

sm_e2e = StateManager(state_path=tmp_state_path)
canon = sm_e2e.get_or_create("e2e_canon", IPV4, "smart-tv")
canon.mac_address = MAC
# Mirrors the real production pattern: the canonical identity's OWN known_ips already
# lists every address (via normal _refresh_identity_signals() accumulation once MAC
# correlation is working for it) -- that's the actual link find_fragmented_groups()
# discovers, not any property of the orphans themselves, which stay minimal/isolated.
canon.known_ips.add(IPV4)
canon.known_ips.add(IPV6_LL)
canon.known_ips.add(IPV6_ULA)
orphan1 = sm_e2e.get_or_create("e2e_orphan1", IPV6_LL, "unknown")
orphan2 = sm_e2e.get_or_create("e2e_orphan2", IPV6_ULA, "unknown")
sm_e2e.flush_to_disk()

device_count_before = len(sm_e2e.get_all_device_ids())
check("smoke-test setup: 3 devices exist before any merge (1 canonical + 2 orphans)",
      device_count_before == 3, f"got={device_count_before}")

# Dry run equivalent: find_fragmented_groups() + pick_canonical() must not mutate state.
groups_e2e = find_fragmented_groups(sm_e2e)
check("dry-run-equivalent pass (grouping only) leaves the device count unchanged",
      len(sm_e2e.get_all_device_ids()) == device_count_before)
check("the 3 devices are correctly identified as ONE fragmented group",
      len(groups_e2e) == 1 and len(groups_e2e[0]) == 3, f"got={groups_e2e}")

# --apply equivalent: actually call merge_into_canonical() for every non-canonical member.
canonical_pick = pick_canonical(groups_e2e[0])
check("the canonical pick for this group is the MAC-resolved device",
      canonical_pick["device_id"] == "e2e_canon", f"got={canonical_pick['device_id']}")
merged_count = 0
for member in groups_e2e[0]:
    if member["device_id"] == canonical_pick["device_id"]:
        continue
    if sm_e2e.merge_into_canonical(member["device_id"], canonical_pick["device_id"]):
        merged_count += 1
sm_e2e.flush_to_disk()

check("--apply-equivalent pass merged exactly 2 orphans", merged_count == 2, f"got={merged_count}")
check("--apply-equivalent pass reduced the device count from 3 to 1",
      len(sm_e2e.get_all_device_ids()) == 1, f"got={sm_e2e.get_all_device_ids()}")

# Reload from disk to confirm the merge was actually persisted, not just in-memory.
sm_reloaded = StateManager(state_path=tmp_state_path)
sm_reloaded.load_from_disk()
check("the merge survives a reload from disk (flush_to_disk() actually persisted it)",
      len(sm_reloaded.get_all_device_ids()) == 1, f"got={sm_reloaded.get_all_device_ids()}")
reloaded_known = set(sm_reloaded.get_or_create("e2e_canon", IPV4, "smart-tv").known_ips.to_list())
check("the persisted canonical identity's known_ips covers all 3 original addresses",
      IPV4 in reloaded_known and IPV6_LL in reloaded_known and IPV6_ULA in reloaded_known,
      f"known_ips={reloaded_known}")

import shutil
shutil.rmtree(tmp_dir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D (continuation session): main()'s graph-mirroring -- real gap found by
# direct investigation: this script (and the live orphan-merge path) previously only
# ever updated state/ids_state.json, leaving the v13 graph completely unaware of any
# merge. main() now also mirrors each real merge into GraphStore.merge_device() when
# a v13_graph.db exists alongside the state file.
# ═══════════════════════════════════════════════════════════════════════════════════
import json
import merge_fragmented_devices as script_module
from argus.graph.store import GraphStore

tmp_dir_d = tempfile.mkdtemp(prefix="phase39_script_graph_")
tmp_state_path_d = os.path.join(tmp_dir_d, "ids_state.json")
tmp_graph_path_d = os.path.join(tmp_dir_d, "v13_graph.db")

sm_d = StateManager(state_path=tmp_state_path_d)
canon_d = sm_d.get_or_create("d_canon", IPV4, "smart-tv")
canon_d.mac_address = MAC
canon_d.known_ips.add(IPV4)
canon_d.known_ips.add(IPV6_LL)
orphan_d = sm_d.get_or_create("d_orphan", IPV6_LL, "unknown")
sm_d.flush_to_disk()

# The graph db must exist BEFORE main() runs for it to be picked up (matches every
# other v13 ops script's own "no db yet -> skip gracefully" convention) -- created
# here with one pre-existing device row for both endpoints, mirroring what a real
# box running engine="v13" would already have.
graph_d = GraphStore(tmp_graph_path_d)
graph_d.upsert_device("d_canon", timestamp=time.time())
graph_d.upsert_device("d_orphan", timestamp=time.time())
graph_d.close()

script_module.CONFIG = {"state_path": tmp_state_path_d}
sys.argv = ["merge_fragmented_devices.py", "--apply"]
script_module.main()

verify_graph_d = GraphStore(tmp_graph_path_d)
check("D: main() mirrors the real merge into the v13 graph -- resolve_canonical_device_id "
      "now redirects the orphan to its canonical id",
      verify_graph_d.resolve_canonical_device_id("d_orphan") == "d_canon")
verify_graph_d.close()
sm_d_reloaded = StateManager(state_path=tmp_state_path_d)
sm_d_reloaded.load_from_disk()
check("D: the v1-side merge ALSO happened (both stores agree, not just the graph) "
      "-- reloaded fresh from disk, matching what main()'s own subprocess actually "
      "persisted, not a stale in-memory object",
      len(sm_d_reloaded.get_all_device_ids()) == 1)
shutil.rmtree(tmp_dir_d, ignore_errors=True)


# --- D: no v13_graph.db present -- main() skips graph mirroring cleanly, v1 merge unaffected ---
tmp_dir_d2 = tempfile.mkdtemp(prefix="phase39_script_nograph_")
tmp_state_path_d2 = os.path.join(tmp_dir_d2, "ids_state.json")

sm_d2 = StateManager(state_path=tmp_state_path_d2)
canon_d2 = sm_d2.get_or_create("d2_canon", IPV4, "smart-tv")
canon_d2.mac_address = OTHER_MAC
canon_d2.known_ips.add(IPV4)
canon_d2.known_ips.add(IPV6_ULA)
sm_d2.get_or_create("d2_orphan", IPV6_ULA, "unknown")
sm_d2.flush_to_disk()

# Deliberately no v13_graph.db created in tmp_dir_d2.
script_module.CONFIG = {"state_path": tmp_state_path_d2}
sys.argv = ["merge_fragmented_devices.py", "--apply"]
script_module.main()  # must not raise despite no graph db existing

sm_d2_reloaded = StateManager(state_path=tmp_state_path_d2)
sm_d2_reloaded.load_from_disk()
check("D: with no v13_graph.db present at all, main() still completes the real "
      "v1 merge without error (graph mirroring is optional, never load-bearing)",
      len(sm_d2_reloaded.get_all_device_ids()) == 1)
check("D: no v13_graph.db file was created as a side effect of this run (the "
      "skip is a real no-op, not an accidental auto-create)",
      not (_PathForSysPath(tmp_dir_d2) / "v13_graph.db").exists())
shutil.rmtree(tmp_dir_d2, ignore_errors=True)


# --- D: dry run (no --apply) never touches the graph, even when a db exists ---
tmp_dir_d3 = tempfile.mkdtemp(prefix="phase39_script_dryrun_")
tmp_state_path_d3 = os.path.join(tmp_dir_d3, "ids_state.json")
tmp_graph_path_d3 = os.path.join(tmp_dir_d3, "v13_graph.db")

sm_d3 = StateManager(state_path=tmp_state_path_d3)
canon_d3 = sm_d3.get_or_create("d3_canon", IPV4, "smart-tv")
canon_d3.mac_address = MAC
canon_d3.known_ips.add(IPV4)
canon_d3.known_ips.add(IPV6_LL)
sm_d3.get_or_create("d3_orphan", IPV6_LL, "unknown")
sm_d3.flush_to_disk()

graph_d3 = GraphStore(tmp_graph_path_d3)
graph_d3.upsert_device("d3_canon", timestamp=time.time())
graph_d3.upsert_device("d3_orphan", timestamp=time.time())
graph_d3.close()

script_module.CONFIG = {"state_path": tmp_state_path_d3}
sys.argv = ["merge_fragmented_devices.py"]  # no --apply
script_module.main()

verify_graph_d3 = GraphStore(tmp_graph_path_d3)
check("D: a dry run (no --apply) leaves the graph completely untouched -- "
      "d3_orphan does NOT resolve to d3_canon",
      verify_graph_d3.resolve_canonical_device_id("d3_orphan") == "d3_orphan")
verify_graph_d3.close()
shutil.rmtree(tmp_dir_d3, ignore_errors=True)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 39 merge_fragmented_devices.py script checks PASSED.")
