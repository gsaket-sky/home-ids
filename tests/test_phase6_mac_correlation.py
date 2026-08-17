"""
Standalone runtime test for Phase 6 (cross-address-family device correlation). Not part
of the pytest suite — run directly: `python3 test_phase6_mac_correlation.py`. Exercises
the real ZeekFeatureExtractor -> StateManager -> DeviceIdentityManager chain end-to-end,
no mocks.

Background: Phase 5 made IPv6 link-local/ULA addresses trackable (previously hard-
excluded). Without a correlation mechanism, every IPv6 address a dual-stack device uses
cold-starts its OWN separate DeviceState, splitting evidence/threat-detection signal
across two profiles for one physical device (a burst split 50/50 across address families
could stay under each profile's individual alert threshold). Phase 6 fixes this by using
the device's MAC address — identical across its IPv4 and IPv6 traffic — as a protocol-
family-agnostic correlation key.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.state_guard import StateManager
from core.identity import DeviceIdentityManager
from extractors.zeek_features import ZeekFeatureExtractor

IPV4 = "192.168.1.42"
IPV6_LL = "fe80::1a2b:3c4d:5e6f:7788"
IPV6_ULA = "fd7c:1234:5678::42"
MAC = "aa:bb:cc:dd:ee:01"
OTHER_MAC = "aa:bb:cc:dd:ee:02"


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: ZeekFeatureExtractor — conn.log MAC binding + multi-IP aggregation
# ═══════════════════════════════════════════════════════════════════════════════════
zfx = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24", "fe80::/10", "fd00::/8"])

zfx.ingest({
    "_zeek_type": "conn", "id.orig_h": IPV4, "id.resp_h": "93.184.216.34",
    "id.resp_p": 443, "proto": "tcp", "orig_bytes": 1000, "uid": "Cxxxxxxxxxxxxx1",
    "ts": time.time(), "orig_l2_addr": MAC.upper(),  # exercise the .lower() normalization too
})
zfx.ingest({
    "_zeek_type": "conn", "id.orig_h": IPV6_LL, "id.resp_h": "2606:4700::1111",
    "id.resp_p": 443, "proto": "tcp", "orig_bytes": 2500, "uid": "Cxxxxxxxxxxxxx2",
    "ts": time.time(), "orig_l2_addr": MAC,
})

check("conn.log orig_l2_addr binds a MAC for the IPv4 address",
      zfx.get_mac(IPV4) == MAC, f"got={zfx.get_mac(IPV4)}")
check("conn.log orig_l2_addr binds the SAME MAC for the IPv6 link-local address "
      "(this is what makes MAC correlation possible for IPv6-only traffic — DHCPv4 "
      "binding alone would never see this address)",
      zfx.get_mac(IPV6_LL) == MAC, f"got={zfx.get_mac(IPV6_LL)}")

feats_v4_only = zfx.get_features(IPV4)
feats_both = zfx.get_features([IPV4, IPV6_LL])
check("get_features(single IP) only sees that address's traffic (baseline, unchanged call convention)",
      feats_v4_only["zeek_outbound_bytes"] == 1000, f"got={feats_v4_only['zeek_outbound_bytes']}")
check("get_features([ipv4, ipv6]) sums outbound bytes across BOTH address families "
      "(this is the fix — without it, a burst split across v4/v6 stays under threshold on each individually)",
      feats_both["zeek_outbound_bytes"] == 3500, f"got={feats_both['zeek_outbound_bytes']}")
check("get_features([ipv4, ipv6]) sums conn_count across both addresses",
      feats_both["zeek_conn_count"] == 2, f"got={feats_both['zeek_conn_count']}")

dest_both = zfx.get_dest_ips([IPV4, IPV6_LL])
check("get_dest_ips([ipv4, ipv6]) unions destination IPs contacted from both addresses",
      dest_both == {"93.184.216.34", "2606:4700::1111"}, f"got={dest_both}")

zfx.reset_client([IPV4, IPV6_LL])
check("reset_client([ipv4, ipv6]) clears counters for BOTH addresses, not just one",
      zfx.get_features([IPV4, IPV6_LL])["zeek_conn_count"] == 0)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: StateManager — MAC-to-device_id canonical index
# ═══════════════════════════════════════════════════════════════════════════════════
sm = StateManager(state_path="/tmp/_phase6_test_state.json")

check("get_device_id_for_mac() returns None for an unknown MAC (no false correlation)",
      sm.get_device_id_for_mac(MAC) is None)

s1 = sm.get_or_create("dev_v4", IPV4, "smart-tv")
s1.mac_address = MAC  # mirrors _refresh_identity_signals() setting this alongside bind_mac()
sm.bind_mac(MAC, "dev_v4")
check("bind_mac() + get_device_id_for_mac() round-trip correctly",
      sm.get_device_id_for_mac(MAC) == "dev_v4")

# Self-healing: a MAC mapping pointing at a since-pruned/removed device_id must not leak
# forever — get_device_id_for_mac() should notice and clean it up rather than resolving
# new traffic onto a device_id that no longer exists.
sm.bind_mac(OTHER_MAC, "ghost_device_never_created")
check("get_device_id_for_mac() self-heals a stale mapping to a since-removed device_id "
      "(returns None instead of resolving onto a dead device_id)",
      sm.get_device_id_for_mac(OTHER_MAC) is None)
check("the self-healing prune actually removed the stale entry (not just masked it)",
      OTHER_MAC not in sm._mac_to_device_id)

# migrate_device_id() must carry the MAC mapping forward onto the new id.
sm.bind_mac(MAC, "dev_v4")
migrated = sm.migrate_device_id("dev_v4", "dev_v4_renamed")
check("migrate_device_id() succeeds", migrated)
check("migrate_device_id() updates the MAC index to point at the NEW device_id "
      "(a lookup by MAC right after a Phase-4 identity migration must not resolve to the "
      "now-gone old id)",
      sm.get_device_id_for_mac(MAC) == "dev_v4_renamed", f"got={sm.get_device_id_for_mac(MAC)}")

# get_or_create(): when a MAC-resolved device_id already exists in _states, calling
# get_or_create() with a NEW client_ip (e.g. this device's other address family) must
# still register that IP in the reverse index — not just silently return the state.
sm.get_or_create("dev_v4_renamed", IPV6_LL, "smart-tv")
check("get_or_create() on an already-existing device_id registers the NEW client_ip in "
      "the reverse _ip_to_device_id index too (needed so update_device_mac()'s O(1) path "
      "and other by-IP lookups work for the second address family as well)",
      sm._ip_to_device_id.get(IPV6_LL) == "dev_v4_renamed",
      f"got={sm._ip_to_device_id.get(IPV6_LL)}")

# load_from_disk() must rebuild the derived MAC index from persisted DeviceState.mac_address.
sm.flush_to_disk()
sm2 = StateManager(state_path="/tmp/_phase6_test_state.json")
sm2.load_from_disk()
check("load_from_disk() rebuilds _mac_to_device_id as a derived index from persisted state "
      "(so MAC correlation survives a process restart without needing its own JSON key)",
      sm2.get_device_id_for_mac(MAC) == "dev_v4_renamed", f"got={sm2.get_device_id_for_mac(MAC)}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: DeviceIdentityManager.resolve_device_id() — MAC-first anchoring
# ═══════════════════════════════════════════════════════════════════════════════════
sm3 = StateManager(state_path="/tmp/_phase6_test_state_c.json")
idm = DeviceIdentityManager(sm3, config={})

dev_id_v4 = idm.resolve_device_id(IPV4, mac_addr=MAC, hostname="smart-tv")
check("cold-start resolve_device_id() with an unbound MAC still anchors on the IPv4 address "
      "(unchanged existing behavior when no correlation exists yet)",
      dev_id_v4 is not None and dev_id_v4 != "")

# Bind that MAC + actually materialize the DeviceState, the way
# process_dns_identities()/process_zeek_identities() do post-resolution (bind_mac() then
# get_or_create()). get_device_id_for_mac() self-heals away mappings pointing at a
# device_id that was never actually created, so the state must exist for this to stick.
sm3.bind_mac(MAC, dev_id_v4)
sm3.get_or_create(dev_id_v4, IPV4, "smart-tv")

dev_id_v6 = idm.resolve_device_id(IPV6_LL, mac_addr=MAC, hostname="unknown")
check("THE CORE FIX: resolving a DIFFERENT address (IPv6) with the SAME MAC returns the "
      "SAME device_id as the IPv4 resolution, instead of independently hashing the IPv6 "
      "string into a brand-new device_id",
      dev_id_v6 == dev_id_v4, f"v4={dev_id_v4} v6={dev_id_v6}")

# A genuinely different device (different MAC) on a different IP must NOT get merged in.
dev_id_unrelated = idm.resolve_device_id("192.168.1.99", mac_addr="11:22:33:44:55:66", hostname="unrelated")
check("a device with a DIFFERENT MAC on a different IP is NOT incorrectly correlated "
      "(no false-merge of unrelated devices)",
      dev_id_unrelated != dev_id_v4)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: end-to-end — process_zeek_identities() unifies dual-stack traffic into ONE
# DeviceState with both addresses recorded in known_ips
# ═══════════════════════════════════════════════════════════════════════════════════
sm4 = StateManager(state_path="/tmp/_phase6_test_state_d.json")
idm4 = DeviceIdentityManager(sm4, config={})
zfx4 = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24", "fe80::/10", "fd00::/8"])

# Same physical device: an IPv4 conn first (its "known" side), then an IPv6 conn later
# (e.g. after Phase 5 made it visible) — both carrying the same L2 MAC via conn.log.
conn_v4 = {"_zeek_type": "conn", "id.orig_h": IPV4, "id.resp_h": "1.2.3.4", "id.resp_p": 443,
           "proto": "tcp", "orig_bytes": 500, "uid": "Cddd1", "ts": time.time(), "orig_l2_addr": MAC}
conn_v6 = {"_zeek_type": "conn", "id.orig_h": IPV6_ULA, "id.resp_h": "2001:db8::1", "id.resp_p": 443,
           "proto": "tcp", "orig_bytes": 700, "uid": "Cddd2", "ts": time.time(), "orig_l2_addr": MAC}

zfx4.ingest(conn_v4)
active_ids_1 = idm4.process_zeek_identities([conn_v4], zfx4)
zfx4.ingest(conn_v6)
active_ids_2 = idm4.process_zeek_identities([conn_v6], zfx4)

check("both address-family events resolve to exactly ONE active device_id, not two",
      len(active_ids_1) == 1 and active_ids_1 == active_ids_2,
      f"pass1={active_ids_1} pass2={active_ids_2}")

unified_id = active_ids_1[0]
final_state = sm4.get_or_create(unified_id, IPV6_ULA, "smart-tv")
known = set(final_state.known_ips.to_list())
check("the unified DeviceState's known_ips contains BOTH the IPv4 and IPv6 addresses "
      "(what pipeline.py's known_ips_snapshot feeds into zeek_fx aggregation)",
      IPV4 in known and IPV6_ULA in known, f"known_ips={known}")

check("StateManager only has ONE DeviceState for this physical device, not two "
      "(the split-brain this whole fix targets)",
      len(sm4.get_all_device_ids()) == 1, f"got={sm4.get_all_device_ids()}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 6 MAC-correlation checks PASSED.")
