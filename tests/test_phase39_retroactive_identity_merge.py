"""
Standalone runtime test for Phase 39 (device-identity fragmentation fix). Not part of
the pytest suite — run directly: `python3 test_phase39_retroactive_identity_merge.py`.
No mocks — exercises the real StateManager / DeviceIdentityManager / ZeekFeatureExtractor
chain, matching test_phase6_mac_correlation.py's own convention.

Background: confirmed live against a real deployment's state/ids_state.json (24
fragmented groups, 60 of 88 tracked device_ids) that resolve_device_id()'s MAC-first
anchoring (Phase 6, tested in test_phase6_mac_correlation.py) only prevents a NEW
device_id from being minted once a MAC binding exists — it never retroactively merges a
device_id that was ALREADY minted via the IP-anchor branch for an address seen BEFORE its
MAC became known. Phase 6's own tests only cover the case where the MAC is known from the
very first packet; this file specifically covers the case where it becomes known LATER,
after a competing "orphan" device_id already exists for that address — the actual live
bug. Also covers the router-specific gateway special-case (a router's genuinely-multiple
physical MACs can never converge via MAC alone) and the two pre-existing gaps closed in
the same pass (fp_engine profile orphaning, the _ip_to_device_id leak on prune).
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
from core.identity import DeviceIdentityManager, stable_device_id
from extractors.zeek_features import ZeekFeatureExtractor

IPV4 = "192.168.1.42"
IPV6_LL = "fe80::1a2b:3c4d:5e6f:7788"
MAC = "aa:bb:cc:dd:ee:03"
GATEWAY_IP = "192.168.1.1"


class _FakeMLRegistry:
    def __init__(self):
        self.discarded = []
        self.migrated = []

    def discard_device(self, device_id, reason="merge"):
        self.discarded.append((device_id, reason))

    def migrate_device(self, old_id, new_id):
        self.migrated.append((old_id, new_id))


class _FakeFPEngine:
    def __init__(self):
        self.discarded = []

    def discard_device_profile(self, device_id, reason="merge"):
        self.discarded.append((device_id, reason))


class _FakeEvidenceStore:
    def __init__(self):
        self.cleared = []

    def clear_device(self, device_id):
        self.cleared.append(device_id)


class _FakeMetricsExporter:
    def __init__(self):
        self.removed = []

    def remove_device_metric_labels(self, dev_id, hostname, device_type, keep_safe_flag=False):
        self.removed.append((dev_id, hostname, device_type))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: StateManager.merge_into_canonical() — the core primitive, in isolation
# ═══════════════════════════════════════════════════════════════════════════════════
sm = StateManager(state_path="/tmp/_phase39_test_state_a.json")

canonical = sm.get_or_create("canon_id", IPV4, "smart-tv")
canonical.mac_address = MAC
orphan = sm.get_or_create("orphan_id", IPV6_LL, "unknown")
# HANDOVER FOLLOW-UP (2026-09-20): real operator-confirmed incident counters on both
# sides -- these must be CARRIED FORWARD (summed/OR'd), unlike statistical state.
canonical.confirmed_threat_count = 2
canonical.fp_count = 1
canonical.has_validated_threat = True
orphan.confirmed_threat_count = 3
orphan.fp_count = 5
orphan.has_validated_threat = False

check("safety: merge_into_canonical() with a canonical_id that isn't tracked is a no-op",
      sm.merge_into_canonical("orphan_id", "nonexistent_id") is False)
check("...and doesn't delete the orphan when it refuses",
      sm.has_device("orphan_id"))

check("safety: merge_into_canonical(x, x) is a no-op", sm.merge_into_canonical("canon_id", "canon_id") is False)

fake_ml = _FakeMLRegistry()
fake_fp = _FakeFPEngine()
merged = sm.merge_into_canonical("orphan_id", "canon_id", ml_registry=fake_ml, familiarity=fake_fp)
check("merge_into_canonical() succeeds for a real orphan/canonical pair", merged)
check("the orphan's own DeviceState is discarded (not blended)", not sm.has_device("orphan_id"))
check("the canonical DeviceState survives untouched (still tracked)", sm.has_device("canon_id"))

canon_known = set(sm.get_or_create("canon_id", IPV4, "smart-tv").known_ips.to_list())
check("the orphan's address is folded into the canonical identity's known_ips",
      IPV6_LL in canon_known, f"known_ips={canon_known}")
check("the reverse _ip_to_device_id index now points the orphan's address at canonical",
      sm._ip_to_device_id.get(IPV6_LL) == "canon_id", f"got={sm._ip_to_device_id.get(IPV6_LL)}")

check("ml_registry.discard_device() was called for the orphan with reason=\"merge\" (not "
      "migrate_device — that would have wrongly overwritten canonical's own live model)",
      fake_ml.discarded == [("orphan_id", "merge")] and fake_ml.migrated == [], f"discarded={fake_ml.discarded} migrated={fake_ml.migrated}")
check("familiarity.discard_device_profile() was called for the orphan with reason=\"merge\"",
      fake_fp.discarded == [("orphan_id", "merge")])

canon_after_merge = sm.get_or_create("canon_id", IPV4, "smart-tv")
check("THE FIX: confirmed_threat_count is CARRIED FORWARD (summed), not discarded -- a "
      "real operator-confirmed incident count, not statistical state",
      canon_after_merge.confirmed_threat_count == 5, f"got={canon_after_merge.confirmed_threat_count}")
check("THE FIX: fp_count is CARRIED FORWARD (summed) too",
      canon_after_merge.fp_count == 6, f"got={canon_after_merge.fp_count}")
check("THE FIX: has_validated_threat is OR'd -- the canonical was already True, stays True",
      canon_after_merge.has_validated_threat is True)

check("idempotent: merging the same (now-gone) orphan a second time is a safe no-op",
      sm.merge_into_canonical("orphan_id", "canon_id") is False)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: side channels — isolation release reuse + new orphan-cleanup channel
# ═══════════════════════════════════════════════════════════════════════════════════
sm_b = StateManager(state_path="/tmp/_phase39_test_state_b.json")
canon_b = sm_b.get_or_create("canon_b", IPV4, "smart-tv")
orphan_b = sm_b.get_or_create("orphan_b", IPV6_LL, "unknown")
orphan_b.mac_address = "aa:bb:cc:dd:ee:04"

sm_b.merge_into_canonical("orphan_b", "canon_b")

isolation_target = sm_b.pop_last_migrated_isolation_target()
check("merge_into_canonical() reuses the EXISTING isolation-release side channel "
      "(identity.py's _release_stale_isolation_if_merged() needs zero changes to pick "
      "this up) — carries the orphan's own pre-merge mac/ip",
      isolation_target == {"mac_addr": "aa:bb:cc:dd:ee:04", "ip_addr": IPV6_LL},
      f"got={isolation_target}")
check("the isolation side channel is consume-once (drained by the pop above)",
      sm_b.pop_last_migrated_isolation_target() is None)

sm_c = StateManager(state_path="/tmp/_phase39_test_state_c.json")
canon_c = sm_c.get_or_create("canon_c", IPV4, "smart-tv")
orphan_c = sm_c.get_or_create("orphan_c", IPV6_LL, "orphan-host")
orphan_c.device_type = "laptop"
orphan_c.has_validated_threat = True  # canon_c stays at its False default
sm_c.merge_into_canonical("orphan_c", "canon_c")
check("THE FIX: has_validated_threat is OR'd the OTHER direction too -- the orphan "
      "was the one flagged True, and that fact survives onto the canonical",
      canon_c.has_validated_threat is True)
cleanup_info = sm_c.pop_last_orphan_merge_cleanup()
check("the new orphan-merge-cleanup side channel carries the orphan's id/hostname/type "
      "and the canonical id it was folded into",
      cleanup_info == {"orphan_id": "orphan_c", "orphan_hostname": "orphan-host",
                        "orphan_device_type": "laptop", "canonical_id": "canon_c"},
      f"got={cleanup_info}")
check("the orphan-merge-cleanup channel is consume-once too",
      sm_c.pop_last_orphan_merge_cleanup() is None)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: blocked_domains re-attribution on merge (cosmetic, but a real gap closed)
# ═══════════════════════════════════════════════════════════════════════════════════
sm_d = StateManager(state_path="/tmp/_phase39_test_state_d.json")
sm_d.get_or_create("canon_d", IPV4, "smart-tv")
sm_d.get_or_create("orphan_d", IPV6_LL, "unknown")
ips_state = sm_d.get_ips_state()
ips_state["blocked_domains"]["evil.example"] = {"device_id": "orphan_d", "hostname": "unknown", "status": "active"}
sm_d._ips_state = ips_state  # test-only direct write, mirrors update_ips_state_atomic()'s effect

sm_d.merge_into_canonical("orphan_d", "canon_d")
reattributed = sm_d.get_ips_state()["blocked_domains"]["evil.example"]
check("a blocked_domains entry tagged with the orphan's device_id is re-attributed to "
      "the canonical identity on merge (pure relabel — release-by-identifier already "
      "worked either way, this just fixes the stale attribution display)",
      reattributed["device_id"] == "canon_d", f"got={reattributed}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: prune_stale_devices() — the _ip_to_device_id leak fix
# ═══════════════════════════════════════════════════════════════════════════════════
sm_e = StateManager(state_path="/tmp/_phase39_test_state_e.json")
multi_ip_state = sm_e.get_or_create("multi_ip_dev", IPV4, "smart-tv")
multi_ip_state.known_ips.add(IPV4)
multi_ip_state.known_ips.add(IPV6_LL)
multi_ip_state.known_ips.add("fd7c:1234:5678::42")
multi_ip_state.last_alert_time = time.time() - (86400 * 8)  # 8 days ago, past the 7-day default
sm_e._ip_to_device_id[IPV6_LL] = "multi_ip_dev"
sm_e._ip_to_device_id["fd7c:1234:5678::42"] = "multi_ip_dev"

pruned = sm_e.prune_stale_devices(time.time())
check("prune_stale_devices() actually pruned the stale device", len(pruned) == 1 and pruned[0][0] == "multi_ip_dev")
check("BUGFIX: every one of the pruned device's known_ips is cleared from "
      "_ip_to_device_id, not just its most-recent client_ip",
      IPV4 not in sm_e._ip_to_device_id and IPV6_LL not in sm_e._ip_to_device_id
      and "fd7c:1234:5678::42" not in sm_e._ip_to_device_id,
      f"remaining={sm_e._ip_to_device_id}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: the gateway special-case
# ═══════════════════════════════════════════════════════════════════════════════════
sm_f = StateManager(state_path="/tmp/_phase39_test_state_f.json")
idm_f = DeviceIdentityManager(sm_f, config={"gateway_ip": GATEWAY_IP})

gw_id_1 = idm_f.resolve_device_id(GATEWAY_IP, mac_addr="aa:11:11:11:11:11", hostname="router-lan")
gw_id_2 = idm_f.resolve_device_id(GATEWAY_IP, mac_addr="bb:22:22:22:22:22", hostname="router-wlan")
check("THE ROUTER FIX: the gateway IP resolves to the SAME device_id regardless of "
      "which MAC is presented for it (a real router genuinely has multiple distinct "
      "physical MACs, one per interface, that can never converge via MAC alone)",
      gw_id_1 == gw_id_2, f"gw_id_1={gw_id_1} gw_id_2={gw_id_2}")
check("the gateway special-case reuses the ordinary IP-anchor hash formula for that "
      "literal IP, so an existing deployment sees zero device_id churn for the "
      "router's already-established gateway-IP identity",
      gw_id_1 == stable_device_id(GATEWAY_IP), f"got={gw_id_1} expected={stable_device_id(GATEWAY_IP)}")

idm_no_gw = DeviceIdentityManager(StateManager(state_path="/tmp/_phase39_test_state_g.json"), config={})
non_special = idm_no_gw.resolve_device_id(GATEWAY_IP, mac_addr="aa:11:11:11:11:11", hostname="router-lan")
check("with gateway_ip unset (default), the special-case is inert and this IP resolves "
      "via the ordinary IP-anchor branch exactly as it always did",
      non_special == stable_device_id(GATEWAY_IP), f"got={non_special}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: end-to-end — the actual live bug scenario, reproduced and fixed
# ═══════════════════════════════════════════════════════════════════════════════════
sm_g = StateManager(state_path="/tmp/_phase39_test_state_h.json")
idm_g = DeviceIdentityManager(sm_g, config={})
zfx_g = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24", "fe80::/10", "fd00::/8"])
fake_evidence = _FakeEvidenceStore()
fake_metrics = _FakeMetricsExporter()

# Step 1: the device's IPv6 link-local traffic is seen FIRST, with NO resolvable L2 MAC
# (orig_l2_addr omitted — mirrors a real Zeek log line where the MAC genuinely isn't
# captured for that specific flow). This mints an orphan, IP-anchored device_id, exactly
# like the real bug.
conn_v6_no_mac = {"_zeek_type": "conn", "id.orig_h": IPV6_LL, "id.resp_h": "2001:db8::1",
                   "id.resp_p": 443, "proto": "tcp", "orig_bytes": 100, "uid": "Cphase39a",
                   "ts": time.time()}
zfx_g.ingest(conn_v6_no_mac)
ids_step1 = idm_g.process_zeek_identities([conn_v6_no_mac], zfx_g)
check("step 1 (no MAC yet): the IPv6 address cold-starts its own orphan device_id",
      len(ids_step1) == 1)
orphan_id_live = ids_step1[0]
check("...and it's exactly the plain IP-anchor hash (the orphan we expect to later merge away)",
      orphan_id_live == stable_device_id(IPV6_LL), f"got={orphan_id_live}")

# Step 2: the SAME device's IPv4 traffic is seen, WITH a resolvable L2 MAC. Since this MAC
# has never been bound before, resolve_device_id() falls through to the IP-anchor branch
# too (mints/reuses the IPv4-hash id) — bind_mac() then records this MAC -> this id.
conn_v4_mac = {"_zeek_type": "conn", "id.orig_h": IPV4, "id.resp_h": "1.2.3.4",
               "id.resp_p": 443, "proto": "tcp", "orig_bytes": 200, "uid": "Cphase39b",
               "ts": time.time(), "orig_l2_addr": MAC}
zfx_g.ingest(conn_v4_mac)
ids_step2 = idm_g.process_zeek_identities([conn_v4_mac], zfx_g)
canonical_id_live = ids_step2[0]
check("step 2 (MAC now known, but for a DIFFERENT address): mints/uses the IPv4-anchored id",
      canonical_id_live == stable_device_id(IPV4), f"got={canonical_id_live}")
check("the orphan from step 1 is STILL separately tracked at this point (not yet merged — "
      "nothing has revisited its address since its MAC became known elsewhere)",
      sm_g.has_device(orphan_id_live) and orphan_id_live != canonical_id_live)

# Step 3: the device's IPv6 link-local traffic is seen AGAIN, this time WITH the same L2
# MAC now resolvable for it too. resolve_device_id()'s MAC-first branch now finds the MAC
# already bound to canonical_id_live -- THE BUG: without the fix, get_or_create() would
# just start using canonical_id_live going forward while orphan_id_live sits forgotten.
conn_v6_with_mac = {"_zeek_type": "conn", "id.orig_h": IPV6_LL, "id.resp_h": "2001:db8::1",
                     "id.resp_p": 443, "proto": "tcp", "orig_bytes": 300, "uid": "Cphase39c",
                     "ts": time.time(), "orig_l2_addr": MAC}
zfx_g.ingest(conn_v6_with_mac)
ids_step3 = idm_g.process_zeek_identities([conn_v6_with_mac], zfx_g, evidence_store=fake_evidence,
                                            metrics_exporter=fake_metrics)
check("THE FIX: step 3 resolves to the CANONICAL (IPv4-anchored) id, not a third id",
      ids_step3 == [canonical_id_live], f"got={ids_step3}")
check("THE FIX: the orphan from step 1 no longer exists as a separate tracked device — "
      "it was retroactively merged, not left permanently orphaned",
      not sm_g.has_device(orphan_id_live))
check("StateManager ends up with exactly ONE DeviceState for this physical device, not "
      "the two-to-three fragments the live bug produced",
      len(sm_g.get_all_device_ids()) == 1, f"got={sm_g.get_all_device_ids()}")

merged_known_ips = set(sm_g.get_or_create(canonical_id_live, IPV4, "unknown").known_ips.to_list())
check("the canonical identity's known_ips ends up covering both address families",
      IPV4 in merged_known_ips and IPV6_LL in merged_known_ips, f"known_ips={merged_known_ips}")

check("evidence_store.clear_device() was called for the discarded orphan",
      fake_evidence.cleared == [orphan_id_live], f"got={fake_evidence.cleared}")
check("metrics_exporter.remove_device_metric_labels() was called for the discarded orphan",
      len(fake_metrics.removed) == 1 and fake_metrics.removed[0][0] == orphan_id_live,
      f"got={fake_metrics.removed}")

# Regression guard: a device whose MAC was NEVER known before either (first-ever packet
# with a MAC) must NOT trigger a spurious merge — this exercises the "nothing orphaned"
# no-op path explicitly, matching today's unchanged behavior for the ordinary case.
sm_h = StateManager(state_path="/tmp/_phase39_test_state_i.json")
idm_h = DeviceIdentityManager(sm_h, config={})
zfx_h = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24", "fe80::/10", "fd00::/8"])
conn_fresh = {"_zeek_type": "conn", "id.orig_h": "192.168.1.55", "id.resp_h": "5.6.7.8",
              "id.resp_p": 443, "proto": "tcp", "orig_bytes": 50, "uid": "Cphase39d",
              "ts": time.time(), "orig_l2_addr": "cc:cc:cc:cc:cc:cc"}
zfx_h.ingest(conn_fresh)
ids_fresh_1 = idm_h.process_zeek_identities([conn_fresh], zfx_h)
ids_fresh_2 = idm_h.process_zeek_identities([conn_fresh], zfx_h)
check("REGRESSION GUARD: a device with no pre-existing fragmentation resolves to the "
      "SAME id on repeated calls with no spurious merge triggered (identical to "
      "pre-fix behavior for the ordinary, non-fragmented case)",
      ids_fresh_1 == ids_fresh_2 and len(sm_h.get_all_device_ids()) == 1,
      f"pass1={ids_fresh_1} pass2={ids_fresh_2} all_ids={sm_h.get_all_device_ids()}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section G: HANDOVER FIX (2026-09-20) -- the zombie-resurrection identity-merge race
#
# Background: real .94 logs showed merge_into_canonical() aborting with "canonical_id
# X is not a currently tracked device" -- X being a device_id that had ALREADY been
# discarded by an earlier, successful merge. Root cause: resolve_device_id()'s
# IP/hostname/MAC hash branches (stable_device_id()) are pure functions with no memory
# of what they've hashed before. A later per-flow signal miss (Zeek didn't capture the
# MAC on THIS specific flow, even though it's known elsewhere for the same device)
# regenerates the exact same hash as a device_id that's since been merged away and
# deleted -- get_or_create() would then silently resurrect a zombie DeviceState under
# the dead id, stealing that address's future traffic from its real canonical identity
# and leaving a stray row behind in anything keyed by device_id (e.g. device_baselines).
# Fixed via a flat, persisted _merge_redirects map (dead id -> live successor),
# consulted by resolve_device_id() and re-checked defensively inside
# merge_into_canonical() itself.
# ═══════════════════════════════════════════════════════════════════════════════════

# G1: continues DIRECTLY from Section F's already-merged state (sm_g/idm_g/orphan_id_live/
# canonical_id_live) -- the exact real scenario, using real stable_device_id() hashes, not
# hand-picked literal ids, so there's no risk of testing a mismatched/synthetic id.
resolved_after_merge = idm_g.resolve_device_id(IPV6_LL, mac_addr=None, hostname="unknown")
check("THE FIX: re-resolving the orphan's OWN address AFTER its merge, this time with a "
      "per-flow MAC miss (mac_addr=None) -- exactly the live .94 failure mode -- returns "
      "the LIVE canonical id instead of resurrecting the dead orphan hash",
      resolved_after_merge == canonical_id_live,
      f"got={resolved_after_merge} want={canonical_id_live}")
check("...and no zombie DeviceState was created under the dead orphan id",
      not sm_g.has_device(orphan_id_live))
check("resolve_merge_redirect() maps the dead orphan id straight to its live successor",
      sm_g.resolve_merge_redirect(orphan_id_live) == canonical_id_live,
      f"got={sm_g.resolve_merge_redirect(orphan_id_live)}")
check("resolve_merge_redirect() is a no-op for an id that was never merged away",
      sm_g.resolve_merge_redirect(canonical_id_live) == canonical_id_live)
check("resolve_merge_redirect() is a no-op for a completely unknown id",
      sm_g.resolve_merge_redirect("never_seen_id") == "never_seen_id")

# G2: chain flattening + merge_into_canonical()'s own defensive re-resolution, and
# persistence -- exercised at the StateManager level directly with hand-picked ids (no
# resolve_device_id() involved here, so literal ids are fine: only the redirect-map
# mechanics are under test, not hash derivation).
sm_i = StateManager(state_path="/tmp/_phase39_test_state_j.json")
canon_i = sm_i.get_or_create("canon_i", IPV4, "smart-tv")
orphan_i = sm_i.get_or_create("orphan_i", IPV6_LL, "unknown")
sm_i.merge_into_canonical("orphan_i", "canon_i")

super_canon = sm_i.get_or_create("super_canon_i", "10.0.0.99", "smart-tv")
merged_chain = sm_i.merge_into_canonical("canon_i", "super_canon_i")
check("setup: a formerly-canonical id can itself be merged away later", merged_chain)
check("CHAIN FLATTENING: resolving the ORIGINAL orphan now returns the NEWEST canonical "
      "directly, in one hop, not the intermediate dead id",
      sm_i.resolve_merge_redirect("orphan_i") == "super_canon_i",
      f"got={sm_i.resolve_merge_redirect('orphan_i')}")
check("merge_into_canonical() resolves a stale canonical_id argument instead of "
      "blindly aborting against it -- calling it again with the now-superseded "
      "'canon_i' as the target correctly finds nothing left to merge",
      sm_i.merge_into_canonical("orphan_i", "canon_i") is False,
      "expected False: orphan_i and canon_i both now resolve to super_canon_i, so "
      "orphan_id == canonical_id after resolution")

# Persistence: the redirect map must survive a restart, or the fix only lasts until the
# next soc.service bounce -- exactly the kind of restart this whole investigation is about.
sm_i.flush_to_disk()
sm_i_reloaded = StateManager(state_path="/tmp/_phase39_test_state_j.json")
sm_i_reloaded.load_from_disk()
check("PERSISTENCE: the merge redirect map survives a flush/reload cycle",
      sm_i_reloaded.resolve_merge_redirect("orphan_i") == "super_canon_i",
      f"got={sm_i_reloaded.resolve_merge_redirect('orphan_i')}")
check("PERSISTENCE: the intermediate redirect also survives",
      sm_i_reloaded.resolve_merge_redirect("canon_i") == "super_canon_i",
      f"got={sm_i_reloaded.resolve_merge_redirect('canon_i')}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 39 retroactive-identity-merge checks PASSED.")
