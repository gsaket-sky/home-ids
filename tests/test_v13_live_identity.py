"""
Standalone runtime test for src/v13/identity/live_manager.py -- the actual swap-in
for `.94`'s live DeviceIdentityManager (v13 full-architecture plan, Phase 3).

Imports core.identity (real v-current code, real deps like `requests`/`manuf`) --
run via the venv python, not bare python3:
`.venv/Scripts/python.exe tests/test_v13_live_identity.py`

Sections:
  A. Inheritance: everything except resolve_device_id() is the REAL, unmodified
     DeviceIdentityManager method -- Fritz!Box polling, process_dns_identities/
     process_zeek_identities, apply_device_type, orphan-merge cleanup are all
     inherited, not reimplemented
  B. Parity: for the single-gateway-anchor case, LiveIdentityManager's
     resolve_device_id() returns THE SAME device_id v-current's own
     DeviceIdentityManager.resolve_device_id() would, for the same inputs
  C. Generalization: a SECOND trust anchor (beyond the single gateway_ip
     v-current supports) resolves correctly -- the actual point of Phase 3
  D. Persistence: a learned anchor MAC survives a fresh LiveIdentityManager
     instance pointed at the SAME GraphStore (simulating a restart) -- v-current's
     own _gateway_mac is pure in-memory and would NOT survive this
  E. MAC-randomization fix: a locally-administered MAC is excluded from
     mac_bindings and the raw-MAC-fallback branch, falling back to the IP anchor
     instead -- the real, deliberate behavioral difference from v-current
"""
import sys
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.identity import DeviceIdentityManager  # noqa: E402
from core.state_guard import StateManager  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402
from v13.identity.live_manager import LiveIdentityManager  # noqa: E402
from v13.identity.resolver import TrustAnchor, stable_device_id as v13_stable_device_id  # noqa: E402
from core.identity import stable_device_id as v_current_stable_device_id  # noqa: E402

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="v13_live_identity_test_"))
GATEWAY_IP = "192.168.77.1"
THIS_HOST_IP = "192.168.77.94"


def _fresh_state_manager(name):
    return StateManager(state_path=str(TMPDIR / f"{name}_ids_state.json"))


def _fresh_graph_store(name):
    return GraphStore(str(TMPDIR / f"{name}_graph.db"))


# --- A. Inheritance: only resolve_device_id() is overridden ---

anchors = {"gateway": TrustAnchor(role="gateway", ip=GATEWAY_IP)}
live_mgr = LiveIdentityManager(_fresh_state_manager("a"), {"gateway_ip": GATEWAY_IP},
                                  _fresh_graph_store("a"), anchors)

check("A: LiveIdentityManager IS a DeviceIdentityManager (real inheritance, not duck-typing)",
      isinstance(live_mgr, DeviceIdentityManager))
check("A: process_dns_identities is the SAME unmodified function object as the base class's",
      LiveIdentityManager.process_dns_identities is DeviceIdentityManager.process_dns_identities)
check("A: process_zeek_identities is inherited unchanged",
      LiveIdentityManager.process_zeek_identities is DeviceIdentityManager.process_zeek_identities)
check("A: apply_device_type is inherited unchanged",
      LiveIdentityManager.apply_device_type is DeviceIdentityManager.apply_device_type)
check("A: the orphan-merge cleanup helpers are inherited unchanged",
      LiveIdentityManager._merge_orphan_if_fragmented is DeviceIdentityManager._merge_orphan_if_fragmented
      and LiveIdentityManager._release_stale_isolation_if_merged is DeviceIdentityManager._release_stale_isolation_if_merged)
check("A: resolve_device_id IS overridden (the one deliberate change)",
      LiveIdentityManager.resolve_device_id is not DeviceIdentityManager.resolve_device_id)


# --- B. Parity with v-current for the single-gateway-anchor case ---

vcurrent_mgr = DeviceIdentityManager(_fresh_state_manager("b1"), {"gateway_ip": GATEWAY_IP})
live_mgr_b = LiveIdentityManager(_fresh_state_manager("b2"), {"gateway_ip": GATEWAY_IP},
                                    _fresh_graph_store("b"), anchors)

check("B: gateway IP resolves to the SAME device_id under both managers",
      vcurrent_mgr.resolve_device_id(GATEWAY_IP, "aa:bb:cc:dd:ee:ff") ==
      live_mgr_b.resolve_device_id(GATEWAY_IP, "aa:bb:cc:dd:ee:ff"))
check("B: a private trackable IP with no other signals resolves identically",
      vcurrent_mgr.resolve_device_id("192.168.77.50") == live_mgr_b.resolve_device_id("192.168.77.50"))
check("B: a non-generic hostname anchor resolves identically",
      vcurrent_mgr.resolve_device_id("2001:db8::1", hostname="living-room-tv") ==
      live_mgr_b.resolve_device_id("2001:db8::1", hostname="living-room-tv"))
check("B: a REAL (non-randomized) MAC fallback resolves identically",
      vcurrent_mgr.resolve_device_id("::1", mac_addr="f0:18:98:aa:bb:cc") ==
      live_mgr_b.resolve_device_id("::1", mac_addr="f0:18:98:aa:bb:cc"))


# --- C. Generalization: a second trust anchor v-current has no equivalent for ---

two_anchors = {
    "gateway": TrustAnchor(role="gateway", ip=GATEWAY_IP),
    "this_host": TrustAnchor(role="this_host", ip=THIS_HOST_IP),
}
live_mgr_c = LiveIdentityManager(_fresh_state_manager("c"), {"gateway_ip": GATEWAY_IP},
                                    _fresh_graph_store("c"), two_anchors)
gw_id = live_mgr_c.resolve_device_id(GATEWAY_IP)
host_id = live_mgr_c.resolve_device_id(THIS_HOST_IP)
check("C: a SECOND trust anchor (this_host) resolves to its own distinct, stable id",
      host_id != gw_id and live_mgr_c.resolve_device_id(THIS_HOST_IP) == host_id)
# Note: v-current's own DeviceIdentityManager has no "this_host" anchor concept at
# all -- it would resolve THIS_HOST_IP via the plain trackable-IP branch, identical
# to any other ordinary device, with no way to mark it as infrastructure. Since an
# anchor WITH a configured ip intentionally uses v-current's own stable_device_id(ip)
# formula for migration continuity (see live_manager.py's own docstring on why), the
# anchor id and the plain trackable-IP id are the SAME value here BY DESIGN -- what
# v13 actually adds is the ROLE-based lookup path (branches 1/2 firing on any of N
# named anchors, not just one hardcoded gateway_ip), not a different id per se.
check("C: this_host's anchor id matches v-current's own stable_device_id(ip) formula "
      "exactly (not resolver.py's role-based one) -- the same migration-continuity "
      "property already proven for the gateway anchor in section B",
      host_id == v13_stable_device_id(THIS_HOST_IP))


# --- D. Persistence: a learned anchor MAC survives a fresh instance (restart) ---

store_d = _fresh_graph_store("d")
live_mgr_d1 = LiveIdentityManager(_fresh_state_manager("d1"), {"gateway_ip": GATEWAY_IP}, store_d, anchors)
live_mgr_d1.resolve_device_id(GATEWAY_IP, mac_addr="f0:18:98:99:88:77")  # learns the gateway's MAC

# Fresh instance, SAME graph store, DIFFERENT state_manager (simulating a real restart --
# StateManager's own file-backed state is a separate concern, not what's under test here)
live_mgr_d2 = LiveIdentityManager(_fresh_state_manager("d2"), {"gateway_ip": GATEWAY_IP}, store_d, anchors)
check("D: a fresh LiveIdentityManager (simulating a restart) still recognizes the "
      "gateway's PREVIOUSLY-LEARNED MAC on a DIFFERENT IP -- the actual restart-survival "
      "property v-current's own single in-memory _gateway_mac field cannot offer",
      live_mgr_d2.resolve_device_id("fe80::aa11:2233:4455", mac_addr="f0:18:98:99:88:77")
      == live_mgr_d1.resolve_device_id(GATEWAY_IP))


# --- E. MAC-randomization fix: excluded from mac_bindings + raw-MAC-fallback ---

state_e = _fresh_state_manager("e")
live_mgr_e = LiveIdentityManager(state_e, {"gateway_ip": GATEWAY_IP}, _fresh_graph_store("e"), {})
RANDOM_MAC = "02:00:00:aa:bb:cc"  # locally-administered bit set

# First call with a non-trackable IP + the randomized MAC -- v-current's OWN logic
# would fall to the raw-MAC-fallback branch (stable_device_id(mac)); v13's fix should
# instead fall to the IP-based fallback.
result_e1 = live_mgr_e.resolve_device_id("::1", mac_addr=RANDOM_MAC)
vcurrent_mgr_e = DeviceIdentityManager(_fresh_state_manager("e_vcurrent"), {"gateway_ip": GATEWAY_IP})
vcurrent_result_e1 = vcurrent_mgr_e.resolve_device_id("::1", mac_addr=RANDOM_MAC)
check("E: v-current's OWN logic really does anchor a non-trackable-IP device to the "
      "raw MAC (confirms this scenario genuinely exercises the MAC-fallback branch, "
      "not some other path)",
      vcurrent_result_e1 == v_current_stable_device_id(RANDOM_MAC))
check("E: LiveIdentityManager instead anchors to the IP (stable_device_id('::1')), "
      "NOT the randomized MAC -- the real, deliberate behavioral difference",
      result_e1 == v13_stable_device_id("::1") and result_e1 != v13_stable_device_id(RANDOM_MAC))

# state_manager.bind_mac() a real, ACTUALLY-REGISTERED device_id under the randomized
# MAC first (get_device_id_for_mac() correctly treats an unregistered device_id as a
# stale/dangling reference and returns None, so the bound id must be real), THEN
# confirm a later call with the SAME randomized MAC does NOT reuse that binding.
state_e.get_or_create(device_id="stale_device_from_prior_rotation", client_ip="192.168.77.77", hostname="unknown")
state_e.bind_mac(RANDOM_MAC, "stale_device_from_prior_rotation")
result_e2 = live_mgr_e.resolve_device_id("2001:db8::99", mac_addr=RANDOM_MAC)
check("E: a randomized MAC's mac_bindings entry (branch 3) is deliberately ignored -- "
      "does NOT return the stale device_id bound under this rotating MAC",
      result_e2 != "stale_device_from_prior_rotation")

# REGRESSION GUARD: a REAL (non-randomized) MAC still uses mac_bindings normally.
state_e.get_or_create(device_id="real_stable_device", client_ip="192.168.77.78", hostname="unknown")
state_e.bind_mac("f0:18:98:aa:bb:cc", "real_stable_device")
result_e3 = live_mgr_e.resolve_device_id("2001:db8::100", mac_addr="f0:18:98:aa:bb:cc")
check("E: REGRESSION GUARD -- a real, non-randomized MAC still correctly uses an "
      "existing mac_binding (the fix is scoped to randomized MACs only)",
      result_e3 == "real_stable_device")


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 live_manager (identity) checks PASSED.")
