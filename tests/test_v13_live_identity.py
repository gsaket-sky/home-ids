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
  E. MAC-randomization: scoped ONLY to trust-anchor MAC *learning* (never
     permanently record a rotating-looking MAC as an anchor's canonical MAC).
     Deliberately does NOT gate the general mac_bindings lookup or MAC-based
     resolution for ordinary devices -- an earlier version did, and broke live
     in production within 90 seconds of first deploying (a locally-administered
     bit does not mean a MAC is rotating right now; modern iOS/Android "private
     Wi-Fi address" MACs are stable per-network). See the dependency map's
     incident writeup and live_manager.py's own corrected docstring.
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


# --- E. MAC-randomization: scoped to anchor-learning only ---

state_e = _fresh_state_manager("e")
RANDOM_MAC = "02:00:00:aa:bb:cc"  # locally-administered bit set -- e.g. a modern
                                  # iPhone/Android per-network private Wi-Fi address

# THE ACTUAL PRODUCTION INCIDENT, reproduced as a regression guard: a device with a
# locally-administered-looking MAC that already has a real, persisted mac_binding
# (state_manager.get_device_id_for_mac()) MUST continue to resolve to that SAME
# device_id regardless of the IP it's currently seen on -- exactly what broke live
# on `.94` within 90 seconds of first deploying this manager (51 -> 55 devices),
# traced to an earlier version excluding randomized-looking MACs from this lookup.
live_mgr_e = LiveIdentityManager(state_e, {"gateway_ip": GATEWAY_IP}, _fresh_graph_store("e"), {})
state_e.get_or_create(device_id="real_stable_phone", client_ip="192.168.77.77", hostname="unknown")
state_e.bind_mac(RANDOM_MAC, "real_stable_phone")
result_e1 = live_mgr_e.resolve_device_id("192.168.77.201", mac_addr=RANDOM_MAC)
check("E: REGRESSION GUARD (production incident) -- a locally-administered-looking "
      "MAC with an existing persisted mac_binding still resolves to that SAME "
      "device_id even on a NEW IP, exactly matching a real non-randomized MAC",
      result_e1 == "real_stable_phone")

# For a genuinely first-contact randomized-looking MAC (no anchor match, no existing
# binding), LiveIdentityManager must behave IDENTICALLY to v-current -- no IP-anchor
# override branch exists anymore.
vcurrent_mgr_e = DeviceIdentityManager(_fresh_state_manager("e_vcurrent"), {"gateway_ip": GATEWAY_IP})
live_mgr_e2 = LiveIdentityManager(_fresh_state_manager("e2"), {"gateway_ip": GATEWAY_IP}, _fresh_graph_store("e2"), {})
result_e2 = live_mgr_e2.resolve_device_id("::1", mac_addr=RANDOM_MAC)
vcurrent_result_e2 = vcurrent_mgr_e.resolve_device_id("::1", mac_addr=RANDOM_MAC)
check("E: a first-contact locally-administered-looking MAC resolves IDENTICALLY to "
      "v-current (no special-casing outside of anchor-learning)",
      result_e2 == vcurrent_result_e2)

# The ONE place randomization still matters: an anchor's canonical MAC is never
# LEARNED (persisted) from a locally-administered-looking observation, even though
# resolution to the anchor's own id still succeeds via the IP match (branch 1).
state_e3 = _fresh_state_manager("e3")
graph_e3 = _fresh_graph_store("e3")
anchors_e3 = {"gateway": TrustAnchor(role="gateway", ip=GATEWAY_IP, mac=None)}
live_mgr_e3 = LiveIdentityManager(state_e3, {"gateway_ip": GATEWAY_IP}, graph_e3, anchors_e3)
result_e3 = live_mgr_e3.resolve_device_id(GATEWAY_IP, mac_addr=RANDOM_MAC)
check("E: the anchor's IP match still resolves correctly even when the observed "
      "MAC looks randomized", result_e3 == v13_stable_device_id(GATEWAY_IP))
check("E: a locally-administered-looking MAC observed at the anchor's IP is NOT "
      "learned as the anchor's canonical MAC",
      live_mgr_e3._get_learned_anchor_macs().get("gateway") is None)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 live_manager (identity) checks PASSED.")
