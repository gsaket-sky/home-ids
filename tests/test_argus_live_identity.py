"""
Standalone runtime test for src/v13/identity/live_manager.py -- the actual swap-in
for `.94`'s live DeviceIdentityManager (v13 full-architecture plan, Phase 3).

Imports core.identity (real v-current code, real deps like `requests`/`manuf`) --
run via the venv python, not bare python3:
`.venv/Scripts/python.exe tests/test_argus_live_identity.py`

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
  F. Graph-aware device merge (continuation session): _merge_orphan_if_fragmented()
     now mirrors a live orphan-merge into the v13 graph (GraphStore.merge_device(),
     audit-preserving) in addition to v1's own state/ids_state.json -- the real v1
     merge is unconditional/load-bearing and never gated on graph availability or
     a graph-side failure (graph_store=None and a graph write exception are both
     exercised as real fail-safe cases, not just no-crash smoke tests).
  G. Release 14, Workstream 3 (item 6 in live_manager.py's own docstring):
     _refresh_identity_signals() now ALSO mirrors ordinary device MAC/IP history
     into the graph's bounded mac_history/known_ips_history -- write-only (never
     read on the hot resolve_device_id() path), only on a genuinely NEW value
     (no write amplification for an already-known MAC/IP), bounded eviction, and
     the same fail-safe/None-graph-store guarantees as every other override here.
  H. HANDOVER FIX (2026-09-20): resolve_device_id()'s pure hash branches have no
     memory of a device_id they minted before that's since been discarded via
     merge_into_canonical() -- a later per-flow signal miss (e.g. a MAC not
     captured on this specific flow) can regenerate the exact same dead hash and
     silently resurrect a zombie DeviceState under it. Fixed via
     StateManager.resolve_merge_redirect(), applied at every return point in THIS
     class's own resolve_device_id() override (core/identity.py's version got the
     same fix independently -- this class doesn't delegate to it).
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
from argus.graph.store import GraphStore  # noqa: E402
from argus.identity.live_manager import LiveIdentityManager  # noqa: E402
from argus.identity.resolver import TrustAnchor, stable_device_id as v13_stable_device_id  # noqa: E402
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
check("A: _release_stale_isolation_if_merged is inherited unchanged",
      LiveIdentityManager._release_stale_isolation_if_merged is DeviceIdentityManager._release_stale_isolation_if_merged)
check("A: resolve_device_id IS overridden (Phase 3's original deliberate change)",
      LiveIdentityManager.resolve_device_id is not DeviceIdentityManager.resolve_device_id)
check("A: _merge_orphan_if_fragmented IS ALSO overridden now (continuation-session "
      "addition, item 5 in this module's own docstring) -- graph-aware merge "
      "mirroring, not the original Phase 3 scope",
      LiveIdentityManager._merge_orphan_if_fragmented is not DeviceIdentityManager._merge_orphan_if_fragmented)
check("A: _refresh_identity_signals IS ALSO overridden now (Release 14 Workstream 3, "
      "item 6) -- ordinary device MAC/IP history mirroring, not the original Phase 3 scope",
      LiveIdentityManager._refresh_identity_signals is not DeviceIdentityManager._refresh_identity_signals)


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


# --- C2 (Phase 11, 2026-09-27): parity between LiveIdentityManager's own inline
# workaround and resolver.py's now-FIXED pure _anchor_device_id() ---
#
# Before this phase, resolver.py's _anchor_device_id() always used the role-based
# hash, a DIFFERENT value than what LiveIdentityManager actually returns for an
# anchor with a configured ip -- LiveIdentityManager never called the broken pure
# function for these branches at all (see its own resolve_device_id() docstring),
# so nothing in production was affected, but any FUTURE direct caller of the pure
# function would have silently diverged from what the live manager actually does.
# This asserts the fixed pure function now agrees byte-for-byte with the live
# manager's own real behavior, for both an ip-configured anchor and a role-only one.
from argus.identity.resolver import _anchor_device_id  # noqa: E402

check("C2: resolver.py's fixed pure _anchor_device_id() matches LiveIdentityManager's "
      "own real gateway-anchor id exactly -- the parity this fix is FOR",
      _anchor_device_id(two_anchors["gateway"]) == gw_id)
check("C2: same parity for the this_host anchor",
      _anchor_device_id(two_anchors["this_host"]) == host_id)

role_only_anchor_c2 = TrustAnchor(role="printer", ip=None, mac="cc:dd:ee:00:00:09")
check("C2: a role-only anchor (no ip) still uses the role-based hash in the pure "
      "function -- unaffected by this fix, since there's no ip to be continuity-"
      "safe WITH in that case",
      _anchor_device_id(role_only_anchor_c2) == v13_stable_device_id("anchor:printer"))


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


# --- F. Graph-aware device merge (continuation session, item 5 in live_manager.py's
# own docstring): _merge_orphan_if_fragmented() now ALSO mirrors the merge into the
# v13 graph, not just v1's state/ids_state.json ---

state_f = _fresh_state_manager("f")
graph_f = _fresh_graph_store("f")
live_mgr_f = LiveIdentityManager(state_f, {"gateway_ip": GATEWAY_IP}, graph_f, {})

# Simulates the real fragmentation scenario process_dns_identities() hits: an IP was
# already tracked under one device_id (the orphan), before a later cycle resolves
# a DIFFERENT, richer canonical device_id for that same IP.
state_f.get_or_create(device_id="orphan_f", client_ip="192.168.77.201", hostname="unknown")
state_f.get_or_create(device_id="canonical_f", client_ip="192.168.77.202", hostname="realhost")

returned_orphan_id = live_mgr_f._merge_orphan_if_fragmented(
    "192.168.77.201", "canonical_f", ml_registry=None, familiarity=None,
    ips_mitigator=None, evidence_store=None, metrics_exporter=None,
)
check("F: _merge_orphan_if_fragmented returns the orphan_id that was actually "
      "merged (previously returned None always, discarded by every caller)",
      returned_orphan_id == "orphan_f")
check("F: the REAL v1-side merge still happened exactly as before (orphan_f no "
      "longer resolves to itself, the IP now resolves to canonical_f)",
      state_f.get_device_id_for_ip("192.168.77.201") == "canonical_f")
check("F: the SAME merge was mirrored into the v13 graph -- resolve_canonical_device_id "
      "now redirects the orphan to the canonical id, audit-preservingly (never deleted)",
      graph_f.resolve_canonical_device_id("orphan_f") == "canonical_f")
check("F: the graph 'merged_into' edge was actually created, not just the devices "
      "table column (the audit trail schema.sql's own design calls for)",
      len(graph_f.get_edges(relation="merged_into", src_kind="device", src_id="orphan_f",
                              dst_kind="device", dst_id="canonical_f")) == 1)

# --- F: no orphan to merge -- a clean no-op, graph never touched ---
state_f2 = _fresh_state_manager("f2")
graph_f2 = _fresh_graph_store("f2")
live_mgr_f2 = LiveIdentityManager(state_f2, {"gateway_ip": GATEWAY_IP}, graph_f2, {})
state_f2.get_or_create(device_id="only_device_f2", client_ip="192.168.77.203", hostname="unknown")
result_f2 = live_mgr_f2._merge_orphan_if_fragmented(
    "192.168.77.203", "only_device_f2", ml_registry=None, familiarity=None,
    ips_mitigator=None, evidence_store=None, metrics_exporter=None,
)
check("F: no merge needed (dev_id already matches the tracked orphan_id) returns "
      "None, same as v1's own no-op case", result_f2 is None)
check("F: the graph gets zero 'merged_into' edges when nothing actually merged",
      len(graph_f2.get_edges(relation="merged_into")) == 0)

# --- F: graph_store=None (matches every other v13 graph consumer's own optional/
# graceful-degradation convention) -- the real v1 merge still happens ---
state_f3 = _fresh_state_manager("f3")
live_mgr_f3 = LiveIdentityManager(state_f3, {"gateway_ip": GATEWAY_IP}, None, {})
state_f3.get_or_create(device_id="orphan_f3", client_ip="192.168.77.204", hostname="unknown")
state_f3.get_or_create(device_id="canonical_f3", client_ip="192.168.77.205", hostname="realhost")
result_f3 = live_mgr_f3._merge_orphan_if_fragmented(
    "192.168.77.204", "canonical_f3", ml_registry=None, familiarity=None,
    ips_mitigator=None, evidence_store=None, metrics_exporter=None,
)
check("F: with graph_store=None, the v1-side merge still fully succeeds (the "
      "real, load-bearing merge is never gated on graph availability)",
      result_f3 == "orphan_f3"
      and state_f3.get_device_id_for_ip("192.168.77.204") == "canonical_f3")

# --- F: a graph-side failure never affects the real (v1) merge -- fail-safe ---
state_f4 = _fresh_state_manager("f4")


class _ExplodingGraphStore:
    def merge_device(self, orphan_id, canonical_id):
        raise RuntimeError("simulated graph write failure")


live_mgr_f4 = LiveIdentityManager(state_f4, {"gateway_ip": GATEWAY_IP}, _ExplodingGraphStore(), {})
state_f4.get_or_create(device_id="orphan_f4", client_ip="192.168.77.206", hostname="unknown")
state_f4.get_or_create(device_id="canonical_f4", client_ip="192.168.77.207", hostname="realhost")
result_f4 = live_mgr_f4._merge_orphan_if_fragmented(
    "192.168.77.206", "canonical_f4", ml_registry=None, familiarity=None,
    ips_mitigator=None, evidence_store=None, metrics_exporter=None,
)
check("F: FAIL-SAFE -- a graph_store.merge_device() failure never raises out to "
      "the caller, and the real v1 merge (already committed by this point) is "
      "completely unaffected",
      result_f4 == "orphan_f4"
      and state_f4.get_device_id_for_ip("192.168.77.206") == "canonical_f4")


# --- G. Release 14, Workstream 3: ordinary device MAC/IP history mirroring ---

state_g = _fresh_state_manager("g")
graph_g = _fresh_graph_store("g")
live_mgr_g = LiveIdentityManager(state_g, {"gateway_ip": GATEWAY_IP}, graph_g, {})
dev_g = state_g.get_or_create(device_id="dev_g", client_ip="192.168.77.50", hostname="host_g")

live_mgr_g._refresh_identity_signals(dev_g, "aa:bb:cc:dd:ee:01", "192.168.77.50", "host_g", None)
meta_g = graph_g.get_device_metadata("dev_g")
check("G: a genuinely new MAC is mirrored into the graph's mac_history",
      "aa:bb:cc:dd:ee:01" in meta_g.get("mac_history", {}))
check("G: a genuinely new IP is mirrored into the graph's known_ips_history",
      "192.168.77.50" in meta_g.get("known_ips_history", {}))
check("G: the REAL v1-side state was also updated exactly as before (this is an "
      "additive override, not a replacement)",
      dev_g.mac_address == "aa:bb:cc:dd:ee:01" and "192.168.77.50" in dev_g.known_ips)

# --- G: no write amplification -- the SAME MAC/IP again does not change the timestamp ---
first_ts = meta_g["mac_history"]["aa:bb:cc:dd:ee:01"]
live_mgr_g._refresh_identity_signals(dev_g, "aa:bb:cc:dd:ee:01", "192.168.77.50", "host_g", None)
meta_g_again = graph_g.get_device_metadata("dev_g")
check("G: calling again with the SAME already-known MAC/IP does not rewrite the "
      "timestamp (no write amplification for an already-known value)",
      meta_g_again["mac_history"]["aa:bb:cc:dd:ee:01"] == first_ts)

# --- G: bounded eviction -- oldest entry evicted once the cap is exceeded ---
state_g2 = _fresh_state_manager("g2")
graph_g2 = _fresh_graph_store("g2")
live_mgr_g2 = LiveIdentityManager(state_g2, {"gateway_ip": GATEWAY_IP}, graph_g2, {})
dev_g2 = state_g2.get_or_create(device_id="dev_g2", client_ip="10.0.0.1", hostname="host_g2")
for i in range(live_mgr_g2._MAX_MAC_HISTORY + 5):
    live_mgr_g2._refresh_identity_signals(
        dev_g2, f"aa:bb:cc:dd:ee:{i:02x}", "10.0.0.1", "host_g2", None,
    )
meta_g2 = graph_g2.get_device_metadata("dev_g2")
check("G: mac_history never grows past its documented cap",
      len(meta_g2["mac_history"]) == live_mgr_g2._MAX_MAC_HISTORY)
check("G: the OLDEST mac was evicted, the most recent ones survive",
      "aa:bb:cc:dd:ee:00" not in meta_g2["mac_history"]
      and f"aa:bb:cc:dd:ee:{(live_mgr_g2._MAX_MAC_HISTORY + 4):02x}" in meta_g2["mac_history"])

# --- G: graph_store=None -- no-op, real v1 update still happens ---
state_g3 = _fresh_state_manager("g3")
live_mgr_g3 = LiveIdentityManager(state_g3, {"gateway_ip": GATEWAY_IP}, None, {})
dev_g3 = state_g3.get_or_create(device_id="dev_g3", client_ip="10.0.0.2", hostname="host_g3")
live_mgr_g3._refresh_identity_signals(dev_g3, "aa:bb:cc:dd:ee:99", "10.0.0.2", "host_g3", None)
check("G: with graph_store=None, the real v1 update still fully succeeds",
      dev_g3.mac_address == "aa:bb:cc:dd:ee:99" and "10.0.0.2" in dev_g3.known_ips)

# --- G: a graph-side failure never affects the real (v1) update -- fail-safe ---
state_g4 = _fresh_state_manager("g4")


class _ExplodingMetadataStore:
    def get_device_metadata(self, device_id):
        raise RuntimeError("simulated graph read failure")


live_mgr_g4 = LiveIdentityManager(state_g4, {"gateway_ip": GATEWAY_IP}, _ExplodingMetadataStore(), {})
dev_g4 = state_g4.get_or_create(device_id="dev_g4", client_ip="10.0.0.3", hostname="host_g4")
live_mgr_g4._refresh_identity_signals(dev_g4, "aa:bb:cc:dd:ee:88", "10.0.0.3", "host_g4", None)
check("G: FAIL-SAFE -- a graph read/write failure never raises out to the caller, "
      "and the real v1 update is completely unaffected",
      dev_g4.mac_address == "aa:bb:cc:dd:ee:88" and "10.0.0.3" in dev_g4.known_ips)

# --- H. HANDOVER FIX (2026-09-20): the zombie-resurrection identity-merge race, this
# time for the ACTUAL live/production resolve_device_id() override (this class fully
# overrides that method rather than delegating to core.identity.DeviceIdentityManager's
# version -- see this module's own docstring -- so core/identity.py's own fix, already
# covered by tests/test_phase39_retroactive_identity_merge.py's Section G, does NOT
# automatically cover this class; it needed its own, separate fix, applied at every
# return point in live_manager.py's resolve_device_id() override). ---
state_h = _fresh_state_manager("h")
live_mgr_h = LiveIdentityManager(state_h, {}, None, {})
ORPHAN_IP_H = "192.168.77.210"
CANON_IP_H = "192.168.77.211"
MAC_H = "aa:bb:cc:dd:ee:77"

orphan_id_h = live_mgr_h.resolve_device_id(ORPHAN_IP_H, mac_addr=None, hostname="unknown")
state_h.get_or_create(device_id=orphan_id_h, client_ip=ORPHAN_IP_H, hostname="unknown")
canonical_id_h = v_current_stable_device_id(CANON_IP_H)
canon_state_h = state_h.get_or_create(device_id=canonical_id_h, client_ip=CANON_IP_H, hostname="realhost")
state_h.bind_mac(MAC_H, canonical_id_h)

merged_h = state_h.merge_into_canonical(orphan_id_h, canonical_id_h)
check("H: setup -- the orphan merges into the canonical normally", merged_h)
check("H: setup -- the orphan no longer exists as a separate tracked device",
      not state_h.has_device(orphan_id_h))

# The orphan's own address is resolved again with NO mac_addr this time (a per-flow
# capture miss) -- v13_resolve_device_id()'s pure IP-anchor branch would, on its own,
# regenerate the exact same dead orphan_id_h hash.
resolved_after_merge_h = live_mgr_h.resolve_device_id(ORPHAN_IP_H, mac_addr=None, hostname="unknown")
check("H: THE FIX -- re-resolving the orphan's OWN address after it's been merged "
      "away (with no MAC this time) returns the LIVE canonical id, not a resurrected "
      "zombie -- this is the code path actually running on .94, not just the "
      "core/identity.py fallback",
      resolved_after_merge_h == canonical_id_h,
      f"got={resolved_after_merge_h} want={canonical_id_h}")
check("H: THE FIX -- no zombie DeviceState was created under the dead orphan id",
      not state_h.has_device(orphan_id_h))

# --- I. IPv6 address-rotation merge correctness (2026-09-20 follow-up request):
# SLAAC privacy addresses rotate periodically (commonly ~daily) -- each rotation's
# first few packets can arrive before Zeek's mac-logging catches up for the NEW
# address, cold-starting a fresh IP-anchored orphan exactly like the IPv4 case
# already covered above, just repeated multiple times over a device's lifetime.
# Confirms every rotation's orphan correctly merges into the SAME accumulating
# canonical identity -- both in v1's own state (state_i) and mirrored into the
# v13 graph (graph_i) -- with zero zombies left behind for ANY of them, not just
# the first. ---
state_i = _fresh_state_manager("i")
graph_i = _fresh_graph_store("i")
live_mgr_i = LiveIdentityManager(state_i, {}, graph_i, {})
MAC_I = "aa:bb:cc:dd:ee:66"
CANON_IP_I = "192.168.77.220"
canonical_id_i = v_current_stable_device_id(CANON_IP_I)
state_i.get_or_create(device_id=canonical_id_i, client_ip=CANON_IP_I, hostname="dual-stack-host")
state_i.bind_mac(MAC_I, canonical_id_i)

IPV6_ROTATIONS = [
    "2001:db8:1::aaaa:bbbb:cccc:0001",
    "2001:db8:1::aaaa:bbbb:cccc:0002",
    "2001:db8:1::aaaa:bbbb:cccc:0003",
]
orphan_ids_i = []
for rotation_ip in IPV6_ROTATIONS:
    # Cold start: this rotation's address hasn't been seen before, and (matching
    # the real gap) its MAC isn't resolvable on this specific flow yet.
    orphan_id = live_mgr_i.resolve_device_id(rotation_ip, mac_addr=None, hostname="unknown")
    state_i.get_or_create(device_id=orphan_id, client_ip=rotation_ip, hostname="unknown")
    orphan_ids_i.append(orphan_id)
    # A moment later, the MAC becomes known for this SAME address (mac-logging
    # catches up) -- process_zeek_identities() would compute dev_id=canonical_id_i
    # via the MAC-first branch and call this exact method before get_or_create().
    merged_id = live_mgr_i._merge_orphan_if_fragmented(
        rotation_ip, canonical_id_i, ml_registry=None, familiarity=None,
        ips_mitigator=None, evidence_store=None, metrics_exporter=None,
    )
    check(f"I: rotation {rotation_ip} -- the orphan created for THIS address is the "
          "one actually merged", merged_id == orphan_id, f"got={merged_id}")

check("I: after 3 separate IPv6 rotations, ALL 3 orphans are gone -- not just the "
      "first one, every single rotation merges cleanly",
      all(not state_i.has_device(oid) for oid in orphan_ids_i),
      f"still tracked: {[oid for oid in orphan_ids_i if state_i.has_device(oid)]}")
check("I: exactly ONE DeviceState survives for this physical device, regardless of "
      "how many times its IPv6 address rotated",
      state_i.get_all_device_ids() == [canonical_id_i], f"got={state_i.get_all_device_ids()}")

canonical_known_ips_i = set(state_i.get_or_create(canonical_id_i, CANON_IP_I, "unknown").known_ips.to_list())
check("I: the canonical identity's known_ips covers every rotation's address",
      set(IPV6_ROTATIONS).issubset(canonical_known_ips_i), f"known_ips={canonical_known_ips_i}")

for rotation_ip, orphan_id in zip(IPV6_ROTATIONS, orphan_ids_i):
    check(f"I: the v13 graph also resolves rotation {rotation_ip}'s orphan id to "
          "the SAME canonical id -- the graph-side mirror kept pace with every "
          "single rotation, not just the first",
          graph_i.resolve_canonical_device_id(orphan_id) == canonical_id_i,
          f"got={graph_i.resolve_canonical_device_id(orphan_id)}")

# THE ACTUAL BUG-A SCENARIO, now for IPv6: the FIRST rotation's address is seen
# again after its own merge (e.g. a brief return to an old privacy address is not
# how SLAAC works, but a delayed/retransmitted packet using it IS realistic),
# again with a MAC-capture miss -- must resolve to canonical, never resurrect.
resolved_old_rotation = live_mgr_i.resolve_device_id(IPV6_ROTATIONS[0], mac_addr=None, hostname="unknown")
check("I: THE FIX applies across IPv6 rotations too -- re-resolving the FIRST "
      "rotation's address after ITS merge (with a MAC-capture miss) returns the "
      "live canonical id, not a resurrected zombie",
      resolved_old_rotation == canonical_id_i, f"got={resolved_old_rotation}")
check("I: still no zombie under the first rotation's orphan id",
      not state_i.has_device(orphan_ids_i[0]))


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 live_manager (identity) checks PASSED.")
