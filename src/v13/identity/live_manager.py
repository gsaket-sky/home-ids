"""
live_manager.py - the actual swap-in for `.94`'s live `DeviceIdentityManager`
(v13 full-architecture plan, Phase 3).

Real investigation before writing this (not assumed): `core/identity.py`'s
`DeviceIdentityManager` is NOT just `resolve_device_id()` -- `process_dns_identities()`/
`process_zeek_identities()` also do Fritz!Box hosts-webhook enrichment, orphan-merge
detection/cleanup (notifying `ml_registry`/`fp_engine`/`ips_mitigator`/`evidence_store`/
`metrics_exporter`), and `device_type` inference, all sharing the same `StateManager`
and internal locks. None of that needed reinventing -- it's real, already-correct,
already-tested machinery, and reinventing it in parallel would risk silently dropping a
real side effect. So `LiveIdentityManager` **subclasses** `DeviceIdentityManager` and
overrides ONLY `resolve_device_id()` -- everything else (Fritz!Box polling, the full
per-row orchestration, device_type inference, orphan-merge cleanup) is inherited
unchanged, exactly like the fast-cutover kept v-current's real detectors/mitigation/
alerting untouched and only swapped the decision computation itself.

What the override actually changes, concretely:
1. Generalizes the single hardcoded `gateway_ip` special case to `self._trust_anchors`
   (Phase 2's config loader) -- an arbitrary list of named anchors (gateway, NAS, a
   second AP, ...), not just one.
2. Persists each anchor's learned MAC via `GraphStore.update_device_metadata()`
   instead of v-current's own single in-memory `_gateway_mac` field -- survives a
   `soc.service` restart instead of needing to relearn it from the next cycle that
   happens to see the anchor with a MAC attached.
3. Real MAC-randomization detection (`resolver.is_locally_administered_mac()`) --
   confirmed via direct investigation that no such check existed anywhere in this
   codebase before Phase 3. Scoped narrowly to trust-anchor MAC *learning* only
   (never permanently record a rotating-looking MAC as an anchor's canonical MAC).
   It deliberately does NOT gate the general mac_bindings lookup or MAC-based
   resolution for ordinary devices: a locally-administered bit does not mean a MAC
   is rotating right now -- modern iOS/Android "private Wi-Fi address" MACs are
   randomized per-SSID but stable across reconnects to the same network, so on a
   single fixed home network this bit is set on most modern phones' otherwise
   perfectly stable MACs. An earlier version of this file excluded these from
   mac_bindings entirely, which broke exactly the continuity it was meant to
   protect (found live in production within 90 seconds of first deploying, fixed
   before this was allowed to run unattended -- see the dependency map).
4. `mac_bindings` (branch 3, "does this MAC already resolve to a known device_id")
   is NOT reinvented -- reuses `self.state_manager.get_device_id_for_mac()` directly,
   v-current's own real, already-persisted-to-disk mechanism, unchanged.

Deliberately NOT covered by Phase 3 (investigated and found to live elsewhere, not in
identity resolution at all): ARP-spoof-vs-benign-MAC-rotation disambiguation lives in
`pipeline.py`'s hard-stop evidence-creation site (a detector/evidence concern, reading
`ZeekFeatureExtractor.layer2_spoofs`) -- see that fix's own separate module. IPv6
address-family display labeling lives in `pipeline.py`'s alert-payload construction --
see that fix's own separate change.
"""
import logging
from typing import Any, Dict, Optional

from core.identity import DeviceIdentityManager, stable_device_id as v_current_stable_device_id
from core.state_guard import StateManager
from v13.graph.store import GraphStore
from v13.identity.resolver import (
    resolve_device_id as v13_resolve_device_id,
    stable_device_id as v13_stable_device_id,
    is_locally_administered_mac,
    TrustAnchor,
)

LOGGER = logging.getLogger("home_ids.v13_live_identity")

# v-current's and v13's stable_device_id() are independently-maintained but confirmed
# byte-for-byte identical formulas (both docstrings say so explicitly) -- asserted once
# here at import time rather than trusted silently, since a future edit to either file
# drifting out of sync would otherwise fail invisibly (every device_id this manager
# returns would just be internally self-consistent but wrong relative to v-current's
# own historical device_ids, a very hard bug to notice after the fact).
assert v_current_stable_device_id("assert-canary") == v13_stable_device_id("assert-canary"), (
    "core.identity.stable_device_id and v13.identity.resolver.stable_device_id have "
    "drifted apart -- LiveIdentityManager's device_ids would silently stop matching "
    "v-current's own historical ones."
)


def _anchor_device_id(role: str) -> str:
    """Matches v13.identity.resolver's own private _anchor_device_id() formula exactly
    (duplicated rather than importing a private name, matching resolver.py's own stated
    preference for small stable formulas being duplicated over a live import
    dependency)."""
    return v13_stable_device_id(f"anchor:{role}")


class LiveIdentityManager(DeviceIdentityManager):
    def __init__(self, state_manager: StateManager, config: Any,
                  graph_store: Optional[GraphStore], trust_anchors: Dict[str, TrustAnchor]):
        super().__init__(state_manager, config)
        self._graph_store = graph_store
        self._trust_anchors = trust_anchors or {}

    def _get_learned_anchor_macs(self) -> Dict[str, str]:
        """Best-effort: a graph failure here degrades to 'no learned anchor MACs yet
        this call' (branch 2 simply won't match), never raises -- matches every other
        v13 graph-read's fail-safe direction."""
        if self._graph_store is None or not self._trust_anchors:
            return {}
        result = {}
        try:
            for role in self._trust_anchors:
                meta = self._graph_store.get_device_metadata(_anchor_device_id(role))
                learned = meta.get("learned_mac")
                if learned:
                    result[role] = learned
        except Exception as e:
            LOGGER.warning("Failed to read learned anchor MACs from graph: %s", e)
        return result

    def _learn_anchor_mac(self, role: str, mac: str) -> None:
        """Best-effort: never raises -- a failure here just means this specific
        learning event isn't persisted (the SAME mac will likely be re-learned on a
        later cycle that sees this anchor again, so this is self-healing, not a
        one-shot opportunity)."""
        if self._graph_store is None:
            return
        try:
            self._graph_store.update_device_metadata(
                _anchor_device_id(role), {"learned_mac": mac, "role": role},
            )
        except Exception as e:
            LOGGER.warning("Failed to persist learned MAC for anchor %r: %s", role, e)

    def resolve_device_id(self, client_ip: str, mac_addr: Optional[str] = None,
                            hostname: Optional[str] = None) -> str:
        mac_addr = mac_addr or "unknown"
        randomized = mac_addr != "unknown" and is_locally_administered_mac(mac_addr)

        # Branches 1 & 2 (trust-anchor identity) are handled HERE, not delegated to
        # v13_resolve_device_id()'s own branch-1/2 logic -- a real bug found by this
        # phase's own parity test, not guessed: resolver.py's `_anchor_device_id()`
        # returns a ROLE-based hash (stable_device_id(f"anchor:{role}")), which is a
        # DIFFERENT value than v-current's real historical formula for its one
        # existing anchor (gateway_ip): stable_device_id(gateway_ip) itself, the IP
        # string. Using resolver.py's own formula here would have silently reset the
        # gateway's ENTIRE historical baseline/evidence/alert trail (a brand-new
        # device_id) the moment this manager went live. For an anchor WITH a
        # configured ip, this uses v-current's exact formula for full migration
        # continuity; a role-only anchor (no ip configured, a real but rare case)
        # has no v-current-compatible formula to match, so it falls back to the
        # role-based id -- there's nothing to be compatible WITH in that case anyway.
        for role, anchor in self._trust_anchors.items():
            if anchor.ip and anchor.ip == client_ip:
                if mac_addr != "unknown" and not randomized:
                    self._learn_anchor_mac(role, mac_addr)
                return v13_stable_device_id(anchor.ip)

        if mac_addr != "unknown" and not randomized:
            learned_anchor_macs = self._get_learned_anchor_macs()
            for role, anchor in self._trust_anchors.items():
                learned = learned_anchor_macs.get(role) or anchor.mac
                if learned and learned == mac_addr:
                    return v13_stable_device_id(anchor.ip) if anchor.ip else _anchor_device_id(role)

        # Branch 3 (mac_bindings): reuses state_manager's own real, already-persisted
        # MAC->device_id index directly -- not reinvented. Checked regardless of
        # `randomized`: a locally-administered bit does NOT mean the MAC is actually
        # rotating right now -- modern iOS/Android "private Wi-Fi address" MACs are
        # randomized PER-SSID but STABLE across reconnects to the SAME network, so on
        # a single fixed home network this bit is set on most modern phones' otherwise
        # perfectly stable MACs. A prior version of this method excluded these from
        # the lookup entirely, which discarded the real persisted binding and forced
        # every such phone through the IP-based cold-start branch on every call --
        # fragmenting its identity every time its IP changed, exactly the failure this
        # method exists to prevent. Found live in production (55 vs. 51 devices within
        # 90 seconds of this manager going live, traced to this exact line) before
        # this comment was corrected -- see the dependency map entry for this incident.
        mac_bindings = {}
        if mac_addr != "unknown":
            existing = self.state_manager.get_device_id_for_mac(mac_addr)
            if existing:
                mac_bindings[mac_addr] = existing

        # Delegate the remaining branches (trackable IP / hostname / MAC fallback /
        # raw IP) to the pure function -- trust_anchors is deliberately omitted here
        # since 1/2 are already fully handled above with the v-current-compatible
        # formula; letting the pure function re-match them with its own role-based
        # formula would silently undo that.
        return v13_resolve_device_id(
            client_ip, client_mac=mac_addr, hostname=hostname, mac_bindings=mac_bindings,
        )
