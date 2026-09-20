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

6. ORDINARY DEVICE MAC/IP HISTORY, DURABLE + QUERYABLE (Release 14, Workstream 3 --
   Documentation/V13_FULL_ARCHITECTURE_SHIFT_PLAN.md; an explicit architecture
   decision, asked and answered by the user rather than defaulted, because the
   identity subsystem has already had 3 real production incidents in this session
   alone). `_refresh_identity_signals()` override: runs the real v1 update
   unchanged via `super()`, then mirrors the MAC/IP just recorded into
   `GraphStore.update_device_metadata()`'s `mac_history`/`known_ips_history`
   dicts (`{value: last_seen_timestamp}`, each capped at a bounded size -- see
   `_mirror_identity_signals()`'s own docstring for exactly why and how). This is
   deliberately NOT wired into the hot `resolve_device_id()` lookup path at
   all -- `state_manager.get_device_id_for_mac()` stays the sole, in-memory,
   sub-millisecond source of truth there, unchanged. The graph side exists ONLY
   so this history becomes durable (survives a restart) and SQL-queryable (a
   real, answerable "show every IP this device has ever used" query), matching
   the middle-ground option chosen over either leaving identity untouched or
   routing the hot path itself through SQLite.

5. GRAPH-AWARE DEVICE MERGE (added a continuation session after Phase 3's initial
   build, once a real audit found it missing): `_merge_orphan_if_fragmented()`
   override, folding the SAME live orphan-merge into the v13 graph via
   `GraphStore.merge_device()` -- audit-preserving (tombstone, never delete,
   `resolve_canonical_device_id()` transparently redirects every later read),
   unlike v1's own `merge_into_canonical()` which DISCARDS the orphan's
   accumulated state entirely. Confirmed via direct investigation this was a
   real, live gap: `GraphStore.merge_device()`/`resolve_canonical_device_id()`
   were fully built (matching schema.sql's own explicitly-stated design goal,
   "a deliberate improvement" over v1's discard-on-merge) but had ZERO callers
   anywhere in the codebase -- every live orphan-merge event updated v1's
   `state/ids_state.json` while the v13 graph stayed completely unaware, so an
   orphan's own evidence/decisions kept accumulating in the graph as a
   permanently separate, never-reunited device forever. Best-effort: a graph
   failure here degrades to "the v1-side merge still happened correctly, only
   the graph-side mirroring didn't," matching every other v13 graph write's own
   fail-safe direction -- never blocks or reverts the real (v1) merge, which is
   the one that actually matters for the live pipeline right now.
"""
import logging
import time
from typing import Any, Dict, Optional

from core.identity import DeviceIdentityManager, stable_device_id as v_current_stable_device_id
from core.state_guard import StateManager
from argus.graph.store import GraphStore
from argus.identity.resolver import (
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

    # Bounded, not unbounded -- the standing Pi-8GB-target constraint applies to
    # every new SQLite write path from day one, not added after an incident (see
    # A14's 43,342-row evidence-duplication incident). A device with a genuinely
    # unstable DHCP lease or a NIC swap history could otherwise grow this without
    # limit; oldest-by-last-seen eviction keeps it a real, bounded improvement
    # over StateManager's own in-memory BoundedSet(max_size=8) for known_ips
    # (a real, documented gap this closes) without becoming its own growth risk.
    _MAX_MAC_HISTORY = 20
    _MAX_IP_HISTORY = 50

    def _mirror_identity_signals(self, device_id: str, mac_addr: str, client_ip: str, now: float) -> None:
        """Best-effort, durable, SQL-queryable mirror of ordinary device MAC/IP
        history -- generalizes the same write-only pattern _learn_anchor_mac()
        already uses for trust anchors, to every device. Deliberately NEVER read
        from on the hot resolve_device_id() path (state_manager's own in-memory
        index stays authoritative there, unchanged, sub-millisecond) -- this
        exists purely so identity history becomes durable/queryable without
        adding any SQLite read/write to the per-cycle identity-resolution hot
        path. Only writes when something GENUINELY NEW is learned (a MAC/IP not
        already recorded for this device) -- writing on every occurrence of an
        already-known value would be pure write amplification for no
        informational gain, and a new MAC/IP is a rare event for any real
        device, so this stays naturally infrequent by construction, not by a
        rate limiter. Known, accepted trade-off: this runs inside
        `identity.py`'s own per-DEVICE lock (`state_manager.lock_device()`), so a
        write here briefly holds that one device's lock -- never a global lock,
        and only on the rare genuinely-new-value path, not the common case."""
        if self._graph_store is None:
            return
        try:
            meta = self._graph_store.get_device_metadata(device_id)
            updates: Dict[str, Any] = {}

            if mac_addr and mac_addr != "unknown":
                mac_history = dict(meta.get("mac_history") or {})
                if mac_addr not in mac_history:
                    mac_history[mac_addr] = now
                    if len(mac_history) > self._MAX_MAC_HISTORY:
                        del mac_history[min(mac_history, key=mac_history.get)]
                    updates["mac_history"] = mac_history

            if client_ip and client_ip != "unknown":
                ip_history = dict(meta.get("known_ips_history") or {})
                if client_ip not in ip_history:
                    ip_history[client_ip] = now
                    if len(ip_history) > self._MAX_IP_HISTORY:
                        del ip_history[min(ip_history, key=ip_history.get)]
                    updates["known_ips_history"] = ip_history

            if updates:
                self._graph_store.update_device_metadata(device_id, updates, timestamp=now)
        except Exception as e:
            LOGGER.warning("Failed to mirror identity signals for %r into the graph: %s", device_id, e)

    def _refresh_identity_signals(self, locked_state: Any, mac_addr: str, client_ip: str,
                                    hostname: str, zeek_fx: Any, overwrite_hostname: bool = True) -> None:
        """Runs the real v1 update unchanged via `super()`, then mirrors the
        MAC/IP just recorded -- see `_mirror_identity_signals()`'s own docstring
        for the full design rationale. A graph failure here never affects the
        real (v1) state update, matching every other v13 graph write's own
        fail-safe direction."""
        super()._refresh_identity_signals(
            locked_state, mac_addr, client_ip, hostname, zeek_fx, overwrite_hostname=overwrite_hostname,
        )
        self._mirror_identity_signals(locked_state.device_id, mac_addr, client_ip, time.time())

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
                return self.state_manager.resolve_merge_redirect(v13_stable_device_id(anchor.ip))

        if mac_addr != "unknown" and not randomized:
            learned_anchor_macs = self._get_learned_anchor_macs()
            for role, anchor in self._trust_anchors.items():
                learned = learned_anchor_macs.get(role) or anchor.mac
                if learned and learned == mac_addr:
                    anchor_id = v13_stable_device_id(anchor.ip) if anchor.ip else _anchor_device_id(role)
                    return self.state_manager.resolve_merge_redirect(anchor_id)

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
        #
        # BUGFIX (identity-merge race, 2026-09-20 handover): every branch reached from
        # here on (and the two anchor branches above) is a pure, state-unaware hash --
        # it has no memory of a device_id it minted before that's since been discarded
        # via merge_into_canonical() (core/state_guard.py). A later per-flow signal miss
        # (e.g. this MAC isn't captured on this specific flow, even though it's known
        # elsewhere for the same device) would otherwise regenerate the exact same dead
        # hash and get_or_create() would silently resurrect a zombie DeviceState under
        # it, stealing this address's future traffic from its real canonical identity.
        # core/identity.py's own resolve_device_id() got the same fix -- this class
        # fully overrides that method rather than delegating to it (see this module's
        # docstring), so the fix has to be applied here too, not inherited.
        return self.state_manager.resolve_merge_redirect(v13_resolve_device_id(
            client_ip, client_mac=mac_addr, hostname=hostname, mac_bindings=mac_bindings,
        ))

    def _merge_orphan_if_fragmented(self, client_ip: str, dev_id: str, ml_registry: Any, fp_engine: Any,
                                      ips_mitigator: Any, evidence_store: Any, metrics_exporter: Any) -> Optional[str]:
        """Runs the real v1 merge unchanged (every side effect -- ml_registry/
        fp_engine/ips_mitigator/evidence_store/metrics_exporter cleanup -- still
        happens exactly as before), then mirrors the SAME merge into the v13
        graph if it actually happened. See this module's own top-of-file item 5
        for the full design rationale."""
        orphan_id = super()._merge_orphan_if_fragmented(
            client_ip, dev_id, ml_registry, fp_engine, ips_mitigator, evidence_store, metrics_exporter,
        )
        if orphan_id is None or self._graph_store is None:
            return orphan_id
        try:
            self._graph_store.merge_device(orphan_id, dev_id)
        except Exception as e:
            LOGGER.warning(
                "Failed to mirror identity merge (orphan=%s -> canonical=%s) into the v13 "
                "graph -- the real (v1) merge above already succeeded and is unaffected: %s",
                orphan_id, dev_id, e,
            )
        return orphan_id
