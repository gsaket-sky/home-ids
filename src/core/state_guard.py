"""
state_guard.py - Thread-Safe Device State Guard & Persistence Manager.

Guarantees thread-safe access to physical device state matrices across parallel
event loops, async ML retrains, and background serialization routines.

RECENT FIXES:
- ADDED (LOGGING): Debug events tracked at lock acquisitions, migrations, and flushes.
"""

import hashlib
import json
import logging
import threading
import time
import copy
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional, Dict, List, Any

from core import state_store
from core.state import DeviceState
from core.device_matching import (
    dhcp_fingerprint_match,
    ja4_overlap,
    hostname_corroborates,
    match_confidence,
    MIN_CANDIDATE_CONFIDENCE,
    AUTO_MERGE_CONFIDENCE,
)
from metrics import (
    transfer_learning_seeds_total,
    identity_merges_total,
    identity_reidentify_migrations_total,
    identity_reidentify_ambiguous_total,
)

LOGGER = logging.getLogger("home_ids.state_guard")


class StateManager:
    # Cap for _merge_redirects (see __init__'s comment) -- LRU-evicted like _states'
    # own max_devices capacity guard, just a separate, much smaller bound since merge
    # events track device churn, not per-packet/per-evidence volume.
    _MAX_MERGE_REDIRECTS = 5000

    def __init__(self, state_path: str = "state/ids_state.json", max_devices: int = 5000,
                  graph_store: Optional[Any] = None):
        self.state_path = Path(state_path)
        self.max_devices = max_devices
        # v13 full-architecture plan, device-state unification: OPTIONAL write-only
        # graph mirror target for flush_to_disk()'s own cold-field snapshot -- see
        # _mirror_graph_metadata()'s docstring. None (the default, and every
        # pre-existing caller/test) means flush_to_disk() behaves EXACTLY as before
        # this param existed.
        self._graph_store = graph_store
        self._states: OrderedDict[str, DeviceState] = OrderedDict()
        # AUDIT FIX #14: Added missing router_isolated_devices / operator_released_devices defaults
        self._ips_state: Dict[str, Any] = {
            "blocked_domains": {},
            "isolated_macs": [],
            "retry_queue": {},
            "dead_letter": {},
            "tarpit_targets": {},
            "router_isolated_devices": {},
            "operator_released_devices": {},
            "last_sync_timestamp": 0.0,
        }
        self._global_lock = threading.RLock()
        # AUDIT FIX #7: Reverse IP → device_id index for O(1) lookups elsewhere in this file.
        self._ip_to_device_id: Dict[str, str] = {}
        # PHASE 3 (closed-loop autonomous actions): revocable-action ledger. Records
        # autonomous actions (currently: immunize_domain) that a human can undo with a
        # one-tap Telegram [Revoke] button. Same persistence pattern as _ips_state —
        # rides along with the existing flush_to_disk/load_from_disk machinery.
        self._action_ledger: Dict[str, Dict[str, Any]] = {}
        # A2 (2026-10-01): the ledger is ~89% of ids_state.json on .94 (1,344 published-alert entries carrying full
        # alert payloads, 5.2 of 5.8 MB) and re-encoding all of it on every flush was one of the engine's largest
        # GIL costs. Entries are written once and only change on revoke, so each entry's JSON is cached by
        # action_id; every mutation drops the affected key (or the whole cache when the ledger is replaced), and a
        # flush encodes only the entries it has not seen before.
        self._ledger_entry_json: Dict[str, str] = {}
        self.flushes_skipped_unchanged = 0
        # Flash wear (checklist §K): state lives in SQLite rows (core/state_store.py); this remembers a digest of every
        # row as it is on disk, so a flush writes only rows whose JSON changed. _ledger_dirty lists the ledger entries
        # (re-)encoded since the last flush -- the only ones that can differ from disk.
        self._disk_digest: Dict[str, Dict[str, bytes]] = {"devices": {}, "ledger": {}, "kv": {}}
        self._ledger_dirty: set = set()
        self._flush_lock = threading.Lock()
        self._legacy_json_pending = False
        self.rows_written_last_flush = 0
        # PHASE 6 (cross-address-family identity correlation): MAC address -> canonical
        # device_id. A MAC address is protocol-family-agnostic (captured at L2), unlike
        # `client_ip`-anchored device_id resolution, which was blind to the fact that the
        # same physical device's IPv4 and IPv6 traffic are genuinely the same device. When
        # a MAC is known for a NEW packet, identity.py checks this index BEFORE computing
        # a fresh IP-anchored device_id, so all of a device's address families unify into
        # one DeviceState instead of each cold-starting its own permanently-separate profile.
        self._mac_to_device_id: Dict[str, str] = {}
        # PHASE 21D: consume-once side channel for the "ambiguous re-identification
        # candidate" reactive-capture trigger (pipeline.py). A candidate strong enough
        # to log about but not strong enough to clear the actual merge bar used for a
        # given get_or_create() call is genuinely ambiguous -- fresh JA4/DHCP data from
        # a capture burst can resolve it next time instead of it staying stuck below
        # the merge bar indefinitely. Not returned from get_or_create() itself (that
        # would mean changing its return type, used by many call sites) -- set here,
        # popped once by pop_last_reidentify_ambiguous() right after the call that
        # produced it, so a stale value can never be misread on a later, unrelated call.
        self._last_reidentify_ambiguous: Optional[Dict[str, Any]] = None
        # BUGFIX (dead-code audit): consume-once side channel for a re-identify MERGE's
        # now-stale isolation identifiers, same pattern as _last_reidentify_ambiguous just
        # above. IPSMitigator.unisolate_all() existed with zero callers anywhere -- a
        # device isolated under an old MAC/IP that then rotated identity (re-identified as
        # a MAC/DHCP rotation of a known device, see get_or_create()'s matched_old_id
        # branch) had no code path ever releasing the stale isolation bookkeeping tied to
        # its old identifiers. Not called directly from inside get_or_create() itself:
        # unisolate_all() can make a real outbound HTTP call to the router, and
        # get_or_create() runs its entire body under self._global_lock -- holding that
        # lock across a network call would stall every other thread needing StateManager
        # for the duration of the request. Set here, popped once by
        # pop_last_migrated_isolation_target() right after the get_or_create() call that
        # produced it, entirely outside any lock.
        self._last_migrated_isolation_target: Optional[Dict[str, str]] = None
        # Consume-once side channel for a RETROACTIVE ORPHAN MERGE's cleanup info, same
        # pattern as the two channels above. merge_into_canonical() (device-identity
        # fragmentation fix) discards an orphan device_id's own state once its MAC/IP is
        # discovered to already belong to a richer canonical identity -- callers with an
        # evidence store / metrics exporter need the orphan's (device_id, hostname,
        # device_type) to purge its now-stale evidence/metric rows. Kept separate from
        # _last_migrated_isolation_target (which only carries mac/ip) rather than widening
        # that struct for a caller its original mechanism doesn't need.
        self._last_orphan_merge_cleanup: Optional[Dict[str, str]] = None
        # BUGFIX (identity-merge race, handover 2026-09-20): flat redirect map from a
        # discarded orphan_id -> the canonical_id it was folded into by
        # merge_into_canonical(). Without this, resolve_device_id()'s pure IP/hostname/MAC
        # hash branches (stable_device_id()) have no memory of a device_id they minted
        # before that's since been merged away -- a later per-flow signal miss (e.g. the
        # MAC isn't captured on this specific flow, even though it IS known elsewhere for
        # this device) regenerates the exact same dead hash and get_or_create() silently
        # resurrects a zombie DeviceState under it, stealing that address's future traffic
        # from its real canonical identity. Kept FLAT (never chained) by
        # merge_into_canonical() itself -- every existing entry pointing at an orphan_id
        # that's itself about to be discarded gets repointed to the new canonical_id in the
        # same step, so resolve_merge_redirect() is always a single O(1) hop. Persisted the
        # same way as _ips_state/_action_ledger (flush_to_disk/load_from_disk) so a
        # soc.service restart can't bring a dead id back to life either. Capped at
        # _MAX_MERGE_REDIRECTS, LRU-evicted, matching this session's "everything capped, no
        # unrestricted growth in production" retention philosophy -- merges track device
        # churn, not traffic volume, so this grows far slower than the evidence tables, but
        # it's still unbounded in principle over a long enough uptime.
        self._merge_redirects: "OrderedDict[str, str]" = OrderedDict()
        LOGGER.debug("StateManager instantiated. Target persistence path: %s", self.state_path)

    # ══════════════════════════════════════════════════════════════════════════════════
    # PHASE 6: MAC-address canonical identity index
    # ══════════════════════════════════════════════════════════════════════════════════

    def bind_mac(self, mac_address: str, device_id: str) -> None:
        """Registers (or updates) the canonical device_id for a MAC address. Safe to call
        repeatedly — idempotent, last-write-wins (relevant only if a MAC address is ever
        legitimately reassigned, e.g. a NIC replacement, or during real spoofing, which
        zeek_features.py's Layer-2 spoof detector separately flags as CRITICAL evidence)."""
        if not mac_address or mac_address == "unknown" or not device_id:
            return
        with self._global_lock:
            self._mac_to_device_id[mac_address] = device_id

    def get_device_id_for_mac(self, mac_address: str) -> Optional[str]:
        """Returns the canonical device_id already known for this MAC, or None if this MAC
        hasn't been bound yet (e.g. no DHCPv4 lease and no conn.log orig_l2_addr seen yet
        for this device — falls back to today's IP-anchored resolution)."""
        if not mac_address or mac_address == "unknown":
            return None
        with self._global_lock:
            dev_id = self._mac_to_device_id.get(mac_address)
            # Guard against a stale mapping pointing at a device_id that's since been
            # pruned/evicted — treat it the same as "not bound" rather than handing the
            # caller a dangling reference.
            if dev_id and dev_id not in self._states:
                del self._mac_to_device_id[mac_address]
                return None
            return dev_id

    def get_device_id_for_ip(self, ip: str) -> Optional[str]:
        """Returns the device_id an IP is CURRENTLY tracked under (via the reverse
        _ip_to_device_id index), or None if this IP has never been seen. Used by the
        device-identity fragmentation fix: identity.py's resolve_device_id() can mint a
        DIFFERENT (MAC-anchored) device_id for the same client_ip once that IP's MAC
        becomes known -- this lets the caller detect that an orphan device_id already
        exists for the IP and merge it into the newly-resolved canonical one, instead of
        silently leaving the orphan permanently disconnected (the actual fragmentation
        bug). Same self-healing guard as get_device_id_for_mac() -- a stale mapping to a
        since-pruned/merged device_id is treated as "not tracked" rather than handed back
        as a dangling reference, and the stale entry is cleaned up in the process."""
        if not ip or ip == "unknown":
            return None
        with self._global_lock:
            dev_id = self._ip_to_device_id.get(ip)
            if dev_id and dev_id not in self._states:
                del self._ip_to_device_id[ip]
                return None
            return dev_id

    @contextmanager
    def lock_device(self, device_id: str) -> Generator[DeviceState, None, None]:
        with self._global_lock:
            state = self._states.get(device_id)
            if state is None:
                LOGGER.error("Lock error: State for '%s' does not exist.", device_id)
                raise KeyError(f"Device state for '{device_id}' does not exist in StateManager store.")
            self._states.move_to_end(device_id)
            yield state

    def get_or_create(self, device_id: str, client_ip: str, hostname: str, alpha: float = 0.05,
                       dhcp_fingerprint: Optional[Dict[str, Any]] = None, ja4_set: Optional[set] = None,
                       reidentify: bool = True, min_confidence: float = AUTO_MERGE_CONFIDENCE,
                       candidate_window: float = 1800.0, ml_registry: Any = None) -> DeviceState:
        with self._global_lock:
            if device_id in self._states:
                state = self._states[device_id]
                if hostname and hostname != "unknown" and getattr(state, "hostname", "") == "unknown":
                    state.hostname = hostname
                # PHASE 6 FIX: this device_id can now be reached via a NEW client_ip that
                # wasn't the one it was originally cold-started under — most commonly the
                # IPv6 side of a dual-stack device resolving to the same device_id as its
                # already-known IPv4 side via the MAC-correlation index. Without this, the
                # reverse IP index would only ever point at whichever address the device
                # happened to cold-start from, so any by-IP reverse lookup elsewhere in this
                # file would silently miss this address family.
                self._ip_to_device_id[client_ip] = device_id
                self._states.move_to_end(device_id)
                return state

            # PHASE 4 (MAC-rotation resilience): before cold-starting a brand-new identity,
            # check whether this looks like a device we already know under a different
            # IP/MAC (e.g. a DHCP client-identifier rotation) rather than a genuinely new
            # device. Only attempts this when the caller supplied a fresh fingerprint to
            # compare — callers that don't care about re-identification (or that predate
            # this feature) get identical cold-start behavior to before.
            if reidentify and (dhcp_fingerprint or ja4_set):
                matched_old_id, best_candidate_id, best_conf = self._find_reidentify_candidate(
                    exclude_ip=client_ip, hostname=hostname,
                    dhcp_fingerprint=dhcp_fingerprint, ja4_set=ja4_set,
                    min_confidence=min_confidence, candidate_window=candidate_window,
                )
                if not matched_old_id and best_candidate_id and best_conf >= MIN_CANDIDATE_CONFIDENCE:
                    # A real candidate was found (strong enough to log about) but didn't
                    # clear THIS call's actual merge bar -- genuinely ambiguous, not "no
                    # match at all". Overwrites any prior unconsumed value; only the
                    # most recent ambiguous case matters, there's no queue semantics here.
                    self._last_reidentify_ambiguous = {
                        "new_device_id": device_id, "candidate_id": best_candidate_id,
                        "confidence": best_conf, "ts": time.time(),
                    }
                    identity_reidentify_ambiguous_total.labels(device=device_id, hostname=hostname or "unknown").inc()
                if matched_old_id:
                    self.migrate_device_id(matched_old_id, device_id, ml_registry=ml_registry)
                    state = self._states[device_id]
                    # BUGFIX: capture the OLD mac/ip BEFORE they're overwritten below, so a
                    # caller can release any stale isolation bookkeeping keyed by them (see
                    # pop_last_migrated_isolation_target()'s docstring). old client_ip is
                    # whatever this device was last known at under its pre-merge identity;
                    # old mac_address survives migrate_device_id() untouched (only
                    # overwritten later by identity.py's _refresh_identity_signals()).
                    self._last_migrated_isolation_target = {
                        "mac_addr": getattr(state, "mac_address", "unknown") or "unknown",
                        "ip_addr": getattr(state, "client_ip", "unknown") or "unknown",
                    }
                    state.client_ip = client_ip
                    if hostname and hostname != "unknown":
                        state.hostname = hostname
                    self._ip_to_device_id[client_ip] = device_id
                    LOGGER.warning(
                        "🔗 IDENTITY RE-LINKED: %s -> %s (hostname=%s, ip=%s) — matched via "
                        "DHCP/JA4/hostname fingerprint, treating as a MAC rotation of a known "
                        "device rather than a cold start.", matched_old_id, device_id, hostname, client_ip
                    )
                    identity_reidentify_migrations_total.labels(device=device_id, hostname=hostname or "unknown").inc()
                    self._prune_lru_capacity()
                    return state

            LOGGER.info("Initializing new DeviceState tracking profile for %s (%s)", hostname, client_ip)
            state = DeviceState(
                device_id=device_id,
                client_ip=client_ip,
                hostname=hostname,
                alpha=alpha
            )
            
            # Peer Profile Transfer Learning:
            # Seed probation device baselines from existing devices of the same category
            dev_type = state.device_type
            peer_states = [s for s in self._states.values() if getattr(s, "device_type", "") == dev_type and sum(getattr(s.rate_baseline, "n", [0])) >= 10]
            if peer_states:
                LOGGER.info("🌱 [TRANSFER LEARNING] Seeding initial baselines for new %s (%s) from %d peer %s profiles", hostname, dev_type, len(peer_states), dev_type)
                transfer_learning_seeds_total.labels(device_type=dev_type or "unknown").inc()
                try:
                    for hour in range(24):
                        peer_rate = sum(p.rate_baseline.get_stats(hour)[0] for p in peer_states) / len(peer_states)
                        peer_ent = sum(p.entropy_baseline.get_stats(hour)[0] for p in peer_states) / len(peer_states)
                        peer_uniq = sum(p.unique_baseline.get_stats(hour)[0] for p in peer_states) / len(peer_states)
                        if peer_rate > 0: state.rate_baseline.update(peer_rate, hour)
                        if peer_ent > 0: state.entropy_baseline.update(peer_ent, hour)
                        if peer_uniq > 0: state.unique_baseline.update(peer_uniq, hour)
                except Exception as exc:
                    LOGGER.debug("Peer transfer learning initialization skipped: %s", exc)

            self._states[device_id] = state
            # Maintain reverse IP index for O(1) MAC updates
            self._ip_to_device_id[client_ip] = device_id
            self._prune_lru_capacity()
            return state

    def _find_reidentify_candidate(self, exclude_ip: str, hostname: str,
                                     dhcp_fingerprint: Optional[Dict[str, Any]], ja4_set: Optional[set],
                                     min_confidence: float, candidate_window: float
                                     ) -> "tuple[Optional[str], Optional[str], float]":
        """Scans currently-tracked devices for one that plausibly IS the new device under
        its old identity — i.e. it just went quiet (not still active, not ancient history;
        that's what the weekly prune sweep is for) and its DHCP/JA4/hostname fingerprint
        matches. Must be called with self._global_lock already held (it iterates
        self._states without re-locking). O(N) in device count — only runs on the
        cold-start path, never per-packet, so this is cheap even at max_devices capacity.

        Returns (matched_id, best_id, best_conf): matched_id is the auto-merge result
        (None unless best_conf >= min_confidence, i.e. identical to this function's
        original single-value return before PHASE 21D); best_id/best_conf are the best
        candidate found regardless of whether it cleared min_confidence, added so the
        caller can distinguish "no candidate at all" from "a candidate existed but
        wasn't confident enough to auto-merge" (the ambiguous-band reactive-capture
        trigger needs exactly this distinction, which the original bool-ish return
        couldn't express).
        """
        now = time.time()
        best_id, best_conf = None, 0.0
        ja4_set = ja4_set or set()

        for cand_id, cand_state in self._states.items():
            cand_ip = getattr(cand_state, "client_ip", "")
            if not cand_ip or cand_ip == exclude_ip:
                continue

            last_seen = getattr(cand_state, "last_seen", 0.0)
            age = now - last_seen
            # Too fresh: still actively using its old identity, this isn't a rotation.
            # Too old: outside the rotation window: let the normal cold-start path handle it.
            if age < 5.0 or age > candidate_window:
                continue

            dhcp_score = dhcp_fingerprint_match(dhcp_fingerprint, getattr(cand_state, "dhcp_fingerprint", None))
            ja4_sim = ja4_overlap(ja4_set, set(getattr(cand_state, "ja4_seen", []) or []))
            host_ok = hostname_corroborates(hostname, getattr(cand_state, "hostname", ""))

            conf = match_confidence(dhcp_score, ja4_sim, host_ok)
            if conf >= MIN_CANDIDATE_CONFIDENCE:
                LOGGER.info(
                    "🔎 Re-identification candidate: %s (hostname=%s) confidence=%.2f "
                    "(dhcp=%.2f ja4_overlap=%.2f hostname_match=%s, idle=%.0fs)",
                    cand_id, getattr(cand_state, "hostname", "?"), conf, dhcp_score, ja4_sim, host_ok, age
                )
            if conf > best_conf:
                best_conf, best_id = conf, cand_id

        matched_id = best_id if (best_id and best_conf >= min_confidence) else None
        return matched_id, best_id, best_conf

    def pop_last_reidentify_ambiguous(self) -> Optional[Dict[str, Any]]:
        """Consume-once accessor for the ambiguous re-identification side channel (see
        __init__'s comment). Returns None if nothing's pending, or the pending finding
        -- and clears it either way, so a caller that doesn't check every cycle can't
        end up re-triggering on a stale value from several cycles ago."""
        with self._global_lock:
            val = self._last_reidentify_ambiguous
            self._last_reidentify_ambiguous = None
            return val

    def pop_last_migrated_isolation_target(self) -> Optional[Dict[str, str]]:
        """Consume-once accessor for the "a re-identify merge just made these old MAC/IP
        isolation bookkeeping entries stale" side channel -- see __init__'s comment.
        Returns None if the most recent get_or_create() call didn't perform a merge, or
        {"mac_addr": ..., "ip_addr": ...} identifying the OLD identity whose isolation
        state (if any) should now be released via IPSMitigator.unisolate_all(). Clears the
        value either way so a caller that doesn't check every cycle can't act on a stale
        result from a much earlier call."""
        with self._global_lock:
            val = self._last_migrated_isolation_target
            self._last_migrated_isolation_target = None
            return val

    def pop_last_orphan_merge_cleanup(self) -> Optional[Dict[str, str]]:
        """Consume-once accessor for the "a retroactive orphan merge just discarded this
        device_id" cleanup side channel (see __init__'s comment). Returns None if
        nothing's pending, or {"orphan_id", "orphan_hostname", "orphan_device_type",
        "canonical_id"} identifying the just-discarded orphan — a caller with an
        evidence store / metrics exporter should purge the orphan's now-stale
        evidence/metric rows using this info. Clears the value either way so a caller
        that doesn't check every cycle can't act on a stale result from a much earlier
        merge."""
        with self._global_lock:
            val = self._last_orphan_merge_cleanup
            self._last_orphan_merge_cleanup = None
            return val

    def has_device(self, device_id: str) -> bool:
        with self._global_lock:
            return device_id in self._states

    def remove_device(self, device_id: str) -> bool:
        """WebUI Maintenance page's "Remove Device" action (PRODUCTIZATION_ROADMAP.md
        Phase 4) -- permanently forgets a device's tracked profile: risk history,
        suspicious_since state, everything DeviceState holds. Distinct from the existing
        release/isolation-clearing methods, which unblock a device without erasing what's
        been learned about it; this is the "the device is gone, stop tracking it
        entirely" action, irreversible for that device's history. Also drops any
        MAC/IP reverse-index entries pointing at it, so a stale index never resolves to a
        pruned device_id (same defensive pattern get_device_id_for_mac/_ip already use).
        Caller is responsible for the matching cleanup in the sibling JSON side files
        (device_labels.json) and the graph -- this method
        only owns in-memory/persisted StateManager state."""
        with self._global_lock:
            existed = device_id in self._states
            self._states.pop(device_id, None)
            for ip, mapped_id in list(self._ip_to_device_id.items()):
                if mapped_id == device_id:
                    del self._ip_to_device_id[ip]
            for mac, mapped_id in list(self._mac_to_device_id.items()):
                if mapped_id == device_id:
                    del self._mac_to_device_id[mac]
        return existed

    def migrate_device_id(self, old_id: str, new_id: str, ml_registry: Any = None) -> bool:
        """ml_registry is optional (default None) so existing callers keep working
        unchanged. When supplied, also migrates that device's per-device ML anomaly
        model to the new id -- BUGFIX: this used to be the caller's job (identity.py's
        process_dns_identities()/process_zeek_identities() accepted an ml_registry
        parameter specifically for this) but nothing ever actually called
        ml_registry.migrate_device() on a re-identify merge, since get_or_create()
        performs the DeviceState migration internally and never surfaced that fact to
        its caller. Doing it here, at the single choke point where a device-id
        migration actually happens, means every migration path (current and future)
        keeps the ML model in sync automatically instead of relying on each caller to
        remember. Called outside self._global_lock -- ml_registry.migrate_device() does
        its own file I/O (renaming the on-disk model) and never calls back into
        StateManager, so there's no reason to hold this lock across it."""
        with self._global_lock:
            if old_id not in self._states:
                LOGGER.debug("Migration failed: %s not found in states.", old_id)
                return False

            old_state = self._states.pop(old_id)
            old_state.device_id = new_id
            self._states[new_id] = old_state
            self._states.move_to_end(new_id)

            # Keep reverse index in sync
            self._ip_to_device_id[old_state.client_ip] = new_id

            # PHASE 6 FIX: keep the MAC-correlation index in sync too. Without this, a
            # since-migrated old_id would linger in _mac_to_device_id until something
            # happened to trigger the self-healing prune in get_device_id_for_mac()
            # (which only fires on a lookup that lands on a since-removed id) — a stale
            # window where a MAC-based cross-address-family lookup could still resolve
            # to the pre-migration id instead of following the migration immediately.
            self._repoint_mac_index(old_id, new_id)
            mac = getattr(old_state, "mac_address", "unknown")
            if mac and mac != "unknown":
                self._mac_to_device_id[mac] = new_id

            hostname = getattr(old_state, "hostname", "unknown")
            client_ip = getattr(old_state, "client_ip", "unknown")
            
            LOGGER.info("Successfully migrated DeviceState tracking profile for %s (%s)", hostname, client_ip)

        if ml_registry is not None:
            ml_registry.migrate_device(old_id, new_id)
        return True

    def _repoint_mac_index(self, old_id: str, new_id: str) -> None:
        """Repoints every _mac_to_device_id entry currently mapped to old_id so it maps
        to new_id instead. Scans the index itself (not just one state's own
        mac_address field) so this stays correct even if a device somehow accumulated
        more than one bound MAC. Shared by migrate_device_id() (DHCP/JA4-fingerprint
        re-identify merge) and merge_into_canonical() (retroactive orphan merge) — the
        one piece of index bookkeeping that's identical between those two otherwise
        differently-shaped operations. Must be called with self._global_lock already
        held."""
        for mac_key, mapped_id in list(self._mac_to_device_id.items()):
            if mapped_id == old_id:
                self._mac_to_device_id[mac_key] = new_id

    def merge_into_canonical(self, orphan_id: str, canonical_id: str,
                              ml_registry: Any = None, familiarity: Any = None) -> bool:
        """Folds an ORPHAN device_id into an already-existing, richer CANONICAL identity
        -- the opposite direction from migrate_device_id(). migrate_device_id() assumes
        its destination (new_id) does NOT already exist yet (it overwrites
        self._states[new_id] with the old state — correct for "this device just rotated
        identity, continue its history under a fresh id"). That would be DESTRUCTIVE
        here: canonical_id already has its own accumulated baselines/history that must
        survive untouched. This is the device-identity fragmentation fix's core
        primitive — see identity.py's _merge_orphan_if_fragmented() for the trigger
        condition (a client_ip's newly-resolved MAC-anchored device_id differs from the
        device_id that IP was already tracked under) and
        src/merge_fragmented_devices.py for the offline one-time cleanup script that
        also calls this directly against the on-disk state file.

        Per explicit product decision: the orphan's OWN accumulated STATISTICAL state
        (baselines, evidence, learned thresholds) is DISCARDED, not blended into the
        canonical identity's — the orphan is typically far sparser (cold-started with
        hostname/mac unresolved) than the canonical identity it's being folded into,
        and blending a near-empty estimator into a mature one would corrupt it, not
        improve it. Its identifying pointers (known_ips, MAC bindings, blocked-domain
        attribution) are redirected so future traffic and existing operator-facing
        records correctly resolve to the canonical id. EXCEPTION (2026-09-20, identity-
        merge handover follow-up): confirmed_threat_count/fp_count/has_validated_threat
        ARE carried forward (summed/OR'd into the canonical) -- these are simple counts
        of real, discrete operator actions against this physical device, not statistical
        estimators, so summing them is lossless and correct rather than corrupting.

        Idempotent / safe: a no-op returning False if canonical_id isn't a currently
        tracked device, if orphan_id == canonical_id, or if orphan_id isn't currently
        tracked (e.g. this exact merge already ran once)."""
        with self._global_lock:
            # BUGFIX (identity-merge race, handover 2026-09-20): resolve BOTH ids through
            # the redirect map before doing anything else. This is a second line of
            # defense on top of resolve_device_id()'s own resolve_merge_redirect() call --
            # it means this method is self-healing even if some OTHER caller (an offline
            # cleanup script, a future call site) passes a stale/dead id directly, and
            # it's also what actually prevents the "both sides stuck" failure mode: if
            # canonical_id itself was already merged away since the caller looked it up,
            # this follows it to its live successor instead of aborting against a dead id.
            canonical_id = self._merge_redirects.get(canonical_id, canonical_id)
            orphan_id = self._merge_redirects.get(orphan_id, orphan_id)
            if canonical_id not in self._states:
                LOGGER.warning(
                    "merge_into_canonical() aborted: canonical_id %s is not a currently "
                    "tracked device (orphan_id=%s left untouched).", canonical_id, orphan_id
                )
                return False
            if orphan_id == canonical_id or orphan_id not in self._states:
                return False

            orphan_state = self._states[orphan_id]
            canonical_state = self._states[canonical_id]

            # Redirect every address the orphan was known at (its accumulated known_ips
            # plus its own client_ip, in case client_ip hasn't made it into known_ips
            # yet) to resolve to the canonical id from now on, and fold those addresses
            # into the canonical identity's own known_ips so future feature/evidence
            # aggregation (which reads state.known_ips) sees the full picture.
            orphan_ips = set(getattr(orphan_state, "known_ips", None) or [])
            orphan_client_ip = getattr(orphan_state, "client_ip", "")
            if orphan_client_ip and orphan_client_ip != "unknown":
                orphan_ips.add(orphan_client_ip)
            for ip in orphan_ips:
                self._ip_to_device_id[ip] = canonical_id
                canonical_state.known_ips.add(ip)

            # BUGFIX (2026-09-20, identity-merge handover follow-up): carry forward the
            # orphan's operator-confirmed incident counters instead of silently dropping
            # them. Per the discard-not-blend policy documented above, STATISTICAL state
            # (baselines, learned thresholds, ML models, FP calibration) stays discarded
            # -- blending a near-empty orphan's estimator into the canonical's mature one
            # would corrupt it, not improve it. These three fields are different in kind:
            # they're simple, monotonically-incrementing counts of real operator actions
            # (a human confirmed a threat / marked a false positive against THIS physical
            # device, e.g. fritzbox_api.py's isolate action or pihole_api.py's mark-FP/
            # mark-threat actions), not a statistical estimate that degrades when summed.
            # Losing them on merge would silently erase a device's real incident history
            # and could make an already-flagged device look falsely clean right after a
            # routine identity-merge event that has nothing to do with its actual risk.
            canonical_state.confirmed_threat_count = (
                getattr(canonical_state, "confirmed_threat_count", 0)
                + getattr(orphan_state, "confirmed_threat_count", 0)
            )
            canonical_state.fp_count = (
                getattr(canonical_state, "fp_count", 0) + getattr(orphan_state, "fp_count", 0)
            )
            canonical_state.has_validated_threat = (
                getattr(canonical_state, "has_validated_threat", False)
                or getattr(orphan_state, "has_validated_threat", False)
            )

            # Redirect the MAC-correlation index the same way migrate_device_id() does.
            self._repoint_mac_index(orphan_id, canonical_id)
            orphan_mac = getattr(orphan_state, "mac_address", "unknown")
            if orphan_mac and orphan_mac != "unknown":
                self._mac_to_device_id[orphan_mac] = canonical_id

            # BUGFIX (identity-merge race, handover 2026-09-20): flatten any existing
            # redirect chain (A already pointed at orphan_id from an EARLIER merge) onto
            # the new canonical_id before recording orphan_id's own redirect, so
            # resolve_merge_redirect() is always a single hop no matter how many times a
            # device_id has been re-merged over its lifetime.
            for old_orphan, redirected_to in list(self._merge_redirects.items()):
                if redirected_to == orphan_id:
                    self._merge_redirects[old_orphan] = canonical_id
            self._merge_redirects[orphan_id] = canonical_id
            self._merge_redirects.move_to_end(orphan_id)
            while len(self._merge_redirects) > self._MAX_MERGE_REDIRECTS:
                self._merge_redirects.popitem(last=False)

            # Reattribute any Pi-hole domain-block records that were tagged with the
            # orphan's device_id/hostname so their "which device caused this" display
            # doesn't point at a dead id after the merge. blocked_domains is keyed by
            # domain string with device_id as metadata only — a pure relabel, no
            # functional block/release behavior change (release-by-identifier already
            # also matches on IP/MAC/hostname, not just device_id).
            canonical_hostname = getattr(canonical_state, "hostname", "unknown")
            for meta in self._ips_state.get("blocked_domains", {}).values():
                if meta.get("device_id") == orphan_id:
                    meta["device_id"] = canonical_id
                    if canonical_hostname and canonical_hostname != "unknown":
                        meta["hostname"] = canonical_hostname

            # Capture the orphan's OLD mac/ip before discarding its state, and reuse the
            # existing isolation-release side channel — identity.py's
            # _release_stale_isolation_if_merged() needs zero changes to pick this up.
            self._last_migrated_isolation_target = {
                "mac_addr": orphan_mac or "unknown",
                "ip_addr": orphan_client_ip or "unknown",
            }
            self._last_orphan_merge_cleanup = {
                "orphan_id": orphan_id,
                "orphan_hostname": getattr(orphan_state, "hostname", "unknown"),
                "orphan_device_type": getattr(orphan_state, "device_type", "unknown"),
                "canonical_id": canonical_id,
            }

            # Discard the orphan's own DeviceState per the discard-not-blend decision.
            del self._states[orphan_id]
            self._states.move_to_end(canonical_id)

            LOGGER.warning(
                "🔗 IDENTITY MERGE (retroactive): orphan %s discarded, %d address(es) "
                "redirected to canonical %s (%s)", orphan_id, len(orphan_ips), canonical_id, canonical_hostname
            )
            identity_merges_total.labels(device=canonical_id, hostname=canonical_hostname or "unknown").inc()

        if ml_registry is not None:
            ml_registry.discard_device(orphan_id, reason="merge")
        if familiarity is not None:
            familiarity.discard_device_profile(orphan_id, reason="merge")
        return True

    def get_all_device_ids(self) -> List[str]:
        with self._global_lock:
            return list(self._states.keys())

    def resolve_merge_redirect(self, device_id: str) -> str:
        """Returns the live device_id `device_id` currently resolves to if it was ever
        discarded via merge_into_canonical() (including across a restart -- persisted
        the same way as everything else via flush_to_disk()/load_from_disk()), or
        device_id unchanged if it was never merged away. Always O(1): merge_into_canonical()
        keeps the redirect map flat (never chained), so at most one lookup is ever needed.

        Closes a real live bug (see identity.py's resolve_device_id(), the primary
        caller): resolve_device_id()'s pure IP/hostname/MAC hash branches have no memory
        of a device_id they minted before that's since been merged away. Without this,
        a later per-flow signal miss (e.g. a MAC isn't captured on this specific flow,
        even though it IS known elsewhere for this device) regenerates the exact same
        dead hash, and get_or_create() silently resurrects a zombie DeviceState under it
        -- confirmed live via merge_into_canonical()'s own abort-warning log lines
        pointing at the same device_id from both directions minutes apart."""
        with self._global_lock:
            return self._merge_redirects.get(device_id, device_id)

    def get_ips_state(self) -> Dict[str, Any]:
        """Returns a shallow copy of the IPS state for inspection.
        AUDIT FIX #6 NOTE: For read-modify-write operations use update_ips_state_atomic()
        to avoid the TOCTOU window between get and save calls. The inner dicts are still
        mutable references — callers must not mutate them directly without the global lock.
        """
        with self._global_lock:
            return copy.deepcopy(self._ips_state)

    def update_ips_state_atomic(self, updates: Dict[str, Any]) -> None:
        """C2 FIX: Atomically merge `updates` into the IPS state under the global lock.
        Replaces the pattern of: get_ips_state() -> mutate copy -> save_ips_state()
        which had a TOCTOU window between the get and save calls.
        """
        with self._global_lock:
            self._ips_state.update(updates)

    def save_ips_state(self, ips_data: Dict[str, Any]) -> None:
        with self._global_lock:
            if not isinstance(ips_data, dict):
                raise TypeError("ips_data must be a dictionary")
            self._ips_state = dict(ips_data)
            self._ips_state.setdefault("blocked_domains", {})
            self._ips_state.setdefault("retry_queue", {})
            self._ips_state.setdefault("dead_letter", {})
            self._ips_state.setdefault("tarpit_targets", {})
            self._ips_state.setdefault("router_isolated_devices", {})
            self._ips_state.setdefault("operator_released_devices", {})
            self._ips_state.setdefault("last_sync_timestamp", 0.0)

    # ══════════════════════════════════════════════════════════════════════════════════
    # PHASE 3: Revocable-action ledger (closed-loop autonomous actions)
    # ══════════════════════════════════════════════════════════════════════════════════

    def record_action(self, action_id: str, action_type: str, target: str, device_id: str,
                       hostname: str = "unknown", ttl_seconds: float = 86400.0,
                       extra: Optional[Dict[str, Any]] = None) -> None:
        """Records an autonomous action (e.g. a CL-AFPE domain immunization) so an
        operator can revoke it later via revoke_action(). `ttl_seconds` bounds how long the
        revoke option stays offered — after expiry prune_expired_actions() drops it, since
        an action nobody objected to within that window is presumed correct.

        PHASE 6: `extra` is an optional free-form dict carried through the ledger entry
        unchanged. Used by the "published_alert" action type (recorded for every alert
        sent to Telegram, not just autonomous actions) to stash the full `alert_payload`
        so the "Mark False Positive" button's IPC handler can retrieve it later without
        re-deriving features from scratch — the Telegram round-trip only carries a short
        action_id string, not the alert body itself."""
        with self._global_lock:
            self._ledger_entry_json.pop(action_id, None)
            self._action_ledger[action_id] = {
                "type": action_type, "target": target, "device_id": device_id, "hostname": hostname,
                "timestamp": time.time(), "expires_at": time.time() + ttl_seconds, "revoked": False,
                "extra": extra or {},
            }

    def revoke_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Marks an action revoked and returns a copy of its ledger entry, or None if the
        action_id is unknown or was already revoked (e.g. a duplicate Telegram tap)."""
        with self._global_lock:
            entry = self._action_ledger.get(action_id)
            if not entry or entry.get("revoked"):
                return None
            entry["revoked"] = True
            entry["revoked_at"] = time.time()
            self._ledger_entry_json.pop(action_id, None)
            return dict(entry)

    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        with self._global_lock:
            entry = self._action_ledger.get(action_id)
            return dict(entry) if entry else None

    def prune_expired_actions(self, now: Optional[float] = None) -> int:
        """Drops ledger entries past their TTL that were never revoked. Call this from the
        same hourly sweep that already prunes stale devices."""
        now = now if now is not None else time.time()
        with self._global_lock:
            expired = [aid for aid, e in self._action_ledger.items()
                       if not e.get("revoked") and e.get("expires_at", 0) < now]
            for aid in expired:
                del self._action_ledger[aid]
                self._ledger_entry_json.pop(aid, None)
        if expired:
            LOGGER.debug("Pruned %d expired action-ledger entries.", len(expired))
        return len(expired)

    def load_historical_ledger(self) -> int:
        ledger_path = self.state_path.parent / "ips_historical_ledger.jsonl"
        if not ledger_path.exists():
            LOGGER.debug("No historical ledger found at %s", ledger_path)
            return 0
            
        loaded_count = 0
        try:
            LOGGER.debug("Parsing historical ledger from %s", ledger_path)
            with open(ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        domain = entry.get("domain")
                        hostname = entry.get("hostname", "unknown")
                        timestamp = entry.get("timestamp", 0.0)
                        if domain:
                            with self._global_lock:
                                self._ips_state["blocked_domains"][domain] = {
                                    "hostname": hostname,
                                    "timestamp": timestamp
                                }
                            loaded_count += 1
                    except json.JSONDecodeError:
                        continue
            LOGGER.info("Successfully loaded %d historical blocks from ledger into active state store", loaded_count)
            return loaded_count
        except Exception as exc:
            LOGGER.error("Failed to parse historical ledger from %s: %s", ledger_path, exc)
            return 0

    def update_baselines(self, state: DeviceState, features: dict, timestamp: float, window_seconds: int = 300, current_risk: float = 0.0) -> None:
        with self._global_lock:
            if timestamp - getattr(state, "last_baseline_update", 0.0) < window_seconds:
                return

            current_hour = int(features.get("current_hour", 12))
            state.rate_baseline.update(features.get("query_rate", 0.0), current_hour)
            state.entropy_baseline.update(features.get("entropy_avg", 0.0), current_hour)
            state.unique_baseline.update(features.get("unique_domains", 0.0), current_hour)
            state.nxdomain_baseline.update(features.get("nxdomain_ratio", 0.0), current_hour)
            state.blocked_baseline.update(features.get("blocked_ratio", 0.0), current_hour)
            state.dga_baseline.update(features.get("suspicious_domains", 0.0), current_hour)
            state.outbound_bytes_baseline.update(features.get("zeek_outbound_bytes", 0.0), current_hour)

            if hasattr(state, "risk_baseline"):
                state.risk_baseline.update(current_risk, current_hour)

            state.last_baseline_update = timestamp
            LOGGER.debug("Baselines updated for device %s", state.device_id)

    def prune_stale_devices(self, now: float, max_idle_seconds: int = 86400 * 7) -> list:
        pruned_devices = []
        with self._global_lock:
            keys_to_check = list(self._states.keys())
            for dev_id in keys_to_check:
                # M5 FIX: use .get() to guard against concurrent eviction by _prune_lru_capacity()
                state = self._states.get(dev_id)
                if state is None:
                    continue
                last_active = max(getattr(state, "last_alert_time", 0.0), getattr(state, "last_baseline_update", 0.0))
                if last_active > 0 and (now - last_active) > max_idle_seconds:
                    pruned_devices.append((dev_id, state.hostname, state.device_type))
                    # BUGFIX (device-identity fragmentation audit): this used to only clear
                    # the single client_ip entry, leaving every OTHER address in this
                    # device's known_ips dangling in _ip_to_device_id (self-healing on next
                    # lookup via get_device_id_for_ip()/get_device_id_for_mac()'s stale-
                    # mapping guards, but a real, needless leak in the meantime). Clear
                    # every known address, not just the most-recent one.
                    addrs_to_clear = set(getattr(state, "known_ips", None) or [])
                    client_ip = getattr(state, "client_ip", "")
                    if client_ip:
                        addrs_to_clear.add(client_ip)
                    for ip in addrs_to_clear:
                        if ip in self._ip_to_device_id:
                            del self._ip_to_device_id[ip]
                    del self._states[dev_id]

        if pruned_devices:
            LOGGER.info("Pruned %d stale device profiles from StateManager store", len(pruned_devices))
        return pruned_devices

    def _prune_lru_capacity(self) -> None:
        while len(self._states) > self.max_devices:
            evicted_id, state = self._states.popitem(last=False)
            client_ip = getattr(state, "client_ip", "")
            if client_ip and self._ip_to_device_id.get(client_ip) == evicted_id:
                del self._ip_to_device_id[client_ip]
            LOGGER.warning("StateManager reached max capacity (%d). Evicted LRU device: %s", self.max_devices, evicted_id)

    @staticmethod
    def _digest(text: str) -> bytes:
        return hashlib.blake2b(text.encode("utf-8"), digest_size=16).digest()

    def _apply_snapshot(self, data: Dict[str, Any], alpha: float) -> None:
        """Replaces the in-memory state with a snapshot in the ids_state.json shape. Caller holds _global_lock."""
        self._states.clear()

        devices_data = data.get("devices", data) if isinstance(data, dict) and "devices" in data else data
        if isinstance(data, dict) and "ips_state" in data:
            self._ips_state = data["ips_state"]
        if isinstance(data, dict) and "action_ledger" in data:
            self._action_ledger = data["action_ledger"] or {}
            self._ledger_entry_json.clear()
        if isinstance(data, dict) and "merge_redirects" in data:
            # BUGFIX (identity-merge race, handover 2026-09-20): must survive a
            # restart -- otherwise a soc.service bounce would forget every
            # discarded id and re-open the exact resurrection window this map
            # exists to close.
            self._merge_redirects = OrderedDict(data["merge_redirects"] or {})

        for dev_id, d in devices_data.items():
            if dev_id in ("ips_state", "action_ledger", "merge_redirects"):
                continue
            st = DeviceState.from_dict(d, alpha=alpha)
            self._states[dev_id] = st

        self._prune_lru_capacity()

        # PHASE 6: _mac_to_device_id is a derived index (not its own persisted
        # source of truth) — rebuild it from each DeviceState's own mac_address
        # field, which IS persisted. Simpler and avoids yet another split-brain
        # surface for the IPC-subprocess reconcile path to worry about.
        self._mac_to_device_id.clear()
        for dev_id, st in self._states.items():
            mac = getattr(st, "mac_address", "unknown")
            if mac and mac != "unknown":
                self._mac_to_device_id[mac] = dev_id

    def load_from_disk(self, alpha: float = 0.05, ledger: bool = True) -> int:
        """Loads the SQLite state (core/state_store.py); without a database yet, an existing ids_state.json -- it is
        migrated by the next flush. ledger=False skips the action ledger (most of the data) for read-only views; such
        an instance never flushes."""
        try:
            self._read_only = not ledger
            rows = state_store.read_rows(self.state_path, tables=("devices", "ledger", "kv") if ledger else ("devices", "kv"))
            if rows is not None and not ledger:
                rows["ledger"] = {}
            legacy = state_store.legacy_json_path(self.state_path)
            if rows is None and not legacy.exists():
                LOGGER.info("No existing state found at %s. Starting fresh store.", self.state_path)
                self.load_historical_ledger()
                return 0

            if rows is not None:
                kv = {k: json.loads(v) for k, v in rows["kv"].items()}
                data = {"devices": {k: json.loads(v) for k, v in rows["devices"].items()},
                        "action_ledger": {k: json.loads(v) for k, v in rows["ledger"].items()},
                        "ips_state": kv.get("ips_state") or {}, "merge_redirects": kv.get("merge_redirects") or {}}
                source = state_store.db_path_for(self.state_path)
            else:
                LOGGER.debug("Reading legacy state snapshot from %s", legacy)
                data = json.loads(legacy.read_text(encoding="utf-8"))
                source = legacy

            with self._global_lock:
                self._apply_snapshot(data, alpha)
                with self._flush_lock:
                    if rows is not None:
                        # What is on disk now: the next flush writes only rows that differ from it.
                        self._disk_digest = {t: {k: self._digest(v) for k, v in rows[t].items()}
                                             for t in ("devices", "ledger", "kv")}
                        self._ledger_entry_json.update(rows["ledger"])
                        self._ledger_dirty.clear()
                        self._legacy_json_pending = False
                    else:
                        self._disk_digest = {"devices": {}, "ledger": {}, "kv": {}}
                        self._ledger_dirty = set(self._action_ledger)
                        self._legacy_json_pending = True

            self.load_historical_ledger()

            loaded_count = len(self._states)
            LOGGER.info("Successfully loaded baselines for %d devices and IPS state from %s", loaded_count, source)
            return loaded_count
        except Exception as exc:
            LOGGER.error("Failed to load state store from %s: %s", self.state_path, exc)
            return 0

    # 2026-09-21 (live incident): confirmed live that a graceful shutdown (pipeline.py's
    # stop(), itself triggered by health_manager's own pipeline_main_loop-heartbeat
    # self-heal) got stuck for 5+ minutes inside this exact json.dump()/file-write --
    # the same "even basic filesystem I/O can stall under this cgroup's memory
    # pressure" pattern already found (twice, via py-spy) in core/health_manager.py's
    # psutil/sysfs reads. This is also called every ~60s from the HOT pipeline loop
    # (pipeline.py's _step()) -- a stall here is very plausibly the ROOT CAUSE of the
    # pipeline_main_loop heartbeat going stale in the first place, not just a
    # shutdown-time inconvenience. Bounding it protects both paths with one fix.
    _FLUSH_IO_TIMEOUT_SECONDS = 20.0

    @staticmethod
    def _bounded_io(fn, timeout: float):
        """Same shape as core/health_manager.py's own _bounded_call() -- kept as a
        small local copy rather than importing across that module boundary (state_
        guard.py has no other dependency on health_manager.py, and this codebase's
        own established precedent, e.g. health_manager.py's _set_config_override(),
        already prefers a small local copy over a cross-layer import for exactly
        this kind of narrow, self-contained helper). Runs fn() on a throwaway daemon
        thread with a hard wall-clock bound; a stuck fn() leaks one thread (bounded
        by process lifetime) instead of freezing the caller forever."""
        result: Dict[str, Any] = {}

        def _target():
            try:
                result["value"] = fn()
            except Exception as exc:
                result["error"] = exc

        t = threading.Thread(target=_target, daemon=True, name="state_flush_io")
        t.start()
        t.join(timeout=timeout)
        if t.is_alive():
            return None, True
        if "error" in result:
            raise result["error"]
        return result.get("value"), False

    def flush_to_disk(self) -> bool:
        if getattr(self, "_read_only", False):
            LOGGER.error("StateManager loaded without the action ledger (read-only view) -- refusing to flush")
            return False
        try:
            LOGGER.debug("Acquiring global lock to initiate state persistence.")
            with self._global_lock:
                devices_snapshot = {}
                graph_metadata_snapshot = {}
                for dev_id, state in self._states.items():
                    devices_snapshot[dev_id] = state.to_dict()
                    if self._graph_store is not None:
                        # v13 full-architecture plan, device-state unification: cheap,
                        # in-memory-only snapshot of the COLD field subset (see
                        # DeviceState.to_graph_metadata()'s own docstring for exactly
                        # which fields and why) -- taken under the SAME lock as
                        # devices_snapshot above so it's consistent with what's about
                        # to hit disk, but the actual graph I/O happens OUTSIDE the
                        # lock below, matching this codebase's established
                        # collect-under-lock/IO-outside-lock convention (see
                        # mitigation/ips.py's release_device() for the same pattern).
                        graph_metadata_snapshot[dev_id] = state.to_graph_metadata()
                kv_json = {"ips_state": json.dumps(self._ips_state, separators=(",", ":")),
                           "merge_redirects": json.dumps(dict(self._merge_redirects), separators=(",", ":"))}
                # A2: per-entry JSON cache (see __init__). Misses -- normally the one or two alerts published since
                # the last flush -- are encoded here, under the lock, so a concurrent revoke can never leave a stale
                # string in the cache; the full first flush after a restart is the only large one.
                entry_cache = self._ledger_entry_json
                ledger_json: Dict[str, str] = {}
                for aid, entry in self._action_ledger.items():
                    js = entry_cache.get(aid)
                    if js is None:
                        js = json.dumps(entry, separators=(",", ":"))
                        entry_cache[aid] = js
                        self._ledger_dirty.add(aid)
                    ledger_json[aid] = js
                if len(entry_cache) > 2 * len(self._action_ledger) + 100:
                    for stale in [k for k in entry_cache if k not in self._action_ledger]:
                        del entry_cache[stale]
                ledger_dirty, self._ledger_dirty = self._ledger_dirty, set()

            def _write_changed_rows():
                # json.dumps(), not json.dump(): CPython only uses its C encoder for one-shot encoding.
                dev_json = {k: json.dumps(v, separators=(",", ":")) for k, v in devices_snapshot.items()}
                with self._flush_lock:
                    if not state_store.db_path_for(self.state_path).exists():
                        # Database removed underneath us (or never written): everything is "changed".
                        self._disk_digest = {"devices": {}, "ledger": {}, "kv": {}}
                    disk = self._disk_digest
                    dev_new = {k: self._digest(v) for k, v in dev_json.items()}
                    dev_changed = {k: dev_json[k] for k, d in dev_new.items() if disk["devices"].get(k) != d}
                    dev_deleted = [k for k in disk["devices"] if k not in dev_json]
                    led_changed = {}
                    for aid in ledger_json:
                        if aid in disk["ledger"] and aid not in ledger_dirty:
                            continue
                        d = self._digest(ledger_json[aid])
                        if disk["ledger"].get(aid) != d:
                            led_changed[aid] = (ledger_json[aid], d)
                    led_deleted = [a for a in disk["ledger"] if a not in ledger_json]
                    kv_new = {k: self._digest(v) for k, v in kv_json.items()}
                    kv_changed = {k: kv_json[k] for k, d in kv_new.items() if disk["kv"].get(k) != d}
                    n = len(dev_changed) + len(dev_deleted) + len(led_changed) + len(led_deleted) + len(kv_changed)
                    if n == 0 and not self._legacy_json_pending:
                        # Flash wear: nothing changed since the last write -> no write at all.
                        self.flushes_skipped_unchanged += 1
                        return 0
                    state_store.write_changes(self.state_path, dev_changed, dev_deleted,
                                              {k: v for k, (v, _) in led_changed.items()}, led_deleted, kv_changed)
                    for k in dev_changed:
                        disk["devices"][k] = dev_new[k]
                    for k in dev_deleted:
                        disk["devices"].pop(k, None)
                    for k, (_, d) in led_changed.items():
                        disk["ledger"][k] = d
                    for k in led_deleted:
                        disk["ledger"].pop(k, None)
                    for k in kv_changed:
                        disk["kv"][k] = kv_new[k]
                    if self._legacy_json_pending:
                        legacy = state_store.legacy_json_path(self.state_path)
                        try:
                            if legacy.exists():
                                legacy.replace(legacy.with_name(legacy.name + ".pre-sqlite"))
                        except OSError as exc:
                            LOGGER.warning("Migrated state to SQLite but could not rename %s: %s", legacy, exc)
                        self._legacy_json_pending = False
                        LOGGER.info("State migrated from %s to %s", legacy, state_store.db_path_for(self.state_path))
                    return n

            written, timed_out = self._bounded_io(_write_changed_rows, timeout=self._FLUSH_IO_TIMEOUT_SECONDS)
            if timed_out:
                # The transaction either commits on the abandoned thread (and updates the row digests there) or
                # never does -- the database is never left half-written.
                with self._global_lock:
                    self._ledger_dirty |= ledger_dirty
                LOGGER.error(
                    "StateManager flush to %s did not complete within %.0fs (likely "
                    "a kernel-level I/O stall under memory pressure) -- abandoning "
                    "this flush attempt rather than blocking the caller.",
                    state_store.db_path_for(self.state_path), self._FLUSH_IO_TIMEOUT_SECONDS,
                )
                return False

            self.rows_written_last_flush = written or 0
            if written:
                LOGGER.info("StateManager flushed %d changed row(s) (%d devices in memory) to %s", written,
                            len(devices_snapshot), state_store.db_path_for(self.state_path))
            else:
                LOGGER.debug("StateManager flush: nothing changed")

            if self._graph_store is not None:
                self._mirror_graph_metadata(graph_metadata_snapshot)

            return True
        except Exception as exc:
            with self._global_lock:
                self._ledger_dirty |= locals().get("ledger_dirty", set())
            LOGGER.error("Failed to flush state store to %s: %s", self.state_path, exc)
            return False

    def _mirror_graph_metadata(self, graph_metadata_snapshot: Dict[str, dict]) -> None:
        """v13 full-architecture plan, device-state unification: best-effort,
        write-only mirror of each device's COLD state fields into
        GraphStore.update_device_metadata() -- extends the SAME durable-mirror
        pattern src/v13/identity/live_manager.py already established for MAC/IP
        history to the rest of a device's cold identity/audit fields (hostname,
        device_type, confirmed_threat_count, fp_count, etc.). Deliberately never
        read back on any hot path -- flush_to_disk()'s local DeviceState/
        state write above stays the sole, unchanged, in-memory-then-disk
        source of truth for everything this class does; this call happens strictly
        AFTER that write succeeds, and a failure here (a single device's graph
        write, or the whole loop) never affects flush_to_disk()'s own return
        value -- the local flush already completed successfully by the time this
        runs. Runs at most once per flush_to_disk() call (already throttled to
        once/60s by every real caller), not on any per-cycle hot path."""
        for dev_id, metadata in graph_metadata_snapshot.items():
            try:
                self._graph_store.update_device_metadata(dev_id, metadata)
            except Exception as exc:
                LOGGER.debug("Device-state graph mirror failed for %r: %s", dev_id, exc)

    save_to_disk = flush_to_disk

    def reconcile_ips_from_disk(self) -> bool:
        """Re-reads ONLY the IPS state (tarpit targets, router isolations, released devices)
        from disk into live memory. Called by the pipeline when the IPC sentinel file is
        detected, pulling in releases executed by the Uvicorn subprocess without touching
        device baselines or re-loading all 5000 device profiles.
        """
        try:
            rows = state_store.read_rows(self.state_path, tables=("kv", "ledger"))
            if rows is not None:
                disk_ips = json.loads(rows["kv"].get("ips_state", "{}"))
                ledger_raw = rows["ledger"]
                disk_ledger = {k: json.loads(v) for k, v in ledger_raw.items()}
            else:
                legacy = state_store.legacy_json_path(self.state_path)
                if not legacy.exists():
                    return False
                raw = json.loads(legacy.read_text(encoding="utf-8"))
                disk_ips = raw.get("ips_state", {})
                disk_ledger = raw.get("action_ledger", {})
                ledger_raw = None
            if not disk_ips and not disk_ledger:
                return False
            with self._global_lock:
                # Merge only IPS state keys; preserve keys not written by Uvicorn
                for key in ("tarpit_targets", "router_isolated_devices", "operator_released_devices",
                            "blocked_domains", "isolated_macs", "retry_queue", "dead_letter"):
                    if key in disk_ips:
                        self._ips_state[key] = disk_ips[key]
                # PHASE 3: pull in action-ledger writes made by the IPC subprocess (e.g. a
                # Telegram [Revoke] tap handled by /api/ipc/revoke) before the next periodic
                # flush would otherwise overwrite disk with this process's stale in-memory
                # copy and silently lose the revoke.
                if disk_ledger:
                    self._action_ledger = disk_ledger
                    self._ledger_entry_json.clear()
                    if ledger_raw is not None:
                        with self._flush_lock:
                            self._ledger_entry_json.update(ledger_raw)
                            self._disk_digest["ledger"] = {k: self._digest(v) for k, v in ledger_raw.items()}
                            self._ledger_dirty.clear()
                    else:
                        self._ledger_dirty = set(disk_ledger)
            LOGGER.info("🔄 IPS state reconciled from disk after external IPC release signal.")
            return True
        except Exception as exc:
            LOGGER.error("Failed to reconcile IPS state from disk: %s", exc)
            return False
