"""
state_guard.py - Thread-Safe Device State Guard & Persistence Manager.

Guarantees thread-safe access to physical device state matrices across parallel
event loops, async ML retrains, and background serialization routines.

RECENT FIXES:
- ADDED (LOGGING): Debug events tracked at lock acquisitions, migrations, and flushes.
"""

import json
import logging
import threading
import time
import copy
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional, Dict, List, Any

from core.state import DeviceState
from core.device_matching import (
    dhcp_fingerprint_match,
    ja3_overlap,
    hostname_corroborates,
    match_confidence,
    MIN_CANDIDATE_CONFIDENCE,
    AUTO_MERGE_CONFIDENCE,
)

LOGGER = logging.getLogger("home_ids.state_guard")


class StateManager:
    def __init__(self, state_path: str = "state/ids_state.json", max_devices: int = 5000):
        self.state_path = Path(state_path)
        self.max_devices = max_devices
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
        # AUDIT FIX #7: Reverse IP → device_id index for O(1) update_device_mac()
        self._ip_to_device_id: Dict[str, str] = {}
        # PHASE 3 (closed-loop autonomous actions): revocable-action ledger. Records
        # autonomous actions (currently: immunize_domain) that a human can undo with a
        # one-tap Telegram [Revoke] button. Same persistence pattern as _ips_state —
        # rides along with the existing flush_to_disk/load_from_disk machinery.
        self._action_ledger: Dict[str, Dict[str, Any]] = {}
        # PHASE 6 (cross-address-family identity correlation): MAC address -> canonical
        # device_id. A MAC address is protocol-family-agnostic (captured at L2), unlike
        # `client_ip`-anchored device_id resolution, which was blind to the fact that the
        # same physical device's IPv4 and IPv6 traffic are genuinely the same device. When
        # a MAC is known for a NEW packet, identity.py checks this index BEFORE computing
        # a fresh IP-anchored device_id, so all of a device's address families unify into
        # one DeviceState instead of each cold-starting its own permanently-separate profile.
        self._mac_to_device_id: Dict[str, str] = {}
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
                       dhcp_fingerprint: Optional[Dict[str, Any]] = None, ja3_set: Optional[set] = None,
                       reidentify: bool = True, min_confidence: float = AUTO_MERGE_CONFIDENCE,
                       candidate_window: float = 1800.0) -> DeviceState:
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
                # happened to cold-start from, so update_device_mac()'s O(1) lookup (and any
                # other by-IP reverse lookup) would silently miss this address family.
                self._ip_to_device_id[client_ip] = device_id
                self._states.move_to_end(device_id)
                return state

            # PHASE 4 (MAC-rotation resilience): before cold-starting a brand-new identity,
            # check whether this looks like a device we already know under a different
            # IP/MAC (e.g. a DHCP client-identifier rotation) rather than a genuinely new
            # device. Only attempts this when the caller supplied a fresh fingerprint to
            # compare — callers that don't care about re-identification (or that predate
            # this feature) get identical cold-start behavior to before.
            if reidentify and (dhcp_fingerprint or ja3_set):
                matched_old_id = self._find_reidentify_candidate(
                    exclude_ip=client_ip, hostname=hostname,
                    dhcp_fingerprint=dhcp_fingerprint, ja3_set=ja3_set,
                    min_confidence=min_confidence, candidate_window=candidate_window,
                )
                if matched_old_id:
                    self.migrate_device_id(matched_old_id, device_id)
                    state = self._states[device_id]
                    state.client_ip = client_ip
                    if hostname and hostname != "unknown":
                        state.hostname = hostname
                    self._ip_to_device_id[client_ip] = device_id
                    LOGGER.warning(
                        "🔗 IDENTITY RE-LINKED: %s -> %s (hostname=%s, ip=%s) — matched via "
                        "DHCP/JA3/hostname fingerprint, treating as a MAC rotation of a known "
                        "device rather than a cold start.", matched_old_id, device_id, hostname, client_ip
                    )
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
                                     dhcp_fingerprint: Optional[Dict[str, Any]], ja3_set: Optional[set],
                                     min_confidence: float, candidate_window: float) -> Optional[str]:
        """Scans currently-tracked devices for one that plausibly IS the new device under
        its old identity — i.e. it just went quiet (not still active, not ancient history;
        that's what the weekly prune sweep is for) and its DHCP/JA3/hostname fingerprint
        matches. Must be called with self._global_lock already held (it iterates
        self._states without re-locking). O(N) in device count — only runs on the
        cold-start path, never per-packet, so this is cheap even at max_devices capacity.
        """
        now = time.time()
        best_id, best_conf = None, 0.0
        ja3_set = ja3_set or set()

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
            ja3_sim = ja3_overlap(ja3_set, set(getattr(cand_state, "ja3_seen", []) or []))
            host_ok = hostname_corroborates(hostname, getattr(cand_state, "hostname", ""))

            conf = match_confidence(dhcp_score, ja3_sim, host_ok)
            if conf >= MIN_CANDIDATE_CONFIDENCE:
                LOGGER.info(
                    "🔎 Re-identification candidate: %s (hostname=%s) confidence=%.2f "
                    "(dhcp=%.2f ja3_overlap=%.2f hostname_match=%s, idle=%.0fs)",
                    cand_id, getattr(cand_state, "hostname", "?"), conf, dhcp_score, ja3_sim, host_ok, age
                )
            if conf > best_conf:
                best_conf, best_id = conf, cand_id

        if best_id and best_conf >= min_confidence:
            return best_id
        return None

    def update_device_mac(self, client_ip: str, mac_address: str) -> None:
        """Dynamically binds real-time MAC updates from Zeek/ARP to the device profile.
        AUDIT FIX #7: O(1) lookup via reverse IP index instead of O(N) linear scan.
        """
        if not client_ip or not mac_address or mac_address == "unknown":
            return
        with self._global_lock:
            device_id = self._ip_to_device_id.get(client_ip)
            if device_id:
                state = self._states.get(device_id)
                if state:
                    state.mac_address = mac_address
                    self._mac_to_device_id[mac_address] = device_id  # PHASE 6
                    LOGGER.debug("Updated MAC binding for IP %s -> %s", client_ip, mac_address)
            else:
                # Fallback: linear scan for IPs not yet in index (e.g., after restart)
                for state in self._states.values():
                    if getattr(state, "client_ip", "") == client_ip:
                        state.mac_address = mac_address
                        self._ip_to_device_id[client_ip] = state.device_id
                        self._mac_to_device_id[mac_address] = state.device_id  # PHASE 6
                        LOGGER.debug("Updated MAC binding (fallback scan) for IP %s -> %s", client_ip, mac_address)
                        break

    def register_existing_state(self, state: DeviceState) -> None:
        with self._global_lock:
            device_id = state.device_id
            self._states[device_id] = state
            self._states.move_to_end(device_id)
            # Keep reverse index in sync
            self._ip_to_device_id[state.client_ip] = device_id
            self._prune_lru_capacity()
            LOGGER.debug("Existing state registered into manager memory for %s.", device_id)

    def has_device(self, device_id: str) -> bool:
        with self._global_lock:
            return device_id in self._states

    def migrate_device_id(self, old_id: str, new_id: str) -> bool:
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
            # Scans the index itself (not just old_state.mac_address) so this stays
            # correct even if a device somehow accumulated more than one bound MAC.
            for mac_key, mapped_id in list(self._mac_to_device_id.items()):
                if mapped_id == old_id:
                    self._mac_to_device_id[mac_key] = new_id
            mac = getattr(old_state, "mac_address", "unknown")
            if mac and mac != "unknown":
                self._mac_to_device_id[mac] = new_id

            hostname = getattr(old_state, "hostname", "unknown")
            client_ip = getattr(old_state, "client_ip", "unknown")
            
            LOGGER.info("Successfully migrated DeviceState tracking profile for %s (%s)", hostname, client_ip)
            return True

    def get_all_device_ids(self) -> List[str]:
        with self._global_lock:
            return list(self._states.keys())

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
        """Records an autonomous action (e.g. an fp_engine domain immunization) so an
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
                    client_ip = getattr(state, "client_ip", "")
                    if client_ip in self._ip_to_device_id:
                        del self._ip_to_device_id[client_ip]
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

    def load_from_disk(self, alpha: float = 0.05) -> int:
        if not self.state_path.exists():
            LOGGER.info("No existing state file found at %s. Starting fresh store.", self.state_path)
            self.load_historical_ledger()
            return 0

        try:
            LOGGER.debug("Reading state snapshot from %s", self.state_path)
            raw_text = self.state_path.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            
            with self._global_lock:
                self._states.clear()
                
                devices_data = data.get("devices", data) if isinstance(data, dict) and "devices" in data else data
                if isinstance(data, dict) and "ips_state" in data:
                    self._ips_state = data["ips_state"]
                if isinstance(data, dict) and "action_ledger" in data:
                    self._action_ledger = data["action_ledger"] or {}

                for dev_id, d in devices_data.items():
                    if dev_id in ("ips_state", "action_ledger"):
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
            
            self.load_historical_ledger()
                    
            loaded_count = len(self._states)
            LOGGER.info("Successfully loaded baselines for %d devices and IPS state from %s", loaded_count, self.state_path)
            return loaded_count
        except Exception as exc:
            LOGGER.error("Failed to load state store from %s: %s", self.state_path, exc)
            return 0

    def flush_to_disk(self) -> bool:
        try:
            LOGGER.debug("Acquiring global lock to initiate state file persistence.")
            with self._global_lock:
                devices_snapshot = {}
                for dev_id, state in self._states.items():
                    devices_snapshot[dev_id] = state.to_dict()

                full_snapshot = {
                    "ips_state": self._ips_state,
                    "devices": devices_snapshot,
                    "action_ledger": dict(self._action_ledger),
                }

            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.state_path.with_suffix(".tmp")
            
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(full_snapshot, f, separators=(",", ":"))
                
            tmp_path.replace(self.state_path)
            LOGGER.info("StateManager flushed state snapshot (%d devices, IPS state) to %s", len(devices_snapshot), self.state_path)
            return True
        except Exception as exc:
            LOGGER.error("Failed to flush state store to %s: %s", self.state_path, exc)
            return False

    save_to_disk = flush_to_disk

    def reconcile_ips_from_disk(self) -> bool:
        """Re-reads ONLY the IPS state (tarpit targets, router isolations, released devices)
        from disk into live memory. Called by the pipeline when the IPC sentinel file is
        detected, pulling in releases executed by the Uvicorn subprocess without touching
        device baselines or re-loading all 5000 device profiles.
        """
        try:
            if not self.state_path.exists():
                return False
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            disk_ips = raw.get("ips_state", {})
            disk_ledger = raw.get("action_ledger", {})
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
            LOGGER.info("🔄 IPS state reconciled from disk after external IPC release signal.")
            return True
        except Exception as exc:
            LOGGER.error("Failed to reconcile IPS state from disk: %s", exc)
            return False
    def reset_device_state(self, device_id: str):
        with self._global_lock:
            if device_id in self._states:
                state = self._states[device_id]
                state.seen_domains = BoundedSet(max_size=10000)
                state.geo_exported_ips = BoundedSet(max_size=5000)
                state.killchain_history = deque(maxlen=5)
                state.has_validated_threat = False
                state.confirmed_threat_count = 0
                state.fp_count = 0
                state.rate_baseline = EWMABaseline(alpha=state.rate_baseline.alpha)
                state.entropy_baseline = EWMABaseline(alpha=state.entropy_baseline.alpha)
                state.unique_baseline = EWMABaseline(alpha=state.unique_baseline.alpha)
                state.nxdomain_baseline = EWMABaseline(alpha=state.nxdomain_baseline.alpha)
                state.blocked_baseline = EWMABaseline(alpha=state.blocked_baseline.alpha)
                state.dga_baseline = EWMABaseline(alpha=state.dga_baseline.alpha)
                state.outbound_bytes_baseline = EWMABaseline(alpha=state.outbound_bytes_baseline.alpha)
                state.risk_baseline = EWMABaseline(alpha=state.risk_baseline.alpha)
                state.last_alert_time = 0.0
                state.last_alert_confidence = 0.0
                LOGGER.info("🧹 Fully reset in-memory state baselines for %s", device_id)
