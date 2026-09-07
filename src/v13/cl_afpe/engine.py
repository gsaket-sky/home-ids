"""
v13 CL-AFPE (Phase 4 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

HONEST SCOPE NOTE (read this before assuming parity with v-current):
intelligence/fp_engine.py is 2,847 lines covering many concerns beyond trust-cache
scoping -- local confirmed-intel poisoning protection, per-device threshold
profiles (CONNECTION_ABUSE arp-sweep/long-conn/rejected-connection threshold
bumping), sigma-shift EWMA widening, ML model (LightGBM/FastEmbed) management, and
training-data write-back to autonomous_muted.jsonl for train_fp_classifier.py. The
plan scopes v13's CL-AFPE specifically to "trust/immunization scoping as native
graph edges" -- THIS FILE PORTS THAT AND ONLY THAT, PLUS THE TWO REFUSAL GUARDS AND
BASELINE FAMILIARITY. Deliberately NOT ported here (tracked as separate, real,
not-yet-scoped future work in the dependency map, not silently dropped):
  - Per-device threshold bumping (mark_false_positive()'s CONNECTION_ABUSE branch)
  - Local confirmed-intel poisoning protection (local_intel.py integration)
  - Sigma-shift EWMA widening (_apply_sigma_shift)
  - ML model training/inference, muted-log training-data write-back

WHAT'S PORTED, faithfully, from fp_engine.py (read directly, not guessed):
  - _immunize_domain()/revoke_immunization()/_is_trust_cached()/get_dynamic_trust_cache()
    (lines 871-891, 1504-1624, 2418-2453) -- redesigned as graph 'trusts' edges
    (device --trusts--> destination, metadata carries source/hypothesis/ttl_seconds)
    instead of a dict-shape-agnostic _trust_cache, per the plan's own stated design.
  - DEVICE_SCOPED_TRUST_HYPOTHESES (lines 139-156) -- copied exactly.
  - mark_false_positive()'s two refusal guards (Phase 64c device-identity check,
    lines 1698-1723; hard-stop-signature refusal, lines 1739-1761) and the DEFAULT
    domain/IP immunization routing (lines 1869-1908).
  - get_baseline_familiarity() (lines 2225-2246) -- ported using this module's own
    lightweight per-device observation counters, mirroring v1's
    _device_fp_profiles[device_id]['_baseline'] structure conceptually (v13 doesn't
    yet have a v13-native per-device-profile store beyond this).

v13 full-architecture plan, Phase 6a/6c (added after this module's initial Phase 4
build, once it was confirmed dormant -- nothing called ClAfpeEngine outside its own
tests): per-device threshold bumping and sigma-shift widening, read directly from
fp_engine.py's real mark_false_positive() (lines 1626-1914) and _apply_sigma_shift()
rather than guessed from this module's own earlier scope note above. Confirmed via
that read: the CONNECTION_ABUSE/PORT_SCAN/INTERNAL_RECONNAISSANCE branch is a
genuine `elif`, mutually exclusive with the default domain/IP immunization branch
below it (a real bugfix in v1's own history: immunizing an "unknown" domain for a
signature type with no meaningful domain used to keep re-suppressing the same FP
forever) -- and _apply_sigma_shift() fires unconditionally AFTER whichever branch
ran, not tied to either one specifically. Per-device threshold values and the
cumulative sigma shift are both stored via GraphStore.update_device_metadata()/
get_device_metadata() (Phase 3) -- a per-device JSON blob under 'fp_profile'/
'sigma_shift' keys, the graph-native equivalent of v1's own flat
device_fp_profiles.json/fp_sigma_shifts.json files.
"""
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from v13.graph.store import GraphStore
from v13.evidence.model import NO_DESTINATION

# Matches fp_engine.py's constants exactly.
TRUST_CACHE_TTL_SECONDS = 14 * 24 * 3600
MIN_TRUST_ENTRY_TTL_SECONDS = 3600
MAX_TRUST_ENTRY_TTL_SECONDS = TRUST_CACHE_TTL_SECONDS

# Matches fp_engine.py:154-156 exactly -- hypotheses whose benign correction is a
# claim about THIS DEVICE's own behavior, not the destination's general safety.
DEVICE_SCOPED_TRUST_HYPOTHESES = frozenset({
    "DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS",
})

# Matches fp_engine.py's _HARD_STOP_SIGNATURES exactly (line 1739-1745).
_HARD_STOP_SIGNATURES = frozenset({
    "Internal Honeypot Accessed",
    "Layer-2 ARP Spoofing Detected",
    "Geofencing Policy Violation",
    "Confirmed Exploit/Malware Signature (Suricata)",
    "Confirmed Malicious IOC",
})

# Matches fp_engine.py's own signature set for the per-device-threshold branch
# exactly (line 1790) -- PORT_SCAN/INTERNAL_RECONNAISSANCE are
# ConnectionAbuseHypothesis's own dynamic names (hypotheses/engine.py) for a
# single-category finding; the branches below inspect raw feature values
# directly, never the signature string itself, so all three route identically.
_CONNECTION_ABUSE_SIGNATURES = frozenset({"CONNECTION_ABUSE", "PORT_SCAN", "INTERNAL_RECONNAISSANCE"})

# Matches fp_engine.py's sigma-shift constants exactly (module-level in that file).
# Asymmetric by design, confirmed via direct read, not assumed symmetric: widening
# (TUNE_DOWN, a correction) is a small step with a wide cap; tightening (TUNE_UP, a
# confirmed threat) is a bigger flat step with a narrower floor -- a real threat
# should sharpen sensitivity faster than a single correction should relax it.
SIGMA_WIDENING_STEP = 0.25
MAX_SIGMA_SHIFT = 2.0
_SIGMA_TIGHTEN_STEP = 0.50
_MIN_SIGMA_SHIFT = -1.5

# Matches fp_engine.py's own default (referenced by get_baseline_familiarity's
# docstring; the exact constant _BASELINE_FAMILIARITY_OBSERVATIONS wasn't in the
# section read this session -- 5 is the value cited by hypotheses/engine.py's own
# FAMILIARITY_TRUST_BAR=0.6 comment, "3 of 5 observations", so 5 is confirmed via
# that cross-reference, not guessed independently).
BASELINE_FAMILIARITY_OBSERVATIONS = 5


def _strip_persistence_suffix(signature: Optional[str]) -> Optional[str]:
    """Matches fp_engine.py's _trust_entry_hypothesis_base()/mark_false_positive()'s
    own signature_base stripping exactly (e.g. 'DNS_EVASION (persisted 603s)' ->
    'DNS_EVASION')."""
    if not signature:
        return None
    return signature.split(" (persisted ", 1)[0] or None


@dataclass
class MarkFalsePositiveResult:
    refused: bool = False
    refused_reason: str = ""
    is_new_immunization: bool = False
    immunized_destination: str = ""
    threshold_bumped: bool = False


class ClAfpeEngine:
    def __init__(self, store: GraphStore, resolve_canonical_device_id=None, has_device=None):
        self.store = store
        # Both optional/defaulted, same pattern fp_engine.py's own state_manager
        # dependency uses -- a no-op device-identity check when not supplied.
        self._resolve_canonical_device_id = resolve_canonical_device_id or store.resolve_canonical_device_id
        self._has_device = has_device or (lambda device_id: self.store._conn.execute(
            "SELECT 1 FROM devices WHERE device_id = ?", (device_id,)).fetchone() is not None)
        self._baseline_observations: Dict[str, Dict[str, Dict[str, int]]] = {}

    # --- trust cache / immunization (graph 'trusts' edges) ----------------------

    def immunize(self, destination_id: str, device_id: Optional[str] = None,
                  hypothesis: Optional[str] = None, source: str = "autonomous",
                  ttl_seconds: Optional[float] = None, now: Optional[float] = None) -> bool:
        """Matches _immunize_domain()'s validation/TTL-clamping/refresh semantics
        exactly. Returns True for a genuinely new immunization, False for a refresh
        of an already-immunized destination (matching v1's own return contract)."""
        if not destination_id or str(destination_id).lower() in ("unknown", "null", "none", NO_DESTINATION):
            return False
        now = now if now is not None else time.time()

        entry_ttl = None
        if ttl_seconds is not None:
            try:
                ttl_val = float(ttl_seconds)
                if ttl_val > 0:
                    entry_ttl = min(max(ttl_val, MIN_TRUST_ENTRY_TTL_SECONDS), MAX_TRUST_ENTRY_TTL_SECONDS)
            except (TypeError, ValueError):
                entry_ttl = None
        hypothesis_base = _strip_persistence_suffix(hypothesis)

        existing = self.store.get_edges(relation="trusts", dst_id=destination_id)
        is_new = len(existing) == 0
        # A refresh replaces the existing edge rather than accumulating duplicates.
        for e in existing:
            self.store.delete_edge(e["edge_id"])

        metadata: Dict[str, Any] = {"source": source}
        if device_id and device_id != "unknown":
            metadata["device_id"] = device_id
        if hypothesis_base:
            metadata["hypothesis"] = hypothesis_base
        if entry_ttl is not None:
            metadata["ttl_seconds"] = entry_ttl

        self.store.upsert_destination(destination_id, "domain", timestamp=now)
        src_id = device_id if (device_id and device_id != "unknown") else "unattributed"
        self.store.upsert_device(src_id, timestamp=now)
        self.store.add_edge("device", src_id, "destination", destination_id, "trusts", timestamp=now, metadata=metadata)
        return is_new

    def revoke(self, destination_id: str) -> bool:
        existing = self.store.get_edges(relation="trusts", dst_id=destination_id)
        for e in existing:
            self.store.delete_edge(e["edge_id"])
        return len(existing) > 0

    def _active_trust_edges(self, destination_id: Optional[str] = None, now: Optional[float] = None):
        now = now if now is not None else time.time()
        edges = self.store.get_edges(relation="trusts", dst_id=destination_id) if destination_id else self.store.get_edges(relation="trusts")
        active = []
        for e in edges:
            ttl = e["metadata"].get("ttl_seconds") or TRUST_CACHE_TTL_SECONDS
            if (now - e["timestamp"]) < ttl:
                active.append(e)
        return active

    def get_dynamic_trust_cache(self, now: Optional[float] = None) -> set:
        """Matches get_dynamic_trust_cache() exactly: every currently-active
        immunized destination, globally unscoped -- deliberately not filtered by
        device/hypothesis, same as v1's own documented choice for this consumer."""
        return {e["dst_id"] for e in self._active_trust_edges(now=now)}

    def is_trust_cached(self, destination_id: str, device_id: Optional[str] = None,
                          hypothesis: Optional[str] = None, now: Optional[float] = None) -> bool:
        """Matches _is_trust_cached() exactly: requires the SAME hypothesis on reuse
        (a recorded hypothesis is a real scoping fact, not a wildcard -- only a
        MISSING recorded hypothesis is a wildcard), and additionally the SAME device
        for DEVICE_SCOPED_TRUST_HYPOTHESES."""
        active = self._active_trust_edges(destination_id, now=now)
        if not active:
            return False
        hypothesis_base = _strip_persistence_suffix(hypothesis)
        for e in active:
            recorded_hypothesis = e["metadata"].get("hypothesis")
            if recorded_hypothesis and recorded_hypothesis != hypothesis_base:
                continue
            if recorded_hypothesis in DEVICE_SCOPED_TRUST_HYPOTHESES:
                if e["metadata"].get("device_id") != device_id:
                    continue
            return True
        return False

    # --- sigma-shift widening (Phase 6c) -----------------------------------------

    def _apply_sigma_shift(self, device_id: str, direction: str = "TUNE_DOWN",
                             source: str = "autonomous", now: Optional[float] = None) -> None:
        """Matches fp_engine.py's _apply_sigma_shift() exactly: TUNE_DOWN (a
        correction -- widen sensitivity) steps by +SIGMA_WIDENING_STEP capped at
        MAX_SIGMA_SHIFT; TUNE_UP (a confirmed threat -- tighten sensitivity) steps
        by a flat -0.50 floored at -1.5 (deliberately NOT SIGMA_WIDENING_STEP-based
        -- confirmed via direct read this asymmetry is real, not an oversight).
        Best-effort: a device_id of "unknown"/empty is a no-op, matching v1's own
        guard against widening a shift nothing is tracked under."""
        if not device_id or device_id == "unknown":
            return
        now = now if now is not None else time.time()
        current = self.get_sigma_shift(device_id)
        if direction == "TUNE_UP":
            new_val = max(current - _SIGMA_TIGHTEN_STEP, _MIN_SIGMA_SHIFT)
        else:
            new_val = min(current + SIGMA_WIDENING_STEP, MAX_SIGMA_SHIFT)
        self.store.update_device_metadata(device_id, {"sigma_shift": new_val}, timestamp=now)

    def get_sigma_shift(self, device_id: str) -> float:
        """Matches get_sigma_shift() exactly -- cumulative shift, default 0.0."""
        if not device_id or device_id == "unknown":
            return 0.0
        try:
            return float(self.store.get_device_metadata(device_id).get("sigma_shift", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    # --- per-device threshold profile (Phase 6a) ---------------------------------

    def apply_device_fp_profile(self, device_id: str, key: str, value: float, baseline: float,
                                  set_by: str, reason: str, sample_count: int = 0,
                                  hostname: str = "", now: Optional[float] = None) -> None:
        """Matches apply_device_fp_profile() exactly: merges ONE key into the
        device's profile (preserves all other keys/devices -- reads the full
        existing 'fp_profile' dict first since update_device_metadata()'s merge is
        shallow at the top level only), increments (not overwrites)
        correction_count."""
        now = now if now is not None else time.time()
        meta = self.store.get_device_metadata(device_id)
        profile = dict(meta.get("fp_profile", {}) or {})
        existing = profile.get(key) or {}
        profile[key] = {
            "value": value, "baseline": baseline, "set_at": now, "set_by": set_by,
            "reason": reason, "sample_count": sample_count, "hostname": hostname,
            "correction_count": int(existing.get("correction_count", 0) or 0) + 1,
        }
        self.store.update_device_metadata(device_id, {"fp_profile": profile}, timestamp=now)

    def _get_device_profile_value(self, device_id: str, key: str, default: float) -> float:
        entry = self.store.get_device_metadata(device_id).get("fp_profile", {}).get(key)
        if not entry:
            return default
        try:
            return float(entry.get("value", default))
        except (TypeError, ValueError):
            return default

    def get_device_arp_sweep_threshold(self, device_id: str, default: float = 8.0) -> float:
        return self._get_device_profile_value(device_id, "arp_sweep_unique_targets_threshold", default)

    def get_device_conn_abuse_unique_ip_threshold(self, device_id: str, default: float = 5.0) -> float:
        return self._get_device_profile_value(device_id, "conn_abuse_unique_ip_threshold", default)

    def get_device_long_conn_duration_threshold(self, device_id: str, default: float = 14400.0) -> float:
        return self._get_device_profile_value(device_id, "long_conn_duration_threshold", default)

    # --- mark_false_positive(): refusal guards + threshold-bump + default routing

    def mark_false_positive(self, alert_payload: dict, source: str = "operator",
                              ttl_seconds: Optional[float] = None,
                              now: Optional[float] = None) -> MarkFalsePositiveResult:
        now = now if now is not None else time.time()
        signature = alert_payload.get("signature", "")
        device_id = alert_payload.get("device", {}).get("id", "unknown")
        hostname = alert_payload.get("device", {}).get("hostname", "") or ""

        # Phase 64c device-identity refusal, ported exactly.
        if device_id and device_id != "unknown":
            canonical = self._resolve_canonical_device_id(device_id)
            if not self._has_device(canonical):
                return MarkFalsePositiveResult(
                    refused=True,
                    refused_reason=f"device_id '{device_id}' is not a currently-known canonical device.",
                )

        # Hard-stop-signature refusal, ported exactly.
        signature_base = _strip_persistence_suffix(signature) or ""
        if signature_base in _HARD_STOP_SIGNATURES:
            return MarkFalsePositiveResult(
                refused=True,
                refused_reason=f"'{signature}' is a hard-stop verdict — cannot be marked false positive.",
            )

        is_new = False
        target = ""
        threshold_bumped = False

        if signature_base in _CONNECTION_ABUSE_SIGNATURES:
            # Ported exactly from fp_engine.py:1790-1868 -- a genuine `elif`, NOT a
            # fall-through to the default domain-immunization branch below (a real
            # v1 bugfix: immunizing an "unknown" domain for a signature type with
            # no meaningful domain used to keep re-suppressing the same FP
            # forever). Inspects the SAME features this alert's own evidence was
            # computed from and bumps every threshold whose condition is still
            # true for THIS alert -- never just one blind guess. Bumping an
            # unrelated threshold that wasn't the cause is harmless; missing the
            # real cause is what kept the v1 bug alive.
            feats = alert_payload.get("features", {}) or {}
            s0_rej = float(feats.get("zeek_s0_rej_count", 0.0) or 0.0)
            s0_rej_unique = float(feats.get("zeek_s0_rej_unique_ips", 0.0) or 0.0)
            max_dur = float(feats.get("zeek_max_duration", 0.0) or 0.0)
            arp_count = float(feats.get("zeek_arp_sweep_count", 0.0) or 0.0)

            bumped_any = False
            current_unique_ip = self.get_device_conn_abuse_unique_ip_threshold(device_id)
            if s0_rej > 25 and s0_rej_unique > current_unique_ip:
                self.apply_device_fp_profile(
                    device_id, "conn_abuse_unique_ip_threshold", current_unique_ip + 4.0,
                    baseline=current_unique_ip, set_by=source, hostname=hostname,
                    sample_count=1, now=now,
                    reason=f"Corrected {signature_base} alert for {hostname or device_id} "
                           f"(zeek_conn_abuse/s0_rej evidence) -- raising this device's own "
                           f"rejected-connection unique-IP threshold instead of the global default.",
                )
                bumped_any = True
            current_long_conn = self.get_device_long_conn_duration_threshold(device_id)
            if max_dur > current_long_conn:
                self.apply_device_fp_profile(
                    device_id, "long_conn_duration_threshold", current_long_conn * 1.5,
                    baseline=current_long_conn, set_by=source, hostname=hostname,
                    sample_count=1, now=now,
                    reason=f"Corrected {signature_base} alert for {hostname or device_id} "
                           f"(zeek_long_conn evidence) -- raising this device's own "
                           f"long-connection duration threshold.",
                )
                bumped_any = True
            if arp_count > 0:
                current_arp = self.get_device_arp_sweep_threshold(device_id)
                self.apply_device_fp_profile(
                    device_id, "arp_sweep_unique_targets_threshold", current_arp + 4.0,
                    baseline=current_arp, set_by=source, hostname=hostname,
                    sample_count=1, now=now,
                    reason=f"Corrected {signature_base} alert for {hostname or device_id} "
                           f"(arp_sweep evidence) -- raising this device's own ARP-sweep "
                           f"threshold instead of the global default.",
                )
                bumped_any = True
            if not bumped_any:
                # None of the three conditions still hold against this alert's own
                # feature snapshot -- fall back to the old blanket behavior rather
                # than silently doing nothing, matching v1 exactly.
                current_arp = self.get_device_arp_sweep_threshold(device_id)
                self.apply_device_fp_profile(
                    device_id, "arp_sweep_unique_targets_threshold", current_arp + 4.0,
                    baseline=current_arp, set_by=source, hostname=hostname,
                    sample_count=1, now=now,
                    reason=f"Corrected {signature_base} alert for {hostname or device_id} -- "
                           f"no evidence-specific features available on this alert, falling "
                           f"back to the ARP-sweep threshold.",
                )
            threshold_bumped = True
        else:
            # Default domain/IP immunization routing (fp_engine.py:1869-1908).
            domain = alert_payload.get("network_context", {}).get("queried_domain", "") or ""
            dest_ip = alert_payload.get("network_context", {}).get("destination_ip", "") or ""
            target = domain if (domain and domain != "unknown") else (dest_ip if dest_ip and dest_ip != "unknown" else "")
            if target:
                is_new = self.immunize(target, device_id=device_id, hypothesis=signature,
                                         source=source, ttl_seconds=ttl_seconds, now=now)

        # Runs regardless of which branch above fired -- a general behavioral
        # dampener, not specific to domain-based corrections (matches v1's own
        # placement exactly, fp_engine.py:1914).
        self._apply_sigma_shift(device_id, source=source, now=now)

        return MarkFalsePositiveResult(refused=False, is_new_immunization=is_new,
                                         immunized_destination=target, threshold_bumped=threshold_bumped)

    # --- baseline familiarity ----------------------------------------------------

    def record_baseline_observation(self, device_id: str, *, dest_port=None,
                                       asn_owner: Optional[str] = None,
                                       domain_base: Optional[str] = None) -> None:
        """Matches fp_engine.py's own safety invariant: callers must only record
        from cycles already classified BENIGN/ANOMALOUS -- this module doesn't
        enforce that itself (no decision context available here), same as v1's
        get_baseline_familiarity() docstring describing it as the CALLER's
        responsibility (pipeline.py in v-current)."""
        if not device_id or device_id == "unknown":
            return
        bucket = self._baseline_observations.setdefault(device_id, {"ports": {}, "asn_owners": {}, "domain_bases": {}})
        for kind, key in (("ports", dest_port), ("asn_owners", asn_owner), ("domain_bases", domain_base)):
            if key is None or key == "" or key == "unknown" or key == 0:
                continue
            bucket[kind][str(key)] = bucket[kind].get(str(key), 0) + 1

    def get_baseline_familiarity(self, device_id: str, *, dest_port=None,
                                    asn_owner: Optional[str] = None,
                                    domain_base: Optional[str] = None) -> float:
        """Matches get_baseline_familiarity() exactly: highest familiarity across
        whichever identity dimensions are supplied, 0.0-1.0."""
        if not device_id or device_id == "unknown":
            return 0.0
        bucket = self._baseline_observations.get(device_id, {})
        best = 0.0
        for kind, key in (("ports", dest_port), ("asn_owners", asn_owner), ("domain_bases", domain_base)):
            if key is None or key == "" or key == "unknown" or key == 0:
                continue
            count = bucket.get(kind, {}).get(str(key), 0)
            best = max(best, min(1.0, count / float(BASELINE_FAMILIARITY_OBSERVATIONS)))
        return best
