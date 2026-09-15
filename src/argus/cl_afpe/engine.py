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

v13 full-architecture plan, Phase 6b: local-intel poisoning protection, ported from
fp_engine.py's real _is_ip_protected_from_confirmed_intel() (lines 909-965),
record_confirmed_threat() (967-1037), and Stage-1 Check 7's read-side logic
(1203-1240) -- read directly, not guessed. REUSES intelligence/local_intel.py's
real LocalConfirmedIntel class via constructor injection (same "inject the real
dependency" pattern RetroHunter already uses for threat_intel_lookup) rather than
reimplementing it -- `local_intel`/`safe_ips` are both optional (None/empty
default), matching this module's own existing graceful-degradation pattern for
`resolve_canonical_device_id`/`has_device`: a caller that hasn't wired a
LocalConfirmedIntel instance yet gets a safe no-op (record does nothing, the
hard-stop check never fires) rather than a hard requirement. Every guard found in
the real file is ported, since each one is a documented live-incident fix: known
public DNS resolvers, `safe_ips`, cloud/CDN-owned ASNs, private/multicast/loopback/
reserved IPs (write-side, in record_confirmed_threat), and telemetry-domain/IP-
protection re-checked on the READ side too (check_local_intel_hard_stop) so an
already-poisoned entry stops being honored immediately rather than waiting for its
TTL to lapse -- v1's own real bugfix history (8.8.8.8, this network's own IDS box,
mDNS multicast addresses, and 357 cloud/CDN IPs were all found poisoned in
production before these guards existed).

v13 full-architecture plan, Phase 6e: the composed `evaluate()` below wires
everything above (6a-6d) into ONE end-to-end verdict, mirroring fp_engine.py's real
`evaluate()` (line 397) faithfully -- trust-cache fast path (460-539), Stage 1
hard-stop (541-588, `_stage1_hard_stop` at 1088), Stage 2/3 ML scoring (590-682,
`ml_scoring.py`), and the final suppress/uncertain/confirmed-threat branch
(690-870) including `get_device_suppress_threshold()` (2043-2056, now ported as a
thin wrapper over the same `_get_device_profile_value()` Phase 6a already built).

TWO DELIBERATE, DOCUMENTED SCOPE DECISIONS for Stage 1, found necessary once the
real `_stage1_hard_stop()` (1088-1241) was read in full for this phase (not
assumed from this module's own earlier docstring paragraphs above):
  - Check 0 (decision_engine.py's own hard-stop verdict) reuses v13's OWN
    already-computed `decision["state"] == "CRITICAL"`, exactly like v1's Check 0
    reuses v-current's decision_engine.py -- the two engines are the SAME kind of
    dependency here, not a shortcut.
  - Checks 1-6 (ThreatIntel IOC, lateral movement, malicious JA3/JA4 TLS, honeypot,
    AbuseIPDB, exfiltration burst) are each RE-PORTED here reading `features`
    directly, NOT approximated via v13's own decision state. Confirmed via a direct
    read of decision/engine.py's DEFAULT_HARD_STOP_REGISTRY that this is necessary,
    not optional: v13's own hard-stop registry only covers honeypot/arp_spoof/
    geofence/confirmed_exploit -- ThreatIntel IOC score, lateral-movement target
    count, JA3/JA4 fingerprints, AbuseIPDB risk, and the exfiltration-burst z-score
    all feed v13's ATTACK HYPOTHESIS SCORE instead (a probabilistic accumulation,
    not a guaranteed hard stop), so treating v13's decision state alone as a proxy
    for these six checks would silently under-detect relative to v1's real
    Stage 1 on exactly the alerts a genuine shadow comparison most needs to catch.
    Check 7 (local confirmed-intel) is NOT re-ported a second time here -- it
    reuses `check_local_intel_hard_stop()` (Phase 6b) directly, since that method
    already IS this check, faithfully.

A THIRD deliberate decision, about STATE MUTATION during shadow evaluation: this
`evaluate()` DOES call the real `mark_false_positive()`/`_apply_sigma_shift()`/
`record_confirmed_threat()` write paths on a suppress/confirmed-threat verdict --
it does not silently no-op them. This only ever mutates v13's OWN graph state
(trust 'trusts' edges, a device's own `fp_profile`/`sigma_shift` metadata, and a
v13-only LocalConfirmedIntel store -- see live_engine.py's own
`evaluate_cl_afpe_shadow()` docstring for why that store is deliberately NOT the
same file v1's real fp_engine reads from). None of this ever reaches v1's live
state or v1's real suppress/containment decision -- "compute-only, never
suppresses" (this plan's own verification section) means CL-AFPE's OWN verdict
never drives pipeline.py's actual routing, not that shadow mode must be a frozen
no-op. Shadow mode needs to accumulate real per-device trust/threshold/sigma
experience -- exactly what Phase 6f's eventual live-flip decision would need
evidence of -- not start from zero the day it's finally flipped live.

Calibration (`_apply_calibration()`, fp_engine.py ~2490) is NOT ported: v1's own
docstring already describes it as "purely additive to the audit trail... never
used for branching," and this shadow verdict has no audit-trail UI to feed it into
-- `calibrated_confidence` is always `None` in the dict this returns, same shape
v1 itself uses when no reliable calibration is loaded.
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from argus.graph.store import GraphStore
from argus.evidence.model import NO_DESTINATION
from argus.cl_afpe.ml_scoring import MLScorer, NEUTRAL_LGBM_SCORE, combine_scores, stage3_rule_fallback
from argus.cl_afpe import composite_trust as ct
from argus.baseline.engine import derive_activity_state
from intelligence.local_intel import LocalConfirmedIntel
from utils import (
    KNOWN_PUBLIC_DNS_RESOLVERS, is_cloud_cdn_provider_org, is_telemetry_domain,
    _is_cdn_or_cloud_domain, etld1,
)

LOGGER = logging.getLogger("home_ids.cl_afpe")

# Release 15 Sheet 03b: regime_id is part of composite_trust's key, but no live
# per-alert regime value exists on this host today -- BOCPD/regime tracking
# (src/argus/baseline/engine.py) only runs on the separate .19 shadow ingest
# daemon, never in this live pipeline. Using a fixed default here (rather than
# fabricating a meaningless per-call value) until baseline scoring is ever wired
# into the live decision path -- see ARGUS_DECISIONS.md.
_DEFAULT_REGIME_ID = 0

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

# Matches fp_engine.py's own Stage-2/3/combined threshold FALLBACK defaults exactly
# (_DEFAULT_LGBM_FP_THRESHOLD / _DEFAULT_EMBED_SIMILARITY_THRESHOLD /
# _DEFAULT_COMBINED_SUPPRESS_THRESHOLD / _DEFAULT_COMBINED_UNCERTAIN_THRESHOLD,
# fp_engine.py:116-125). v1 itself reads these live from config.json when present;
# v13 doesn't yet have that config-override wiring for CL-AFPE specifically (a real,
# tracked gap, not a silent one -- see Phase 6e's own docstring paragraph above), so
# these fallback numbers are used unconditionally for now.
DEFAULT_LGBM_FP_THRESHOLD = 0.75
DEFAULT_EMBED_SIMILARITY_THRESHOLD = 0.82
DEFAULT_COMBINED_SUPPRESS_THRESHOLD = 0.80
DEFAULT_COMBINED_UNCERTAIN_THRESHOLD = 0.55

# Matches fp_engine.py's real Stage-1 numeric thresholds exactly (Checks 1/2/5/6,
# _stage1_hard_stop() lines 1120-1201).
_TI_RISK_HARD_STOP = 2.0
_ABUSEIPDB_HARD_STOP = 4.0
_EXFIL_OUTBOUND_Z_HARD_STOP = 5.0
_EXFIL_OUTBOUND_BYTES_HARD_STOP = 2_500_000
_DEFAULT_LATERAL_MOVEMENT_UNIQUE_TARGETS_THRESHOLD = 2


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
    def __init__(self, store: GraphStore, resolve_canonical_device_id=None, has_device=None,
                  local_intel: Optional[LocalConfirmedIntel] = None, safe_ips: Optional[Any] = None,
                  ml_scorer: Optional[MLScorer] = None):
        self.store = store
        # Both optional/defaulted, same pattern fp_engine.py's own state_manager
        # dependency uses -- a no-op device-identity check when not supplied.
        self._resolve_canonical_device_id = resolve_canonical_device_id or store.resolve_canonical_device_id
        self._has_device = has_device or (lambda device_id: self.store._conn.execute(
            "SELECT 1 FROM devices WHERE device_id = ?", (device_id,)).fetchone() is not None)
        self._baseline_observations: Dict[str, Dict[str, Dict[str, int]]] = {}
        # Phase 6b: injected, real LocalConfirmedIntel -- optional (None = poisoning
        # protection is a safe no-op: record_confirmed_threat() does nothing,
        # check_local_intel_hard_stop() never fires), matching this constructor's
        # own existing graceful-degradation pattern for the two params above.
        self.local_intel = local_intel
        self._safe_ips = safe_ips or set()
        # Phase 6d: injected, real MLScorer -- optional (None = Stage 2 always
        # falls back to the neutral 0.50 score and Stage 3 always uses the static
        # rule fallback, exactly matching v1's own "model not loaded yet" behavior,
        # never an error).
        self.ml_scorer = ml_scorer

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

    def get_device_suppress_threshold(self, device_id: Optional[str],
                                        default: float = DEFAULT_COMBINED_SUPPRESS_THRESHOLD) -> float:
        """Matches get_device_suppress_threshold() exactly (fp_engine.py:2043-2056):
        this device's own calibrated combined-suppress threshold if
        apply_device_fp_profile() has ever written one under the
        'fp_combined_suppress_threshold' key, else the global default. v1's global
        default itself layers over config.json; v13 doesn't have that override
        wiring yet (see this module's own DEFAULT_COMBINED_SUPPRESS_THRESHOLD
        comment), so `default` is the effective global value for now."""
        return self._get_device_profile_value(device_id, "fp_combined_suppress_threshold", default)

    # --- mark_false_positive(): refusal guards + threshold-bump + default routing

    def mark_false_positive(self, alert_payload: dict, source: str = "operator",
                              ttl_seconds: Optional[float] = None,
                              decision: Optional[dict] = None, asn_owner: str = "",
                              now: Optional[float] = None) -> MarkFalsePositiveResult:
        now = now if now is not None else time.time()
        signature = alert_payload.get("signature", "")
        device_id = alert_payload.get("device", {}).get("id", "unknown")
        hostname = alert_payload.get("device", {}).get("hostname", "") or ""
        # Hoisted here (2026-09-15, gap 1 of the "3 automated-learning gaps" fix) so
        # the corroboration-recording block at the end of this method -- and the
        # existing default domain/IP immunization branch below, which used to
        # compute its own separate copy of these three -- share one computation.
        domain = alert_payload.get("network_context", {}).get("queried_domain", "") or ""
        dest_ip = alert_payload.get("network_context", {}).get("destination_ip", "") or ""
        base_domain = ""
        if domain and domain != "unknown":
            try:
                base_domain = etld1(domain) or ""
            except Exception:
                base_domain = ""

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
            # BUGFIX (found writing Phase 6e's own tests, fixed here since it's the
            # SAME code this phase's shadow evaluate() now depends on for a correct
            # trust-cache round-trip): the immunized target must be the eTLD+1 BASE
            # domain, matching what evaluate()'s own trust-cache check looks up
            # (base_domain, see this class's own evaluate() method below) -- v1
            # itself immunizes base_domain, never the raw queried_domain (a raw
            # subdomain would only ever re-match itself, never a sibling subdomain
            # of the same vendor, defeating the entire point of "immunizing
            # sentry.io suppresses xyz.ingest.us.sentry.io too"). This version had
            # been immunizing the raw domain instead since Phase 6a first wrote
            # this branch -- never actually exercised end-to-end until Phase 6e's
            # composed evaluate() tests caught the mismatch.
            # `domain`/`base_domain` now computed once at the top of this method
            # (see 2026-09-15 gap-1 comment there) -- no longer recomputed here.
            if base_domain:
                target = base_domain
                is_new = self.immunize(target, device_id=device_id, hypothesis=signature,
                                         source=source, ttl_seconds=ttl_seconds, now=now)
            else:
                # No extractable base domain (no domain at all, or etld1() couldn't
                # parse it) -- fall back to the raw destination IP, matching v1
                # exactly (the live-audit bugfix that closed the "raw-IP alert
                # falls through to a total no-op" gap).
                if dest_ip and dest_ip != "unknown":
                    target = dest_ip
                    is_new = self.immunize(target, device_id=device_id, hypothesis=signature,
                                             source=source, ttl_seconds=ttl_seconds, now=now)

        # Runs regardless of which branch above fired -- a general behavioral
        # dampener, not specific to domain-based corrections (matches v1's own
        # placement exactly, fp_engine.py:1914).
        self._apply_sigma_shift(device_id, source=source, now=now)

        # GAP 1 FIX (2026-09-15, "3 automated-learning gaps" audit): this used to
        # live ONLY inside evaluate()'s STAGE_3_COMBINED branch, so composite-trust
        # corroboration accumulated exclusively from the autonomous Stage 2/3 ML
        # path -- an operator tapping "Mark False Positive" in Telegram
        # (pihole_api.py, source="operator") created a trust-cache edge via
        # immunize() above but never fed this table, meaning the composite-trust
        # hard-gate (this class's evaluate(), trust-cache fast path) could keep
        # denying suppression indefinitely even after a human corrected the alert.
        # Moved here so ANY genuine, non-refused correction -- operator,
        # autonomous_stage23, or the new autonomous_local_origin (gap 3) -- feeds
        # the same table identically. `decision` carries the freshest
        # evidence_types/evidence_families during a live evaluate() cycle; callers
        # with no live decision (the operator path has none) fall back to the
        # alert's own persisted hee_evidence_types/hee_evidence_families -- the
        # same data, confirmed present on every real alert payload, just read from
        # a different place.
        try:
            if decision is not None:
                evidence_types_this_cycle = decision.get("evidence_types", [])
                evidence_families_this_cycle = decision.get("evidence_families", [])
            else:
                evidence_types_this_cycle = alert_payload.get("hee_evidence_types", [])
                evidence_families_this_cycle = alert_payload.get("hee_evidence_families", [])
            behavior_fingerprint = derive_activity_state(evidence_types_this_cycle)
            destination_class = ct.classify_destination(dest_ip, base_domain, asn_owner)
            for family in evidence_families_this_cycle:
                ct.record_corroborating_signal(
                    self.store, device_id, behavior_fingerprint, destination_class,
                    signature, family, _DEFAULT_REGIME_ID, now=now,
                )
        except Exception:
            LOGGER.exception("[COMPOSITE_TRUST] record_corroborating_signal failed, non-fatal")

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

    # --- local-intel poisoning protection (Phase 6b) -----------------------------

    def _is_ip_protected_from_confirmed_intel(self, ip: str, asn_owner: str = "") -> bool:
        """Matches fp_engine.py's _is_ip_protected_from_confirmed_intel() exactly
        (lines 909-965): True if `ip` should NEVER be recordable/matchable via the
        local confirmed-intel store -- a known public DNS resolver, explicitly
        listed in `safe_ips`, a cloud/CDN-owned ASN, or private/multicast/loopback/
        link-local/reserved/unspecified (stdlib ipaddress -- these structurally
        cannot be "malicious external infrastructure," the entire premise of this
        store). Every branch here is a documented live-incident fix in v1, not a
        speculative safeguard -- see this module's own top-of-file docstring for
        the real numbers found poisoned in production before each one existed."""
        if not ip or ip == "unknown":
            return False
        if ip in KNOWN_PUBLIC_DNS_RESOLVERS:
            return True
        if ip in self._safe_ips:
            return True
        if asn_owner and is_cloud_cdn_provider_org(asn_owner):
            return True
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return bool(addr.is_private or addr.is_multicast or addr.is_loopback
                        or addr.is_link_local or addr.is_reserved or addr.is_unspecified)
        except ValueError:
            return False

    def record_confirmed_threat(self, device_id: str, base_domain: Optional[str], dest_ip: Optional[str],
                                  reason: str, asn_owner: str = "",
                                  ttl_seconds: Optional[float] = None) -> None:
        """Matches record_confirmed_threat() exactly (lines 967-1037): the write
        path into the shared LocalConfirmedIntel store, so a DIFFERENT device
        touching the same IOC later gets an immediate hard-stop via
        check_local_intel_hard_stop() below -- the same network-wide propagation
        concept Phase 1a already established for reputation, applied here to false-
        positive-adjacent confirmations. Refuses to write a known-telemetry base
        domain (too broad/shared to ever hard-stop on at this granularity) or a
        protected IP (see _is_ip_protected_from_confirmed_intel above) -- both real,
        live-incident-driven guards, not speculative. A no-op, not an error, when
        no LocalConfirmedIntel was ever injected (self.local_intel is None) --
        never raises, matching v1's own 'a bookkeeping failure must not take down
        the confirmed-threat verdict itself' discipline."""
        if self.local_intel is None:
            return
        try:
            if base_domain and is_telemetry_domain(base_domain):
                base_domain = None
            if base_domain:
                self.local_intel.record("domain", base_domain, device_id, reason=reason, ttl_seconds=ttl_seconds)
            if dest_ip and dest_ip != "unknown" and self._is_ip_protected_from_confirmed_intel(dest_ip, asn_owner=asn_owner):
                dest_ip = "unknown"
            if dest_ip and dest_ip != "unknown":
                self.local_intel.record("ip", dest_ip, device_id, reason=reason, ttl_seconds=ttl_seconds)
        except Exception:
            # Matches v1: a bookkeeping failure here must never take down the
            # confirmed-threat verdict that triggered this call.
            pass

    def check_local_intel_hard_stop(self, base_domain: Optional[str], dest_ip: Optional[str],
                                       asn_owner: str = "") -> Optional[Dict[str, Any]]:
        """Matches Stage-1 Check 7's real read-side logic exactly (fp_engine.py
        lines 1203-1240): once ANY device on this network was confirmed touching
        this domain/IP, a DIFFERENT device touching the SAME IOC doesn't have to
        re-earn independent corroboration from scratch. Re-checks the SAME
        telemetry/protection guards on the READ side as record_confirmed_threat()
        uses on the write side -- an already-poisoned entry (e.g. a previously-
        mis-attributed shared vendor domain) stops being honored immediately,
        without needing to hand-edit the state file or wait for its TTL to lapse.

        Returns {"target": str, "kind": "domain"|"ip", "entry": dict} for the
        caller to build a trigger/reason string from, or None if nothing matched
        (including when no LocalConfirmedIntel was ever injected)."""
        if self.local_intel is None:
            return None
        domain_hit_eligible = bool(base_domain) and not is_telemetry_domain(base_domain)
        local_domain_hit = self.local_intel.check("domain", base_domain) if domain_hit_eligible else None
        if local_domain_hit:
            return {"target": base_domain, "kind": "domain", "entry": local_domain_hit}
        ip_hit_eligible = bool(dest_ip) and dest_ip != "unknown" \
            and not self._is_ip_protected_from_confirmed_intel(dest_ip, asn_owner=asn_owner)
        local_ip_hit = self.local_intel.check("ip", dest_ip) if ip_hit_eligible else None
        if local_ip_hit:
            return {"target": dest_ip, "kind": "ip", "entry": local_ip_hit}
        return None

    # --- Stage 1 hard-stop (Phase 6e) --------------------------------------------

    @staticmethod
    def _is_domain_causal_hard_stop(triggers: Optional[List[str]]) -> bool:
        """Matches _is_domain_causal_hard_stop() exactly (fp_engine.py:1243-1273):
        only Check 1 (ThreatIntel IOC) has a plausible causal link to `domain` --
        every other check is behavioral or IP-based and records dest_ip only."""
        if not triggers:
            return False
        return any(t.startswith("ThreatIntel IOC match") for t in triggers)

    def _stage1_hard_stop(self, features: dict, hostname: str, domain: str, dest_ip: str,
                            base_domain: str, decision: Optional[dict] = None,
                            asn_owner: str = "") -> Optional[List[str]]:
        """Matches _stage1_hard_stop() exactly (fp_engine.py:1088-1241) -- see this
        module's own top-of-file Phase 6e docstring paragraph for why Checks 0-6 are
        each re-derived here (not approximated from v13's own decision state) while
        Check 7 reuses check_local_intel_hard_stop() (Phase 6b) directly."""
        triggers: List[str] = []
        features = features or {}

        # Check 0: v13's own already-computed decision verdict, the same
        # cross-engine-recognition role v1's Check 0 plays for decision_engine.py.
        if decision is not None and decision.get("state") == "CRITICAL":
            triggers.append(f"HEE hard-stop verdict: {decision.get('explanation', 'unknown')}")

        # Check 1: ThreatIntel IOC.
        ti_risk = float(features.get("ti_risk", 0.0) or 0.0)
        if ti_risk > _TI_RISK_HARD_STOP:
            triggers.append(f"ThreatIntel IOC match (ti_risk={ti_risk:.2f}) – domain on global malware blacklist")

        # Check 2: lateral movement / internal port scanning (distinct-target gated).
        lateral = int(features.get("zeek_lateral_moves", 0) or 0)
        lateral_targets = int(features.get("zeek_lateral_unique_targets", 0) or 0)
        if lateral > 0 and lateral_targets >= _DEFAULT_LATERAL_MOVEMENT_UNIQUE_TARGETS_THRESHOLD:
            triggers.append(
                f"Internal lateral movement / port scan ({lateral} connection(s) across "
                f"{lateral_targets} distinct target(s))"
            )

        # Check 3: malicious TLS fingerprint.
        ja3 = int(features.get("zeek_ja3_malicious", 0) or 0)
        ja4 = int(features.get("zeek_ja4_malicious", 0) or 0)
        if ja3 > 0 or ja4 > 0:
            triggers.append(f"Malicious TLS fingerprint (JA3={ja3}, JA4+={ja4} hits)")

        # Check 4: honeypot access.
        honeypot = int(features.get("zeek_honeypot_hits", 0) or 0)
        if honeypot > 0:
            triggers.append(f"Internal honeypot accessed ({honeypot} connections to decoy server)")

        # Check 5: AbuseIPDB confirmed blacklisted destination.
        abuse = float(features.get("abuseipdb_risk", 0.0) or 0.0)
        if abuse >= _ABUSEIPDB_HARD_STOP:
            triggers.append(f"AbuseIPDB blacklisted destination IP (risk={abuse:.1f})")

        # Check 6: exfiltration payload burst (absolute-byte-floor + telemetry/CDN exempt).
        out_z = float(features.get("outbound_bytes_z", 0.0) or 0.0)
        out_bytes = float(features.get("zeek_outbound_bytes", 0.0) or 0.0)
        is_exempt_exfil_dest = bool(domain) and (
            is_telemetry_domain(base_domain) or _is_cdn_or_cloud_domain(domain)
        )
        if (out_z > _EXFIL_OUTBOUND_Z_HARD_STOP and out_bytes > _EXFIL_OUTBOUND_BYTES_HARD_STOP
                and not is_exempt_exfil_dest):
            triggers.append(f"Exfiltration Payload Burst (outbound_bytes_z={out_z:.2f}, bytes={int(out_bytes)})")

        # Check 7: local confirmed-threat store (Phase 6b, reused directly).
        local_hit = self.check_local_intel_hard_stop(base_domain, dest_ip, asn_owner=asn_owner)
        if local_hit:
            entry = local_hit["entry"]
            triggers.append(
                f"Local confirmed-threat match: '{local_hit['target']}' previously confirmed malicious on "
                f"this network ({entry.get('count', 1)} confirmation(s), first seen "
                f"{time.strftime('%Y-%m-%d', time.localtime(entry.get('first_confirmed', time.time())))})"
            )

        return triggers if triggers else None

    # --- composed evaluate() (Phase 6e) -------------------------------------------

    def evaluate(self, alert_payload: dict, features: dict, decision: Optional[dict] = None,
                  asn_owner: str = "", now: Optional[float] = None) -> Dict[str, Any]:
        """Matches fp_engine.py's real evaluate() control flow exactly (line 397) --
        trust-cache fast path, Stage 1 hard-stop, Stage 2/3 ML scoring, final
        suppress/uncertain/confirmed-threat branch. See this module's own
        top-of-file Phase 6e docstring paragraphs for the three deliberate scope
        decisions (Check-0 reuse, Checks-1-6 re-ported not approximated, and
        shadow-mode state mutation) before changing this method."""
        now = now if now is not None else time.time()
        device_id = alert_payload.get("device", {}).get("id", "unknown")
        hostname = alert_payload.get("device", {}).get("hostname", "") or ""
        domain = alert_payload.get("network_context", {}).get("queried_domain", "") or ""
        dest_ip = alert_payload.get("network_context", {}).get("destination_ip", "") or ""
        alert_hypothesis = alert_payload.get("signature", "")

        try:
            base_domain = etld1(domain) if domain else ""
        except Exception:
            base_domain = ""

        # --- trust cache fast path ---
        cached_target = None
        if base_domain and self.is_trust_cached(base_domain, device_id=device_id, hypothesis=alert_hypothesis, now=now):
            cached_target = base_domain
        elif dest_ip and self.is_trust_cached(dest_ip, device_id=device_id, hypothesis=alert_hypothesis, now=now):
            cached_target = dest_ip

        if cached_target:
            # Release 15 Sheet 03b, HARD-GATED (2026-09-15, promoted from shadow-only
            # per explicit instruction): composite_trust must ALSO permit this exact
            # tuple, not just the existing trust-cache, before the fast path below is
            # taken. Fail-open toward re-evaluation, not suppression: any error here
            # (or a real "not yet permitted") means falling through to the full
            # Stage 1/2/3 path below, exactly as if this target had never been
            # trust-cached at all -- never a reason to suppress something the
            # composite gate hasn't independently corroborated.
            composite_permits = False
            try:
                evidence_types_this_cycle = decision.get("evidence_types", []) if decision else []
                behavior_fingerprint = derive_activity_state(evidence_types_this_cycle)
                destination_class = ct.classify_destination(dest_ip, base_domain, asn_owner)
                composite_permits = ct.permits_suppression(
                    self.store, device_id, behavior_fingerprint, destination_class,
                    alert_hypothesis, _DEFAULT_REGIME_ID, now=now,
                )
                LOGGER.info(
                    "[COMPOSITE_TRUST] device=%s target=%s hypothesis=%s "
                    "fingerprint=%s dest_class=%s composite_permits=%s "
                    "(trust-cache permitted, composite gate %s)",
                    device_id, cached_target, alert_hypothesis, behavior_fingerprint,
                    destination_class, composite_permits,
                    "AGREED" if composite_permits else "DENIED -- falling through to full evaluation",
                )
            except Exception:
                LOGGER.exception("[COMPOSITE_TRUST] evaluation failed -- fail-open, falling through to full evaluation")
            if not composite_permits:
                cached_target = None

        if cached_target:
            stage1_triggers = self._stage1_hard_stop(
                features, hostname, domain, dest_ip, base_domain, decision=decision, asn_owner=asn_owner)
            if stage1_triggers:
                self._apply_sigma_shift(device_id, direction="TUNE_UP", source="autonomous", now=now)
                self.record_confirmed_threat(
                    device_id,
                    base_domain if self._is_domain_causal_hard_stop(stage1_triggers) else None,
                    dest_ip, reason="TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP", asn_owner=asn_owner,
                )
                return {
                    "verdict": "CONFIRMED_THREAT", "confidence": 0.0,
                    "calibrated_confidence": None,
                    "stage": "TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP",
                    "reasons": stage1_triggers, "suppress": False,
                }
            return {
                "verdict": "FALSE_POSITIVE", "confidence": 1.0,
                "calibrated_confidence": None,
                "stage": "TRUST_CACHE",
                "reasons": [f"'{cached_target}' previously verified safe – dynamic trust cache hit"],
                "suppress": True,
            }

        # --- Stage 1 ---
        stage1_triggers = self._stage1_hard_stop(
            features, hostname, domain, dest_ip, base_domain, decision=decision, asn_owner=asn_owner)
        if stage1_triggers:
            self._apply_sigma_shift(device_id, direction="TUNE_UP", source="autonomous", now=now)
            self.record_confirmed_threat(
                device_id,
                base_domain if self._is_domain_causal_hard_stop(stage1_triggers) else None,
                dest_ip, reason="STAGE_1_HARD_STOP", asn_owner=asn_owner,
            )
            return {
                "verdict": "CONFIRMED_THREAT", "confidence": 0.0,
                "calibrated_confidence": None,
                "stage": "STAGE_1_HARD_STOP",
                "reasons": stage1_triggers, "suppress": False,
            }

        # --- Stage 1b: local-origin auto-corroboration (gap 3, 2026-09-15, "3
        # automated-learning gaps" audit) ---
        # Design principle, per feedback_network_agnostic_design.md: NOT a fixed
        # protocol/port allowlist (an early draft proposed mDNS/SSDP/ARP/DHCP by
        # name -- rejected on review as hand-encoding this one household's
        # discovery protocols, which wouldn't generalize to a different consumer
        # network's own quirks). The only signal used here is structurally
        # general: is the DESTINATION itself one of this network's own already-
        # registered devices (is_own_registered_device()), and are threat-intel/
        # reputation signals clean. Neither mentions a port, protocol, or vendor,
        # so it behaves identically regardless of what local-discovery mechanism
        # a given household's devices happen to use.
        #
        # Deliberately does NOT auto-resolve on a first sighting -- only records a
        # corroborating signal (same table/mechanism gap 1 universalized) and
        # checks whether THIS exact (device, behavior_fingerprint,
        # destination_class, hypothesis, regime) tuple has now crossed
        # composite_trust's existing distinct-evidence-family trust floor. A
        # genuinely new device-pair/pattern therefore still alerts for real the
        # first several times -- correctly, since it IS new and unverified -- and
        # only quiets down once real, diverse corroboration has accumulated. This
        # method is only ever reached when the trust-cache fast path above did
        # NOT already resolve this alert (no edge yet, or composite_permits was
        # still false), so there's no redundant work once a destination is fully
        # resolved -- future cycles hit that fast path directly instead.
        #
        # mark_false_positive()'s own _HARD_STOP_SIGNATURES refusal guard, and
        # Stage 1's hard-stop check just above, both still run before this can
        # ever fire -- a genuinely confirmed-malicious verdict can never reach
        # this branch, exactly like the existing autonomous Stage 2/3 path.
        try:
            if self.store.is_own_registered_device(dest_ip):
                ti_risk = float(features.get("ti_risk", 0.0) or 0.0)
                abuseipdb_risk = float(features.get("abuseipdb_risk", 0.0) or 0.0)
                if ti_risk == 0.0 and abuseipdb_risk == 0.0:
                    evidence_types_this_cycle = decision.get("evidence_types", []) if decision else []
                    evidence_families_this_cycle = decision.get("evidence_families", []) if decision else []
                    behavior_fingerprint = derive_activity_state(evidence_types_this_cycle)
                    destination_class = ct.classify_destination(dest_ip, base_domain, asn_owner)
                    for family in evidence_families_this_cycle:
                        ct.record_corroborating_signal(
                            self.store, device_id, behavior_fingerprint, destination_class,
                            alert_hypothesis, family, _DEFAULT_REGIME_ID, now=now,
                        )
                    if ct.permits_suppression(
                        self.store, device_id, behavior_fingerprint, destination_class,
                        alert_hypothesis, _DEFAULT_REGIME_ID, now=now,
                    ):
                        mark_result = self.mark_false_positive(
                            alert_payload, source="autonomous_local_origin", decision=decision,
                            asn_owner=asn_owner, now=now)
                        if not mark_result.refused:
                            return {
                                "verdict": "FALSE_POSITIVE", "confidence": 1.0,
                                "calibrated_confidence": None,
                                "stage": "STAGE_1B_LOCAL_ORIGIN",
                                "reasons": [
                                    f"'{dest_ip}' is one of this network's own registered devices, "
                                    f"threat-intel/reputation signals are clean, and repeated "
                                    f"corroborating evidence for this exact pattern has crossed the "
                                    f"composite-trust floor -- autonomously resolved with no human "
                                    f"input (source=autonomous_local_origin).",
                                ],
                                "suppress": True,
                            }
        except Exception:
            LOGGER.exception("[LOCAL_ORIGIN] Stage 1b auto-corroboration failed, non-fatal")

        # --- Stage 2: LightGBM ---
        lgbm_prob = self.ml_scorer.score_stage2(features, domain, is_trust_cached=False) if self.ml_scorer else None
        if lgbm_prob is None:
            lgbm_prob = NEUTRAL_LGBM_SCORE

        # --- Stage 3: FastEmbed (skipped for a placeholder domain, Phase 10 fix) ---
        has_real_domain = bool(domain) and domain.strip().lower() not in ("unknown", "null", "none", "")
        embed_sim, embed_match = None, "N/A (no resolved hostname/domain — raw IP connection)"
        if has_real_domain:
            if self.ml_scorer:
                embed_sim, embed_match = self.ml_scorer.score_stage3(domain)
            if embed_sim is None:
                embed_sim, embed_match = stage3_rule_fallback(domain)
        embed_sim_str = f"{embed_sim:.3f}" if embed_sim is not None else "N/A"

        # --- Final verdict ---
        combined = combine_scores(lgbm_prob, embed_sim, DEFAULT_EMBED_SIMILARITY_THRESHOLD)
        effective_suppress_threshold = self.get_device_suppress_threshold(device_id)

        if combined >= effective_suppress_threshold:
            # GAP 1 FIX (2026-09-15): decision/asn_owner now threaded through so
            # mark_false_positive()'s own corroboration-recording (moved there, see
            # its 2026-09-15 comment) has the freshest evidence_types/
            # evidence_families/destination-classification data from THIS live
            # cycle, matching what this call site used to compute inline itself.
            mark_result = self.mark_false_positive(
                alert_payload, source="autonomous_stage23", decision=decision,
                asn_owner=asn_owner, now=now)
            if mark_result.refused:
                return {
                    "verdict": "UNCERTAIN", "confidence": combined,
                    "calibrated_confidence": None,
                    "stage": "STAGE_3_COMBINED",
                    "reasons": [
                        f"Stage 2/3 combined confidence={combined:.3f} >= suppress threshold, "
                        f"but this alert carries hard-stop/verifiable-fact evidence — "
                        f"mark_false_positive() refused the correction: {mark_result.refused_reason}",
                    ],
                    "suppress": False,
                }
            return {
                "verdict": "FALSE_POSITIVE", "confidence": combined,
                "calibrated_confidence": None,
                "stage": "STAGE_3_COMBINED",
                "reasons": [
                    f"LightGBM FP_MODEL_SCORE={lgbm_prob:.3f} (Stage 2, uncalibrated classifier output)",
                    f"FastEmbed similarity (contextual evidence, not a verdict)={embed_sim_str} → closest known pattern: '{embed_match}' (Stage 3)",
                    f"Combined confidence={combined:.3f} >= {effective_suppress_threshold} (suppress threshold)",
                ],
                "suppress": True,
                "action": {"type": "immunize_domain", "target": base_domain, "is_new": mark_result.is_new_immunization}
                          if base_domain and mark_result.is_new_immunization else None,
            }
        elif combined >= DEFAULT_COMBINED_UNCERTAIN_THRESHOLD:
            return {
                "verdict": "UNCERTAIN", "confidence": combined,
                "calibrated_confidence": None,
                "stage": "STAGE_3_COMBINED",
                "reasons": [
                    f"LightGBM FP_MODEL_SCORE={lgbm_prob:.3f} (uncalibrated classifier output)",
                    f"FastEmbed similarity (contextual evidence, not a verdict)={embed_sim_str} for domain '{domain}' → closest known pattern: '{embed_match or 'N/A'}'",
                    f"Combined confidence={combined:.3f} insufficient to suppress (threshold={effective_suppress_threshold})",
                ],
                "suppress": False,
            }
        else:
            self._apply_sigma_shift(device_id, direction="TUNE_UP", source="autonomous", now=now)
            return {
                "verdict": "CONFIRMED_THREAT", "confidence": combined,
                "calibrated_confidence": None,
                "stage": "STAGE_3_COMBINED",
                "reasons": [
                    f"LightGBM FP_MODEL_SCORE={lgbm_prob:.3f} (uncalibrated classifier output)",
                    f"FastEmbed similarity (contextual evidence, not a verdict)={embed_sim_str} for domain '{domain}' → closest known pattern: '{embed_match or 'N/A'}'",
                    f"Combined confidence={combined:.3f} — LOW FP probability, published at full severity",
                ],
                "suppress": False,
            }
