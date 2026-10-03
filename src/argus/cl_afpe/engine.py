"""
CL-AFPE: the closed-loop false-positive engine. For every alert that reaches it, evaluate() returns one verdict --
FALSE_POSITIVE (suppressed), UNCERTAIN (published, softer) or CONFIRMED_THREAT -- and every correction or
confirmation feeds back into what it decides next time.

evaluate(), in order:
  1. Trust-cache fast path: a destination already corrected as safe (a graph 'trusts' edge, device-scoped for the
     DEVICE_SCOPED_TRUST_HYPOTHESES) is suppressed straight away -- once composite trust (composite_trust.py, two
     independent evidence families) clears its bar.
  2. Stage 1 hard stops, never suppressible: the decision engine's own CRITICAL verdict (check 0); a threat-intel
     IOC, lateral movement, a corroborated malicious JA3/JA4, the decoy host, AbuseIPDB, an exfiltration burst
     (checks 1-6, re-derived from `features`, because only some of them are hard stops in the decision engine);
     and the local confirmed-intel store (check 7: once any device was confirmed touching a domain/IP, every
     other device touching it is stopped too).
  3. Stages 2/3: the LightGBM false-positive classifier and FastEmbed vendor similarity (ml_scoring.py), combined
     and compared with the device's suppress / uncertain thresholds (config, then the device's profile, then a
     promoted autotuner value).

Learning (the write paths):
  - mark_false_positive() -- an operator, LLM-validated or autonomous correction: refuses hard-stop and
    unknown-device alerts; for connection-abuse signatures raises the device's own detection thresholds, otherwise
    immunizes the base domain (or the destination IP); always widens the device's sensitivity shift; records
    composite-trust corroboration; writes a training record for the nightly retrain.
  - record_confirmed_threat() -- records the destination in the shared local confirmed-intel store (never a public
    resolver, a safe IP, cloud/CDN infrastructure or a private/reserved address -- each guard exists because such
    an entry once poisoned the store), counts the confirmation per device/signature and tightens sensitivity.

STATE: trust edges and per-device values (fp_profile, sigma_shift, confirmed_threat_counts) live in the graph;
confirmed intel in state/local_confirmed_intel.json and device familiarity in state/device_familiarity.json (both
injected by pipeline.py, see live_engine.py's CL-AFPE wiring). Models are read-only here: the nightly
train_fp_classifier.py writes them and MLScorer reloads them when the files change.

If evaluate() raises, live_engine.evaluate_cl_afpe_live() returns UNCERTAIN (never suppressed) and reports the error
to the health manager. `calibrated_confidence` is always None (no calibration layer is applied).
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from argus.autotune.engine import AutotuneEngine
from argus.graph.store import GraphStore
from argus.evidence.model import NO_DESTINATION
from argus.cl_afpe.ml_scoring import MLScorer, NEUTRAL_LGBM_SCORE, combine_scores, stage3_rule_fallback
from argus.cl_afpe import composite_trust as ct
from argus.baseline.engine import derive_activity_state
from intelligence.local_intel import LocalConfirmedIntel
from intelligence.device_familiarity import DeviceFamiliarity
from utils import (
    NOT_A_THREAT_INDICATOR_RESOLVERS, is_cloud_cdn_provider_org, is_telemetry_domain,
    _is_cdn_or_cloud_domain, etld1_strict as etld1,  # trust decisions fail closed (see utils.etld1_strict)
)

LOGGER = logging.getLogger("home_ids.cl_afpe")

# A correction may be reviewed long after the alert: the decision row is matched by device + the alert's own
# timestamp within this window.
_TRAINING_RECORD_MATCH_SECONDS = 120.0

# Release 15 Sheet 03b: regime_id is part of composite_trust's key, but no live
# per-alert regime value exists on this host today -- BOCPD/regime tracking
# (src/argus/baseline/engine.py) only runs on the separate .19 shadow ingest
# daemon, never in this live pipeline. Using a fixed default here (rather than
# fabricating a meaningless per-call value) until baseline scoring is ever wired
# into the live decision path -- see ARGUS_DECISIONS.md.
_DEFAULT_REGIME_ID = 0

TRUST_CACHE_TTL_SECONDS = 14 * 24 * 3600
MIN_TRUST_ENTRY_TTL_SECONDS = 3600
MAX_TRUST_ENTRY_TTL_SECONDS = TRUST_CACHE_TTL_SECONDS

# Hypotheses whose benign correction is a
# claim about THIS DEVICE's own behavior, not the destination's general safety.
DEVICE_SCOPED_TRUST_HYPOTHESES = frozenset({
    "DNS_EVASION", "DNS_ATTRIBUTION_GAP", "DNS_POLICY_BYPASS",
})

# Alerts a correction can never mark safe (verifiable facts, not judgements).
_HARD_STOP_SIGNATURES = frozenset({
    "Internal Honeypot Accessed",
    "Layer-2 ARP Spoofing Detected",
    "Geofencing Policy Violation",
    "Confirmed Exploit/Malware Signature (Suricata)",
    "Confirmed Malicious IOC",
})

# Signatures whose correction raises the device's own thresholds -- PORT_SCAN/INTERNAL_RECONNAISSANCE are
# ConnectionAbuseHypothesis's own dynamic names (argus/hypotheses/engine.py) for a
# single-category finding; the branches below inspect raw feature values
# directly, never the signature string itself, so all three route identically.
_CONNECTION_ABUSE_SIGNATURES = frozenset({"CONNECTION_ABUSE", "PORT_SCAN", "INTERNAL_RECONNAISSANCE"})

# Sensitivity (sigma) shift steps. Asymmetric by design: widening
# (TUNE_DOWN, a correction) is a small step with a wide cap; tightening (TUNE_UP, a
# confirmed threat) is a bigger flat step with a narrower floor -- a real threat
# should sharpen sensitivity faster than a single correction should relax it.
SIGMA_WIDENING_STEP = 0.25
MAX_SIGMA_SHIFT = 2.0
_SIGMA_TIGHTEN_STEP = 0.50
_MIN_SIGMA_SHIFT = -1.5

# Stage-2/3/combined thresholds when no config is injected. Live, they come from config (fp_lgbm_threshold,
# fp_embed_similarity_threshold, fp_combined_suppress_threshold, fp_combined_uncertain_threshold), read on every
# alert; the suppress and uncertain thresholds then layer the device's own profile and the autotuner on top.
DEFAULT_LGBM_FP_THRESHOLD = 0.75
DEFAULT_EMBED_SIMILARITY_THRESHOLD = 0.82
DEFAULT_COMBINED_SUPPRESS_THRESHOLD = 0.80
DEFAULT_COMBINED_UNCERTAIN_THRESHOLD = 0.55

# Stage-1 numeric thresholds (checks 1/2/5/6).
_TI_RISK_HARD_STOP = 2.0
_ABUSEIPDB_HARD_STOP = 4.0
_EXFIL_OUTBOUND_Z_HARD_STOP = 5.0
_EXFIL_OUTBOUND_BYTES_HARD_STOP = 2_500_000
_DEFAULT_LATERAL_MOVEMENT_UNIQUE_TARGETS_THRESHOLD = 2


LOCAL_INTEL_TRIGGER_PREFIX = "Local confirmed-threat match"


def _is_independent_confirmation(stage1_triggers: List[str]) -> bool:
    """True when at least one Stage-1 trigger is NOT the local confirmed-intel match. A hard stop caused only by that
    match is not a new confirmation: recording it again would refresh the entry's last_confirmed, so an entry renewed
    itself for as long as any device kept contacting it and never expired (found 2026-10-03 on .94: one entry
    re-confirmed 1,230 times this way)."""
    return any(not str(t).startswith(LOCAL_INTEL_TRIGGER_PREFIX) for t in stage1_triggers or [])


def _strip_persistence_suffix(signature: Optional[str]) -> Optional[str]:
    """The signature without its persistence suffix ('DNS_EVASION (persisted 603s)' -> 'DNS_EVASION')."""
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
                  ml_scorer: Optional[MLScorer] = None, familiarity: Optional[DeviceFamiliarity] = None,
                  lateral_targets_threshold=None, config_get=None):
        self.store = store
        # (key, default) -> value; live_engine passes CONFIG.get so console edits apply on the next alert.
        self._config_get = config_get
        # Distinct internal targets needed for the lateral-movement hard stop; a callable is read on every alert so a
        # config change applies live (live_engine passes config's lateral_movement_unique_targets_threshold).
        self._lateral_targets_threshold = lateral_targets_threshold
        # Both optional: default to the graph's own identity lookups.
        self._resolve_canonical_device_id = resolve_canonical_device_id or store.resolve_canonical_device_id
        self._has_device = has_device or (lambda device_id: self.store._conn.execute(
            "SELECT 1 FROM devices WHERE device_id = ?", (device_id,)).fetchone() is not None)
        # Which destinations each device normally uses (intelligence/device_familiarity.py). The pipeline injects its
        # persisted instance, which it also records into; without one this is an in-memory store.
        self.familiarity = familiarity or DeviceFamiliarity()
        # The shared confirmed-intel store. Optional: without one, record_confirmed_threat() records nothing and
        # check_local_intel_hard_stop() never fires.
        self.local_intel = local_intel
        self._safe_ips = safe_ips or set()
        # Optional: without it (or before its models load) Stage 2 gives the neutral 0.50 score and Stage 3 uses
        # the static vendor rules -- never an error.
        self.ml_scorer = ml_scorer
        # 2026-09-27 (Phase 4 of the autonomy-completion effort): lazy, same
        # construct-once-reuse pattern live_engine.py's own _get_autotune_engine()
        # already uses -- trust_cache_ttl_seconds is global-scope-only here (the
        # fallback used when an edge has no per-entry ttl_seconds of its own; the
        # edges themselves carry per-immunization TTLs already, see immunize()
        # above), so no device_id threading is needed at this call site.
        self._autotune_engine: Optional[AutotuneEngine] = None

    def _get_autotune_engine(self) -> AutotuneEngine:
        if self._autotune_engine is None:
            self._autotune_engine = AutotuneEngine(self.store)
        return self._autotune_engine

    # --- trust cache / immunization (graph 'trusts' edges) ----------------------

    def immunize(self, destination_id: str, device_id: Optional[str] = None,
                  hypothesis: Optional[str] = None, source: str = "autonomous",
                  ttl_seconds: Optional[float] = None, now: Optional[float] = None) -> bool:
        """Marks a destination safe (a 'trusts' edge; TTL clamped to 1 h .. 14 days). Returns True for a new
        immunization, False for a refresh of an existing one or an unusable destination."""
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
        default_ttl = self._get_autotune_engine().get_active_value(
            "trust_cache_ttl_seconds", default=TRUST_CACHE_TTL_SECONDS)
        for e in edges:
            ttl = e["metadata"].get("ttl_seconds") or default_ttl
            if (now - e["timestamp"]) < ttl:
                active.append(e)
        return active

    def get_dynamic_trust_cache(self, now: Optional[float] = None) -> set:
        """Every currently-active immunized destination, not filtered by device or hypothesis (threat intel uses it
        to skip lookups for destinations already corrected as safe)."""
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
        """TUNE_DOWN (a
        correction -- widen sensitivity) steps by +SIGMA_WIDENING_STEP capped at
        MAX_SIGMA_SHIFT; TUNE_UP (a confirmed threat -- tighten sensitivity) steps
        by a flat -0.50 floored at -1.5 (deliberately NOT SIGMA_WIDENING_STEP-based
        -- the asymmetry is deliberate).
        A device_id of "unknown"/empty is a no-op."""
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
        """Merges ONE key into the
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

    def _configured(self, key: str, default: float) -> float:
        if self._config_get is None:
            return default
        try:
            return float(self._config_get(key, default))
        except (TypeError, ValueError):
            return default

    def _autotuned(self, parameter: str, device_id: Optional[str], default: float) -> float:
        """A promoted autotuner value (device, then category, then global) wins over `default`. Never blocks a verdict:
        on any failure `default` is used."""
        try:
            value = self._get_autotune_engine().get_active_value(parameter, device_id=device_id, default=default)
            return float(value) if value is not None else default
        except Exception as e:
            LOGGER.warning("Autotuned %s lookup failed for %r, using %s: %s", parameter, device_id, default, e)
            return default

    def get_device_suppress_threshold(self, device_id: Optional[str], default: Optional[float] = None) -> float:
        """The combined score at or above which an alert is suppressed, for ONE device: a promoted autotuner value
        (nightly calibration) if there is one, else this device's own profile value (raised by corrections), else the
        configured global value."""
        if default is None:
            default = self._configured("fp_combined_suppress_threshold", DEFAULT_COMBINED_SUPPRESS_THRESHOLD)
        profile_value = self._get_device_profile_value(device_id, "fp_combined_suppress_threshold", default) \
            if device_id else default
        return self._autotuned("fp_combined_suppress_threshold", device_id, profile_value)

    def get_device_uncertain_threshold(self, device_id: Optional[str]) -> float:
        """The combined score at or above which a non-suppressed alert is UNCERTAIN rather than kept as a threat: the
        autotuner's value if promoted, else the configured one."""
        return self._autotuned("combined_uncertain_threshold", device_id,
                               self._configured("fp_combined_uncertain_threshold", DEFAULT_COMBINED_UNCERTAIN_THRESHOLD))

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
            # Exclusive with the domain-immunization branch below (immunizing an "unknown" domain for a signature type with
            # no meaningful domain used to keep re-suppressing the same FP
            # forever). Inspects the SAME features this alert's own evidence was
            # computed from and bumps every threshold whose condition is still
            # true for THIS alert -- never just one blind guess. Bumping an
            # unrelated threshold that wasn't the cause is harmless; missing the
            # real cause is what kept the false positive coming back.
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
                # than silently doing nothing.
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
            # Default routing: immunize the eTLD+1 BASE domain -- what evaluate()'s trust-cache check looks up, so
            # immunizing sentry.io also covers xyz.ingest.us.sentry.io (a raw subdomain would only re-match itself).
            if base_domain:
                target = base_domain
                is_new = self.immunize(target, device_id=device_id, hypothesis=signature,
                                         source=source, ttl_seconds=ttl_seconds, now=now)
            else:
                # No extractable base domain (no domain at all, or etld1() couldn't
                # parse it) -- immunize the raw destination IP instead, so a raw-IP
                # alert's correction is not a no-op.
                if dest_ip and dest_ip != "unknown":
                    target = dest_ip
                    is_new = self.immunize(target, device_id=device_id, hypothesis=signature,
                                             source=source, ttl_seconds=ttl_seconds, now=now)

        # Runs regardless of which branch above fired -- a general behavioral
        # dampener, not specific to domain-based corrections.
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

        event_type = {"llm_validated": "LLM_VALIDATED_FALSE_POSITIVE",
                      "autonomous_stage23": "AUTONOMOUS_FP_SUPPRESSED",
                      "autonomous_local_origin": "AUTONOMOUS_FP_SUPPRESSED"}.get(source, "OPERATOR_MARKED_FALSE_POSITIVE")
        self._write_training_record(
            alert_payload, event_type,
            [f"Marked as false positive ({source}) for '{target or domain or dest_ip or 'unknown'}'."],
            1.0, decision=decision)

        return MarkFalsePositiveResult(refused=False, is_new_immunization=is_new,
                                         immunized_destination=target, threshold_bumped=threshold_bumped)

    # --- baseline familiarity ----------------------------------------------------

    def record_baseline_observation(self, device_id: str, *, dest_port=None,
                                       asn_owner: Optional[str] = None,
                                       domain_base: Optional[str] = None) -> None:
        """Callers must only record from cycles already classified BENIGN/ANOMALOUS."""
        self.familiarity.record_device_baseline_observation(
            device_id, dest_port=dest_port, asn_owner=asn_owner, domain_base=domain_base)

    def get_baseline_familiarity(self, device_id: str, *, dest_port=None,
                                    asn_owner: Optional[str] = None,
                                    domain_base: Optional[str] = None) -> float:
        """Highest familiarity across whichever identity dimensions are supplied, 0.0-1.0."""
        return self.familiarity.get_baseline_familiarity(
            device_id, dest_port=dest_port, asn_owner=asn_owner, domain_base=domain_base)

    # --- local-intel poisoning protection (Phase 6b) -----------------------------

    def _is_ip_protected_from_confirmed_intel(self, ip: str, asn_owner: str = "") -> bool:
        """True if `ip` should NEVER be recordable/matchable via the
        local confirmed-intel store -- a known public DNS resolver, explicitly
        listed in `safe_ips`, a cloud/CDN-owned ASN, or private/multicast/loopback/
        link-local/reserved/unspecified (stdlib ipaddress -- these structurally
        cannot be "malicious external infrastructure," the entire premise of this
        store). Each branch exists because such an entry once poisoned the store in production
        (public resolvers, this network's own IDS host, mDNS multicast, hundreds of cloud/CDN IPs)."""
        if not ip or ip == "unknown":
            return False
        if ip in NOT_A_THREAT_INDICATOR_RESOLVERS:
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
                                  ttl_seconds: Optional[float] = None, signature: str = "") -> None:
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
        never raises: a bookkeeping failure must not take down the confirmed-threat verdict."""
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
            # A bookkeeping failure here must never take down the confirmed-threat verdict.
            LOGGER.exception("Failed to record confirmed intel (non-fatal)")
        self._increment_confirmed_count(device_id, signature)

    def _increment_confirmed_count(self, device_id: str, signature: str = "") -> None:
        """How often this device was confirmed malicious, overall and per signature (graph metadata
        `confirmed_threat_counts`) -- the nightly calibration weighs corrections against it."""
        if not device_id or device_id == "unknown":
            return
        try:
            counts = dict(self.store.get_device_metadata(device_id).get("confirmed_threat_counts") or {})
            counts["_total"] = int(counts.get("_total", 0)) + 1
            if signature:
                counts[signature] = int(counts.get(signature, 0)) + 1
            self.store.update_device_metadata(device_id, {"confirmed_threat_counts": counts})
        except Exception:
            LOGGER.exception("Failed to increment the confirmed-threat count (non-fatal)")

    def get_confirmed_count(self, device_id: str, signature: str = "") -> int:
        try:
            counts = self.store.get_device_metadata(device_id).get("confirmed_threat_counts") or {}
            return int(counts.get(signature or "_total", 0))
        except Exception:
            return 0

    # --- training records (decisions.raw_payload_json.fp_suppression_log) ----------------------------------------

    def _write_training_record(self, alert_payload: dict, event_type: str, reasons: List[str],
                               confidence: float, decision: Optional[dict] = None) -> None:
        """Records a suppressed or corrected alert on its own decision row as `fp_suppression_log`. The nightly
        retrain (scripts/train_fp_classifier.py) learns false-positive samples from these, and the calibration
        counts the correction types. Resolves the decision by `decision["_graph_decision_id"]` when given, else by
        device + the alert's own timestamp. Never raises."""
        try:
            graph_decision_id = decision.get("_graph_decision_id") if decision else None
            if graph_decision_id is None:
                device_id = alert_payload.get("device", {}).get("id")
                ts = alert_payload.get("timestamp")
                if device_id and device_id != "unknown" and ts is not None:
                    row = self.store._conn.execute(
                        "SELECT decision_id FROM decisions WHERE device_id=? AND timestamp BETWEEN ? AND ? "
                        "ORDER BY ABS(timestamp - ?) LIMIT 1",
                        (device_id, ts - _TRAINING_RECORD_MATCH_SECONDS, ts + _TRAINING_RECORD_MATCH_SECONDS, ts),
                    ).fetchone()
                    if row is not None:
                        graph_decision_id = row["decision_id"]
            if graph_decision_id is None:
                LOGGER.warning("No graph decision row for this %s alert (device=%r) -- no training record written.",
                               event_type, alert_payload.get("device", {}).get("id"))
                return
            entry = {
                "ts_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "ts_unix": time.time(),
                "type": event_type,
                "confidence": round(float(confidence), 4),
                "reasons": reasons,
                "device": alert_payload.get("device", {}),
                "domain": alert_payload.get("network_context", {}).get("queried_domain", ""),
                "risk_score": alert_payload.get("risk", 0.0),
                "original_alert": alert_payload,
            }
            self.store.update_decision_payload(graph_decision_id, {"fp_suppression_log": entry})
        except Exception:
            LOGGER.exception("Failed to write the training record (non-fatal)")

    def check_local_intel_hard_stop(self, base_domain: Optional[str], dest_ip: Optional[str],
                                       asn_owner: str = "") -> Optional[Dict[str, Any]]:
        """Stage-1 check 7: once ANY device on this network was confirmed touching
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
        """Only check 1 (ThreatIntel IOC) has a plausible causal link to `domain` --
        every other check is behavioral or IP-based and records dest_ip only."""
        if not triggers:
            return False
        return any(t.startswith("ThreatIntel IOC match") for t in triggers)

    def _stage1_hard_stop(self, features: dict, hostname: str, domain: str, dest_ip: str,
                            base_domain: str, decision: Optional[dict] = None,
                            asn_owner: str = "") -> Optional[List[str]]:
        """Stage-1 hard stops (see the module docstring). Checks 1-6 are re-derived from `features` because the
        decision engine treats most of them as weighted evidence, not hard stops; check 7 is
        check_local_intel_hard_stop()."""
        triggers: List[str] = []
        features = features or {}

        # Check 0: the decision engine's own verdict for this cycle.
        if decision is not None and decision.get("state") == "CRITICAL":
            triggers.append(f"HEE hard-stop verdict: {decision.get('explanation', 'unknown')}")

        # Check 1: ThreatIntel IOC.
        ti_risk = float(features.get("ti_risk", 0.0) or 0.0)
        if ti_risk > _TI_RISK_HARD_STOP:
            triggers.append(f"ThreatIntel IOC match (ti_risk={ti_risk:.2f}) – domain on global malware blacklist")

        # Check 2: lateral movement / internal port scanning (distinct-target gated).
        lateral = int(features.get("zeek_lateral_moves", 0) or 0)
        lateral_targets = int(features.get("zeek_lateral_unique_targets", 0) or 0)
        threshold = self._lateral_targets_threshold
        threshold = threshold() if callable(threshold) else (threshold or _DEFAULT_LATERAL_MOVEMENT_UNIQUE_TARGETS_THRESHOLD)
        if lateral > 0 and lateral_targets >= int(threshold):
            triggers.append(
                f"Internal lateral movement / port scan ({lateral} connection(s) across "
                f"{lateral_targets} distinct target(s))"
            )

        # Check 3: malicious TLS fingerprint.
        ja3 = int(features.get("zeek_ja3_malicious", 0) or 0)
        ja4 = int(features.get("zeek_ja4_malicious", 0) or 0)
        # B1: fingerprint alone = weighted evidence; hard stop only with a second reputation indicator.
        if (ja3 > 0 or ja4 > 0) and (
            float(features.get("ti_risk", 0.0) or 0.0) > 0.0
            or float(features.get("abuseipdb_risk", 0.0) or 0.0) >= 1.0
        ):
            triggers.append(f"Malicious TLS fingerprint (JA3={ja3}, JA4+={ja4} hits) corroborated by reputation data")

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
                f"{LOCAL_INTEL_TRIGGER_PREFIX}: '{local_hit['target']}' previously confirmed malicious on "
                f"this network ({entry.get('count', 1)} confirmation(s), first seen "
                f"{time.strftime('%Y-%m-%d', time.localtime(entry.get('first_confirmed', time.time())))})"
            )

        return triggers if triggers else None

    # --- composed evaluate() (Phase 6e) -------------------------------------------

    def evaluate(self, alert_payload: dict, features: dict, decision: Optional[dict] = None,
                  asn_owner: str = "", now: Optional[float] = None) -> Dict[str, Any]:
        """One verdict for one alert: trust-cache fast path, Stage 1 hard stops, Stage 2/3 ML scoring, then
        suppress / uncertain / confirmed threat. See the module docstring."""
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
                if _is_independent_confirmation(stage1_triggers):
                    self.record_confirmed_threat(
                        device_id,
                        base_domain if self._is_domain_causal_hard_stop(stage1_triggers) else None,
                        dest_ip, reason="TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP", asn_owner=asn_owner,
                        signature=alert_hypothesis,
                    )
                return {
                    "verdict": "CONFIRMED_THREAT", "confidence": 0.0,
                    "calibrated_confidence": None,
                    "stage": "TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP",
                    "reasons": stage1_triggers, "suppress": False,
                }
            reasons = [f"'{cached_target}' previously verified safe – dynamic trust cache hit"]
            self._write_training_record(alert_payload, "TRUST_CACHE_HIT", reasons, 1.0, decision=decision)
            return {
                "verdict": "FALSE_POSITIVE", "confidence": 1.0,
                "calibrated_confidence": None,
                "stage": "TRUST_CACHE",
                "reasons": reasons,
                "suppress": True,
            }

        # --- Stage 1 ---
        stage1_triggers = self._stage1_hard_stop(
            features, hostname, domain, dest_ip, base_domain, decision=decision, asn_owner=asn_owner)
        if stage1_triggers:
            self._apply_sigma_shift(device_id, direction="TUNE_UP", source="autonomous", now=now)
            if _is_independent_confirmation(stage1_triggers):
                self.record_confirmed_threat(
                    device_id,
                    base_domain if self._is_domain_causal_hard_stop(stage1_triggers) else None,
                    dest_ip, reason="STAGE_1_HARD_STOP", asn_owner=asn_owner, signature=alert_hypothesis,
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
        embed_threshold = self._configured("fp_embed_similarity_threshold", DEFAULT_EMBED_SIMILARITY_THRESHOLD)
        combined = combine_scores(lgbm_prob, embed_sim, embed_threshold)
        effective_suppress_threshold = self.get_device_suppress_threshold(device_id)
        # Which stage carried a suppression (for the stage-hit metrics): the embedding match, else the classifier.
        if embed_sim is not None and embed_sim >= embed_threshold:
            stage_hit = "embed"
        elif lgbm_prob is not None and lgbm_prob >= self._configured("fp_lgbm_threshold", DEFAULT_LGBM_FP_THRESHOLD):
            stage_hit = "lgbm"
        else:
            stage_hit = None

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
                "stage_hit": stage_hit,
                "action": {"type": "immunize_domain", "target": base_domain, "is_new": mark_result.is_new_immunization}
                          if base_domain and mark_result.is_new_immunization else None,
            }
        elif combined >= self.get_device_uncertain_threshold(device_id):
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
