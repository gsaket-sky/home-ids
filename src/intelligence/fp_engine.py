"""
fp_engine.py – Closed-Loop Autonomous False-Positive Elimination Engine (CL-AFPE)

======================================================================================
WHAT DOES THIS MODULE DO?  (Plain English for Novice Users)
======================================================================================

When the IDS raises an alert (risk score >= 6.0), it doesn't automatically mean a
device is under attack. Sometimes a laptop querying a developer API endpoint like
"sentry.io" or a phone checking for iOS updates will trigger a false positive alert.

This engine intercepts those alerts BEFORE they are sent to Telegram or Grafana and
runs them through a 3-stage autonomous validation pipeline:

  STAGE 1 – HARD STOP SECURITY FILTER (< 1 ms)
  A fast check for definitive threat signals: ThreatIntel IOC match, lateral movement,
  malicious JA3/JA4+ TLS fingerprints, or internal honeypot access. If ANY of these
  are present → bypass FP engine → alert is CONFIRMED THREAT.

  STAGE 2 – LightGBM ONNX TABULAR CLASSIFIER (< 2 ms)
  A pre-trained LightGBM model evaluates numeric features: Tranco domain rank, DNS
  label entropy, maximum label length, outbound bytes Z-score, device type, and
  historical FP rate for this base domain. Outputs P(False Positive) in [0, 1].

  STAGE 3 – FastEmbed MiniLM-L6 VECTOR SIMILARITY MATCHER (< 15 ms)
  Uses semantic text embedding (BAAI/bge-small-en-v1.5, 384-dim vectors) to compare
  the queried domain against a reference database of ~50+ known-safe vendor telemetry
  patterns. Cosine similarity >= 0.82 classifies the domain as safe.

  AUTONOMOUS SELF-HEALING ACTIONS (if stages agree it's FP)
  1. Auto-Immunize the eTLD+1 base domain → dynamic trust cache (14-day TTL)
  2. Widen the device's EWMA baseline sigma by +0.25 per confirmed FP
  3. Log suppressed alert silently to state/autonomous_muted.jsonl
  4. Expose all decisions via Prometheus metrics for Grafana transparency

======================================================================================
MEMORY BUDGET ON BOSGAME E4 (AMD Ryzen 5 3550H, 16GB RAM)
======================================================================================
  - LightGBM ONNX model file:         ~1.8 MB
  - FastEmbed BAAI/bge-small-en-v1.5: ~85 MB (loaded once at boot, cached on disk)
  - Python objects / trust cache:      ~5 MB
  - TOTAL NEW OVERHEAD:               ~92 MB  (0.6% of 16GB RAM)
  - CPU per alert evaluation:         < 15 ms (imperceptible on 8-thread Ryzen)
  - All ML models load in background daemon threads → zero startup delay
======================================================================================
"""

import json
import logging
import math
import threading
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ALL decisions made by this engine are visible in Grafana.
# Every Prometheus metric below appears as a panel you can add to your dashboard.
# ---------------------------------------------------------------------------
from metrics import (
    fp_engine_evaluations_total,
    fp_engine_suppressed_total,
    fp_engine_confirmed_threats_total,
    fp_engine_confidence_score,
    fp_engine_trust_cache_size,
    fp_engine_lgbm_model_status,
    fp_engine_embed_model_status,
    fp_engine_stage2_lgbm_hits,
    fp_engine_stage3_embed_hits,
    fp_engine_domains_immunized_total,
    fp_engine_sigma_shifts_total,
)

# ---------------------------------------------------------------------------
# Logger: home_ids.fp_engine appears as its own channel in journalctl
# Run: journalctl -u soc.service -g 'fp_engine' to see only FP engine logs
# ---------------------------------------------------------------------------
LOGGER = logging.getLogger("home_ids.fp_engine")


# ---------------------------------------------------------------------------
# TUNABLE CONSTANTS
# These control the sensitivity of the FP suppression engine.
# More aggressive (lower thresholds) = fewer alerts but more risk of missing real threats.
# More conservative (higher thresholds) = more alerts but zero missed threats.
#
# 2026-08-17 FIX: the four Stage 2/3/combined thresholds below are now read live from
# config.json (fp_lgbm_threshold / fp_embed_similarity_threshold /
# fp_combined_suppress_threshold / fp_combined_uncertain_threshold) via the
# lgbm_fp_threshold / embed_similarity_threshold / combined_suppress_threshold /
# combined_uncertain_threshold properties defined right after __init__ below.
# Previously these were hardcoded here and config.json's matching keys were silently
# ignored no matter what they were set to. The constants below are now only the
# fallback defaults used if the key is missing from config.json.
# ---------------------------------------------------------------------------

# Stage 2: minimum LightGBM P(FP) to proceed towards suppression
_DEFAULT_LGBM_FP_THRESHOLD = 0.75

# Stage 3: minimum cosine similarity to count as a safe vendor pattern match
_DEFAULT_EMBED_SIMILARITY_THRESHOLD = 0.82

# Combined confidence required to autonomously suppress the alert
_DEFAULT_COMBINED_SUPPRESS_THRESHOLD = 0.80

# Combined confidence for "uncertain" (alert sent but marked low-confidence)
_DEFAULT_COMBINED_UNCERTAIN_THRESHOLD = 0.55

# How long an immunized domain stays in the trust cache before re-evaluation
TRUST_CACHE_TTL_SECONDS = 14 * 24 * 3600  # 14 days

# How much to widen a device's EWMA sigma per confirmed FP event
SIGMA_WIDENING_STEP = 0.25

# Maximum total sigma widening per device (safety cap)
MAX_SIGMA_SHIFT = 2.0


class AutonomousFPEngine:
    """
    Closed-Loop Autonomous False-Positive Elimination Engine (CL-AFPE).

    Designed as a drop-in interception layer between risk scorer and alert publisher
    in src/core/pipeline.py. Intercepts every alert breach, runs 3-stage validation,
    and either suppresses it (FP) or confirms it (real threat) autonomously.

    Usage in pipeline.py:
        fp_verdict = self.fp_engine.evaluate(alert_payload, features, risk, ti_engine)
        if fp_verdict["suppress"]:
            continue  # Skip Telegram/Grafana alert – this is a false positive

    All decisions are:
    - Logged at INFO level in journalctl
    - Exported as Prometheus metrics for Grafana
    - Written to state/autonomous_muted.jsonl for full audit trail
    """

    def __init__(self, config: dict, state_dir: str = "state"):
        """
        Initialise the FP Engine. ML models load in background threads
        so the main pipeline is NEVER blocked at startup.

        Args:
            config:     The IDS config dictionary (from config.yaml).
            state_dir:  Path to the state directory. Default: "state/"
        """
        self.config = config

        # -----------------------------------------------------------------
        # File system paths for persistence
        # -----------------------------------------------------------------
        self._state_dir = Path(state_dir)
        self._state_dir.mkdir(parents=True, exist_ok=True)

        # Every suppressed alert is written here with full context.
        # Novice users can inspect this file to see what the engine auto-resolved.
        self._muted_log_path = self._state_dir / "autonomous_muted.jsonl"

        # Base domains that have been verified safe are cached here (14-day TTL).
        # The file survives daemon restarts so the engine remembers your network.
        self._trust_cache_path = self._state_dir / "fp_trust_cache.json"

        # -----------------------------------------------------------------
        # In-memory state
        # -----------------------------------------------------------------
        # Maps eTLD+1 base domain -> unix timestamp when added to cache
        # Example: {"sentry.io": 1722870000.0, "brave.com": 1722870100.0}
        self._trust_cache: dict = {}

        # Maps device_id -> total sigma shift applied (cumulative FP evidence)
        # Example: {"fc3e26115482": 0.50}  (2 FPs confirmed, 2 x 0.25 = 0.5 sigma)
        self._sigma_shifts: dict = {}

        # PHASE 13: per-device threshold profiles — same "strongly different device
        # profiles deserve their own tuning" reasoning that already justifies
        # per-device sigma shifts above, extended to the suppress threshold itself.
        # Maps device_id -> {config_key: {"value", "baseline", "set_at", "set_by",
        # "reason", "sample_count"}}. Written only by
        # scripts/train_fp_classifier.py's per-device calibration pass (see
        # apply_device_fp_profile() below); deliberately NOT routed through config.py's
        # global override layer, which is a flat key-value store not designed for
        # per-device granularity — this stays scoped to AutonomousFPEngine's own state,
        # the same architectural home sigma shifts and the trust cache already use.
        self._device_fp_profiles: dict = {}

        # Thread lock for concurrent access from pipeline worker threads
        self._lock = threading.Lock()

        # -----------------------------------------------------------------
        # ML Model handles (None until background threads finish loading)
        # -----------------------------------------------------------------
        self._lgbm_session = None       # onnxruntime InferenceSession
        self._embed_model = None        # fastembed TextEmbedding model
        self._safe_vendor_embeddings = None   # numpy (N, 384) normalised matrix
        self._safe_vendor_labels: list = []   # human-readable label per row

        # -----------------------------------------------------------------
        # Boot sequence
        # -----------------------------------------------------------------
        LOGGER.info("="*70)
        LOGGER.info("  🤖 Autonomous FP Engine (CL-AFPE) initialising")
        LOGGER.info("  Muted alert audit log : %s", self._muted_log_path)
        LOGGER.info("  Dynamic trust cache   : %s", self._trust_cache_path)
        LOGGER.info("  Stage 2 LGBM threshold: %.2f", self.lgbm_fp_threshold)
        LOGGER.info("  Stage 3 embed threshold: %.2f", self.embed_similarity_threshold)
        LOGGER.info("  Combined suppress threshold: %.2f", self.combined_suppress_threshold)
        LOGGER.info("  Trust cache TTL       : %d days", TRUST_CACHE_TTL_SECONDS // 86400)
        LOGGER.info("="*70)

        # Load persisted trust cache and sigma-shifts from previous session
        self._load_trust_cache()
        self._load_sigma_shifts()
        self._load_device_fp_profiles()

        # Set model status Prometheus gauges to 0 until models are ready
        fp_engine_lgbm_model_status.set(0.0)
        fp_engine_embed_model_status.set(0.0)

        # Launch background model loaders
        # These are daemon threads so they die with the process if soc.service stops.
        threading.Thread(
            target=self._load_lgbm_model,
            daemon=True,
            name="fp_lgbm_loader"
        ).start()
        threading.Thread(
            target=self._load_embed_model,
            daemon=True,
            name="fp_embed_loader"
        ).start()
        threading.Thread(
            target=self._weekly_retrain_loop,
            daemon=True,
            name="fp_weekly_retrainer"
        ).start()

        LOGGER.info(
            "🤖 CL-AFPE boot complete. ML loaders & 7-day retrain daemon active."
        )

    # ==========================================================================
    # LIVE-TUNABLE THRESHOLDS
    # Read from config.json on every access (self.config is the live CONFIG singleton,
    # so a config.json edit + reload picks these up with no restart needed — same as
    # every other dynamic_live_reload key). Falls back to the historically-shipped
    # defaults above if the key is absent from config.json.
    # ==========================================================================

    @property
    def lgbm_fp_threshold(self) -> float:
        """Stage 2: minimum LightGBM P(FP) to proceed towards suppression."""
        return float(self.config.get("fp_lgbm_threshold", _DEFAULT_LGBM_FP_THRESHOLD))

    @property
    def embed_similarity_threshold(self) -> float:
        """Stage 3: minimum cosine similarity to count as a safe vendor pattern match."""
        return float(self.config.get("fp_embed_similarity_threshold", _DEFAULT_EMBED_SIMILARITY_THRESHOLD))

    @property
    def combined_suppress_threshold(self) -> float:
        """Combined confidence required to autonomously suppress the alert."""
        return float(self.config.get("fp_combined_suppress_threshold", _DEFAULT_COMBINED_SUPPRESS_THRESHOLD))

    @property
    def combined_uncertain_threshold(self) -> float:
        """Combined confidence for "uncertain" (alert sent but marked low-confidence)."""
        return float(self.config.get("fp_combined_uncertain_threshold", _DEFAULT_COMBINED_UNCERTAIN_THRESHOLD))

    # ==========================================================================
    # PUBLIC API – Main evaluation entry point
    # ==========================================================================

    def evaluate(
        self,
        alert_payload: dict,
        features: dict,
        risk_score: float,
        ti_engine=None,
    ) -> dict:
        """
        Evaluate a breach alert through the 3-stage autonomous pipeline.

        Call this in pipeline.py BEFORE publishing alerts to Telegram/Grafana.
        The returned verdict tells the pipeline whether to suppress or send the alert.

        Args:
            alert_payload:  Full alert dict (device info, risk, factors, schema).
            features:       Raw feature dict from DNS/Zeek extractors.
            risk_score:     Risk score that triggered the alert (>= alert_threshold).
            ti_engine:      ThreatIntel engine for IOC cross-check (optional).

        Returns:
            dict with keys:
                verdict    : "FALSE_POSITIVE" | "CONFIRMED_THREAT" | "UNCERTAIN"
                confidence : float [0.0=threat, 1.0=definitely FP]
                stage      : str   (which stage made the decision)
                reasons    : list  (human-readable explanation for each factor)
                suppress   : bool  (True → skip Telegram/Grafana alert)
        """
        fp_engine_evaluations_total.inc()

        # Extract identifiers from the alert payload for logging and metrics
        device_id = alert_payload.get("device", {}).get("id", "unknown")
        hostname  = alert_payload.get("device", {}).get("hostname", "unknown")
        domain    = alert_payload.get("network_context", {}).get("queried_domain", "") or ""
        dest_ip   = alert_payload.get("network_context", {}).get("destination_ip", "") or ""

        LOGGER.info(
            "🔍 [FP ENGINE] Evaluating │ device=%-25s │ target=%-40s │ risk=%.2f",
            f"{hostname} ({device_id})", domain or dest_ip, risk_score
        )

        # ==================================================================
        # TRUST CACHE FAST PATH
        # If this domain's base domain or destination IP was previously verified safe,
        # skip ML inference and hard-stops entirely and suppress immediately.
        # This handles recurring alerts for the same FP domain at zero CPU cost,
        # and allows explicit admin immunization to bypass AbuseIPDB/TI false positives.
        # ==================================================================
        base_domain = self._extract_base_domain(domain)
        
        cached_target = None
        if self._is_trust_cached(base_domain):
            cached_target = base_domain
        elif dest_ip and self._is_trust_cached(dest_ip):
            cached_target = dest_ip
            
        if cached_target:
            # ==============================================================
            # PHASE 3 FIX (non-negotiable): the trust-cache fast path used to suppress
            # unconditionally on a cache hit, WITHOUT re-checking hard-stop evidence. That
            # meant an already-immunized domain/IP could be reused for real attack traffic
            # (e.g. domain-fronting through a previously-trusted CDN, or a device that's
            # ALSO doing lateral movement or hitting the honeypot at the same time) and it
            # would be silently suppressed forever, immunization never re-evaluated. Now
            # every cache hit re-runs the same Stage 1 hard-stop filter Stage-2/3 alerts
            # already get, every time, even for immunized domains. This closes audit
            # Finding #2 outright.
            # ==============================================================
            stage1_triggers = self._stage1_hard_stop(features, ti_engine, hostname, domain)
            if stage1_triggers:
                fp_engine_confirmed_threats_total.inc()
                fp_engine_confidence_score.labels(device=device_id, hostname=hostname).set(0.0)
                self._apply_sigma_shift(device_id, hostname, direction="TUNE_UP")
                LOGGER.warning(
                    "🚨 [FP ENGINE » Trust Cache OVERRIDDEN] %s: '%s' is immunized BUT hard-stop "
                    "signal(s) fired: %s → CONFIRMED THREAT despite trust cache hit.",
                    hostname, cached_target, " | ".join(stage1_triggers)
                )
                return {
                    "verdict": "CONFIRMED_THREAT",
                    "confidence": 0.0,
                    "stage": "TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP",
                    "reasons": stage1_triggers,
                    "suppress": False,
                }

            LOGGER.info(
                "✅ [FP ENGINE » Trust Cache] %s: '%s' is immunized (trust cache hit) → suppressed.",
                hostname, cached_target
            )
            fp_engine_suppressed_total.inc()
            fp_engine_confidence_score.labels(device=device_id, hostname=hostname).set(1.0)
            self._write_muted_log(
                alert_payload,
                "TRUST_CACHE_HIT",
                [f"Target '{cached_target}' is in autonomous trust cache (14-day TTL)"],
                1.0
            )
            return {
                "verdict": "FALSE_POSITIVE",
                "confidence": 1.0,
                "stage": "TRUST_CACHE",
                "reasons": [f"'{cached_target}' previously verified safe – dynamic trust cache hit"],
                "suppress": True,
            }

        # ==================================================================
        # STAGE 1: Hard-Stop Security Filter
        # If ANY definitive threat signal is present, bypass all ML models.
        # Real malware C2, port scans and honeypot access CANNOT be FPs.
        # ==================================================================
        LOGGER.debug("[FP ENGINE » Stage 1] Running hard-stop security filter...")
        stage1_triggers = self._stage1_hard_stop(features, ti_engine, hostname, domain)

        if stage1_triggers:
            # One or more hard-stop signals fired → this is a real threat
            fp_engine_confirmed_threats_total.inc()
            fp_engine_confidence_score.labels(device=device_id, hostname=hostname).set(0.0)
            
            # Self-Strengthening Action: TUNE UP sensitivity for this device (tighten thresholds)
            self._apply_sigma_shift(device_id, hostname, direction="TUNE_UP")

            LOGGER.warning(
                "🚨 [FP ENGINE » Stage 1] CONFIRMED THREAT for %s │ Triggers: %s │ Sensitivity tuned UP",
                hostname, " | ".join(stage1_triggers)
            )
            return {
                "verdict": "CONFIRMED_THREAT",
                "confidence": 0.0,
                "stage": "STAGE_1_HARD_STOP",
                "reasons": stage1_triggers,
                "suppress": False,
            }

        LOGGER.debug("[FP ENGINE » Stage 1] Passed – no hard-stop threat signals detected.")

        # ==================================================================
        # STAGE 2: LightGBM ONNX Tabular Classifier
        # Fast probabilistic scoring on numeric features.
        # Returns None if model not yet loaded – Stage 3 will still run.
        # ==================================================================
        LOGGER.debug("[FP ENGINE » Stage 2] Running LightGBM ONNX inference...")
        lgbm_prob = self._stage2_lgbm(features, domain, hostname, device_id)

        if lgbm_prob is not None:
            # PHASE 6 FIX (Stage 2 early-return bug): this used to `return` right here
            # whenever lgbm_prob < self.lgbm_fp_threshold, publishing the alert as UNCERTAIN
            # WITHOUT ever running Stage 3 — directly contradicting the log line below,
            # which has always claimed Stage 3 runs "for corroboration" in exactly this
            # case. The practical effect: Stage 3 (semantic vendor-domain matching) could
            # only ever CONFIRM an FP that LightGBM already leaned towards (P(FP)>=0.75,
            # the untouched branch below that already falls through), never RESCUE a
            # legitimate domain LightGBM scored low on its own — backwards from the point
            # of running two independent, differently-failure-prone classifiers. This is
            # mostly moot today since the shipped LightGBM model is a freshly-generated,
            # untrained placeholder, but once it retrains on real alert history (see
            # train_fp_classifier.py / mark_false_positive() below) this would have started
            # silently skipping semantic corroboration for every alert LightGBM felt
            # confident about — including the exact aiv-delivery.net-shaped case (a CDN
            # domain with numerically anomalous features that Stage 3's vendor-pattern
            # matching is specifically built to catch). Both branches now fall through
            # identically to Stage 3 and the weighted combined score below.
            LOGGER.info(
                "📊 [FP ENGINE » Stage 2] %s: P(FP)=%.3f (threshold=%.2f) %s",
                hostname, lgbm_prob, self.lgbm_fp_threshold,
                "→ proceeding to Stage 3" if lgbm_prob >= self.lgbm_fp_threshold else "→ LOW FP probability (continuing to Stage 3 for corroboration)"
            )
        else:
            LOGGER.debug("[FP ENGINE » Stage 2] Model not ready yet – using neutral fallback (0.50).")
            lgbm_prob = 0.50  # neutral – let Stage 3 decide

        # ==================================================================
        # STAGE 3: FastEmbed Vector Similarity Matcher
        # Compares the domain semantically against the safe vendor reference db.
        # Falls back to static CDN rule matching if model not loaded yet.
        #
        # PHASE 10 FIX: a raw-IP-only connection (no DNS resolution happened) has
        # `domain` set to the literal string "unknown", not empty. Previously that string
        # was fed straight into FastEmbed as if it were a real hostname — cosine-similarity
        # scoring the word "unknown" against vendor domain embeddings and getting back a
        # meaningless-but-real-looking number (e.g. 0.608) that then materially swayed the
        # combined suppression score. Skip Stage 3 entirely when there's no real
        # domain/hostname to compare — the honest answer is "not applicable", not a
        # semantic similarity score for a placeholder string.
        # ==================================================================
        has_real_domain = bool(domain) and domain.strip().lower() not in ("unknown", "null", "none", "")

        if not has_real_domain:
            embed_sim, embed_match = None, "N/A (no resolved hostname/domain — raw IP connection)"
            LOGGER.debug("[FP ENGINE » Stage 3] Skipped: no real domain/hostname to compare (target='%s').", domain)
        else:
            LOGGER.debug("[FP ENGINE » Stage 3] Running FastEmbed vector similarity...")
            embed_sim, embed_match = self._stage3_embed(domain, hostname)

            if embed_sim is None:
                # FastEmbed not yet loaded – use static CDN/vendor rule fallback
                embed_sim, embed_match = self._stage3_rule_fallback(domain)
                LOGGER.debug(
                    "[FP ENGINE » Stage 3] Rule fallback: similarity=%.3f, match='%s'",
                    embed_sim, embed_match
                )
            else:
                LOGGER.info(
                    "🧠 [FP ENGINE » Stage 3] %s: cosine similarity=%.3f for domain='%s' │ best match='%s'",
                    hostname, embed_sim, domain, embed_match
                )

        embed_sim_str = f"{embed_sim:.3f}" if embed_sim is not None else "N/A"

        # ==================================================================
        # FINAL VERDICT: Weighted combination of Stage 2 + Stage 3 scores
        #
        # Weight rationale:
        #   LightGBM (0.45): Good at tabular numeric features but knows nothing
        #                    about the semantics of domain names.
        #   FastEmbed (0.55): Better at understanding vendor domain name patterns
        #                     but slower and needs model warm-up.
        #
        # PHASE 10 FIX: when Stage 3 is N/A (embed_sim is None), fall back to LightGBM
        # alone at full weight instead of silently treating a missing signal as 0.0 in the
        # weighted blend — a 0.0 would itself be a false "strongly not similar to anything
        # safe" signal, just as wrong as the "unknown"-string similarity it replaces.
        # ==================================================================
        if embed_sim is None:
            combined = lgbm_prob
        elif lgbm_prob == 0.50 and embed_sim >= self.embed_similarity_threshold:
            combined = embed_sim
        else:
            combined = (lgbm_prob * 0.45) + (embed_sim * 0.55)
        LOGGER.info(
            "⚖️  [FP ENGINE » Final] %s: combined=%.3f "
            "(LGBM=%.3f×0.45 + Embed=%s×0.55) | domain='%s'",
            hostname, combined, lgbm_prob, embed_sim_str, domain
        )
        fp_engine_confidence_score.labels(device=device_id, hostname=hostname).set(combined)

        # PHASE 13: per-device threshold, falling back to the global one — see
        # get_device_suppress_threshold()'s docstring. Computed once and reused for both
        # the actual decision and the audit-trail text below so they can never disagree.
        effective_suppress_threshold = self.get_device_suppress_threshold(device_id)

        if combined >= effective_suppress_threshold:
            # ---------------------------------------------------------------
            # HIGH CONFIDENCE FALSE POSITIVE → auto-suppress + self-heal
            # ---------------------------------------------------------------
            LOGGER.info(
                "✅ [FP ENGINE » SUPPRESS] %s: ALERT SUPPRESSED as FALSE POSITIVE "
                "(confidence=%.3f, domain='%s', match='%s')",
                hostname, combined, domain, embed_match
            )
            fp_engine_suppressed_total.inc()
            if embed_sim is not None and embed_sim >= self.embed_similarity_threshold:
                fp_engine_stage3_embed_hits.inc()
            elif lgbm_prob >= self.lgbm_fp_threshold:
                fp_engine_stage2_lgbm_hits.inc()

            # Self-healing Action 1: Add base domain to 14-day trust cache
            is_new_immunization = self._immunize_domain(base_domain, hostname)

            # Self-healing Action 2: Widen device's EWMA sigma by +0.25
            self._apply_sigma_shift(device_id, hostname)

            # Self-healing Action 3: Write full audit log entry (never silently lost)
            reasons = [
                f"LightGBM P(FP)={lgbm_prob:.3f} (Stage 2)",
                f"FastEmbed cosine similarity={embed_sim_str} → best match: '{embed_match}' (Stage 3)",
                f"Combined confidence={combined:.3f} >= {effective_suppress_threshold} (suppress threshold)",
            ]
            self._write_muted_log(alert_payload, "AUTONOMOUS_FP_SUPPRESSED", reasons, combined)

            return {
                "verdict": "FALSE_POSITIVE",
                "confidence": combined,
                "stage": "STAGE_3_COMBINED",
                "reasons": reasons,
                "suppress": True,
                # PHASE 3 (closed-loop): pipeline.py uses this to decide whether to record
                # a revocable action + send a non-blocking "🔔 Auto-action" Telegram
                # notification with a one-tap [Revoke] button. Only on a genuinely NEW
                # immunization — a repeat suppression of an already-known-safe domain
                # doesn't need a fresh revoke prompt every time it recurs.
                "action": {"type": "immunize_domain", "target": base_domain, "is_new": is_new_immunization}
                          if base_domain and is_new_immunization else None,
            }

        elif combined >= self.combined_uncertain_threshold:
            # ---------------------------------------------------------------
            # UNCERTAIN – alert is published but marked as low-confidence
            # The pipeline will add an '⚠️ Low Confidence Alert' tag to Telegram
            # ---------------------------------------------------------------
            LOGGER.info(
                "⚠️  [FP ENGINE » UNCERTAIN] %s: Alert PUBLISHED with LOW CONFIDENCE "
                "(combined=%.3f). Monitoring for pattern...",
                hostname, combined
            )
            return {
                "verdict": "UNCERTAIN",
                "confidence": combined,
                "stage": "STAGE_3_COMBINED",
                "reasons": [
                    f"LightGBM P(FP)={lgbm_prob:.3f}",
                    f"FastEmbed similarity={embed_sim_str} for domain '{domain}' → best match: '{embed_match or 'N/A'}'",
                    f"Combined confidence={combined:.3f} insufficient to suppress (threshold={effective_suppress_threshold})",
                ],
                "suppress": False,
            }

        else:
            # ---------------------------------------------------------------
            # LOW FP PROBABILITY → CONFIRMED THREAT
            # Alert published at full severity & threat detection tuned UP
            # ---------------------------------------------------------------
            fp_engine_confirmed_threats_total.inc()
            
            # Self-Strengthening Action: TUNE UP sensitivity for this device (tighten thresholds)
            self._apply_sigma_shift(device_id, hostname, direction="TUNE_UP")

            LOGGER.warning(
                "🚨 [FP ENGINE » THREAT] %s: LOW FP confidence (%.3f) → CONFIRMED THREAT "
                "| Published at full severity | Sensitivity tuned UP.",
                hostname, combined
            )
            return {
                "verdict": "CONFIRMED_THREAT",
                "confidence": combined,
                "stage": "STAGE_3_COMBINED",
                "reasons": [
                    f"LightGBM P(FP)={lgbm_prob:.3f}",
                    f"FastEmbed similarity={embed_sim_str} for domain '{domain}' → best match: '{embed_match or 'N/A'}'",
                    "Alert pattern consistent with genuine threat activity",
                ],
                "suppress": False,
            }

    # ==========================================================================
    # PUBLIC UTILITY METHODS (used by pipeline.py and scoring.py)
    # ==========================================================================

    def get_dynamic_trust_cache(self) -> set:
        """
        Returns the set of currently immunized base domains (non-expired only).

        Called by scoring.py / pipeline.py each evaluation cycle so that domains
        in the trust cache get an is_domain_safe=True bypass with zero ML overhead.

        Example return: {"sentry.io", "brave.com", "grafana.sky"}
        """
        now = time.time()
        with self._lock:
            active = {d for d, ts in self._trust_cache.items()
                      if (now - ts) < TRUST_CACHE_TTL_SECONDS}
        return active

    def get_sigma_shift(self, device_id: str) -> float:
        """
        Returns the cumulative sigma widening applied to this device.

        Used by scoring.py to expand the device's EWMA baseline comparison
        threshold so repeated legitimate alerts don't cause flapping.

        Example: 0.25 means one confirmed FP event has widened threshold by 0.25 sigma.
        """
        with self._lock:
            return self._sigma_shifts.get(device_id, 0.0)

    # ==========================================================================
    # STAGE 1: Hard-Stop Security Filter
    # ==========================================================================

    def _stage1_hard_stop(
        self, features: dict, ti_engine, hostname: str, domain: str
    ) -> Optional[list]:
        """
        Fast filter for definitive threat signals that cannot be false positives.

        Checks are ordered from most to least severe:
        1. ThreatIntel IOC match (Feodo, ThreatFox, OTX malware blacklists)
        2. Active lateral movement (internal port scanning)
        3. Malicious TLS fingerprint (JA3/JA4+ known malware libraries)
        4. Honeypot access (decoy server 192.168.1.200)
        5. AbuseIPDB confirmed malicious destination IP

        Returns:
            List of trigger strings if any hard-stop signal fires → CONFIRMED THREAT
            None if no hard-stop signals → proceed to Stage 2
        """
        triggers = []

        # Check 1: ThreatIntel IOC (Feodo Tracker, ThreatFox, OTX)
        # If the queried domain is on a global malware blocklist, this CANNOT be a FP.
        ti_risk = float(features.get("ti_risk", 0.0) or 0.0)
        if ti_risk > 0:
            triggers.append(
                f"ThreatIntel IOC match (ti_risk={ti_risk:.2f}) – domain on global malware blacklist"
            )
            LOGGER.debug("[Stage 1] %s: ThreatIntel IOC hit (ti_risk=%.2f)", hostname, ti_risk)

        # Check 2: Lateral movement / internal port scanning
        # A device scanning internal network ports (192.168.x.x) is active attack behaviour.
        lateral = int(features.get("zeek_lateral_moves", 0) or 0)
        if lateral > 0:
            triggers.append(f"Internal lateral movement / port scan ({lateral} events)")
            LOGGER.debug("[Stage 1] %s: Lateral movement (%d events)", hostname, lateral)

        # Check 3: Malicious TLS fingerprint (JA3/JA4+)
        # These are cryptographic fingerprints of specific malware TLS implementations.
        # If the device is using a malware TLS stack, this is a definitive threat signal.
        ja3 = int(features.get("zeek_ja3_malicious", 0) or 0)
        ja4 = int(features.get("zeek_ja4_malicious", 0) or 0)
        if ja3 > 0 or ja4 > 0:
            triggers.append(f"Malicious TLS fingerprint (JA3={ja3}, JA4+={ja4} hits)")
            LOGGER.debug("[Stage 1] %s: Malicious TLS (JA3=%d, JA4=%d)", hostname, ja3, ja4)

        # Check 4: Honeypot access
        # Our internal decoy server should NEVER receive legitimate traffic.
        honeypot = int(features.get("zeek_honeypot_hits", 0) or 0)
        if honeypot > 0:
            triggers.append(f"Internal honeypot accessed ({honeypot} connections to decoy server)")
            LOGGER.debug("[Stage 1] %s: Honeypot hit (%d)", hostname, honeypot)

        # Check 5: AbuseIPDB confirmed blacklisted destination
        abuse = float(features.get("abuseipdb_risk", 0.0) or 0.0)
        if abuse >= 4.0:
            triggers.append(f"AbuseIPDB blacklisted destination IP (risk={abuse:.1f})")
            LOGGER.debug("[Stage 1] %s: AbuseIPDB risk=%.1f", hostname, abuse)

        # Check 6: Exfiltration Payload Burst Hard-Stop
        out_z = float(features.get("outbound_bytes_z", 0.0) or 0.0)
        if out_z > 5.0:
            triggers.append(f"Exfiltration Payload Burst (outbound_bytes_z={out_z:.2f})")
            LOGGER.warning("[Stage 1] %s: Exfiltration Hard-Stop triggered (Z=%.2f)", hostname, out_z)

        return triggers if triggers else None

    # ==========================================================================
    # STAGE 2: LightGBM ONNX Tabular Classifier
    # ==========================================================================

    def _stage2_lgbm(
        self, features: dict, domain: str, hostname: str, device_id: str
    ) -> Optional[float]:
        """
        Run the LightGBM ONNX model to produce P(False Positive).

        Feature vector construction (9 dimensions):
          [0] tranco_rank_norm    : 0.0 (unknown domain) → 1.0 (rank #1 globally)
          [1] label_entropy_norm  : 0.0 (low entropy, human-readable) → 1.0 (high entropy)
          [2] label_len_norm      : 0.0 (short, normal label) → 1.0 (>60 chars, tunneling)
          [3] outbound_z_norm     : 0.0 (no unusual upload) → 1.0 (extreme exfil Z-score)
          [4] dev_type_norm       : device category weight (laptop=0.5, iot=0.1)
          [5] hist_fp             : 1.0 if base domain was previously in trust cache, else 0.0
          [6] lateral_moves_norm  : min(zeek_lateral_moves / 10.0, 1.0)
          [7] port_scans_norm     : min(zeek_s0_rej_count / 50.0, 1.0)
          [8] app_proto_norm      : application protocol weight [0.2, 1.0]

        Returns:
            float P(FP) in [0, 1] if model is loaded.
            None if model is still warming up (caller uses fallback).
        """
        if self._lgbm_session is None:
            return None  # Model not ready yet – caller will use neutral 0.50

        try:
            import numpy as np
            from utils import entropy as compute_entropy

            # Feature 0: Tranco global domain rank
            tranco_rank = float(features.get("tranco_rank", 0) or 0)
            f0_tranco = max(0.0, 1.0 - (tranco_rank / 1_000_000.0)) if tranco_rank > 0 else 0.0

            # Feature 1: Shannon entropy of the first subdomain label
            label = domain.split(".")[0] if domain else ""
            f1_entropy = min(compute_entropy(label) / 5.0, 1.0)

            # Feature 2: Maximum subdomain label length
            max_label = float(features.get("max_label_length", 0) or 0)
            f2_label_len = min(max_label / 60.0, 1.0)

            # Feature 3: Outbound bytes Z-score
            out_z = float(features.get("outbound_bytes_z", 0.0) or 0.0)
            f3_out_z = min(max(out_z, 0.0) / 10.0, 1.0)

            # Feature 4: Device type category weight
            dev_type_weights = {
                "laptop": 0.5, "desktop": 0.5,
                "phone": 0.4, "tablet": 0.4,
                "smart_tv": 0.3, "gaming_console": 0.3,
                "printer": 0.2, "nas": 0.2,
                "iot": 0.1, "camera": 0.1,
                "unknown": 0.3,
            }
            dev_type = str(features.get("device_type", "unknown") or "unknown")
            f4_dev_type = dev_type_weights.get(dev_type, 0.3)

            # Feature 5: Historical FP signal
            base_domain = self._extract_base_domain(domain)
            with self._lock:
                f5_hist_fp = 1.0 if base_domain in self._trust_cache else 0.0

            # Multi-Threat Features 6, 7, 8: Lateral Moves, Port Scans, Application Protocol Weight
            f6_lateral = min(float(features.get("zeek_lateral_moves", 0) or 0) / 10.0, 1.0)
            f7_port_scans = min(float(features.get("zeek_s0_rej_count", 0) or 0) / 50.0, 1.0)
            f8_app_proto = min(max(float(features.get("zeek_app_protocol_weight", 0.2) or 0.2), 0.0), 1.0)

            # Check ONNX model expected input shape (6-feature legacy vs 9-feature multi-threat)
            input_spec = self._lgbm_session.get_inputs()[0]
            input_name = input_spec.name
            expected_feats = input_spec.shape[1] if (len(input_spec.shape) > 1 and isinstance(input_spec.shape[1], int)) else 6

            if expected_feats == 6:
                feat_vec = np.array([[f0_tranco, f1_entropy, f2_label_len,
                                      f3_out_z, f4_dev_type, f5_hist_fp]], dtype=np.float32)
            else:
                feat_vec = np.array([[f0_tranco, f1_entropy, f2_label_len,
                                      f3_out_z, f4_dev_type, f5_hist_fp,
                                      f6_lateral, f7_port_scans, f8_app_proto]], dtype=np.float32)

            LOGGER.debug(
                "[Stage 2] %s: %d-feature_vector=[tranco=%.3f, entropy=%.3f, label_len=%.3f, "
                "out_z=%.3f, dev_type=%.3f, hist_fp=%.1f]",
                hostname, expected_feats, f0_tranco, f1_entropy, f2_label_len, f3_out_z, f4_dev_type, f5_hist_fp
            )

            # Run ONNX inference (< 2 ms)
            input_name = self._lgbm_session.get_inputs()[0].name
            outputs = self._lgbm_session.run(None, {input_name: feat_vec})

            prob_fp = self._parse_onnx_prob(outputs)
            LOGGER.debug("[Stage 2] %s: ONNX P(FP)=%.4f", hostname, prob_fp)
            return prob_fp

        except Exception as exc:
            LOGGER.error(
                "[Stage 2] ONNX inference error for %s: %s – falling through to Stage 3.",
                hostname, exc, exc_info=True
            )
            return None

    def _parse_onnx_prob(self, outputs: list) -> float:
        """
        Robustly extracts P(False Positive) [class 1 probability] from ONNX session outputs.
        Handles both skl2onnx ZipMap format ([{0: p0, 1: p1}]) and 2D array format ([[p0, p1]]).
        """
        if not outputs:
            return 0.50

        # skl2onnx puts probabilities in outputs[1] when outputs[0] is class labels
        target = outputs[1] if len(outputs) > 1 else outputs[0]

        # Case 1: ZipMap format -> list of dicts: [{0: 0.85, 1: 0.15}]
        if isinstance(target, list) and len(target) > 0 and isinstance(target[0], dict):
            d = target[0]
            val = d.get(1, d.get(1.0, d.get("1", 0.50)))
            return float(val)

        # Case 2: Numpy array format
        try:
            import numpy as np
            arr = np.array(target)
            if arr.ndim == 2 and arr.shape[1] >= 2:
                return float(arr[0][1])
            elif arr.ndim == 1 and arr.shape[0] >= 2:
                return float(arr[1])
            elif arr.size == 1:
                return float(arr.flat[0])
        except Exception:
            pass

        return 0.50

    # ==========================================================================
    # STAGE 3: FastEmbed Vector Similarity Matcher
    # ==========================================================================

    def _stage3_embed(self, domain: str, hostname: str):
        """
        Compare the queried domain against pre-computed safe vendor embeddings.

        The BAAI/bge-small-en-v1.5 model converts domain strings to 384-dim dense
        vectors. We pre-computed the safe vendor matrix at boot so this stage is
        a single fast matrix multiply (< 15 ms on Ryzen 5 3550H CPU).

        Returns:
            (cosine_similarity: float, best_match_label: str) if model ready
            (None, None) if FastEmbed model is still loading
        """
        if self._embed_model is None or self._safe_vendor_embeddings is None:
            return None, None

        try:
            import numpy as np

            # Embed the queried domain to a 384-dim vector
            query_vec = list(self._embed_model.embed([domain]))[0]
            query_vec = np.array(query_vec, dtype=np.float32)

            # Normalise to unit vector for cosine similarity via dot product
            q_norm = query_vec / (np.linalg.norm(query_vec) + 1e-9)

            # Matrix-vector multiplication: (N, 384) × (384,) → (N,)
            similarities = self._safe_vendor_embeddings @ q_norm

            # Find the best-matching vendor pattern
            best_idx = int(np.argmax(similarities))
            best_sim = float(similarities[best_idx])
            best_label = (self._safe_vendor_labels[best_idx]
                          if best_idx < len(self._safe_vendor_labels) else "unknown")

            LOGGER.debug(
                "[Stage 3] %s: top match='%s' (sim=%.4f) for domain='%s'",
                hostname, best_label, best_sim, domain
            )
            return best_sim, best_label

        except Exception as exc:
            LOGGER.error(
                "[Stage 3] FastEmbed error for %s: %s – using rule fallback.",
                hostname, exc, exc_info=True
            )
            return None, None

    def _stage3_rule_fallback(self, domain: str):
        """
        Static rule-based fallback for Stage 3 when FastEmbed is not yet loaded.

        Uses the comprehensive CDN/vendor allowlists from utils.py which cover
        the most common legitimate traffic sources. Less accurate than vector
        matching but instant and requires zero ML dependencies.

        Returns: (similarity_score: float, match_description: str)
        """
        from utils import _is_cdn_or_cloud_domain, is_telemetry_domain
        if is_telemetry_domain(domain):
            return 0.92, "static rule: known telemetry domain"
        if _is_cdn_or_cloud_domain(domain):
            return 0.88, "static rule: known CDN/cloud vendor domain"
        return 0.05, "static rule: no vendor pattern match"

    # ==========================================================================
    # SELF-HEALING ACTIONS
    # ==========================================================================

    def _immunize_domain(self, base_domain: str, hostname: str, source: str = "autonomous") -> bool:
        """
        Add a base domain to the persistent dynamic trust cache (14-day TTL).

        `source` is one of "autonomous" (CL-AFPE's own Stage 2/3 suppress path),
        "operator" (Telegram "Mark False Positive" tap), or "llm_validated" (Brain 3) --
        tags the immunized_total counter so Grafana can show how much of the healing is
        autonomous vs human-approved, the entire point of the self-calibration story.

        After immunization:
        - Any subdomain of base_domain across ALL devices gets is_domain_safe=True
          without running any ML inference.
        - The cache entry is written to disk so it survives soc.service restarts.
        - The Prometheus trust cache size gauge is updated.

        Example: immunizing 'sentry.io' means future alerts for
                 'xyz.ingest.us.sentry.io' are instantly suppressed.

        Returns:
            True if this was a NEW immunization (not previously cached), False if it was
            invalid or just a TTL refresh of an already-immunized domain. PHASE 3: the
            caller uses this to decide whether to offer a fresh [Revoke] prompt.
        """
        if not base_domain or str(base_domain).lower() in ("unknown", "null", "none"):
            LOGGER.warning("❌ [FP ENGINE » IMMUNIZE] Rejected invalid domain immunization attempt: '%s'", base_domain)
            return False

        now = time.time()
        with self._lock:
            is_new = base_domain not in self._trust_cache
            self._trust_cache[base_domain] = now
            cache_size = len(self._trust_cache)

        try:
            from utils import register_dynamic_allowlist_domain
            register_dynamic_allowlist_domain(base_domain)
        except Exception:
            pass

        if is_new:
            fp_engine_domains_immunized_total.labels(source=source).inc()
            LOGGER.info(
                "🛡️  [FP ENGINE » IMMUNIZE] NEW: '%s' added to autonomous trust cache "
                "(TTL: 14 days). Triggered by device: %s",
                base_domain, hostname
            )
        else:
            LOGGER.info(
                "🔄 [FP ENGINE » IMMUNIZE] REFRESH: '%s' trust cache TTL refreshed.",
                base_domain
            )

        fp_engine_trust_cache_size.set(cache_size)
        self._save_trust_cache()
        return is_new

    def revoke_immunization(self, base_domain: str) -> bool:
        """PHASE 3 (closed-loop): reverses _immunize_domain() — removes a base domain from
        the trust cache. Called when an operator taps [Revoke] on a Telegram '🔔
        Auto-action' notification, i.e. the human-in-the-loop half of the closed loop.

        Known limitation: this does not remove the domain from utils.py's separate
        `_DYNAMIC_TELEMETRY_ALLOWLIST` (register_dynamic_allowlist_domain has no
        unregister counterpart), so is_telemetry_domain() may still treat the domain as
        safe for DGA/tunneling-signal dampening purposes after a revoke. The trust cache
        itself — which is what actually suppresses alerts and what
        ThreatIntel.is_allowlisted() checks — is fully reversed.
        """
        with self._lock:
            existed = base_domain in self._trust_cache
            if existed:
                del self._trust_cache[base_domain]
                cache_size = len(self._trust_cache)
        if existed:
            fp_engine_trust_cache_size.set(cache_size)
            self._save_trust_cache()
            LOGGER.warning("🔙 [FP ENGINE » REVOKE] '%s' removed from trust cache by operator revoke.", base_domain)
        else:
            LOGGER.debug("[FP ENGINE » REVOKE] '%s' was not in trust cache (already expired or never cached).", base_domain)
        return existed

    def mark_false_positive(self, alert_payload: dict, hostname: str, target_domain: str = "", source: str = "operator") -> dict:
        """PHASE 6 (operator-driven self-healing): originally the human-in-the-loop half of
        the FP closed loop — called when an operator taps "🛡️ Mark False Positive" on a
        PUBLISHED alert's Telegram message (i.e. one fp_engine did NOT autonomously
        suppress; see AUTONOMOUS_FP_SUPPRESSED for the fully-autonomous Stage2/3 path via
        evaluate()).

        PHASE 13: also called by scripts/ollama_soc.py for its own validated LLM verdicts
        — the same correction, just triggered autonomously every 4h instead of by a
        Telegram tap. Both call this same method (same domain-immunization, same sigma
        widening, same training-set correction), but `source` tags WHICH judge made the
        call ("operator" | "llm_validated") so downstream consumers — specifically
        train_fp_classifier.py's threshold self-calibration — can tell them apart, or pool
        both, without conflating "a human confirmed this" with "the LLM did, and passed
        DeterministicValidator's hallucination check". Per explicit direction: with
        alert volume high enough that 5 human corrections in a reasonable window isn't
        realistic, autonomous LLM-validated evidence is the PRIMARY calibration signal;
        human corrections remain a valid, faster-acting, optional addition on top, never
        a requirement.

        Why this matters beyond just immunizing the domain: without this, an operator
        correction only ever silences the ONE alert in front of them. The alert itself
        stays sitting in the alert stream (state/alerts.json) labeled as a confirmed
        threat (label=0) forever, and train_fp_classifier.py's weekly retrain would keep
        reinforcing it as "this pattern = threat" on every future run — actively teaching
        the model the WRONG lesson from a correction the operator already made. This
        method closes that gap the same way the fully-autonomous path already does: by
        writing the correction to autonomous_muted.jsonl (label=1/FP) via the exact same
        _write_muted_log() used by AUTONOMOUS_FP_SUPPRESSED, so load_dataset() picks it up
        as a false-positive training sample without any special-casing on the training
        side. train_fp_classifier.py's load_dataset() additionally cross-references this
        log to drop the matching pre-correction entry from the alerts.json "threat" set,
        so the SAME event doesn't end up labeled both ways in one training run.

        Returns a dict with `base_domain` (the eTLD+1 that got immunized, or "" if the
        domain couldn't be safely extracted) and `is_new_immunization` for the caller to
        report back to the operator / decide whether an unblock is even necessary.
        """
        domain = target_domain or alert_payload.get("network_context", {}).get("queried_domain", "") or ""
        base_domain = self._extract_base_domain(domain)
        device_id = alert_payload.get("device", {}).get("id", "unknown")

        is_new_immunization = False
        if base_domain:
            is_new_immunization = self._immunize_domain(base_domain, hostname, source=source)
        else:
            LOGGER.warning(
                "⚠️ [FP ENGINE » MARK FP] %s: could not extract a safe base domain from '%s' — "
                "skipping trust-cache immunization, but still recording the training "
                "correction and sigma widening below.",
                hostname, domain
            )

        # Self-healing Action: widen THIS device's EWMA sigma — same TUNE_DOWN adjustment
        # the autonomous path applies, scoped to the one device this correction is about.
        self._apply_sigma_shift(device_id, hostname, source=source)

        is_llm = source == "llm_validated"
        event_type = "LLM_VALIDATED_FALSE_POSITIVE" if is_llm else "OPERATOR_MARKED_FALSE_POSITIVE"
        origin_text = "Ollama LLM (DeterministicValidator-passed)" if is_llm else "operator via Telegram"

        reasons = [
            f"Marked as false positive for '{domain or 'unknown'}' by {origin_text}.",
            f"Base domain '{base_domain}' added to trust cache." if base_domain else
            "Base domain could not be extracted — trust cache NOT updated for this domain.",
        ]
        self._write_muted_log(alert_payload, event_type, reasons, 1.0)

        LOGGER.warning(
            "🛡️  [FP ENGINE » MARK FP] %s: %s-corrected alert for '%s' — training "
            "correction logged, sigma widened, domain %s.",
            hostname, "LLM" if is_llm else "operator", domain,
            f"immunized ('{base_domain}')" if base_domain else "NOT immunized (extraction failed)"
        )

        return {
            "base_domain": base_domain,
            "is_new_immunization": is_new_immunization,
            "domain": domain,
        }

    def _apply_sigma_shift(self, device_id: str, hostname: str, direction: str = "TUNE_DOWN", source: str = "autonomous"):
        """
        Bidirectional sensitivity adjustment:
        - TUNE_DOWN (FP confirmed): Widens EWMA threshold by +0.25σ (up to +2.0σ max).
        - TUNE_UP (Threat confirmed): Tightens EWMA threshold by -0.50σ (down to -1.5σ floor).

        The shift value is read by scoring.py via get_sigma_shift(device_id).
        `source` is "autonomous"/"operator"/"llm_validated" -- see _immunize_domain()'s
        docstring for why this is tagged the same way.
        """
        with self._lock:
            current = self._sigma_shifts.get(device_id, 0.0)
            if direction == "TUNE_DOWN":
                new_val = min(current + SIGMA_WIDENING_STEP, MAX_SIGMA_SHIFT)
            else:
                # TUNE_UP: Tighten sensitivity for threat-associated devices
                new_val = max(current - 0.50, -1.5)
            self._sigma_shifts[device_id] = new_val

        fp_engine_sigma_shifts_total.labels(device=device_id, hostname=hostname, source=source).inc()
        self._save_sigma_shifts()

        if direction == "TUNE_DOWN":
            LOGGER.info(
                "📐 [FP ENGINE » SIGMA TUNE DOWN] %s (%s): threshold widened +%.2fσ → total shift=%.2fσ (cap=%.1fσ)",
                hostname, device_id, SIGMA_WIDENING_STEP, new_val, MAX_SIGMA_SHIFT
            )
        else:
            LOGGER.warning(
                "⚡ [FP ENGINE » SIGMA TUNE UP] %s (%s): SENSITIVITY TIGHTENED -0.50σ → total shift=%.2fσ (floor=-1.5σ)",
                hostname, device_id, new_val
            )

    def _save_sigma_shifts(self):
        try:
            p = self._state_dir / "fp_sigma_shifts.json"
            with self._lock:
                snapshot = dict(self._sigma_shifts)
            p.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        except Exception: pass

    def _load_sigma_shifts(self):
        path = self._state_dir / "fp_sigma_shifts.json"
        if not path.exists():
            LOGGER.info("No existing sigma-shift state at %s. Starting fresh.", path)
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            now = time.time()
            pruned = 0
            with self._lock:
                for device_id, shift in list(raw.items()):
                    if isinstance(shift, (int, float)):
                        self._sigma_shifts[device_id] = float(shift)
                    else:
                        pruned += 1
                self._prune_expired_fp_state(now)
            LOGGER.info("✅ Sigma shift state loaded: %d entries, %d pruned.", len(self._sigma_shifts), pruned)
        except Exception as exc:
            LOGGER.error("Failed to load sigma shifts: %s", exc, exc_info=True)

    # ==========================================================================
    # PHASE 13: PER-DEVICE THRESHOLD PROFILES
    # ==========================================================================

    def get_device_suppress_threshold(self, device_id: Optional[str]) -> float:
        """The effective fp_combined_suppress_threshold for ONE device: its own calibrated
        profile if one exists (written by train_fp_classifier.py's per-device calibration
        pass, gated on that device's own confirmed-FP history), else the global value
        (config.yaml, possibly itself autonomously lowered by the global calibration pass
        — see config.py's LiveConfig._load_overrides()). Devices with "strongly different
        profiles" (an IoT bulb vs. a laptop vs. a NAS) get their own number once there's
        enough of their OWN evidence to justify it; everything else shares the global
        default, same layered-fallback shape as the config override layer."""
        with self._lock:
            profile = self._device_fp_profiles.get(device_id or "")
        if profile and "fp_combined_suppress_threshold" in profile:
            return float(profile["fp_combined_suppress_threshold"]["value"])
        return self.combined_suppress_threshold

    def apply_device_fp_profile(self, device_id: str, key: str, value: float, baseline: float,
                                 set_by: str, reason: str, sample_count: int = 0) -> None:
        """Writes ONE calibrated value into ONE device's profile, preserving every other
        key/device already present. Called by train_fp_classifier.py's per-device
        calibration pass — see get_device_suppress_threshold() for how it's read back."""
        with self._lock:
            profile = self._device_fp_profiles.setdefault(device_id, {})
            profile[key] = {
                "value": value, "baseline": baseline, "set_at": time.time(),
                "set_by": set_by, "reason": reason, "sample_count": sample_count,
            }
        self._save_device_fp_profiles()
        LOGGER.info(
            "🔧 [FP ENGINE » DEVICE PROFILE] %s: %s = %.3f (baseline %.3f, %d sample(s)). %s",
            device_id, key, value, baseline, sample_count, reason
        )

    def _save_device_fp_profiles(self):
        try:
            p = self._state_dir / "device_fp_profiles.json"
            with self._lock:
                snapshot = dict(self._device_fp_profiles)
            p.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        except Exception:
            LOGGER.error("Failed to save device FP profiles.", exc_info=True)

    def _load_device_fp_profiles(self):
        path = self._state_dir / "device_fp_profiles.json"
        if not path.exists():
            LOGGER.info("No existing per-device FP profiles at %s. Starting fresh.", path)
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            with self._lock:
                for device_id, profile in raw.items():
                    if isinstance(profile, dict):
                        self._device_fp_profiles[device_id] = profile
            LOGGER.info("✅ Per-device FP profiles loaded: %d device(s).", len(self._device_fp_profiles))
        except Exception as exc:
            LOGGER.error("Failed to load per-device FP profiles: %s", exc, exc_info=True)

    # ==========================================================================
    # TRUST CACHE PERSISTENCE
    # ==========================================================================

    def _prune_expired_fp_state(self, now: Optional[float] = None) -> None:
        if now is None:
            now = time.time()
        if self._trust_cache:
            expired_domains = [domain for domain, added_at in self._trust_cache.items() if (now - float(added_at)) >= TRUST_CACHE_TTL_SECONDS]
            for domain in expired_domains:
                self._trust_cache.pop(domain, None)
        self._sigma_shifts = {k: v for k, v in self._sigma_shifts.items() if isinstance(v, (int, float))}

    def _load_trust_cache(self):
        """
        Load the trust cache from disk. Called once at boot.
        Entries that have passed their 14-day TTL are pruned automatically.
        """
        if not self._trust_cache_path.exists():
            LOGGER.info(
                "No existing trust cache at %s. Starting fresh.", self._trust_cache_path
            )
            return

        try:
            raw = json.loads(self._trust_cache_path.read_text(encoding="utf-8"))
            now = time.time()
            loaded = expired = 0

            for domain, added_at in raw.items():
                age = now - float(added_at)
                if age < TRUST_CACHE_TTL_SECONDS:
                    if str(domain).lower() in ("unknown", "null", "none"):
                        LOGGER.info("🧹 [FP ENGINE] Pruning legacy invalid domain '%s' from loaded trust cache.", domain)
                        continue
                    self._trust_cache[domain] = float(added_at)
                    loaded += 1
                    try:
                        from utils import register_dynamic_allowlist_domain
                        register_dynamic_allowlist_domain(domain)
                    except Exception:
                        pass
                    LOGGER.debug(
                        "  Trust cache: '%s' (age=%dd, expires in %dd)",
                        domain,
                        int(age // 86400),
                        int((TRUST_CACHE_TTL_SECONDS - age) // 86400)
                    )
                else:
                    expired += 1
                    LOGGER.debug("  Trust cache: '%s' EXPIRED (age=%dd) – pruned.", domain, int(age // 86400))

            fp_engine_trust_cache_size.set(loaded)
            LOGGER.info(
                "✅ Trust cache loaded: %d active immunized domains, %d expired entries pruned.",
                loaded, expired
            )
        except Exception as exc:
            LOGGER.error("Failed to load trust cache: %s", exc, exc_info=True)

    def _save_trust_cache(self):
        """
        Persist the current trust cache to disk as JSON.
        Called after every immunization to ensure daemon restarts don't lose state.
        """
        try:
            with self._lock:
                snapshot = dict(self._trust_cache)
            self._trust_cache_path.write_text(
                json.dumps(snapshot, indent=2), encoding="utf-8"
            )
            LOGGER.debug(
                "Trust cache saved to disk (%d entries): %s",
                len(snapshot), self._trust_cache_path
            )
        except Exception as exc:
            LOGGER.error("Failed to save trust cache: %s", exc, exc_info=True)

    def _write_muted_log(self, alert_payload: dict, event_type: str, reasons: list, confidence: float):
        """
        Append a suppressed alert entry to the JSONL audit log.

        TRANSPARENCY GUARANTEE: Every auto-suppressed alert is ALWAYS written here.
        Nothing is silently discarded. An admin can run:
            cat state/autonomous_muted.jsonl | python -m json.tool | less
        to inspect everything the engine has auto-resolved.

        Args:
            alert_payload: Original alert payload
            event_type:    Classification category string
            reasons:       List of human-readable suppression reasons
            confidence:    Final FP confidence score [0.0, 1.0]
        """
        try:
            entry = {
                # Human-readable timestamp for easy grep/tail inspection
                "ts_human":    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "ts_unix":     time.time(),
                "type":        event_type,
                "confidence":  round(confidence, 4),
                "reasons":     reasons,
                "device":      alert_payload.get("device", {}),
                "domain":      alert_payload.get("network_context", {}).get("queried_domain", ""),
                "risk_score":  alert_payload.get("risk", 0.0),
                # Full original alert preserved for human review if needed
                "original_alert": alert_payload,
            }
            with open(self._muted_log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
            LOGGER.debug("Muted alert written to audit log: %s", self._muted_log_path)
        except Exception as exc:
            LOGGER.error("Failed to write muted audit log: %s", exc, exc_info=True)

    # ==========================================================================
    # HELPER UTILITIES
    # ==========================================================================

    def _extract_base_domain(self, domain: str) -> str:
        """Extract eTLD+1 base domain for trust cache key. E.g. 'o1234.ingest.sentry.io' -> 'sentry.io'.

        PHASE 0 FIX: fails closed (returns "") instead of falling back to a naive
        last-two-labels split when tldextract-backed suffix parsing isn't available. That
        naive fallback breaks on multi-part public suffixes (e.g. 'mail.example.co.uk' ->
        'co.uk'), which would then immunize every '.co.uk' domain on the network — far
        broader than intended, and a real domain-immunization-hijack surface. An empty
        return is safe: _immunize_domain() already rejects empty/invalid base domains, so
        failing closed here means "no auto-immunization for this domain" rather than
        "auto-immunize something dangerously broad."
        """
        if not domain:
            return ""
        try:
            from utils import etld1, tldextract as _te
        except Exception as exc:
            LOGGER.warning("[FP ENGINE] utils.etld1 unavailable (%s) — failing closed, no domain immunization for '%s'.", exc, domain)
            return ""
        if _te is None:
            LOGGER.warning(
                "[FP ENGINE] tldextract not installed — failing closed (no domain immunization) for '%s'. "
                "Install with: pip install tldextract", domain
            )
            return ""
        try:
            return etld1(domain)
        except Exception as exc:
            LOGGER.warning("[FP ENGINE] etld1() raised for '%s' (%s) — failing closed, no domain immunization.", domain, exc)
            return ""

    def _is_trust_cached(self, base_domain: str) -> bool:
        """True if base_domain is in the dynamic trust cache and its TTL has not expired."""
        if not base_domain:
            return False
        now = time.time()
        with self._lock:
            added_at = self._trust_cache.get(base_domain)
        return added_at is not None and (now - added_at) < TRUST_CACHE_TTL_SECONDS

    # ==========================================================================
    # BACKGROUND MODEL LOADERS
    # ==========================================================================

    def _load_lgbm_model(self):
        """
        Background thread: loads the LightGBM ONNX model from the models/ directory.

        If the model file does not exist, a lightweight placeholder is generated
        automatically using scikit-learn + skl2onnx so Stage 2 can operate
        immediately. Replace the file with a model trained on your real alert
        history for improved accuracy over time.

        Required packages: pip install onnxruntime
        Optional (for placeholder generation): pip install scikit-learn skl2onnx
        """
        # Small delay lets the main pipeline fully start before model loading
        # begins, avoiding any disk I/O contention at startup.
        time.sleep(2.0)
        LOGGER.info("[FP ENGINE » Stage 2 Loader] Starting LightGBM ONNX model loader thread...")

        model_dir = Path(self.config.get("model_path", "state/ids_model.pkl")).parent
        onnx_path = model_dir / "fp_classifier.onnx"

        if not onnx_path.exists():
            LOGGER.warning(
                "[FP ENGINE » Stage 2 Loader] Model not found at %s. Generating placeholder...",
                onnx_path
            )
            self._generate_placeholder_lgbm(onnx_path)

        try:
            import onnxruntime as ort

            # Use a single CPU thread to avoid contention with Zeek packet capture
            # and Pi-hole DNS processing running on the same Ryzen CPU.
            sess_opts = ort.SessionOptions()
            sess_opts.intra_op_num_threads = 1
            sess_opts.inter_op_num_threads = 1
            sess_opts.log_severity_level = 3  # Suppress verbose ONNX runtime logs

            self._lgbm_session = ort.InferenceSession(str(onnx_path), sess_options=sess_opts)
            fp_engine_lgbm_model_status.set(1.0)

            # Log the model's input/output spec so novice users can understand the structure
            inp = self._lgbm_session.get_inputs()[0]
            out = self._lgbm_session.get_outputs()[0]
            LOGGER.info(
                "✅ [FP ENGINE » Stage 2] LightGBM ONNX loaded from %s "
                "| Input: %s %s | Output: %s %s",
                onnx_path, inp.name, inp.shape, out.name, out.shape
            )
        except ImportError:
            LOGGER.warning(
                "⚠️  [FP ENGINE » Stage 2] onnxruntime not installed. "
                "Install with: pip install onnxruntime"
            )
            fp_engine_lgbm_model_status.set(0.0)
        except Exception as exc:
            LOGGER.error("[FP ENGINE » Stage 2] Load failed: %s", exc, exc_info=True)
            fp_engine_lgbm_model_status.set(0.0)

    def _generate_placeholder_lgbm(self, onnx_path: Path):
        """
        Generate a minimal placeholder LightGBM ONNX model.

        Uses a small synthetic dataset that encodes the core FP heuristics:
        - Known top-ranked domains with normal entropy -> False Positive
        - Unknown domains with high entropy and long labels -> Threat

        This placeholder can be improved by training on real labeled alert data.
        See: src/scripts/train_fp_classifier.py (future training script).
        """
        LOGGER.info("[FP ENGINE] Generating placeholder ONNX classifier...")
        try:
            import numpy as np
            from sklearn.ensemble import GradientBoostingClassifier
            from sklearn.pipeline import Pipeline
            from sklearn.preprocessing import StandardScaler

            onnx_path.parent.mkdir(parents=True, exist_ok=True)

            # Synthetic training data
            # Features: [tranco_norm, entropy_norm, label_len, outbound_z, dev_type, hist_fp]
            # Label: 0=threat, 1=false_positive
            X = np.array([
                # Threat-like patterns
                [0.0, 0.90, 0.90, 0.80, 0.1, 0.0],  # IoT, high-entropy DGA
                [0.1, 0.85, 0.80, 0.70, 0.1, 0.0],  # IoT, suspicious C2
                [0.0, 0.88, 0.85, 0.90, 0.3, 0.0],  # Unknown device, tunneling
                [0.2, 0.75, 0.70, 0.60, 0.2, 0.0],  # Printer, unusual behaviour
                # FP-like patterns
                [0.9, 0.20, 0.30, 0.00, 0.5, 0.0],  # Laptop, google.com
                [0.8, 0.30, 0.40, 0.05, 0.5, 0.0],  # Laptop, apple.com
                [0.7, 0.35, 0.50, 0.00, 0.5, 1.0],  # Laptop, previously seen FP
                [0.6, 0.40, 0.50, 0.10, 0.4, 0.0],  # Phone, normal telemetry
                [0.5, 0.30, 0.30, 0.00, 0.4, 1.0],  # Phone, previously seen FP
                [0.85, 0.25, 0.35, 0.05, 0.5, 0.0], # Laptop, Microsoft CDN
                [0.75, 0.30, 0.60, 0.00, 0.5, 0.0], # Laptop, sentry.io ingest hash
                [0.65, 0.28, 0.55, 0.02, 0.5, 0.0], # Laptop, bitdefender nimbus
            ], dtype=np.float32)
            y = np.array([0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1], dtype=np.int32)

            pipe = Pipeline([
                ("scaler", StandardScaler()),
                ("clf", GradientBoostingClassifier(
                    n_estimators=30, max_depth=3, random_state=42
                ))
            ])
            pipe.fit(X, y)

            try:
                from skl2onnx import convert_sklearn
                from skl2onnx.common.data_types import FloatTensorType

                onnx_model = convert_sklearn(
                    pipe,
                    initial_types=[("input", FloatTensorType([None, 6]))],
                    options={GradientBoostingClassifier: {"zipmap": False}}
                )
                with open(onnx_path, "wb") as f:
                    f.write(onnx_model.SerializeToString())
                LOGGER.info(
                    "✅ [FP ENGINE] Placeholder ONNX model saved to: %s", onnx_path
                )
            except ImportError:
                LOGGER.warning(
                    "⚠️  skl2onnx not installed. Cannot save placeholder model. "
                    "Run: pip install skl2onnx"
                )
        except Exception as exc:
            LOGGER.error(
                "[FP ENGINE] Placeholder model generation failed: %s", exc, exc_info=True
            )

    def _load_embed_model(self):
        """
        Background thread: loads FastEmbed BAAI/bge-small-en-v1.5 (~85 MB ONNX).

        Pre-computes the full safe vendor embedding matrix at load time so
        that all Stage 3 evaluations at runtime are a single fast matrix multiply.

        First boot: model downloads automatically from HuggingFace (~85 MB).
        Subsequent boots: model loads from local cache (instant).
        Cache location: state/models/fastembed_cache/

        Required package: pip install fastembed
        """
        time.sleep(5.0)  # Let LightGBM loader run first to avoid disk I/O contention
        LOGGER.info(
            "[FP ENGINE » Stage 3 Loader] Starting FastEmbed model loader thread... "
            "(~85 MB, may take 10-30 seconds on first boot)"
        )

        try:
            from fastembed import TextEmbedding
            import numpy as np

            cache_dir = str(
                Path(self.config.get("model_path", "state/ids_model.pkl")).parent
                / "fastembed_cache"
            )

            LOGGER.info("[FP ENGINE » Stage 3] Loading BAAI/bge-small-en-v1.5 from cache: %s", cache_dir)

            # Load the embedding model (ONNX-based, CPU-only, ~85 MB RAM)
            model = TextEmbedding(
                model_name="BAAI/bge-small-en-v1.5",
                cache_dir=cache_dir
            )

            # Build the safe vendor reference database and pre-compute embeddings
            patterns = self._build_safe_vendor_patterns()
            LOGGER.info(
                "[FP ENGINE » Stage 3] Pre-computing embeddings for %d safe vendor patterns...",
                len(patterns)
            )

            labels = [p["label"] for p in patterns]
            texts  = [p["text"]  for p in patterns]

            # Batch-embed all patterns (fastembed handles chunking efficiently)
            raw_embeddings = list(model.embed(texts))
            embed_matrix = np.array(raw_embeddings, dtype=np.float32)

            # Normalise rows to unit vectors for cosine similarity via dot product
            norms = np.linalg.norm(embed_matrix, axis=1, keepdims=True) + 1e-9
            normed_matrix = embed_matrix / norms

            # Store in instance variables for runtime use by _stage3_embed()
            self._embed_model = model
            self._safe_vendor_embeddings = normed_matrix
            self._safe_vendor_labels = labels

            fp_engine_embed_model_status.set(1.0)
            LOGGER.info(
                "✅ [FP ENGINE » Stage 3] FastEmbed loaded. "
                "Embedding matrix: %s (%.1f KB)",
                normed_matrix.shape,
                normed_matrix.nbytes / 1024.0
            )

        except ImportError:
            LOGGER.warning(
                "⚠️  [FP ENGINE » Stage 3] fastembed not installed. "
                "Install with: pip install fastembed\n"
                "Stage 3 will use static CDN/vendor rule matching as fallback."
            )
            fp_engine_embed_model_status.set(0.0)
        except Exception as exc:
            LOGGER.error(
                "[FP ENGINE » Stage 3] Load failed: %s", exc, exc_info=True
            )
            fp_engine_embed_model_status.set(0.0)

    def _build_safe_vendor_patterns(self) -> list:
        """
        Returns the reference dataset of known-safe vendor telemetry patterns.

        Each entry:
          label: Human-readable name shown in Grafana and logs
          text:  Domain pattern string that will be embedded for similarity comparison

        To extend the engine, add new entries here and restart soc.service.
        The model automatically re-embeds the full list at next boot.
        """
        return [
            # --- Developer Error Tracking & APM ---
            {"label": "Sentry Ingest US",           "text": "o1234.ingest.us.sentry.io"},
            {"label": "Sentry Ingest EU",           "text": "o9999.ingest.de.sentry.io"},
            {"label": "Sentry API",                 "text": "sentry.io"},
            {"label": "Datadog APM",                "text": "trace.agent.datadoghq.com"},
            {"label": "New Relic APM",              "text": "collector.newrelic.com"},
            {"label": "Grafana Telemetry",          "text": "telemetry.grafana.com"},
            # --- Browsers ---
            {"label": "Brave Usage Ping",           "text": "usage-ping.brave.com"},
            {"label": "Firefox Telemetry",          "text": "incoming.telemetry.mozilla.org"},
            {"label": "Chrome SafeBrowsing",        "text": "safebrowsing.googleapis.com"},
            {"label": "Chrome Update",              "text": "update.googleapis.com"},
            # --- Antivirus & Security Cloud ---
            {"label": "Bitdefender NIMBUS",         "text": "nimbus.bitdefender.net"},
            {"label": "Bitdefender EU NIMBUS",      "text": "eu.nimbus.bitdefender.net"},
            {"label": "Bitdefender Telemetry",      "text": "telemetry.bitdefender.com"},
            {"label": "Norton Cloud",               "text": "lookup.norton.com"},
            {"label": "Malwarebytes Telemetry",     "text": "telemetry.malwarebytes.com"},
            # --- Apple Ecosystem ---
            {"label": "Apple Push Notification",    "text": "32-courier.push.apple.com"},
            {"label": "Apple iCloud Sync",          "text": "p12-caldav.icloud.com"},
            {"label": "Apple Software Update",      "text": "swscan.apple.com"},
            {"label": "Apple Device Activation",    "text": "albert.apple.com"},
            # --- Google Ecosystem ---
            {"label": "Google GMS Check-in",        "text": "android.clients.google.com"},
            {"label": "Google Optimization Guide",  "text": "optimizationguide-pa.googleapis.com"},
            {"label": "Firebase Database",          "text": "project.firebaseio.com"},
            # --- Microsoft / Windows ---
            {"label": "Windows Update",             "text": "windowsupdate.microsoft.com"},
            {"label": "Microsoft NCSI",             "text": "www.msftncsi.com"},
            {"label": "Office 365",                 "text": "outlook.office365.com"},
            # --- Amazon / Alexa ---
            {"label": "Amazon Captive Portal",      "text": "captive.amazon.com"},
            {"label": "FireTV Captive Portal",      "text": "firetvcaptiveportal.com"},
            {"label": "Alexa Smart Home",           "text": "alexa.amazon.com"},
            # --- CDN & Infrastructure ---
            {"label": "Cloudflare",                 "text": "cloudflare.com"},
            {"label": "Fastly CDN",                 "text": "fastly.net"},
            {"label": "Akamai CDN",                 "text": "akamaized.net"},
            {"label": "Let's Encrypt ACME",         "text": "acme-v02.api.letsencrypt.org"},
            # --- Developer Package Registries ---
            {"label": "Wordnik Dictionary API",     "text": "www.wordnik.com"},
            {"label": "NPM Registry",               "text": "registry.npmjs.org"},
            {"label": "PyPI Package Index",         "text": "pypi.org"},
            {"label": "GitHub API",                 "text": "api.github.com"},
            {"label": "DockerHub",                  "text": "registry-1.docker.io"},
            # --- Smart Home & IoT ---
            {"label": "TP-Link Tapo Cloud",         "text": "euw1-api.tplinkcloud.com"},
            {"label": "Tuya Smart Home",            "text": "a1.tuyaus.com"},
            {"label": "Synology QuickConnect",      "text": "global.quickconnect.to"},
            {"label": "Sonos Music",                "text": "music.sonos.com"},
            {"label": "Samsung SmartThings",        "text": "samsungcloud.com"},
            # --- Streaming ---
            {"label": "Netflix CDN",                "text": "nflxvideo.net"},
            {"label": "Spotify CDN",                "text": "scdn.co"},
            # --- Fritz!Box & Local Router ---
            {"label": "Fritz!Box Local UI",         "text": "fritz.box"},
            {"label": "Fritz!Box MyFRITZ! DDNS",    "text": "myfritz.net"},
            # --- Homelab & Internal Services ---
            {"label": "Local Grafana Dashboard",    "text": "grafana.sky"},
            {"label": "Local Prometheus",           "text": "prometheus.sky"},
            {"label": "Local Pi-hole",              "text": "pihole.sky"},
            {"label": "Home Assistant Local",       "text": "homeassistant.local"},
            # --- App Analytics ---
            {"label": "Napps2 App Backend",         "text": "tp.napps-2.com"},
            {"label": "Apple Diagnostics",          "text": "radarsubmissions.apple.com"},
        ]

    def _weekly_retrain_loop(self):
        """
        Background daemon thread: periodically retrains fp_classifier.onnx
        every 7 days using alerts.json and autonomous_muted.jsonl history.
        """
        time.sleep(120.0)  # Wait 2 minutes after boot before checking
        while True:
            try:
                last_retrain_file = self._state_dir / "models" / ".last_retrain"
                now = time.time()
                last_ts = 0.0
                if last_retrain_file.exists():
                    try:
                        last_ts = float(last_retrain_file.read_text().strip())
                    except Exception:
                        pass

                # Retrain once every 7 days (604,800 seconds)
                if (now - last_ts) >= 7 * 24 * 3600:
                    LOGGER.info("📅 [FP ENGINE] Scheduled 7-day model retraining interval reached. Launching trainer...")
                    from scripts.train_fp_classifier import train_and_export_onnx, run_threshold_calibration
                    success = train_and_export_onnx(self._state_dir)
                    if success:
                        last_retrain_file.parent.mkdir(parents=True, exist_ok=True)
                        last_retrain_file.write_text(str(now))
                        # Hot-reload ONNX session with the newly trained model
                        self._load_lgbm_model()
                        LOGGER.info("✅ [FP ENGINE] Retrained LightGBM ONNX model hot-reloaded successfully.")
                    # PHASE 13 FIX: this in-process 7-day loop is a second, independent path
                    # to the exact same train_fp_classifier.py module the scheduler's daily
                    # 3am cron job invokes as a standalone script — but only the standalone
                    # script's main() called run_threshold_calibration(). This path called
                    # train_and_export_onnx() directly, silently skipping self-calibration
                    # every time IT fired. Threshold calibration is independent of whether
                    # the (expensive) ONNX retrain above succeeded — same reasoning as
                    # main()'s own unconditional call — so it runs regardless of `success`.
                    run_threshold_calibration(self._state_dir)
            except Exception as exc:
                LOGGER.error("❌ Exception during scheduled weekly retrain loop: %s", exc, exc_info=True)

            time.sleep(3600.0)  # Check once per hour
