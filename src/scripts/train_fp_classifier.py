"""
train_fp_classifier.py – Weekly Autonomous Model Retraining + Threshold Self-Calibration
for Home IDS.

======================================================================================
WHAT DOES THIS SCRIPT DO?  (Plain English for Novice Users)
======================================================================================
This script reads your network's actual alert history and auto-suppressed false positive
logs to train a custom LightGBM / Gradient Boosting ONNX classifier specifically
tuned to YOUR home network.

PHASE 12: it also now calibrates fp_combined_suppress_threshold (the CL-AFPE knob that
decides whether an alert gets auto-suppressed) based on the same evidence — see
calibrate_suppress_threshold() below for the exact rule. Adjustments are written to
state/config_overrides.json, NEVER to config.yaml — config.yaml stays the human-authored
baseline; the override layer is a separate, plainly-inspectable, deletable file. See
config.py's LiveConfig._load_overrides() for how the running pipeline picks this up live.

INPUT DATA SOURCES:
  1. config.yaml -> paths.alert_json_path (preferred; JSONL or JSON array)
  2. state/alerts.json (legacy fallback)
  3. state/autonomous_muted.jsonl (auto-suppressed false positives)

FEATURE MATRIX EXTRACTED (9 normalized dimensions):
  [0] Tranco global rank score
  [1] First label entropy score
  [2] Max subdomain label length
  [3] Outbound bytes Z-score
  [4] Device type weight
  [5] Historical FP cache flag
  [6] Lateral movement normalized
  [7] Port scan intensity normalized
  [8] Application protocol weight

USAGE:
  Manual run:      python src/scripts/train_fp_classifier.py
  Automated run:   Scheduled periodically by fp_engine.py (~7-day interval)
======================================================================================
"""

import json
import logging
import sys
import time
from pathlib import Path

# Ensure src/ directory is in Python path for standalone CLI execution
SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from utils import entropy as compute_entropy
from config import CONFIG
from intelligence.fp_engine import AutonomousFPEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
LOGGER = logging.getLogger("home_ids.train_fp")

DEV_TYPE_WEIGHTS = {
    "laptop": 0.5, "desktop": 0.5,
    "phone": 0.4, "tablet": 0.4,
    "smart_tv": 0.3, "gaming_console": 0.3,
    "printer": 0.2, "nas": 0.2,
    "iot": 0.1, "camera": 0.1,
    "unknown": 0.3,
}

FP_FEATURE_DIM = 9
FP_FEATURE_NAMES = (
    "tranco_rank_norm",
    "label_entropy_norm",
    "label_len_norm",
    "outbound_z_norm",
    "device_type_weight",
    "historical_fp_flag",
    "lateral_moves_norm",
    "port_scans_norm",
    "app_protocol_norm",
)

MAX_REAL_SAMPLES_PER_CLASS = 5000

# Synthetic baseline samples used to seed training if historical dataset is small (9 features)
SYNTHETIC_X = [
    [0.0, 0.90, 0.90, 0.80, 0.1, 0.0, 0.0, 0.0, 0.2],  # Threat: IoT, DGA domain
    [0.1, 0.85, 0.80, 0.70, 0.1, 0.0, 0.0, 0.0, 0.2],  # Threat: IoT, suspicious C2
    [0.0, 0.88, 0.85, 0.90, 0.3, 0.0, 0.0, 0.0, 0.4],  # Threat: Unknown device, tunneling
    [0.2, 0.75, 0.70, 0.60, 0.2, 0.0, 0.8, 0.9, 0.6],  # Threat: Printer, unusual scan
    [0.9, 0.20, 0.30, 0.00, 0.5, 0.0, 0.0, 0.0, 0.2],  # FP: Laptop, google.com
    [0.8, 0.30, 0.40, 0.05, 0.5, 0.0, 0.0, 0.0, 0.2],  # FP: Laptop, apple.com
    [0.7, 0.35, 0.50, 0.00, 0.5, 1.0, 0.0, 0.0, 0.2],  # FP: Laptop, trusted FP domain
    [0.6, 0.40, 0.50, 0.10, 0.4, 0.0, 0.0, 0.0, 0.2],  # FP: Phone, normal telemetry
    [0.5, 0.30, 0.30, 0.00, 0.4, 1.0, 0.0, 0.0, 0.2],  # FP: Phone, trusted FP domain
    [0.85, 0.25, 0.35, 0.05, 0.5, 0.0, 0.0, 0.0, 0.2], # FP: Laptop, Microsoft CDN
    [0.75, 0.30, 0.60, 0.00, 0.5, 0.0, 0.0, 0.0, 0.2], # FP: Laptop, sentry.io ingest
    [0.65, 0.28, 0.55, 0.02, 0.5, 0.0, 0.1, 0.0, 0.2], # FP: Laptop, bitdefender nimbus
]
SYNTHETIC_Y = [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]


def _safe_float(val, default=0.0) -> float:
    try:
        return float(val) if val is not None else float(default)
    except (TypeError, ValueError):
        return float(default)


def _resolve_alert_input_paths(state_dir: Path) -> list[Path]:
    repo_root = SRC_DIR.parent
    configured = Path(str(CONFIG.get("alert_json_path", "state/alerts.json")))
    if not configured.is_absolute():
        configured = repo_root / configured
    fallback = state_dir / "alerts.json"
    return [configured] if configured == fallback else [configured, fallback]


def _read_alert_docs(path: Path) -> list[dict]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []

    # Try JSON array first
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [d for d in parsed if isinstance(d, dict)]
    except json.JSONDecodeError:
        pass

    # Fallback JSONL
    docs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
            if isinstance(doc, dict):
                docs.append(doc)
        except json.JSONDecodeError:
            continue
    return docs


def _extract_payload(doc: dict) -> dict:
    nested = doc.get("original_alert")
    return nested if isinstance(nested, dict) else doc


def extract_features_from_alert(doc: dict) -> list:
    """Extracts the normalized 9 feature dimensions from an alert payload."""
    src = _extract_payload(doc)
    features = src.get("features", {})
    context = src.get("network_context", {})
    device = src.get("device", {})

    domain = context.get("queried_domain", "") or src.get("domain", "")

    # Feature 0: Tranco rank
    tranco_rank = float(features.get("tranco_rank", 0) or 0)
    f0_tranco = max(0.0, 1.0 - (tranco_rank / 1_000_000.0)) if tranco_rank > 0 else 0.0

    # Feature 1: First label entropy
    first_label = domain.split(".")[0] if domain else ""
    f1_entropy = min(compute_entropy(first_label) / 5.0, 1.0)

    # Feature 2: Max label length
    max_label = float(features.get("max_label_length", 0) or 0)
    f2_label_len = min(max_label / 60.0, 1.0)

    # Feature 3: Outbound bytes Z-score
    out_z = float(features.get("outbound_bytes_z", 0.0) or 0.0)
    f3_out_z = min(max(out_z, 0.0) / 10.0, 1.0)

    # Feature 4: Device type weight
    dev_type = str(device.get("type", "unknown") or "unknown")
    f4_dev_type = DEV_TYPE_WEIGHTS.get(dev_type, 0.3)

    # Feature 5: Historical FP signal
    reasons = doc.get("reasons", [])
    f5_hist_fp = 1.0 if any("trust cache" in str(r).lower() for r in reasons) else 0.0
    # Features 6, 7, 8: Multi-Threat Lateral, Port Scans, App Protocol Weight

    f6_lateral = min(_safe_float(features.get("zeek_lateral_moves", 0), 0.0) / 10.0, 1.0)
    f7_port_scans = min(_safe_float(features.get("zeek_s0_rej_count", 0), 0.0) / 50.0, 1.0)
    f8_app_proto = min(max(_safe_float(features.get("zeek_app_protocol_weight", 0.2), 0.2), 0.0), 1.0)

    row = [f0_tranco, f1_entropy, f2_label_len, f3_out_z, f4_dev_type, f5_hist_fp, f6_lateral, f7_port_scans, f8_app_proto]
    if len(row) != FP_FEATURE_DIM:
        raise ValueError(f"Feature row dimension mismatch: got {len(row)}, expected {FP_FEATURE_DIM}")
    return row


def _append_sample(X: list, y: list, doc: dict, label: int, stats: dict, source: str) -> None:
    try:
        row = extract_features_from_alert(doc)
        X.append(row)
        y.append(label)
        stats[f"{source}_accepted"] += 1
    except Exception:
        stats[f"{source}_rejected"] += 1


def _alert_dedup_key(payload: dict) -> str:
    """PHASE 6: best-effort identity key for a single alert EVENT (not just a domain),
    used to cross-reference an entry in the alerts.json "threat" stream against a later
    correction of the SAME alert in autonomous_muted.jsonl (either autonomously
    suppressed at publish time, or operator-marked afterward via the "Mark False
    Positive" Telegram button). device_id + queried_domain + the alert's own `timestamp`
    field is stable and specific enough in practice — two genuinely distinct alerts for
    the same device+domain would have to land in the exact same evaluation cycle
    (identical float timestamp) to collide, which the pipeline's alert-gate cooldown
    already makes vanishingly rare."""
    device_id = payload.get("device", {}).get("id", "?")
    domain = payload.get("network_context", {}).get("queried_domain", "?")
    ts = payload.get("timestamp", "?")
    return f"{device_id}|{domain}|{ts}"


# ══════════════════════════════════════════════════════════════════════════════════════
# PHASE 12/13: threshold self-calibration, global AND per-device. Separate from
# load_dataset() deliberately — it reads the same underlying files but needs different
# information from them (fp_verdict confidence scores, not feature vectors), and
# load_dataset()'s return contract is already asserted against by
# test_phase6_fp_selfheal.py / test_phase7_scheduling.py.
#
# PHASE 13: evidence now pools TWO correction sources, not one — "OPERATOR_MARKED_FALSE_
# POSITIVE" (a real Telegram tap) and "LLM_VALIDATED_FALSE_POSITIVE" (scripts/ollama_soc.py's
# own autonomous, DeterministicValidator-passed correction, running every 4h with zero
# human involvement). Per explicit direction: with alert volume high enough that "wait for
# 5 human corrections" isn't realistic, the LLM-validated path is now the PRIMARY,
# human-independent evidence source; operator taps remain valid and are pooled in when
# they happen, but nothing here requires them.
# ══════════════════════════════════════════════════════════════════════════════════════

_FP_CORRECTION_TYPES = {"OPERATOR_MARKED_FALSE_POSITIVE", "LLM_VALIDATED_FALSE_POSITIVE"}

AUTOTUNE_MIN_SAMPLES = 5          # need at least this many pooled (operator + LLM-validated)
                                   # confirmed FPs before proposing a GLOBAL change
AUTOTUNE_DEVICE_MIN_SAMPLES = 3   # lower bar for a PER-DEVICE profile — device-scoped
                                   # evidence is inherently sparser than the global pool,
                                   # but a device's own history is also more directly
                                   # relevant to that device than the global average is
AUTOTUNE_SAFETY_MARGIN = 0.02     # stay this far below the lowest confirmed-FP score
AUTOTUNE_ABSOLUTE_FLOOR = 0.60    # never auto-suppress below this regardless of evidence


def _collect_calibration_evidence(state_dir: Path) -> tuple:
    """Independently re-reads alerts.json + autonomous_muted.jsonl (same sources
    load_dataset() uses, via the same helpers) to build threshold-calibration evidence,
    both pooled (global) and grouped by device (per-device).

    Returns (corrected_fp_scores, uncorrected_uncertain_scores, per_device_corrected,
             per_device_uncorrected):
      corrected_fp_scores: CL-AFPE combined confidence (fp_verdict.confidence) of alerts
        that were PUBLISHED (not auto-suppressed — the current threshold missed them) but
        were LATER confirmed as false positives — by an operator OR by ollama_soc.py's
        validated LLM pass (see _FP_CORRECTION_TYPES). Proof that suppression at that
        score would have been correct.
      uncorrected_uncertain_scores: combined confidence of alerts published with verdict
        UNCERTAIN that were NEVER corrected by either source — no evidence either way.
        Used only as a safety ceiling: calibration refuses to act if this overlaps the
        corrected-FP range.
      per_device_corrected / per_device_uncorrected: the same two lists, grouped by
        device_id, for the per-device calibration pass.
    """
    muted_docs = []
    muted_path = state_dir / "autonomous_muted.jsonl"
    if muted_path.exists():
        try:
            for line in muted_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    muted_docs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except Exception as exc:
            LOGGER.warning(f"[AUTOTUNE] Could not read autonomous_muted.jsonl: {exc}")

    corrected_fp_scores = []
    per_device_corrected = {}
    for doc in muted_docs:
        if doc.get("type") not in _FP_CORRECTION_TYPES:
            continue
        original = doc.get("original_alert", {}) or {}
        conf = original.get("fp_verdict", {}).get("confidence")
        if not isinstance(conf, (int, float)):
            continue
        corrected_fp_scores.append(float(conf))
        device_id = original.get("device", {}).get("id", "unknown")
        per_device_corrected.setdefault(device_id, []).append(float(conf))

    corrected_keys = {_alert_dedup_key(_extract_payload(d)) for d in muted_docs}

    uncorrected_uncertain_scores = []
    per_device_uncorrected = {}
    for path in _resolve_alert_input_paths(state_dir):
        docs = _read_alert_docs(path)
        if not docs:
            continue
        for doc in docs:
            payload = _extract_payload(doc)
            if payload.get("type") != "ids_alert":
                continue
            fp_v = payload.get("fp_verdict", {}) or {}
            if fp_v.get("verdict") != "UNCERTAIN":
                continue
            if _alert_dedup_key(payload) in corrected_keys:
                continue  # this one WAS corrected — it's positive evidence, not negative
            conf = fp_v.get("confidence")
            if not isinstance(conf, (int, float)):
                continue
            uncorrected_uncertain_scores.append(float(conf))
            device_id = payload.get("device", {}).get("id", "unknown")
            per_device_uncorrected.setdefault(device_id, []).append(float(conf))
        break  # mirrors load_dataset()'s own "first non-empty source wins" priority order

    return corrected_fp_scores, uncorrected_uncertain_scores, per_device_corrected, per_device_uncorrected


def calibrate_suppress_threshold(corrected_fp_scores: list, uncorrected_uncertain_scores: list,
                                  current: float, min_samples: int = AUTOTUNE_MIN_SAMPLES) -> tuple:
    """Conservative, one-directional, evidence-gated calibration of
    fp_combined_suppress_threshold. Returns (new_value_or_None, reason_string) — reason is
    always populated (including for "no change" outcomes) so a run with nothing to do
    still leaves an auditable trail of why.

    Shared by both the global calibration pass (current=the effective global value,
    min_samples=AUTOTUNE_MIN_SAMPLES) and the per-device pass (current=that device's own
    effective value, min_samples=AUTOTUNE_DEVICE_MIN_SAMPLES) — one tested rule, not two
    parallel implementations that could quietly drift apart.

    Rule (deliberately simple and defensible over a clever one):
    - Only ever LOWERS the threshold (more auto-suppression, fewer alerts) — never raises
      it automatically. Raising it back up after over-tuning is a human decision.
    - Requires >= min_samples confirmed false positives (operator taps AND/OR ollama_soc.py's
      validated LLM corrections — see _FP_CORRECTION_TYPES) before proposing anything.
    - Refuses to act at all if any UNCORRECTED "UNCERTAIN" alert (no evidence either way)
      scored at or above the lowest confirmed-FP score — that's an ambiguous overlap
      between "proven safe to suppress" and "not proven", and the whole point of "without
      compromising detection" is to never let that overlap resolve in favor of suppression.
    - Never goes below AUTOTUNE_ABSOLUTE_FLOOR regardless of evidence.
    """
    if len(corrected_fp_scores) < min_samples:
        return None, (
            f"Only {len(corrected_fp_scores)} confirmed FP sample(s) "
            f"(need >= {min_samples}) — not enough evidence to calibrate yet."
        )

    lowest_corrected = min(corrected_fp_scores)

    if uncorrected_uncertain_scores:
        highest_uncorrected = max(uncorrected_uncertain_scores)
        if highest_uncorrected >= lowest_corrected:
            return None, (
                f"Refusing to calibrate: an uncorrected UNCERTAIN alert scored "
                f"{highest_uncorrected:.3f}, at or above the lowest confirmed-FP score "
                f"{lowest_corrected:.3f} — ambiguous overlap, not safe to auto-resolve."
            )

    candidate = max(lowest_corrected - AUTOTUNE_SAFETY_MARGIN, AUTOTUNE_ABSOLUTE_FLOOR)
    candidate = round(min(candidate, current), 4)

    if candidate >= current:
        return None, (
            f"Calibration would not lower the threshold below its current effective "
            f"value {current:.3f} — no change needed."
        )

    gap_note = (
        f", clean gap above the highest uncorrected UNCERTAIN score "
        f"{max(uncorrected_uncertain_scores):.3f}"
        if uncorrected_uncertain_scores else
        ", no uncorrected UNCERTAIN alerts observed in this window to compare against"
    )
    reason = (
        f"{len(corrected_fp_scores)} confirmed false positive(s) observed with "
        f"combined scores as low as {lowest_corrected:.3f} (published as UNCERTAIN, "
        f"requiring correction each time) — lowered fp_combined_suppress_threshold "
        f"from {current:.3f} to {candidate:.3f} ({AUTOTUNE_SAFETY_MARGIN:.2f} safety margin "
        f"below the lowest confirmed-FP score{gap_note})."
    )
    return candidate, reason


def _write_config_override(state_dir: Path, key: str, value, baseline, set_by: str, reason: str) -> None:
    """Writes ONE key into state/config_overrides.json, preserving every other key already
    present — this file may hold overrides from other mechanisms later, and this must never
    clobber them. See config.py's LiveConfig._load_overrides() for how the running pipeline
    picks this up live (within one watcher poll interval, no restart)."""
    overrides_path = state_dir / "config_overrides.json"
    try:
        existing = json.loads(overrides_path.read_text(encoding="utf-8")) if overrides_path.exists() else {}
    except Exception:
        existing = {}
    existing[key] = {
        "value": value, "baseline": baseline, "set_at": time.time(),
        "set_by": set_by, "reason": reason,
    }
    overrides_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    LOGGER.info(f"🔧 [AUTOTUNE] Wrote config override: {key} = {value} (baseline {baseline}).")


def run_threshold_calibration(state_dir: Path) -> None:
    """Entry point called from main() after the model retrain. Never allowed to raise past
    this function — a calibration failure must never be mistaken for (or cause) a
    model-retrain failure; main()'s exit code is driven by train_and_export_onnx() alone.

    PHASE 13: runs TWO passes over the same evidence — global (unchanged from Phase 12,
    still the fallback for devices without enough of their own history) and per-device
    (new: devices with "strongly different profiles" get their own calibrated threshold
    once their OWN evidence supports it, via AutonomousFPEngine's device-profile state —
    see fp_engine.py's get_device_suppress_threshold())."""
    try:
        corrected_fp_scores, uncorrected_uncertain_scores, per_device_corrected, per_device_uncorrected = \
            _collect_calibration_evidence(state_dir)
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE] Failed to collect calibration evidence (non-fatal): {exc}")
        return

    # --- Global pass ---------------------------------------------------------------
    try:
        global_current = float(CONFIG.get("fp_combined_suppress_threshold", 0.80))
        new_value, reason = calibrate_suppress_threshold(
            corrected_fp_scores, uncorrected_uncertain_scores,
            current=global_current, min_samples=AUTOTUNE_MIN_SAMPLES,
        )
        LOGGER.info(f"[AUTOTUNE » GLOBAL] fp_combined_suppress_threshold: {reason}")
        if new_value is not None:
            _write_config_override(
                state_dir, "fp_combined_suppress_threshold", new_value,
                baseline=global_current,
                set_by="train_fp_classifier.py:calibrate_suppress_threshold",
                reason=reason,
            )
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE » GLOBAL] Threshold calibration failed (non-fatal): {exc}")

    # --- Per-device pass -------------------------------------------------------------
    try:
        device_ids = set(per_device_corrected.keys()) | set(per_device_uncorrected.keys())
        device_ids.discard("unknown")
        if not device_ids:
            LOGGER.info("[AUTOTUNE » PER-DEVICE] No per-device evidence this run.")
            return

        # CONFIG (config.py's LiveConfig singleton) already exposes .get(key, default) —
        # the exact interface AutonomousFPEngine's config properties expect — so it can be
        # passed directly, no need to reach into its internals.
        fp_engine = AutonomousFPEngine(config=CONFIG, state_dir=str(state_dir))
        for device_id in sorted(device_ids):
            dev_corrected = per_device_corrected.get(device_id, [])
            dev_uncorrected = per_device_uncorrected.get(device_id, [])
            dev_current = fp_engine.get_device_suppress_threshold(device_id)
            new_value, reason = calibrate_suppress_threshold(
                dev_corrected, dev_uncorrected,
                current=dev_current, min_samples=AUTOTUNE_DEVICE_MIN_SAMPLES,
            )
            if new_value is not None:
                LOGGER.info(f"[AUTOTUNE » DEVICE {device_id}] fp_combined_suppress_threshold: {reason}")
                fp_engine.apply_device_fp_profile(
                    device_id, "fp_combined_suppress_threshold", new_value, baseline=dev_current,
                    set_by="train_fp_classifier.py:calibrate_suppress_threshold",
                    reason=reason, sample_count=len(dev_corrected),
                )
            else:
                LOGGER.debug(f"[AUTOTUNE » DEVICE {device_id}] {reason}")
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE » PER-DEVICE] Threshold calibration failed (non-fatal): {exc}")


def load_dataset(state_dir: Path) -> tuple:
    """Loads labeled training samples from configured alerts stream + autonomous muted log.

    PHASE 6 FIX (critical mislabeling bug): this used to label EVERY entry from the
    alerts.json stream as label=0 ("confirmed threat") unconditionally, with no mechanism
    to correct an entry that was later determined to be a false positive. Two concrete
    ways that happened:
      1. pipeline.py writes EVERY evaluated alert to the alert stream unconditionally
         (`self.alert_writer.write(alert_payload)`), including ones fp_engine itself
         already autonomously suppressed as FALSE_POSITIVE that cycle (flagged via
         `alert_payload["suppressed"] = True` right before the write). Those were being
         trained as label=0 AND label=1 (from autonomous_muted.jsonl) in the same run —
         directly contradictory signal for the exact same event.
      2. An alert an OPERATOR later marks false positive via the "🛡️ Mark False Positive"
         Telegram button (fp_engine.mark_false_positive()) writes a label=1 correction to
         autonomous_muted.jsonl, but the original alerts.json entry stayed labeled
         label=0 forever — so the weekly retrain kept reinforcing the exact pattern the
         operator just corrected, meaning FP-reduction-through-operator-feedback couldn't
         actually influence future predictions.
    Both are now excluded from the label=0 threat set below.
    """
    X, y = [], []
    stats = {
        "threat_accepted": 0, "threat_rejected": 0,
        "fp_accepted": 0, "fp_rejected": 0,
        "threat_skipped_corrected": 0,
        "threat_skipped_non_alert": 0,
    }

    # Read autonomous_muted.jsonl FIRST so its dedup keys are available while filtering
    # the alerts.json threat stream below.
    muted_docs = []
    muted_path = state_dir / "autonomous_muted.jsonl"
    if muted_path.exists():
        try:
            with open(muted_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[-MAX_REAL_SAMPLES_PER_CLASS:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    muted_docs.append(json.loads(line))
                except json.JSONDecodeError:
                    stats["fp_rejected"] += 1
        except Exception as exc:
            LOGGER.warning("Could not read autonomous_muted.jsonl: %s", exc)

    corrected_keys = {_alert_dedup_key(_extract_payload(d)) for d in muted_docs}

    # 1. Threat samples from configured alert stream path (fallback to state/alerts.json)
    alert_docs = []
    for path in _resolve_alert_input_paths(state_dir):
        docs = _read_alert_docs(path)
        if docs:
            alert_docs = docs
            LOGGER.info("Using threat training source: %s (%d docs)", path, len(docs))
            break

    for doc in alert_docs[-MAX_REAL_SAMPLES_PER_CLASS:]:
        payload = _extract_payload(doc)
        # BUGFIX (non-alert stream contamination): alerts.json isn't exclusively real
        # alert records — scripts/ollama_soc.py appends `type="ollama_transparency"`
        # entries to this SAME file for operator visibility. Those entries have no
        # `network_context`/`features`/`device.type`, so extract_features_from_alert()
        # was silently producing an all-near-zero feature row for them and training it as
        # a confirmed-threat (label=0) sample — confirmed empirically: a single injected
        # transparency-log doc produced the feature row [0,0,0,0,0.3,0,0,0,0.2] labeled
        # threat. Every ollama_soc.py run (every few hours) adds more of these, so this
        # was steadily diluting the model with synthetic noise. Real alerts always carry
        # `type="ids_alert"` (set in pipeline.py); anything else recognizable as a
        # non-alert transparency record is excluded here rather than trained on.
        if payload.get("type") == "ollama_transparency":
            stats["threat_skipped_non_alert"] += 1
            continue
        if payload.get("suppressed"):
            # Already autonomously flagged FP at publish time — its label=1 sample lives
            # in autonomous_muted.jsonl; do not ALSO train it as label=0 here.
            stats["threat_skipped_corrected"] += 1
            continue
        if _alert_dedup_key(payload) in corrected_keys:
            # Corrected after the fact (autonomous or operator) — same reasoning.
            stats["threat_skipped_corrected"] += 1
            continue
        _append_sample(X, y, doc, 0, stats, source="threat")

    # 2. False positives from autonomous muted JSONL (parsed above, label=1)
    for doc in muted_docs:
        _append_sample(X, y, doc, 1, stats, source="fp")

    return X, y, stats


def train_and_export_onnx(state_dir: Path) -> bool:
    """Trains GradientBoostingClassifier on 9 features and exports to state/models/fp_classifier.onnx."""
    X, y, stats = load_dataset(state_dir)
    LOGGER.info(
        "Dataset loaded: %d accepted real samples | threat accepted/rejected=%d/%d "
        "(skipped as corrected FPs=%d, skipped as non-alert transparency logs=%d) | "
        "fp accepted/rejected=%d/%d | dim=%d",
        len(X),
        stats["threat_accepted"], stats["threat_rejected"],
        stats["threat_skipped_corrected"], stats["threat_skipped_non_alert"],
        stats["fp_accepted"], stats["fp_rejected"],
        FP_FEATURE_DIM
    )

    if len(X) < 10 or len(set(y)) < 2:
        LOGGER.info("Dataset too small – augmenting with %d synthetic baseline samples.", len(SYNTHETIC_X))
        X.extend(SYNTHETIC_X)
        y.extend(SYNTHETIC_Y)

    try:
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import make_pipeline

        pipeline = make_pipeline(
            StandardScaler(),
            GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42)
        )
        pipeline.fit(X, y)
        acc = pipeline.score(X, y)
        LOGGER.info("✅ GBDT Model trained successfully. Training Accuracy: %.2f%%", acc * 100.0)

        # Convert to ONNX format (zipmap=False outputs clean 2D numpy probability arrays)
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        onnx_model = convert_sklearn(
            pipeline,
            initial_types=[("input", FloatTensorType([None, FP_FEATURE_DIM]))],
            options={GradientBoostingClassifier: {"zipmap": False}}
        )

        model_dir = state_dir / "models"
        model_dir.mkdir(parents=True, exist_ok=True)
        onnx_path = model_dir / "fp_classifier.onnx"

        with open(onnx_path, "wb") as f:
            f.write(onnx_model.SerializeToString())

        LOGGER.info("🎉 Retrained LightGBM/ONNX model exported to: %s (%.1f KB)", onnx_path, onnx_path.stat().st_size / 1024.0)
        return True

    except Exception as exc:
        LOGGER.error("❌ Model retraining or ONNX export failed: %s", exc, exc_info=True)
        return False


def main():
    state_dir = SRC_DIR.parent / "state"
    success = train_and_export_onnx(state_dir)

    # PHASE 12: independent of model-retrain success — reads a different (though
    # overlapping) slice of the same alert history, and a calibration failure must never
    # affect this script's exit code (see run_threshold_calibration()'s own docstring).
    run_threshold_calibration(state_dir)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
