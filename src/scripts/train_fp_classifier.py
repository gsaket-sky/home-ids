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
  4. state/training_row_exclusions.json (optional; written by
     identify_corrupted_training_rows.py) -- rows listed here are skipped during
     load_dataset(), without alerts.json/autonomous_muted.jsonl themselves being
     modified. Currently used to exclude historical DNS_COVERT_TUNNELING/DGA_BOTNET_C2
     rows whose f1_entropy feature was computed from the wrong domain, predating each
     signature's own domain-attribution fix.

FEATURE MATRIX EXTRACTED (11 normalized dimensions):
  [0] Tranco global rank score
  [1] First label entropy score
  [2] Max subdomain label length
  [3] Outbound bytes Z-score
  [4] Device type weight
  [5] Historical FP cache flag
  [6] Lateral movement normalized
  [7] Port scan intensity normalized
  [8] Application protocol weight
  [9] ARP-sweep intensity normalized (PHASE 21-LGBM-EXTEND)
  [10] DNS-evasion unexplained-connection ratio (PHASE 21-LGBM-EXTEND)

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

from utils import entropy as compute_entropy, write_job_health
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

FP_FEATURE_DIM = 11
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
    "arp_sweep_norm",
    "dns_evasion_ratio",
)

MAX_REAL_SAMPLES_PER_CLASS = 5000

# Synthetic baseline samples used to seed training if historical dataset is small
# (11 features -- PHASE 21-LGBM-EXTEND added arp_sweep_norm/dns_evasion_ratio; existing
# rows keep their original 9 values and simply carry 0.0 for both new columns, since
# none of the original illustrative scenarios involved an ARP sweep or a DNS-evasion
# finding -- only the two new rows below actually exercise the new dimensions).
SYNTHETIC_X = [
    [0.0, 0.90, 0.90, 0.80, 0.1, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0],  # Threat: IoT, DGA domain
    [0.1, 0.85, 0.80, 0.70, 0.1, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0],  # Threat: IoT, suspicious C2
    [0.0, 0.88, 0.85, 0.90, 0.3, 0.0, 0.0, 0.0, 0.4, 0.0, 0.0],  # Threat: Unknown device, tunneling
    [0.2, 0.75, 0.70, 0.60, 0.2, 0.0, 0.8, 0.9, 0.6, 0.0, 0.0],  # Threat: Printer, unusual scan
    [0.3, 0.40, 0.30, 0.10, 0.3, 0.0, 0.0, 0.0, 0.2, 0.9, 0.0],  # Threat: unknown device, ARP host-discovery sweep
    [0.4, 0.30, 0.30, 0.05, 0.5, 0.0, 0.0, 0.0, 0.2, 0.0, 0.8],  # Threat: laptop, real traffic with no matching DNS history
    [0.9, 0.20, 0.30, 0.00, 0.5, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0],  # FP: Laptop, google.com
    [0.8, 0.30, 0.40, 0.05, 0.5, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0],  # FP: Laptop, apple.com
    [0.7, 0.35, 0.50, 0.00, 0.5, 1.0, 0.0, 0.0, 0.2, 0.0, 0.0],  # FP: Laptop, trusted FP domain
    [0.6, 0.40, 0.50, 0.10, 0.4, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0],  # FP: Phone, normal telemetry
    [0.5, 0.30, 0.30, 0.00, 0.4, 1.0, 0.0, 0.0, 0.2, 0.0, 0.0],  # FP: Phone, trusted FP domain
    [0.85, 0.25, 0.35, 0.05, 0.5, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0], # FP: Laptop, Microsoft CDN
    [0.75, 0.30, 0.60, 0.00, 0.5, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0], # FP: Laptop, sentry.io ingest
    [0.65, 0.28, 0.55, 0.02, 0.5, 0.0, 0.1, 0.0, 0.2, 0.0, 0.0], # FP: Laptop, bitdefender nimbus
    [0.6, 0.35, 0.40, 0.05, 0.2, 0.0, 0.0, 0.0, 0.2, 0.3, 0.0],  # FP: IoT hub, legitimate startup ARP scan (low sweep count)
    [0.7, 0.30, 0.35, 0.05, 0.5, 0.0, 0.0, 0.0, 0.2, 0.0, 0.2],  # FP: laptop on a recognized VPN, low unexplained ratio
]
SYNTHETIC_Y = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]


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
    """Extracts the normalized 11 feature dimensions from an alert payload."""
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

    # PHASE 21-LGBM-EXTEND: features 9, 10 -- ARP-sweep and DNS-evasion signals. Both
    # previously reached alerts.json's `features` dict (zeek_arp_sweep_count/
    # zeek_dns_evasion_ratio) but were invisible to LightGBM specifically, since this
    # 9-dim vector never read those keys -- an earlier session claim that they were
    # "inherited for free" by the classifier was wrong for this stage; true only for
    # Ollama (which sees the full raw payload) and the training-SET inclusion, not the
    # fixed-shape feature vector itself. 20.0 ceiling on the sweep count is roughly 2.5x
    # the default arp_sweep_unique_targets_threshold (8), so a device right at the
    # detection threshold sits near the low end of this feature's range, not already
    # saturated at 1.0.
    f9_arp_sweep = min(_safe_float(features.get("zeek_arp_sweep_count", 0), 0.0) / 20.0, 1.0)
    f10_dns_evasion = min(max(_safe_float(features.get("zeek_dns_evasion_ratio", 0.0), 0.0), 0.0), 1.0)

    row = [f0_tranco, f1_entropy, f2_label_len, f3_out_z, f4_dev_type, f5_hist_fp, f6_lateral, f7_port_scans,
           f8_app_proto, f9_arp_sweep, f10_dns_evasion]
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


def _collect_connection_abuse_corrections(state_dir: Path) -> dict:
    """PHASE 21D3 ('enable per device tuning'): independently scans
    autonomous_muted.jsonl for CONNECTION_ABUSE-signature corrections (covers
    arp_sweep evidence among others), grouped by device -- separate from
    _collect_calibration_evidence() above, since arp_sweep_unique_targets_threshold
    calibration needs a per-device correction COUNT, not the pooled fp_verdict
    confidence-score distribution that function computes (arp_sweep has no comparable
    0-1 confidence score to calibrate against). Returns {device_id: corrected_count}."""
    counts: dict = {}
    muted_path = state_dir / "autonomous_muted.jsonl"
    if not muted_path.exists():
        return counts
    try:
        for line in muted_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            if doc.get("type") not in _FP_CORRECTION_TYPES:
                continue
            original = doc.get("original_alert", {}) or {}
            # VERSION 12 (G7): INTERNAL_RECONNAISSANCE is ConnectionAbuseHypothesis's own
            # dynamic name (hypotheses/engine.py) for the arp_sweep-ONLY case that used to
            # always be named "CONNECTION_ABUSE" -- this is exactly the case this arp-sweep
            # calibration pass cares about, so it must count both names. Deliberately does
            # NOT add "PORT_SCAN" (the OTHER new dynamic name, for a zeek_conn_abuse-only
            # finding with no arp_sweep evidence at all) -- that correction says nothing
            # about whether arp_sweep_unique_targets_threshold is too sensitive.
            if original.get("signature") not in ("CONNECTION_ABUSE", "INTERNAL_RECONNAISSANCE"):
                continue
            device_id = original.get("device", {}).get("id", "unknown")
            counts[device_id] = counts.get(device_id, 0) + 1
    except Exception as exc:
        LOGGER.warning(f"[AUTOTUNE] Could not read autonomous_muted.jsonl for CONNECTION_ABUSE evidence: {exc}")
    return counts


ARP_SWEEP_MIN_CORRECTED_SAMPLES = 2   # a device needs at least this many confirmed FPs
                                       # before its threshold gets raised automatically
ARP_SWEEP_MIN_CONFIRMED_SAMPLES = 5   # ...and this many confirmed THREATS (zero
                                       # corrections) before it gets tightened instead
ARP_SWEEP_RAISE_STEP = 4.0
ARP_SWEEP_LOWER_STEP = 1.0
ARP_SWEEP_MIN_THRESHOLD = 4.0
ARP_SWEEP_MAX_THRESHOLD = 40.0


def calibrate_arp_sweep_threshold(corrected_count: int, confirmed_count: int, current: float) -> tuple:
    """Bidirectional per-device calibration of arp_sweep_unique_targets_threshold --
    deliberately NOT the same one-directional-only rule calibrate_suppress_threshold()
    uses above. A suppress-CONFIDENCE threshold has a safe default direction (lowering
    it only ever means MORE suppression, so evidence-gated lowering is conservative by
    construction); a raw COUNT threshold like this one has a genuine two-sided
    precision/recall tradeoff -- too low false-positives on a device that legitimately
    ARP-scans, too high misses real recon sweeps. Requiring evidence on only ONE side
    (corrections with zero confirmations, or confirmations with zero corrections) for a
    given device is what keeps each direction safe to act on automatically -- mixed/
    contradictory evidence is left for a human to look at rather than auto-resolved.

    Returns (new_value_or_None, reason_string), same shape as
    calibrate_suppress_threshold()."""
    if corrected_count >= ARP_SWEEP_MIN_CORRECTED_SAMPLES and confirmed_count == 0:
        new_value = min(current + ARP_SWEEP_RAISE_STEP, ARP_SWEEP_MAX_THRESHOLD)
        if new_value <= current:
            return None, (
                f"{corrected_count} CONNECTION_ABUSE correction(s) observed, but the threshold "
                f"is already at its ceiling ({ARP_SWEEP_MAX_THRESHOLD:.0f}) -- no further change."
            )
        return new_value, (
            f"{corrected_count} CONNECTION_ABUSE correction(s) confirmed as false positives, "
            f"with zero confirmed real threats to contradict -- raised "
            f"arp_sweep_unique_targets_threshold from {current:.1f} to {new_value:.1f} "
            f"(less sensitive for this device)."
        )

    if confirmed_count >= ARP_SWEEP_MIN_CONFIRMED_SAMPLES and corrected_count == 0:
        new_value = max(current - ARP_SWEEP_LOWER_STEP, ARP_SWEEP_MIN_THRESHOLD)
        if new_value >= current:
            return None, (
                f"{confirmed_count} confirmed threat(s) observed, but the threshold is already "
                f"at its floor ({ARP_SWEEP_MIN_THRESHOLD:.0f}) -- no further change."
            )
        return new_value, (
            f"{confirmed_count} confirmed real threat(s) for this device with zero corrected "
            f"false positives -- tightened arp_sweep_unique_targets_threshold from "
            f"{current:.1f} to {new_value:.1f} (this detector has a strong confirmed track "
            f"record here, worth more sensitivity, not less)."
        )

    return None, (
        f"{corrected_count} correction(s), {confirmed_count} confirmation(s) -- not enough "
        f"one-sided evidence yet to calibrate (need >= {ARP_SWEEP_MIN_CORRECTED_SAMPLES:.0f} "
        f"corrections with zero confirmations, or >= {ARP_SWEEP_MIN_CONFIRMED_SAMPLES:.0f} "
        f"confirmations with zero corrections)."
    )


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


def _classify_outcome(new_value, reason: str) -> str:
    """Maps calibrate_suppress_threshold()'s (new_value, reason) to a small fixed enum
    for the home_ids_autotune_calibration_total relay metric. Matched against the exact
    reason-string prefixes calibrate_suppress_threshold() returns -- see its docstring."""
    if new_value is not None:
        return "applied"
    if reason.startswith("Refusing to calibrate"):
        return "refused_ambiguous"
    if reason.startswith("Only "):
        return "insufficient_samples"
    return "no_change_needed"


def _write_autotune_relay_stats(state_dir: Path, run_start: float, global_outcome: str,
                                 global_evidence: tuple, device_outcomes: dict, device_evidence: dict,
                                 device_confirmed_counts: dict = None,
                                 arp_sweep_outcomes: dict = None, arp_sweep_evidence: dict = None) -> None:
    """Writes state/autotune_stats.json -- synced into Prometheus gauges by the
    long-running pipeline process's sync_relay_metrics() (this script is a separate
    cron/thread-triggered process with no HTTP server of its own). Reads back
    config_overrides.json/device_fp_profiles.json for the authoritative effective/
    baseline values rather than re-deriving them, since _write_config_override() and
    apply_device_fp_profile() already recorded that pairing at the moment they wrote it.
    calibration_outcomes counts are cumulative across runs (read-modify-write), matching
    the metric's own documented semantics.

    PHASE 21D3: device_confirmed_counts adds a "confirmed" figure alongside the existing
    "corrected"/"uncorrected" evidence_counts -- not just how often a detector was WRONG
    (corrected), but how often it was RIGHT (confirmed), so a detector with a strong
    confirmed track record can eventually be tightened, not just loosened on correction.
    arp_sweep_outcomes/arp_sweep_evidence are the SEPARATE per-device ARP-sweep-threshold
    calibration pass's own outcome/evidence, written alongside (not merged into) the
    existing fp_combined_suppress_threshold figures, since they calibrate a different key
    with a different (bidirectional) rule -- see calibrate_arp_sweep_threshold().
    """
    device_confirmed_counts = device_confirmed_counts or {}
    arp_sweep_outcomes = arp_sweep_outcomes or {}
    arp_sweep_evidence = arp_sweep_evidence or {}

    stats_path = state_dir / "autotune_stats.json"
    try:
        existing = json.loads(stats_path.read_text(encoding="utf-8")) if stats_path.exists() else {}
    except Exception:
        existing = {}

    global_current = float(CONFIG.get("fp_combined_suppress_threshold", 0.80))
    global_baseline = global_current
    try:
        overrides = json.loads((state_dir / "config_overrides.json").read_text(encoding="utf-8"))
        entry = overrides.get("fp_combined_suppress_threshold")
        if entry:
            global_baseline = entry.get("baseline", global_current)
    except Exception:
        pass

    prev_global = existing.get("global", {})
    prev_outcomes = prev_global.get("calibration_outcomes", {})
    prev_outcomes[global_outcome] = prev_outcomes.get(global_outcome, 0) + 1

    devices = existing.get("devices", {})
    try:
        profiles = json.loads((state_dir / "device_fp_profiles.json").read_text(encoding="utf-8"))
    except Exception:
        profiles = {}

    for device_id, outcome in device_outcomes.items():
        dev_entry = devices.setdefault(device_id, {})
        dev_outcomes = dev_entry.get("calibration_outcomes", {})
        dev_outcomes[outcome] = dev_outcomes.get(outcome, 0) + 1
        dev_entry["calibration_outcomes"] = dev_outcomes
        dev_profile = profiles.get(device_id, {}).get("fp_combined_suppress_threshold", {})
        if "value" in dev_profile:
            dev_entry["effective"] = dev_profile["value"]
        corrected, uncorrected = device_evidence.get(device_id, (0, 0))
        dev_entry["evidence_counts"] = {
            "corrected": corrected, "uncorrected": uncorrected,
            "confirmed": device_confirmed_counts.get(device_id, 0),
        }
        dev_entry.setdefault("hostname", "unknown")

    for device_id, outcome in arp_sweep_outcomes.items():
        dev_entry = devices.setdefault(device_id, {})
        dev_arp_outcomes = dev_entry.get("arp_sweep_calibration_outcomes", {})
        dev_arp_outcomes[outcome] = dev_arp_outcomes.get(outcome, 0) + 1
        dev_entry["arp_sweep_calibration_outcomes"] = dev_arp_outcomes
        dev_arp_profile = profiles.get(device_id, {}).get("arp_sweep_unique_targets_threshold", {})
        if "value" in dev_arp_profile:
            dev_entry["arp_sweep_effective"] = dev_arp_profile["value"]
        corrected, confirmed = arp_sweep_evidence.get(device_id, (0, 0))
        dev_entry["arp_sweep_evidence_counts"] = {"corrected": corrected, "confirmed": confirmed}
        dev_entry.setdefault("hostname", "unknown")

    corrected, uncorrected = global_evidence
    stats = {
        "global": {
            "effective": global_current,
            "baseline": global_baseline,
            "calibration_outcomes": prev_outcomes,
            "evidence_counts": {
                "corrected": corrected, "uncorrected": uncorrected,
                "confirmed": sum(device_confirmed_counts.values()),
            },
        },
        "devices": devices,
    }
    try:
        stats_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    except Exception as exc:
        LOGGER.debug(f"Failed to write autotune_stats.json: {exc}")

    write_job_health(state_dir, "train_fp_classifier", time.time() - run_start)


def run_threshold_calibration(state_dir: Path) -> None:
    """Entry point called from main() after the model retrain. Never allowed to raise past
    this function — a calibration failure must never be mistaken for (or cause) a
    model-retrain failure; main()'s exit code is driven by train_and_export_onnx() alone.

    PHASE 13: runs TWO passes over the same evidence — global (unchanged from Phase 12,
    still the fallback for devices without enough of their own history) and per-device
    (new: devices with "strongly different profiles" get their own calibrated threshold
    once their OWN evidence supports it, via AutonomousFPEngine's device-profile state —
    see fp_engine.py's get_device_suppress_threshold()).

    PHASE 18: also writes state/autotune_stats.json (see _write_autotune_relay_stats())
    and updates job_health.json -- this function is the single code path BOTH the daily
    cron trigger (via main()) AND fp_engine.py's independent in-process weekly retrain
    thread converge on, so hooking the relay write here (rather than in main()) is what
    makes job-health/calibration metrics correctly reflect activity from either trigger.
    """
    run_start = time.time()
    global_outcome = "no_change_needed"
    global_evidence = (0, 0)
    device_outcomes: dict = {}
    device_evidence: dict = {}
    device_confirmed_counts: dict = {}
    arp_sweep_outcomes: dict = {}
    arp_sweep_evidence: dict = {}
    fp_engine = None  # lazily created by whichever pass below needs it first

    try:
        corrected_fp_scores, uncorrected_uncertain_scores, per_device_corrected, per_device_uncorrected = \
            _collect_calibration_evidence(state_dir)
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE] Failed to collect calibration evidence (non-fatal): {exc}")
        _write_autotune_relay_stats(state_dir, run_start, global_outcome, global_evidence, device_outcomes, device_evidence)
        return

    global_evidence = (len(corrected_fp_scores), len(uncorrected_uncertain_scores))

    # --- Global pass ---------------------------------------------------------------
    try:
        global_current = float(CONFIG.get("fp_combined_suppress_threshold", 0.80))
        new_value, reason = calibrate_suppress_threshold(
            corrected_fp_scores, uncorrected_uncertain_scores,
            current=global_current, min_samples=AUTOTUNE_MIN_SAMPLES,
        )
        global_outcome = _classify_outcome(new_value, reason)
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
        else:
            # CONFIG (config.py's LiveConfig singleton) already exposes .get(key, default) —
            # the exact interface AutonomousFPEngine's config properties expect — so it can be
            # passed directly, no need to reach into its internals.
            fp_engine = fp_engine or AutonomousFPEngine(config=CONFIG, state_dir=str(state_dir))
            for device_id in sorted(device_ids):
                dev_corrected = per_device_corrected.get(device_id, [])
                dev_uncorrected = per_device_uncorrected.get(device_id, [])
                device_evidence[device_id] = (len(dev_corrected), len(dev_uncorrected))
                device_confirmed_counts[device_id] = fp_engine.get_confirmed_count(device_id)
                dev_current = fp_engine.get_device_suppress_threshold(device_id)
                new_value, reason = calibrate_suppress_threshold(
                    dev_corrected, dev_uncorrected,
                    current=dev_current, min_samples=AUTOTUNE_DEVICE_MIN_SAMPLES,
                )
                device_outcomes[device_id] = _classify_outcome(new_value, reason)
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

    # --- Per-device ARP-sweep threshold pass (PHASE 21D3, 'enable per device tuning') --
    # Genuinely separate evidence/rule from the suppress-threshold pass above -- see
    # calibrate_arp_sweep_threshold()'s docstring for why a count threshold needs a
    # bidirectional rule instead of calibrate_suppress_threshold()'s one-directional one.
    try:
        connection_abuse_corrections = _collect_connection_abuse_corrections(state_dir)
        # Union with the suppress-threshold device set above so a device that ONLY ever
        # had CONNECTION_ABUSE evidence (no UNCERTAIN-verdict alerts at all) still gets
        # considered, not just devices already touched by the pass above.
        arp_device_ids = set(connection_abuse_corrections.keys()) | set(device_ids)
        arp_device_ids.discard("unknown")
        if not arp_device_ids:
            LOGGER.info("[AUTOTUNE » ARP-SWEEP] No per-device evidence this run.")
        else:
            fp_engine = fp_engine or AutonomousFPEngine(config=CONFIG, state_dir=str(state_dir))
            global_arp_sweep_default = float(CONFIG.get("arp_sweep_unique_targets_threshold", 8.0))
            for device_id in sorted(arp_device_ids):
                corrected_count = connection_abuse_corrections.get(device_id, 0)
                # VERSION 12 (G7): get_confirmed_count() only matches one exact signature key
                # -- sum both names an arp_sweep-relevant confirmed threat can carry now (see
                # _collect_connection_abuse_corrections()'s own comment for why PORT_SCAN is
                # deliberately excluded).
                confirmed_count = (
                    fp_engine.get_confirmed_count(device_id, signature="CONNECTION_ABUSE")
                    + fp_engine.get_confirmed_count(device_id, signature="INTERNAL_RECONNAISSANCE")
                )
                arp_sweep_evidence[device_id] = (corrected_count, confirmed_count)
                dev_current = fp_engine.get_device_arp_sweep_threshold(device_id, default=global_arp_sweep_default)
                new_value, reason = calibrate_arp_sweep_threshold(corrected_count, confirmed_count, dev_current)
                arp_sweep_outcomes[device_id] = _classify_outcome(new_value, reason)
                if new_value is not None:
                    LOGGER.info(f"[AUTOTUNE » ARP-SWEEP {device_id}] arp_sweep_unique_targets_threshold: {reason}")
                    fp_engine.apply_device_fp_profile(
                        device_id, "arp_sweep_unique_targets_threshold", new_value, baseline=dev_current,
                        set_by="train_fp_classifier.py:calibrate_arp_sweep_threshold",
                        reason=reason, sample_count=corrected_count + confirmed_count,
                    )
                else:
                    LOGGER.debug(f"[AUTOTUNE » ARP-SWEEP {device_id}] {reason}")
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE » ARP-SWEEP] Threshold calibration failed (non-fatal): {exc}")

    try:
        _write_autotune_relay_stats(
            state_dir, run_start, global_outcome, global_evidence, device_outcomes, device_evidence,
            device_confirmed_counts=device_confirmed_counts,
            arp_sweep_outcomes=arp_sweep_outcomes, arp_sweep_evidence=arp_sweep_evidence,
        )
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE] Failed to write autotune relay stats (non-fatal): {exc}")


def _load_training_row_exclusions(state_dir: Path) -> set:
    """Reads state/training_row_exclusions.json (written by
    identify_corrupted_training_rows.py), a set of dedup keys for historically-
    corrupted rows -- e.g. DNS_COVERT_TUNNELING/DGA_BOTNET_C2 alerts predating their
    domain-attribution fix, whose f1_entropy feature was computed from the wrong
    domain. This file is a separate, deletable overlay; load_dataset() below skips
    matching rows without alerts.json/autonomous_muted.jsonl themselves ever being
    modified. Missing/unreadable file -> empty set, i.e. no exclusions (fail-open,
    matches config_overrides.json's own missing-file behavior elsewhere in this file)."""
    path = state_dir / "training_row_exclusions.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("excluded_keys", {}).keys())
    except Exception:
        return set()


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
        "skipped_corrupted_attribution": 0,
    }
    excluded_keys = _load_training_row_exclusions(state_dir)

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
        if payload.get("escalated_via_persistence"):
            # BUGFIX (live audit): this alert's HIGH state/confidence came from the SAME
            # single, uncorroborated hypothesis simply recurring for suspicious_escalation_
            # seconds -- decision_engine.py never found a 2nd independent evidence source.
            # Training it as a clean label=0 "this is what a genuine HIGH looks like"
            # sample would reinforce exactly the pattern pipeline.py's own confidence cap
            # (0.55, well below a real hypothesis_high's 0.85) already treats as weaker
            # evidence, not stronger.
            stats["threat_skipped_corrected"] += 1
            continue
        if _alert_dedup_key(payload) in corrected_keys:
            # Corrected after the fact (autonomous or operator) — same reasoning.
            stats["threat_skipped_corrected"] += 1
            continue
        if _alert_dedup_key(payload) in excluded_keys:
            # Historically-corrupted domain attribution (see
            # identify_corrupted_training_rows.py) — f1_entropy would be computed from
            # the wrong domain for this row; excluded rather than trained on.
            stats["skipped_corrupted_attribution"] += 1
            continue
        _append_sample(X, y, doc, 0, stats, source="threat")

    # 2. False positives from autonomous muted JSONL (parsed above, label=1)
    for doc in muted_docs:
        payload = _extract_payload(doc)
        if _alert_dedup_key(payload) in excluded_keys:
            stats["skipped_corrupted_attribution"] += 1
            continue
        _append_sample(X, y, doc, 1, stats, source="fp")

    return X, y, stats


def train_and_export_onnx(state_dir: Path) -> bool:
    """Trains GradientBoostingClassifier on 11 features and exports to state/models/fp_classifier.onnx."""
    X, y, stats = load_dataset(state_dir)
    LOGGER.info(
        "Dataset loaded: %d accepted real samples | threat accepted/rejected=%d/%d "
        "(skipped as corrected FPs=%d, skipped as non-alert transparency logs=%d) | "
        "fp accepted/rejected=%d/%d | skipped as historically-corrupted attribution=%d | dim=%d",
        len(X),
        stats["threat_accepted"], stats["threat_rejected"],
        stats["threat_skipped_corrected"], stats["threat_skipped_non_alert"],
        stats["fp_accepted"], stats["fp_rejected"],
        stats["skipped_corrupted_attribution"],
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
        from sklearn.model_selection import train_test_split
        from sklearn.isotonic import IsotonicRegression

        # VERSION 11 (P2, review #13/#14): a genuine held-out split, used ONLY for
        # calibration below -- fitting isotonic regression against the SAME data the
        # classifier trained on would just refit an already-overconfident curve to
        # itself (the model has seen every one of those labels already), which is
        # not calibration, it's restating training accuracy in a different shape.
        # Stratified on y so a rare class isn't accidentally starved from either
        # split. Falls back to training on everything (previous behavior) when
        # there's too little data for a genuine split -- see calibration_reliable
        # below for how that case is handled honestly rather than silently.
        can_split = len(X) >= 40 and len(set(y)) >= 2
        if can_split:
            X_train, X_calib, y_train, y_calib = train_test_split(
                X, y, test_size=0.25, random_state=42, stratify=y
            )
        else:
            X_train, y_train = X, y
            X_calib, y_calib = [], []

        pipeline = make_pipeline(
            StandardScaler(),
            GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42)
        )
        pipeline.fit(X_train, y_train)
        acc = pipeline.score(X_train, y_train)
        LOGGER.info("✅ GBDT Model trained successfully. Training Accuracy: %.2f%%", acc * 100.0)

        # VERSION 11 (P2): isotonic calibration -- maps the raw classifier score to
        # an actually-calibrated probability, fit against the HELD-OUT split above
        # (never seen during training). Saved as a small breakpoint JSON, not a
        # pickled sklearn object, so fp_engine.py's lean ONNX-only runtime inference
        # path can apply it via plain linear interpolation -- no sklearn import
        # needed at inference time, matching this project's existing train-with-
        # sklearn / infer-with-ONNX split.
        model_dir = state_dir / "models"
        model_dir.mkdir(parents=True, exist_ok=True)
        calibrator_path = model_dir / "fp_calibration.json"
        calibration_reliable = can_split and len(X_calib) >= 20 and len(set(y_calib)) >= 2
        if calibration_reliable:
            raw_calib_probs = pipeline.predict_proba(X_calib)[:, 1]
            iso = IsotonicRegression(out_of_bounds="clip")
            iso.fit(raw_calib_probs, y_calib)
            calibrator_path.write_text(json.dumps({
                "reliable": True,
                "x_thresholds": [float(v) for v in iso.X_thresholds_],
                "y_thresholds": [float(v) for v in iso.y_thresholds_],
                "fit_at": time.time(),
                "calibration_sample_count": len(X_calib),
            }, indent=2), encoding="utf-8")
            LOGGER.info("📐 Isotonic calibration fit on %d held-out samples (never used for "
                        "training), saved to %s", len(X_calib), calibrator_path)
        else:
            # Not enough held-out data for a trustworthy calibration curve -- an
            # explicit "unreliable" marker, not a silently-stale or fabricated-from-
            # too-few-points curve. fp_engine.py must fall back to the raw,
            # explicitly-labeled-as-uncalibrated score when this is present.
            calibrator_path.write_text(json.dumps({
                "reliable": False,
                "reason": f"only {len(X_calib)} held-out sample(s) available "
                          f"(need >=20 with both classes present for a trustworthy curve)",
                "fit_at": time.time(),
            }, indent=2), encoding="utf-8")
            LOGGER.warning("⚠️ Not enough held-out data (%d sample(s)) for reliable calibration -- "
                           "wrote an explicit 'unreliable' marker; fp_engine.py will use the raw, "
                           "uncalibrated score (FP_MODEL_SCORE) instead of a fabricated calibration.",
                           len(X_calib))

        # Convert to ONNX format (zipmap=False outputs clean 2D numpy probability arrays)
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        onnx_model = convert_sklearn(
            pipeline,
            initial_types=[("input", FloatTensorType([None, FP_FEATURE_DIM]))],
            options={GradientBoostingClassifier: {"zipmap": False}}
        )

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
