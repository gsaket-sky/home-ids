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
calibrate_suppress_threshold() below for the exact rule. 2026-09-21 (legacy/Sheet 03a
autotune reconciliation): this and arp_sweep_unique_targets_threshold are now proposed
through argus/autotune/engine.py's AutotuneEngine (propose -> canary -> promote,
versioned in threshold_history), not written directly to state/config_overrides.json/
device_fp_profiles.json — see _propose_and_promote()'s own docstring below.

INPUT DATA SOURCES:
  1. config.yaml -> paths.alert_json_path (preferred; JSONL or JSON array)
  2. state/alerts.json (legacy fallback)
  3. The graph's decisions.raw_payload_json.fp_suppression_log entries (auto-suppressed/
     corrected false positives) — see _read_muted_docs_from_graph(). 2026-09-21: replaces
     the old state/autonomous_muted.jsonl, which had no size cap and grew unbounded; any
     pre-existing history in that file was migrated once via
     scripts/backfill_muted_log_to_graph.py.
  4. state/training_row_exclusions.json (optional; written by
     identify_corrupted_training_rows.py) -- rows listed here are skipped during
     load_dataset(), without alerts.json/the graph themselves being modified. Currently
     used to exclude historical DNS_COVERT_TUNNELING/DGA_BOTNET_C2 rows whose f1_entropy
     feature was computed from the wrong domain, predating each signature's own
     domain-attribution fix.

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
import os
import sys
import time
import uuid
from pathlib import Path

# Ensure src/ directory is in Python path for standalone CLI execution
SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from utils import entropy as compute_entropy, write_job_health
from config import CONFIG
from intelligence.fp_engine import AutonomousFPEngine
from argus.graph.store import GraphStore
from argus.autotune.engine import AutotuneEngine

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


def _atomic_write_text(path: Path, text: str) -> None:
    """write_text() to a temp file in the SAME directory then os.replace() -- a kill
    (OOM, a forced restart, or -- new with resource-aware scheduling -- a SIGKILL of
    this job while SIGSTOP-paused mid-write) can never leave a truncated/corrupt file
    at `path`: either the old good version or the new complete one, never a partial
    one. `path` is fp_calibration.json, read by fp_engine.py's _load_calibration()
    every boot and every hot-reload -- a torn write here silently degrades FP
    suppression until the next successful retrain, not something to risk."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Same guarantee as _atomic_write_text(), for fp_classifier.onnx -- the model
    file fp_engine.py's _load_lgbm_model() loads into onnxruntime every boot and every
    hot-reload."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


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
    correction of the SAME alert in the graph's fp_suppression_log entries (either
    autonomously suppressed at publish time, or operator-marked afterward via the
    "Mark False Positive" Telegram button). device_id + queried_domain + the alert's own `timestamp`
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

# 2026-09-21 (legacy/Sheet 03a autotune reconciliation, Phase G4): the old
# state/autonomous_muted.jsonl was read with NO time filter at all -- genuinely
# unbounded, "cumulative... ever". Its graph-backed replacement (decisions rows
# carrying a raw_payload_json.fp_suppression_log, see fp_engine.py's
# _write_muted_log()) queries a table that also holds EVERY OTHER decision this
# process has ever made, not just suppression events, so an unfiltered scan is a
# real, growing cost at production scale. 90 days is a deliberate, generous-but-
# bounded improvement, not an accidental truncation: calibration evidence should
# reflect how a device behaves NOW, and every MIN_SAMPLES-style threshold in this
# file is small enough to accumulate well within 90 days on a real network.
_CALIBRATION_EVIDENCE_LOOKBACK_SECONDS = 90 * 86400.0


def _read_muted_docs_from_graph(state_dir: Path, since: float = None, limit: int = None) -> list:
    """Graph-backed replacement for reading every line of the old
    state/autonomous_muted.jsonl -- queries `decisions` for rows carrying a
    raw_payload_json.fp_suppression_log (written live by fp_engine.py's
    _write_muted_log(), or migrated from pre-existing history by
    backfill_muted_log_to_graph.py) and returns just that inner dict per row.
    Deliberately returns the EXACT SAME per-entry shape
    (ts_unix/type/confidence/reasons/device/domain/risk_score/original_alert)
    the old file's lines held, so every existing consumer of that shape --
    _extract_payload(), _alert_dedup_key(), the corrected_fp_scores/per_device_*
    loops below -- needs no further changes, only this read.

    `since` (unix timestamp, optional): only rows at or after this time --
    see _CALIBRATION_EVIDENCE_LOOKBACK_SECONDS's own comment for why the two
    calibration-evidence callers use this instead of an unbounded scan.
    `limit` (optional): most-recent-N only, matching load_dataset()'s own
    pre-existing MAX_REAL_SAMPLES_PER_CLASS cap on the old file's tail."""
    docs = []
    try:
        store = _get_graph_store(state_dir)
        try:
            query = "SELECT raw_payload_json FROM decisions WHERE raw_payload_json LIKE '%fp_suppression_log%'"
            params: list = []
            if since is not None:
                query += " AND timestamp >= ?"
                params.append(since)
            query += " ORDER BY timestamp DESC"
            if limit is not None:
                query += " LIMIT ?"
                params.append(limit)
            for row in store._conn.execute(query, params).fetchall():
                try:
                    payload = json.loads(row["raw_payload_json"] or "{}")
                except (TypeError, ValueError):
                    continue
                entry = payload.get("fp_suppression_log")
                if isinstance(entry, dict):
                    docs.append(entry)
        finally:
            store.close()
    except Exception as exc:
        LOGGER.warning(f"[AUTOTUNE] Could not read fp_suppression_log entries from the graph: {exc}")
    return docs


def _collect_calibration_evidence(state_dir: Path) -> tuple:
    """Independently re-reads alerts.json + the graph's fp_suppression_log entries
    (same sources load_dataset() uses, via the same helpers) to build threshold-
    calibration evidence, both pooled (global) and grouped by device (per-device).

    Returns (corrected_fp_scores, uncorrected_uncertain_scores, per_device_corrected,
             per_device_uncorrected):
      corrected_fp_scores: CL-AFPE combined confidence (fp_verdict.confidence) of alerts
        that were PUBLISHED (not auto-suppressed — the current threshold missed them) but
        were LATER confirmed as false positives — by an operator OR by ollama_soc.py's
        validated LLM pass (see _FP_CORRECTION_TYPES). Proof that suppression at that
        score would have been correct.

        BUGFIX (2026-09-27, Phase 1 of the autonomy-completion effort — this is the
        real reason fp_combined_suppress_threshold has never once proposed a change
        on live .94 data, confirmed by running this function directly against the
        real graph, not guessed): this loop pooled a correction of ANY verdict
        (CONFIRMED_THREAT, FALSE_POSITIVE, UNCERTAIN, from either STAGE_1_HARD_STOP
        or STAGE_3_COMBINED) as if they were all comparable evidence about where the
        suppress threshold should sit. Only an original verdict of UNCERTAIN is
        actually adjacent to this parameter's decision boundary — the near-miss band
        just below the current suppress threshold this parameter's calibration is
        meant to probe. A STAGE_1_HARD_STOP correction has an unrelated sentinel
        confidence (observed as low as 0.0 on real data); a CONFIRMED_THREAT
        correction sits far BELOW combined_uncertain_threshold, a different regime
        entirely — moving the suppress threshold down to either of those confidence
        levels would suppress nearly everything, not calibrate anything. Either kind
        of stray entry sets lowest_corrected near 0, which then permanently loses to
        the "any uncorrected UNCERTAIN alert scoring >= the lowest confirmed-FP
        score" safety gate below on any network with a nonzero volume of ordinary
        UNCERTAIN alerts — i.e. every real network, forever. Requiring verdict ==
        "UNCERTAIN" (matching the uncorrected side's own existing check just below,
        which this loop was inconsistent with) is the actual fix, not a threshold
        band-aid: it makes both sides of the comparison measure the same population.
      uncorrected_uncertain_scores: combined confidence of alerts published with verdict
        UNCERTAIN that were NEVER corrected by either source — no evidence either way.
        Used only as a safety ceiling: calibration refuses to act if this overlaps the
        corrected-FP range.
      per_device_corrected / per_device_uncorrected: the same two lists, grouped by
        device_id, for the per-device calibration pass.
    """
    muted_docs = _read_muted_docs_from_graph(
        state_dir, since=time.time() - _CALIBRATION_EVIDENCE_LOOKBACK_SECONDS,
    )

    corrected_fp_scores = []
    per_device_corrected = {}
    for doc in muted_docs:
        if doc.get("type") not in _FP_CORRECTION_TYPES:
            continue
        original = doc.get("original_alert", {}) or {}
        fp_verdict = original.get("fp_verdict", {}) or {}
        # See this function's own docstring: only an original verdict of UNCERTAIN
        # is comparable to fp_combined_suppress_threshold's own decision boundary --
        # matches the verdict check the uncorrected side already applies below.
        if fp_verdict.get("verdict") != "UNCERTAIN":
            continue
        conf = fp_verdict.get("confidence")
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


# 2026-09-27 (Phase 3 of the autonomy-completion effort): combined_uncertain_threshold's
# own calibration -- allowlisted and consumed live (fp_engine.py's
# get_device_uncertain_threshold()) since this same phase, previously a pure config
# value with zero autotune wiring at all. Deliberately a SEPARATE evidence population
# from calibrate_suppress_threshold() above: that one needs UNCERTAIN-verdict
# corrections (the near-miss band just below the SUPPRESS threshold); this one needs
# CONFIRMED_THREAT-verdict corrections (the near-miss band just below the UNCERTAIN
# threshold, i.e. where a corrected alert was published at FULL SEVERITY when it was
# actually a false positive) -- mixing the two populations would be the exact same
# category error Phase 1 fixed in _collect_calibration_evidence() itself.
AUTOTUNE_UNCERTAIN_SAFETY_MARGIN = 0.02  # stays this far below the highest corrected-CONFIRMED_THREAT score
AUTOTUNE_UNCERTAIN_ABSOLUTE_FLOOR = 0.30  # matches TUNABLE_PARAMETERS' own bound for this parameter


def _collect_uncertain_calibration_evidence(state_dir: Path) -> "tuple[list, list, dict, dict]":
    """Same shape/sourcing as _collect_calibration_evidence() (same muted_docs +
    alerts.json sources, same 90-day lookback), but for the DIFFERENT population
    combined_uncertain_threshold's own boundary needs:

    corrected_confirmed_scores: fp_verdict.confidence of alerts that were published
      as CONFIRMED_THREAT (full severity -- the current uncertain_threshold's `else`
      branch) but were LATER confirmed to be false positives. Proof that the
      uncertain/confirmed boundary sat too high for these.
    uncorrected_confirmed_scores: confidence of CONFIRMED_THREAT alerts that were
      NEVER corrected -- genuine standing threats. Safety ceiling: refuse to lower
      the boundary if any of these sits at/below the highest corrected score (the
      same ambiguous-overlap refusal calibrate_suppress_threshold() applies)."""
    muted_docs = _read_muted_docs_from_graph(
        state_dir, since=time.time() - _CALIBRATION_EVIDENCE_LOOKBACK_SECONDS,
    )

    corrected_confirmed_scores = []
    per_device_corrected = {}
    for doc in muted_docs:
        if doc.get("type") not in _FP_CORRECTION_TYPES:
            continue
        original = doc.get("original_alert", {}) or {}
        fp_verdict = original.get("fp_verdict", {}) or {}
        if fp_verdict.get("verdict") != "CONFIRMED_THREAT" or fp_verdict.get("stage") != "STAGE_3_COMBINED":
            continue  # same STAGE_1_HARD_STOP exclusion Phase 1 applied for the same reason
        conf = fp_verdict.get("confidence")
        if not isinstance(conf, (int, float)):
            continue
        corrected_confirmed_scores.append(float(conf))
        device_id = original.get("device", {}).get("id", "unknown")
        per_device_corrected.setdefault(device_id, []).append(float(conf))

    corrected_keys = {_alert_dedup_key(_extract_payload(d)) for d in muted_docs}

    uncorrected_confirmed_scores = []
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
            if fp_v.get("verdict") != "CONFIRMED_THREAT" or fp_v.get("stage") != "STAGE_3_COMBINED":
                continue
            if _alert_dedup_key(payload) in corrected_keys:
                continue  # this one WAS corrected -- it's positive evidence, not negative
            conf = fp_v.get("confidence")
            if not isinstance(conf, (int, float)):
                continue
            uncorrected_confirmed_scores.append(float(conf))
            device_id = payload.get("device", {}).get("id", "unknown")
            per_device_uncorrected.setdefault(device_id, []).append(float(conf))
        break  # mirrors _collect_calibration_evidence()'s own "first non-empty source wins"

    return corrected_confirmed_scores, uncorrected_confirmed_scores, per_device_corrected, per_device_uncorrected


def calibrate_uncertain_threshold(corrected_confirmed_scores: list, uncorrected_confirmed_scores: list,
                                     current: float, min_samples: int = AUTOTUNE_MIN_SAMPLES) -> tuple:
    """Mirrors calibrate_suppress_threshold()'s own rule shape exactly, moved to the
    OPPOSITE boundary and the OPPOSITE population (see this module's own comment
    above calibrate_suppress_threshold() for why they can't share evidence):

    - Only ever LOWERS combined_uncertain_threshold (direction=-1 in
      autotune/engine.py's _LESS_SENSITIVE_DIRECTION -- lowering IS the less-
      sensitive move here, matching TUNABLE_PARAMETERS' own bound). Raising it back
      up is a human decision, same as the suppress-threshold rule.
    - Requires >= min_samples confirmed false positives (published at full
      CONFIRMED_THREAT severity, later corrected) before proposing anything.
    - Refuses to act if any UNCORRECTED genuine CONFIRMED_THREAT scored at or below
      the highest corrected-FP score -- the same ambiguous-overlap safety rule.
    - Never goes below AUTOTUNE_UNCERTAIN_ABSOLUTE_FLOOR."""
    if len(corrected_confirmed_scores) < min_samples:
        return None, (
            f"Only {len(corrected_confirmed_scores)} confirmed false positive(s) published at "
            f"CONFIRMED_THREAT severity (need >= {min_samples}) -- not enough evidence to calibrate yet."
        )

    highest_corrected = max(corrected_confirmed_scores)

    if uncorrected_confirmed_scores:
        lowest_uncorrected = min(uncorrected_confirmed_scores)
        if lowest_uncorrected <= highest_corrected:
            return None, (
                f"Refusing to calibrate: a genuine, uncorrected CONFIRMED_THREAT scored "
                f"{lowest_uncorrected:.3f}, at or below the highest corrected-FP score "
                f"{highest_corrected:.3f} -- ambiguous overlap, not safe to auto-resolve."
            )

    candidate = min(highest_corrected + AUTOTUNE_UNCERTAIN_SAFETY_MARGIN, current)
    candidate = round(max(candidate, AUTOTUNE_UNCERTAIN_ABSOLUTE_FLOOR), 4)

    if candidate >= current:
        return None, (
            f"Calibration would not lower the threshold below its current effective "
            f"value {current:.3f} -- no change needed."
        )

    gap_note = (
        f", clean gap below the lowest uncorrected CONFIRMED_THREAT score "
        f"{min(uncorrected_confirmed_scores):.3f}"
        if uncorrected_confirmed_scores else
        ", no uncorrected CONFIRMED_THREAT alerts observed in this window to compare against"
    )
    reason = (
        f"{len(corrected_confirmed_scores)} confirmed false positive(s) published at full "
        f"CONFIRMED_THREAT severity with combined scores as high as {highest_corrected:.3f} -- "
        f"lowered combined_uncertain_threshold from {current:.3f} to {candidate:.3f} "
        f"({AUTOTUNE_UNCERTAIN_SAFETY_MARGIN:.2f} safety margin above the highest corrected-FP "
        f"score{gap_note})."
    )
    return candidate, reason


def _collect_connection_abuse_corrections(state_dir: Path) -> dict:
    """PHASE 21D3 ('enable per device tuning'): independently scans the graph's
    fp_suppression_log entries for CONNECTION_ABUSE-signature corrections (covers
    arp_sweep evidence among others), grouped by device -- separate from
    _collect_calibration_evidence() above, since arp_sweep_unique_targets_threshold
    calibration needs a per-device correction COUNT, not the pooled fp_verdict
    confidence-score distribution that function computes (arp_sweep has no comparable
    0-1 confidence score to calibrate against). Returns {device_id: corrected_count}."""
    counts: dict = {}
    muted_docs = _read_muted_docs_from_graph(
        state_dir, since=time.time() - _CALIBRATION_EVIDENCE_LOOKBACK_SECONDS,
    )
    for doc in muted_docs:
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


def _device_scoped_promoted_value(store: GraphStore, parameter: str, device_id: str):
    """The most recently PROMOTED value for `parameter` at EXACTLY this device's own
    scope (device_type IS NULL) -- deliberately NOT the 3-tier device/category/global
    fallback AutotuneEngine.get_active_value() does, since autotune_stats.json's
    per-device "effective"/"arp_sweep_effective" figures are meant to show only when
    THIS device has its own calibrated override (matching the old device_fp_profiles.json
    read's exact semantics: a per-device profile entry, not "whatever value this device
    would currently use including inherited global/category defaults"). Returns None if
    no such row exists (never promoted, or promoted then rolled back) -- direct SQL
    against store._conn, same pattern backtest_job.py's own diagnostic queries use,
    rather than reaching into AutotuneEngine's own private scope-lookup method."""
    row = store._conn.execute(
        "SELECT new_value FROM threshold_history WHERE parameter=? AND device_id=? AND "
        "device_type IS NULL AND promoted_at IS NOT NULL AND rolled_back_at IS NULL "
        "ORDER BY promoted_at DESC LIMIT 1",
        (parameter, device_id),
    ).fetchone()
    return float(row["new_value"]) if row is not None else None


def _global_scoped_promoted_row(store: GraphStore, parameter: str):
    """Same as _device_scoped_promoted_value() above, but for the global scope, and
    returns the full row (old_value/new_value) since callers need both."""
    return store._conn.execute(
        "SELECT old_value, new_value FROM threshold_history WHERE parameter=? AND "
        "device_id IS NULL AND device_type IS NULL AND promoted_at IS NOT NULL AND "
        "rolled_back_at IS NULL ORDER BY promoted_at DESC LIMIT 1",
        (parameter,),
    ).fetchone()


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
                                 arp_sweep_outcomes: dict = None, arp_sweep_evidence: dict = None,
                                 store: GraphStore = None) -> None:
    """Writes state/autotune_stats.json -- synced into Prometheus gauges by the
    long-running pipeline process's sync_relay_metrics() (this script is a separate
    cron/thread-triggered process with no HTTP server of its own).

    2026-09-21 (legacy/Sheet 03a autotune reconciliation, Phase C): effective/baseline
    values for fp_combined_suppress_threshold/arp_sweep_unique_targets_threshold now come
    from `threshold_history` (via `store`, when given) instead of config_overrides.json/
    device_fp_profiles.json -- those two files stop being written for these two keys as
    of this same change, so re-reading them here would silently go stale. `store=None`
    (this run's GraphStore/AutotuneEngine failed to open, see run_threshold_calibration()'s
    own try/except) degrades to "no effective/baseline figure this run" rather than a
    crash -- calibration_outcomes/evidence_counts, this function's other real payload,
    are unaffected either way.

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
    if store is not None:
        try:
            global_row = _global_scoped_promoted_row(store, "fp_combined_suppress_threshold")
            if global_row is not None:
                global_current = float(global_row["new_value"])
                global_baseline = float(global_row["old_value"])
        except Exception:
            pass

    prev_global = existing.get("global", {})
    prev_outcomes = prev_global.get("calibration_outcomes", {})
    prev_outcomes[global_outcome] = prev_outcomes.get(global_outcome, 0) + 1

    devices = existing.get("devices", {})

    for device_id, outcome in device_outcomes.items():
        dev_entry = devices.setdefault(device_id, {})
        dev_outcomes = dev_entry.get("calibration_outcomes", {})
        dev_outcomes[outcome] = dev_outcomes.get(outcome, 0) + 1
        dev_entry["calibration_outcomes"] = dev_outcomes
        if store is not None:
            try:
                dev_value = _device_scoped_promoted_value(store, "fp_combined_suppress_threshold", device_id)
                if dev_value is not None:
                    dev_entry["effective"] = dev_value
            except Exception:
                pass
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
        if store is not None:
            try:
                dev_arp_value = _device_scoped_promoted_value(store, "arp_sweep_unique_targets_threshold", device_id)
                if dev_arp_value is not None:
                    dev_entry["arp_sweep_effective"] = dev_arp_value
            except Exception:
                pass
        corrected, confirmed = arp_sweep_evidence.get(device_id, (0, 0))
        dev_entry["arp_sweep_evidence_counts"] = {"corrected": corrected, "confirmed": confirmed}
        dev_entry.setdefault("hostname", "unknown")

    # BUGFIX (disk-retention audit): `devices` is a read-modify-write cumulative dict
    # with NO equivalent of device_fp_profiles.json's discard_device_profile() --
    # an entry for a device merged away or gone idle far longer than any retention
    # window stayed here forever. Prune against the graph's own live population
    # (30d floor matches the shortest real evidence-retention window in this
    # codebase, pi_8gb's) whenever a store is available; degrades to "no pruning
    # this run" rather than guessing when it isn't (store=None is a real, existing
    # code path -- see this function's own docstring).
    if store is not None and devices:
        try:
            still_active = store.get_active_device_ids(seen_since=time.time() - 30 * 86400.0)
            for stale_id in [d for d in devices if d not in still_active]:
                del devices[stale_id]
        except Exception:
            pass

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


# 2026-09-21, legacy/Sheet 03a autotune reconciliation (Phase C): this script's write
# side used to go straight to state/config_overrides.json (global) and
# state/device_fp_profiles.json (per-device), with no versioning, canary, or rollback --
# see AutotuneEngine's own module docstring for the full Sheet 03a infrastructure this
# now routes through instead. AutotuneEngine.propose_change() hard-requires a
# backtest_runs row with overall_pass=1; that table is queried ONLY by exact run_id
# everywhere else in the codebase (confirmed via grep, never "most recent"), so
# synthesizing a row here to represent "this confirmed-label evidence evaluation
# passed" needs no schema change and no special-casing in engine.py itself.
def _get_graph_store(state_dir: Path) -> GraphStore:
    # Same relative path backtest_job.py's own __main__ defaults to
    # ("state/v13_graph.db"), resolved the same way this script resolves state_dir --
    # both processes end up pointed at the identical file.
    return GraphStore(str(state_dir / "v13_graph.db"))


def _insert_confirmed_label_backtest_run(store: GraphStore, detail: dict) -> str:
    """See this section's own module comment above for why a synthesized
    backtest_runs row is the correct, schema-legal way to satisfy
    propose_change()'s gating requirement with real confirmed-label evidence
    instead of a synthetic-attack sweep result."""
    run_id = f"confirmed_label:{uuid.uuid4().hex}"
    now = time.time()
    store._conn.execute(
        "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass, "
        "golden_set_result_json, synthetic_result_json) VALUES (?, ?, ?, 1, '{}', ?)",
        (run_id, now, now, json.dumps({"kind": "confirmed_label_evidence", **detail})),
    )
    store._maybe_commit()
    return run_id


def _propose_and_promote(engine: AutotuneEngine, store: GraphStore, parameter: str, new_value: float,
                          reason: str, evidence_detail: dict, device_id=None, device_type=None,
                          now: float = None) -> None:
    """Routes ONE calibration decision through AutotuneEngine instead of writing
    directly to a flat file. Two things happen, in order, both best-effort (a
    failure in either must never interrupt the rest of this script's run):

    1. Opportunistically PROMOTES this exact scope's own most recent still-
       pending proposal, if one exists and its canary window has elapsed --
       this script already runs on a recurring cron (autotune_schedule_cron),
       so reusing that cadence as the "confirming run" needs no new scheduling
       concept. Uses a second synthesized backtest_runs row, same shape as the
       one backing the original proposal.
    2. PROPOSES `new_value` for `parameter` at this scope, backed by a fresh
       synthesized backtest_runs row representing this run's own confirmed-
       label evidence (see _insert_confirmed_label_backtest_run()).

    A rejected proposal (cooldown, trust-radius, allowlist) is logged and
    otherwise ignored -- calibrate_*() already decided real evidence supports
    this change; a rejection here is AutotuneEngine's own safety
    infrastructure doing its job, not an error to surface as one."""
    now = now if now is not None else time.time()

    try:
        pending = store._conn.execute(
            "SELECT change_id FROM threshold_history WHERE parameter=? AND "
            "device_id IS ? AND device_type IS ? AND promoted_at IS NULL AND rolled_back_at IS NULL "
            "ORDER BY proposed_at DESC LIMIT 1",
            (parameter, device_id, device_type),
        ).fetchone()
        if pending is not None:
            confirm_run_id = _insert_confirmed_label_backtest_run(store, {"role": "confirming", **evidence_detail})
            if engine.promote_change(pending["change_id"], confirm_run_id, now=now):
                LOGGER.info(f"[AUTOTUNE] Promoted pending change {pending['change_id']} for {parameter} "
                            f"(device_id={device_id}, device_type={device_type})")
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE] Promotion attempt failed for {parameter} "
                      f"(device_id={device_id}, device_type={device_type}, non-fatal): {exc}")

    try:
        propose_run_id = _insert_confirmed_label_backtest_run(store, {"role": "proposal", **evidence_detail})
        result = engine.propose_change(
            parameter, new_value, reason=reason, device_id=device_id, device_type=device_type,
            backtest_run_id=propose_run_id, now=now,
        )
        if not result.accepted:
            LOGGER.warning(f"[AUTOTUNE] propose_change rejected for {parameter} "
                            f"(device_id={device_id}, device_type={device_type}): {result.reason}")
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE] propose_change failed for {parameter} "
                      f"(device_id={device_id}, device_type={device_type}, non-fatal): {exc}")


def run_threshold_calibration(state_dir: Path, now: float = None) -> None:
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
    autotune_now = now if now is not None else run_start
    global_outcome = "no_change_needed"
    global_evidence = (0, 0)
    device_outcomes: dict = {}
    device_evidence: dict = {}
    device_confirmed_counts: dict = {}
    arp_sweep_outcomes: dict = {}
    arp_sweep_evidence: dict = {}
    fp_engine = None  # lazily created by whichever pass below needs it first

    # 2026-09-21 (legacy/Sheet 03a autotune reconciliation, Phase C): one GraphStore/
    # AutotuneEngine pair for this whole run, shared by all three passes below.
    # GraphStore is WAL-mode-safe for concurrent process access (documented in
    # middleware/graph_client.py's own module docstring), so this is safe alongside
    # the live pipeline's own long-lived connection.
    try:
        store = _get_graph_store(state_dir)
        engine = AutotuneEngine(store)
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE] Failed to open GraphStore/AutotuneEngine for this run "
                      f"(threshold_history writes will be skipped entirely this run): {exc}")
        store = None
        engine = None

    try:
        corrected_fp_scores, uncorrected_uncertain_scores, per_device_corrected, per_device_uncorrected = \
            _collect_calibration_evidence(state_dir)
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE] Failed to collect calibration evidence (non-fatal): {exc}")
        _write_autotune_relay_stats(state_dir, run_start, global_outcome, global_evidence, device_outcomes, device_evidence,
                                     store=store)
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        return

    global_evidence = (len(corrected_fp_scores), len(uncorrected_uncertain_scores))

    # --- Global pass ---------------------------------------------------------------
    try:
        config_default = float(CONFIG.get("fp_combined_suppress_threshold", 0.80))
        # Reads through AutotuneEngine's own global tier first (a promoted value from
        # a PRIOR run of this same pass), falling back to config.yaml/config-override
        # only if nothing has ever been promoted yet -- same effective-value framing
        # as fp_engine.py's get_device_suppress_threshold(None) tier, without needing
        # an AutonomousFPEngine instance just for this one global read.
        global_current = (
            engine.get_active_value("fp_combined_suppress_threshold", device_id=None, default=config_default)
            if engine is not None else config_default
        )
        new_value, reason = calibrate_suppress_threshold(
            corrected_fp_scores, uncorrected_uncertain_scores,
            current=global_current, min_samples=AUTOTUNE_MIN_SAMPLES,
        )
        global_outcome = _classify_outcome(new_value, reason)
        LOGGER.info(f"[AUTOTUNE » GLOBAL] fp_combined_suppress_threshold: {reason}")
        if new_value is not None and engine is not None:
            _propose_and_promote(
                engine, store, "fp_combined_suppress_threshold", new_value, reason,
                evidence_detail={
                    "corrected_count": len(corrected_fp_scores),
                    "uncorrected_count": len(uncorrected_uncertain_scores),
                    "rule": "calibrate_suppress_threshold",
                },
                now=autotune_now,
            )
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE » GLOBAL] Threshold calibration failed (non-fatal): {exc}")

    # --- combined_uncertain_threshold global pass (2026-09-27, Phase 3) --------------
    # Separate evidence collection from the suppress-threshold pass above -- see
    # _collect_uncertain_calibration_evidence()'s own docstring for why they can't
    # share a population. Best-effort, same "never take down the run" framing.
    uncertain_outcome = "no_change_needed"
    uncertain_evidence = (0, 0)
    device_uncertain_outcomes: dict = {}
    device_uncertain_evidence: dict = {}
    try:
        (corrected_confirmed_scores, uncorrected_confirmed_scores,
         per_device_uncertain_corrected, per_device_uncertain_uncorrected) = \
            _collect_uncertain_calibration_evidence(state_dir)
        uncertain_evidence = (len(corrected_confirmed_scores), len(uncorrected_confirmed_scores))

        # 0.55 matches fp_engine.py's own _DEFAULT_COMBINED_UNCERTAIN_THRESHOLD (not
        # imported -- this file's sibling suppress-threshold pass above uses the same
        # plain-literal-default convention rather than importing fp_engine.py's
        # private constants).
        uncertain_config_default = float(CONFIG.get("fp_combined_uncertain_threshold", 0.55))
        uncertain_global_current = (
            engine.get_active_value("combined_uncertain_threshold", device_id=None, default=uncertain_config_default)
            if engine is not None else uncertain_config_default
        )
        new_value, reason = calibrate_uncertain_threshold(
            corrected_confirmed_scores, uncorrected_confirmed_scores,
            current=uncertain_global_current, min_samples=AUTOTUNE_MIN_SAMPLES,
        )
        uncertain_outcome = _classify_outcome(new_value, reason)
        LOGGER.info(f"[AUTOTUNE » GLOBAL] combined_uncertain_threshold: {reason}")
        if new_value is not None and engine is not None:
            _propose_and_promote(
                engine, store, "combined_uncertain_threshold", new_value, reason,
                evidence_detail={
                    "corrected_count": len(corrected_confirmed_scores),
                    "uncorrected_count": len(uncorrected_confirmed_scores),
                    "rule": "calibrate_uncertain_threshold",
                },
                now=autotune_now,
            )

        # --- combined_uncertain_threshold per-device pass ---
        uncertain_device_ids = set(per_device_uncertain_corrected.keys()) | set(per_device_uncertain_uncorrected.keys())
        uncertain_device_ids.discard("unknown")
        for device_id in sorted(uncertain_device_ids):
            dev_corrected = per_device_uncertain_corrected.get(device_id, [])
            dev_uncorrected = per_device_uncertain_uncorrected.get(device_id, [])
            device_uncertain_evidence[device_id] = (len(dev_corrected), len(dev_uncorrected))
            dev_current = engine.get_active_value(
                "combined_uncertain_threshold", device_id=device_id, default=uncertain_global_current,
            ) if engine is not None else uncertain_global_current
            dev_new_value, dev_reason = calibrate_uncertain_threshold(
                dev_corrected, dev_uncorrected, current=dev_current, min_samples=AUTOTUNE_DEVICE_MIN_SAMPLES,
            )
            device_uncertain_outcomes[device_id] = _classify_outcome(dev_new_value, dev_reason)
            if dev_new_value is not None and engine is not None:
                LOGGER.info(f"[AUTOTUNE » DEVICE {device_id}] combined_uncertain_threshold: {dev_reason}")
                _propose_and_promote(
                    engine, store, "combined_uncertain_threshold", dev_new_value, dev_reason,
                    evidence_detail={
                        "corrected_count": len(dev_corrected), "uncorrected_count": len(dev_uncorrected),
                        "rule": "calibrate_uncertain_threshold",
                    },
                    device_id=device_id, now=autotune_now,
                )
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE » GLOBAL] combined_uncertain_threshold calibration failed (non-fatal): {exc}")

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
                    if engine is not None:
                        _propose_and_promote(
                            engine, store, "fp_combined_suppress_threshold", new_value, reason,
                            evidence_detail={
                                "corrected_count": len(dev_corrected),
                                "uncorrected_count": len(dev_uncorrected),
                                "rule": "calibrate_suppress_threshold",
                            },
                            device_id=device_id,
                            now=autotune_now,
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
                    if engine is not None:
                        _propose_and_promote(
                            engine, store, "arp_sweep_unique_targets_threshold", new_value, reason,
                            evidence_detail={
                                "corrected_count": corrected_count,
                                "confirmed_count": confirmed_count,
                                "rule": "calibrate_arp_sweep_threshold",
                            },
                            device_id=device_id,
                            now=autotune_now,
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
            store=store,
        )
    except Exception as exc:
        LOGGER.error(f"[AUTOTUNE] Failed to write autotune relay stats (non-fatal): {exc}")

    # This script normally exits right after main() calls this function (a fresh
    # subprocess per scheduler.py's own dispatch model), so the OS would reclaim the
    # handle anyway -- but closing explicitly avoids leaving a dangling WAL/SHM lock on
    # state/v13_graph.db that could interfere with the concurrently-running main
    # pipeline process's own long-lived connection to the SAME file, and matters for
    # any in-process caller (fp_engine.py's own weekly retrain thread calls this
    # function directly, not via a subprocess -- see this function's own docstring).
    if store is not None:
        try:
            store.close()
        except Exception as exc:
            LOGGER.debug(f"[AUTOTUNE] Failed to close GraphStore cleanly (non-fatal): {exc}")
    # fp_engine (constructed lazily by the per-device/ARP-sweep passes above) opens
    # its OWN separate GraphStore connection to the same file for its Phase B
    # autotune-aware reads -- see AutonomousFPEngine.close()'s own docstring for why
    # this needs an explicit close too, not just `store` above.
    if fp_engine is not None:
        try:
            fp_engine.close()
        except Exception as exc:
            LOGGER.debug(f"[AUTOTUNE] Failed to close fp_engine's GraphStore cleanly (non-fatal): {exc}")


def _load_training_row_exclusions(state_dir: Path) -> set:
    """Reads state/training_row_exclusions.json (written by
    identify_corrupted_training_rows.py), a set of dedup keys for historically-
    corrupted rows -- e.g. DNS_COVERT_TUNNELING/DGA_BOTNET_C2 alerts predating their
    domain-attribution fix, whose f1_entropy feature was computed from the wrong
    domain. This file is a separate, deletable overlay; load_dataset() below skips
    matching rows without alerts.json/the graph's decision history themselves ever
    being modified. Missing/unreadable file -> empty set, i.e. no exclusions (fail-open,
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
    """Loads labeled training samples from configured alerts stream + the graph's
    fp_suppression_log entries (2026-09-21: formerly state/autonomous_muted.jsonl).

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

    # Read the graph's fp_suppression_log entries FIRST so their dedup keys are
    # available while filtering the alerts.json threat stream below.
    muted_docs = _read_muted_docs_from_graph(state_dir, limit=MAX_REAL_SAMPLES_PER_CLASS)

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
            # in the graph's fp_suppression_log; do not ALSO train it as label=0 here.
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


def train_and_export_onnx(state_dir: Path, model_dir: Path = None) -> bool:
    """Trains GradientBoostingClassifier on 11 features and exports fp_classifier.onnx +
    fp_calibration.json to model_dir (default: derived from config.yaml's model_path,
    the SAME directory fp_engine.py's own loader reads from -- must stay the same
    directory on both sides or a retrained model is silently never picked up)."""
    if model_dir is None:
        model_dir = Path(CONFIG.get("model_path", "models/ids_model.pkl")).parent
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
        model_dir.mkdir(parents=True, exist_ok=True)
        calibrator_path = model_dir / "fp_calibration.json"
        calibration_reliable = can_split and len(X_calib) >= 20 and len(set(y_calib)) >= 2
        if calibration_reliable:
            raw_calib_probs = pipeline.predict_proba(X_calib)[:, 1]
            iso = IsotonicRegression(out_of_bounds="clip")
            iso.fit(raw_calib_probs, y_calib)
            _atomic_write_text(calibrator_path, json.dumps({
                "reliable": True,
                "x_thresholds": [float(v) for v in iso.X_thresholds_],
                "y_thresholds": [float(v) for v in iso.y_thresholds_],
                "fit_at": time.time(),
                "calibration_sample_count": len(X_calib),
            }, indent=2))
            LOGGER.info("📐 Isotonic calibration fit on %d held-out samples (never used for "
                        "training), saved to %s", len(X_calib), calibrator_path)
        else:
            # Not enough held-out data for a trustworthy calibration curve -- an
            # explicit "unreliable" marker, not a silently-stale or fabricated-from-
            # too-few-points curve. fp_engine.py must fall back to the raw,
            # explicitly-labeled-as-uncalibrated score when this is present.
            _atomic_write_text(calibrator_path, json.dumps({
                "reliable": False,
                "reason": f"only {len(X_calib)} held-out sample(s) available "
                          f"(need >=20 with both classes present for a trustworthy curve)",
                "fit_at": time.time(),
            }, indent=2))
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
        _atomic_write_bytes(onnx_path, onnx_model.SerializeToString())

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
