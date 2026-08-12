"""
train_fp_classifier.py – Weekly Autonomous Model Retraining Script for Home IDS.

======================================================================================
WHAT DOES THIS SCRIPT DO?  (Plain English for Novice Users)
======================================================================================
This script reads your network's actual alert history and auto-suppressed false positive
logs to train a custom LightGBM / Gradient Boosting ONNX classifier specifically
tuned to YOUR home network.

INPUT DATA SOURCES:
  1. config.json -> static_requires_restart.alert_json_path (preferred; JSONL or JSON array)
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
from pathlib import Path

# Ensure src/ directory is in Python path for standalone CLI execution
SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from utils import entropy as compute_entropy
from config import CONFIG

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


def load_dataset(state_dir: Path) -> tuple:
    """Loads labeled training samples from configured alerts stream + autonomous muted log."""
    X, y = [], []
    stats = {
        "threat_accepted": 0, "threat_rejected": 0,
        "fp_accepted": 0, "fp_rejected": 0,
    }

    # 1. Threat samples from configured alert stream path (fallback to state/alerts.json)
    alert_docs = []
    for path in _resolve_alert_input_paths(state_dir):
        docs = _read_alert_docs(path)
        if docs:
            alert_docs = docs
            LOGGER.info("Using threat training source: %s (%d docs)", path, len(docs))
            break

    for doc in alert_docs[-MAX_REAL_SAMPLES_PER_CLASS:]:
        _append_sample(X, y, doc, 0, stats, source="threat")

    # 2. False positives from autonomous muted JSONL
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
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    stats["fp_rejected"] += 1
                    continue
                _append_sample(X, y, doc, 1, stats, source="fp")
        except Exception as exc:
            LOGGER.warning("Could not read autonomous_muted.jsonl: %s", exc)

    return X, y, stats


def train_and_export_onnx(state_dir: Path) -> bool:
    """Trains GradientBoostingClassifier on 9 features and exports to state/models/fp_classifier.onnx."""
    X, y, stats = load_dataset(state_dir)
    LOGGER.info(
        "Dataset loaded: %d accepted real samples | threat accepted/rejected=%d/%d | fp accepted/rejected=%d/%d | dim=%d",
        len(X),
        stats["threat_accepted"], stats["threat_rejected"],
        stats["fp_accepted"], stats["fp_rejected"],
        FP_FEATURE_DIM
    )

    if len(X) < 10:
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
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
