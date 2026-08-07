"""
train_fp_classifier.py – Weekly Autonomous Model Retraining Script for Home IDS.

======================================================================================
WHAT DOES THIS SCRIPT DO?  (Plain English for Novice Users)
======================================================================================
This script reads your network's actual alert history and auto-suppressed false positive
logs to train a custom LightGBM / Gradient Boosting ONNX classifier specifically
tuned to YOUR home network.

INPUT DATA SOURCES:
  1. state/alerts.json           → Real breach alerts (Label 0: Threat)
  2. state/autonomous_muted.jsonl → Auto-suppressed alerts (Label 1: False Positive)

FEATURE MATRIX EXTRACTED (6 normalized dimensions):
  [0] Tranco global rank score   (0.0 = unknown, 1.0 = top 1M global domain)
  [1] First label entropy score  (0.0 = readable, 1.0 = random string)
  [2] Max subdomain label length (0.0 = short, 1.0 = >60 chars)
  [3] Outbound bytes Z-score     (0.0 = normal upload, 1.0 = large upload spike)
  [4] Device type weight         (laptop=0.5, phone=0.4, iot=0.1)
  [5] Historical FP cache flag   (1.0 if base domain is in trust cache, else 0.0)

OUTPUT MODEL:
  state/models/fp_classifier.onnx

USAGE:
  Manual run:      python src/scripts/train_fp_classifier.py
  Automated run:   Scheduled weekly by fp_engine.py at Sunday 00:00:00
======================================================================================
"""

import json
import logging
import sys
import time
from pathlib import Path
import numpy as np

# Ensure src/ directory is in Python path for standalone CLI execution
SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from utils import entropy as compute_entropy

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


def extract_features_from_alert(doc: dict) -> list:
    """Extracts the 9 normalized feature dimensions from an alert payload."""
    features = doc.get("features", {})
    context = doc.get("network_context", {})
    device = doc.get("device", {})

    domain = context.get("queried_domain", "") or doc.get("domain", "")

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
    f6_lateral = min(float(features.get("zeek_lateral_moves", 0) or 0) / 10.0, 1.0)
    f7_port_scans = min(float(features.get("zeek_s0_rej_count", 0) or 0) / 50.0, 1.0)
    f8_app_proto = float(features.get("zeek_app_protocol_weight", 0.2) or 0.2)

    return [f0_tranco, f1_entropy, f2_label_len, f3_out_z, f4_dev_type, f5_hist_fp, f6_lateral, f7_port_scans, f8_app_proto]


def load_dataset(state_dir: Path) -> tuple:
    """Loads labeled training samples from alerts.json and autonomous_muted.jsonl (max 10,000 recent samples)."""
    X, y = [], []

    # 1. Load alerts.json (Threats -> Label 0)
    alerts_path = state_dir / "alerts.json"
    if alerts_path.exists():
        try:
            raw = alerts_path.read_text(encoding="utf-8")
            docs = json.loads(raw)
            if isinstance(docs, list):
                for doc in docs[-5000:]:
                    X.append(extract_features_from_alert(doc))
                    y.append(0)
        except Exception as exc:
            LOGGER.warning("Could not read alerts.json: %s", exc)

    # 2. Load autonomous_muted.jsonl (False Positives -> Label 1)
    muted_path = state_dir / "autonomous_muted.jsonl"
    if muted_path.exists():
        try:
            with open(muted_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[-5000:]:
                line = line.strip()
                if line:
                    doc = json.loads(line)
                    X.append(extract_features_from_alert(doc))
                    y.append(1)
        except Exception as exc:
            LOGGER.warning("Could not read autonomous_muted.jsonl: %s", exc)

    return X, y


def train_and_export_onnx(state_dir: Path) -> bool:
    """Trains GradientBoostingClassifier on 9 features and exports to state/models/fp_classifier.onnx."""
    X, y = load_dataset(state_dir)
    LOGGER.info("Dataset loaded: %d real samples from disk.", len(X))

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
            initial_types=[("input", FloatTensorType([None, 9]))],
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
